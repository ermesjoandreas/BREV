//! The mail store: identity, contacts, threads and messages in a
//! brev-vault [`Vault`], which holds the file, the DEK and the
//! `Locked`/`Unlocked` state (the gate in `Core::dek` is the vault's).
//!
//! Every content column is a ciphertext BLOB sealed under the DEK, with the
//! row's immutable fields in the AEAD associated data. Only ids, timestamps,
//! flags and the keyed contact tags are plaintext. The core caches no
//! plaintext: every read decrypts into a fresh [`Plaintext`] owned by the
//! caller.
//!
//! Contacts (schema v3, docs/PHASE3_DESIGN.md §6.1) have a random local id
//! that never changes; a sender is found by the keyed tag of its identity id,
//! so the file holds neither a contact's identity id nor its address.
//!
//! Schema v5 (docs/PHASE4_DESIGN.md §5.1) adds each contact's sealed flags
//! (they take my letters, blocked). Schema v8 (docs/DECISIONS.md D-0116)
//! drops the user's open invites and the flag "key verified by an
//! invite".
//!
//! Schema v6 (docs/AUTHORSHIP.md §6) adds `messages.proof`: a received
//! letter's Hand result (brev-hand's `Verification::encode`, the checks that
//! passed and the token), sealed beside it; empty for a sent letter. The
//! envelope payload is protocol version 2: the letter and its token.
//! Schema v7 (docs/DECISIONS.md D-0115) drops `messages.env_class`: there
//! are no classes, and a letter goes out only when it meets the
//! requirements.

use std::path::Path;
use std::sync::Arc;
#[cfg(test)]
use std::sync::Weak;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use brev_hand::token::MAX_TOKEN;
use brev_hand::{Rule, Verification};
use brev_proto::body::{self, is_valid_address};
use brev_proto::{identity_code, sig, IDENTITY_CODE_LEN, SIG_LEN};
use brev_vault::{check_path, Clock, DekSlot, Text, Vault, VaultConfig};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use zeroize::Zeroizing;

use crate::crypto::{self, column_ad, Plaintext};
use crate::{Envelope, Error};

/// "BREV" in the SQLite header's application_id field.
const APPLICATION_ID: i32 = 0x4252_4556;
/// 8: version 3 (local contact ids, the keyed contact tag, sealed
/// addresses and `pending`, the relay token in `identity.keys`;
/// docs/PHASE3_DESIGN.md §6.1), `contacts.flags` (version 5,
/// docs/PHASE4_DESIGN.md §5.1), `messages.proof` (version 6,
/// docs/AUTHORSHIP.md §6), no `messages.env_class` (version 4 added it,
/// version 7 drops it; D-0115), and no `invites` (version 5 added it,
/// version 8 drops it; D-0116). A version 2 to 7 store opens
/// as `Corrupt`; there is no migration.
const SCHEMA_VERSION: i32 = 8;

/// The requirements a letter must meet, sent and received (brev-hand's
/// `requirements`): all of them. A test archive built with the cargo
/// feature allow-software-keys (for the Swift harness, the lock probe, the
/// view host and the snapshot tool, which have software keys and no Touch
/// ID) skips only the hardware key, on both sides. The app's archive never
/// has that feature: scripts/gen-bindings.sh and the build phase in
/// app/project.yml fail on its marker (ffi.rs; docs/VAULT_SPLIT_PLAN.md
/// §6).
pub(crate) const KEY_RULE: Rule = if cfg!(feature = "allow-software-keys") {
    Rule::AnyKey
} else {
    Rule::All
};

const SCHEMA: &str = "
CREATE TABLE identity (
    id         BLOB PRIMARY KEY,           -- pt: own identity id
    keys       BLOB NOT NULL,              -- ct: X25519 secret || X25519 public || signing key (65) || relay token (32)
    address    BLOB NOT NULL               -- ct: own address; empty until registered
) STRICT;
CREATE TABLE contacts (
    id         BLOB PRIMARY KEY,           -- pt: 16 random bytes, local; kept when the key changes
    tag        BLOB NOT NULL UNIQUE,       -- pt: keyed tag of the pinned identity id (finds the sender)
    bundle     BLOB NOT NULL,              -- ct: pinned bundle
    address    BLOB NOT NULL,              -- ct: the address, also shown as the name
    pending    BLOB NOT NULL,              -- ct: empty, or the other bundle the relay returned
    flags      BLOB NOT NULL               -- ct: one byte: 1 takes my letters, 4 blocked, 8 relay not yet told of the block
) STRICT;
CREATE TABLE threads (
    id         BLOB PRIMARY KEY,           -- pt: 16 random bytes, shared with peer
    contact_id BLOB NOT NULL REFERENCES contacts(id),
    created_at INTEGER NOT NULL,           -- pt: unix seconds
    subject    BLOB NOT NULL               -- ct
) STRICT;
CREATE TABLE messages (
    id         BLOB PRIMARY KEY,           -- pt: 16 random bytes, chosen by sender
    thread_id  BLOB NOT NULL REFERENCES threads(id),
    created_at INTEGER NOT NULL,           -- pt
    outgoing   INTEGER NOT NULL,           -- pt: 1 = sent by me
    read       INTEGER NOT NULL,           -- pt
    body       BLOB NOT NULL,              -- ct
    proof      BLOB NOT NULL               -- ct: a received letter's Hand result (pass bits || token); empty for a sent one
) STRICT;
CREATE INDEX messages_by_thread ON messages(thread_id, created_at);
";

/// The user's store: `brev.db` in the folder the app passes, with the
/// schema above.
pub(crate) const MAIL: VaultConfig = VaultConfig {
    file_name: "brev.db",
    application_id: APPLICATION_ID,
    schema: SCHEMA,
    schema_version: SCHEMA_VERSION,
};

/// Layout of the decrypted `identity.keys`: X25519 secret, X25519 public,
/// signing key, relay token.
const KEY_SECRET: std::ops::Range<usize> = 0..32;
const KEY_X25519: std::ops::Range<usize> = 32..64;
const KEY_SIGNING: std::ops::Range<usize> = 64..64 + sig::KEY_LEN;
const KEY_TOKEN: std::ops::Range<usize> = 64 + sig::KEY_LEN..96 + sig::KEY_LEN;

/// `contacts.flags`: the contact takes the user's letters (it approved the
/// user, or asked the user).
pub(crate) const APPROVED_ME: u8 = 1;
// 2 was "key verified by an invite" (D-0116); it is not
// reused.
/// `contacts.flags`: the user blocked the contact (*Blokker*): nothing is
/// sent to it and its letters are dropped.
pub(crate) const BLOCKED: u8 = 4;
/// `contacts.flags`, beside `BLOCKED`: the relay has not yet answered the
/// block (`/v1/block`), so every sync tells it again until it does. Sealed,
/// so a lock does not forget it (WP5 review).
pub(crate) const BLOCK_UNTOLD: u8 = 8;

/// An identity id: SHA-256 over a [`PublicBundle`]. Used as the envelope
/// sender and recipient; the store keeps only the own one in plaintext.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IdentityId(pub [u8; 32]);

/// A contact's local id: 16 random bytes, kept when its key changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ContactId(pub [u8; 16]);

/// A thread id, chosen at random by whoever starts the thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ThreadId(pub [u8; 16]);

/// A message id, chosen at random by the sender and shared by both stores.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MessageId(pub [u8; 16]);

/// Everything public about an identity. Its hash is the [`IdentityId`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicBundle {
    /// The identity (signing) key: an uncompressed P-256 point, the Secure
    /// Enclave key's public half.
    pub signing_key: [u8; sig::KEY_LEN],
    /// X25519 public key for encrypting to this identity.
    pub x25519: [u8; 32],
}

impl PublicBundle {
    /// A bundle with a checked signing key: 65 bytes, `04`, on the curve
    /// (`Malformed` otherwise).
    pub fn new(signing_key: &[u8], x25519: [u8; 32]) -> Result<PublicBundle, Error> {
        let signing_key = *sig::check_key(signing_key).map_err(|_| Error::Malformed)?;
        Ok(PublicBundle {
            signing_key,
            x25519,
        })
    }

    /// Parses the relay's lookup answer layout: signing key (65) ‖ X25519
    /// key (32), the key checked (`Malformed` otherwise).
    pub fn from_bytes(b: &[u8]) -> Result<PublicBundle, Error> {
        let (signing_key, x25519) = body::parse_lookup_answer(b).map_err(|_| Error::Malformed)?;
        Ok(PublicBundle {
            signing_key: *signing_key,
            x25519: *x25519,
        })
    }

    /// The layout [`PublicBundle::from_bytes`] reads.
    pub fn to_bytes(&self) -> [u8; body::LOOKUP_ANSWER_LEN] {
        body::lookup_answer(&self.signing_key, &self.x25519)
    }

    /// SHA-256("brev/v0/identity" || 65 || signing key || X25519 key).
    pub fn id(&self) -> IdentityId {
        IdentityId(brev_proto::identity_id(&self.signing_key, &self.x25519))
    }

    /// The identity code shown in the app (base32 of the id's first 150
    /// bits, 35 ASCII bytes).
    pub fn code(&self) -> [u8; IDENTITY_CODE_LEN] {
        identity_code(&self.id().0)
    }
}

/// A contact. No `Debug`: the address is shown as its name, content in the
/// UI (docs/PHASE3_DESIGN.md §6.4).
pub struct Contact {
    /// Local id.
    pub id: ContactId,
    /// The address, wiped on drop.
    pub address: Plaintext,
    /// The relay returned another key than the pinned one, and it has not
    /// been accepted: nothing can be sent to this contact.
    pub key_changed: bool,
    /// The contact takes the user's letters, as far as the user knows.
    pub approved_me: bool,
    /// The user blocked the contact.
    pub blocked: bool,
}

/// A thread with one contact. No `Debug`: the subject is content.
pub struct Thread {
    /// Thread id.
    pub id: ThreadId,
    /// The other party.
    pub contact: ContactId,
    /// Local creation time, unix seconds.
    pub created_at: i64,
    /// Subject (content), wiped on drop.
    pub subject: Plaintext,
}

/// One message's metadata. The body is read separately with
/// [`Core::read_body`], so listing a thread decrypts nothing (§1.10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Message {
    /// Message id.
    pub id: MessageId,
    /// Thread it belongs to.
    pub thread: ThreadId,
    /// Local time it was sent or received, unix seconds.
    pub created_at: i64,
    /// True if this store's owner sent it.
    pub outgoing: bool,
    /// Read flag.
    pub read: bool,
}

/// A letter before its token (docs/AUTHORSHIP.md §3.1), from
/// [`Core::draft`]: the contact, fresh thread and message ids, the time, and
/// the letter's plaintext, which the token's content hash covers. The
/// plaintext is a [`Plaintext`], wiped on drop. No `Debug`: it is content.
pub struct Draft {
    contact: [u8; 16],
    thread: [u8; 16],
    message: [u8; 16],
    created_at: i64,
    letter: Plaintext,
}

impl Draft {
    /// The letter: `message id (16) || thread id (16) || subject length
    /// (u16 BE) || subject || body`.
    pub fn letter(&self) -> &[u8] {
        &self.letter
    }

    /// The contact it goes to.
    pub fn contact(&self) -> ContactId {
        ContactId(self.contact)
    }
}

/// A letter that starts a new thread, sealed and waiting for its signature
/// and its delivery ([`Core::seal_letter`]). It holds ciphertext only: the
/// envelope, and the thread and message rows already sealed under the DEK
/// for the sender's own copy, which [`Core::store_sent`] inserts once the
/// relay has the envelope.
pub struct Letter {
    contact: [u8; 16],
    thread: [u8; 16],
    message: [u8; 16],
    created_at: i64,
    subject: Vec<u8>,
    body: Vec<u8>,
    /// The own copy's `messages.proof`: sealed, empty.
    proof: Vec<u8>,
    envelope: Envelope,
}

impl Letter {
    /// What the identity key signs: SHA-256 of the envelope's signed bytes,
    /// which is also the envelope id.
    pub fn digest(&self) -> [u8; 32] {
        self.envelope.id()
    }

    /// The envelope; its signature slot is empty until
    /// [`Core::attach_signature`].
    pub fn envelope(&self) -> &Envelope {
        &self.envelope
    }

    /// True once a verified signature is attached.
    pub fn is_signed(&self) -> bool {
        self.envelope.signature.len() == SIG_LEN
    }

    /// The thread this letter starts.
    pub fn thread(&self) -> ThreadId {
        ThreadId(self.thread)
    }

    /// The contact this letter goes to.
    pub fn contact(&self) -> ContactId {
        ContactId(self.contact)
    }
}

/// One user's encrypted store plus session state.
pub struct Core {
    /// The file, the DEK and the lock state.
    v: Vault,
}

/// The own identity, decrypted for one operation.
struct Me {
    id: [u8; 32],
    /// Counted by itself in test builds, so it is seen even when moved out.
    secret: crypto::Secret,
}

impl Core {
    /// Creates a new store at `path` with a fresh X25519 identity and a
    /// fresh relay token, sealed under `dek`. `signing_key` is this
    /// identity's signing key and must be an uncompressed P-256 point.
    /// `dek` is zeroed before anything can fail, so after an error the caller
    /// must make a fresh DEK. Refuses a relative path, an all-zero DEK, a bad
    /// key and an existing path; on any later failure the new file is
    /// removed. The file is created with mode 0600 (SQLite gives its journal
    /// the same mode), in a folder with mode 0700 that no other store holds
    /// (`Unsafe`, `Busy`). The new core is armed: [`Core::confirm_active`]
    /// opens it.
    pub fn create(path: &Path, dek: &mut [u8; 32], signing_key: &[u8]) -> Result<Core, Error> {
        let slot = DekSlot::take(dek);
        check_path(path)?;
        if slot.is_zero() {
            return Err(Error::Malformed);
        }
        let signing_key = sig::check_key(signing_key).map_err(|_| Error::Malformed)?;
        Core::init(path, slot, signing_key)
    }

    /// Opens an existing store, locked. Refuses a file that is not a Brev
    /// store of this schema version (`Corrupt`), before writing anything to
    /// it, then a file that is not mode 0600 or a folder that is not 0700
    /// (`Unsafe`), and a folder another store holds (`Busy`).
    pub fn open(path: &Path) -> Result<Core, Error> {
        Ok(Core {
            v: Vault::open(path, &MAIL)?,
        })
    }

    /// Unlocks with `dek`, which is zeroed before this returns. An all-zero
    /// DEK, or one that cannot open the identity row, gives `WrongKey`; any
    /// failure leaves the core locked. Success leaves it armed: every
    /// content call gives `Locked` until [`Core::confirm_active`].
    pub fn unlock(&mut self, dek: &mut [u8; 32]) -> Result<(), Error> {
        // Opening the identity row is the key check. The X25519 secret is
        // not needed, so it is never built and never copied onto the stack.
        self.v.unlock(dek, |db, k| {
            open_identity(db, k).map(drop).map_err(|e| {
                if matches!(e, Error::Crypto) {
                    Error::WrongKey
                } else {
                    e
                }
            })
        })
    }

    /// The second step of `unlock` (or `create`): within 2 s of it, the
    /// core opens until it has been idle for the idle time
    /// ([`Core::set_idle`]). Late, or locked: locks, and `Locked`.
    /// Idempotent while open.
    pub fn confirm_active(&mut self) -> Result<(), Error> {
        Ok(self.v.confirm_active()?)
    }

    /// The idle time from the next `confirm_active` on (300 s until set).
    pub fn set_idle(&mut self, idle: Duration) {
        self.v.set_idle(idle);
    }

    /// Closes the texts handed out, zeroes the DEK and locks. Idempotent.
    /// The core holds no other key or plaintext between calls, so this is
    /// all there is to wipe.
    pub fn lock(&mut self) {
        self.v.lock();
    }

    /// True unless open: also while armed, and once the idle time has
    /// passed.
    pub fn is_locked(&self) -> bool {
        self.v.is_locked()
    }

    /// This identity's public bundle, as registered at the relay.
    pub fn bundle(&self) -> Result<PublicBundle, Error> {
        // Both public keys are in the row, so the X25519 secret is never
        // built and never copied onto the stack (see `me()`).
        let (_, keys) = self.identity_keys()?;
        let x25519 = keys.get(KEY_X25519).ok_or(Error::Crypto)?;
        let signing_key = keys.get(KEY_SIGNING).ok_or(Error::Crypto)?;
        PublicBundle::new(signing_key, x25519.try_into().map_err(|_| Error::Crypto)?)
    }

    /// The own address: empty until registered.
    pub fn address(&self) -> Result<Plaintext, Error> {
        let dek = self.dek()?;
        let (id, sealed): ([u8; 32], Vec<u8>) =
            self.db()
                .query_row("SELECT id, address FROM identity", [], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })?;
        Ok(crypto::open_column(
            dek,
            &column_ad("identity.address", &[&id]),
            &sealed,
        )?)
    }

    /// True once an address is registered.
    pub fn is_registered(&self) -> Result<bool, Error> {
        Ok(!self.address()?.is_empty())
    }

    /// Stores the address the relay has registered for this identity.
    /// Addresses are permanent: `Duplicate` if one is already stored,
    /// `Malformed` if `address` breaks the rules.
    pub fn set_address(&mut self, address: &[u8]) -> Result<(), Error> {
        let dek = self.dek()?;
        if !is_valid_address(address) {
            return Err(Error::Malformed);
        }
        if self.is_registered()? {
            return Err(Error::Duplicate);
        }
        let id = self.my_id()?;
        let sealed = crypto::seal_column(dek, &column_ad("identity.address", &[&id]), address)?;
        self.db()
            .execute("UPDATE identity SET address = ?1", [sealed])?;
        Ok(())
    }

    /// The registration v3 body without its signature (D-0116):
    /// `address`, both public keys and SHA-256 of the relay
    /// token. The identity key signs `body::register_preimage_v3` of it.
    pub fn registration(&self, address: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        let (_, keys) = self.identity_keys()?;
        let x25519: &[u8; 32] = keys
            .get(KEY_X25519)
            .and_then(|k| k.try_into().ok())
            .ok_or(Error::Crypto)?;
        let token: &[u8; 32] = keys
            .get(KEY_TOKEN)
            .and_then(|k| k.try_into().ok())
            .ok_or(Error::Crypto)?;
        let signing_key = keys.get(KEY_SIGNING).ok_or(Error::Crypto)?;
        let hash = body::token_hash(token);
        body::registration_body(address, signing_key, x25519, &hash)
            .map(Zeroizing::new)
            .map_err(|_| Error::Malformed)
    }

    /// The own identity id and the relay token, for the token-authenticated
    /// requests (lookup, inbox, ack). The token is in a buffer that wipes
    /// itself.
    pub fn relay_token(&self) -> Result<(IdentityId, Zeroizing<[u8; 32]>), Error> {
        let (id, keys) = self.identity_keys()?;
        let mut token = Zeroizing::new([0u8; 32]);
        token.copy_from_slice(keys.get(KEY_TOKEN).ok_or(Error::Crypto)?);
        Ok((IdentityId(id), token))
    }

    /// Checks a DER signature from the Secure Enclave over `msg` with the
    /// own identity key, and returns it as raw r ‖ s (S unchanged). Not DER,
    /// or not by the own key (a replaced keychain item): `Signing`.
    pub fn verify_own(&self, msg: &[u8], der: &[u8]) -> Result<[u8; SIG_LEN], Error> {
        let own = self.bundle()?;
        let raw = sig::der_to_raw(der).map_err(|_| Error::Signing)?;
        sig::verify(&own.signing_key, msg, &raw).map_err(|_| Error::Signing)?;
        Ok(raw)
    }

    /// Refuses an address for a new contact: the own address (`Malformed`)
    /// and the address of a contact already there (`Duplicate`: a changed
    /// key goes through [`Core::check_key`], never around it).
    pub fn check_new_address(&self, address: &[u8]) -> Result<(), Error> {
        if &self.address()?[..] == address {
            return Err(Error::Malformed);
        }
        match self.contact_at(address)? {
            Some(_) => Err(Error::Duplicate),
            None => Ok(()),
        }
    }

    /// The contact with `address`, if any.
    pub fn contact_at(&self, address: &[u8]) -> Result<Option<ContactId>, Error> {
        let dek = self.dek()?;
        let mut stmt = self.db().prepare("SELECT id, address FROM contacts")?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, [u8; 16]>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?;
        for row in rows {
            let (id, sealed) = row?;
            let known = crypto::open_column(dek, &column_ad("contacts.address", &[&id]), &sealed)?;
            if &known[..] == address {
                return Ok(Some(ContactId(id)));
            }
        }
        Ok(None)
    }

    /// The contact whose pinned key is the identity `id` (found by its
    /// keyed tag), if any.
    pub fn contact_of(&self, id: &IdentityId) -> Result<Option<ContactId>, Error> {
        let dek = self.dek()?;
        let tag = crypto::contact_tag(dek, &id.0);
        Ok(self
            .db()
            .query_row("SELECT id FROM contacts WHERE tag = ?1", [&tag[..]], |r| {
                r.get(0).map(ContactId)
            })
            .optional()?)
    }

    /// Adds a contact with the bundle the relay returned for `address`, and
    /// pins it (trust on first use), with no flags. Refuses an address that
    /// breaks the rules or is the own one and the own identity
    /// (`Malformed`), and an address or identity that is already a contact
    /// (`Duplicate`).
    pub fn add_contact(
        &mut self,
        bundle: &PublicBundle,
        address: &[u8],
    ) -> Result<ContactId, Error> {
        self.insert_contact(bundle, address, 0)
    }

    /// [`Core::add_contact`] with `flags` sealed into the new row.
    pub(crate) fn insert_contact(
        &mut self,
        bundle: &PublicBundle,
        address: &[u8],
        flags: u8,
    ) -> Result<ContactId, Error> {
        let dek = self.dek()?;
        if !is_valid_address(address) {
            return Err(Error::Malformed);
        }
        self.check_new_address(address)?;
        let their = bundle.id();
        if their.0 == self.my_id()? {
            return Err(Error::Malformed);
        }
        let id: [u8; 16] = crypto::random()?;
        let tag = crypto::contact_tag(dek, &their.0);
        let sealed_bundle = crypto::seal_column(
            dek,
            &column_ad("contacts.bundle", &[&id]),
            &bundle.to_bytes(),
        )?;
        let sealed_address =
            crypto::seal_column(dek, &column_ad("contacts.address", &[&id]), address)?;
        let pending = crypto::seal_column(dek, &column_ad("contacts.pending", &[&id]), &[])?;
        let sealed_flags = crypto::seal_column(dek, &flags_ad(&id, &tag), &[flags])?;
        // Any uniqueness conflict: the same identity (tag) is already there.
        let n = self.db().execute(
            "INSERT INTO contacts (id, tag, bundle, address, pending, flags)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT DO NOTHING",
            params![
                &id[..],
                &tag[..],
                sealed_bundle,
                sealed_address,
                pending,
                sealed_flags
            ],
        )?;
        if n == 0 {
            return Err(Error::Duplicate);
        }
        Ok(ContactId(id))
    }

    /// All contacts, in the order they were added.
    pub fn contacts(&self) -> Result<Vec<Contact>, Error> {
        let dek = self.dek()?;
        let mut stmt = self
            .db()
            .prepare("SELECT id, address FROM contacts ORDER BY rowid")?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, [u8; 16]>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, address) = row?;
            let address =
                crypto::open_column(dek, &column_ad("contacts.address", &[&id]), &address)?;
            let key_changed = self.pending_bundle(ContactId(id))?.is_some();
            let flags = self.contact_flags(ContactId(id))?;
            out.push(Contact {
                id: ContactId(id),
                address,
                key_changed,
                approved_me: flags & APPROVED_ME != 0,
                blocked: flags & BLOCKED != 0,
            });
        }
        Ok(out)
    }

    /// The flags of `contact` (one byte, `Corrupt` if the value is not one
    /// byte; `Crypto` if it does not open under this row's AD).
    pub(crate) fn contact_flags(&self, contact: ContactId) -> Result<u8, Error> {
        Ok(self.flags_and_tag(contact)?.0)
    }

    /// The flags of `contact` and the row's tag. The flags' AD holds the
    /// tag, so flags sealed while another key was pinned do not open.
    fn flags_and_tag(&self, contact: ContactId) -> Result<(u8, [u8; 32]), Error> {
        let dek = self.dek()?;
        let (tag, sealed): ([u8; 32], Vec<u8>) = self.db().query_row(
            "SELECT tag, flags FROM contacts WHERE id = ?1",
            [&contact.0[..]],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let flags = crypto::open_column(dek, &flags_ad(&contact.0, &tag), &sealed)?;
        match flags[..] {
            [byte] => Ok((byte, tag)),
            _ => Err(Error::Corrupt),
        }
    }

    /// Sets `set` and clears `clear` in the flags of `contact`. Writes only
    /// if they change; true if they did.
    pub(crate) fn change_flags(
        &mut self,
        contact: ContactId,
        set: u8,
        clear: u8,
    ) -> Result<bool, Error> {
        let dek = self.dek()?;
        let (before, tag) = self.flags_and_tag(contact)?;
        let after = (before | set) & !clear;
        if after == before {
            return Ok(false);
        }
        let sealed = crypto::seal_column(dek, &flags_ad(&contact.0, &tag), &[after])?;
        self.db().execute(
            "UPDATE contacts SET flags = ?1 WHERE id = ?2",
            params![sealed, &contact.0[..]],
        )?;
        Ok(true)
    }

    /// The blocked contacts the relay has not answered yet (`BLOCKED` and
    /// `BLOCK_UNTOLD`), each with the identity id of its pinned key: the
    /// peer `/v1/block` names.
    pub(crate) fn untold_blocks(&self) -> Result<Vec<(ContactId, IdentityId)>, Error> {
        let ids: Vec<[u8; 16]> = {
            let mut stmt = self
                .db()
                .prepare("SELECT id FROM contacts ORDER BY rowid")?;
            let rows = stmt.query_map([], |r| r.get(0))?;
            rows.collect::<Result<_, _>>()?
        };
        let mut out = Vec::new();
        for id in ids {
            let contact = ContactId(id);
            let untold = BLOCKED | BLOCK_UNTOLD;
            if self.contact_flags(contact)? & untold == untold {
                out.push((contact, self.contact_bundle(contact)?.id()));
            }
        }
        Ok(out)
    }

    /// Pins `bundle` as the contact at `address` with `flags` added, for a
    /// peer the user approved (docs/PHASE4_DESIGN.md §5.3). A contact already at `address` keeps
    /// its row: the pinned key gains the flags (and a pending change is
    /// cleared); another key is sealed into `pending` (Phase 3's warning)
    /// and gives `None`, with nothing else changed. A new address gets a
    /// new row (`Duplicate` if that identity is pinned at another address).
    /// The own identity is `Malformed`. Returns the contact and whether the
    /// file changed.
    pub(crate) fn pin(
        &mut self,
        bundle: &PublicBundle,
        address: &[u8],
        flags: u8,
    ) -> Result<(Option<ContactId>, bool), Error> {
        if bundle.id().0 == self.my_id()? {
            return Err(Error::Malformed);
        }
        let Some(contact) = self.contact_at(address)? else {
            return Ok((Some(self.insert_contact(bundle, address, flags)?), true));
        };
        let (same, wrote) = self.compare_key(contact, bundle)?;
        if !same {
            return Ok((None, wrote));
        }
        let changed = self.change_flags(contact, flags, 0)?;
        Ok((Some(contact), wrote || changed))
    }

    /// One contact's address.
    pub fn contact_address(&self, contact: ContactId) -> Result<Plaintext, Error> {
        let dek = self.dek()?;
        let sealed: Vec<u8> = self.db().query_row(
            "SELECT address FROM contacts WHERE id = ?1",
            [&contact.0[..]],
            |r| r.get(0),
        )?;
        Ok(crypto::open_column(
            dek,
            &column_ad("contacts.address", &[&contact.0]),
            &sealed,
        )?)
    }

    /// The pinned bundle of `contact`. It must open under the row's AD
    /// (`Crypto` otherwise) and hash to an id whose tag is the row's `tag`
    /// (`Corrupt` otherwise), so a bundle or tag swapped between rows is
    /// caught.
    pub fn contact_bundle(&self, contact: ContactId) -> Result<PublicBundle, Error> {
        let dek = self.dek()?;
        let (tag, sealed): ([u8; 32], Vec<u8>) = self.db().query_row(
            "SELECT tag, bundle FROM contacts WHERE id = ?1",
            [&contact.0[..]],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let b = crypto::open_column(dek, &column_ad("contacts.bundle", &[&contact.0]), &sealed)?;
        let bundle = PublicBundle::from_bytes(&b).map_err(|_| Error::Corrupt)?;
        if crypto::contact_tag(dek, &bundle.id().0) != tag {
            return Err(Error::Corrupt);
        }
        Ok(bundle)
    }

    /// The other bundle the relay returned for `contact`, if its key
    /// changed and the change is not accepted yet.
    pub fn pending_bundle(&self, contact: ContactId) -> Result<Option<PublicBundle>, Error> {
        let dek = self.dek()?;
        let sealed: Vec<u8> = self.db().query_row(
            "SELECT pending FROM contacts WHERE id = ?1",
            [&contact.0[..]],
            |r| r.get(0),
        )?;
        let b = crypto::open_column(dek, &column_ad("contacts.pending", &[&contact.0]), &sealed)?;
        if b.is_empty() {
            return Ok(None);
        }
        PublicBundle::from_bytes(&b)
            .map(Some)
            .map_err(|_| Error::Corrupt)
    }

    /// Compares the bundle the relay returned for `contact` just now with
    /// the pinned one (docs/PHASE3_DESIGN.md §6.3). The pinned one clears
    /// `pending`; any other is sealed into `pending` and gives `KeyChanged`,
    /// which blocks sending until [`Core::accept_new_key`]. The own
    /// identity is `Malformed`.
    pub fn check_key(&mut self, contact: ContactId, found: &PublicBundle) -> Result<(), Error> {
        match self.compare_key(contact, found)? {
            (true, _) => Ok(()),
            (false, _) => Err(Error::KeyChanged),
        }
    }

    /// [`Core::check_key`]'s work: whether `found` is the pinned key, and
    /// whether `pending` was written.
    pub(crate) fn compare_key(
        &mut self,
        contact: ContactId,
        found: &PublicBundle,
    ) -> Result<(bool, bool), Error> {
        if found.id().0 == self.my_id()? {
            return Err(Error::Malformed);
        }
        let pinned = self.contact_bundle(contact)?;
        let pending = self.pending_bundle(contact)?;
        if pinned == *found {
            if pending.is_some() {
                self.set_pending(contact, &[])?;
                return Ok((true, true));
            }
            return Ok((true, false));
        }
        if pending.as_ref() != Some(found) {
            self.set_pending(contact, &found.to_bytes())?;
            return Ok((false, true));
        }
        Ok((false, false))
    }

    /// Pins the pending bundle of `contact`, if `code` is its identity code:
    /// the code the app is showing (`KeyChanged` otherwise, also when no key
    /// change is pending). One statement sets the tag and the bundle,
    /// empties `pending`, and clears the flags that were about the old key
    /// (it took the user's letters; a block stays), sealed under the new tag, so the old flags no longer open;
    /// a key that belongs to another contact gives `Duplicate`. The
    /// contact keeps its local id and its threads.
    pub fn accept_new_key(&mut self, contact: ContactId, code: &[u8]) -> Result<(), Error> {
        let dek = self.dek()?;
        let pending = self.pending_bundle(contact)?.ok_or(Error::KeyChanged)?;
        if pending.code()[..] != *code {
            return Err(Error::KeyChanged);
        }
        let flags = self.contact_flags(contact)? & BLOCKED;
        let tag = crypto::contact_tag(dek, &pending.id().0);
        let taken: Option<i64> = self
            .db()
            .query_row(
                "SELECT 1 FROM contacts WHERE tag = ?1 AND id != ?2",
                params![&tag[..], &contact.0[..]],
                |r| r.get(0),
            )
            .optional()?;
        if taken.is_some() {
            return Err(Error::Duplicate);
        }
        let sealed_bundle = crypto::seal_column(
            dek,
            &column_ad("contacts.bundle", &[&contact.0]),
            &pending.to_bytes(),
        )?;
        let empty = crypto::seal_column(dek, &column_ad("contacts.pending", &[&contact.0]), &[])?;
        let sealed_flags = crypto::seal_column(dek, &flags_ad(&contact.0, &tag), &[flags])?;
        self.db().execute(
            "UPDATE contacts SET tag = ?1, bundle = ?2, pending = ?3, flags = ?4 WHERE id = ?5",
            params![&tag[..], sealed_bundle, empty, sealed_flags, &contact.0[..]],
        )?;
        Ok(())
    }

    /// Starts a letter to `contact` that starts a new thread
    /// (docs/AUTHORSHIP.md §3.1): fresh thread and message ids, the time,
    /// and the letter's plaintext for the token's content hash. Checks what
    /// [`Core::seal_letter`] checks, so a letter that cannot be sealed is
    /// refused before the Touch ID prompt: `KeyChanged` while the contact's
    /// key change is pending, `NotApproved` for a blocked contact, and the
    /// contact's pinned bundle must open. Subjects are limited to 65535
    /// bytes. Stores nothing.
    pub fn draft(&self, contact: ContactId, subject: &[u8], body: &[u8]) -> Result<Draft, Error> {
        self.sealable(contact)?;
        u16::try_from(subject.len()).map_err(|_| Error::Malformed)?;
        self.contact_bundle(contact)?;
        let thread: [u8; 16] = crypto::random()?;
        let message: [u8; 16] = crypto::random()?;
        Ok(Draft {
            contact: contact.0,
            thread,
            message,
            created_at: now(),
            letter: encode_payload(&message, &thread, subject, body)?,
        })
    }

    /// Seals `draft` with its authorship token `token` (at most
    /// `MAX_TOKEN` bytes, `Malformed` otherwise): the payload of protocol
    /// version 2 (docs/AUTHORSHIP.md §2.5), padded, in an envelope without
    /// signature, and the subject, the body and an empty proof under the
    /// DEK for the own copy. Every decrypted value and the X25519 secret are
    /// dropped before this returns. `KeyChanged` while the contact's key
    /// change is pending, `NotApproved` for a blocked contact, both before
    /// anything is sealed. Stores nothing.
    pub fn seal_letter(&self, draft: &Draft, token: &[u8]) -> Result<Letter, Error> {
        let dek = self.dek()?;
        let contact = draft.contact();
        self.sealable(contact)?;
        let bundle = self.contact_bundle(contact)?;
        let (message, thread, created_at) = (draft.message, draft.thread, draft.created_at);
        // The payload and the identity secret live only inside this block.
        let (envelope, subject, body, proof) = {
            let (_, _, subject, body) = decode_payload(draft.letter())?;
            let me = self.me()?;
            let payload = encode_v2(draft.letter(), token)?;
            let env =
                crypto::seal_message(&me.secret, &bundle.x25519, me.id, bundle.id().0, &payload)?;
            let subject =
                crypto::seal_column(dek, &subject_ad(&thread, &contact.0, created_at), subject)?;
            let ad = |label| message_ad(label, &message, &thread, &contact.0, true, created_at);
            let body = crypto::seal_column(dek, &ad("messages.body"), body)?;
            let proof = crypto::seal_column(dek, &ad("messages.proof"), &[])?;
            (env, subject, body, proof)
        };
        crypto::scrub_stack();
        Ok(Letter {
            contact: contact.0,
            thread,
            message,
            created_at,
            subject,
            body,
            proof,
            envelope,
        })
    }

    /// The checks before a letter to `contact` is started or sealed:
    /// `KeyChanged` while its key change is pending, `NotApproved` while it
    /// is blocked.
    fn sealable(&self, contact: ContactId) -> Result<(), Error> {
        if self.pending_bundle(contact)?.is_some() {
            return Err(Error::KeyChanged);
        }
        if self.contact_flags(contact)? & BLOCKED != 0 {
            return Err(Error::NotApproved);
        }
        Ok(())
    }

    /// Attaches the Secure Enclave's DER signature over the letter's digest,
    /// after checking it with the own identity key (`Signing` otherwise).
    pub fn attach_signature(&self, letter: &mut Letter, der: &[u8]) -> Result<(), Error> {
        let raw = self.verify_own(&letter.envelope.signed_bytes(), der)?;
        letter.envelope.signature = raw.to_vec();
        Ok(())
    }

    /// Stores the own copy of a signed letter the relay has accepted: its
    /// thread and message rows, sealed by [`Core::seal_letter`], in one
    /// transaction, with an empty proof. An unsigned letter gives
    /// `Malformed`.
    pub fn store_sent(&mut self, letter: &Letter) -> Result<ThreadId, Error> {
        self.dek()?;
        if !letter.is_signed() {
            return Err(Error::Malformed);
        }
        let tx = self.db_mut().transaction()?;
        tx.execute(
            "INSERT INTO threads (id, contact_id, created_at, subject) VALUES (?1, ?2, ?3, ?4)",
            params![
                &letter.thread[..],
                &letter.contact[..],
                letter.created_at,
                letter.subject
            ],
        )?;
        tx.execute(
            "INSERT INTO messages (id, thread_id, created_at, outgoing, read, body, proof) VALUES (?1, ?2, ?3, 1, 1, ?4, ?5)",
            params![
                &letter.message[..],
                &letter.thread[..],
                letter.created_at,
                letter.body,
                letter.proof
            ],
        )?;
        tx.commit()?;
        Ok(ThreadId(letter.thread))
    }

    /// All threads, oldest first.
    pub fn threads(&self) -> Result<Vec<Thread>, Error> {
        let dek = self.dek()?;
        let mut stmt = self.db().prepare(
            "SELECT id, contact_id, created_at, subject FROM threads ORDER BY created_at, rowid",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, [u8; 16]>(0)?,
                r.get::<_, [u8; 16]>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Vec<u8>>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, contact, created_at, subject) = row?;
            let subject =
                crypto::open_column(dek, &subject_ad(&id, &contact, created_at), &subject)?;
            out.push(Thread {
                id: ThreadId(id),
                contact: ContactId(contact),
                created_at,
                subject,
            });
        }
        Ok(out)
    }

    /// Metadata of the messages in `thread`, oldest first. Decrypts nothing.
    pub fn messages(&self, thread: ThreadId) -> Result<Vec<Message>, Error> {
        self.dek()?;
        let mut stmt = self.db().prepare(
            "SELECT id, created_at, outgoing, read FROM messages WHERE thread_id = ?1 ORDER BY created_at, rowid",
        )?;
        let rows = stmt.query_map([&thread.0[..]], |r| {
            Ok(Message {
                id: MessageId(r.get(0)?),
                thread,
                created_at: r.get(1)?,
                outgoing: r.get(2)?,
                read: r.get(3)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Decrypts one message body.
    pub fn read_body(&self, message: MessageId) -> Result<Plaintext, Error> {
        let dek = self.dek()?;
        let (thread, contact, outgoing, created_at, body): (
            [u8; 16],
            [u8; 16],
            bool,
            i64,
            Vec<u8>,
        ) = self.db().query_row(
            "SELECT m.thread_id, t.contact_id, m.outgoing, m.created_at, m.body
                 FROM messages m JOIN threads t ON t.id = m.thread_id WHERE m.id = ?1",
            [&message.0[..]],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )?;
        let ad = message_ad(
            "messages.body",
            &message.0,
            &thread,
            &contact,
            outgoing,
            created_at,
        );
        Ok(crypto::open_column(dek, &ad, &body)?)
    }

    /// The Hand result of a received letter (docs/AUTHORSHIP.md §6): what
    /// [`Core::receive`] stored, rebuilt by brev-hand's
    /// `Verification::decode` under [`KEY_RULE`]. `None` for a sent letter,
    /// whose proof is empty. The proof must open under
    /// the row's AD, which holds the direction (`Crypto` otherwise), and
    /// decode (`Corrupt` otherwise).
    pub fn proof(&self, message: MessageId) -> Result<Option<Verification>, Error> {
        let dek = self.dek()?;
        let (thread, contact, outgoing, created_at, sealed): (
            [u8; 16],
            [u8; 16],
            bool,
            i64,
            Vec<u8>,
        ) = self.db().query_row(
            "SELECT m.thread_id, t.contact_id, m.outgoing, m.created_at, m.proof
                 FROM messages m JOIN threads t ON t.id = m.thread_id WHERE m.id = ?1",
            [&message.0[..]],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )?;
        let ad = message_ad(
            "messages.proof",
            &message.0,
            &thread,
            &contact,
            outgoing,
            created_at,
        );
        let proof = crypto::open_column(dek, &ad, &sealed)?;
        match (outgoing, proof.is_empty()) {
            (true, true) => Ok(None),
            (false, false) => Verification::decode(&proof, KEY_RULE)
                .map(Some)
                .ok_or(Error::Corrupt),
            _ => Err(Error::Corrupt),
        }
    }

    /// The thread a message belongs to. Metadata only: decrypts nothing, but
    /// goes through the gate like every other call.
    pub fn thread_of(&self, message: MessageId) -> Result<ThreadId, Error> {
        self.dek()?;
        Ok(ThreadId(self.db().query_row(
            "SELECT thread_id FROM messages WHERE id = ?1",
            [&message.0[..]],
            |r| r.get(0),
        )?))
    }

    /// Marks a message read.
    pub fn mark_read(&mut self, message: MessageId) -> Result<(), Error> {
        self.dek()?;
        let n = self.db().execute(
            "UPDATE messages SET read = 1 WHERE id = ?1",
            [&message.0[..]],
        )?;
        if n == 0 {
            return Err(Error::NotFound);
        }
        Ok(())
    }

    /// Checks an envelope in the order of docs/PHASE3_DESIGN.md §3.3 and
    /// stores its letter. [`is_permanent`] sorts the errors: a permanent
    /// one is the letter's fault and it is acknowledged and dropped; any
    /// other is local (a damaged or swapped row, a failed write) and the
    /// letter is fetched again later.
    ///
    /// 1. addressed to me (`Malformed`);
    /// 2. the keyed tag of the sender finds a contact (`NotFound`: a
    ///    stranger, or a contact's new key before it is accepted);
    /// 3. that contact's bundle opens and hashes to the sender (`Corrupt`),
    ///    and its flags open (`Corrupt`) and do not say blocked (`NotFound`,
    ///    like a stranger; docs/PHASE4_DESIGN.md owner answer 6);
    /// 4. the signature over the signed bytes, with the pinned signing key
    ///    (`Crypto`), before anything is decrypted;
    /// 5. the AEAD (`Crypto`), then padding and the payload's shape
    ///    (`Malformed`): protocol version 2's letter and token, strictly
    ///    framed, the token at most `MAX_TOKEN` bytes;
    /// 6. for a known thread, its subject opens (`Corrupt`) and its owner is
    ///    the sender (`Malformed`);
    /// 7. the insert (`Duplicate` for a stored message id: a replayed letter,
    ///    docs/AUTHORSHIP.md §6 step 5).
    ///
    /// The token is checked (brev-hand's `verify`, with the pinned signing
    /// key that verified the envelope, the relay's `received_at`, Unix
    /// seconds, and [`KEY_RULE`]) and its result is sealed beside the
    /// letter. A token that fails does not refuse the letter: the letter is
    /// stored with its failed result, and the app shows «Ikke verifisert».
    pub fn receive(&mut self, env: &Envelope, received_at: u64) -> Result<MessageId, Error> {
        let dek = self.dek()?;
        let now = now();
        // The identity secret and the decrypted letter live only inside this
        // block, so neither is alive during the commit (a full fsync).
        let (id, thread, contact, new_subject, body, proof) = {
            if env.recipient != self.my_id().map_err(local)? {
                return Err(Error::Malformed);
            }
            let tag = crypto::contact_tag(dek, &env.sender);
            let contact: [u8; 16] =
                self.db()
                    .query_row("SELECT id FROM contacts WHERE tag = ?1", [&tag[..]], |r| {
                        r.get(0)
                    })?;
            let bundle = self.contact_bundle(ContactId(contact)).map_err(local)?;
            if bundle.id().0 != env.sender {
                return Err(Error::Corrupt);
            }
            if self.contact_flags(ContactId(contact)).map_err(local)? & BLOCKED != 0 {
                return Err(Error::NotFound);
            }
            let signature: &[u8; SIG_LEN] = env
                .signature
                .as_slice()
                .try_into()
                .map_err(|_| Error::Crypto)?;
            sig::verify(&bundle.signing_key, &env.signed_bytes(), signature)
                .map_err(|_| Error::Crypto)?;
            let payload = {
                let me = self.me().map_err(local)?;
                crypto::open_message(&me.secret, &bundle.x25519, env)?
            };
            let (letter, token) = decode_v2(&payload)?;
            let (id, thread, subject, body) = decode_payload(letter)?;
            let proof =
                brev_hand::verify(letter, token, &bundle.signing_key, received_at, KEY_RULE)
                    .encode(token);

            let existing: Option<([u8; 16], i64, Vec<u8>)> = self
                .db()
                .query_row(
                    "SELECT contact_id, created_at, subject FROM threads WHERE id = ?1",
                    [&thread[..]],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            let new_subject = match existing {
                Some((owner, created_at, sealed)) => {
                    // Authenticates `owner` before trusting it.
                    crypto::open_column(dek, &subject_ad(&thread, &owner, created_at), &sealed)
                        .map_err(|e| local(e.into()))?;
                    if owner != contact {
                        return Err(Error::Malformed);
                    }
                    None
                }
                None => Some(crypto::seal_column(
                    dek,
                    &subject_ad(&thread, &contact, now),
                    subject,
                )?),
            };
            let ad = |label| message_ad(label, &id, &thread, &contact, false, now);
            (
                id,
                thread,
                contact,
                new_subject,
                crypto::seal_column(dek, &ad("messages.body"), body)?,
                crypto::seal_column(dek, &ad("messages.proof"), &proof)?,
            )
        };

        let tx = self.db_mut().transaction()?;
        if let Some(subject) = new_subject {
            tx.execute(
                "INSERT INTO threads (id, contact_id, created_at, subject) VALUES (?1, ?2, ?3, ?4)",
                params![&thread[..], &contact[..], now, subject],
            )?;
        }
        let n = tx.execute(
            "INSERT INTO messages (id, thread_id, created_at, outgoing, read, body, proof) VALUES (?1, ?2, ?3, 0, 0, ?4, ?5)
             ON CONFLICT (id) DO NOTHING",
            params![&id[..], &thread[..], now, body, proof],
        )?;
        if n == 0 {
            return Err(Error::Duplicate); // dropping `tx` rolls back
        }
        tx.commit()?;
        Ok(MessageId(id))
    }

    /// Second half of `create`: the vault makes the file (mode 0600) and
    /// the schema, and the identity row goes in with them. The file is
    /// removed on any failure.
    fn init(path: &Path, slot: DekSlot, signing_key: &[u8; sig::KEY_LEN]) -> Result<Core, Error> {
        // The X25519 secret and the token live only inside `seal`, so they
        // are gone before the commit.
        let seal = |dek: &[u8; 32]| -> Result<_, Error> {
            let mut secret = Zeroizing::new([0u8; 32]);
            crypto::fill(secret.as_mut_slice())?;
            let mut token = Zeroizing::new([0u8; 32]);
            crypto::fill(token.as_mut_slice())?;
            let x25519 = crypto::public_key(&*crypto::static_secret(secret.as_slice())?);
            let id = brev_proto::identity_id(signing_key, &x25519);
            let keys = identity_row(&secret, &x25519, signing_key, &token);
            let sealed = crypto::seal_column(dek, &column_ad("identity.keys", &[&id]), &keys)?;
            let address = crypto::seal_column(dek, &column_ad("identity.address", &[&id]), &[])?;
            Ok((id, sealed, address))
        };
        let insert = |tx: &Transaction<'_>, (id, keys, address): ([u8; 32], Vec<u8>, Vec<u8>)| {
            tx.execute(
                "INSERT INTO identity (id, keys, address) VALUES (?1, ?2, ?3)",
                params![&id[..], keys, address],
            )?;
            Ok::<_, Error>(())
        };
        Ok(Core {
            v: Vault::create(path, slot, &MAIL, seal, insert)?,
        })
    }

    /// The single gate: every content call goes through here.
    fn dek(&self) -> Result<&[u8; 32], Error> {
        Ok(self.v.dek()?)
    }

    /// The connection: ids, metadata and ciphertext only.
    fn db(&self) -> &Connection {
        self.v.db()
    }

    /// The connection, for a transaction.
    fn db_mut(&mut self) -> &mut Connection {
        self.v.db_mut()
    }

    /// Wraps `p` in a text that [`Core::lock`] closes.
    pub(crate) fn open_text(&mut self, p: Plaintext) -> Arc<Text> {
        self.v.open_text(p)
    }

    /// The vault's clock, for the session's timer.
    pub(crate) fn clock(&self) -> Arc<Clock> {
        self.v.clock()
    }

    /// Own identity id (plaintext column), behind the gate.
    fn my_id(&self) -> Result<[u8; 32], Error> {
        self.dek()?;
        Ok(self
            .db()
            .query_row("SELECT id FROM identity", [], |r| r.get(0))?)
    }

    /// Own id and the decrypted identity row (X25519 secret || X25519
    /// public || signing key || relay token).
    fn identity_keys(&self) -> Result<([u8; 32], Plaintext), Error> {
        let dek = self.dek()?;
        open_identity(self.db(), dek)
    }

    /// Decrypts the own identity for one operation; the secret is wiped on drop.
    fn me(&self) -> Result<Me, Error> {
        let (id, keys) = self.identity_keys()?;
        let secret = keys.get(KEY_SECRET).ok_or(Error::Crypto)?;
        let me = Me {
            id,
            secret: crypto::static_secret(secret)?,
        };
        // Reaches only the frames below this one. In release builds
        // `static_secret` is inlined here and `me()` may be inlined into its
        // caller, so the by-value [u8; 32] and the `Me` being built can sit
        // in the caller's own frame, which no scrub reaches until that frame
        // returns. So call `me()` only where the secret is needed.
        crypto::scrub_stack();
        Ok(me)
    }

    fn set_pending(&mut self, contact: ContactId, bundle: &[u8]) -> Result<(), Error> {
        let dek = self.dek()?;
        let sealed =
            crypto::seal_column(dek, &column_ad("contacts.pending", &[&contact.0]), bundle)?;
        self.db().execute(
            "UPDATE contacts SET pending = ?1 WHERE id = ?2",
            params![sealed, &contact.0[..]],
        )?;
        Ok(())
    }

    #[cfg(test)]
    fn dek_for_test(&self) -> [u8; 32] {
        self.v.dek_for_test()
    }

    #[cfg(test)]
    fn dek_addr_for_test(&self) -> usize {
        self.v.dek_addr_for_test()
    }

    /// Test only: the texts handed out and not yet closed by a lock.
    #[cfg(test)]
    pub(crate) fn open_texts_for_test(&self) -> &[Weak<Text>] {
        self.v.open_texts_for_test()
    }
}

/// The ungated half of `Core::identity_keys`: the own id and the identity
/// row opened with `dek`. Also the key check of `unlock`.
fn open_identity(db: &Connection, dek: &[u8; 32]) -> Result<([u8; 32], Plaintext), Error> {
    let (id, sealed): ([u8; 32], Vec<u8>) =
        db.query_row("SELECT id, keys FROM identity", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?;
    let keys = crypto::open_column(dek, &column_ad("identity.keys", &[&id]), &sealed)?;
    Ok((id, keys))
}

/// True for the [`Core::receive`] errors that are the letter's fault: it is
/// acknowledged and dropped (`Malformed`, `NotFound`, `Crypto`, `Duplicate`;
/// class P of docs/PHASE3_DESIGN.md §3.3). Every other error is local (class
/// L): the letter stays at the relay and comes again.
pub(crate) fn is_permanent(e: &Error) -> bool {
    matches!(
        e,
        Error::Malformed | Error::NotFound | Error::Crypto | Error::Duplicate
    )
}

/// A local row that fails to open or parse during `receive` is damaged or
/// swapped: `Corrupt` (class L), never one of the permanent errors, so the
/// letter is not dropped because of the row.
fn local(e: Error) -> Error {
    match e {
        Error::Crypto | Error::Malformed | Error::NotFound => Error::Corrupt,
        e => e,
    }
}

/// AD for `contacts.flags`: local contact id, and the tag of the key the
/// flags describe.
fn flags_ad(contact: &[u8; 16], tag: &[u8; 32]) -> Vec<u8> {
    column_ad("contacts.flags", &[contact, tag])
}

/// AD for `threads.subject`: thread id, local contact id, created_at.
fn subject_ad(id: &[u8; 16], contact: &[u8; 16], created_at: i64) -> Vec<u8> {
    column_ad("threads.subject", &[id, contact, &created_at.to_be_bytes()])
}

/// AD for `messages.body` and `messages.proof` (`label`): message id,
/// thread id, the thread's local contact id, direction, created_at.
fn message_ad(
    label: &str,
    id: &[u8; 16],
    thread: &[u8; 16],
    contact: &[u8; 16],
    outgoing: bool,
    created_at: i64,
) -> Vec<u8> {
    column_ad(
        label,
        &[
            id,
            thread,
            contact,
            &[u8::from(outgoing)],
            &created_at.to_be_bytes(),
        ],
    )
}

/// The identity row: `X25519 secret (32) || X25519 public (32) || signing
/// key (65) || relay token (32)`. Returned as a [`Plaintext`], so its type
/// pins the wipe on drop.
fn identity_row(
    secret: &[u8; 32],
    x25519: &[u8; 32],
    signing_key: &[u8; sig::KEY_LEN],
    token: &[u8; 32],
) -> Plaintext {
    let cap = KEY_TOKEN.end;
    let mut keys = Zeroizing::new(Vec::with_capacity(cap));
    keys.extend_from_slice(secret);
    keys.extend_from_slice(x25519);
    keys.extend_from_slice(signing_key);
    keys.extend_from_slice(token);
    debug_assert_eq!(keys.capacity(), cap, "identity key buffer reallocated");
    Plaintext::new(keys)
}

/// Payload inside the message AEAD:
/// `message id (16) || thread id (16) || subject length (u16 BE) || subject || body`.
/// Returned as a [`Plaintext`], so the tests' live counter sees it.
fn encode_payload(
    id: &[u8; 16],
    thread: &[u8; 16],
    subject: &[u8],
    body: &[u8],
) -> Result<Plaintext, Error> {
    let len = u16::try_from(subject.len()).map_err(|_| Error::Malformed)?;
    let cap = 34 + subject.len() + body.len();
    let mut p = Zeroizing::new(Vec::with_capacity(cap));
    p.extend_from_slice(id);
    p.extend_from_slice(thread);
    p.extend_from_slice(&len.to_be_bytes());
    p.extend_from_slice(subject);
    p.extend_from_slice(body);
    debug_assert_eq!(p.capacity(), cap, "payload buffer reallocated");
    Ok(Plaintext::new(p))
}

/// Message id, thread id, subject and body borrowed from a decrypted payload.
type Decoded<'a> = ([u8; 16], [u8; 16], &'a [u8], &'a [u8]);

fn decode_payload(p: &[u8]) -> Result<Decoded<'_>, Error> {
    let field = |r: std::ops::Range<usize>| p.get(r).ok_or(Error::Malformed);
    let id: [u8; 16] = field(0..16)?.try_into().map_err(|_| Error::Malformed)?;
    let thread: [u8; 16] = field(16..32)?.try_into().map_err(|_| Error::Malformed)?;
    let len: [u8; 2] = field(32..34)?.try_into().map_err(|_| Error::Malformed)?;
    let end = 34 + usize::from(u16::from_be_bytes(len));
    Ok((id, thread, field(34..end)?, &p[end..]))
}

/// The payload inside the message AEAD, protocol version 2
/// (docs/AUTHORSHIP.md §2.5): `letter length (u32 BE) || letter || token
/// length (u16 BE) || token`, where `letter` is [`encode_payload`]'s
/// layout. A token over `MAX_TOKEN` bytes is `Malformed`. Returned as a
/// [`Plaintext`], so the tests' live counter sees it.
fn encode_v2(letter: &[u8], token: &[u8]) -> Result<Plaintext, Error> {
    let letter_len = u32::try_from(letter.len()).map_err(|_| Error::Malformed)?;
    if token.len() > MAX_TOKEN {
        return Err(Error::Malformed);
    }
    let token_len = u16::try_from(token.len()).map_err(|_| Error::Malformed)?;
    let cap = 6 + letter.len() + token.len();
    let mut p = Zeroizing::new(Vec::with_capacity(cap));
    p.extend_from_slice(&letter_len.to_be_bytes());
    p.extend_from_slice(letter);
    p.extend_from_slice(&token_len.to_be_bytes());
    p.extend_from_slice(token);
    debug_assert_eq!(p.capacity(), cap, "payload buffer reallocated");
    Ok(Plaintext::new(p))
}

/// The letter and the token of a protocol version 2 payload, borrowed from
/// it. Strict: the two lengths and their bytes make up the whole payload,
/// and the token is at most `MAX_TOKEN` bytes; `Malformed` otherwise.
fn decode_v2(p: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    let (len, rest) = p.split_first_chunk::<4>().ok_or(Error::Malformed)?;
    let len = usize::try_from(u32::from_be_bytes(*len)).map_err(|_| Error::Malformed)?;
    let (letter, rest) = rest.split_at_checked(len).ok_or(Error::Malformed)?;
    let (len, token) = rest.split_first_chunk::<2>().ok_or(Error::Malformed)?;
    if usize::from(u16::from_be_bytes(*len)) != token.len() || token.len() > MAX_TOKEN {
        return Err(Error::Malformed);
    }
    Ok((letter, token))
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests;
