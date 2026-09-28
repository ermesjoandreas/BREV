//! The encrypted store and the `Locked`/`Unlocked` state machine.
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

use std::fs::{self, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use brev_proto::body::{self, is_valid_address};
use brev_proto::{identity_code, sig, IDENTITY_CODE_LEN, SIG_LEN};
use rusqlite::config::DbConfig;
use rusqlite::{params, Connection, ErrorCode, OpenFlags, OptionalExtension};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{self, column_ad, Plaintext};
use crate::{Envelope, Error};

/// "BREV" in the SQLite header's application_id field.
const APPLICATION_ID: i32 = 0x4252_4556;
/// 3: local contact ids, the keyed contact tag, sealed addresses and
/// `pending`, the relay token in `identity.keys` (docs/PHASE3_DESIGN.md
/// §6.1). A version 2 store opens as `Corrupt`.
const SCHEMA_VERSION: i32 = 3;

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
    pending    BLOB NOT NULL               -- ct: empty, or the other bundle the relay returned
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
    body       BLOB NOT NULL               -- ct
) STRICT;
CREATE INDEX messages_by_thread ON messages(thread_id, created_at);
";

/// Layout of the decrypted `identity.keys`: X25519 secret, X25519 public,
/// signing key, relay token.
const KEY_SECRET: std::ops::Range<usize> = 0..32;
const KEY_X25519: std::ops::Range<usize> = 32..64;
const KEY_SIGNING: std::ops::Range<usize> = 64..64 + sig::KEY_LEN;
const KEY_TOKEN: std::ops::Range<usize> = 64 + sig::KEY_LEN..96 + sig::KEY_LEN;

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
}

/// One user's encrypted store plus session state.
pub struct Core {
    db: Connection,
    /// The DEK. Allocated once per `Core` and never moved or reallocated, so
    /// `lock()` wipes the only copy the core holds.
    dek: Box<Zeroizing<[u8; 32]>>,
    unlocked: bool,
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
    /// the same mode). The new core is unlocked.
    pub fn create(path: &Path, dek: &mut [u8; 32], signing_key: &[u8]) -> Result<Core, Error> {
        let mut slot = Box::new(Zeroizing::new([0u8; 32]));
        slot.copy_from_slice(dek);
        dek.zeroize();
        check_path(path)?;
        if crypto::is_zero(&slot) {
            return Err(Error::Malformed);
        }
        let signing_key = sig::check_key(signing_key).map_err(|_| Error::Malformed)?;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        let result = Core::init(path, slot, signing_key);
        if result.is_err() {
            let _ = fs::remove_file(path);
        }
        result
    }

    /// Opens an existing store, locked. Refuses a file that is not a Brev
    /// store of this schema version, before writing anything to it.
    pub fn open(path: &Path) -> Result<Core, Error> {
        check_path(path)?;
        let core = Core::connect(path, Box::new(Zeroizing::new([0u8; 32])))?;
        verify_store(&core.db).map_err(not_a_store)?;
        set_journal_mode(&core.db)?;
        Ok(core)
    }

    /// Unlocks with `dek`, which is zeroed before this returns. An all-zero
    /// DEK, or one that cannot open the identity row, gives `WrongKey`; any
    /// failure leaves the core locked.
    pub fn unlock(&mut self, dek: &mut [u8; 32]) -> Result<(), Error> {
        self.dek.copy_from_slice(dek);
        dek.zeroize();
        if crypto::is_zero(&self.dek) {
            self.lock();
            return Err(Error::WrongKey);
        }
        self.unlocked = true;
        // Opening the identity row is the key check. The X25519 secret is
        // not needed, so it is never built and never copied onto the stack.
        match self.identity_keys() {
            Ok(_) => Ok(()),
            Err(e) => {
                self.lock();
                Err(if matches!(e, Error::Crypto) {
                    Error::WrongKey
                } else {
                    e
                })
            }
        }
    }

    /// Zeroes the DEK and locks. Idempotent. The core holds no other key or
    /// plaintext between calls, so this is all there is to wipe.
    pub fn lock(&mut self) {
        self.dek.zeroize();
        self.unlocked = false;
        crypto::scrub_stack();
    }

    /// True while locked.
    pub fn is_locked(&self) -> bool {
        !self.unlocked
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
            self.db
                .query_row("SELECT id, address FROM identity", [], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })?;
        crypto::open_column(dek, &column_ad("identity.address", &[&id]), &sealed)
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
        self.db
            .execute("UPDATE identity SET address = ?1", [sealed])?;
        Ok(())
    }

    /// The registration body without its signature (docs/PHASE3_DESIGN.md
    /// §2.4): `address`, both public keys and SHA-256 of the relay token.
    /// The identity key signs `body::register_preimage` of it.
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
        let dek = self.dek()?;
        if &self.address()?[..] == address {
            return Err(Error::Malformed);
        }
        let mut stmt = self.db.prepare("SELECT id, address FROM contacts")?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, [u8; 16]>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?;
        for row in rows {
            let (id, sealed) = row?;
            let known = crypto::open_column(dek, &column_ad("contacts.address", &[&id]), &sealed)?;
            if &known[..] == address {
                return Err(Error::Duplicate);
            }
        }
        Ok(())
    }

    /// Adds a contact with the bundle the relay returned for `address`, and
    /// pins it (trust on first use). Refuses an address that breaks the
    /// rules or is the own one and the own identity (`Malformed`), and an
    /// address or identity that is already a contact (`Duplicate`).
    pub fn add_contact(
        &mut self,
        bundle: &PublicBundle,
        address: &[u8],
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
        // Any uniqueness conflict: the same identity (tag) is already there.
        let n = self.db.execute(
            "INSERT INTO contacts (id, tag, bundle, address, pending) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT DO NOTHING",
            params![&id[..], &tag[..], sealed_bundle, sealed_address, pending],
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
            .db
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
            out.push(Contact {
                id: ContactId(id),
                address,
                key_changed,
            });
        }
        Ok(out)
    }

    /// One contact's address.
    pub fn contact_address(&self, contact: ContactId) -> Result<Plaintext, Error> {
        let dek = self.dek()?;
        let sealed: Vec<u8> = self.db.query_row(
            "SELECT address FROM contacts WHERE id = ?1",
            [&contact.0[..]],
            |r| r.get(0),
        )?;
        crypto::open_column(dek, &column_ad("contacts.address", &[&contact.0]), &sealed)
    }

    /// The pinned bundle of `contact`. It must open under the row's AD
    /// (`Crypto` otherwise) and hash to an id whose tag is the row's `tag`
    /// (`Corrupt` otherwise), so a bundle or tag swapped between rows is
    /// caught.
    pub fn contact_bundle(&self, contact: ContactId) -> Result<PublicBundle, Error> {
        let dek = self.dek()?;
        let (tag, sealed): ([u8; 32], Vec<u8>) = self.db.query_row(
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
        let sealed: Vec<u8> = self.db.query_row(
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
        if found.id().0 == self.my_id()? {
            return Err(Error::Malformed);
        }
        let pinned = self.contact_bundle(contact)?;
        let pending = self.pending_bundle(contact)?;
        if pinned == *found {
            if pending.is_some() {
                self.set_pending(contact, &[])?;
            }
            return Ok(());
        }
        if pending.as_ref() != Some(found) {
            self.set_pending(contact, &found.to_bytes())?;
        }
        Err(Error::KeyChanged)
    }

    /// Pins the pending bundle of `contact`, if `code` is its identity code:
    /// the code the app is showing (`KeyChanged` otherwise, also when no key
    /// change is pending). One statement sets the tag and the bundle and
    /// empties `pending`; a key that belongs to another contact gives
    /// `Duplicate`. The contact keeps its local id and its threads.
    pub fn accept_new_key(&mut self, contact: ContactId, code: &[u8]) -> Result<(), Error> {
        let dek = self.dek()?;
        let pending = self.pending_bundle(contact)?.ok_or(Error::KeyChanged)?;
        if pending.code()[..] != *code {
            return Err(Error::KeyChanged);
        }
        let tag = crypto::contact_tag(dek, &pending.id().0);
        let taken: Option<i64> = self
            .db
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
        self.db.execute(
            "UPDATE contacts SET tag = ?1, bundle = ?2, pending = ?3 WHERE id = ?4",
            params![&tag[..], sealed_bundle, empty, &contact.0[..]],
        )?;
        Ok(())
    }

    /// Seals a letter to `contact` that starts a new thread: the payload
    /// (padded) in an envelope without signature, and the subject and body
    /// under the DEK for the own copy. Every decrypted value and the X25519
    /// secret are dropped before this returns. `KeyChanged` while the
    /// contact's key change is pending, before anything is sealed. Subjects
    /// are limited to 65535 bytes. Stores nothing.
    pub fn seal_letter(
        &self,
        contact: ContactId,
        subject: &[u8],
        body: &[u8],
    ) -> Result<Letter, Error> {
        let dek = self.dek()?;
        if self.pending_bundle(contact)?.is_some() {
            return Err(Error::KeyChanged);
        }
        u16::try_from(subject.len()).map_err(|_| Error::Malformed)?;
        let bundle = self.contact_bundle(contact)?;
        let thread: [u8; 16] = crypto::random()?;
        let message: [u8; 16] = crypto::random()?;
        let now = now();
        // The payload and the identity secret live only inside this block.
        let (envelope, subject, body) = {
            let me = self.me()?;
            let payload = encode_payload(&message, &thread, subject, body)?;
            let env =
                crypto::seal_message(&me.secret, &bundle.x25519, me.id, bundle.id().0, &payload)?;
            let subject = crypto::seal_column(dek, &subject_ad(&thread, &contact.0, now), subject)?;
            let body = crypto::seal_column(
                dek,
                &body_ad(&message, &thread, &contact.0, true, now),
                body,
            )?;
            (env, subject, body)
        };
        crypto::scrub_stack();
        Ok(Letter {
            contact: contact.0,
            thread,
            message,
            created_at: now,
            subject,
            body,
            envelope,
        })
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
    /// transaction. An unsigned letter gives `Malformed`.
    pub fn store_sent(&mut self, letter: &Letter) -> Result<ThreadId, Error> {
        self.dek()?;
        if !letter.is_signed() {
            return Err(Error::Malformed);
        }
        let tx = self.db.transaction()?;
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
            "INSERT INTO messages (id, thread_id, created_at, outgoing, read, body) VALUES (?1, ?2, ?3, 1, 1, ?4)",
            params![
                &letter.message[..],
                &letter.thread[..],
                letter.created_at,
                letter.body
            ],
        )?;
        tx.commit()?;
        Ok(ThreadId(letter.thread))
    }

    /// All threads, oldest first.
    pub fn threads(&self) -> Result<Vec<Thread>, Error> {
        let dek = self.dek()?;
        let mut stmt = self.db.prepare(
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
        let mut stmt = self.db.prepare(
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
        ) = self.db.query_row(
            "SELECT m.thread_id, t.contact_id, m.outgoing, m.created_at, m.body
                 FROM messages m JOIN threads t ON t.id = m.thread_id WHERE m.id = ?1",
            [&message.0[..]],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )?;
        let ad = body_ad(&message.0, &thread, &contact, outgoing, created_at);
        crypto::open_column(dek, &ad, &body)
    }

    /// The thread a message belongs to. Metadata only: decrypts nothing, but
    /// goes through the gate like every other call.
    pub fn thread_of(&self, message: MessageId) -> Result<ThreadId, Error> {
        self.dek()?;
        Ok(ThreadId(self.db.query_row(
            "SELECT thread_id FROM messages WHERE id = ?1",
            [&message.0[..]],
            |r| r.get(0),
        )?))
    }

    /// Marks a message read.
    pub fn mark_read(&mut self, message: MessageId) -> Result<(), Error> {
        self.dek()?;
        let n = self.db.execute(
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
    /// 3. that contact's bundle opens and hashes to the sender (`Corrupt`);
    /// 4. the signature over the signed bytes, with the pinned signing key
    ///    (`Crypto`), before anything is decrypted;
    /// 5. the AEAD (`Crypto`), then padding and payload shape (`Malformed`);
    /// 6. for a known thread, its subject opens (`Corrupt`) and its owner is
    ///    the sender (`Malformed`);
    /// 7. the insert (`Duplicate` for a stored message id).
    pub fn receive(&mut self, env: &Envelope) -> Result<MessageId, Error> {
        let dek = self.dek()?;
        let now = now();
        // The identity secret and the decrypted letter live only inside this
        // block, so neither is alive during the commit (a full fsync).
        let (id, thread, contact, new_subject, body) = {
            if env.recipient != self.my_id().map_err(local)? {
                return Err(Error::Malformed);
            }
            let tag = crypto::contact_tag(dek, &env.sender);
            let contact: [u8; 16] =
                self.db
                    .query_row("SELECT id FROM contacts WHERE tag = ?1", [&tag[..]], |r| {
                        r.get(0)
                    })?;
            let bundle = self.contact_bundle(ContactId(contact)).map_err(local)?;
            if bundle.id().0 != env.sender {
                return Err(Error::Corrupt);
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
            let (id, thread, subject, body) = decode_payload(&payload)?;

            let existing: Option<([u8; 16], i64, Vec<u8>)> = self
                .db
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
                        .map_err(local)?;
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
            let ad = body_ad(&id, &thread, &contact, false, now);
            (
                id,
                thread,
                contact,
                new_subject,
                crypto::seal_column(dek, &ad, body)?,
            )
        };

        let tx = self.db.transaction()?;
        if let Some(subject) = new_subject {
            tx.execute(
                "INSERT INTO threads (id, contact_id, created_at, subject) VALUES (?1, ?2, ?3, ?4)",
                params![&thread[..], &contact[..], now, subject],
            )?;
        }
        let n = tx.execute(
            "INSERT INTO messages (id, thread_id, created_at, outgoing, read, body) VALUES (?1, ?2, ?3, 0, 0, ?4)
             ON CONFLICT (id) DO NOTHING",
            params![&id[..], &thread[..], now, body],
        )?;
        if n == 0 {
            return Err(Error::Duplicate); // dropping `tx` rolls back
        }
        tx.commit()?;
        Ok(MessageId(id))
    }

    /// Second half of `create`, after the file exists.
    fn init(
        path: &Path,
        slot: Box<Zeroizing<[u8; 32]>>,
        signing_key: &[u8; sig::KEY_LEN],
    ) -> Result<Core, Error> {
        let mut core = Core::connect(path, slot)?;
        set_journal_mode(&core.db)?;
        // The X25519 secret and the token live only inside this block, so
        // they are gone before the commit.
        let (id, keys, address) = {
            let mut secret = Zeroizing::new([0u8; 32]);
            crypto::fill(secret.as_mut_slice())?;
            let mut token = Zeroizing::new([0u8; 32]);
            crypto::fill(token.as_mut_slice())?;
            let x25519 = crypto::public_key(&*crypto::static_secret(secret.as_slice())?);
            let id = brev_proto::identity_id(signing_key, &x25519);
            let keys = identity_row(&secret, &x25519, signing_key, &token);
            let sealed =
                crypto::seal_column(&core.dek, &column_ad("identity.keys", &[&id]), &keys)?;
            let address =
                crypto::seal_column(&core.dek, &column_ad("identity.address", &[&id]), &[])?;
            (id, sealed, address)
        };
        let tx = core.db.transaction()?;
        tx.pragma_update(None, "application_id", APPLICATION_ID)?;
        tx.execute_batch(SCHEMA)?;
        tx.execute(
            "INSERT INTO identity (id, keys, address) VALUES (?1, ?2, ?3)",
            params![&id[..], keys, address],
        )?;
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        tx.commit()?;
        core.unlocked = true;
        Ok(core)
    }

    /// Opens the file without CREATE, then applies the per-connection
    /// settings. Writes nothing to the file. The bundled SQLite parses any
    /// name starting with `file:` as a URI whatever the flags say, so only
    /// absolute paths get here (`check_path`).
    fn connect(path: &Path, slot: Box<Zeroizing<[u8; 32]>>) -> Result<Core, Error> {
        let db = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        db.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
        db.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?;
        db.pragma_update(None, "secure_delete", "ON")?;
        db.pragma_update(None, "temp_store", "MEMORY")?;
        db.pragma_update(None, "foreign_keys", "ON")?;
        db.pragma_update(None, "cell_size_check", "ON")?;
        // On macOS plain fsync() does not flush the drive's cache, so a power
        // cut mid-commit could corrupt the only copy of the history.
        db.pragma_update(None, "fullfsync", "ON")?;
        Ok(Core {
            db,
            dek: slot,
            unlocked: false,
        })
    }

    /// The single gate: every content call goes through here.
    fn dek(&self) -> Result<&[u8; 32], Error> {
        if self.unlocked {
            Ok(&self.dek)
        } else {
            Err(Error::Locked)
        }
    }

    /// Own identity id (plaintext column), behind the gate.
    fn my_id(&self) -> Result<[u8; 32], Error> {
        self.dek()?;
        Ok(self
            .db
            .query_row("SELECT id FROM identity", [], |r| r.get(0))?)
    }

    /// Own id and the decrypted identity row (X25519 secret || X25519
    /// public || signing key || relay token).
    fn identity_keys(&self) -> Result<([u8; 32], Plaintext), Error> {
        let dek = self.dek()?;
        let (id, sealed): ([u8; 32], Vec<u8>) =
            self.db
                .query_row("SELECT id, keys FROM identity", [], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })?;
        let keys = crypto::open_column(dek, &column_ad("identity.keys", &[&id]), &sealed)?;
        Ok((id, keys))
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
        self.db.execute(
            "UPDATE contacts SET pending = ?1 WHERE id = ?2",
            params![sealed, &contact.0[..]],
        )?;
        Ok(())
    }

    #[cfg(test)]
    fn dek_for_test(&self) -> [u8; 32] {
        **self.dek
    }

    #[cfg(test)]
    fn dek_addr_for_test(&self) -> usize {
        self.dek.as_ptr().addr()
    }
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

/// SQLite reads a name that starts with `file:` as a URI (the bundled build
/// sets SQLITE_USE_URI), and `:memory:` or `""` as no file at all. An
/// absolute path starts with `/`, so it is always taken literally.
fn check_path(path: &Path) -> Result<(), Error> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(Error::Malformed)
    }
}

/// AD for `threads.subject`: thread id, local contact id, created_at.
fn subject_ad(id: &[u8; 16], contact: &[u8; 16], created_at: i64) -> Vec<u8> {
    column_ad("threads.subject", &[id, contact, &created_at.to_be_bytes()])
}

/// AD for `messages.body`: message id, thread id, the thread's local contact
/// id, direction, created_at.
fn body_ad(
    id: &[u8; 16],
    thread: &[u8; 16],
    contact: &[u8; 16],
    outgoing: bool,
    created_at: i64,
) -> Vec<u8> {
    column_ad(
        "messages.body",
        &[
            id,
            thread,
            contact,
            &[u8::from(outgoing)],
            &created_at.to_be_bytes(),
        ],
    )
}

/// `application_id`, `user_version` and the exact schema must match what
/// `create` writes, so a planted trigger, view or index is refused.
fn verify_store(db: &Connection) -> Result<(), Error> {
    let app: i32 = db.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let version: i32 = db.pragma_query_value(None, "user_version", |r| r.get(0))?;
    let expected = Connection::open_in_memory()?;
    expected.execute_batch(SCHEMA)?;
    if app != APPLICATION_ID || version != SCHEMA_VERSION || schema_of(db)? != schema_of(&expected)?
    {
        return Err(Error::Corrupt);
    }
    Ok(())
}

/// A file SQLite cannot parse (random bytes, an encrypted or damaged
/// database, a header naming an unsupported schema format) is not a Brev
/// store either: `Corrupt`, not `Storage`.
fn not_a_store(e: Error) -> Error {
    match &e {
        Error::Storage(s)
            if matches!(
                s.sqlite_error_code(),
                // `Unknown` is plain SQLITE_ERROR: "unsupported file format".
                Some(ErrorCode::NotADatabase | ErrorCode::DatabaseCorrupt | ErrorCode::Unknown)
            ) =>
        {
            Error::Corrupt
        }
        _ => e,
    }
}

type SchemaRow = (String, String, String, Option<String>);

fn schema_of(db: &Connection) -> Result<Vec<SchemaRow>, Error> {
    let mut stmt =
        db.prepare("SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name")?;
    let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// Rollback journal, deleted after every transaction: no -wal or -shm files.
fn set_journal_mode(db: &Connection) -> Result<(), Error> {
    let mode: String = db.pragma_update_and_check(None, "journal_mode", "DELETE", |r| r.get(0))?;
    if mode != "delete" {
        return Err(Error::Corrupt);
    }
    Ok(())
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

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests;
