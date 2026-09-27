//! The encrypted store and the `Locked`/`Unlocked` state machine.
//!
//! Every content column is a ciphertext BLOB sealed under the DEK, with the
//! row's immutable fields in the AEAD associated data. Only ids, timestamps
//! and flags are plaintext. The core caches no plaintext: every read decrypts
//! into a fresh [`Plaintext`] owned by the caller.

use std::fs::{self, OpenOptions};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::config::DbConfig;
use rusqlite::{params, Connection, ErrorCode, OpenFlags, OptionalExtension};
use x25519_dalek::StaticSecret;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{self, column_ad, Plaintext};
use crate::{Envelope, Error, Signer, Transport};

/// "BREV" in the SQLite header's application_id field.
const APPLICATION_ID: i32 = 0x4252_4556;
const SCHEMA_VERSION: i32 = 1;

const SCHEMA: &str = "
CREATE TABLE identity (
    id         BLOB PRIMARY KEY,           -- pt: own identity id
    keys       BLOB NOT NULL               -- ct: X25519 secret || X25519 public || signing public key
) STRICT;
CREATE TABLE contacts (
    id         BLOB PRIMARY KEY,           -- pt: identity id
    bundle     BLOB NOT NULL,              -- ct: public bundle
    name       BLOB NOT NULL               -- ct
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

/// An identity id: SHA-256 over a [`PublicBundle`]. Used for contacts and as
/// the envelope sender and recipient.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IdentityId(pub [u8; 32]);

/// A thread id, chosen at random by whoever starts the thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ThreadId(pub [u8; 16]);

/// A message id, chosen at random by the sender and shared by both stores.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MessageId(pub [u8; 16]);

/// Everything public about an identity. Its hash is the [`IdentityId`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicBundle {
    /// Signature public key, opaque, 1..=255 bytes: an Ed25519 test key in
    /// Phase 1, the Secure Enclave P-256 key from Phase 2.
    pub signing_key: Vec<u8>,
    /// X25519 public key for encrypting to this identity.
    pub x25519: [u8; 32],
}

impl PublicBundle {
    /// SHA-256("brev/v0/identity" || len || signing key || X25519 key).
    pub fn id(&self) -> IdentityId {
        IdentityId(crypto::identity_id(&self.signing_key, &self.x25519))
    }

    fn encode(&self) -> Result<Vec<u8>, Error> {
        let len = signing_key_len(&self.signing_key)?;
        Ok([&[len][..], &self.signing_key, &self.x25519].concat())
    }

    fn decode(b: &[u8]) -> Result<PublicBundle, Error> {
        let (len, rest) = b.split_first().ok_or(Error::Malformed)?;
        let (signing_key, x25519) = rest
            .split_at_checked(usize::from(*len))
            .ok_or(Error::Malformed)?;
        Ok(PublicBundle {
            signing_key: signing_key.to_vec(),
            x25519: x25519.try_into().map_err(|_| Error::Malformed)?,
        })
    }
}

/// A contact. No `Debug`: the name is content.
pub struct Contact {
    /// Identity id.
    pub id: IdentityId,
    /// Display name (content), wiped on drop.
    pub name: Plaintext,
}

/// A thread with one contact. No `Debug`: the subject is content.
pub struct Thread {
    /// Thread id.
    pub id: ThreadId,
    /// The other party.
    pub contact: IdentityId,
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

/// What one [`Core::receive_all`] call did. Content-free.
#[derive(Debug)]
pub struct Delivery {
    /// New messages stored, in poll order.
    pub received: Vec<MessageId>,
    /// One error per envelope that was not stored: `Duplicate` (replay),
    /// `NotFound` (not a contact), `Crypto` (tampered), `Malformed`, or a
    /// storage failure. The envelope itself is gone (at-most-once).
    pub rejected: Vec<Error>,
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
    secret: StaticSecret,
    /// Test only: counts live `Me` values. A field, not `Drop for Me`, so
    /// fields can still be moved out.
    #[cfg(test)]
    _live: tests::LiveMe,
}

impl Core {
    /// Creates a new store at `path` with a fresh X25519 identity, sealed
    /// under `dek`. `signing_key` is this identity's signature public key.
    /// `dek` is zeroed before anything can fail, so after an error the caller
    /// must make a fresh DEK. Refuses a relative path, an all-zero DEK and an
    /// existing path; on any later failure the new file is removed. The new
    /// core is unlocked.
    pub fn create(path: &Path, dek: &mut [u8; 32], signing_key: &[u8]) -> Result<Core, Error> {
        let mut slot = Box::new(Zeroizing::new([0u8; 32]));
        slot.copy_from_slice(dek);
        dek.zeroize();
        check_path(path)?;
        if crypto::is_zero(&slot) {
            return Err(Error::Malformed);
        }
        signing_key_len(signing_key)?;
        OpenOptions::new().write(true).create_new(true).open(path)?;
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

    /// This identity's public bundle, to hand to a contact out of band.
    pub fn bundle(&self) -> Result<PublicBundle, Error> {
        // Both public keys are in the row, so the X25519 secret is never
        // built and never copied onto the stack (see `me()`).
        let (_, keys) = self.identity_keys()?;
        let (x25519, signing_key) = keys
            .get(32..)
            .and_then(|k| k.split_at_checked(32))
            .ok_or(Error::Crypto)?;
        Ok(PublicBundle {
            x25519: x25519.try_into().map_err(|_| Error::Crypto)?,
            signing_key: signing_key.to_vec(),
        })
    }

    /// Adds a contact; the id is the hash of the bundle. A contact that is
    /// already there gives `Duplicate`.
    pub fn add_contact(&mut self, bundle: &PublicBundle, name: &[u8]) -> Result<IdentityId, Error> {
        let dek = self.dek()?;
        let id = bundle.id();
        if id.0 == self.my_id()? {
            return Err(Error::Malformed);
        }
        let b = crypto::seal_column(
            dek,
            &column_ad("contacts.bundle", &[&id.0]),
            &bundle.encode()?,
        )?;
        let name = crypto::seal_column(dek, &column_ad("contacts.name", &[&id.0]), name)?;
        let n = self.db.execute(
            "INSERT INTO contacts (id, bundle, name) VALUES (?1, ?2, ?3) ON CONFLICT (id) DO NOTHING",
            params![&id.0[..], b, name],
        )?;
        if n == 0 {
            return Err(Error::Duplicate);
        }
        Ok(id)
    }

    /// All contacts.
    pub fn contacts(&self) -> Result<Vec<Contact>, Error> {
        let dek = self.dek()?;
        let mut stmt = self
            .db
            .prepare("SELECT id, name FROM contacts ORDER BY rowid")?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, [u8; 32]>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, name) = row?;
            let name = crypto::open_column(dek, &column_ad("contacts.name", &[&id]), &name)?;
            out.push(Contact {
                id: IdentityId(id),
                name,
            });
        }
        Ok(out)
    }

    /// Starts a thread with `contact` (`NotFound` if it is not a contact).
    /// Subjects are limited to 65535 bytes.
    pub fn new_thread(&mut self, contact: IdentityId, subject: &[u8]) -> Result<ThreadId, Error> {
        let dek = self.dek()?;
        self.contact_bundle(&contact.0)?; // NotFound, or Crypto for a tampered row
        u16::try_from(subject.len()).map_err(|_| Error::Malformed)?;
        let id: [u8; 16] = crypto::random()?;
        let now = now();
        let subject = crypto::seal_column(dek, &subject_ad(&id, &contact.0, now), subject)?;
        self.db.execute(
            "INSERT INTO threads (id, contact_id, created_at, subject) VALUES (?1, ?2, ?3, ?4)",
            params![&id[..], &contact.0[..], now, subject],
        )?;
        Ok(ThreadId(id))
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
                r.get::<_, [u8; 32]>(1)?,
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
                contact: IdentityId(contact),
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
            [u8; 32],
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

    /// Seals `body` into `thread` for the contact and under the DEK, drops
    /// every decrypted value, then has `signer` fill the signature slot and
    /// stores the sent copy. Returns the envelope, ready for a [`Transport`].
    /// If signing fails, nothing is stored.
    pub fn send(
        &mut self,
        thread: ThreadId,
        body: &[u8],
        signer: &dyn Signer,
    ) -> Result<Envelope, Error> {
        let dek = self.dek()?;
        let (contact, created_at, subject): ([u8; 32], i64, Vec<u8>) = self.db.query_row(
            "SELECT contact_id, created_at, subject FROM threads WHERE id = ?1",
            [&thread.0[..]],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        let id: [u8; 16] = crypto::random()?;
        let now = now();
        // The subject, payload and identity secret live only inside this
        // block, so none of them is alive while the signer runs.
        let (mut env, stored) = {
            // Opening the subject authenticates `contact_id` before we encrypt to it.
            let subject =
                crypto::open_column(dek, &subject_ad(&thread.0, &contact, created_at), &subject)?;
            let their_x25519 = self.contact_bundle(&contact)?.x25519;
            let me = self.me()?;
            let payload = encode_payload(&id, &thread.0, &subject, body)?;
            let env = crypto::seal_message(&me.secret, &their_x25519, me.id, contact, &payload)?;
            let ad = body_ad(&id, &thread.0, &contact, true, now);
            (env, crypto::seal_column(dek, &ad, body)?)
        };
        crypto::scrub_stack();
        env.signature = signer.sign(&env.signed_bytes())?;
        self.db.execute(
            "INSERT INTO messages (id, thread_id, created_at, outgoing, read, body) VALUES (?1, ?2, ?3, 1, 1, ?4)",
            params![&id[..], &thread.0[..], now, stored],
        )?;
        Ok(env)
    }

    /// Opens an envelope from a known contact and stores the message. The
    /// signature slot is not checked here (D-0019); the sender is
    /// authenticated by the static-static key agreement.
    pub fn receive(&mut self, env: &Envelope) -> Result<MessageId, Error> {
        let dek = self.dek()?;
        let me = self.me()?;
        if env.recipient != me.id {
            return Err(Error::Malformed);
        }
        let their_x25519 = self.contact_bundle(&env.sender)?.x25519;
        let payload = crypto::open_message(&me.secret, &their_x25519, env)?;
        let (id, thread, subject, body) = decode_payload(&payload)?;
        let now = now();

        let existing: Option<([u8; 32], i64, Vec<u8>)> = self
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
                crypto::open_column(dek, &subject_ad(&thread, &owner, created_at), &sealed)?;
                if owner != env.sender {
                    return Err(Error::Malformed);
                }
                None
            }
            None => Some(crypto::seal_column(
                dek,
                &subject_ad(&thread, &env.sender, now),
                subject,
            )?),
        };
        let body = crypto::seal_column(dek, &body_ad(&id, &thread, &env.sender, false, now), body)?;

        let tx = self.db.transaction()?;
        if let Some(subject) = new_subject {
            tx.execute(
                "INSERT INTO threads (id, contact_id, created_at, subject) VALUES (?1, ?2, ?3, ?4)",
                params![&thread[..], &env.sender[..], now, subject],
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

    /// Polls `net` and receives every envelope on its own, so one replayed,
    /// foreign or tampered envelope never costs the ones behind it. While
    /// locked it returns `Locked` without polling, so nothing is drained.
    pub fn receive_all(&mut self, net: &dyn Transport) -> Result<Delivery, Error> {
        self.dek()?;
        let mut out = Delivery {
            received: Vec::new(),
            rejected: Vec::new(),
        };
        for env in net.poll() {
            match self.receive(&env) {
                Ok(id) => out.received.push(id),
                Err(e) => out.rejected.push(e),
            }
        }
        Ok(out)
    }

    /// Second half of `create`, after the file exists.
    fn init(
        path: &Path,
        slot: Box<Zeroizing<[u8; 32]>>,
        signing_key: &[u8],
    ) -> Result<Core, Error> {
        let mut core = Core::connect(path, slot)?;
        set_journal_mode(&core.db)?;
        let mut secret = Zeroizing::new([0u8; 32]);
        crypto::fill(secret.as_mut_slice())?;
        let x25519 = crypto::public_key(&crypto::static_secret(secret.as_slice())?);
        let id = crypto::identity_id(signing_key, &x25519);
        let cap = 64 + signing_key.len();
        let mut keys = Zeroizing::new(Vec::with_capacity(cap));
        keys.extend_from_slice(secret.as_slice());
        keys.extend_from_slice(&x25519);
        keys.extend_from_slice(signing_key);
        debug_assert_eq!(keys.capacity(), cap, "identity key buffer reallocated");
        let sealed = crypto::seal_column(&core.dek, &column_ad("identity.keys", &[&id]), &keys)?;
        let tx = core.db.transaction()?;
        tx.pragma_update(None, "application_id", APPLICATION_ID)?;
        tx.execute_batch(SCHEMA)?;
        tx.execute(
            "INSERT INTO identity (id, keys) VALUES (?1, ?2)",
            params![&id[..], sealed],
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
    /// public || signing key).
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
        let secret = keys.get(..32).ok_or(Error::Crypto)?;
        let me = Me {
            id,
            secret: crypto::static_secret(secret)?,
            #[cfg(test)]
            _live: tests::LiveMe::new(),
        };
        // Reaches only the frames below this one. In release builds
        // `static_secret` is inlined here and `me()` may be inlined into its
        // caller, so the by-value [u8; 32] and the `Me` being built can sit
        // in the caller's own frame, which no scrub reaches until that frame
        // returns. So call `me()` only where the secret is needed.
        crypto::scrub_stack();
        Ok(me)
    }

    fn contact_bundle(&self, id: &[u8; 32]) -> Result<PublicBundle, Error> {
        let dek = self.dek()?;
        let sealed: Vec<u8> = self.db.query_row(
            "SELECT bundle FROM contacts WHERE id = ?1",
            [&id[..]],
            |r| r.get(0),
        )?;
        let b = crypto::open_column(dek, &column_ad("contacts.bundle", &[id]), &sealed)?;
        PublicBundle::decode(&b)
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

fn signing_key_len(key: &[u8]) -> Result<u8, Error> {
    match u8::try_from(key.len()) {
        Ok(n) if n > 0 => Ok(n),
        _ => Err(Error::Malformed),
    }
}

/// AD for `threads.subject`: thread id, contact id, created_at.
fn subject_ad(id: &[u8; 16], contact: &[u8; 32], created_at: i64) -> Vec<u8> {
    column_ad("threads.subject", &[id, contact, &created_at.to_be_bytes()])
}

/// AD for `messages.body`: message id, thread id, the thread's contact id,
/// direction, created_at.
fn body_ad(
    id: &[u8; 16],
    thread: &[u8; 16],
    contact: &[u8; 32],
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
/// database) is not a Brev store either: `Corrupt`, not `Storage`.
fn not_a_store(e: Error) -> Error {
    match &e {
        Error::Storage(s)
            if matches!(
                s.sqlite_error_code(),
                Some(ErrorCode::NotADatabase | ErrorCode::DatabaseCorrupt)
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
mod tests {
    use std::sync::Mutex;

    use rusqlite::trace::{TraceEvent, TraceEventCodes};

    use super::*;

    thread_local! {
        static LIVE_ME: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    /// The counting field of every [`Me`].
    pub(super) struct LiveMe;

    impl LiveMe {
        pub(super) fn new() -> LiveMe {
            LIVE_ME.with(|n| n.set(n.get() + 1));
            LiveMe
        }
    }

    impl Drop for LiveMe {
        fn drop(&mut self) {
            LIVE_ME.with(|n| n.set(n.get() - 1));
        }
    }

    /// `Me` values (decrypted X25519 identity secrets) alive on this thread.
    fn live_me() -> usize {
        LIVE_ME.with(|n| n.get())
    }

    fn temp_path() -> std::path::PathBuf {
        let r: [u8; 8] = crypto::random().unwrap();
        std::env::temp_dir().join(format!("brev-unit-{:016x}.db", u64::from_le_bytes(r)))
    }

    /// Each core gets its own signing key, so two cores never share an id
    /// even if their X25519 keys were equal.
    fn new_core(path: &Path) -> Core {
        let signing_key: [u8; 32] = crypto::random().unwrap();
        Core::create(path, &mut crypto::random().unwrap(), &signing_key).unwrap()
    }

    /// An envelope from `from` to `to` with a hand-built payload.
    fn seal_from(from: &Core, to: &PublicBundle, payload: &[u8]) -> Envelope {
        let me = from.me().unwrap();
        crypto::seal_message(&me.secret, &to.x25519, me.id, to.id().0, payload).unwrap()
    }

    struct NoSig;
    impl Signer for NoSig {
        fn sign(&self, _: &[u8]) -> Result<Vec<u8>, Error> {
            Ok(Vec::new())
        }
    }

    /// Mandatory lock test, part 2: the DEK buffer itself is zeroed.
    #[test]
    fn lock_zeroes_the_dek_buffer() {
        let path = temp_path();
        let mut key: [u8; 32] = crypto::random().unwrap();
        let original = key;
        let mut core = Core::create(&path, &mut key, &[7; 32]).unwrap();
        assert_eq!(key, [0u8; 32], "caller's DEK copy must be wiped");
        assert_eq!(core.dek_for_test(), original, "positive control");
        let addr = core.dek_addr_for_test();

        core.lock();
        assert_eq!(core.dek_for_test(), [0u8; 32]);
        assert_eq!(core.dek_addr_for_test(), addr, "same buffer, not a new one");

        let mut wrong: [u8; 32] = crypto::random().unwrap();
        assert!(matches!(core.unlock(&mut wrong), Err(Error::WrongKey)));
        assert_eq!(wrong, [0u8; 32]);
        assert!(core.is_locked());
        assert_eq!(core.dek_for_test(), [0u8; 32]);

        let mut right = original;
        let built = crypto::secrets_built();
        core.unlock(&mut right).unwrap();
        assert_eq!(right, [0u8; 32]);
        assert_eq!(core.dek_for_test(), original);
        assert_eq!(core.dek_addr_for_test(), addr);
        core.bundle().unwrap();
        assert_eq!(
            crypto::secrets_built(),
            built,
            "unlock and bundle never build the X25519 secret"
        );

        // All zeros (a wiped buffer, a failed unwrap) also locks a core that
        // was unlocked.
        assert!(matches!(core.unlock(&mut [0u8; 32]), Err(Error::WrongKey)));
        assert!(core.is_locked());
        assert_eq!(core.dek_for_test(), [0u8; 32]);
        assert!(matches!(core.bundle().map(drop), Err(Error::Locked)));

        // So does a failure that is not about the key: the right DEK with
        // the identity row gone.
        right = original;
        core.unlock(&mut right).unwrap();
        core.db.execute("DELETE FROM identity", []).unwrap();
        right = original;
        assert!(matches!(core.unlock(&mut right), Err(Error::NotFound)));
        assert!(core.is_locked());
        assert_eq!(core.dek_for_test(), [0u8; 32]);
        assert!(matches!(core.bundle().map(drop), Err(Error::Locked)));
        drop(core);
        let _ = fs::remove_file(&path);
    }

    /// A store sealed under the all-zero key (a crafted file: `create`
    /// refuses to make one) still does not unlock with zeros, which is what
    /// a caller holds after a failed unwrap or a wiped buffer.
    #[test]
    fn unlock_refuses_all_zero_dek() {
        let path = temp_path();
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        drop(Core::init(&path, Box::new(Zeroizing::new([0u8; 32])), &[7; 32]).unwrap());
        let mut core = Core::open(&path).unwrap();
        let mut zero = [0u8; 32];
        assert!(matches!(core.unlock(&mut zero), Err(Error::WrongKey)));
        assert!(core.is_locked());
        drop(core);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn pragmas_are_applied() {
        let path = temp_path();
        drop(new_core(&path));
        let core = Core::open(&path).unwrap();
        let q = |name: &str| -> String {
            core.db
                .pragma_query_value(None, name, |r| r.get::<_, rusqlite::types::Value>(0))
                .map(|v| format!("{v:?}"))
                .unwrap()
        };
        assert_eq!(q("journal_mode"), "Text(\"delete\")");
        assert_eq!(q("secure_delete"), "Integer(1)");
        assert_eq!(q("temp_store"), "Integer(2)");
        assert_eq!(q("foreign_keys"), "Integer(1)");
        assert_eq!(q("cell_size_check"), "Integer(1)");
        assert_eq!(q("fullfsync"), "Integer(1)");
        assert_eq!(q("trusted_schema"), "Integer(0)");
        assert_eq!(q("application_id"), format!("Integer({APPLICATION_ID})"));
        assert_eq!(q("user_version"), "Integer(1)");
        assert!(core
            .db
            .db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE)
            .unwrap());
        drop(core);
        let _ = fs::remove_file(&path);
    }

    static SQL_LOG: Mutex<Vec<String>> = Mutex::new(Vec::new());

    fn record(e: TraceEvent<'_>) {
        if let TraceEvent::Stmt(s, _) = e {
            if let Some(sql) = s.expanded_sql() {
                SQL_LOG.lock().unwrap().push(sql);
            }
        }
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// SQLite is never handed plaintext: every statement, with its bound
    /// values expanded, is recorded and searched. This covers the rollback
    /// journal, temp storage and freed pages by construction: SQLite can only
    /// write what it was given.
    #[test]
    fn sqlite_never_receives_plaintext() {
        const MARKER: &[u8] = b"BREV-TRACE-MARKER-5d1c";
        let (pa, pb) = (temp_path(), temp_path());
        let (mut a, mut b) = (new_core(&pa), new_core(&pb));
        for c in [&a, &b] {
            c.db.trace_v2(TraceEventCodes::SQLITE_TRACE_STMT, Some(record));
        }
        let b_id = a.add_contact(&b.bundle().unwrap(), MARKER).unwrap();
        b.add_contact(&a.bundle().unwrap(), MARKER).unwrap();
        let t = a.new_thread(b_id, MARKER).unwrap();
        let env = a.send(t, MARKER, &NoSig).unwrap();
        let m = b.receive(&env).unwrap();
        assert_eq!(&b.read_body(m).unwrap()[..], MARKER);
        b.mark_read(m).unwrap();
        assert!(b.contacts().is_ok() && b.threads().is_ok());

        let text = String::from_utf8(MARKER.to_vec()).unwrap();
        let log = std::mem::take(&mut *SQL_LOG.lock().unwrap());
        assert!(log.len() > 10, "trace recorded the flow");
        for sql in &log {
            let lower = sql.to_ascii_lowercase();
            assert!(
                !sql.contains(&text) && !lower.contains(&hex(MARKER)),
                "{sql}"
            );
        }
        // Positive control: a bound marker is visible in the trace.
        a.db.query_row("SELECT ?1", [MARKER], |_| Ok(())).unwrap();
        let log = std::mem::take(&mut *SQL_LOG.lock().unwrap());
        assert!(log
            .iter()
            .any(|s| s.to_ascii_lowercase().contains(&hex(MARKER))));
        drop((a, b));
        let _ = (fs::remove_file(&pa), fs::remove_file(&pb));
    }

    #[test]
    fn receive_rejects_thread_owned_by_another_contact() {
        let paths = [temp_path(), temp_path(), temp_path()];
        let (mut a, mut b, c) = (
            new_core(&paths[0]),
            new_core(&paths[1]),
            new_core(&paths[2]),
        );
        let b_bundle = b.bundle().unwrap();
        let b_at_a = a.add_contact(&b_bundle, b"B").unwrap();
        b.add_contact(&a.bundle().unwrap(), b"A").unwrap();
        b.add_contact(&c.bundle().unwrap(), b"C").unwrap();
        let t = a.new_thread(b_at_a, b"s").unwrap();
        b.receive(&a.send(t, b"x", &NoSig).unwrap()).unwrap();

        // C, a real contact of B, names A's thread id in its payload.
        let payload = encode_payload(&[9; 16], &t.0, b"s", b"hijack").unwrap();
        let env = seal_from(&c, &b_bundle, &payload);
        assert!(matches!(b.receive(&env), Err(Error::Malformed)));
        assert_eq!(b.messages(t).unwrap().len(), 1);

        // An agent re-points the thread at C in B's file: the owner is
        // authenticated through the subject before C's letter is accepted.
        let c_id = c.bundle().unwrap().id();
        b.db.execute(
            "UPDATE threads SET contact_id = ?1 WHERE id = ?2",
            params![&c_id.0[..], &t.0[..]],
        )
        .unwrap();
        assert!(matches!(b.receive(&env), Err(Error::Crypto)));
        assert_eq!(b.messages(t).unwrap().len(), 1);
        drop((a, b, c));
        for p in &paths {
            let _ = fs::remove_file(p);
        }
    }

    /// The one receive path that writes before it fails: a stored message id
    /// under a new thread id. The thread insert is rolled back.
    #[test]
    fn failed_receive_leaves_no_new_thread() {
        let paths = [temp_path(), temp_path()];
        let (mut a, mut b) = (new_core(&paths[0]), new_core(&paths[1]));
        let b_bundle = b.bundle().unwrap();
        let b_at_a = a.add_contact(&b_bundle, b"B").unwrap();
        b.add_contact(&a.bundle().unwrap(), b"A").unwrap();
        let t = a.new_thread(b_at_a, b"s").unwrap();
        let m = b.receive(&a.send(t, b"x", &NoSig).unwrap()).unwrap();

        let payload = encode_payload(&m.0, &[0x55; 16], b"new", b"x").unwrap();
        let env = seal_from(&a, &b_bundle, &payload);
        assert!(matches!(b.receive(&env), Err(Error::Duplicate)));
        assert_eq!(b.threads().unwrap().len(), 1);
        assert_eq!(b.messages(t).unwrap().len(), 1);
        drop((a, b));
        for p in &paths {
            let _ = fs::remove_file(p);
        }
    }

    /// Nothing decrypted is alive while the signer runs: `send` drops the
    /// subject, the payload and the X25519 secret before it signs.
    #[test]
    fn nothing_decrypted_is_alive_while_signing() {
        struct Counts(std::cell::Cell<Option<(usize, usize)>>);
        impl Signer for Counts {
            fn sign(&self, _: &[u8]) -> Result<Vec<u8>, Error> {
                self.0.set(Some((crypto::live_plaintexts(), live_me())));
                Ok(Vec::new())
            }
        }
        let paths = [temp_path(), temp_path()];
        let (mut a, b) = (new_core(&paths[0]), new_core(&paths[1]));
        let b_at_a = a.add_contact(&b.bundle().unwrap(), b"B").unwrap();
        let t = a.new_thread(b_at_a, b"s").unwrap();
        // Positive controls: the counters see a decrypted subject, an
        // encoded payload and a decrypted identity.
        let threads = a.threads().unwrap();
        assert_eq!(crypto::live_plaintexts(), 1);
        drop(threads);
        let payload = encode_payload(&[0; 16], &t.0, b"s", b"x").unwrap();
        assert_eq!(crypto::live_plaintexts(), 1);
        drop(payload);
        let me = a.me().unwrap();
        assert_eq!(live_me(), 1);
        drop(me);

        let signer = Counts(std::cell::Cell::new(None));
        a.send(t, b"x", &signer).unwrap();
        assert_eq!(signer.0.get(), Some((0, 0)));
        drop((a, b));
        for p in &paths {
            let _ = fs::remove_file(p);
        }
    }

    #[test]
    fn payload_round_trip_and_truncation() {
        let p = encode_payload(&[6; 16], &[7; 16], b"subj", b"body").unwrap();
        let (i, t, s, b) = decode_payload(&p).unwrap();
        assert_eq!((i, t, s, b), ([6; 16], [7; 16], &b"subj"[..], &b"body"[..]));
        assert!(matches!(decode_payload(&p[..35]), Err(Error::Malformed)));
        assert!(matches!(decode_payload(&p[..20]), Err(Error::Malformed)));
    }
}
