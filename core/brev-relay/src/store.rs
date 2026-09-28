//! The relay's SQLite file (docs/PHASE3_DESIGN.md §4.3): the directory of
//! identities and the waiting envelopes. One connection behind one mutex;
//! every method is one short hold with no I/O but the file.

use std::fs::{DirBuilder, OpenOptions};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;
use std::sync::{Mutex, MutexGuard, PoisonError};

use brev_proto::body::{INBOX_MAX, INBOX_MAX_BYTES};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};

use crate::{Error, Policy};

/// `application_id` of a relay file: "BRLY".
const APPLICATION_ID: i32 = 0x4252_4C59;
/// `user_version` of this schema.
const USER_VERSION: i32 = 1;

const SCHEMA: &str = "
CREATE TABLE identities (
    id          BLOB PRIMARY KEY,
    address     TEXT NOT NULL UNIQUE,
    signing_key BLOB NOT NULL,
    x25519      BLOB NOT NULL,
    token_hash  BLOB NOT NULL
) STRICT;
CREATE TABLE envelopes (
    seq         INTEGER PRIMARY KEY,
    id          BLOB NOT NULL UNIQUE,
    recipient   BLOB NOT NULL,
    wire        BLOB NOT NULL
) STRICT;
CREATE INDEX inbox ON envelopes(recipient, seq);
";

/// The relay's state: the SQLite file and the [`Policy`].
pub struct Relay {
    db: Mutex<Connection>,
    pub(crate) policy: Box<dyn Policy>,
}

/// A registered signing key and X25519 key, as stored.
pub(crate) type Bundle = (Vec<u8>, Vec<u8>);

/// What a valid registration did.
pub(crate) enum Registered {
    /// A new identity with this address (201).
    New,
    /// Exactly this identity, address and token hash already (200).
    Same,
    /// The address belongs to another identity, or this identity has
    /// another address or token (409).
    Conflict,
}

impl Relay {
    /// Opens the relay file at `path` (absolute), creating it and its folder
    /// if needed: the folder 0700, the file 0600. A new file gets the
    /// schema; an existing one must be a relay file of this version. On the
    /// connection: `secure_delete` (freed cells are zeroed, so an
    /// acknowledged envelope leaves no bytes), `foreign_keys`, and
    /// `journal_mode = DELETE` (no `-wal`; a `-journal` only during a write).
    pub fn open(path: &Path, policy: Box<dyn Policy>) -> Result<Relay, Error> {
        if !path.is_absolute() {
            return Err(Error::Path);
        }
        if let Some(dir) = path.parent() {
            DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        }
        // Created here, empty, so it gets mode 0600 from the start; SQLite
        // takes an empty file as a new database, and gives any `-journal`
        // the same mode.
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)?;
        let mut db = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        let app: i32 = db.pragma_query_value(None, "application_id", |r| r.get(0))?;
        let version: i32 = db.pragma_query_value(None, "user_version", |r| r.get(0))?;
        let objects: i64 = db.query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))?;
        match (app, version, objects) {
            (APPLICATION_ID, USER_VERSION, _) => {}
            (0, 0, 0) => {}
            _ => return Err(Error::NotRelay),
        }
        let mode: String =
            db.pragma_update_and_check(None, "journal_mode", "DELETE", |r| r.get(0))?;
        if !mode.eq_ignore_ascii_case("delete") {
            return Err(Error::NotRelay);
        }
        db.pragma_update(None, "secure_delete", true)?;
        db.pragma_update(None, "foreign_keys", true)?;
        if app == 0 {
            let tx = db.transaction()?;
            tx.execute_batch(SCHEMA)?;
            tx.pragma_update(None, "application_id", APPLICATION_ID)?;
            tx.pragma_update(None, "user_version", USER_VERSION)?;
            tx.commit()?;
        }
        Ok(Relay {
            db: Mutex::new(db),
            policy,
        })
    }

    /// The connection. A panic while it was held cannot leave a transaction
    /// half-done (a dropped transaction rolls back), so a poisoned lock is
    /// recovered.
    fn db(&self) -> MutexGuard<'_, Connection> {
        self.db.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Registers `id` with `address`, or finds it already registered.
    pub(crate) fn register(
        &self,
        id: &[u8; 32],
        address: &str,
        signing_key: &[u8],
        x25519: &[u8; 32],
        token_hash: &[u8; 32],
    ) -> Result<Registered, Error> {
        let mut db = self.db();
        let tx = db.transaction()?;
        let by_address: Option<(Vec<u8>, Vec<u8>)> = tx
            .query_row(
                "SELECT id, token_hash FROM identities WHERE address = ?1",
                [address],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let answer = match by_address {
            Some((known, hash)) if known == id && hash == token_hash => Registered::Same,
            Some(_) => Registered::Conflict,
            None => {
                let by_id: Option<i64> = tx
                    .query_row("SELECT 1 FROM identities WHERE id = ?1", [id], |r| r.get(0))
                    .optional()?;
                if by_id.is_some() {
                    Registered::Conflict
                } else {
                    tx.execute(
                        "INSERT INTO identities (id, address, signing_key, x25519, token_hash)
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![id, address, signing_key, x25519, token_hash],
                    )?;
                    Registered::New
                }
            }
        };
        tx.commit()?;
        Ok(answer)
    }

    /// SHA-256 of `id`'s relay token, if `id` is registered.
    pub(crate) fn token_hash(&self, id: &[u8; 32]) -> Result<Option<Vec<u8>>, Error> {
        Ok(self
            .db()
            .query_row(
                "SELECT token_hash FROM identities WHERE id = ?1",
                [id],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// The signing key registered for `id`.
    pub(crate) fn signing_key(&self, id: &[u8; 32]) -> Result<Option<Vec<u8>>, Error> {
        Ok(self
            .db()
            .query_row(
                "SELECT signing_key FROM identities WHERE id = ?1",
                [id],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Whether `id` is registered.
    pub(crate) fn is_registered(&self, id: &[u8; 32]) -> Result<bool, Error> {
        Ok(self.signing_key(id)?.is_some())
    }

    /// The signing key and X25519 key registered with `address`.
    pub(crate) fn lookup(&self, address: &str) -> Result<Option<Bundle>, Error> {
        Ok(self
            .db()
            .query_row(
                "SELECT signing_key, x25519 FROM identities WHERE address = ?1",
                [address],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
    }

    /// Stores an envelope for `recipient` under its id. False if that id
    /// already waits (the stored copy is kept).
    pub(crate) fn store(
        &self,
        id: &[u8; 32],
        recipient: &[u8; 32],
        wire: &[u8],
    ) -> Result<bool, Error> {
        let n = self.db().execute(
            "INSERT INTO envelopes (id, recipient, wire) VALUES (?1, ?2, ?3)
             ON CONFLICT(id) DO NOTHING",
            params![id, recipient, wire],
        )?;
        Ok(n == 1)
    }

    /// `recipient`'s waiting envelopes, oldest first: at most
    /// [`INBOX_MAX`] and [`INBOX_MAX_BYTES`] in all. Deletes nothing.
    pub(crate) fn inbox(&self, recipient: &[u8; 32]) -> Result<Vec<Vec<u8>>, Error> {
        let db = self.db();
        let mut stmt =
            db.prepare("SELECT wire FROM envelopes WHERE recipient = ?1 ORDER BY seq")?;
        let mut rows = stmt.query([recipient])?;
        let mut out = Vec::new();
        let mut bytes = 0;
        while let Some(row) = rows.next()? {
            let wire: Vec<u8> = row.get(0)?;
            if out.len() == INBOX_MAX || bytes + wire.len() > INBOX_MAX_BYTES {
                break;
            }
            bytes += wire.len();
            out.push(wire);
        }
        Ok(out)
    }

    /// Deletes each of `ids` that waits for `recipient`, in one transaction.
    /// Other recipients' envelopes and unknown ids are left alone.
    pub(crate) fn ack(&self, recipient: &[u8; 32], ids: &[[u8; 32]]) -> Result<(), Error> {
        let mut db = self.db();
        let tx = db.transaction()?;
        for id in ids {
            tx.execute(
                "DELETE FROM envelopes WHERE id = ?1 AND recipient = ?2",
                params![id, recipient],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Operator command (owner question Q3): deletes the identity registered
    /// with `address` and every envelope waiting for it, so the address can
    /// be registered again. False if no identity has that address.
    pub fn release(&self, address: &str) -> Result<bool, Error> {
        let mut db = self.db();
        let tx = db.transaction()?;
        let id: Option<Vec<u8>> = tx
            .query_row(
                "SELECT id FROM identities WHERE address = ?1",
                [address],
                |r| r.get(0),
            )
            .optional()?;
        let Some(id) = id else {
            return Ok(false);
        };
        tx.execute("DELETE FROM envelopes WHERE recipient = ?1", [&id])?;
        tx.execute("DELETE FROM identities WHERE id = ?1", [&id])?;
        tx.commit()?;
        Ok(true)
    }

    /// The number of envelopes waiting, for all recipients.
    pub fn waiting(&self) -> Result<u64, Error> {
        let n: i64 = self
            .db()
            .query_row("SELECT count(*) FROM envelopes", [], |r| r.get(0))?;
        Ok(n.unsigned_abs()) // count(*) is never negative
    }
}
