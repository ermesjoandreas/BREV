//! The relay's SQLite file (docs/PHASE3_DESIGN.md §4.3, docs/PHASE4_DESIGN.md
//! §4.2): the directory of identities, the waiting envelopes, the approval
//! graph (`links`), pending events and daily counts. One connection behind one mutex; every method is one short
//! hold with no I/O but the file. Phase 4's rules are in `rules.rs`.

use std::fs::{DirBuilder, OpenOptions};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;
use std::sync::{Mutex, MutexGuard, PoisonError};

use brev_proto::body::{INBOX_MAX, INBOX_MAX_BYTES};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};

use crate::{Config, Error, Gates, Policy};

/// `application_id` of a relay file: "BRLY".
const APPLICATION_ID: i32 = 0x4252_4C59;
/// `user_version` of this schema: 4 since registration is open and the
/// invites, the invite graph and the events' tags are gone
/// (docs/DECISIONS.md D-0116); 3 added each envelope's
/// `received_at` (docs/AUTHORSHIP.md §2.5). Phase 3's files (1), Phase 4's
/// (2) and those with invites (3) are refused.
const USER_VERSION: i32 = 4;

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
    wire        BLOB NOT NULL,
    received_at INTEGER NOT NULL
) STRICT;
CREATE INDEX inbox ON envelopes(recipient, seq);
CREATE TABLE links (
    owner       BLOB NOT NULL,
    peer        BLOB NOT NULL,
    state       INTEGER NOT NULL,
    PRIMARY KEY (owner, peer)
) STRICT, WITHOUT ROWID;
CREATE TABLE events (
    seq         INTEGER PRIMARY KEY,
    recipient   BLOB NOT NULL,
    peer        BLOB NOT NULL,
    kind        INTEGER NOT NULL,
    UNIQUE (recipient, peer)
) STRICT;
CREATE TABLE counts (
    identity    BLOB NOT NULL,
    kind        INTEGER NOT NULL,
    day         INTEGER NOT NULL,
    n           INTEGER NOT NULL,
    PRIMARY KEY (identity, kind)
) STRICT, WITHOUT ROWID;
";

/// The relay's state: the SQLite file, the [`Policy`], the limits and clock
/// ([`Config`]) and the registration [`Gates`].
pub struct Relay {
    db: Mutex<Connection>,
    pub(crate) policy: Box<dyn Policy>,
    pub(crate) config: Config,
    pub(crate) gates: Gates,
}

impl Relay {
    /// Opens the relay file at `path` (absolute), creating it and its folder
    /// if needed: the folder 0700, the file 0600. A new file gets the
    /// schema; an existing one must be a relay file of this version. On the
    /// connection: `secure_delete` (freed cells are zeroed, so an
    /// acknowledged envelope leaves no bytes),
    /// `foreign_keys`, and `journal_mode = DELETE` (no `-wal`; a `-journal`
    /// only during a write).
    pub fn open_with(
        path: &Path,
        policy: Box<dyn Policy>,
        config: Config,
        gates: Gates,
    ) -> Result<Relay, Error> {
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
            config,
            gates,
        })
    }

    /// The connection. A panic while it was held cannot leave a transaction
    /// half-done (a dropped transaction rolls back), so a poisoned lock is
    /// recovered.
    pub(crate) fn db(&self) -> MutexGuard<'_, Connection> {
        self.db.lock().unwrap_or_else(PoisonError::into_inner)
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

    /// `recipient`'s waiting envelopes, oldest first, each with its
    /// `received_at`: at most [`INBOX_MAX`] and [`INBOX_MAX_BYTES`] in all.
    /// Deletes nothing.
    pub(crate) fn inbox(&self, recipient: &[u8; 32]) -> Result<Vec<(u64, Vec<u8>)>, Error> {
        let db = self.db();
        let mut stmt = db
            .prepare("SELECT received_at, wire FROM envelopes WHERE recipient = ?1 ORDER BY seq")?;
        let mut rows = stmt.query([recipient])?;
        let mut out = Vec::new();
        let mut bytes = 0;
        while let Some(row) = rows.next()? {
            let received_at: i64 = row.get(0)?;
            let wire: Vec<u8> = row.get(1)?;
            if out.len() == INBOX_MAX || bytes + wire.len() > INBOX_MAX_BYTES {
                break;
            }
            bytes += wire.len();
            // Written from a u64 below, so never negative.
            out.push((received_at.unsigned_abs(), wire));
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

    /// Operator command (Phase 3 owner question Q3, design §4.3): deletes
    /// the identity registered with `address`, every envelope waiting for
    /// it, its links (either side), its events (as recipient or peer) and
    /// its counts, so the address can be registered again. False if no
    /// identity has that address.
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
        for sql in [
            "DELETE FROM envelopes WHERE recipient = ?1",
            "DELETE FROM links WHERE owner = ?1 OR peer = ?1",
            "DELETE FROM events WHERE recipient = ?1 OR peer = ?1",
            "DELETE FROM counts WHERE identity = ?1",
            "DELETE FROM identities WHERE id = ?1",
        ] {
            tx.execute(sql, [&id])?;
        }
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

    /// Today's UTC day as SQLite stores it.
    pub(crate) fn day(&self) -> i64 {
        // Day numbers are about 20 000; saturate rather than wrap.
        i64::try_from(self.config.clock.today()).unwrap_or(i64::MAX)
    }

    /// Now, in Unix seconds as SQLite stores them: a new envelope's
    /// `received_at`.
    pub(crate) fn now(&self) -> i64 {
        i64::try_from(self.config.clock.now()).unwrap_or(i64::MAX)
    }
}
