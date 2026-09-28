//! The store and the `Locked`/`Unlocked` state of its DEK.
//!
//! The vault owns the file (created with mode 0600, opened only if it is a
//! store of the caller's [`VaultConfig`]), the connection settings, the one
//! buffer that holds the DEK, the gate in front of it ([`Vault::dek`]) and
//! the open [`Text`]s. The caller owns the schema and every row, which it
//! seals with [`crate::seal_column`] and reads through [`Vault::db`].
//!
//! Before a store is made, opened or unlocked, the vault checks the process
//! (the launch guard, `crate::launch`), and it keeps its directory locked
//! while it is open (mode 0700, one store per directory). The file must
//! have mode 0600. An unlock is `Armed` until [`Vault::confirm_active`], and
//! an active vault locks itself when idle ([`crate::Clock`]).

use std::fs::{self, OpenOptions};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};
use std::time::Duration;

use rusqlite::config::DbConfig;
use rusqlite::{Connection, ErrorCode, OpenFlags, Transaction};
use zeroize::{Zeroize, Zeroizing};

use crate::clock::{Clock, CONFIRM_WINDOW, DEFAULT_IDLE};
use crate::crypto::{is_zero, scrub_stack};
use crate::dirlock::DirLock;
use crate::launch::check_env;
use crate::{Error, Plaintext, Text};

/// What kind of store a file is: its name, its SQLite `application_id`,
/// its exact schema and its schema version (`user_version`).
pub struct VaultConfig {
    /// The file's name in the directory the app passes.
    pub file_name: &'static str,
    /// The `application_id` in the SQLite header.
    pub application_id: i32,
    /// The exact schema: `create` runs it, and `open` refuses a file whose
    /// schema differs in anything (a planted trigger, view or index).
    pub schema: &'static str,
    /// The `user_version`; `open` refuses any other.
    pub schema_version: i32,
}

impl VaultConfig {
    /// The store's path in `dir`.
    pub fn path_in(&self, dir: &Path) -> PathBuf {
        dir.join(self.file_name)
    }
}

/// A DEK in the one buffer a [`Vault`] will keep it in.
pub struct DekSlot(Box<Zeroizing<[u8; 32]>>);

impl DekSlot {
    /// Copies `dek` into a fresh buffer that wipes itself, then zeroes `dek`.
    pub fn take(dek: &mut [u8; 32]) -> DekSlot {
        let mut slot = Box::new(Zeroizing::new([0u8; 32]));
        slot.copy_from_slice(dek);
        dek.zeroize();
        DekSlot(slot)
    }

    /// True if the key is all zeros.
    pub fn is_zero(&self) -> bool {
        is_zero(&self.0)
    }
}

/// One encrypted store and the state of its DEK.
pub struct Vault {
    db: Connection,
    /// The DEK. Allocated once per `Vault` and never moved or reallocated,
    /// so `lock()` wipes the only copy the vault holds.
    dek: Box<Zeroizing<[u8; 32]>>,
    /// The DEK is loaded. The gate also needs the clock to say `Active`.
    unlocked: bool,
    /// Every `Text` handed out; `lock` closes the ones still alive.
    texts: Vec<Weak<Text>>,
    /// Armed, active or locked, and until when; shared with a [`crate::Timer`].
    clock: Arc<Clock>,
    /// How long `Active` lasts without activity (from the next confirm).
    idle: Duration,
    /// How long an unlock stays `Armed`: [`CONFIRM_WINDOW`] (the vault's
    /// own tests shorten it).
    window: Duration,
    /// Last, so the directory is unlocked after the connection is closed.
    _dir: DirLock,
}

impl Vault {
    /// Creates a store of `cfg` at `path` (absolute; it may not exist yet),
    /// with mode 0600 (SQLite gives its journal the same mode), in a
    /// directory with mode 0700 that no other store holds. `seal` gets the
    /// DEK before the transaction and seals the first rows; one transaction
    /// then writes the `application_id`, the schema, those rows (`insert`)
    /// and the schema version. On any failure after the file exists, the
    /// file is removed while the directory is still locked. The new vault is
    /// armed ([`Vault::confirm_active`]).
    pub fn create<T, E: From<Error>>(
        path: &Path,
        dek: DekSlot,
        cfg: &'static VaultConfig,
        seal: impl FnOnce(&[u8; 32]) -> Result<T, E>,
        insert: impl FnOnce(&Transaction<'_>, T) -> Result<(), E>,
    ) -> Result<Vault, E> {
        check_path(path)?;
        check_env()?;
        let dir = DirLock::acquire(path)?;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(Error::from)?;
        match Vault::init(path, dek, cfg, seal, insert) {
            Ok((db, dek)) => {
                let mut v = Vault::assemble(db, dek.0, dir);
                v.unlocked = true;
                v.clock.arm(v.window);
                Ok(v)
            }
            Err(e) => {
                let _ = fs::remove_file(path);
                Err(e)
            }
        }
    }

    /// Opens an existing store, locked. Refuses a file that is not a store
    /// of `cfg` (`Corrupt`), before writing anything to it, and then a file
    /// whose mode is not 0600 (`Unsafe`). The directory must have mode 0700
    /// (`Unsafe`) and no other store may hold it (`Busy`).
    pub fn open(path: &Path, cfg: &'static VaultConfig) -> Result<Vault, Error> {
        check_path(path)?;
        check_env()?;
        let dir = DirLock::acquire(path)?;
        let db = connect(path)?;
        verify_store(&db, cfg).map_err(not_a_store)?;
        check_file_mode(path)?;
        set_journal_mode(&db)?;
        Ok(Vault::assemble(
            db,
            Box::new(Zeroizing::new([0u8; 32])),
            dir,
        ))
    }

    /// Unlocks with `dek`, which is zeroed before this returns. An unsafe
    /// process (the launch guard) gives `Unsafe`, an all-zero DEK
    /// `WrongKey`; any other must pass `check` (the caller opens a sealed
    /// row with it). Success leaves the vault armed: the gate opens with
    /// [`Vault::confirm_active`]. Any failure leaves the vault locked.
    pub fn unlock<E: From<Error>>(
        &mut self,
        dek: &mut [u8; 32],
        check: impl FnOnce(&Connection, &[u8; 32]) -> Result<(), E>,
    ) -> Result<(), E> {
        self.dek.copy_from_slice(dek);
        dek.zeroize();
        if let Err(e) = check_env() {
            self.lock();
            return Err(e.into());
        }
        if is_zero(&self.dek) {
            self.lock();
            return Err(Error::WrongKey.into());
        }
        self.unlocked = true;
        match check(&self.db, &self.dek) {
            Ok(()) => {
                self.clock.arm(self.window);
                Ok(())
            }
            Err(e) => {
                self.lock();
                Err(e)
            }
        }
    }

    /// The second step of an unlock (or a create): within the confirm
    /// window ([`CONFIRM_WINDOW`] after it), the gate opens until the vault
    /// has been idle for its idle time ([`Vault::set_idle`]). Late, or not
    /// unlocked: locks, and `Locked`. Idempotent while active.
    pub fn confirm_active(&mut self) -> Result<(), Error> {
        if self.unlocked && self.clock.confirm(self.idle) {
            Ok(())
        } else {
            self.lock();
            Err(Error::Locked)
        }
    }

    /// The idle time from the next [`Vault::confirm_active`] on. The default
    /// is 300 s.
    pub fn set_idle(&mut self, idle: Duration) {
        self.idle = idle;
    }

    /// The clock, for a [`crate::Timer`] and for activity.
    pub fn clock(&self) -> Arc<Clock> {
        Arc::clone(&self.clock)
    }

    /// Closes every open text, zeroes the DEK and locks. Idempotent. The
    /// vault holds no other key or plaintext, so this is all there is to
    /// wipe.
    pub fn lock(&mut self) {
        for w in self.texts.drain(..) {
            if let Some(t) = w.upgrade() {
                t.close();
            }
        }
        self.dek.zeroize();
        self.unlocked = false;
        self.clock.set_locked();
        scrub_stack();
    }

    /// True unless the gate is open: also while armed, and once a deadline
    /// has passed, before anything wiped.
    pub fn is_locked(&self) -> bool {
        !(self.unlocked && self.clock.is_active())
    }

    /// The single gate: every content call goes through here. Open only
    /// while unlocked, confirmed, and before the idle deadline.
    pub fn dek(&self) -> Result<&[u8; 32], Error> {
        if self.unlocked && self.clock.is_active() {
            Ok(&self.dek)
        } else {
            Err(Error::Locked)
        }
    }

    /// The connection, for the caller's rows. Holds ids, metadata and
    /// ciphertext only.
    pub fn db(&self) -> &Connection {
        &self.db
    }

    /// The connection, for a transaction.
    pub fn db_mut(&mut self) -> &mut Connection {
        &mut self.db
    }

    /// Wraps `p` in a [`Text`] that [`Vault::lock`] closes.
    pub fn open_text(&mut self, p: Plaintext) -> Arc<Text> {
        self.texts.retain(|w| w.strong_count() > 0);
        let t = Arc::new(Text::new(p));
        self.texts.push(Arc::downgrade(&t));
        t
    }

    /// Test only: a copy of the DEK buffer.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn dek_for_test(&self) -> [u8; 32] {
        **self.dek
    }

    /// Test only: the address of the DEK buffer.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn dek_addr_for_test(&self) -> usize {
        self.dek.as_ptr().addr()
    }

    /// Test only: the DEK buffer itself, to pin its type.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn dek_cell_for_test(&self) -> &Zeroizing<[u8; 32]> {
        &self.dek
    }

    /// Test only: the registry of open texts.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn open_texts_for_test(&self) -> &[Weak<Text>] {
        &self.texts
    }

    /// Test only: a shorter confirm window.
    #[cfg(test)]
    pub(crate) fn set_window(&mut self, window: Duration) {
        self.window = window;
    }

    /// A locked vault of `db`, with `dek` as its key buffer.
    fn assemble(db: Connection, dek: Box<Zeroizing<[u8; 32]>>, dir: DirLock) -> Vault {
        Vault {
            db,
            dek,
            unlocked: false,
            texts: Vec::new(),
            clock: Arc::new(Clock::new()),
            idle: DEFAULT_IDLE,
            window: CONFIRM_WINDOW,
            _dir: dir,
        }
    }

    /// Second half of `create`, after the file exists: the connection and
    /// the DEK, or the error (the connection is closed by then).
    fn init<T, E: From<Error>>(
        path: &Path,
        dek: DekSlot,
        cfg: &'static VaultConfig,
        seal: impl FnOnce(&[u8; 32]) -> Result<T, E>,
        insert: impl FnOnce(&Transaction<'_>, T) -> Result<(), E>,
    ) -> Result<(Connection, DekSlot), E> {
        let mut db = connect(path)?;
        set_journal_mode(&db)?;
        // What `seal` decrypts or generates lives only inside it, so it is
        // gone before the commit.
        let sealed = seal(&dek.0)?;
        let tx = db.transaction().map_err(Error::from)?;
        tx.pragma_update(None, "application_id", cfg.application_id)
            .map_err(Error::from)?;
        tx.execute_batch(cfg.schema).map_err(Error::from)?;
        insert(&tx, sealed)?;
        tx.pragma_update(None, "user_version", cfg.schema_version)
            .map_err(Error::from)?;
        tx.commit().map_err(Error::from)?;
        Ok((db, dek))
    }
}

/// Opens the file without CREATE, then applies the per-connection
/// settings. Writes nothing to the file. The bundled SQLite parses any name
/// starting with `file:` as a URI whatever the flags say, so only absolute
/// paths get here (`check_path`).
fn connect(path: &Path) -> Result<Connection, Error> {
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
    Ok(db)
}

/// The store file must have mode 0600: `Unsafe` otherwise.
fn check_file_mode(path: &Path) -> Result<(), Error> {
    if fs::metadata(path)?.permissions().mode() & 0o7777 == 0o600 {
        Ok(())
    } else {
        Err(Error::Unsafe)
    }
}

/// SQLite reads a name that starts with `file:` as a URI (the bundled build
/// sets SQLITE_USE_URI), and `:memory:` or `""` as no file at all. An
/// absolute path starts with `/`, so it is always taken literally.
pub fn check_path(path: &Path) -> Result<(), Error> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(Error::Malformed)
    }
}

/// `application_id`, `user_version` and the exact schema must match what
/// `create` writes, so a planted trigger, view or index is refused.
fn verify_store(db: &Connection, cfg: &VaultConfig) -> Result<(), Error> {
    let app: i32 = db.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let version: i32 = db.pragma_query_value(None, "user_version", |r| r.get(0))?;
    let expected = Connection::open_in_memory()?;
    expected.execute_batch(cfg.schema)?;
    if app != cfg.application_id
        || version != cfg.schema_version
        || schema_of(db)? != schema_of(&expected)?
    {
        return Err(Error::Corrupt);
    }
    Ok(())
}

/// A file SQLite cannot parse (random bytes, an encrypted or damaged
/// database, a header naming an unsupported schema format) is not a store
/// either: `Corrupt`, not `Storage`.
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

#[cfg(test)]
mod tests;
