//! The store's checks (docs/VAULT_SPLIT_PLAN.md §5): the directory lock,
//! the modes, the launch guard (with the feature), and the two-step unlock,
//! the idle deadline and the timer, in milliseconds.

use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use super::*;
use crate::crypto::random;
use crate::{Holder, Timer};

const TEST: VaultConfig = VaultConfig {
    file_name: "t.db",
    application_id: 0x5445_5354,
    schema: "CREATE TABLE t (id INTEGER PRIMARY KEY, v BLOB NOT NULL) STRICT;",
    schema_version: 1,
};

const MS: Duration = Duration::from_millis(1);

/// A fresh directory with mode 0700 under the system temp dir, removed on
/// drop.
struct TestDir(PathBuf);

impl TestDir {
    fn new() -> TestDir {
        let r: [u8; 8] = random().unwrap();
        let p = std::env::temp_dir().join(format!("brev-vault-{:016x}", u64::from_le_bytes(r)));
        fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
        TestDir(p)
    }

    fn chmod(&self, mode: u32) {
        fs::set_permissions(&self.0, fs::Permissions::from_mode(mode)).unwrap();
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn create(dir: &TestDir) -> Result<Vault, Error> {
    Vault::create(
        &TEST.path_in(&dir.0),
        DekSlot::take(&mut random().unwrap()),
        &TEST,
        |_| Ok(()),
        |_, ()| Ok(()),
    )
}

/// Unlocks with any non-zero key (the test's check accepts it).
fn unlock(v: &mut Vault) -> Result<(), Error> {
    v.unlock(&mut random().unwrap(), |_, _| Ok(()))
}

fn text(v: &mut Vault) -> Arc<Text> {
    v.open_text(Plaintext::new(Zeroizing::new(b"content".to_vec())))
}

/// A vault in a mutex, as a timer holds it; each wipe is reported.
struct Held {
    v: Vault,
    wiped: Sender<()>,
}

impl Holder for Held {
    fn lock_all(&mut self) {
        self.v.lock();
        let _ = self.wiped.send(());
    }
}

/// `v` behind a mutex, with its timer and the channel of its wipes.
fn held(v: Vault) -> (Arc<Mutex<Held>>, Timer, Receiver<()>) {
    let (wiped, rx) = mpsc::channel();
    let clock = v.clock();
    let h = Arc::new(Mutex::new(Held { v, wiped }));
    let timer = Timer::spawn(Arc::downgrade(&h), clock).unwrap();
    (h, timer, rx)
}

#[test]
fn a_directory_holds_one_open_store() {
    let dir = TestDir::new();
    let path = TEST.path_in(&dir.0);
    let first = create(&dir).unwrap();
    assert!(matches!(
        Vault::open(&path, &TEST).map(drop),
        Err(Error::Busy)
    ));
    // Another name in the same directory: the directory is what is locked.
    let other = dir.0.join("other.db");
    let r = Vault::create(
        &other,
        DekSlot::take(&mut [7; 32]),
        &TEST,
        |_| Ok(()),
        |_, ()| Ok::<_, Error>(()),
    );
    assert!(matches!(r.map(drop), Err(Error::Busy)));
    assert!(!other.exists());
    drop(first);
    let again = Vault::open(&path, &TEST).unwrap();
    assert!(matches!(
        Vault::open(&path, &TEST).map(drop),
        Err(Error::Busy)
    ));
    drop(again);
    drop(Vault::open(&path, &TEST).unwrap());
}

#[test]
fn directory_must_be_0700_and_the_file_0600() {
    let dir = TestDir::new();
    let path = TEST.path_in(&dir.0);
    for mode in [0o755, 0o750, 0o701, 0o1700] {
        dir.chmod(mode);
        assert!(
            matches!(create(&dir).map(drop), Err(Error::Unsafe)),
            "{mode:o}"
        );
        assert!(!path.exists(), "{mode:o}");
    }
    dir.chmod(0o700);
    drop(create(&dir).unwrap());
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
        0o600
    );
    dir.chmod(0o755);
    assert!(matches!(
        Vault::open(&path, &TEST).map(drop),
        Err(Error::Unsafe)
    ));
    dir.chmod(0o700);

    let before = fs::read(&path).unwrap();
    for mode in [0o644, 0o640, 0o604, 0o700, 0o400] {
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        assert!(
            matches!(Vault::open(&path, &TEST).map(drop), Err(Error::Unsafe)),
            "{mode:o}"
        );
        assert_eq!(
            fs::read(&path).unwrap(),
            before,
            "nothing written: {mode:o}"
        );
    }
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    drop(Vault::open(&path, &TEST).unwrap());

    // A foreign file is `Corrupt` before its mode is looked at.
    let foreign = dir.0.join("foreign.db");
    fs::write(&foreign, b"not a store").unwrap();
    fs::set_permissions(&foreign, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        Vault::open(&foreign, &TEST).map(drop),
        Err(Error::Corrupt)
    ));
}

#[test]
fn unlock_is_armed_until_confirmed() {
    let dir = TestDir::new();
    let mut v = create(&dir).unwrap();
    // `create` leaves it armed too.
    assert!(v.is_locked());
    assert!(matches!(v.dek(), Err(Error::Locked)));
    assert_ne!(v.dek_for_test(), [0u8; 32], "the DEK is loaded");
    v.confirm_active().unwrap();
    assert!(!v.is_locked() && v.dek().is_ok());
    v.confirm_active().unwrap();
    assert!(v.dek().is_ok(), "idempotent while active");

    v.lock();
    assert!(
        matches!(v.confirm_active(), Err(Error::Locked)),
        "nothing to confirm"
    );
    unlock(&mut v).unwrap();
    assert!(v.is_locked() && matches!(v.dek(), Err(Error::Locked)));
    v.confirm_active().unwrap();
    assert!(v.dek().is_ok());
    // A new unlock arms again.
    unlock(&mut v).unwrap();
    assert!(matches!(v.dek(), Err(Error::Locked)));
}

#[test]
fn a_late_confirm_locks_and_wipes() {
    let dir = TestDir::new();
    let mut v = create(&dir).unwrap();
    v.lock();
    v.set_window(50 * MS);
    unlock(&mut v).unwrap();
    let t = text(&mut v);
    thread::sleep(80 * MS);
    assert!(matches!(v.confirm_active(), Err(Error::Locked)));
    assert!(v.is_locked());
    assert_eq!(v.dek_for_test(), [0u8; 32]);
    assert_eq!(t.byte_len(), 0);
}

#[test]
fn the_timer_wipes_an_unconfirmed_unlock() {
    let dir = TestDir::new();
    let mut v = create(&dir).unwrap();
    v.lock();
    v.set_window(50 * MS);
    unlock(&mut v).unwrap();
    let t = text(&mut v);
    let (h, _timer, wiped) = held(v);
    wiped.recv_timeout(Duration::from_secs(5)).unwrap();
    let g = h.lock().unwrap();
    assert!(g.v.is_locked());
    assert_eq!(g.v.dek_for_test(), [0u8; 32]);
    assert_eq!(t.byte_len(), 0, "the open text is closed");
    assert!(g.v.open_texts_for_test().is_empty());
}

/// Activity moves the idle deadline; without it the timer wipes.
#[test]
fn the_timer_wipes_when_idle_and_activity_postpones_it() {
    let dir = TestDir::new();
    let mut v = create(&dir).unwrap();
    v.set_idle(200 * MS);
    v.confirm_active().unwrap();
    let t = text(&mut v);
    let clock = v.clock();
    let (h, _timer, wiped) = held(v);
    let start = Instant::now();
    while start.elapsed() < 600 * MS {
        clock.note_activity();
        thread::sleep(40 * MS);
    }
    assert!(wiped.try_recv().is_err(), "activity kept it unlocked");
    assert!(h.lock().unwrap().v.dek().is_ok() && t.byte_len() > 0);
    let idle = Instant::now();
    wiped.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(idle.elapsed() >= 150 * MS, "not before the idle time");
    let g = h.lock().unwrap();
    assert!(g.v.is_locked() && matches!(g.v.dek(), Err(Error::Locked)));
    assert_eq!(g.v.dek_for_test(), [0u8; 32]);
    assert_eq!(t.byte_len(), 0);
}

#[test]
fn activity_while_armed_does_nothing() {
    let dir = TestDir::new();
    let mut v = create(&dir).unwrap();
    v.lock();
    v.set_window(100 * MS);
    unlock(&mut v).unwrap();
    let start = Instant::now();
    while start.elapsed() < 150 * MS {
        v.clock().note_activity();
        thread::sleep(20 * MS);
    }
    assert!(matches!(v.confirm_active(), Err(Error::Locked)));
    assert_eq!(v.dek_for_test(), [0u8; 32]);
}

/// A deadline that passes while the holder's mutex is held: the gate is
/// shut at once, activity neither blocks nor revives it, and the timer
/// wipes as soon as the mutex is free.
#[test]
fn the_timer_waits_for_a_held_holder() {
    let dir = TestDir::new();
    let mut v = create(&dir).unwrap();
    v.set_idle(50 * MS);
    v.confirm_active().unwrap();
    let clock = v.clock();
    let (h, _timer, wiped) = held(v);
    let g = h.lock().unwrap();
    thread::sleep(150 * MS);
    assert!(
        matches!(g.v.dek(), Err(Error::Locked)),
        "shut before the wipe"
    );
    assert_ne!(
        g.v.dek_for_test(),
        [0u8; 32],
        "not wiped yet: the timer waits"
    );
    let (done, noted) = mpsc::channel();
    let c = Arc::clone(&clock);
    thread::spawn(move || {
        c.note_activity();
        let _ = done.send(());
    });
    noted
        .recv_timeout(Duration::from_secs(5))
        .expect("note_activity blocked on the holder's mutex");
    assert!(
        matches!(g.v.dek(), Err(Error::Locked)),
        "activity does not revive it"
    );
    assert!(wiped.try_recv().is_err());
    drop(g);
    wiped
        .recv_timeout(Duration::from_secs(5))
        .expect("the timer wiped once the mutex was free");
    assert_eq!(h.lock().unwrap().v.dek_for_test(), [0u8; 32]);
}

#[test]
fn dropping_the_timer_joins_its_thread() {
    let dir = TestDir::new();
    let v = create(&dir).unwrap();
    let clock = v.clock();
    let (h, timer, _wiped) = held(v);
    // The vault's, this one, the timer's and its thread's.
    assert_eq!(Arc::strong_count(&clock), 4);
    drop(timer);
    assert_eq!(Arc::strong_count(&clock), 2, "the thread is gone");
    drop(h);
    // The directory is free again.
    drop(Vault::open(&TEST.path_in(&dir.0), &TEST).unwrap());
}

/// With the feature on, this test process is refused: cargo sets
/// `DYLD_FALLBACK_LIBRARY_PATH` on macOS, and nothing sets
/// `MallocScribble=1`. Create, open and unlock give `Unsafe`; the caller's
/// DEK is zeroed, no file is made and nothing is unlocked.
#[cfg(feature = "launch-guard")]
#[test]
fn launch_guard_refuses_this_process() {
    assert!(matches!(check_env(), Err(Error::Unsafe)));
    let dir = TestDir::new();
    let path = TEST.path_in(&dir.0);
    let mut dek = [7u8; 32];
    let r = Vault::create(
        &path,
        DekSlot::take(&mut dek),
        &TEST,
        |_| Ok(()),
        |_, ()| Ok::<_, Error>(()),
    );
    assert!(matches!(r.map(drop), Err(Error::Unsafe)));
    assert_eq!(dek, [0u8; 32]);
    assert!(!path.exists());
    fs::write(&path, b"").unwrap();
    assert!(matches!(
        Vault::open(&path, &TEST).map(drop),
        Err(Error::Unsafe)
    ));
    // Unlock, on a vault put together without the checks.
    let db = connect(&path).unwrap();
    let mut v = Vault::assemble(
        db,
        Box::new(Zeroizing::new([0u8; 32])),
        DirLock::acquire(&path).unwrap(),
    );
    let mut dek = [7u8; 32];
    let r = v.unlock(&mut dek, |_, _| Ok::<(), Error>(()));
    assert!(matches!(r, Err(Error::Unsafe)));
    assert_eq!(dek, [0u8; 32]);
    assert!(v.is_locked());
    assert_eq!(v.dek_for_test(), [0u8; 32]);
}
