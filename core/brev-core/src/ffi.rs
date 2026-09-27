//! The UniFFI surface (CLAUDE.md §3.1): [`Brev`], the session the app
//! holds, and [`OpenText`], one decrypted name, subject or body.
//!
//! Content goes in only as `&[u8]` plus a used length (zero-copy
//! `ForeignBytes`) and comes out only through [`OpenText::chunk`], in chunks
//! of exactly [`CHUNK`] bytes. No `String` carries content in either
//! direction, errors are unit variants, and records carry ids and metadata
//! only.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

use zeroize::Zeroizing;

use crate::crypto::{self, Plaintext};
use crate::echo::{self, Peer};
use crate::{Core, Error, IdentityId, MessageId, Signer, ThreadId};

/// Bytes per [`OpenText::chunk`]. Every chunk has exactly this length, so no
/// buffer that carries content across the FFI is ever above 1 KiB.
pub const CHUNK: usize = 960;
/// Largest subject, in UTF-8 bytes.
pub const MAX_SUBJECT: usize = 256;
/// Largest body, in UTF-8 bytes.
pub const MAX_BODY: usize = 64 * 1024;

/// The user's store, in the directory the app passes to `create` and `open`.
const MY_FILE: &str = "brev.db";

/// Errors across the FFI. Unit variants only, so nothing but a variant
/// index ever crosses. Each is the [`Error`] of the same name.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum BrevError {
    /// The session is locked, or a text was closed.
    #[error("locked")]
    Locked,
    /// The DEK does not open the stores, or is not 32 bytes.
    #[error("wrong key")]
    WrongKey,
    /// Authenticated decryption failed.
    #[error("decryption failed")]
    Crypto,
    /// No row with that id.
    #[error("not found")]
    NotFound,
    /// Already stored.
    #[error("duplicate")]
    Duplicate,
    /// Input has the wrong shape or is over a limit.
    #[error("malformed")]
    Malformed,
    /// A file is not a Brev store of this schema version.
    #[error("not a brev store")]
    Corrupt,
    /// Signing failed.
    #[error("signing failed")]
    Signing,
    /// The OS random number generator failed.
    #[error("randomness unavailable")]
    Rng,
    /// A file could not be created (including: it already exists).
    #[error("io")]
    Io,
    /// SQLite error.
    #[error("storage")]
    Storage,
}

impl From<Error> for BrevError {
    fn from(e: Error) -> Self {
        match e {
            Error::Locked => BrevError::Locked,
            Error::WrongKey => BrevError::WrongKey,
            Error::Crypto => BrevError::Crypto,
            Error::NotFound => BrevError::NotFound,
            Error::Duplicate => BrevError::Duplicate,
            Error::Malformed => BrevError::Malformed,
            Error::Corrupt => BrevError::Corrupt,
            Error::Signing => BrevError::Signing,
            Error::Rng => BrevError::Rng,
            Error::Io(_) => BrevError::Io,
            Error::Storage(_) => BrevError::Storage,
        }
    }
}

/// The content limits and chunk size, so the app sizes its fixed buffers
/// from one source.
#[derive(uniffi::Record)]
pub struct Limits {
    /// [`MAX_SUBJECT`].
    pub max_subject: u32,
    /// [`MAX_BODY`].
    pub max_body: u32,
    /// [`CHUNK`].
    pub chunk: u32,
}

/// The content limits and chunk size.
#[uniffi::export]
pub fn limits() -> Limits {
    Limits {
        max_subject: MAX_SUBJECT as u32,
        max_body: MAX_BODY as u32,
        chunk: CHUNK as u32,
    }
}

/// A contact: its identity id and its name.
#[derive(uniffi::Record)]
pub struct ContactRow {
    /// Identity id, 32 bytes.
    pub id: Vec<u8>,
    /// The name (content).
    pub name: Arc<OpenText>,
}

/// A thread: ids, time and its subject.
#[derive(uniffi::Record)]
pub struct ThreadRow {
    /// Thread id, 16 bytes.
    pub id: Vec<u8>,
    /// The contact's identity id, 32 bytes.
    pub contact: Vec<u8>,
    /// Local creation time, unix seconds.
    pub created_at: i64,
    /// The subject (content).
    pub subject: Arc<OpenText>,
}

/// One letter's metadata. Its body is opened with [`Brev::open_body`].
#[derive(uniffi::Record)]
pub struct MessageRow {
    /// Message id, 16 bytes.
    pub id: Vec<u8>,
    /// Local time it was sent or received, unix seconds.
    pub created_at: i64,
    /// True if the user sent it.
    pub outgoing: bool,
}

/// One decrypted name, subject or body, opaque to Swift. Read it with
/// [`OpenText::chunk`] and close it at once. [`Brev::lock`] closes every
/// one that is still open.
#[derive(uniffi::Object)]
pub struct OpenText {
    plain: Mutex<Option<Plaintext>>,
}

#[uniffi::export]
impl OpenText {
    /// Content length in bytes; 0 once closed.
    pub fn byte_len(&self) -> u32 {
        guard(&self.plain).as_ref().map_or(0, |p| p.len() as u32)
    }

    /// Bytes `[index * CHUNK, index * CHUNK + CHUNK)`, zero-padded to
    /// exactly [`CHUNK`]. `Malformed` past the end (so an empty text has no
    /// chunk), `Locked` once closed.
    pub fn chunk(&self, index: u32) -> Result<Vec<u8>, BrevError> {
        let g = guard(&self.plain);
        let p = g.as_ref().ok_or(BrevError::Locked)?;
        let start = (index as usize)
            .checked_mul(CHUNK)
            .ok_or(BrevError::Malformed)?;
        if start >= p.len() {
            return Err(BrevError::Malformed);
        }
        let end = p.len().min(start + CHUNK);
        let mut out = vec![0u8; CHUNK];
        out[..end - start].copy_from_slice(&p[start..end]);
        Ok(out)
    }

    /// Wipes the content now. Idempotent.
    pub fn close(&self) {
        guard(&self.plain).take();
    }
}

/// The app's session: the user's store plus the two echo peers (`echo`),
/// locked and unlocked together.
#[derive(uniffi::Object)]
pub struct Brev {
    s: Mutex<Session>,
}

struct Session {
    me: Core,
    peers: Vec<Peer>,
    /// Every `OpenText` handed out; `lock_all` closes the ones still alive.
    open: Vec<Weak<OpenText>>,
}

/// Leaves the signature slot empty. Envelopes are unsigned in Phase 2, and
/// nothing verifies them before Phase 3 (docs/DECISIONS.md D-0019).
pub(crate) struct Unsigned;

impl Signer for Unsigned {
    fn sign(&self, _: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(Vec::new())
    }
}

#[uniffi::export]
impl Brev {
    /// Creates the user's store and both peer stores in `dir` (absolute;
    /// none of the files may exist yet), makes the peers contacts, and
    /// returns the session locked. `dek` must be 32 bytes and not all zero;
    /// Rust copies it into its own buffer and Swift wipes its own.
    /// `signing_key` is the identity's signing public key (1 to 255 bytes).
    /// On error, the file being made is removed; files made by earlier steps
    /// are left for the app's cleanup.
    #[uniffi::constructor]
    pub fn create(dir: String, dek: &[u8], signing_key: &[u8]) -> Result<Arc<Brev>, BrevError> {
        let r = Self::create_in(&PathBuf::from(dir), dek, signing_key);
        crypto::scrub_stack();
        Ok(Arc::new(r?))
    }

    /// Opens the three stores in `dir`, locked. A foreign or older store
    /// gives `Corrupt`.
    #[uniffi::constructor]
    pub fn open(dir: String) -> Result<Arc<Brev>, BrevError> {
        let dir = PathBuf::from(dir);
        let me = Core::open(&dir.join(MY_FILE))?;
        let peers = echo::open_peers(&dir)?;
        Ok(Arc::new(Brev::new(me, peers)))
    }

    /// Unlocks all three stores with the DEK (the peers' keys are derived
    /// from it). A DEK that is not 32 bytes gives `WrongKey`. Any failure,
    /// also a panic, leaves everything locked. Every exit ends with a 64 KiB
    /// stack scrub.
    pub fn unlock(&self, dek: &[u8]) -> Result<(), BrevError> {
        let mut fin = Finish { s: None, ok: false };
        let s = fin.s.insert(self.session()?);
        let r = unlock_all(s, dek);
        fin.ok = r.is_ok();
        r
    }

    /// Closes every open text and locks all three stores (their DEKs are
    /// zeroed). Idempotent; never fails, also after a panic.
    pub fn lock(&self) {
        guard(&self.s).lock_all();
    }

    /// True while locked.
    pub fn is_locked(&self) -> bool {
        self.session().map_or(true, |s| s.me.is_locked())
    }

    /// The contacts, in the order they were added.
    pub fn contacts(&self) -> Result<Vec<ContactRow>, BrevError> {
        let mut s = self.session()?;
        let list = s.me.contacts()?;
        let mut out = Vec::with_capacity(list.len());
        for c in list {
            out.push(ContactRow {
                id: c.id.0.to_vec(),
                name: s.register(c.name),
            });
        }
        Ok(out)
    }

    /// The threads with `contact`, oldest first.
    pub fn threads(&self, contact: Vec<u8>) -> Result<Vec<ThreadRow>, BrevError> {
        let contact = IdentityId(id(&contact)?);
        let mut s = self.session()?;
        let all = s.me.threads()?;
        let mut out = Vec::new();
        for t in all.into_iter().filter(|t| t.contact == contact) {
            out.push(ThreadRow {
                id: t.id.0.to_vec(),
                contact: contact.0.to_vec(),
                created_at: t.created_at,
                subject: s.register(t.subject),
            });
        }
        Ok(out)
    }

    /// The letters in `thread`, oldest first. Decrypts nothing.
    pub fn messages(&self, thread: Vec<u8>) -> Result<Vec<MessageRow>, BrevError> {
        let thread = ThreadId(id(&thread)?);
        let s = self.session()?;
        Ok(s.me
            .messages(thread)?
            .into_iter()
            .map(|m| MessageRow {
                id: m.id.0.to_vec(),
                created_at: m.created_at,
                outgoing: m.outgoing,
            })
            .collect())
    }

    /// Decrypts one letter's body.
    pub fn open_body(&self, message: Vec<u8>) -> Result<Arc<OpenText>, BrevError> {
        let message = MessageId(id(&message)?);
        let mut s = self.session()?;
        let body = s.me.read_body(message)?;
        Ok(s.register(body))
    }

    /// Starts a thread with `contact` and sends its first letter. The
    /// content is `subject[..subject_len]` and `body[..body_len]`: Swift
    /// passes its whole fixed buffer and the used length. A length over the
    /// buffer or over [`MAX_SUBJECT`] / [`MAX_BODY`] gives `Malformed`.
    /// Returns the new thread's id.
    pub fn send_new(
        &self,
        contact: Vec<u8>,
        subject: &[u8],
        subject_len: u32,
        body: &[u8],
        body_len: u32,
    ) -> Result<Vec<u8>, BrevError> {
        let contact = IdentityId(id(&contact)?);
        let subject = used(subject, subject_len, MAX_SUBJECT)?;
        let body = used(body, body_len, MAX_BODY)?;
        let mut s = self.session()?;
        let thread = s.me.new_thread(contact, subject)?;
        let env = s.me.send(thread, body, &Unsigned)?;
        echo::post(&s.peers, env)?;
        Ok(thread.0.to_vec())
    }

    /// Moves letters: each peer receives and echoes what the user sent it,
    /// then the user's store receives the echoes. Returns how many letters
    /// arrived for the user.
    pub fn sync(&self) -> Result<u32, BrevError> {
        let mut s = self.session()?;
        let Session { me, peers, .. } = &mut *s;
        let mut arrived = 0;
        for p in peers.iter_mut() {
            echo::pump(p)?;
            arrived += me.receive_all(&p.mine)?.received.len() as u32;
        }
        Ok(arrived)
    }
}

impl Brev {
    fn new(me: Core, peers: Vec<Peer>) -> Brev {
        Brev {
            s: Mutex::new(Session {
                me,
                peers,
                open: Vec::new(),
            }),
        }
    }

    fn create_in(dir: &Path, dek: &[u8], signing_key: &[u8]) -> Result<Brev, BrevError> {
        let mut key = dek32(dek).ok_or(BrevError::Malformed)?;
        let mut peer_keys = [echo::peer_dek(&key, 0)?, echo::peer_dek(&key, 1)?];
        let mut me = Core::create(&dir.join(MY_FILE), &mut key, signing_key)?;
        let peers = echo::create_peers(dir, &mut me, &mut peer_keys)?;
        me.lock();
        Ok(Brev::new(me, peers))
    }

    /// The session. If a panic poisoned the mutex, locks everything, clears
    /// the poison and gives `Locked`.
    fn session(&self) -> Result<MutexGuard<'_, Session>, BrevError> {
        match self.s.lock() {
            Ok(g) => Ok(g),
            Err(p) => {
                p.into_inner().lock_all();
                self.s.clear_poison();
                Err(BrevError::Locked)
            }
        }
    }
}

impl Drop for Brev {
    fn drop(&mut self) {
        guard(&self.s).lock_all();
    }
}

/// Runs on every exit from `unlock`, also while unwinding from a panic and
/// when the session could not be taken: locks everything unless the unlock
/// succeeded, then scrubs 64 KiB of stack.
struct Finish<'a> {
    s: Option<MutexGuard<'a, Session>>,
    ok: bool,
}

impl Drop for Finish<'_> {
    fn drop(&mut self) {
        if !self.ok {
            if let Some(s) = self.s.as_mut() {
                s.lock_all();
            }
        }
        crypto::scrub_stack_deep();
    }
}

#[cfg(test)]
thread_local! {
    static PANIC_IN_UNLOCK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn unlock_all(s: &mut Session, dek: &[u8]) -> Result<(), BrevError> {
    let mut key = dek32(dek).ok_or(BrevError::WrongKey)?;
    let mut peer_keys = [echo::peer_dek(&key, 0)?, echo::peer_dek(&key, 1)?];
    s.me.unlock(&mut key)?;
    #[cfg(test)]
    if PANIC_IN_UNLOCK.with(|p| p.get()) {
        panic!("test panic after the user core unlocked");
    }
    for (p, k) in s.peers.iter_mut().zip(peer_keys.iter_mut()) {
        p.core.unlock(k)?;
    }
    Ok(())
}

impl Session {
    /// Wraps `p` in an `OpenText` that `lock_all` can close.
    fn register(&mut self, p: Plaintext) -> Arc<OpenText> {
        self.open.retain(|w| w.strong_count() > 0);
        let t = Arc::new(OpenText {
            plain: Mutex::new(Some(p)),
        });
        self.open.push(Arc::downgrade(&t));
        t
    }

    fn lock_all(&mut self) {
        for w in self.open.drain(..) {
            if let Some(t) = w.upgrade() {
                t.close();
            }
        }
        self.me.lock();
        for p in &mut self.peers {
            p.core.lock();
        }
    }
}

/// The lock, recovered if poisoned: for `lock`, `Drop` and `OpenText`, which
/// never fail.
fn guard<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A 32-byte DEK copied into a buffer that wipes itself.
fn dek32(dek: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
    if dek.len() != 32 {
        return None;
    }
    let mut k = Zeroizing::new([0u8; 32]);
    k.copy_from_slice(dek);
    Some(k)
}

/// `buf[..len]`, if `len` is within both the buffer and `max`.
fn used(buf: &[u8], len: u32, max: usize) -> Result<&[u8], BrevError> {
    let len = len as usize;
    if len > max {
        return Err(BrevError::Malformed);
    }
    buf.get(..len).ok_or(BrevError::Malformed)
}

/// An id of the expected length (16 or 32 bytes).
fn id<const N: usize>(b: &[u8]) -> Result<[u8; N], BrevError> {
    b.try_into().map_err(|_| BrevError::Malformed)
}

#[cfg(test)]
mod tests {
    use std::panic::{catch_unwind, AssertUnwindSafe};

    use super::*;

    /// A fresh directory under the system temp dir, removed on drop.
    struct Tmp(PathBuf);
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn tmp() -> Tmp {
        let r: [u8; 8] = crypto::random().unwrap();
        let p = std::env::temp_dir().join(format!("brev-ffi-{:016x}", u64::from_le_bytes(r)));
        std::fs::create_dir(&p).unwrap();
        Tmp(p)
    }

    /// A new session in `dir` (locked) and its DEK.
    fn session(dir: &Path) -> (Arc<Brev>, [u8; 32]) {
        let dek: [u8; 32] = crypto::random().unwrap();
        let b = Brev::create(dir.to_str().unwrap().into(), &dek, &[4u8; 65]).unwrap();
        (b, dek)
    }

    fn all_locked(b: &Brev) -> bool {
        let s = guard(&b.s);
        s.me.is_locked() && s.peers.iter().all(|p| p.core.is_locked())
    }

    #[test]
    fn locked_session_refuses_every_export() {
        let t = tmp();
        let (b, dek) = session(&t.0);
        b.unlock(&dek).unwrap();
        let contact = b.contacts().unwrap()[0].id.clone();
        let thread = b.send_new(contact.clone(), b"s", 1, b"b", 1).unwrap();
        let msg = b.messages(thread.clone()).unwrap()[0].id.clone();
        b.lock();
        assert!(b.is_locked());
        assert!(all_locked(&b));
        assert!(matches!(b.contacts(), Err(BrevError::Locked)));
        assert!(matches!(b.threads(contact.clone()), Err(BrevError::Locked)));
        assert!(matches!(b.messages(thread), Err(BrevError::Locked)));
        assert!(matches!(b.open_body(msg), Err(BrevError::Locked)));
        assert!(matches!(
            b.send_new(contact, b"s", 1, b"b", 1),
            Err(BrevError::Locked)
        ));
        assert!(matches!(b.sync(), Err(BrevError::Locked)));
        assert!(all_locked(&b));
    }

    #[test]
    fn panic_in_unlock_locks_all_scrubs_and_poison_returns_locked() {
        let t = tmp();
        let (b, dek) = session(&t.0);
        // Panics after the user core unlocked: the drop guard locks all
        // three cores and scrubs while unwinding, and the mutex is poisoned.
        let panic_in_unlock = || {
            let deep = crypto::deep_scrubs();
            PANIC_IN_UNLOCK.with(|p| p.set(true));
            let r = catch_unwind(AssertUnwindSafe(|| b.unlock(&dek)));
            PANIC_IN_UNLOCK.with(|p| p.set(false));
            assert!(r.is_err(), "the test panic must propagate");
            assert_eq!(crypto::deep_scrubs(), deep + 1, "scrubbed while unwinding");
            assert!(b.s.is_poisoned());
            assert!(all_locked(&b));
        };

        // A content call on the poisoned session: `Locked`, poison cleared.
        panic_in_unlock();
        assert!(matches!(b.contacts(), Err(BrevError::Locked)));
        assert!(!b.s.is_poisoned());
        assert!(all_locked(&b));

        // `unlock` on the poisoned session: `Locked`, and it still scrubs.
        panic_in_unlock();
        let deep = crypto::deep_scrubs();
        assert!(matches!(b.unlock(&dek), Err(BrevError::Locked)));
        assert_eq!(crypto::deep_scrubs(), deep + 1);
        assert!(!b.s.is_poisoned());
        assert!(all_locked(&b));

        // `lock` and `is_locked` on the poisoned session never fail.
        panic_in_unlock();
        b.lock();
        assert!(all_locked(&b));
        assert!(b.is_locked());
        assert!(!b.s.is_poisoned());

        b.unlock(&dek).unwrap();
        assert!(!b.is_locked());
        assert_eq!(b.contacts().unwrap().len(), 2);
    }

    #[test]
    fn unlock_scrubs_deep_on_every_path() {
        let t = tmp();
        let (b, dek) = session(&t.0);
        for bad in [
            &[0u8; 31][..],
            &[0u8; 33][..],
            &[0u8; 32][..],
            &[7u8; 32][..],
        ] {
            let n = crypto::deep_scrubs();
            assert!(matches!(b.unlock(bad), Err(BrevError::WrongKey)));
            assert_eq!(crypto::deep_scrubs(), n + 1);
            assert!(all_locked(&b));
        }
        let n = crypto::deep_scrubs();
        b.unlock(&dek).unwrap();
        assert_eq!(crypto::deep_scrubs(), n + 1);
        assert!(!b.is_locked());
        assert!(guard(&b.s).peers.iter().all(|p| !p.core.is_locked()));
        let n = crypto::deep_scrubs();
        assert!(matches!(b.unlock(&[7u8; 32]), Err(BrevError::WrongKey)));
        assert_eq!(crypto::deep_scrubs(), n + 1);
        assert!(
            all_locked(&b),
            "a wrong DEK on an unlocked session locks everything"
        );
    }

    #[test]
    fn echo_pump_holds_no_plaintext_after_sync() {
        let t = tmp();
        let (b, dek) = session(&t.0);
        b.unlock(&dek).unwrap();
        let c = b.contacts().unwrap();
        assert_eq!(crypto::live_plaintexts(), 2, "positive control: the names");
        for row in &c {
            b.send_new(row.id.clone(), b"s", 1, b"body", 4).unwrap();
        }
        drop(c);
        assert_eq!(crypto::live_plaintexts(), 0);
        echo::live_at_sends();
        assert_eq!(b.sync().unwrap(), 2);
        assert_eq!(echo::live_at_sends(), [0, 0], "at each echo send");
        assert_eq!(crypto::live_plaintexts(), 0);
    }

    /// Item 7 of the design's test list; here rather than in
    /// tests/phase2.rs because the live `Plaintext` counter is test-only.
    #[test]
    fn lock_closes_every_open_text() {
        let t = tmp();
        let (b, dek) = session(&t.0);
        b.unlock(&dek).unwrap();
        let contacts = b.contacts().unwrap();
        let contact = contacts[0].id.clone();
        b.send_new(contact.clone(), b"subject", 7, b"body", 4)
            .unwrap();
        let threads = b.threads(contact).unwrap();
        let msg = b.messages(threads[0].id.clone()).unwrap()[0].id.clone();
        let body = b.open_body(msg).unwrap();
        let mut kept: Vec<Arc<OpenText>> = contacts.iter().map(|c| Arc::clone(&c.name)).collect();
        kept.push(Arc::clone(&threads[0].subject));
        kept.push(body);
        drop((contacts, threads));
        // Positive control: the kept handles hold live plaintext.
        assert_eq!(crypto::live_plaintexts(), 4);
        assert!(kept.iter().all(|t| t.byte_len() > 0 && t.chunk(0).is_ok()));

        b.lock();
        assert_eq!(crypto::live_plaintexts(), 0);
        for t in &kept {
            assert_eq!(t.byte_len(), 0);
            assert!(matches!(t.chunk(0), Err(BrevError::Locked)));
            t.close(); // idempotent
        }
        assert!(guard(&b.s).open.is_empty());
    }
}
