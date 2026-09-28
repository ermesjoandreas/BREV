//! The UniFFI surface (CLAUDE.md §3.1, docs/PHASE3_DESIGN.md §5.6):
//! [`Brev`], the session the app holds, and [`OpenText`], one decrypted
//! address, subject or body.
//!
//! Content goes in only as `&[u8]` plus a used length (zero-copy
//! `ForeignBytes`) and comes out only through [`OpenText::chunk`], in chunks
//! of exactly [`CHUNK`] bytes. No `String` carries content in either
//! direction (the only ones are the store directory and the relay URL),
//! errors are unit variants but `Environment` (the names of report fields),
//! and records carry ids, codes, metadata and the app's environment report
//! only.
//!
//! No call that takes content does network I/O, and no network call takes
//! content (§3.2). Every network call runs with the session mutex released,
//! so `lock()` never waits for the relay; the session's lock epoch tells the
//! second half of a call that a lock came in between (§5.2).
//!
//! An unlock takes effect only with `confirm_active`, and the session locks
//! itself when idle (docs/VAULT_SPLIT_PLAN.md §5d, §5e): its timer thread,
//! or the first call to take the session mutex after the deadline, wipes.
//!
//! A letter goes out only in environment class A, from the app's report of
//! its own defences (`report_environment`, docs/VAULT_SPLIT_PLAN.md §6). The
//! report is the app's own word: until attestation it catches bugs in the
//! app, not attackers (CLAUDE.md §2).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use brev_proto::body::{self, is_valid_address, ADDRESS_MAX};
use brev_vault::{classify, failed_fields, EnvironmentClass, Holder, Platform, Text, Timer};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto::{self, Plaintext};
use crate::relay::RelayTransport;
use crate::store::{is_permanent, Letter, MAIL};
use crate::transport::{NetError, Transport};
use crate::{ContactId, Core, Error, MessageId, ThreadId};

/// Bytes per [`OpenText::chunk`]. Every chunk has exactly this length, so no
/// buffer that carries content across the FFI is ever above 1 KiB.
pub const CHUNK: usize = brev_vault::CHUNK;
/// Largest subject, in UTF-8 bytes.
pub const MAX_SUBJECT: usize = 256;
/// Largest body, in UTF-8 bytes.
pub const MAX_BODY: usize = 64 * 1024;
/// Longest idle time `unlock` takes, in seconds.
const MAX_IDLE_SECS: u32 = 3600;

/// The lowest environment class that may send a letter: A. A test archive
/// built with the cargo feature allow-software-keys (for the Swift harness,
/// the lock probe and the view host, which have software keys and no Touch
/// ID) lowers it to C. The app's archive never has that feature:
/// scripts/gen-bindings.sh and the build phase in app/project.yml fail on
/// its marker (docs/VAULT_SPLIT_PLAN.md §6).
const SEND_THRESHOLD: EnvironmentClass = if cfg!(feature = "allow-software-keys") {
    EnvironmentClass::C
} else {
    EnvironmentClass::A
};

/// The mark of allow-software-keys in the archive, for the release checks
/// above; scripts/test.sh checks that the test archive has it.
#[cfg(feature = "allow-software-keys")]
#[used]
static SOFTWARE_KEYS_MARKER: [u8; 26] = *b"BREV-ALLOW-SOFTWARE-KEYS-1";

/// Errors across the FFI. Unit variants, but `Environment`, which carries
/// the names of report fields, so nothing but a variant index and those
/// names ever crosses. Each unit variant is the [`Error`] of the same name.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum BrevError {
    /// The session is locked, or a text was closed, or a lock came while
    /// the call was waiting for the relay.
    #[error("locked")]
    Locked,
    /// The DEK does not open the store, or is not 32 bytes.
    #[error("wrong key")]
    WrongKey,
    /// Authenticated decryption failed.
    #[error("decryption failed")]
    Crypto,
    /// No row with that id; no such address at the relay; not registered;
    /// no letter to sign or submit.
    #[error("not found")]
    NotFound,
    /// Already stored, or already a contact, or already registered.
    #[error("duplicate")]
    Duplicate,
    /// Input has the wrong shape or is over a limit; `sign_request` without
    /// a fresh `prepare_send` for that contact.
    #[error("malformed")]
    Malformed,
    /// The store is not a Brev store of this schema version, or a local
    /// row is damaged.
    #[error("not a brev store")]
    Corrupt,
    /// The signature is not DER or not by the own identity key.
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
    /// The contact's key changed: nothing is sent until the new key is
    /// accepted.
    #[error("key changed")]
    KeyChanged,
    /// The address is taken.
    #[error("address taken")]
    AddressTaken,
    /// The relay could not be reached or failed.
    #[error("network")]
    Network,
    /// The relay refused the request.
    #[error("refused")]
    Refused,
    /// The store's folder is held by another open store.
    #[error("busy")]
    Busy,
    /// The folder or the file has the wrong mode, or the process is not
    /// safe to decrypt in (a `DYLD_*` variable, no `MallocScribble=1`).
    #[error("unsafe")]
    Unsafe,
    /// `prepare_send`: the app's environment report since the unlock is
    /// below the class sending needs (A), so nothing was sent.
    #[error("environment")]
    Environment {
        /// The report's fields short of class A, in field order; empty if
        /// there was no report since the unlock.
        failed: Vec<ReportField>,
    },
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
            Error::KeyChanged => BrevError::KeyChanged,
            Error::AddressTaken => BrevError::AddressTaken,
            Error::Network => BrevError::Network,
            Error::Refused => BrevError::Refused,
            Error::Busy => BrevError::Busy,
            Error::Unsafe => BrevError::Unsafe,
        }
    }
}

impl From<NetError> for BrevError {
    fn from(e: NetError) -> Self {
        Error::from(e).into()
    }
}

/// Where the identity key lives, as the app reports it (brev-vault's
/// `KeyOrigin`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum KeyOrigin {
    /// In the Secure Enclave.
    SecureEnclave,
    /// In a TPM.
    Tpm,
    /// In software.
    Software,
    /// Not known.
    Unknown,
}

impl From<KeyOrigin> for brev_vault::KeyOrigin {
    fn from(o: KeyOrigin) -> Self {
        match o {
            KeyOrigin::SecureEnclave => brev_vault::KeyOrigin::SecureEnclave,
            KeyOrigin::Tpm => brev_vault::KeyOrigin::Tpm,
            KeyOrigin::Software => brev_vault::KeyOrigin::Software,
            KeyOrigin::Unknown => brev_vault::KeyOrigin::Unknown,
        }
    }
}

/// The app's report on its own defences, made right before `prepare_send`
/// (brev-vault's `EnvironmentReport`). Flags only, no content.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct EnvironmentReport {
    /// Where the identity key lives.
    pub key_origin: KeyOrigin,
    /// This unlock unwrapped the DEK with Touch ID.
    pub biometric_used: bool,
    /// Every window is excluded from capture and every content layer
    /// prevents capture.
    pub capture_excluded: bool,
    /// Secure event input is on.
    pub secure_input_active: bool,
    /// The app drops synthetic input.
    pub synthetic_input_rejected: bool,
    /// The content views expose nothing to accessibility.
    pub accessibility_opaque: bool,
    /// No Copy, Cut or Paste reaches content.
    pub pasteboard_disabled: bool,
}

impl From<EnvironmentReport> for brev_vault::EnvironmentReport {
    fn from(r: EnvironmentReport) -> Self {
        brev_vault::EnvironmentReport {
            key_origin: r.key_origin.into(),
            biometric_used: r.biometric_used,
            capture_excluded: r.capture_excluded,
            secure_input_active: r.secure_input_active,
            synthetic_input_rejected: r.synthetic_input_rejected,
            accessibility_opaque: r.accessibility_opaque,
            pasteboard_disabled: r.pasteboard_disabled,
        }
    }
}

/// A field of [`EnvironmentReport`], as `BrevError::Environment` names it
/// (brev-vault's `ReportField`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ReportField {
    /// `key_origin`: not the Secure Enclave (or a TPM).
    KeyOrigin,
    /// `biometric_used`.
    BiometricUsed,
    /// `capture_excluded`.
    CaptureExcluded,
    /// `secure_input_active`.
    SecureInputActive,
    /// `synthetic_input_rejected`.
    SyntheticInputRejected,
    /// `accessibility_opaque`.
    AccessibilityOpaque,
    /// `pasteboard_disabled`.
    PasteboardDisabled,
}

impl From<brev_vault::ReportField> for ReportField {
    fn from(f: brev_vault::ReportField) -> Self {
        use brev_vault::ReportField as V;
        match f {
            V::KeyOrigin => ReportField::KeyOrigin,
            V::BiometricUsed => ReportField::BiometricUsed,
            V::CaptureExcluded => ReportField::CaptureExcluded,
            V::SecureInputActive => ReportField::SecureInputActive,
            V::SyntheticInputRejected => ReportField::SyntheticInputRejected,
            V::AccessibilityOpaque => ReportField::AccessibilityOpaque,
            V::PasteboardDisabled => ReportField::PasteboardDisabled,
        }
    }
}

/// The app's report, as the platform the vault classifies.
struct Reported(brev_vault::EnvironmentReport);

impl Platform for Reported {
    fn environment_report(&self) -> brev_vault::EnvironmentReport {
        self.0
    }
}

/// Whether class `c` reaches `threshold`.
fn may_send(c: EnvironmentClass, threshold: EnvironmentClass) -> bool {
    c.rank() >= threshold.rank()
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
    /// The longest address (brev-proto's `ADDRESS_MAX`).
    pub max_address: u32,
}

/// The content limits and chunk size.
#[uniffi::export]
pub fn limits() -> Limits {
    Limits {
        max_subject: MAX_SUBJECT as u32,
        max_body: MAX_BODY as u32,
        chunk: CHUNK as u32,
        max_address: ADDRESS_MAX as u32,
    }
}

/// A contact: its local id, its address (shown as its name) and whether
/// its key changed.
#[derive(uniffi::Record)]
pub struct ContactRow {
    /// Local id, 16 bytes.
    pub id: Vec<u8>,
    /// The address, drawn only in the protected layer.
    pub name: Arc<OpenText>,
    /// The relay returned another key; sending is blocked until the new
    /// key is accepted.
    pub key_changed: bool,
}

/// What the contact header shows for one contact.
#[derive(uniffi::Record)]
pub struct ContactInfo {
    /// The address.
    pub address: Arc<OpenText>,
    /// Identity code of the pinned key: 35 ASCII bytes.
    pub code: Vec<u8>,
    /// Identity code of the changed key waiting for acceptance: 35 ASCII
    /// bytes, or empty.
    pub new_code: Vec<u8>,
}

/// What the header shows for the user.
#[derive(uniffi::Record)]
pub struct MeInfo {
    /// True once an address is registered.
    pub registered: bool,
    /// The own address; empty until registered.
    pub address: Arc<OpenText>,
    /// The own identity code: 35 ASCII bytes.
    pub code: Vec<u8>,
}

/// A thread: ids, time and its subject.
#[derive(uniffi::Record)]
pub struct ThreadRow {
    /// Thread id, 16 bytes.
    pub id: Vec<u8>,
    /// The contact's local id, 16 bytes.
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

/// One decrypted address, subject or body, opaque to Swift. Read it with
/// [`OpenText::chunk`] and close it at once. [`Brev::lock`] closes every
/// one that is still open.
#[derive(uniffi::Object)]
pub struct OpenText {
    /// The vault's text; the vault closes it when it locks.
    text: Arc<Text>,
}

#[uniffi::export]
impl OpenText {
    /// Content length in bytes; 0 once closed.
    pub fn byte_len(&self) -> u32 {
        self.text.byte_len()
    }

    /// Bytes `[index * CHUNK, index * CHUNK + CHUNK)`, zero-padded to
    /// exactly [`CHUNK`]. `Malformed` past the end (so an empty text has no
    /// chunk), `Locked` once closed.
    pub fn chunk(&self, index: u32) -> Result<Vec<u8>, BrevError> {
        self.text.chunk(index).map_err(|e| Error::from(e).into())
    }

    /// Wipes the content now. Idempotent.
    pub fn close(&self) {
        self.text.close();
    }
}

/// The app's session: the user's store and the relay client.
#[derive(uniffi::Object)]
pub struct Brev {
    /// Wipes the session when its deadline passes. Dropped (joined) before
    /// `s`, so the last `Arc` of the session is this one's.
    timer: Timer,
    s: Arc<Mutex<Session>>,
    net: RelayTransport,
}

struct Session {
    /// The store; every `OpenText` handed out is registered in its vault,
    /// which closes the ones still alive when it locks.
    me: Core,
    /// Bumped by every lock. A call that released the mutex for the network
    /// and finds another epoch when it takes it again stores nothing.
    epoch: u64,
    /// The contact `prepare_send` found with its pinned key just now, and
    /// the environment class it was allowed in; used once by
    /// `sign_request`.
    ticket: Option<(ContactId, EnvironmentClass)>,
    /// The one letter being sent (ciphertext only): sealed by
    /// `sign_request`, signed by `attach_signature`, stored by `submit`.
    letter: Option<Letter>,
    /// The registration being made: its unsigned body and the address.
    registration: Option<Registering>,
    /// The app's last environment report since the unlock.
    report: Option<Reported>,
}

struct Registering {
    body: Zeroizing<Vec<u8>>,
    address: Zeroizing<Vec<u8>>,
}

#[uniffi::export]
impl Brev {
    /// Creates the user's store in `dir` (absolute; `brev.db` may not exist
    /// yet) and returns the session locked. `relay` must be exactly
    /// `http://127.0.0.1:<port>`. `dek` must be 32 bytes and not all zero;
    /// Rust copies it into its own buffer and Swift wipes its own.
    /// `signing_key` is the identity's signing key, an uncompressed P-256
    /// point (65 bytes). On error, no file is left.
    #[uniffi::constructor]
    pub fn create(
        dir: String,
        relay: String,
        dek: &[u8],
        signing_key: &[u8],
    ) -> Result<Arc<Brev>, BrevError> {
        let r = Self::create_in(&PathBuf::from(dir), &relay, dek, signing_key);
        crypto::scrub_stack();
        Ok(Arc::new(r?))
    }

    /// Opens the store in `dir`, locked. A foreign or older store (schema
    /// v2 included) gives `Corrupt`; a relay URL other than
    /// `http://127.0.0.1:<port>` gives `Malformed`.
    #[uniffi::constructor]
    pub fn open(dir: String, relay: String) -> Result<Arc<Brev>, BrevError> {
        let net = RelayTransport::new(&relay)?;
        let me = Core::open(&MAIL.path_in(&PathBuf::from(dir)))?;
        Ok(Arc::new(Brev::start(me, net).map_err(|_| BrevError::Io)?))
    }

    /// Unlocks with the DEK. A DEK that is not 32 bytes gives `WrongKey`.
    /// `idle_secs` (1 to 3600, `Malformed` otherwise) is how long the
    /// session stays open without `note_activity`. Success leaves the
    /// session armed: every content call gives `Locked` until
    /// `confirm_active`. Any failure, also a panic, leaves the session
    /// locked. Every exit ends with a 64 KiB stack scrub.
    pub fn unlock(&self, dek: &[u8], idle_secs: u32) -> Result<(), BrevError> {
        let mut fin = Finish { s: None, ok: false };
        let s = fin.s.insert(self.session()?);
        if !(1..=MAX_IDLE_SECS).contains(&idle_secs) {
            return Err(BrevError::Malformed);
        }
        s.me.set_idle(Duration::from_secs(idle_secs.into()));
        let r = unlock_all(s, dek);
        fin.ok = r.is_ok();
        r
    }

    /// The second step of an unlock, once the app shows the mail: within
    /// 2 s of `unlock` returning, the session opens until it has been idle
    /// for `idle_secs`. Later, or while locked: everything is locked, and
    /// `Locked`. Idempotent while open.
    pub fn confirm_active(&self) -> Result<(), BrevError> {
        let mut s = self.session()?;
        if s.me.confirm_active().is_err() {
            s.lock_all();
            return Err(BrevError::Locked);
        }
        Ok(())
    }

    /// A human used the app just now: an open session's idle deadline
    /// moves to `idle_secs` from now. Call it only for input that passed
    /// the synthetic-event filter. Does nothing while locked or armed, or
    /// once the deadline has passed. Never fails, and never waits for the
    /// session mutex.
    pub fn note_activity(&self) {
        self.timer.clock().note_activity();
    }

    /// Closes every open text, forgets the letter and the registration
    /// being made, and locks the store (its DEK is zeroed). Idempotent;
    /// never fails, also after a panic. It clears the poison a panic left,
    /// so the unlock after it works. It never waits for the relay.
    pub fn lock(&self) {
        let mut s = guard(&self.s);
        s.lock_all();
        // Cleared while `s` is held, so no other call can poison the mutex
        // between `lock_all` and here.
        self.s.clear_poison();
    }

    /// True while locked.
    pub fn is_locked(&self) -> bool {
        self.session().map_or(true, |s| s.me.is_locked())
    }

    /// The user's registration state, address and identity code.
    pub fn me(&self) -> Result<MeInfo, BrevError> {
        let mut s = self.session()?;
        let address = s.me.address()?;
        let code = s.me.bundle()?.code().to_vec();
        Ok(MeInfo {
            registered: !address.is_empty(),
            address: s.register(address),
            code,
        })
    }

    /// Starts a registration of the typed address `address[..address_len]`
    /// (ASCII upper case is folded; then 3 to 32 of `a-z 0-9 -`, a letter
    /// first, `Malformed` otherwise). Returns the SHA-256 digest the
    /// identity key signs. No I/O. `Duplicate` once registered.
    pub fn register_request(&self, address: &[u8], address_len: u32) -> Result<Vec<u8>, BrevError> {
        let address = typed_address(address, address_len)?;
        let mut s = self.session()?;
        s.registration = None;
        if s.me.is_registered()? {
            return Err(BrevError::Duplicate);
        }
        let body = s.me.registration(&address)?;
        let digest: [u8; 32] =
            Sha256::digest(&*Zeroizing::new(body::register_preimage(&body))).into();
        s.registration = Some(Registering { body, address });
        Ok(digest.to_vec())
    }

    /// Finishes the registration with the Secure Enclave's DER signature:
    /// checked with the own key (`Signing` otherwise, and the registration
    /// is forgotten), then posted. Success stores the address. `AddressTaken`
    /// or `Refused` forget the registration; `Network` keeps it, so calling
    /// this again with the same signature retries without a second prompt.
    /// `NotFound` without a `register_request`.
    pub fn register(&self, signature: Vec<u8>) -> Result<(), BrevError> {
        let (signed, epoch) = {
            let mut s = self.session()?;
            if s.me.is_locked() {
                return Err(BrevError::Locked);
            }
            let reg = s.registration.as_ref().ok_or(BrevError::NotFound)?;
            let preimage = Zeroizing::new(body::register_preimage(&reg.body));
            match s.me.verify_own(&preimage, &signature) {
                Ok(raw) => (Zeroizing::new([&reg.body[..], &raw].concat()), s.epoch),
                Err(e) => {
                    s.registration = None;
                    return Err(e.into());
                }
            }
        };
        let sent = self.net.register(&signed);
        let mut s = self.resume(epoch)?;
        // The registration that was posted, not one requested meanwhile.
        let same = s.registration.as_ref().is_some_and(|r| {
            signed.len() == r.body.len() + brev_proto::SIG_LEN && signed.starts_with(&r.body)
        });
        match sent {
            Ok(()) => {
                if !same {
                    return Err(BrevError::NotFound);
                }
                let reg = s.registration.take().ok_or(BrevError::NotFound)?;
                Ok(s.me.set_address(&reg.address)?)
            }
            Err(NetError::Network) => Err(BrevError::Network),
            Err(NetError::Refused(status)) => {
                if same {
                    s.registration = None;
                }
                Err(if status == 409 {
                    BrevError::AddressTaken
                } else {
                    BrevError::Refused
                })
            }
        }
    }

    /// Adds the contact with the typed address `address[..address_len]`
    /// (folded and checked like `register_request`): the own address is
    /// `Malformed`, a known one `Duplicate`; then the relay's bundle for it
    /// is pinned (`NotFound` if there is none). The address is copied out of
    /// the borrowed buffer before the lookup. Returns the new local id.
    pub fn add_contact(&self, address: &[u8], address_len: u32) -> Result<Vec<u8>, BrevError> {
        let address = typed_address(address, address_len)?;
        let (caller, token, epoch) = {
            let s = self.session()?;
            s.me.check_new_address(&address)?;
            let (caller, token) = s.credentials()?;
            (caller, token, s.epoch)
        };
        let found = self.net.lookup(&caller, &token, &address);
        drop(token);
        let bundle = found?.ok_or(BrevError::NotFound)?;
        let mut s = self.resume(epoch)?;
        Ok(s.me.add_contact(&bundle, &address)?.0.to_vec())
    }

    /// The contacts, in the order they were added.
    pub fn contacts(&self) -> Result<Vec<ContactRow>, BrevError> {
        let mut s = self.session()?;
        let list = s.me.contacts()?;
        let mut out = Vec::with_capacity(list.len());
        for c in list {
            out.push(ContactRow {
                id: c.id.0.to_vec(),
                name: s.register(c.address),
                key_changed: c.key_changed,
            });
        }
        Ok(out)
    }

    /// One contact's address, its pinned code and, while its key change
    /// waits, the new code.
    pub fn contact_info(&self, contact: Vec<u8>) -> Result<ContactInfo, BrevError> {
        let contact = ContactId(id(&contact)?);
        let mut s = self.session()?;
        let code = s.me.contact_bundle(contact)?.code().to_vec();
        let new_code =
            s.me.pending_bundle(contact)?
                .map_or_else(Vec::new, |b| b.code().to_vec());
        let address = s.me.contact_address(contact)?;
        Ok(ContactInfo {
            address: s.register(address),
            code,
            new_code,
        })
    }

    /// Accepts the contact's changed key. `new_code` must be the code the
    /// header is showing, which must still be the pending key's
    /// (`KeyChanged` otherwise).
    pub fn accept_new_key(&self, contact: Vec<u8>, new_code: Vec<u8>) -> Result<(), BrevError> {
        let contact = ContactId(id(&contact)?);
        let mut s = self.session()?;
        Ok(s.me.accept_new_key(contact, &new_code)?)
    }

    /// The threads with `contact` (a local id), oldest first.
    pub fn threads(&self, contact: Vec<u8>) -> Result<Vec<ThreadRow>, BrevError> {
        let contact = ContactId(id(&contact)?);
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

    /// The app's report on its own defences (key origin, Touch ID, capture
    /// exclusion, secure input, synthetic-input rejection, accessibility
    /// opacity, no pasteboard), made right before `prepare_send`. Kept until
    /// the next report or a lock. `Locked` while locked.
    pub fn report_environment(&self, report: EnvironmentReport) -> Result<(), BrevError> {
        let mut s = self.session()?;
        if s.me.is_locked() {
            return Err(BrevError::Locked);
        }
        s.report = Some(Reported(report.into()));
        Ok(())
    }

    /// Step 0 of a letter (docs/PHASE3_DESIGN.md §3.2), without content:
    /// looks the contact's address up at the relay. The pinned key gives
    /// the send ticket for this contact (and clears a pending change); any
    /// other key is kept as pending and gives `KeyChanged`. `NotFound` if
    /// the relay has no such address or this user is not registered;
    /// `Network`, `Refused`. Before any request, the environment report
    /// since the unlock must reach class A (docs/VAULT_SPLIT_PLAN.md §6):
    /// `Environment` otherwise, also without a report.
    pub fn prepare_send(&self, contact: Vec<u8>) -> Result<(), BrevError> {
        let contact = ContactId(id(&contact)?);
        let (caller, token, address, epoch, class) = {
            let mut s = self.session()?;
            s.ticket = None;
            let (caller, token) = s.credentials()?;
            let class = s.send_class()?;
            let address = Zeroizing::new(s.me.contact_address(contact)?.to_vec());
            (caller, token, address, s.epoch, class)
        };
        let found = self.net.lookup(&caller, &token, &address);
        drop((token, address));
        let found = found?.ok_or(BrevError::NotFound)?;
        let mut s = self.resume(epoch)?;
        s.me.check_key(contact, &found)?;
        s.ticket = Some((contact, class));
        Ok(())
    }

    /// Step 1: seals a letter that starts a new thread with `contact`. The
    /// content is `subject[..subject_len]` and `body[..body_len]`: Swift
    /// passes its whole fixed buffer and the used length. A length over the
    /// buffer or over [`MAX_SUBJECT`] / [`MAX_BODY`] gives `Malformed`.
    /// `KeyChanged` while the contact's key change waits; `Malformed`
    /// without the ticket of a `prepare_send` for this contact (the ticket
    /// is used up either way). No I/O. Keeps the sealed letter (ciphertext
    /// only), with the ticket's environment class, and returns the digest
    /// the identity key signs.
    pub fn sign_request(
        &self,
        contact: Vec<u8>,
        subject: &[u8],
        subject_len: u32,
        body: &[u8],
        body_len: u32,
    ) -> Result<Vec<u8>, BrevError> {
        let contact = ContactId(id(&contact)?);
        let subject = used(subject, subject_len, MAX_SUBJECT)?;
        let body = used(body, body_len, MAX_BODY)?;
        let mut s = self.session()?;
        s.letter = None;
        if s.me.pending_bundle(contact)?.is_some() {
            return Err(BrevError::KeyChanged);
        }
        let Some((_, class)) = s.ticket.take().filter(|&(c, _)| c == contact) else {
            return Err(BrevError::Malformed);
        };
        let mut letter = s.me.seal_letter(contact, subject, body)?;
        letter.class = Some(class);
        let digest = letter.digest();
        s.letter = Some(letter);
        Ok(digest.to_vec())
    }

    /// Step 3: attaches the Secure Enclave's DER signature to the letter,
    /// checked with the own identity key. `Signing` clears the letter;
    /// `NotFound` if there is none.
    pub fn attach_signature(&self, signature: Vec<u8>) -> Result<(), BrevError> {
        let mut s = self.session()?;
        if s.me.is_locked() {
            return Err(BrevError::Locked);
        }
        let Session { me, letter, .. } = &mut *s;
        let pending = letter.as_mut().ok_or(BrevError::NotFound)?;
        if let Err(e) = me.attach_signature(pending, &signature) {
            *letter = None;
            return Err(e.into());
        }
        Ok(())
    }

    /// Step 4: posts the signed letter. Accepted (or already there): stores
    /// the own copy, forgets the letter and returns the thread id.
    /// `Network` keeps the signed letter, so calling this again resends the
    /// same bytes without a second prompt; `Refused` forgets it. `NotFound`
    /// if no signed letter waits. Nothing is stored before the relay has it.
    pub fn submit(&self) -> Result<Vec<u8>, BrevError> {
        let (envelope, epoch) = {
            let s = self.session()?;
            if s.me.is_locked() {
                return Err(BrevError::Locked);
            }
            let letter = s
                .letter
                .as_ref()
                .filter(|l| l.is_signed())
                .ok_or(BrevError::NotFound)?;
            (letter.envelope().clone(), s.epoch)
        };
        let sent = self.net.submit(&envelope);
        let mut s = self.resume(epoch)?;
        let Session { me, letter, .. } = &mut *s;
        let same = letter
            .as_ref()
            .is_some_and(|l| l.is_signed() && l.digest() == envelope.id());
        match sent {
            Ok(()) => {
                let sent = letter
                    .as_ref()
                    .filter(|_| same)
                    .ok_or(BrevError::NotFound)?;
                let thread = me.store_sent(sent)?;
                *letter = None;
                Ok(thread.0.to_vec())
            }
            Err(NetError::Network) => Err(BrevError::Network),
            Err(NetError::Refused(_)) => {
                if same {
                    *letter = None;
                }
                Err(BrevError::Refused)
            }
        }
    }

    /// Forgets the send ticket and the letter, signed or not. Never fails.
    pub fn cancel_send(&self) {
        let mut s = guard(&self.s);
        s.ticket = None;
        s.letter = None;
    }

    /// Fetches the letters waiting at the relay, stores each, and
    /// acknowledges the stored ones and the ones refused for good
    /// (docs/PHASE3_DESIGN.md §5.3). Never sends a letter. Returns how many
    /// letters arrived. `NotFound` before registration (no request);
    /// `Locked` if a lock comes in between (nothing more is stored and
    /// nothing is acknowledged, so the letters come again).
    pub fn sync(&self) -> Result<u32, BrevError> {
        let (caller, token, epoch) = {
            let s = self.session()?;
            let (caller, token) = s.credentials()?;
            (caller, token, s.epoch)
        };
        let mailbox = self.net.mailbox(caller, token);
        self.sync_via(&mailbox, epoch)
    }
}

impl Brev {
    /// The session and its timer. If the timer thread cannot start, gives
    /// the session back, so `create_in` can remove the new file while the
    /// store's folder is still locked.
    fn start(me: Core, net: RelayTransport) -> Result<Brev, Arc<Mutex<Session>>> {
        let clock = me.clock();
        let s = Arc::new(Mutex::new(Session {
            me,
            epoch: 0,
            ticket: None,
            letter: None,
            registration: None,
            report: None,
        }));
        match Timer::spawn(Arc::downgrade(&s), clock) {
            Ok(timer) => Ok(Brev { timer, s, net }),
            Err(_) => Err(s),
        }
    }

    /// Never inlined, so any copy of the DEK its frame holds is one that the
    /// scrub in `create` reaches once it has returned (see `unlock_all`).
    #[inline(never)]
    fn create_in(
        dir: &Path,
        relay: &str,
        dek: &[u8],
        signing_key: &[u8],
    ) -> Result<Brev, BrevError> {
        let net = RelayTransport::new(relay)?;
        let mut key = dek32(dek).ok_or(BrevError::Malformed)?;
        let path = MAIL.path_in(dir);
        let mut me = Core::create(&path, &mut key, signing_key)?;
        me.lock();
        Brev::start(me, net).map_err(|s| {
            let _ = fs::remove_file(&path);
            drop(s);
            BrevError::Io
        })
    }

    /// The session. If its deadline has passed, it is wiped first, so the
    /// first call after the deadline (or the timer, whichever takes the
    /// mutex first) wipes and moves the epoch before anything else runs.
    /// If a panic poisoned the mutex, locks everything, clears the poison
    /// and gives `Locked`.
    fn session(&self) -> Result<MutexGuard<'_, Session>, BrevError> {
        match self.s.lock() {
            Ok(mut g) => {
                if self.timer.clock().take_expired() {
                    g.lock_all();
                }
                Ok(g)
            }
            Err(p) => {
                p.into_inner().lock_all();
                self.s.clear_poison();
                Err(BrevError::Locked)
            }
        }
    }

    /// The session again after a network call: `Locked` if it was locked
    /// since `epoch`, also if it was unlocked again.
    fn resume(&self, epoch: u64) -> Result<MutexGuard<'_, Session>, BrevError> {
        let s = self.session()?;
        if s.me.is_locked() || s.epoch != epoch {
            return Err(BrevError::Locked);
        }
        Ok(s)
    }

    /// Steps 2 to 4 of `sync` over `net`: poll without the mutex; take it
    /// once per envelope to store it; ack what was stored or refused for
    /// good. A lock at any point stops it before the ack. If letters arrived,
    /// a failed ack is not an error: they come again, are `Duplicate`, and
    /// are acknowledged then.
    fn sync_via(&self, net: &dyn Transport, epoch: u64) -> Result<u32, BrevError> {
        let envelopes = net.poll()?;
        let mut done = Vec::with_capacity(envelopes.len());
        let mut arrived = 0u32;
        for env in &envelopes {
            let mut s = self.resume(epoch)?;
            match s.me.receive(env) {
                Ok(_) => {
                    arrived += 1;
                    done.push(env.id());
                }
                Err(e) if is_permanent(&e) => done.push(env.id()),
                Err(_) => {}
            }
        }
        if done.is_empty() {
            return Ok(arrived);
        }
        drop(self.resume(epoch)?);
        match net.ack(&done) {
            Ok(()) => Ok(arrived),
            Err(_) if arrived > 0 => Ok(arrived),
            Err(e) => Err(e.into()),
        }
    }
}

/// Then the timer is joined, and the session, its connection and its
/// folder lock go with the last `Arc`, before the drop returns.
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

/// Never inlined, so any key copy its frame holds (the DEK moved out of
/// `dek32`'s `Option`) lies below `Brev::unlock`'s frame, where `Finish`'s
/// scrub reaches it once this frame is gone. Inlined into `Brev::unlock`,
/// such copies sit in the frame that calls the scrub, above the scrubbed
/// area, and survive the lock on the unlock thread's stack: Phase 2 found
/// two copies of each echo peer's key there (docs/DECISIONS.md D-0063).
#[inline(never)]
fn unlock_all(s: &mut Session, dek: &[u8]) -> Result<(), BrevError> {
    let mut key = dek32(dek).ok_or(BrevError::WrongKey)?;
    s.me.unlock(&mut key)?;
    #[cfg(test)]
    if PANIC_IN_UNLOCK.with(|p| p.get()) {
        panic!("test panic after the core unlocked");
    }
    Ok(())
}

impl Session {
    /// Wraps `p` in an `OpenText` that `lock_all` can close.
    fn register(&mut self, p: Plaintext) -> Arc<OpenText> {
        Arc::new(OpenText {
            text: self.me.open_text(p),
        })
    }

    /// The texts are closed inside `me.lock()`, under the same mutex.
    fn lock_all(&mut self) {
        self.ticket = None;
        self.letter = None;
        self.registration = None;
        self.report = None;
        self.epoch = self.epoch.wrapping_add(1);
        self.me.lock();
    }

    /// The class of the environment report since the unlock (C without
    /// one), if it reaches [`SEND_THRESHOLD`]; otherwise `Environment` with
    /// the report's fields short of class A.
    fn send_class(&self) -> Result<EnvironmentClass, BrevError> {
        let report = self.report.as_ref().map(Platform::environment_report);
        let class = report.as_ref().map_or(EnvironmentClass::C, classify);
        if may_send(class, SEND_THRESHOLD) {
            return Ok(class);
        }
        Err(BrevError::Environment {
            failed: report
                .as_ref()
                .map_or_else(Vec::new, failed_fields)
                .into_iter()
                .map(ReportField::from)
                .collect(),
        })
    }

    /// The own id and relay token for a token-authenticated request. Gated,
    /// and `NotFound` before registration, so neither a locked nor an
    /// unregistered session makes such a request.
    fn credentials(&self) -> Result<([u8; 32], Zeroizing<[u8; 32]>), BrevError> {
        if !self.me.is_registered()? {
            return Err(BrevError::NotFound);
        }
        let (id, token) = self.me.relay_token()?;
        Ok((id.0, token))
    }
}

/// The timer's wipe, on its thread, under the session mutex: everything
/// `lock` wipes. A call waiting for the relay finds a new epoch and stores
/// nothing.
impl Holder for Session {
    fn lock_all(&mut self) {
        Session::lock_all(self);
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

/// A typed address, `buf[..len]`, copied into a buffer that wipes itself,
/// ASCII upper case folded to lower case, then checked against the address
/// rules (brev-proto's `is_valid_address`, the one place they live).
fn typed_address(buf: &[u8], len: u32) -> Result<Zeroizing<Vec<u8>>, BrevError> {
    let mut address = Zeroizing::new(used(buf, len, ADDRESS_MAX)?.to_vec());
    address.make_ascii_lowercase();
    if !is_valid_address(&address) {
        return Err(BrevError::Malformed);
    }
    Ok(address)
}

/// An id of the expected length (16 bytes).
fn id<const N: usize>(b: &[u8]) -> Result<[u8; N], BrevError> {
    b.try_into().map_err(|_| BrevError::Malformed)
}

#[cfg(test)]
mod tests;
