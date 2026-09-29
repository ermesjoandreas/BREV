//! The UniFFI surface (CLAUDE.md §3.1, docs/PHASE3_DESIGN.md §5.6,
//! docs/PHASE4_DESIGN.md §5.4): [`Brev`], the session the app holds, and
//! [`OpenText`], one decrypted address, subject or body.
//!
//! Content goes in only as `&[u8]` plus a used length (zero-copy
//! `ForeignBytes`) and comes out only through [`OpenText::chunk`], in chunks
//! of exactly [`CHUNK`] bytes. No `String` carries content in either
//! direction (the only ones are the store directory, the relay URL, the
//! process names of a [`Sample`] and the fixed names of facts and checks),
//! errors are unit variants but `Environment` (the names of facts), and
//! records carry ids, codes, metadata, the app's raw samples and a letter's
//! [`Proof`] only. Invite codes cross as ASCII bytes, addresses as
//! [`OpenText`].
//!
//! No call that takes content does network I/O, and no network call takes
//! content (§3.2). Every network call runs with the session mutex released,
//! so `lock()` never waits for the relay; the session's lock epoch tells the
//! second half of a call that a lock came in between (§5.2).
//!
//! Phase 4 (docs/PHASE4_DESIGN.md §5.3): a new identity registers with an
//! invite code that `open_invite` checked; contacts are the peers the user
//! added (which always sends a contact request), approved, or verified by
//! an invite; `sync` handles the relay's events first, then the letters;
//! *Blokker* sets a sealed flag and tells the relay. Requests and an opened
//! invite live only in the session, and a lock forgets them.
//!
//! An unlock takes effect only with `confirm_active`, and the session locks
//! itself when idle (docs/VAULT_SPLIT_PLAN.md §5d, §5e): its timer thread,
//! or the first call to take the session mutex after the deadline, wipes.
//!
//! Hand (docs/AUTHORSHIP.md, D-0107 to D-0109): facts, not flags. While
//! unlocked the app hands over raw [`Sample`]s (`observe`, every 2 s), and a
//! compose session (`compose_started` to `compose_closed`) keeps a
//! brev-hand `FactLog` of them and of the input events. A sample that shows
//! a running `sudo` or `su`, or SIP off, locks everything at once. A letter
//! goes out only in environment class A, computed here from the facts and
//! the key origin the app names, and it carries a token that the identity
//! key signs with the same Touch ID as the envelope: `sign_request` gives
//! the token's digest, `attach_token_signature` seals the letter with the
//! token and gives the envelope's. The app has no call that sets a count or
//! a class. The facts are still the app's own word: until attestation they
//! catch bugs in the app, not attackers (CLAUDE.md §2). A received letter's
//! token is checked and its result stored; [`Brev::letter_proof`] reads it
//! for the badge.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use brev_hand::{lock_reasons, token, Claims, Env, FactLog, LockReason, Verification};
use brev_proto::body::{self, is_valid_address, EventKind, ADDRESS_MAX};
use brev_proto::invite::{self, MAX_CODE, SECRET_LEN};
use brev_proto::SIG_LEN;
use brev_vault::{EnvironmentClass, Holder, Text, Timer};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto::{self, Plaintext};
use crate::relay::{Incoming, Mailbox, RelayTransport};
use crate::store::{
    is_permanent, today, Draft, Letter, APPROVED_ME, BLOCKED, BLOCK_UNTOLD, MAIL, VERIFIED,
};
use crate::transport::{NetError, Transport};
use crate::{ContactId, Core, Error, IdentityId, MessageId, PublicBundle, ThreadId};

/// Bytes per [`OpenText::chunk`]. Every chunk has exactly this length, so no
/// buffer that carries content across the FFI is ever above 1 KiB.
pub const CHUNK: usize = brev_vault::CHUNK;
/// Largest subject, in UTF-8 bytes.
pub const MAX_SUBJECT: usize = 256;
/// Largest body, in UTF-8 bytes.
pub const MAX_BODY: usize = 64 * 1024;
/// Longest idle time `unlock` takes, in seconds.
const MAX_IDLE_SECS: u32 = 3600;
/// Longest used length `open_invite` takes: what the contact field reads
/// from the pasteboard (docs/PHASE4_DESIGN.md §6.2). The code itself is at
/// most [`MAX_CODE`] bytes once trimmed.
const MAX_PASTE: usize = 256;

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
/// the fixed names of facts, so nothing but a variant index and those names
/// ever crosses. Each unit variant is the [`Error`] of the same name.
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
    /// The signature is not DER, or not by the own identity key, or not
    /// over the digest it answers.
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
    /// `prepare_send`, `sign_request`: the letter's facts are below the
    /// class sending needs (A), or no compose session is open, so nothing
    /// was signed or sent. `confirm_active`, `prepare_send`, `sign_request`:
    /// the sample shows a reason to lock (docs/AUTHORSHIP.md §4.3), and
    /// everything is locked now.
    #[error("environment")]
    Environment {
        /// The token's names of the facts short of class A, in token order
        /// (`"key"` for a key that is not in hardware), or of the facts
        /// that locked (`"sudo"`, `"sip"`); empty without a compose
        /// session.
        failed: Vec<String>,
    },
    // Phase 4 (docs/PHASE4_DESIGN.md §5.4): appended, so no variant index
    // above moves.
    /// The contact does not take the user's letters yet (or declined; the
    /// relay does not tell them apart), or the user blocked the contact.
    /// Nothing was signed or sent.
    #[error("not approved")]
    NotApproved,
    /// The relay's daily limit for letters, requests or invites is reached.
    #[error("rate limited")]
    RateLimited,
    /// The invite code does not parse, or the relay does not know it
    /// (unknown, used or expired), or no opened invite where one is needed.
    #[error("invite invalid")]
    InviteInvalid,
    /// The relay's answer does not match the invite code (its form, the
    /// inviter's address or the key fingerprint). Nothing was stored or
    /// sent.
    #[error("invite mismatch")]
    InviteMismatch,
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
            Error::NotApproved => BrevError::NotApproved,
            Error::RateLimited => BrevError::RateLimited,
            Error::InviteInvalid => BrevError::InviteInvalid,
            Error::InviteMismatch => BrevError::InviteMismatch,
        }
    }
}

impl From<brev_vault::Error> for BrevError {
    fn from(e: brev_vault::Error) -> Self {
        Error::from(e).into()
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

/// One on-screen window, as `CGWindowListCopyWindowInfo` lists it
/// (brev-hand's `Window`). No title, no content.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Window {
    /// The owning process.
    pub owner_pid: i32,
    /// The window layer; 0 is an ordinary app window.
    pub layer: i32,
}

/// What the app read at one moment (brev-hand's `Sample`): raw
/// observations, never a count or a verdict. `None` is a read that failed.
/// Process names are kept only while they are counted.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Sample {
    /// `IsSecureEventInputEnabled()`.
    pub secure_input: bool,
    /// The compose window's `sharingType` is `.none`.
    pub sharing_none: bool,
    /// The protected content layer has `preventsCapture`.
    pub prevents_capture: bool,
    /// `csr_get_active_config`.
    pub csr_config: Option<u32>,
    /// The name of every process (`sysctl KERN_PROC_ALL`).
    pub processes: Option<Vec<String>>,
    /// Every on-screen window.
    pub windows: Option<Vec<Window>>,
}

impl From<Sample> for brev_hand::Sample {
    fn from(s: Sample) -> Self {
        brev_hand::Sample {
            secure_input: s.secure_input,
            sharing_none: s.sharing_none,
            prevents_capture: s.prevents_capture,
            csr_config: s.csr_config,
            processes: s.processes,
            windows: s.windows.map(|w| {
                w.into_iter()
                    .map(|w| brev_hand::Window {
                        owner_pid: w.owner_pid,
                        layer: w.layer,
                    })
                    .collect()
            }),
        }
    }
}

/// What the app is built to do, which it cannot measure (brev-hand's
/// `Design`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Design {
    /// Content views expose no text to Accessibility.
    pub ax_opaque: bool,
    /// No copy, cut, paste or drag of content.
    pub pasteboard_off: bool,
    /// Events from another process are dropped.
    pub input_filter: bool,
}

impl From<Design> for brev_hand::Design {
    fn from(d: Design) -> Self {
        brev_hand::Design {
            ax_opaque: d.ax_opaque,
            pasteboard_off: d.pasteboard_off,
            input_filter: d.input_filter,
        }
    }
}

/// Why a sample locked Brev (docs/AUTHORSHIP.md §4.3; brev-hand's
/// `LockReason`). `BrevError::Environment` names the same facts `"sudo"`
/// and `"sip"`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum LockCause {
    /// A `sudo` or `su` process runs.
    Sudo,
    /// A SIP bit that guards Brev is off.
    SipOff,
}

impl From<LockReason> for LockCause {
    fn from(r: LockReason) -> Self {
        match r {
            LockReason::Sudo => LockCause::Sudo,
            LockReason::SipOff => LockCause::SipOff,
        }
    }
}

/// The token's name of the fact behind a lock reason.
fn lock_fact(r: LockReason) -> &'static str {
    match r {
        LockReason::Sudo => "sudo",
        LockReason::SipOff => "sip",
    }
}

/// What a received letter's authorship token showed (docs/AUTHORSHIP.md
/// §6), for the badge and its detail view. Content-free: flags, fixed
/// names and counts.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Proof {
    /// Every check passed: «Skrevet i Brev · klasse …». Otherwise
    /// «Ikke verifisert».
    pub verified: bool,
    /// The class, when verified: 1 = A, 2 = B, 3 = C.
    pub class: Option<u8>,
    /// What failed, in the order of the checks: `"token"` (its form),
    /// `"signature"`, `"app-attest"`, `"content"`, `"iat"` (its time), and
    /// for the class check the facts that do not support the claimed class
    /// (`"sip"`, `"key"`, …). Empty when verified.
    pub failed: Vec<String>,
    /// Apple's App Attest vouched for the app: always false on Mac
    /// (D-0108), «Appen er ikke bekreftet av Apple».
    pub attested: bool,
    /// The sender's app reported: the user is an admin. Like every number
    /// below, only when verified, and `None` for a fact it could not read.
    pub admin: Option<bool>,
    /// Known AI programs running.
    pub agents: Option<u32>,
    /// Other apps' windows on screen.
    pub windows: Option<u32>,
    /// Synthetic events the filter dropped.
    pub blocked_input: Option<u32>,
    /// Seconds from opening compose to sending.
    pub seconds: Option<u32>,
    /// SIP on.
    pub sip: Option<bool>,
    /// `sudo` or `su` processes.
    pub sudo: Option<u32>,
}

impl From<&Verification> for Proof {
    fn from(v: &Verification) -> Self {
        let failed = v
            .outcomes
            .iter()
            .flat_map(|o| o.failed.iter().map(|&n| n.to_owned()))
            .collect();
        let env = v.claims.as_ref().filter(|_| v.passed()).map(|c| c.env);
        Proof {
            verified: v.passed(),
            class: v.class().and_then(|c| u8::try_from(c.code()).ok()),
            failed,
            attested: false,
            admin: env.and_then(|e| e.admin),
            agents: env.and_then(|e| e.agents),
            windows: env.and_then(|e| e.windows),
            blocked_input: env.map(|e| e.blocked_input),
            seconds: env.map(|e| e.seconds),
            sip: env.and_then(|e| e.sip),
            sudo: env.and_then(|e| e.sudo),
        }
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
    /// The longest invite code (brev-proto's `MAX_CODE`, 96 ASCII bytes).
    pub max_invite: u32,
}

/// The content limits and chunk size.
#[uniffi::export]
pub fn limits() -> Limits {
    Limits {
        max_subject: MAX_SUBJECT as u32,
        max_body: MAX_BODY as u32,
        chunk: CHUNK as u32,
        max_address: ADDRESS_MAX as u32,
        max_invite: MAX_CODE as u32,
    }
}

/// A contact: its local id, its address (shown as its name), whether its
/// key changed, and its state (docs/PHASE4_DESIGN.md §5.2).
#[derive(uniffi::Record)]
pub struct ContactRow {
    /// Local id, 16 bytes.
    pub id: Vec<u8>,
    /// The address, drawn only in the protected layer.
    pub name: Arc<OpenText>,
    /// The relay returned another key; sending is blocked until the new
    /// key is accepted.
    pub key_changed: bool,
    /// The contact has not approved the user yet: «Venter på svar».
    pub waiting: bool,
    /// The contact's key was checked through an invite code: «Bekreftet
    /// med invitasjon».
    pub verified: bool,
    /// The user blocked the contact (*Blokker*): nothing is sent to it and
    /// its letters are dropped.
    pub blocked: bool,
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
    /// As [`ContactRow::waiting`].
    pub waiting: bool,
    /// As [`ContactRow::verified`].
    pub verified: bool,
    /// As [`ContactRow::blocked`].
    pub blocked: bool,
}

/// A contact request from an address that is not a contact, fetched by the
/// last `sync`. It carries no text.
#[derive(uniffi::Record)]
pub struct RequestRow {
    /// The asker's identity id, 32 bytes: what `answer_request` takes.
    pub peer: Vec<u8>,
    /// The asker's address, drawn only in the protected layer.
    pub address: Arc<OpenText>,
    /// The asker's identity code: 35 ASCII bytes.
    pub code: Vec<u8>,
}

/// An invite code that `open_invite` checked.
#[derive(uniffi::Record)]
pub struct InviteInfo {
    /// A root invite, from the relay's operator: no inviter.
    pub root: bool,
    /// The inviter's address; empty for a root invite.
    pub address: Arc<OpenText>,
    /// The inviter's identity code: 35 ASCII bytes, or empty for a root
    /// invite.
    pub code: Vec<u8>,
}

/// What a `sync` brought.
#[derive(uniffi::Record)]
pub struct SyncResult {
    /// Letters that arrived.
    pub letters: u32,
    /// A contact was added, or its state or pending key changed.
    pub contacts_changed: bool,
    /// Contact requests now waiting for an answer (`requests`).
    pub requests: u32,
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
    /// The contact `prepare_send` found with its pinned key just now; used
    /// once by `sign_request`.
    ticket: Option<ContactId>,
    /// The open compose session's facts (docs/AUTHORSHIP.md §3.1).
    compose: Option<Compose>,
    /// The letter between `sign_request` and `attach_token_signature`: its
    /// plaintext and the claims whose digest is being signed.
    pending: Option<Pending>,
    /// The one letter being sent (ciphertext only): sealed by
    /// `attach_token_signature`, signed by `attach_signature`, stored by
    /// `submit`.
    letter: Option<Letter>,
    /// The registration being made: its unsigned body and the address.
    registration: Option<Registering>,
    /// The contact requests of the last sync from addresses that are not
    /// contacts (docs/PHASE4_DESIGN.md §5.1).
    requests: Vec<Peer>,
    /// The invite code `open_invite` checked last, until it is used.
    invite: Option<Opened>,
}

/// A compose session: the fact log, the monotonic clock its times (ms) are
/// read from, and the key origin the app named.
struct Compose {
    log: FactLog,
    started: Instant,
    key: brev_vault::KeyOrigin,
}

impl Compose {
    /// Milliseconds since the session started.
    fn now(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// The facts as they stand with `sample`, taken now; the log goes on.
    fn facts(&self, sample: &brev_hand::Sample) -> Env {
        self.log.clone().finish(self.now(), sample)
    }
}

/// A letter whose token is being signed (docs/AUTHORSHIP.md §3.2): its
/// draft (the plaintext, a vault `Plaintext` that a lock wipes), the claims
/// as signed, and their class.
struct Pending {
    draft: Draft,
    payload: Vec<u8>,
    class: EnvironmentClass,
}

struct Registering {
    body: Zeroizing<Vec<u8>>,
    address: Zeroizing<Vec<u8>>,
    /// The inviter whose invite the body names (checked at `open_invite`);
    /// `None` for a root invite.
    inviter: Option<Peer>,
}

/// Another identity as the relay named it: its bundle and address.
#[derive(Clone)]
struct Peer {
    bundle: PublicBundle,
    address: Zeroizing<Vec<u8>>,
}

/// An invite code checked against the relay's answer (design §3.4).
struct Opened {
    /// The code's secret `s`.
    secret: Zeroizing<[u8; SECRET_LEN]>,
    /// The inviter, whose address and fingerprint matched the code; `None`
    /// for a root invite.
    inviter: Option<Peer>,
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

    /// The second step of an unlock, once the app shows the mail, with a
    /// sample taken just now: within 2 s of `unlock` returning, the session
    /// opens until it has been idle for `idle_secs`. A sample with a reason
    /// to lock (a running `sudo` or `su`, SIP off; docs/AUTHORSHIP.md §4.3)
    /// locks everything and gives `Environment` naming it (`"sudo"`,
    /// `"sip"`). Later, or while locked: everything is locked, and `Locked`.
    /// Idempotent while open.
    pub fn confirm_active(&self, sample: Sample) -> Result<(), BrevError> {
        let mut s = self.session()?;
        s.lock_if_unsafe(&sample.into())?;
        if s.me.confirm_active().is_err() {
            s.lock_all();
            return Err(BrevError::Locked);
        }
        Ok(())
    }

    /// A sample of the Mac while unlocked; the app hands one over every
    /// 2 s (docs/AUTHORSHIP.md §4.3). A running `sudo` or `su`, or SIP off,
    /// locks everything at once, as `lock` does, and the reasons come back
    /// so the app can say why; otherwise the list is empty, and an open
    /// compose session counts the sample. A read that failed (`None`) is no
    /// reason to lock. `Locked` while locked.
    pub fn observe(&self, sample: Sample) -> Result<Vec<LockCause>, BrevError> {
        let mut s = self.session()?;
        if s.me.is_locked() {
            return Err(BrevError::Locked);
        }
        let sample = brev_hand::Sample::from(sample);
        let reasons = lock_reasons(&sample);
        if !reasons.is_empty() {
            s.lock_all();
            return Ok(reasons.into_iter().map(LockCause::from).collect());
        }
        if let Some(c) = s.compose.as_mut() {
            let now = c.now();
            c.log.sample(now, &sample);
        }
        Ok(Vec::new())
    }

    /// The compose sheet opened: a new fact log starts, on a monotonic
    /// clock, with `design`, `admin` (read once; `None` if the read failed)
    /// and the identity key's origin. Own windows are this process's
    /// (`std::process::id`). A second call starts it again. `Locked` while
    /// locked.
    pub fn compose_started(
        &self,
        design: Design,
        admin: Option<bool>,
        key_origin: KeyOrigin,
    ) -> Result<(), BrevError> {
        let mut s = self.session()?;
        if s.me.is_locked() {
            return Err(BrevError::Locked);
        }
        let own = i32::try_from(std::process::id()).unwrap_or(i32::MAX);
        s.compose = Some(Compose {
            log: FactLog::start(0, own, design.into(), admin),
            started: Instant::now(),
            key: key_origin.into(),
        });
        Ok(())
    }

    /// The compose sheet closed: its fact log is dropped. `Locked` while
    /// locked (a lock drops it too).
    pub fn compose_closed(&self) -> Result<(), BrevError> {
        let mut s = self.session()?;
        if s.me.is_locked() {
            return Err(BrevError::Locked);
        }
        s.compose = None;
        Ok(())
    }

    /// The input filter dropped a synthetic event while composing: counted
    /// in the open compose session, if any. `Locked` while locked.
    pub fn synthetic_dropped(&self) -> Result<(), BrevError> {
        self.count_event(FactLog::synthetic_dropped)
    }

    /// A paste reached the content while composing: counted in the open
    /// compose session, if any. Brev never calls it (paste is blocked); an
    /// app on the SDK that allows paste must. `Locked` while locked.
    pub fn paste_accepted(&self) -> Result<(), BrevError> {
        self.count_event(FactLog::paste_accepted)
    }

    /// A human used the app just now: an open session's idle deadline
    /// moves to `idle_secs` from now. Call it only for input that passed
    /// the synthetic-event filter. Does nothing while locked or armed, or
    /// once the deadline has passed. Never fails, and never waits for the
    /// session mutex.
    pub fn note_activity(&self) {
        self.timer.clock().note_activity();
    }

    /// Closes every open text, forgets the letter (its plaintext wiped,
    /// while its token is signed), the compose session and the
    /// registration being made, and locks the store (its DEK is zeroed).
    /// Idempotent;
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
    /// first, `Malformed` otherwise) with the invite `open_invite` checked
    /// (`InviteInvalid` without one). Builds registration v2
    /// (docs/PHASE4_DESIGN.md §3.2) with the invite's relay key and the
    /// tag that proves the code to the inviter (zeros for a root invite).
    /// Returns the SHA-256 digest the identity key signs. No I/O.
    /// `Duplicate` once registered.
    pub fn register_request(&self, address: &[u8], address_len: u32) -> Result<Vec<u8>, BrevError> {
        let address = typed_address(address, address_len)?;
        let mut s = self.session()?;
        s.registration = None;
        if s.me.is_registered()? {
            return Err(BrevError::Duplicate);
        }
        let own = s.me.bundle()?.id();
        let opened = s.invite.as_ref().ok_or(BrevError::InviteInvalid)?;
        let key = relay_key(&opened.secret);
        let tag = match &opened.inviter {
            None => invite::ROOT_TAG,
            Some(inviter) => proof(&opened.secret, &own, &inviter.bundle.id(), &address)?,
        };
        let inviter = opened.inviter.clone();
        let body = s.me.registration(&address, &key, &tag)?;
        let digest: [u8; 32] =
            Sha256::digest(&*Zeroizing::new(body::register_preimage_v2(&body))).into();
        s.registration = Some(Registering {
            body,
            address,
            inviter,
        });
        Ok(digest.to_vec())
    }

    /// Finishes the registration with the Secure Enclave's DER signature and
    /// the app's attestation (empty until App Attest, at most 8 192 bytes,
    /// `Malformed` otherwise; docs/PHASE4_DESIGN.md §7.1): the signature is
    /// checked with the own key (`Signing` otherwise, and the registration
    /// is forgotten), then the body is posted. Success stores the address,
    /// pins the inviter as approved and verified (the key `open_invite`
    /// checked against the code) and uses up the opened invite.
    /// `InviteInvalid` (the relay knows no such unused invite), `AddressTaken`
    /// (the invite is kept for another address) and `Refused` (among them
    /// 428, attestation or identity check) forget the registration;
    /// `Network` keeps it, so calling this again with the same signature
    /// retries without a second prompt. `NotFound` without a
    /// `register_request`.
    pub fn register(&self, signature: Vec<u8>, attestation: Vec<u8>) -> Result<(), BrevError> {
        let (signed, epoch) = {
            let mut s = self.session()?;
            if s.me.is_locked() {
                return Err(BrevError::Locked);
            }
            let reg = s.registration.as_ref().ok_or(BrevError::NotFound)?;
            let preimage = Zeroizing::new(body::register_preimage_v2(&reg.body));
            let raw = match s.me.verify_own(&preimage, &signature) {
                Ok(raw) => raw,
                Err(e) => {
                    s.registration = None;
                    return Err(e.into());
                }
            };
            let signed = body::signed_registration_v2(&reg.body, &raw, &attestation)
                .map_err(|_| BrevError::Malformed)?;
            (Zeroizing::new(signed), s.epoch)
        };
        let sent = self.net.register(&signed);
        let mut s = self.resume(epoch)?;
        // The registration that was posted, not one requested meanwhile.
        let same = s.registration.as_ref().is_some_and(|r| {
            signed.len() == r.body.len() + SIG_LEN + 2 + attestation.len()
                && signed.starts_with(&r.body)
        });
        match sent {
            Ok(()) => {
                if !same {
                    return Err(BrevError::NotFound);
                }
                let reg = s.registration.take().ok_or(BrevError::NotFound)?;
                s.invite = None;
                s.me.set_address(&reg.address)?;
                if let Some(inviter) = reg.inviter {
                    let flags = APPROVED_ME | VERIFIED;
                    pinned(s.me.pin(&inviter.bundle, &inviter.address, flags)?)?;
                }
                Ok(())
            }
            Err(NetError::Network) => Err(BrevError::Network),
            Err(NetError::Refused(status)) => {
                if same {
                    s.registration = None;
                }
                Err(match status {
                    403 => {
                        if same {
                            s.invite = None;
                        }
                        BrevError::InviteInvalid
                    }
                    409 => BrevError::AddressTaken,
                    _ => BrevError::Refused,
                })
            }
        }
    }

    /// Adds the contact with the typed address `address[..address_len]`
    /// (folded and checked like `register_request`): the own address is
    /// `Malformed`, a known one `Duplicate`. Then the relay's bundle for it
    /// is looked up (`NotFound` if there is none), a contact request is
    /// always sent (docs/PHASE4_DESIGN.md §5.3; it also lifts the user's
    /// own earlier decline of that peer; `RateLimited` over the daily
    /// limit, and nothing is added), and the bundle is pinned, marked as
    /// taking the user's letters if the relay says it does. The address is
    /// copied out of the borrowed buffer before any request. Returns the
    /// new local id.
    pub fn add_contact(&self, address: &[u8], address_len: u32) -> Result<Vec<u8>, BrevError> {
        let address = typed_address(address, address_len)?;
        let (caller, token, epoch) = {
            let s = self.session()?;
            s.me.check_new_address(&address)?;
            let (caller, token) = s.credentials()?;
            (caller, token, s.epoch)
        };
        let found = self.net.lookup(&caller, &token, &address);
        let (bundle, approved) = found?.ok_or(BrevError::NotFound)?;
        if bundle.id().0 == caller {
            return Err(BrevError::Malformed);
        }
        let asked = self.net.request(&caller, &token, &address);
        drop(token);
        let approved = match asked {
            Ok(already) => approved || already,
            Err(NetError::Refused(429)) => return Err(BrevError::RateLimited),
            Err(NetError::Refused(404)) => return Err(BrevError::NotFound),
            Err(e) => return Err(e.into()),
        };
        let mut s = self.resume(epoch)?;
        let flags = if approved { APPROVED_ME } else { 0 };
        let contact = s.me.insert_contact(&bundle, &address, flags)?;
        s.requests.retain(|r| r.bundle != bundle);
        Ok(contact.0.to_vec())
    }

    /// The contact requests the last `sync` fetched from addresses that
    /// are not contacts, oldest first. No I/O; `Locked` while locked (a
    /// lock forgets them).
    pub fn requests(&self) -> Result<Vec<RequestRow>, BrevError> {
        let mut s = self.session()?;
        if s.me.is_locked() {
            return Err(BrevError::Locked);
        }
        let asking = s.requests.clone();
        let mut out = Vec::with_capacity(asking.len());
        for peer in asking {
            out.push(RequestRow {
                peer: peer.bundle.id().0.to_vec(),
                code: peer.bundle.code().to_vec(),
                address: s.register(Plaintext::new(peer.address)),
            });
        }
        Ok(out)
    }

    /// Answers the contact request of `peer` (an identity id from
    /// `requests`; `NotFound` if it is not there) with one click: `approve`
    /// pins the asker as a contact that takes the user's letters and
    /// returns its local id; a decline returns an empty id, and the relay
    /// then stores nothing more from the asker (who is not told).
    pub fn answer_request(&self, peer: Vec<u8>, approve: bool) -> Result<Vec<u8>, BrevError> {
        let peer = IdentityId(id(&peer)?);
        let (caller, token, epoch, asking) = {
            let s = self.session()?;
            let (caller, token) = s.credentials()?;
            let asking = s
                .requests
                .iter()
                .find(|r| r.bundle.id() == peer)
                .cloned()
                .ok_or(BrevError::NotFound)?;
            (caller, token, s.epoch, asking)
        };
        let sent = self.net.answer(&caller, &token, &peer.0, approve);
        drop(token);
        match sent {
            // 404: answered already (an answer whose reply was lost).
            Ok(()) | Err(NetError::Refused(404)) => {}
            Err(e) => return Err(e.into()),
        }
        let mut s = self.resume(epoch)?;
        s.requests.retain(|r| r.bundle.id() != peer);
        if !approve {
            return Ok(Vec::new());
        }
        let contact = pinned(s.me.pin(&asking.bundle, &asking.address, APPROVED_ME)?)?;
        Ok(contact.0.to_vec())
    }

    /// Makes a one-time invite code (docs/PHASE4_DESIGN.md §3.1, §5.3): a
    /// fresh secret from the OS RNG, registered at the relay by SHA-256 of
    /// its relay key, then kept sealed in the store so the invitee's tag
    /// can be checked. One human click, no Touch ID. Returns the code,
    /// `brev1.<address>.<fingerprint>.<secret>`, as at most 96 ASCII bytes.
    /// `NotFound` before registration; `RateLimited` at the relay's caps.
    pub fn create_invite(&self) -> Result<Vec<u8>, BrevError> {
        let (caller, token, epoch, address) = {
            let s = self.session()?;
            let (caller, token) = s.credentials()?;
            let address = Zeroizing::new(s.me.address()?.to_vec());
            (caller, token, s.epoch, address)
        };
        let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
        crypto::fill(&mut secret[..])?;
        let hash = invite::stored_hash(&relay_key(&secret));
        let made = self.net.invite_create(&caller, &token, &hash);
        drop(token);
        match made {
            Ok(()) => {}
            Err(NetError::Refused(429)) => return Err(BrevError::RateLimited),
            Err(e) => return Err(e.into()),
        }
        let mut s = self.resume(epoch)?;
        s.me.store_invite(&secret, today())?;
        invite::format(Some((&address[..], &caller)), &secret).map_err(|_| BrevError::Malformed)
    }

    /// Opens the invite code `code[..code_len]` (at most 256 bytes; it is
    /// trimmed and folded, docs/PHASE4_DESIGN.md §3.1) and checks it
    /// against the relay's answer, which needs no token, so it works before
    /// registration too. A code that does not parse, or that the relay does
    /// not know, is `InviteInvalid`. The answer must have the code's form
    /// (root or not), the code's address and a key with the code's
    /// fingerprint, else `InviteMismatch` and nothing is kept or sent. The
    /// own identity is `Malformed`. An inviter who is already a contact must
    /// have the pinned key; another key goes into that contact's `pending`
    /// (Phase 3's warning) and gives `KeyChanged`. The checked invite is
    /// kept for `register_request` or `redeem_invite` until it is used or
    /// the session locks. The code is copied out of the borrowed buffer
    /// before the request.
    pub fn open_invite(&self, code: &[u8], code_len: u32) -> Result<InviteInfo, BrevError> {
        let code = Zeroizing::new(used(code, code_len, MAX_PASTE)?.to_vec());
        let (own, epoch) = {
            let mut s = self.session()?;
            s.invite = None;
            (s.me.bundle()?.id(), s.epoch)
        };
        let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
        let named = invite::parse(&code, &mut secret).map_err(|_| BrevError::InviteInvalid)?;
        drop(code);
        let answer = self.net.invite_open(&relay_key(&secret));
        let inviter = match answer {
            Ok(inviter) => inviter,
            Err(NetError::Refused(_)) => return Err(BrevError::InviteInvalid),
            Err(e) => return Err(e.into()),
        };
        // Design §3.4: the form, the address and the fingerprint.
        let inviter = match (named, inviter) {
            (None, None) => None,
            (Some(named), Some((bundle, address)))
                if named.address[..] == address[..] && named.matches(&bundle.id().0) =>
            {
                Some(Peer { bundle, address })
            }
            _ => return Err(BrevError::InviteMismatch),
        };
        let mut s = self.resume(epoch)?;
        let info = match &inviter {
            None => InviteInfo {
                root: true,
                address: s.register(Plaintext::new(Zeroizing::new(Vec::new()))),
                code: Vec::new(),
            },
            Some(peer) => {
                if peer.bundle.id() == own {
                    return Err(BrevError::Malformed);
                }
                if let Some(contact) = s.me.contact_at(&peer.address)? {
                    s.me.check_key(contact, &peer.bundle)?;
                }
                InviteInfo {
                    root: false,
                    address: s.register(Plaintext::new(peer.address.clone())),
                    code: peer.bundle.code().to_vec(),
                }
            }
        };
        s.invite = Some(Opened { secret, inviter });
        Ok(info)
    }

    /// Redeems the invite `open_invite` checked, once registered
    /// (`NotFound` before; `InviteInvalid` without an opened invite, for a
    /// root invite, and when the relay knows no such unused invite). The
    /// relay makes both approved contacts and tells the inviter, with the
    /// user's tag as proof of the code. The inviter is pinned (or its
    /// contact flagged) as approved and verified; returns its local id.
    pub fn redeem_invite(&self) -> Result<Vec<u8>, BrevError> {
        let (caller, token, epoch, key, tag, inviter) = {
            let s = self.session()?;
            let (caller, token) = s.credentials()?;
            let opened = s.invite.as_ref().ok_or(BrevError::InviteInvalid)?;
            let inviter = opened.inviter.clone().ok_or(BrevError::InviteInvalid)?;
            let address = Zeroizing::new(s.me.address()?.to_vec());
            let key = relay_key(&opened.secret);
            let own = IdentityId(caller);
            let tag = proof(&opened.secret, &own, &inviter.bundle.id(), &address)?;
            (caller, token, s.epoch, key, tag, inviter)
        };
        let sent = self.net.invite_redeem(&caller, &token, &key, &tag);
        drop((token, key));
        match sent {
            Ok(()) => {}
            Err(NetError::Refused(400 | 404)) => {
                if let Ok(mut s) = self.resume(epoch) {
                    s.invite = None;
                }
                return Err(BrevError::InviteInvalid);
            }
            Err(e) => return Err(e.into()),
        }
        let mut s = self.resume(epoch)?;
        s.invite = None;
        let flags = APPROVED_ME | VERIFIED;
        let contact = pinned(s.me.pin(&inviter.bundle, &inviter.address, flags)?)?;
        s.requests.retain(|r| r.bundle != inviter.bundle);
        Ok(contact.0.to_vec())
    }

    /// *Blokker* (docs/PHASE4_DESIGN.md owner answer 6): one click undoes
    /// the approval of `contact`. First the sealed local flag, which stops
    /// sending to it and drops its letters, and forgets a ticket or letter
    /// for it (also one waiting for its token signature); then the relay is told to store no more letters or requests
    /// from it. Until the relay answers, the sealed `BLOCK_UNTOLD` stays
    /// beside the flag, and every `sync` tells the relay again, also after
    /// a lock (WP5 review). An error means the relay was not told yet (the
    /// flag is set); calling this again tells it too.
    pub fn block_contact(&self, contact: Vec<u8>) -> Result<(), BrevError> {
        let contact = ContactId(id(&contact)?);
        let (caller, token, peer, epoch) = {
            let mut s = self.session()?;
            let (caller, token) = s.credentials()?;
            let peer = s.me.contact_bundle(contact)?.id();
            s.me.change_flags(contact, BLOCKED | BLOCK_UNTOLD, 0)?;
            if s.ticket == Some(contact) {
                s.ticket = None;
            }
            if s.pending
                .as_ref()
                .is_some_and(|p| p.draft.contact() == contact)
            {
                s.pending = None;
            }
            if s.letter.as_ref().is_some_and(|l| l.contact() == contact) {
                s.letter = None;
            }
            (caller, token, peer, s.epoch)
        };
        let told = self.net.block(&caller, &token, &peer.0);
        drop(token);
        told_block(told)?;
        self.resume(epoch)?
            .me
            .change_flags(contact, 0, BLOCK_UNTOLD)?;
        Ok(())
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
                waiting: !c.approved_me,
                verified: c.verified,
                blocked: c.blocked,
            });
        }
        Ok(out)
    }

    /// One contact's address, its pinned code and, while its key change
    /// waits, the new code; and its state.
    pub fn contact_info(&self, contact: Vec<u8>) -> Result<ContactInfo, BrevError> {
        let contact = ContactId(id(&contact)?);
        let mut s = self.session()?;
        let code = s.me.contact_bundle(contact)?.code().to_vec();
        let new_code =
            s.me.pending_bundle(contact)?
                .map_or_else(Vec::new, |b| b.code().to_vec());
        let flags = s.me.contact_flags(contact)?;
        let address = s.me.contact_address(contact)?;
        Ok(ContactInfo {
            address: s.register(address),
            code,
            new_code,
            waiting: flags & APPROVED_ME == 0,
            verified: flags & VERIFIED != 0,
            blocked: flags & BLOCKED != 0,
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

    /// What a received letter's authorship token showed, as stored when it
    /// arrived (docs/AUTHORSHIP.md §6): for the badge and its detail. `None`
    /// for a letter the user sent (its own class went out with it and is
    /// not shown back). Decrypts no content.
    pub fn letter_proof(&self, message: Vec<u8>) -> Result<Option<Proof>, BrevError> {
        let message = MessageId(id(&message)?);
        let s = self.session()?;
        Ok(s.me.proof(message)?.as_ref().map(Proof::from))
    }

    /// Step 0 of a letter (docs/PHASE3_DESIGN.md §3.2), without content:
    /// looks the contact's address up at the relay. The pinned key gives
    /// the send ticket for this contact (and clears a pending change); any
    /// other key is kept as pending and gives `KeyChanged`. The relay's
    /// status sets or clears the contact's «takes my letters» flag; a
    /// contact that does not take the user's letters is `NotApproved`, with
    /// no ticket, so there is no digest and no prompt (docs/PHASE4_DESIGN.md
    /// §5.3). `NotFound` if the relay has no such address or this user is
    /// not registered; `Network`, `Refused`. Before any request, with
    /// `sample` taken just now: a reason to lock locks everything
    /// (`Environment`, docs/AUTHORSHIP.md §4.3); the open compose session's
    /// facts must reach class A (§3.3, an early exit: `sign_request`
    /// decides), else `Environment` with the facts short of it, also
    /// without a compose session; and a blocked contact is `NotApproved`.
    /// Forgets a letter waiting for its token signature.
    pub fn prepare_send(&self, contact: Vec<u8>, sample: Sample) -> Result<(), BrevError> {
        let contact = ContactId(id(&contact)?);
        let sample = brev_hand::Sample::from(sample);
        let (caller, token, address, epoch) = {
            let mut s = self.session()?;
            s.ticket = None;
            s.pending = None;
            let (caller, token) = s.credentials()?;
            s.lock_if_unsafe(&sample)?;
            let (key, env) = s.facts(&sample)?;
            allowed(key, &env)?;
            if s.me.contact_flags(contact)? & BLOCKED != 0 {
                return Err(BrevError::NotApproved);
            }
            let address = Zeroizing::new(s.me.contact_address(contact)?.to_vec());
            (caller, token, address, s.epoch)
        };
        let found = self.net.lookup(&caller, &token, &address);
        drop((token, address));
        let (found, approved) = found?.ok_or(BrevError::NotFound)?;
        let mut s = self.resume(epoch)?;
        s.me.check_key(contact, &found)?;
        if approved {
            s.me.change_flags(contact, APPROVED_ME, 0)?;
        } else {
            s.me.change_flags(contact, 0, APPROVED_ME)?;
            return Err(BrevError::NotApproved);
        }
        s.ticket = Some(contact);
        Ok(())
    }

    /// Step 1: a letter that starts a new thread with `contact`, and its
    /// authorship token (docs/AUTHORSHIP.md §3). The content is
    /// `subject[..subject_len]` and `body[..body_len]`: Swift passes its
    /// whole fixed buffer and the used length. A length over the buffer or
    /// over [`MAX_SUBJECT`] / [`MAX_BODY`] gives `Malformed`. With `sample`
    /// taken just now: a reason to lock locks everything (`Environment`).
    /// `KeyChanged` while the contact's key change waits; `Malformed`
    /// without the ticket of a `prepare_send` for this contact (the ticket
    /// is used up either way). Then the compose session's facts are frozen
    /// with the sample, and their class must reach A (§3.3): `Environment`
    /// with the facts short of it otherwise, also without a compose
    /// session. No I/O. Keeps the letter's plaintext (a vault `Plaintext`,
    /// which `cancel_send` and a lock wipe) and the claims, with the
    /// sender's clock as `iat`, and returns the digest of the token the
    /// identity key signs. Any failure forgets the letter.
    pub fn sign_request(
        &self,
        contact: Vec<u8>,
        subject: &[u8],
        subject_len: u32,
        body: &[u8],
        body_len: u32,
        sample: Sample,
    ) -> Result<Vec<u8>, BrevError> {
        let contact = ContactId(id(&contact)?);
        let subject = used(subject, subject_len, MAX_SUBJECT)?;
        let body = used(body, body_len, MAX_BODY)?;
        let sample = brev_hand::Sample::from(sample);
        let mut s = self.session()?;
        s.letter = None;
        s.pending = None;
        if s.me.is_locked() {
            return Err(BrevError::Locked);
        }
        s.lock_if_unsafe(&sample)?;
        if s.me.pending_bundle(contact)?.is_some() {
            return Err(BrevError::KeyChanged);
        }
        if s.ticket.take() != Some(contact) {
            return Err(BrevError::Malformed);
        }
        let (key, env) = s.facts(&sample)?;
        let class = allowed(key, &env)?;
        let draft = s.me.draft(contact, subject, body)?;
        let claims = Claims::new(draft.letter(), unix_now(), key, env)?;
        debug_assert_eq!(claims.class, class, "one class rule");
        let payload = claims.encode();
        let digest = token::digest(&payload);
        s.pending = Some(Pending {
            draft,
            payload,
            class,
        });
        Ok(digest.to_vec())
    }

    /// Step 2, after the one Touch ID of the letter (docs/AUTHORSHIP.md
    /// §3.2): the Secure Enclave's DER signature over the token digest
    /// `sign_request` returned, checked with the own identity key. Then the
    /// token is assembled, the letter sealed with it (the payload of
    /// protocol version 2), and its plaintext wiped. Returns the envelope's
    /// digest, which the same context signs next. A signature that is not
    /// DER, not by the own key or not over that digest gives `Signing` and
    /// forgets the letter and the ticket; `NotFound` without a letter
    /// waiting for it.
    pub fn attach_token_signature(&self, signature: Vec<u8>) -> Result<Vec<u8>, BrevError> {
        let mut s = self.session()?;
        if s.me.is_locked() {
            return Err(BrevError::Locked);
        }
        let pending = s.pending.take().ok_or(BrevError::NotFound)?;
        let signed = token::signed_bytes(&pending.payload);
        let raw = match s.me.verify_own(&signed, &signature) {
            Ok(raw) => raw,
            Err(e) => {
                s.ticket = None;
                s.letter = None;
                return Err(e.into());
            }
        };
        let token = token::assemble(&pending.payload, &raw);
        let mut letter = s.me.seal_letter(&pending.draft, &token)?;
        drop(pending.draft);
        letter.class = Some(pending.class);
        let digest = letter.digest();
        s.letter = Some(letter);
        Ok(digest.to_vec())
    }

    /// Step 3: attaches the Secure Enclave's DER signature over the
    /// envelope digest `attach_token_signature` returned, checked with the
    /// own identity key. `Signing` clears the letter; `NotFound` if there is
    /// none.
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

    /// Step 4: posts the signed letter with the user's token (the relay
    /// stores it only from its sender). Accepted (or already there): stores
    /// the own copy, forgets the letter and returns the thread id.
    /// `Network` keeps the signed letter, so calling this again resends the
    /// same bytes without a second prompt; `NotApproved` (the recipient
    /// does not take the user's letters), `RateLimited` (the daily limit)
    /// and `Refused` forget it. `NotFound` if no signed letter waits.
    /// Nothing is stored before the relay has it.
    pub fn submit(&self) -> Result<Vec<u8>, BrevError> {
        let (caller, token, envelope, epoch) = {
            let s = self.session()?;
            if s.me.is_locked() {
                return Err(BrevError::Locked);
            }
            let letter = s
                .letter
                .as_ref()
                .filter(|l| l.is_signed())
                .ok_or(BrevError::NotFound)?;
            let envelope = letter.envelope().clone();
            let (caller, token) = s.credentials()?;
            (caller, token, envelope, s.epoch)
        };
        let sent = self.net.submit(&caller, &token, &envelope);
        drop(token);
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
            Err(NetError::Refused(status)) => {
                if same {
                    *letter = None;
                }
                Err(match status {
                    409 => BrevError::NotApproved,
                    429 => BrevError::RateLimited,
                    _ => BrevError::Refused,
                })
            }
        }
    }

    /// Forgets the send ticket and the letter: its plaintext waiting for
    /// the token signature (wiped), and the sealed letter, signed or not.
    /// The compose session goes on. Never fails.
    pub fn cancel_send(&self) {
        let mut s = guard(&self.s);
        s.ticket = None;
        s.pending = None;
        s.letter = None;
    }

    /// Deletes the local invites past their life, tells the relay again of
    /// each block it has not answered yet (`block_contact`), then handles
    /// the events waiting at the relay (docs/PHASE4_DESIGN.md §5.3: requests,
    /// redeemed invites, approvals) and answers them, then fetches the
    /// letters waiting at the relay, stores each, and acknowledges the
    /// stored ones and the ones refused for good (docs/PHASE3_DESIGN.md
    /// §5.3). The events come first, so a letter from an invitee or an
    /// approver arrives in the same sync that pins its sender. Never sends a
    /// letter. `NotFound` before registration (no request); `Locked` if a
    /// lock comes in between (nothing more is stored and nothing is
    /// acknowledged, so the letters and events come again).
    pub fn sync(&self) -> Result<SyncResult, BrevError> {
        let (caller, token, epoch, untold) = {
            let mut s = self.session()?;
            let (caller, token) = s.credentials()?;
            s.me.sweep_invites(today())?;
            let untold = s.me.untold_blocks()?;
            (caller, token, s.epoch, untold)
        };
        let mailbox = self.net.mailbox(caller, token);
        self.blocks_via(&mailbox, &untold, epoch)?;
        let contacts_changed = self.events_via(&mailbox, epoch)?;
        let letters = self.sync_via(&mailbox, epoch)?;
        let requests = self.resume(epoch)?.requests.len();
        Ok(SyncResult {
            letters,
            contacts_changed,
            requests: u32::try_from(requests).unwrap_or(u32::MAX),
        })
    }
}

/// Test hooks, never exported (brev-mail's feature `test-hooks`).
#[cfg(any(test, feature = "test-hooks"))]
impl Brev {
    /// A send ticket for `contact` without `prepare_send`, as a buggy or
    /// hostile app could fake one: the relay's own check must then stop
    /// the letter (docs/PHASE4_DESIGN.md §8, brev-mail test 4).
    pub fn force_ticket_for_test(&self, contact: Vec<u8>) -> Result<(), BrevError> {
        let contact = ContactId(id(&contact)?);
        self.session()?.ticket = Some(contact);
        Ok(())
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
            compose: None,
            pending: None,
            letter: None,
            registration: None,
            requests: Vec::new(),
            invite: None,
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
        for (received_at, env) in &envelopes {
            let mut s = self.resume(epoch)?;
            match s.me.receive(env, *received_at) {
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

    /// The first step of `sync`: each block in `untold` is told to the
    /// relay again without the mutex, and one it answers loses its
    /// `BLOCK_UNTOLD`. One it does not answer keeps it for the next sync.
    fn blocks_via(
        &self,
        net: &Mailbox<'_>,
        untold: &[(ContactId, IdentityId)],
        epoch: u64,
    ) -> Result<(), BrevError> {
        for (contact, peer) in untold {
            if told_block(net.block(&peer.0)).is_ok() {
                self.resume(epoch)?
                    .me
                    .change_flags(*contact, 0, BLOCK_UNTOLD)?;
            }
        }
        Ok(())
    }

    /// Counts one input event (`count`) in the open compose session, if
    /// any. `Locked` while locked.
    fn count_event(&self, count: fn(&mut FactLog)) -> Result<(), BrevError> {
        let mut s = self.session()?;
        if s.me.is_locked() {
            return Err(BrevError::Locked);
        }
        if let Some(c) = s.compose.as_mut() {
            count(&mut c.log);
        }
        Ok(())
    }

    /// The events step of `sync` (docs/PHASE4_DESIGN.md §5.3): fetch the
    /// events without the mutex; take it once per event to handle it; keep
    /// the requests from strangers in the session; then send the answers
    /// without it. An event that is not answered (a changed key, a local
    /// failure, a lost answer) stays at the relay and is handled again by
    /// the next sync, which finds the same state and gives the same answer.
    /// Returns whether a contact changed.
    fn events_via(&self, net: &Mailbox<'_>, epoch: u64) -> Result<bool, BrevError> {
        let events = net.events()?;
        let mut answers = Vec::new();
        let mut asking = Vec::new();
        let mut changed = false;
        for event in &events {
            let mut s = self.resume(epoch)?;
            match s.take_event(event, &mut asking) {
                Ok((answer, c)) => {
                    changed |= c;
                    if let Some(yes) = answer {
                        answers.push((event.bundle.id().0, yes));
                    }
                }
                Err(Error::Locked) => return Err(BrevError::Locked),
                // A local failure: no answer, so the event comes again.
                Err(_) => {}
            }
        }
        self.resume(epoch)?.requests = asking;
        for (peer, yes) in &answers {
            // A lost answer leaves its event at the relay (see above).
            let _ = net.answer(peer, *yes);
        }
        Ok(changed)
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

    /// The texts are closed inside `me.lock()`, under the same mutex; a
    /// letter's plaintext waiting for its token signature is wiped with
    /// `pending`, and the compose session's facts go too (CLAUDE.md §1.10).
    fn lock_all(&mut self) {
        self.ticket = None;
        self.pending = None;
        self.compose = None;
        self.letter = None;
        self.registration = None;
        self.requests.clear();
        self.invite = None;
        self.epoch = self.epoch.wrapping_add(1);
        self.me.lock();
    }

    /// Handles one event under the mutex (docs/PHASE4_DESIGN.md §5.3).
    /// Returns the answer to send (`Some(true)` approve or seen,
    /// `Some(false)` decline, `None` none, so the event comes again) and
    /// whether a contact changed.
    ///
    /// - A request from an address that is not a contact joins `asking`.
    ///   From a contact: the pinned key is approved at once (unless the
    ///   contact is blocked: declined); another key goes into `pending`
    ///   (Phase 3's warning) with no answer, so after `accept_new_key` the
    ///   next sync approves it.
    /// - An invited event is checked against the local invites with the
    ///   tag only a holder of the secret can make (design §3.4). A match
    ///   pins the invitee as approved and verified and deletes that invite;
    ///   a changed key goes into `pending` with no answer and the invite
    ///   kept. No match: seen, and nothing pinned.
    /// - An approved event marks the contact with that key as taking the
    ///   user's letters; seen either way.
    fn take_event(
        &mut self,
        event: &Incoming,
        asking: &mut Vec<Peer>,
    ) -> Result<(Option<bool>, bool), Error> {
        let own = self.me.bundle()?.id();
        let peer = event.bundle.id();
        if peer == own {
            return Ok((None, false));
        }
        match event.kind {
            EventKind::Request => {
                let Some(contact) = self.me.contact_at(&event.address)? else {
                    asking.push(Peer {
                        bundle: event.bundle.clone(),
                        address: event.address.clone(),
                    });
                    return Ok((None, false));
                };
                let (same, wrote) = self.me.compare_key(contact, &event.bundle)?;
                if !same {
                    return Ok((None, wrote));
                }
                if self.me.contact_flags(contact)? & BLOCKED != 0 {
                    return Ok((Some(false), wrote));
                }
                let flagged = self.me.change_flags(contact, APPROVED_ME, 0)?;
                Ok((Some(true), wrote || flagged))
            }
            EventKind::Invited => {
                let invites = self.me.local_invites()?;
                let matched = invites
                    .iter()
                    .find(|i| {
                        invite::tag(&i.secret, &peer.0, &own.0, &event.address)
                            .is_ok_and(|tag| tag == event.tag)
                    })
                    .map(|i| i.id);
                drop(invites);
                crypto::scrub_stack();
                let Some(id) = matched else {
                    return Ok((Some(true), false));
                };
                let flags = APPROVED_ME | VERIFIED;
                let (contact, changed) = self.me.pin(&event.bundle, &event.address, flags)?;
                if contact.is_none() {
                    return Ok((None, changed));
                }
                self.me.delete_invite(&id)?;
                Ok((Some(true), changed))
            }
            EventKind::Approved => {
                let mut changed = false;
                if let Some(contact) = self.me.contact_of(&peer)? {
                    if self.me.contact_flags(contact)? & BLOCKED == 0 {
                        changed = self.me.change_flags(contact, APPROVED_ME, 0)?;
                    }
                }
                Ok((Some(true), changed))
            }
        }
    }

    /// The lock rule for a sample handed over with a call
    /// (docs/AUTHORSHIP.md §4.3): with a reason to lock, everything is
    /// locked and the call gives `Environment` naming the facts.
    fn lock_if_unsafe(&mut self, sample: &brev_hand::Sample) -> Result<(), BrevError> {
        let reasons = lock_reasons(sample);
        if reasons.is_empty() {
            return Ok(());
        }
        self.lock_all();
        Err(names(reasons.into_iter().map(lock_fact)))
    }

    /// The key origin and the facts of the open compose session with
    /// `sample`, taken now; `Environment` naming nothing without one.
    fn facts(&self, sample: &brev_hand::Sample) -> Result<(brev_vault::KeyOrigin, Env), BrevError> {
        let c = self
            .compose
            .as_ref()
            .ok_or(BrevError::Environment { failed: Vec::new() })?;
        Ok((c.key, c.facts(sample)))
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

/// The class of a letter written with a key in `key` under `env`
/// (brev-hand's rule), if it reaches [`SEND_THRESHOLD`]; otherwise
/// `Environment` with the facts short of class A.
fn allowed(key: brev_vault::KeyOrigin, env: &Env) -> Result<EnvironmentClass, BrevError> {
    let (class, failed) = brev_hand::classify(key, env);
    if may_send(class, SEND_THRESHOLD) {
        Ok(class)
    } else {
        Err(names(failed))
    }
}

/// `Environment` naming `facts`.
fn names(facts: impl IntoIterator<Item = &'static str>) -> BrevError {
    BrevError::Environment {
        failed: facts.into_iter().map(str::to_owned).collect(),
    }
}

/// The wall clock in Unix seconds: a token's `iat`.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
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

/// An id of the expected length (16 bytes for a local id, 32 for an
/// identity id).
fn id<const N: usize>(b: &[u8]) -> Result<[u8; N], BrevError> {
    b.try_into().map_err(|_| BrevError::Malformed)
}

/// The relay key `a` of an invite's secret (brev-proto's
/// `invite::relay_key`), in a buffer that wipes itself; then a stack scrub,
/// since SHA-256 ran over the secret.
fn relay_key(secret: &[u8; SECRET_LEN]) -> Zeroizing<[u8; 32]> {
    let key = Zeroizing::new(invite::relay_key(secret));
    crypto::scrub_stack();
    key
}

/// The invitee's tag for the inviter (brev-proto's `invite::tag`); then a
/// stack scrub, since HKDF ran on the secret. An address that breaks the
/// rules is `Malformed`.
fn proof(
    secret: &[u8; SECRET_LEN],
    invitee: &IdentityId,
    inviter: &IdentityId,
    invitee_address: &[u8],
) -> Result<[u8; 32], BrevError> {
    let tag = invite::tag(secret, &invitee.0, &inviter.0, invitee_address);
    crypto::scrub_stack();
    tag.map_err(|_| BrevError::Malformed)
}

/// The contact `Core::pin` pinned, or `KeyChanged` when the address is a
/// contact with another key (now pending).
fn pinned((contact, _): (Option<ContactId>, bool)) -> Result<ContactId, BrevError> {
    contact.ok_or(BrevError::KeyChanged)
}

/// The relay's answer to `/v1/block`: 204, or 404 (it no longer knows
/// that identity), means it takes nothing more from that peer.
fn told_block(answer: Result<(), NetError>) -> Result<(), NetError> {
    match answer {
        Ok(()) | Err(NetError::Refused(404)) => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests;
