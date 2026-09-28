//! The UniFFI surface (CLAUDE.md §3.1, docs/PHASE3_DESIGN.md §5.6):
//! [`Brev`], the session the app holds, and [`OpenText`], one decrypted
//! address, subject or body.
//!
//! Content goes in only as `&[u8]` plus a used length (zero-copy
//! `ForeignBytes`) and comes out only through [`OpenText::chunk`], in chunks
//! of exactly [`CHUNK`] bytes. No `String` carries content in either
//! direction (the only ones are the store directory and the relay URL),
//! errors are unit variants, and records carry ids, codes and metadata only.
//!
//! No call that takes content does network I/O, and no network call takes
//! content (§3.2). Every network call runs with the session mutex released,
//! so `lock()` never waits for the relay; the session's lock epoch tells the
//! second half of a call that a lock came in between (§5.2).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

use brev_proto::body::{self, is_valid_address, ADDRESS_MAX};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto::{self, Plaintext};
use crate::relay::RelayTransport;
use crate::store::{is_permanent, Letter};
use crate::transport::{NetError, Transport};
use crate::{ContactId, Core, Error, MessageId, ThreadId};

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
        }
    }
}

impl From<NetError> for BrevError {
    fn from(e: NetError) -> Self {
        Error::from(e).into()
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

/// The app's session: the user's store and the relay client.
#[derive(uniffi::Object)]
pub struct Brev {
    s: Mutex<Session>,
    net: RelayTransport,
}

struct Session {
    me: Core,
    /// Every `OpenText` handed out; `lock_all` closes the ones still alive.
    open: Vec<Weak<OpenText>>,
    /// Bumped by every lock. A call that released the mutex for the network
    /// and finds another epoch when it takes it again stores nothing.
    epoch: u64,
    /// The contact `prepare_send` found with its pinned key just now; used
    /// once by `sign_request`.
    ticket: Option<ContactId>,
    /// The one letter being sent (ciphertext only): sealed by
    /// `sign_request`, signed by `attach_signature`, stored by `submit`.
    letter: Option<Letter>,
    /// The registration being made: its unsigned body and the address.
    registration: Option<Registering>,
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
        let me = Core::open(&PathBuf::from(dir).join(MY_FILE))?;
        Ok(Arc::new(Brev::new(me, net)))
    }

    /// Unlocks with the DEK. A DEK that is not 32 bytes gives `WrongKey`.
    /// Any failure, also a panic, leaves the session locked. Every exit
    /// ends with a 64 KiB stack scrub.
    pub fn unlock(&self, dek: &[u8]) -> Result<(), BrevError> {
        let mut fin = Finish { s: None, ok: false };
        let s = fin.s.insert(self.session()?);
        let r = unlock_all(s, dek);
        fin.ok = r.is_ok();
        r
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

    /// Step 0 of a letter (docs/PHASE3_DESIGN.md §3.2), without content:
    /// looks the contact's address up at the relay. The pinned key gives
    /// the send ticket for this contact (and clears a pending change); any
    /// other key is kept as pending and gives `KeyChanged`. `NotFound` if
    /// the relay has no such address or this user is not registered;
    /// `Network`, `Refused`.
    pub fn prepare_send(&self, contact: Vec<u8>) -> Result<(), BrevError> {
        let contact = ContactId(id(&contact)?);
        let (caller, token, address, epoch) = {
            let mut s = self.session()?;
            s.ticket = None;
            let (caller, token) = s.credentials()?;
            let address = Zeroizing::new(s.me.contact_address(contact)?.to_vec());
            (caller, token, address, s.epoch)
        };
        let found = self.net.lookup(&caller, &token, &address);
        drop((token, address));
        let found = found?.ok_or(BrevError::NotFound)?;
        let mut s = self.resume(epoch)?;
        s.me.check_key(contact, &found)?;
        s.ticket = Some(contact);
        Ok(())
    }

    /// Step 1: seals a letter that starts a new thread with `contact`. The
    /// content is `subject[..subject_len]` and `body[..body_len]`: Swift
    /// passes its whole fixed buffer and the used length. A length over the
    /// buffer or over [`MAX_SUBJECT`] / [`MAX_BODY`] gives `Malformed`.
    /// `KeyChanged` while the contact's key change waits; `Malformed`
    /// without the ticket of a `prepare_send` for this contact (the ticket
    /// is used up either way). No I/O. Keeps the sealed letter (ciphertext
    /// only) and returns the digest the identity key signs.
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
        if s.ticket.take() != Some(contact) {
            return Err(BrevError::Malformed);
        }
        let letter = s.me.seal_letter(contact, subject, body)?;
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
    fn new(me: Core, net: RelayTransport) -> Brev {
        Brev {
            s: Mutex::new(Session {
                me,
                open: Vec::new(),
                epoch: 0,
                ticket: None,
                letter: None,
                registration: None,
            }),
            net,
        }
    }

    fn create_in(
        dir: &Path,
        relay: &str,
        dek: &[u8],
        signing_key: &[u8],
    ) -> Result<Brev, BrevError> {
        let net = RelayTransport::new(relay)?;
        let mut key = dek32(dek).ok_or(BrevError::Malformed)?;
        let mut me = Core::create(&dir.join(MY_FILE), &mut key, signing_key)?;
        me.lock();
        Ok(Brev::new(me, net))
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
        self.ticket = None;
        self.letter = None;
        self.registration = None;
        self.epoch = self.epoch.wrapping_add(1);
        self.me.lock();
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
