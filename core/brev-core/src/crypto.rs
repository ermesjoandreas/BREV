//! Every cryptographic operation in the core, built only from audited crates
//! (CLAUDE.md §1.7). Two uses of XChaCha20-Poly1305:
//!
//! * columns: key = DEK, random nonce, stored as `nonce || ct || tag`,
//!   AD = column label and the row's immutable fields. The plaintext is
//!   padded with `brev_proto::pad_into` first, so a stored length shows only
//!   the bucket;
//! * messages: key = HKDF-SHA256(salt = nonce, ikm = X25519(static, static),
//!   info = label || sender id || recipient id), AD = envelope header.
//!
//! Plaintext only ever sits in a [`Zeroizing`] buffer, a [`Plaintext`], or the
//! caller's slice.

use brev_proto::Envelope;
use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{KeyInit, Tag, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::rngs::SysRng;
use rand::TryRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::Error;

const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const IDENTITY_LABEL: &[u8] = b"brev/v0/identity";
const MESSAGE_KEY_LABEL: &[u8] = b"brev/v0/message-key";
const COLUMN_LABEL: &[u8] = b"brev/v0/column/";

/// Fills `out` from the OS CSPRNG.
pub(crate) fn fill(out: &mut [u8]) -> Result<(), Error> {
    SysRng.try_fill_bytes(out).map_err(|_| Error::Rng)
}

/// Random non-secret bytes (ids, nonces).
pub(crate) fn random<const N: usize>() -> Result<[u8; N], Error> {
    let mut out = [0u8; N];
    fill(&mut out)?;
    Ok(out)
}

/// Identity id: SHA-256("brev/v0/identity" || len || signing key || X25519
/// key). `signing_key` is 1..=255 bytes (checked by the caller), so the
/// encoding is unambiguous.
pub(crate) fn identity_id(signing_key: &[u8], x25519: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(IDENTITY_LABEL);
    h.update([u8::try_from(signing_key.len()).unwrap_or(0)]);
    h.update(signing_key);
    h.update(x25519);
    h.finalize().into()
}

/// AEAD associated data for a column: label, NUL, then the row's immutable
/// fields. Every label always gets the same fixed-length fields, so the
/// concatenation is unambiguous.
pub(crate) fn column_ad(label: &str, fields: &[&[u8]]) -> Vec<u8> {
    let mut ad = [COLUMN_LABEL, label.as_bytes(), &[0]].concat();
    for f in fields {
        ad.extend_from_slice(f);
    }
    ad
}

/// Decrypted content handed to a caller: a name, a subject or a body.
///
/// Read-only bytes, wiped on drop. It has no `Debug`, `Clone` or `DerefMut`,
/// so it cannot be printed by `{:?}`, `dbg!` or a panic message, and the
/// caller cannot grow it (a reallocation would free an unwiped copy).
///
/// ```
/// fn read(p: &brev_core::Plaintext) -> usize { p.len() }
/// ```
/// ```compile_fail
/// fn print(p: &brev_core::Plaintext) -> String { format!("{p:?}") }
/// ```
/// ```compile_fail
/// fn grow(p: &mut brev_core::Plaintext) { p.push(0) }
/// ```
pub struct Plaintext(Zeroizing<Vec<u8>>);

impl Plaintext {
    pub(crate) fn new(buf: Zeroizing<Vec<u8>>) -> Plaintext {
        #[cfg(test)]
        LIVE_PLAINTEXTS.with(|n| n.set(n.get() + 1));
        Plaintext(buf)
    }
}

impl std::ops::Deref for Plaintext {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
impl Drop for Plaintext {
    fn drop(&mut self) {
        LIVE_PLAINTEXTS.with(|n| n.set(n.get() - 1));
    }
}

/// The X25519 identity secret, built for one operation by [`static_secret`].
/// `StaticSecret` wipes itself on drop. Test builds count the live ones, and
/// their `Drop` forbids moving the secret out of this wrapper uncounted.
pub(crate) struct Secret(StaticSecret);

impl std::ops::Deref for Secret {
    type Target = StaticSecret;
    fn deref(&self) -> &StaticSecret {
        &self.0
    }
}

#[cfg(test)]
impl Drop for Secret {
    fn drop(&mut self) {
        LIVE_SECRETS.with(|n| n.set(n.get() - 1));
    }
}

#[cfg(test)]
thread_local! {
    static LIVE_PLAINTEXTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static SECRETS_BUILT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static LIVE_SECRETS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static SCRUBS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static DEEP_SCRUBS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Test only: `Plaintext` values alive on this thread.
#[cfg(test)]
pub(crate) fn live_plaintexts() -> usize {
    LIVE_PLAINTEXTS.with(|n| n.get())
}

/// Test only: how many times [`static_secret`] has run on this thread.
#[cfg(test)]
pub(crate) fn secrets_built() -> usize {
    SECRETS_BUILT.with(|n| n.get())
}

/// Test only: [`Secret`] values (X25519 identity secrets) alive on this thread.
#[cfg(test)]
pub(crate) fn live_secrets() -> usize {
    LIVE_SECRETS.with(|n| n.get())
}

/// Test only: how many times [`scrub_stack`] has run on this thread.
#[cfg(test)]
pub(crate) fn scrubs() -> usize {
    SCRUBS.with(|n| n.get())
}

/// Test only: how many times [`scrub_stack_deep`] has run on this thread.
#[cfg(test)]
pub(crate) fn deep_scrubs() -> usize {
    DEEP_SCRUBS.with(|n| n.get())
}

/// Test only: compiles only if `T` wipes itself on drop. Memory cannot be
/// read back without `unsafe`, so this pins the wiping type instead.
#[cfg(test)]
pub(crate) fn wiped_on_drop<T: zeroize::ZeroizeOnDrop + ?Sized>(_: &T) {}

/// True if every byte is zero. Used to refuse an all-zero DEK, which is also
/// the value of a locked core's key buffer.
pub(crate) fn is_zero(key: &[u8; 32]) -> bool {
    key.iter().fold(0u8, |acc, b| acc | b) == 0
}

/// The X25519 public key of `secret`. `PublicKey::from` copies the secret by
/// value onto the stack, so scrub after it.
pub(crate) fn public_key(secret: &StaticSecret) -> [u8; 32] {
    let p = PublicKey::from(secret).to_bytes();
    scrub_stack();
    p
}

/// Builds a static secret from decrypted bytes.
pub(crate) fn static_secret(bytes: &[u8]) -> Result<Secret, Error> {
    let arr: [u8; 32] = bytes.try_into().map_err(|_| Error::Crypto)?;
    #[cfg(test)]
    SECRETS_BUILT.with(|n| n.set(n.get() + 1));
    #[cfg(test)]
    LIVE_SECRETS.with(|n| n.set(n.get() + 1));
    Ok(Secret(StaticSecret::from(arr)))
}

/// Pads a column value and encrypts it under the DEK:
/// `nonce || ciphertext || tag`, with the ciphertext exactly one bucket long.
/// Content above the padding maximum gives `Malformed`.
pub(crate) fn seal_column(dek: &[u8; 32], ad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let nonce: [u8; NONCE_LEN] = random()?;
    let r = pad(plaintext).and_then(|padded| encrypt(dek, &nonce, ad, &nonce, &padded));
    scrub_stack();
    r
}

/// `content` padded to its bucket, in a buffer of exactly that length that
/// wipes itself.
fn pad(content: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let n = brev_proto::padded_len(content.len()).ok_or(Error::Malformed)?;
    let mut out = Zeroizing::new(vec![0u8; n]);
    brev_proto::pad_into(content, &mut out).map_err(|_| Error::Malformed)?;
    Ok(out)
}

/// Decrypts a value written by [`seal_column`] and strips the padding. The
/// padded plaintext is wiped when it drops; the content is copied into a
/// `Plaintext` of exact length. Bad padding under a valid tag gives `Crypto`.
pub(crate) fn open_column(dek: &[u8; 32], ad: &[u8], stored: &[u8]) -> Result<Plaintext, Error> {
    let (nonce, rest) = stored.split_at_checked(NONCE_LEN).ok_or(Error::Crypto)?;
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| Error::Crypto)?;
    let r = decrypt(dek, &nonce, ad, rest).and_then(|padded| {
        let content = brev_proto::unpad(&padded).map_err(|_| Error::Crypto)?;
        Ok(Plaintext::new(Zeroizing::new(content.to_vec())))
    });
    scrub_stack();
    r
}

/// Seals `payload` from `sender` to `recipient`. The signature slot is empty.
pub(crate) fn seal_message(
    my_secret: &StaticSecret,
    their_public: &[u8; 32],
    sender: [u8; 32],
    recipient: [u8; 32],
    payload: &[u8],
) -> Result<Envelope, Error> {
    let nonce: [u8; NONCE_LEN] = random()?;
    let r = message_key(my_secret, their_public, &sender, &recipient, &nonce).and_then(|key| {
        let ad = Envelope::header_bytes(&sender, &recipient, &nonce);
        encrypt(&key, &nonce, &ad, &[], payload)
    });
    scrub_stack();
    Ok(Envelope {
        sender,
        recipient,
        nonce,
        ciphertext: r?,
        signature: Vec::new(),
    })
}

/// Opens an envelope addressed to the holder of `my_secret`.
pub(crate) fn open_message(
    my_secret: &StaticSecret,
    their_public: &[u8; 32],
    env: &Envelope,
) -> Result<Plaintext, Error> {
    let r = message_key(
        my_secret,
        their_public,
        &env.sender,
        &env.recipient,
        &env.nonce,
    )
    .and_then(|key| {
        let ad = Envelope::header_bytes(&env.sender, &env.recipient, &env.nonce);
        decrypt(&key, &env.nonce, &ad, &env.ciphertext)
    });
    scrub_stack();
    r
}

/// Best-effort overwrite of the stack region that the cipher, HKDF and
/// X25519 code just used. Those crates leave key-equivalent locals there
/// (the HChaCha20 state, the HKDF intermediate key, by-value scalar copies)
/// that no `zeroize` feature reaches. Unobservable without `unsafe`, so it is
/// defence in depth, not a guarantee: an accepted residual risk (CLAUDE.md §2).
///
/// Fills a stack buffer with a pattern, wipes it with volatile writes, and
/// returns how many bytes are still non-zero (always 0). The fill and the
/// read-back both go through `black_box`, so the optimiser must do them on
/// real memory and cannot drop the wipe as a dead store. Callers ignore the
/// result; a test asserts it in release builds (scripts/test.sh).
#[inline(never)]
pub(crate) fn scrub_stack() -> usize {
    #[cfg(test)]
    SCRUBS.with(|n| n.set(n.get() + 1));
    let mut buf = [0xA5u8; 16 * 1024];
    std::hint::black_box(&mut buf);
    buf.zeroize();
    std::hint::black_box(&buf)
        .iter()
        .filter(|&&b| b != 0)
        .count()
}

/// [`scrub_stack`] with a 64 KiB buffer (CLAUDE.md §2). Runs once at the end
/// of every `Brev::unlock`, on the thread that has just run the Secure
/// Enclave unwrap, where the Phase 2 spike found key-agreement residue up to
/// 64 KiB deep. Best effort in the same way; a test asserts the result in
/// release builds.
#[inline(never)]
pub(crate) fn scrub_stack_deep() -> usize {
    #[cfg(test)]
    DEEP_SCRUBS.with(|n| n.set(n.get() + 1));
    let mut buf = [0xA5u8; 64 * 1024];
    std::hint::black_box(&mut buf);
    buf.zeroize();
    std::hint::black_box(&buf)
        .iter()
        .filter(|&&b| b != 0)
        .count()
}

/// HKDF-SHA256(salt = nonce, ikm = X25519(mine, theirs),
/// info = label || sender id || recipient id). One key per message.
fn message_key(
    my_secret: &StaticSecret,
    their_public: &[u8; 32],
    sender: &[u8; 32],
    recipient: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let shared = my_secret.diffie_hellman(&PublicKey::from(*their_public));
    if !shared.was_contributory() {
        return Err(Error::Crypto);
    }
    let hk = Hkdf::<Sha256>::new(Some(nonce), shared.as_bytes());
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand_multi_info(&[MESSAGE_KEY_LABEL, sender, recipient], key.as_mut_slice())
        .map_err(|_| Error::Crypto)?;
    Ok(key)
}

/// `prefix || XChaCha20-Poly1305(key, nonce, ad, plaintext) || tag`.
///
/// The plaintext is copied into a buffer with its final capacity already
/// reserved and encrypted in place, so no reallocation ever leaves a
/// plaintext copy behind; on error the buffer is wiped.
fn encrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    ad: &[u8],
    prefix: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let cap = prefix.len() + plaintext.len() + TAG_LEN;
    let mut buf = Zeroizing::new(Vec::with_capacity(cap));
    buf.extend_from_slice(prefix);
    buf.extend_from_slice(plaintext);
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::Crypto)?;
    let tag = cipher
        .encrypt_inout_detached(&XNonce::from(*nonce), ad, (&mut buf[prefix.len()..]).into())
        .map_err(|_| Error::Crypto)?;
    buf.extend_from_slice(&tag);
    debug_assert_eq!(buf.capacity(), cap, "plaintext buffer reallocated");
    Ok(std::mem::take(&mut *buf))
}

/// Inverse of [`encrypt`] without the prefix. The tag is checked before any
/// byte is decrypted, so a failed call never produces plaintext.
fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    ad: &[u8],
    ct_and_tag: &[u8],
) -> Result<Plaintext, Error> {
    let n = ct_and_tag.len().checked_sub(TAG_LEN).ok_or(Error::Crypto)?;
    let tag = Tag::try_from(&ct_and_tag[n..]).map_err(|_| Error::Crypto)?;
    let mut buf = Zeroizing::new(ct_and_tag[..n].to_vec());
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::Crypto)?;
    cipher
        .decrypt_inout_detached(&XNonce::from(*nonce), ad, buf.as_mut_slice().into(), &tag)
        .map_err(|_| Error::Crypto)?;
    Ok(Plaintext::new(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn column_round_trip_and_ad_binding() {
        let dek: [u8; 32] = random().unwrap();
        let ad = column_ad("messages.body", &[&[1; 16]]);
        let sealed = seal_column(&dek, &ad, b"hello").unwrap();
        assert_eq!(sealed.len(), NONCE_LEN + 256 + TAG_LEN);
        assert_eq!(&open_column(&dek, &ad, &sealed).unwrap()[..], b"hello");
        let other_row = column_ad("messages.body", &[&[2; 16]]);
        assert!(matches!(
            open_column(&dek, &other_row, &sealed),
            Err(Error::Crypto)
        ));
        let other_column = column_ad("threads.subject", &[&[1; 16]]);
        assert!(matches!(
            open_column(&dek, &other_column, &sealed),
            Err(Error::Crypto)
        ));
        let other_dek: [u8; 32] = random().unwrap();
        assert!(matches!(
            open_column(&other_dek, &ad, &sealed),
            Err(Error::Crypto)
        ));
    }

    /// Also run with `--release` by scripts/test.sh, where the optimiser
    /// would drop a wipe it could prove dead.
    #[test]
    fn scrub_stack_wipes_its_buffer() {
        assert_eq!(scrub_stack(), 0);
    }

    /// Also run with `--release` by scripts/test.sh.
    #[test]
    fn scrub_stack_deep_wipes_its_buffer() {
        let before = deep_scrubs();
        assert_eq!(scrub_stack_deep(), 0);
        assert_eq!(deep_scrubs(), before + 1);
    }

    /// A value above the padding maximum is refused before anything is
    /// encrypted, and a correctly tagged value with bad padding does not
    /// open.
    #[test]
    fn column_padding_is_enforced() {
        let dek: [u8; 32] = random().unwrap();
        let big = vec![0u8; brev_proto::MAX_PADDED - 3];
        assert!(matches!(
            seal_column(&dek, b"ad", &big),
            Err(Error::Malformed)
        ));
        let n = brev_proto::MAX_PADDED - 4;
        let sealed = seal_column(&dek, b"ad", &big[..n]).unwrap();
        assert_eq!(sealed.len(), NONCE_LEN + brev_proto::MAX_PADDED + TAG_LEN);
        assert_eq!(open_column(&dek, b"ad", &sealed).unwrap().len(), n);
        // Unpadded content sealed under the right key and AD (a v1 column).
        let nonce: [u8; NONCE_LEN] = random().unwrap();
        let raw = encrypt(&dek, &nonce, b"ad", &nonce, b"hello").unwrap();
        assert!(matches!(open_column(&dek, b"ad", &raw), Err(Error::Crypto)));
    }

    /// Every operation on key material ends with one stack scrub, so
    /// deleting a call site fails here.
    #[test]
    fn every_key_operation_scrubs_the_stack() {
        fn scrubs_in(f: impl FnOnce()) -> usize {
            let before = scrubs();
            f();
            scrubs() - before
        }
        let dek: [u8; 32] = random().unwrap();
        let (a, b) = (secret(), secret());
        let (mut pa, mut pb, mut sealed, mut env) = ([0; 32], [0; 32], Vec::new(), None);
        assert_eq!(scrubs_in(|| pa = public_key(&a)), 1);
        assert_eq!(scrubs_in(|| pb = public_key(&b)), 1);
        assert_eq!(
            scrubs_in(|| sealed = seal_column(&dek, b"ad", b"x").unwrap()),
            1
        );
        assert_eq!(scrubs_in(|| drop(open_column(&dek, b"ad", &sealed))), 1);
        assert_eq!(
            scrubs_in(|| env = seal_message(&a, &pb, [1; 32], [2; 32], b"x").ok()),
            1
        );
        let env = env.unwrap();
        assert_eq!(scrubs_in(|| drop(open_message(&b, &pa, &env))), 1);
        // The echo peers' HKDF over the user DEK (echo.rs); `Brev::create`
        // is pinned in ffi.rs.
        assert_eq!(scrubs_in(|| drop(crate::echo::peer_dek(&dek, 0))), 1);
    }

    #[test]
    fn low_order_public_key_is_rejected() {
        let mut s = [0u8; 32];
        fill(&mut s).unwrap();
        let secret = StaticSecret::from(s);
        let r = seal_message(&secret, &[0u8; 32], [1; 32], [2; 32], b"x");
        assert!(matches!(r, Err(Error::Crypto)));
    }

    fn secret() -> StaticSecret {
        StaticSecret::from(random::<32>().unwrap())
    }

    /// The key needs one party's X25519 secret: a third party (or the relay)
    /// cannot open a letter, and neither can its sender once the header is
    /// reflected back to it.
    #[test]
    fn only_the_two_parties_can_open_a_message() {
        let (a, b, c) = (secret(), secret(), secret());
        let (pa, pb) = (public_key(&a), public_key(&b));
        let env = seal_message(&a, &pb, [1; 32], [2; 32], b"letter").unwrap();
        assert_eq!(&open_message(&b, &pa, &env).unwrap()[..], b"letter");
        assert!(matches!(open_message(&c, &pa, &env), Err(Error::Crypto)));
        let mut reflected = env.clone();
        (reflected.sender, reflected.recipient) = (env.recipient, env.sender);
        assert!(matches!(
            open_message(&a, &pb, &reflected),
            Err(Error::Crypto)
        ));
    }

    /// With both X25519 keys unchanged, a letter relabelled with another
    /// sender or recipient id does not open. Clients do not verify
    /// signatures in Phase 1, so this binding is what stops a contact whose
    /// bundle reuses someone's X25519 key from receiving their letters under
    /// its own name.
    #[test]
    fn a_letter_is_bound_to_both_ids() {
        let (a, b) = (secret(), secret());
        let (pa, pb) = (public_key(&a), public_key(&b));
        let env = seal_message(&a, &pb, [1; 32], [2; 32], b"x").unwrap();
        assert_eq!(&open_message(&b, &pa, &env).unwrap()[..], b"x");
        let mut e = env.clone();
        e.sender = [3; 32];
        assert!(matches!(open_message(&b, &pa, &e), Err(Error::Crypto)));
        let mut e = env.clone();
        e.recipient = [3; 32];
        assert!(matches!(open_message(&b, &pa, &e), Err(Error::Crypto)));
    }

    /// Closing a letter wipes it: `Plaintext` holds a buffer that zeroizes
    /// itself on drop (checked at compile time).
    #[test]
    fn plaintext_wipes_on_drop() {
        let p = Plaintext::new(Zeroizing::new(vec![1]));
        wiped_on_drop(&p.0);
    }

    /// Every seal draws a fresh nonce, so the same input never repeats a
    /// (key, nonce) pair or a ciphertext.
    #[test]
    fn every_seal_uses_a_fresh_nonce() {
        let dek: [u8; 32] = random().unwrap();
        let c1 = seal_column(&dek, b"ad", b"same").unwrap();
        let c2 = seal_column(&dek, b"ad", b"same").unwrap();
        assert_ne!(c1[..NONCE_LEN], c2[..NONCE_LEN]);
        assert_ne!(c1[NONCE_LEN..], c2[NONCE_LEN..]);
        let (a, b) = (secret(), secret());
        let pb = public_key(&b);
        let e1 = seal_message(&a, &pb, [1; 32], [2; 32], b"same").unwrap();
        let e2 = seal_message(&a, &pb, [1; 32], [2; 32], b"same").unwrap();
        assert_ne!(e1.nonce, e2.nonce);
        assert_ne!(e1.ciphertext, e2.ciphertext);
    }

    /// The id commits to both keys, so a relay cannot swap the X25519 key
    /// behind a known id.
    #[test]
    fn identity_id_commits_to_both_keys() {
        let id = identity_id(&[7; 32], &[1; 32]);
        assert_ne!(id, identity_id(&[7; 32], &[2; 32]));
        assert_ne!(id, identity_id(&[8; 32], &[1; 32]));
    }
}
