//! Every cryptographic operation in the core, built only from audited crates
//! (CLAUDE.md §1.7). Two uses of XChaCha20-Poly1305:
//!
//! * columns: key = DEK, random nonce, stored as `nonce || ct || tag`,
//!   AD = column label and the row's immutable fields;
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

impl std::ops::Deref for Plaintext {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

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
pub(crate) fn static_secret(bytes: &[u8]) -> Result<StaticSecret, Error> {
    let arr: [u8; 32] = bytes.try_into().map_err(|_| Error::Crypto)?;
    Ok(StaticSecret::from(arr))
}

/// Encrypts a column value under the DEK: `nonce || ciphertext || tag`.
pub(crate) fn seal_column(dek: &[u8; 32], ad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let nonce: [u8; NONCE_LEN] = random()?;
    let r = encrypt(dek, &nonce, ad, &nonce, plaintext);
    scrub_stack();
    r
}

/// Decrypts a value written by [`seal_column`].
pub(crate) fn open_column(dek: &[u8; 32], ad: &[u8], stored: &[u8]) -> Result<Plaintext, Error> {
    let (nonce, rest) = stored.split_at_checked(NONCE_LEN).ok_or(Error::Crypto)?;
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| Error::Crypto)?;
    let r = decrypt(dek, &nonce, ad, rest);
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
    let mut buf = [0xA5u8; 16 * 1024];
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
    Ok(Plaintext(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn column_round_trip_and_ad_binding() {
        let dek: [u8; 32] = random().unwrap();
        let ad = column_ad("messages.body", &[&[1; 16]]);
        let sealed = seal_column(&dek, &ad, b"hello").unwrap();
        assert_eq!(sealed.len(), NONCE_LEN + 5 + TAG_LEN);
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

    #[test]
    fn low_order_public_key_is_rejected() {
        let mut s = [0u8; 32];
        fill(&mut s).unwrap();
        let secret = StaticSecret::from(s);
        let r = seal_message(&secret, &[0u8; 32], [1; 32], [2; 32], b"x");
        assert!(matches!(r, Err(Error::Crypto)));
    }
}
