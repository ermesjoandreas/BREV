//! The vault's cryptography, built only from audited crates (CLAUDE.md
//! §1.7): XChaCha20-Poly1305 for the store's columns. Key = DEK, random
//! nonce, stored as `nonce || ct || tag`, AD = column label and the row's
//! immutable fields. The plaintext is padded with [`crate::padding`] first,
//! so a stored length shows only the bucket. [`aead_seal`] and
//! [`aead_open`] are the same AEAD under a caller's own key and nonce.
//!
//! Plaintext only ever sits in a [`Zeroizing`] buffer, a [`Plaintext`], or the
//! caller's slice. The stack scrubs live here too.
//!
//! Test builds (`cfg(test)`, or the feature `test-hooks` for the tests of
//! the crates built on the vault) count, per thread, the live `Plaintext`
//! values and the stack scrubs; `test_hooks` exports the counters.

use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{KeyInit, Tag, XChaCha20Poly1305, XNonce};
use rand::rngs::SysRng;
use rand::TryRng;
use zeroize::{Zeroize, Zeroizing};

use crate::padding::{pad_into, padded_len, unpad};
use crate::Error;

/// Length of an XChaCha20-Poly1305 nonce.
pub const NONCE_LEN: usize = 24;
/// Length of a Poly1305 tag.
pub const TAG_LEN: usize = 16;
const COLUMN_LABEL: &[u8] = b"brev/v0/column/";

/// Fills `out` from the OS CSPRNG.
pub fn fill(out: &mut [u8]) -> Result<(), Error> {
    SysRng.try_fill_bytes(out).map_err(|_| Error::Rng)
}

/// Random non-secret bytes (ids, nonces).
pub fn random<const N: usize>() -> Result<[u8; N], Error> {
    let mut out = [0u8; N];
    fill(&mut out)?;
    Ok(out)
}

/// True if every byte is zero. Used to refuse an all-zero DEK, which is also
/// the value of a locked store's key buffer.
pub fn is_zero(key: &[u8; 32]) -> bool {
    key.iter().fold(0u8, |acc, b| acc | b) == 0
}

/// AEAD associated data for a column: label, NUL, then the row's immutable
/// fields. Every label always gets the same fixed-length fields, so the
/// concatenation is unambiguous.
pub fn column_ad(label: &str, fields: &[&[u8]]) -> Vec<u8> {
    let mut ad = [COLUMN_LABEL, label.as_bytes(), &[0]].concat();
    for f in fields {
        ad.extend_from_slice(f);
    }
    ad
}

#[cfg(any(test, feature = "test-hooks"))]
thread_local! {
    static LIVE_PLAINTEXTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static SCRUBS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static DEEP_SCRUBS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Test only: `Plaintext` values alive on this thread.
#[cfg(any(test, feature = "test-hooks"))]
pub fn live_plaintexts() -> usize {
    LIVE_PLAINTEXTS.with(|n| n.get())
}

/// Decrypted content handed to a caller: a name, a subject or a body.
///
/// Read-only bytes, wiped on drop. It has no `Debug`, `Clone` or `DerefMut`,
/// so it cannot be printed by `{:?}`, `dbg!` or a panic message, and the
/// caller cannot grow it (a reallocation would free an unwiped copy).
///
/// ```
/// fn read(p: &brev_vault::Plaintext) -> usize { p.len() }
/// ```
/// ```compile_fail
/// fn print(p: &brev_vault::Plaintext) -> String { format!("{p:?}") }
/// ```
/// ```compile_fail
/// fn grow(p: &mut brev_vault::Plaintext) { p.push(0) }
/// ```
pub struct Plaintext(Zeroizing<Vec<u8>>);

impl Plaintext {
    /// Takes a buffer that already wipes itself.
    pub fn new(buf: Zeroizing<Vec<u8>>) -> Plaintext {
        #[cfg(any(test, feature = "test-hooks"))]
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

#[cfg(any(test, feature = "test-hooks"))]
impl Drop for Plaintext {
    fn drop(&mut self) {
        // Wraps on a thread that drops what another made (the timer's wipe).
        LIVE_PLAINTEXTS.with(|n| n.set(n.get().wrapping_sub(1)));
    }
}

/// Test only: how many times [`scrub_stack`] has run on this thread.
#[cfg(any(test, feature = "test-hooks"))]
pub fn scrubs() -> usize {
    SCRUBS.with(|n| n.get())
}

/// Test only: how many times [`scrub_stack_deep`] has run on this thread.
#[cfg(any(test, feature = "test-hooks"))]
pub fn deep_scrubs() -> usize {
    DEEP_SCRUBS.with(|n| n.get())
}

/// Test only: compiles only if `T` wipes itself on drop. Memory cannot be
/// read back without `unsafe`, so this pins the wiping type instead.
#[cfg(any(test, feature = "test-hooks"))]
pub fn wiped_on_drop<T: zeroize::ZeroizeOnDrop + ?Sized>(_: &T) {}

/// Pads a column value and encrypts it under the DEK:
/// `nonce || ciphertext || tag`, with the ciphertext exactly one bucket long.
/// Content above the padding maximum gives `Malformed`.
pub fn seal_column(dek: &[u8; 32], ad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let nonce: [u8; NONCE_LEN] = random()?;
    let r = pad(plaintext).and_then(|padded| aead_seal(dek, &nonce, ad, &nonce, &padded));
    scrub_stack();
    r
}

/// `content` padded to its bucket, in a buffer of exactly that length that
/// wipes itself. Content above the padding maximum gives `Malformed`.
pub fn pad(content: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let n = padded_len(content.len()).ok_or(Error::Malformed)?;
    let mut out = Zeroizing::new(vec![0u8; n]);
    pad_into(content, &mut out).map_err(|_| Error::Malformed)?;
    Ok(out)
}

/// Decrypts a value written by [`seal_column`] and strips the padding. The
/// padded plaintext is wiped when it drops; the content is copied into a
/// `Plaintext` of exact length. Bad padding under a valid tag gives `Crypto`.
pub fn open_column(dek: &[u8; 32], ad: &[u8], stored: &[u8]) -> Result<Plaintext, Error> {
    let (nonce, rest) = stored.split_at_checked(NONCE_LEN).ok_or(Error::Crypto)?;
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| Error::Crypto)?;
    let r = aead_open(dek, &nonce, ad, rest).and_then(|padded| {
        let content = unpad(&padded).map_err(|_| Error::Crypto)?;
        Ok(Plaintext::new(Zeroizing::new(content.to_vec())))
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
pub fn scrub_stack() -> usize {
    #[cfg(any(test, feature = "test-hooks"))]
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
pub fn scrub_stack_deep() -> usize {
    #[cfg(any(test, feature = "test-hooks"))]
    DEEP_SCRUBS.with(|n| n.set(n.get() + 1));
    let mut buf = [0xA5u8; 64 * 1024];
    std::hint::black_box(&mut buf);
    buf.zeroize();
    std::hint::black_box(&buf)
        .iter()
        .filter(|&&b| b != 0)
        .count()
}

/// `prefix || XChaCha20-Poly1305(key, nonce, ad, plaintext) || tag`.
///
/// The plaintext is copied into a buffer with its final capacity already
/// reserved and encrypted in place, so no reallocation ever leaves a
/// plaintext copy behind; on error the buffer is wiped.
pub fn aead_seal(
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

/// Inverse of [`aead_seal`] without the prefix. The tag is checked before
/// any byte is decrypted, so a failed call never produces plaintext.
pub fn aead_open(
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
    use crate::padding::MAX_PADDED;

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
        let big = vec![0u8; MAX_PADDED - 3];
        assert!(matches!(
            seal_column(&dek, b"ad", &big),
            Err(Error::Malformed)
        ));
        let n = MAX_PADDED - 4;
        let sealed = seal_column(&dek, b"ad", &big[..n]).unwrap();
        assert_eq!(sealed.len(), NONCE_LEN + MAX_PADDED + TAG_LEN);
        assert_eq!(open_column(&dek, b"ad", &sealed).unwrap().len(), n);
        // Unpadded content sealed under the right key and AD (a v1 column).
        let nonce: [u8; NONCE_LEN] = random().unwrap();
        let raw = aead_seal(&dek, &nonce, b"ad", &nonce, b"hello").unwrap();
        assert!(matches!(open_column(&dek, b"ad", &raw), Err(Error::Crypto)));
    }

    /// Closing a letter wipes it: `Plaintext` holds a buffer that zeroizes
    /// itself on drop (checked at compile time).
    #[test]
    fn plaintext_wipes_on_drop() {
        let p = Plaintext::new(Zeroizing::new(vec![1]));
        wiped_on_drop(&p.0);
    }
}
