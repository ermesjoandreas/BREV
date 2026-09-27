//! Brev wire format: the [`Envelope`] and the exact bytes it binds, and the
//! length-hiding padding ([`pad_into`], [`unpad`]).
//!
//! Nothing in this crate may ever hold plaintext message content: an envelope
//! carries sender id, recipient id, nonce, ciphertext and a signature, and
//! nothing else. The padding functions work on buffers the caller owns and
//! wipes; they keep no copy.
//!
//! The padding is used for every sealed store column from Phase 2 (schema
//! v2). TODO(Phase 3): pad the envelope payload before encryption with the
//! same functions, enforce [`MAX_PADDED`] in the app and the relay, and test
//! equal ciphertext length within a bucket (CLAUDE.md §5 Phase 3).

#![forbid(unsafe_code)]

/// Wire-format version. Bumped whenever the envelope layout changes.
pub const PROTOCOL_VERSION: u16 = 0;

/// Length of [`Envelope::header_bytes`]: magic, version, two ids, nonce.
pub const HEADER_LEN: usize = 4 + 2 + 32 + 32 + 24;

const MAGIC: &[u8; 4] = b"BREV";

/// One sealed message in transit. Every field is either routing metadata or
/// ciphertext; the relay may see all of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    /// Sender identity id (SHA-256 over the sender's public bundle: signing
    /// key and X25519 key).
    pub sender: [u8; 32],
    /// Recipient identity id.
    pub recipient: [u8; 32],
    /// XChaCha20-Poly1305 nonce, random per message; also the HKDF salt.
    pub nonce: [u8; 24],
    /// AEAD output: encrypted payload followed by the 16-byte tag.
    pub ciphertext: Vec<u8>,
    /// Signature over [`Envelope::signed_bytes`]. Opaque here: Ed25519 in
    /// Phase 1 tests, a Secure Enclave P-256 signature from Phase 3.
    pub signature: Vec<u8>,
}

impl Envelope {
    /// `"BREV" || version (u16 BE) || sender || recipient || nonce`.
    ///
    /// Used verbatim as the AEAD associated data, so every header field is
    /// authenticated by the ciphertext.
    pub fn header_bytes(
        sender: &[u8; 32],
        recipient: &[u8; 32],
        nonce: &[u8; 24],
    ) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[..4].copy_from_slice(MAGIC);
        out[4..6].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        out[6..38].copy_from_slice(sender);
        out[38..70].copy_from_slice(recipient);
        out[70..].copy_from_slice(nonce);
        out
    }

    /// The exact bytes the signature covers: header followed by ciphertext.
    ///
    /// Every field but the last has a fixed length, so this encoding is
    /// unambiguous without a length prefix.
    pub fn signed_bytes(&self) -> Vec<u8> {
        let header = Self::header_bytes(&self.sender, &self.recipient, &self.nonce);
        let mut out = Vec::with_capacity(HEADER_LEN + self.ciphertext.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&self.ciphertext);
        out
    }
}

/// Largest padded length: 1 MiB (CLAUDE.md §5 Phase 3).
pub const MAX_PADDED: usize = 1 << 20;
const LEN_PREFIX: usize = 4;
const BUCKETS: [usize; 4] = [256, 1024, 4096, 16 * 1024];
const STEP: usize = 16 * 1024;

/// Padding errors. Content-free.
#[derive(Debug, PartialEq, Eq)]
pub enum PadError {
    /// The content is above the maximum, or `out` has the wrong length.
    Size,
    /// Not a buffer that [`pad_into`] could have written.
    Malformed,
}

/// Padded length for `n` content bytes: `4 + n` rounded up to 256 B, 1 KiB,
/// 4 KiB or 16 KiB, and above that to a multiple of 16 KiB. `None` above
/// [`MAX_PADDED`].
pub fn padded_len(n: usize) -> Option<usize> {
    let need = n.checked_add(LEN_PREFIX)?;
    let len = match BUCKETS.iter().find(|&&b| need <= b) {
        Some(&b) => b,
        None => need.div_ceil(STEP).checked_mul(STEP)?,
    };
    (len <= MAX_PADDED).then_some(len)
}

/// Writes `length (u32 BE) || content || zeros` into `out`, which must be
/// exactly `padded_len(content.len())` bytes. The caller owns `out` and
/// wipes it.
pub fn pad_into(content: &[u8], out: &mut [u8]) -> Result<(), PadError> {
    if padded_len(content.len()) != Some(out.len()) {
        return Err(PadError::Size);
    }
    let n = u32::try_from(content.len()).map_err(|_| PadError::Size)?;
    out[..LEN_PREFIX].copy_from_slice(&n.to_be_bytes());
    out[LEN_PREFIX..LEN_PREFIX + content.len()].copy_from_slice(content);
    out[LEN_PREFIX + content.len()..].fill(0);
    Ok(())
}

/// The content inside a buffer written by [`pad_into`], borrowed from it.
/// Refuses anything `pad_into` could not have written: a length that does
/// not match the buffer's bucket, or a non-zero byte in the padding.
pub fn unpad(padded: &[u8]) -> Result<&[u8], PadError> {
    let (len, rest) = padded
        .split_at_checked(LEN_PREFIX)
        .ok_or(PadError::Malformed)?;
    let len: [u8; LEN_PREFIX] = len.try_into().map_err(|_| PadError::Malformed)?;
    let n = usize::try_from(u32::from_be_bytes(len)).map_err(|_| PadError::Malformed)?;
    if padded_len(n) != Some(padded.len()) {
        return Err(PadError::Malformed);
    }
    let (content, zeros) = rest.split_at_checked(n).ok_or(PadError::Malformed)?;
    if zeros.iter().any(|&b| b != 0) {
        return Err(PadError::Malformed);
    }
    Ok(content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_version_starts_at_zero() {
        assert_eq!(PROTOCOL_VERSION, 0);
    }

    #[test]
    fn signed_bytes_layout_is_fixed() {
        let env = Envelope {
            sender: [1; 32],
            recipient: [2; 32],
            nonce: [3; 24],
            ciphertext: vec![4, 5],
            signature: vec![9; 64],
        };
        let b = env.signed_bytes();
        assert_eq!(b.len(), HEADER_LEN + 2);
        assert_eq!(&b[..4], b"BREV");
        assert_eq!(&b[4..6], &[0, 0]);
        assert_eq!(&b[6..38], &[1; 32]);
        assert_eq!(&b[38..70], &[2; 32]);
        assert_eq!(&b[70..94], &[3; 24]);
        assert_eq!(&b[94..], &[4, 5]);
    }

    /// Exact bucket and bucket + 1 at every step, the maximum and
    /// maximum + 1; each size that fits round-trips.
    #[test]
    fn padding_boundaries() {
        let cases = [
            (0, Some(256)),
            (252, Some(256)),
            (253, Some(1024)),
            (1020, Some(1024)),
            (1021, Some(4096)),
            (4092, Some(4096)),
            (4093, Some(16384)),
            (16380, Some(16384)),
            (16381, Some(32768)),
            (65536, Some(81920)),
            (MAX_PADDED - 4, Some(MAX_PADDED)),
            (MAX_PADDED - 3, None),
            (usize::MAX, None),
        ];
        for (n, want) in cases {
            assert_eq!(padded_len(n), want, "{n}");
            let Some(len) = want else { continue };
            let content = vec![7u8; n];
            let mut out = vec![0xFFu8; len];
            pad_into(&content, &mut out).unwrap();
            assert_eq!(&out[..4], &u32::try_from(n).unwrap().to_be_bytes());
            assert!(out[4 + n..].iter().all(|&b| b == 0), "{n}");
            assert_eq!(unpad(&out).unwrap(), &content[..], "{n}");
        }
        let over = vec![0u8; MAX_PADDED - 3];
        assert_eq!(
            pad_into(&over, &mut vec![0u8; MAX_PADDED]),
            Err(PadError::Size)
        );
    }

    /// `unpad` accepts only what `pad_into` writes, and `pad_into` only an
    /// output of the exact padded length.
    #[test]
    fn padding_is_strict() {
        let mut out = [0u8; 256];
        pad_into(b"abc", &mut out).unwrap();
        assert_eq!(unpad(&out), Ok(&b"abc"[..]));
        let mut bad = out;
        bad[255] = 1; // a non-zero padding byte
        assert_eq!(unpad(&bad), Err(PadError::Malformed));
        let mut bad = out;
        bad[..4].copy_from_slice(&253u32.to_be_bytes()); // a length of another bucket
        assert_eq!(unpad(&bad), Err(PadError::Malformed));
        assert_eq!(unpad(&out[..255]), Err(PadError::Malformed));
        assert_eq!(unpad(&out[..3]), Err(PadError::Malformed));
        assert_eq!(unpad(&[0, 0, 1, 0]), Err(PadError::Malformed));
        assert_eq!(pad_into(b"x", &mut [0u8; 255]), Err(PadError::Size));
        assert_eq!(pad_into(b"x", &mut [0u8; 1024]), Err(PadError::Size));
    }
}
