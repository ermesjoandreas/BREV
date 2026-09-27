//! Brev wire format: the [`Envelope`] and the exact bytes it binds.
//!
//! Nothing in this crate may ever hold plaintext message content: an envelope
//! carries sender id, recipient id, nonce, ciphertext and a signature, and
//! nothing else.
//!
//! TODO(Phase 3): pad the plaintext payload to fixed buckets (256 B / 1 KiB /
//! 4 KiB / 16 KiB) before encryption, here as part of the envelope format,
//! with a test that payloads of different lengths within one bucket give
//! ciphertexts of equal length (CLAUDE.md §5 Phase 3).

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
}
