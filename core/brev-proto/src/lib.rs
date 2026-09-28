//! Brev wire format, protocol version 1 (docs/PHASE3_DESIGN.md §2): the
//! [`Envelope`] with its signed bytes and wire bytes, the length-hiding
//! padding ([`pad_into`], [`unpad`]), identity ids and codes, the other relay
//! bodies ([`body`]) and the P-256 signature checks ([`sig`]). brev-core and
//! brev-relay both use this crate, so each rule has one implementation.
//!
//! Nothing in this crate may ever hold plaintext message content: an envelope
//! carries sender id, recipient id, nonce, ciphertext and a signature, and
//! nothing else. The padding functions work on buffers the caller owns and
//! wipes; they keep no copy.
//!
//! The padding is used for every sealed store column from Phase 2 (schema
//! v2). TODO(Phase 3, WP3): brev-core pads the envelope payload with the same
//! functions before encryption (docs/PHASE3_DESIGN.md §2.2).

#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};

pub mod body;
pub mod sig;
#[cfg(test)]
mod test_keys;

/// Wire-format version. Bumped whenever the envelope layout or the payload
/// inside the AEAD changes: 1 since the payload is padded (Phase 3).
pub const PROTOCOL_VERSION: u16 = 1;

/// Length of [`Envelope::header_bytes`]: magic, version, two ids, nonce.
pub const HEADER_LEN: usize = 4 + 2 + 32 + 32 + 24;

/// Length of an envelope signature on the wire: raw r ‖ s ([`sig`]).
pub const SIG_LEN: usize = 64;

/// Largest ciphertext: the largest padded payload and the AEAD tag.
pub const MAX_CIPHERTEXT: usize = MAX_PADDED + TAG_LEN;

/// Largest wire envelope (1 048 750 bytes). The relay refuses larger bodies.
pub const MAX_WIRE: usize = HEADER_LEN + MAX_CIPHERTEXT + SIG_LEN;

const MAGIC: &[u8; 4] = b"BREV";
const TAG_LEN: usize = 16;
/// Smallest wire envelope (430 bytes): the smallest bucket, tag, signature.
const MIN_WIRE: usize = HEADER_LEN + BUCKETS[0] + TAG_LEN + SIG_LEN;

/// One sealed message in transit. Every field is either routing metadata or
/// ciphertext; the relay may see all of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    /// Sender identity id ([`identity_id`] of the sender's public bundle:
    /// signing key and X25519 key).
    pub sender: [u8; 32],
    /// Recipient identity id.
    pub recipient: [u8; 32],
    /// XChaCha20-Poly1305 nonce, random per message; also the HKDF salt.
    pub nonce: [u8; 24],
    /// AEAD output: encrypted payload followed by the 16-byte tag.
    pub ciphertext: Vec<u8>,
    /// Signature over [`Envelope::signed_bytes`] by the sender's identity key:
    /// raw r ‖ s of ECDSA P-256 ([`sig::verify`]). [`Envelope::to_wire`]
    /// refuses any length but [`SIG_LEN`].
    pub signature: Vec<u8>,
}

/// Why [`Envelope::from_wire`] or [`Envelope::to_wire`] refused. Content-free.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError {
    /// Shorter than the smallest envelope (430 bytes) or longer than
    /// [`MAX_WIRE`].
    Length,
    /// The first four bytes are not `"BREV"`.
    Magic,
    /// A version other than [`PROTOCOL_VERSION`].
    Version,
    /// The ciphertext minus the tag is not a padded length
    /// ([`is_padded_len`]).
    Padding,
    /// A signature that is not [`SIG_LEN`] bytes (`to_wire`).
    Signature,
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

    /// The envelope id: SHA-256 of [`Envelope::signed_bytes`]. The relay
    /// dedupes and acknowledges by it. It does not cover the signature, so
    /// another valid signature over the same bytes changes no id. It is also
    /// the digest the Secure Enclave signs (docs/PHASE3_DESIGN.md §3.1).
    pub fn id(&self) -> [u8; 32] {
        Sha256::digest(self.signed_bytes()).into()
    }

    /// The wire bytes: [`Envelope::signed_bytes`] followed by the signature
    /// (docs/PHASE3_DESIGN.md §2.1). Refuses a signature that is not
    /// [`SIG_LEN`] bytes.
    pub fn to_wire(&self) -> Result<Vec<u8>, WireError> {
        if self.signature.len() != SIG_LEN {
            return Err(WireError::Signature);
        }
        let mut out = self.signed_bytes();
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    /// Parses wire bytes. Refuses a length below 430 or above [`MAX_WIRE`],
    /// a wrong magic, a version other than [`PROTOCOL_VERSION`], and a
    /// ciphertext whose length minus the tag is not a padded length. The
    /// header and the signature have fixed lengths, so the ciphertext is
    /// what lies between them. The signature is not checked here
    /// ([`sig::verify`]).
    pub fn from_wire(wire: &[u8]) -> Result<Envelope, WireError> {
        if !(MIN_WIRE..=MAX_WIRE).contains(&wire.len()) {
            return Err(WireError::Length);
        }
        let (signed, signature) = wire.split_at(wire.len() - SIG_LEN);
        let (header, ciphertext) = signed.split_at(HEADER_LEN);
        if header[..4] != MAGIC[..] {
            return Err(WireError::Magic);
        }
        if header[4..6] != PROTOCOL_VERSION.to_be_bytes() {
            return Err(WireError::Version);
        }
        if !ciphertext
            .len()
            .checked_sub(TAG_LEN)
            .is_some_and(is_padded_len)
        {
            return Err(WireError::Padding);
        }
        // `header` is exactly HEADER_LEN bytes, so these cannot fail.
        Ok(Envelope {
            sender: header[6..38].try_into().map_err(|_| WireError::Length)?,
            recipient: header[38..70].try_into().map_err(|_| WireError::Length)?,
            nonce: header[70..94].try_into().map_err(|_| WireError::Length)?,
            ciphertext: ciphertext.to_vec(),
            signature: signature.to_vec(),
        })
    }
}

const IDENTITY_LABEL: &[u8] = b"brev/v0/identity";

/// Identity id (docs/DECISIONS.md D-0016, unchanged): SHA-256(`"brev/v0/identity"`
/// ‖ 65 ‖ signing key ‖ X25519 key). The signing key is an uncompressed
/// P-256 point, which the caller checks with [`sig::check_key`]. brev-core
/// and brev-relay both compute ids here, so they agree.
pub fn identity_id(signing_key: &[u8; sig::KEY_LEN], x25519: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(IDENTITY_LABEL);
    h.update([sig::KEY_LEN as u8]); // 65
    h.update(signing_key);
    h.update(x25519);
    h.finalize().into()
}

/// Length of an [`identity_code`]: 30 characters and 5 spaces.
pub const IDENTITY_CODE_LEN: usize = 35;
const CODE_CHARS: usize = 30;
const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Identity code (docs/PHASE3_DESIGN.md §3.4): RFC 4648 base32 (A–Z, 2–7)
/// of the first 150 bits of an identity id, 30 characters in 6 groups of 5
/// separated by one space, as ASCII, for example
/// `ILXVI CAOQX JQVH5 NDNTQ 6N5SJ KKA2B`. 150 bits is more than the 128 that
/// D-0016 asks for. A table lookup, not cryptography.
pub fn identity_code(id: &[u8; 32]) -> [u8; IDENTITY_CODE_LEN] {
    let mut out = [b' '; IDENTITY_CODE_LEN];
    for i in 0..CODE_CHARS {
        // Character i is bits 5i .. 5i + 4 (big-endian), which lie in the
        // two bytes from 5i / 8 on; the last character reads bytes 18 and 19.
        let bit = 5 * i;
        let pair = u16::from_be_bytes([id[bit / 8], id[bit / 8 + 1]]);
        let value = (pair >> (11 - bit % 8)) & 0x1F;
        out[i + i / 5] = BASE32[usize::from(value)];
    }
    out
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

/// True exactly for the lengths [`pad_into`] writes: 256, 1024, 4096, and
/// every multiple of 16 384 up to [`MAX_PADDED`]. The relay's check on an
/// envelope's ciphertext.
pub fn is_padded_len(n: usize) -> bool {
    n >= LEN_PREFIX && padded_len(n - LEN_PREFIX) == Some(n)
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
    use crate::test_keys::{unhex, TestKey};

    /// An envelope with a ciphertext of `padded` + 16 bytes, signed by `key`.
    fn envelope(padded: usize, key: &TestKey) -> Envelope {
        let mut env = Envelope {
            sender: [1; 32],
            recipient: [2; 32],
            nonce: [3; 24],
            ciphertext: (0..padded + TAG_LEN).map(|i| (i % 251) as u8).collect(),
            signature: Vec::new(),
        };
        env.signature = key.sign(&env.signed_bytes()).to_vec();
        env
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
        assert_eq!(&b[4..6], &[0, 1]);
        assert_eq!(&b[6..38], &[1; 32]);
        assert_eq!(&b[38..70], &[2; 32]);
        assert_eq!(&b[70..94], &[3; 24]);
        assert_eq!(&b[94..], &[4, 5]);
    }

    /// The offsets of design §2.1, the sizes 430 and `MAX_WIRE`, the round
    /// trip, and the id as SHA-256 of the signed bytes only.
    #[test]
    fn wire_round_trip_and_layout() {
        assert_eq!(PROTOCOL_VERSION, 1);
        assert_eq!(
            (MIN_WIRE, MAX_CIPHERTEXT, MAX_WIRE),
            (430, 1_048_592, 1_048_750)
        );
        let key = TestKey::new(1);
        let env = envelope(256, &key);
        let wire = env.to_wire().unwrap();
        assert_eq!(wire.len(), 430);
        assert_eq!(&wire[..4], &[0x42, 0x52, 0x45, 0x56]);
        assert_eq!(&wire[4..6], &[0x00, 0x01]);
        assert_eq!(&wire[6..38], &env.sender);
        assert_eq!(&wire[38..70], &env.recipient);
        assert_eq!(&wire[70..94], &env.nonce);
        assert_eq!(&wire[94..94 + 272], &env.ciphertext[..]);
        assert_eq!(&wire[94 + 272..], &env.signature[..]);
        assert_eq!(&wire[..94 + 272], &env.signed_bytes()[..]);
        assert_eq!(Envelope::from_wire(&wire), Ok(env.clone()));
        sig::verify(
            &key.public,
            &env.signed_bytes(),
            wire[366..].try_into().unwrap(),
        )
        .unwrap();

        let id: [u8; 32] = Sha256::digest(&wire[..366]).into();
        assert_eq!(env.id(), id);
        let mut resigned = env.clone();
        resigned.signature = TestKey::new(2).sign(&env.signed_bytes()).to_vec();
        assert_ne!(resigned.signature, env.signature);
        assert_eq!(resigned.id(), id, "the id does not cover the signature");
        let mut other = env.clone();
        other.ciphertext[0] ^= 1;
        assert_ne!(other.id(), id);

        let big = envelope(MAX_PADDED, &key);
        let wire = big.to_wire().unwrap();
        assert_eq!(wire.len(), MAX_WIRE);
        assert_eq!(Envelope::from_wire(&wire), Ok(big));
    }

    /// Each rule of design §2.1 on its own, on an otherwise valid envelope.
    #[test]
    fn from_wire_refuses() {
        let key = TestKey::new(1);
        let good = envelope(1024, &key).to_wire().unwrap();
        assert!(Envelope::from_wire(&good).is_ok());

        // Length: below 430 and above MAX_WIRE, and the empty input.
        let small = envelope(256, &key).to_wire().unwrap();
        assert_eq!(Envelope::from_wire(&small[..429]), Err(WireError::Length));
        assert_eq!(Envelope::from_wire(&[]), Err(WireError::Length));
        let mut over = envelope(MAX_PADDED, &key).to_wire().unwrap();
        over.push(0);
        assert_eq!(over.len(), MAX_WIRE + 1);
        assert_eq!(Envelope::from_wire(&over), Err(WireError::Length));

        let mut bad = good.clone();
        bad[0] = b'b';
        assert_eq!(Envelope::from_wire(&bad), Err(WireError::Magic));

        for version in [0u16, 2, 0x0100, u16::MAX] {
            let mut bad = good.clone();
            bad[4..6].copy_from_slice(&version.to_be_bytes());
            assert_eq!(
                Envelope::from_wire(&bad),
                Err(WireError::Version),
                "{version}"
            );
        }

        // A ciphertext of 1024 + 16 + k bytes for k != 0, and a bucket with
        // no tag room: every length that is not bucket + 16.
        for delta in [1isize, -1, 16, -16, 64, 511] {
            let mut bad = good.clone();
            let len = usize::try_from(isize::try_from(good.len()).unwrap() + delta).unwrap();
            bad.resize(len, 0);
            assert_eq!(
                Envelope::from_wire(&bad),
                Err(WireError::Padding),
                "{delta}"
            );
        }
        let mut two_buckets = envelope(16384, &key).to_wire().unwrap();
        two_buckets.truncate(two_buckets.len() - 16384 / 2);
        assert_eq!(Envelope::from_wire(&two_buckets), Err(WireError::Padding));

        // to_wire: a signature that is not 64 bytes.
        let mut env = envelope(256, &key);
        for len in [0, 63, 65, 72] {
            env.signature = vec![1; len];
            assert_eq!(env.to_wire(), Err(WireError::Signature), "{len}");
        }
    }

    /// `is_padded_len` is true exactly on 256, 1 KiB, 4 KiB and the
    /// multiples of 16 KiB up to 1 MiB, checked for every length up to
    /// 1 MiB + 32 KiB.
    #[test]
    fn padded_lengths_only() {
        let mut expected: Vec<usize> = vec![256, 1024, 4096];
        expected.extend((1..=64).map(|k| k * 16384));
        assert_eq!(expected.last(), Some(&MAX_PADDED));
        let found: Vec<usize> = (0..=MAX_PADDED + 2 * STEP)
            .filter(|&n| is_padded_len(n))
            .collect();
        assert_eq!(found, expected);
        assert!(!is_padded_len(usize::MAX));
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

    /// All-zero, all-0xFF, the 150-bit cut, and one real id, against
    /// Python's `base64.b32encode` of the id's first 19 bytes, cut to 30
    /// characters.
    #[test]
    fn identity_code_known_answers() {
        assert_eq!(
            &identity_code(&[0; 32]),
            b"AAAAA AAAAA AAAAA AAAAA AAAAA AAAAA"
        );
        assert_eq!(
            &identity_code(&[0xFF; 32]),
            b"77777 77777 77777 77777 77777 77777"
        );
        // Bit 149 (the last one in the code) and bit 150 (the first one out).
        let mut id = [0u8; 32];
        id[18] = 0b0000_0100;
        assert_eq!(&identity_code(&id), b"AAAAA AAAAA AAAAA AAAAA AAAAA AAAAB");
        id[18] = 0b0000_0010;
        assert_eq!(&identity_code(&[0; 32]), &identity_code(&id));
        let mut id = [0u8; 32];
        id[19..].fill(0xFF);
        assert_eq!(&identity_code(&[0; 32]), &identity_code(&id));
        let real = unhex("42ef54080e85d30a9fad1b670f37b24a940d0555a6431a732878664527ef6b0a");
        assert_eq!(
            &identity_code(&real.try_into().unwrap()),
            b"ILXVI CAOQX JQVH5 NDNTQ 6N5SJ KKA2B"
        );
    }

    /// The D-0016 formula with a length byte of 65, computed here by hand,
    /// and one known answer from Python's hashlib: the Enclave key of the
    /// committed vectors with the X25519 key 00 01 … 1f.
    #[test]
    fn identity_id_matches_d0016() {
        let key: [u8; 65] = crate::test_keys::VECTORS[2].key().try_into().unwrap();
        let x25519: [u8; 32] = std::array::from_fn(|i| i as u8);
        let mut preimage = b"brev/v0/identity".to_vec();
        preimage.push(65);
        preimage.extend_from_slice(&key);
        preimage.extend_from_slice(&x25519);
        let by_hand: [u8; 32] = Sha256::digest(&preimage).into();
        let id = identity_id(&key, &x25519);
        assert_eq!(id, by_hand);
        assert_eq!(
            id.to_vec(),
            unhex("42ef54080e85d30a9fad1b670f37b24a940d0555a6431a732878664527ef6b0a")
        );
        // Either key changes the id.
        let mut other = x25519;
        other[0] ^= 1;
        assert_ne!(identity_id(&key, &other), id);
        assert_ne!(identity_id(&TestKey::new(1).public, &x25519), id);
    }
}
