//! ECDSA P-256 / SHA-256 signatures by an identity key
//! (docs/PHASE3_DESIGN.md §3.3). One implementation for brev-core (receive,
//! `attach_signature`, `register`) and brev-relay (registration, submit).
//!
//! Verification only: the Secure Enclave signs, in Swift, and production
//! code never builds a signing key (test signers live in `test_keys.rs`).
//! p256 is not independently audited; here it only handles public inputs.
//!
//! On the wire a signature is raw r ‖ s, 32 bytes each, big-endian, as the
//! signer produced it. Either S is accepted: Security.framework does not
//! normalise S (about half of its signatures are high-S), p256 verifies them
//! unchanged, and a low-S rule would protect nothing because the envelope id
//! does not cover the signature.

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};

use crate::SIG_LEN;

/// Length of a signing key: SEC1 uncompressed `04 ‖ X ‖ Y`.
pub const KEY_LEN: usize = 65;

/// Why a key or a signature was refused. Content-free.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigError {
    /// Not an uncompressed P-256 point on the curve: not 65 bytes, not
    /// starting with 04, or off the curve.
    BadKey,
    /// Not a signature by this key over this message: r or s is 0 or not
    /// below the group order, the DER is not strict DER, or the check fails.
    BadSignature,
}

/// The key as p256's type. [`VerifyingKey::from_sec1_bytes`] alone would
/// also take a compressed key, so length and prefix are checked first.
fn verifying_key(key: &[u8]) -> Result<VerifyingKey, SigError> {
    if key.len() != KEY_LEN || key[0] != 0x04 {
        return Err(SigError::BadKey);
    }
    VerifyingKey::from_sec1_bytes(key).map_err(|_| SigError::BadKey)
}

/// Checks that `key` is a valid signing key (65 bytes, 04, on the curve):
/// the rule for `Core::create`, a lookup answer and a registration.
pub fn check_key(key: &[u8]) -> Result<&[u8; KEY_LEN], SigError> {
    verifying_key(key)?;
    key.try_into().map_err(|_| SigError::BadKey)
}

/// Checks `sig` (raw r ‖ s) over `msg` with `key`. `msg` is the signed
/// preimage, not its digest: p256 hashes it with SHA-256, which gives the
/// digest the Enclave signed.
pub fn verify(key: &[u8], msg: &[u8], sig: &[u8; SIG_LEN]) -> Result<(), SigError> {
    let key = verifying_key(key)?;
    let sig = Signature::from_slice(sig).map_err(|_| SigError::BadSignature)?;
    key.verify(msg, &sig).map_err(|_| SigError::BadSignature)
}

/// The DER signature Security.framework returns (X9.62 ECDSA-Sig-Value), as
/// raw r ‖ s, S unchanged. Strict DER only; r and s must be in 1 ..= n − 1.
pub fn der_to_raw(der: &[u8]) -> Result<[u8; SIG_LEN], SigError> {
    let sig = Signature::from_der(der).map_err(|_| SigError::BadSignature)?;
    Ok(sig.to_bytes().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_keys::{TestKey, VECTORS};

    /// Group order n of P-256, big-endian.
    const N: [u8; 32] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63,
        0x25, 0x51,
    ];

    fn is_high_s(raw: &[u8; SIG_LEN]) -> bool {
        let sig = Signature::from_slice(raw).unwrap();
        sig.normalize_s() != sig
    }

    #[test]
    fn verify_rules() {
        let key = TestKey::new(1);
        let msg = b"BREV\x00\x01 a signed preimage".to_vec();
        let good = key.sign(&msg);
        assert_eq!(verify(&key.public, &msg, &good), Ok(()));

        let mut flipped = msg.clone();
        flipped[7] ^= 1;
        assert_eq!(
            verify(&key.public, &flipped, &good),
            Err(SigError::BadSignature)
        );
        for byte in [0, 31, 32, 63] {
            let mut bad = good;
            bad[byte] ^= 0x10;
            assert_eq!(
                verify(&key.public, &msg, &bad),
                Err(SigError::BadSignature),
                "{byte}"
            );
        }
        assert_eq!(
            verify(&TestKey::new(2).public, &msg, &good),
            Err(SigError::BadSignature)
        );

        // High-S as the signer produced it: the Security.framework vectors,
        // and the test signature with s replaced by n − s.
        for v in VECTORS.iter().filter(|v| v.high_s) {
            let raw = super::der_to_raw(&v.der()).unwrap();
            assert!(is_high_s(&raw), "{}", v.name);
            assert_eq!(verify(&v.key(), &v.msg(), &raw), Ok(()), "{}", v.name);
        }
        let other_s = negate_s(&good);
        assert_ne!(is_high_s(&other_s), is_high_s(&good));
        assert_eq!(verify(&key.public, &msg, &other_s), Ok(()));

        // r = 0, s = 0, s = n, s = 2^256 − 1, r = n.
        let mut bad = good;
        bad[..32].fill(0);
        assert_eq!(verify(&key.public, &msg, &bad), Err(SigError::BadSignature));
        let mut bad = good;
        bad[32..].fill(0);
        assert_eq!(verify(&key.public, &msg, &bad), Err(SigError::BadSignature));
        let mut bad = good;
        bad[32..].copy_from_slice(&N);
        assert_eq!(verify(&key.public, &msg, &bad), Err(SigError::BadSignature));
        let mut bad = good;
        bad[32..].fill(0xFF);
        assert_eq!(verify(&key.public, &msg, &bad), Err(SigError::BadSignature));
        let mut bad = good;
        bad[..32].copy_from_slice(&N);
        assert_eq!(verify(&key.public, &msg, &bad), Err(SigError::BadSignature));

        // Keys: only 65 bytes, 04, on the curve.
        assert_eq!(check_key(&key.public), Ok(&key.public));
        let bare = &key.public[1..]; // X ‖ Y without the prefix
        assert_eq!(check_key(bare), Err(SigError::BadKey));
        assert_eq!(verify(bare, &msg, &good), Err(SigError::BadKey));
        let compressed = key.compressed();
        assert_eq!(compressed.len(), 33);
        assert!(
            VerifyingKey::from_sec1_bytes(&compressed).is_ok(),
            "control: p256 alone takes it"
        );
        assert_eq!(check_key(&compressed), Err(SigError::BadKey));
        assert_eq!(verify(&compressed, &msg, &good), Err(SigError::BadKey));
        let mut off_curve = key.public;
        off_curve[64] ^= 1;
        assert_eq!(check_key(&off_curve), Err(SigError::BadKey));
        assert_eq!(verify(&off_curve, &msg, &good), Err(SigError::BadKey));
        let mut hybrid = key.public;
        hybrid[0] = 0x06 | (key.public[64] & 1);
        assert_eq!(check_key(&hybrid), Err(SigError::BadKey));
        let mut long = key.public.to_vec();
        long.push(0);
        assert_eq!(check_key(&long), Err(SigError::BadKey));
        assert_eq!(check_key(&[]), Err(SigError::BadKey));
        assert_eq!(
            check_key(&[0]),
            Err(SigError::BadKey),
            "the point at infinity"
        );
    }

    /// n − s for the s half of `raw`.
    fn negate_s(raw: &[u8; SIG_LEN]) -> [u8; SIG_LEN] {
        let mut out = *raw;
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let d = i16::from(N[i]) - i16::from(raw[32 + i]) - borrow;
            borrow = i16::from(d < 0);
            out[32 + i] = (d + 256 * borrow) as u8;
        }
        out
    }

    /// The four Security.framework vectors (tools/verify/spikes/p3): each
    /// converts, verifies against its key and message, and is exactly the
    /// DER's r and s; then the six malformed inputs of design §0.
    #[test]
    fn der_to_raw() {
        let mut lengths = Vec::new();
        for v in &VECTORS {
            let der = v.der();
            let raw = super::der_to_raw(&der).unwrap();
            assert_eq!(verify(&v.key(), &v.msg(), &raw), Ok(()), "{}", v.name);
            assert_eq!(is_high_s(&raw), v.high_s, "{}", v.name);
            let back = Signature::from_slice(&raw).unwrap().to_der();
            assert_eq!(
                back.as_bytes(),
                &der[..],
                "{}: re-encodes byte for byte",
                v.name
            );
            let mut msg = v.msg();
            msg[0] ^= 1;
            assert_eq!(
                verify(&v.key(), &msg, &raw),
                Err(SigError::BadSignature),
                "{}",
                v.name
            );
            lengths.push(der.len());
        }
        assert_eq!(lengths, [70, 72, 72, 69]);
        // The 69-byte DER has a 31-byte s: its raw form starts s with 00.
        let short = super::der_to_raw(&VECTORS[3].der()).unwrap();
        assert_eq!(short[32], 0);

        let malformed: [&[u8]; 6] = [
            &[],
            &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00], // trailing byte
            &[0x30, 0x06, 0x02, 0x01, 0x81, 0x02, 0x01, 0x01],       // negative r
            &[0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01], // non-minimal r
            &[0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01], // long-form length
            &[0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01],       // r = 0
        ];
        for (i, der) in malformed.iter().enumerate() {
            assert_eq!(super::der_to_raw(der), Err(SigError::BadSignature), "{i}");
        }
        // Control: the same shape with r = s = 1 parses.
        let mut one = [0u8; SIG_LEN];
        one[31] = 1;
        one[63] = 1;
        assert_eq!(
            super::der_to_raw(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]),
            Ok(one)
        );
    }
}
