//! Test-only signers for the identity key. With brev-proto's, the only file
//! under `src/` that may name `SigningKey` (docs/PHASE3_DESIGN.md §3.3);
//! `lib.rs` compiles it only for tests.

use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{DerSignature, Signature, SigningKey};

use crate::crypto;

/// A random P-256 test identity key and its SEC1 uncompressed public key.
pub(crate) struct TestKey {
    key: SigningKey,
    pub(crate) public: [u8; 65],
}

impl TestKey {
    pub(crate) fn new() -> TestKey {
        loop {
            // A random scalar is valid unless it is 0 or at least n.
            if let Ok(key) = SigningKey::from_slice(&crypto::random::<32>().unwrap()) {
                let public = key
                    .verifying_key()
                    .to_sec1_point(false)
                    .as_bytes()
                    .try_into()
                    .unwrap();
                return TestKey { key, public };
            }
        }
    }

    /// DER over a 32-byte digest, as the Secure Enclave signs with
    /// `.ecdsaSignatureDigestX962SHA256`.
    pub(crate) fn sign_digest(&self, digest: &[u8]) -> Vec<u8> {
        let sig: DerSignature = self.key.sign_prehash(digest).unwrap();
        sig.as_bytes().to_vec()
    }

    /// DER over `msg` with a high S (s > n / 2), as about half of the
    /// Secure Enclave's signatures are.
    pub(crate) fn sign_der_high_s(&self, msg: &[u8]) -> Vec<u8> {
        let sig: Signature = self.key.sign(msg);
        let low = sig.normalize_s();
        let (r, s) = low.split_scalars();
        let high = Signature::from_scalars(r, -s).unwrap();
        assert_ne!(high.normalize_s(), high, "high S");
        high.to_der().as_bytes().to_vec()
    }

    /// Raw r ‖ s over `msg`, as it goes on the wire.
    pub(crate) fn sign_raw(&self, msg: &[u8]) -> [u8; 64] {
        let sig: Signature = self.key.sign(msg);
        sig.to_bytes().into()
    }
}
