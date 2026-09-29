//! Test-only signers for the identity key. With brev-proto's, the only file
//! under `src/` that may name `SigningKey` (docs/PHASE3_DESIGN.md §3.3);
//! `lib.rs` compiles it only for tests.

use brev_hand::{token, Claims, Env, KeyOrigin};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{DerSignature, Signature, SigningKey};

use crate::crypto;

/// Every fact of a class-A letter (docs/AUTHORSHIP.md §4.1).
pub(crate) fn clean_env() -> Env {
    Env {
        sip: Some(true),
        sudo: Some(0),
        admin: Some(true),
        agents: Some(0),
        pastes: 0,
        max_gap: 2,
        seconds: 30,
        windows: Some(1),
        ax_opaque: true,
        capture_off: Some(true),
        input_filter: true,
        secure_input: Some(true),
        blocked_input: 0,
        pasteboard_off: true,
    }
}

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

    /// A class-A authorship token for `letter` at `iat`, signed by this
    /// key, as the Secure Enclave signs the digest `sign_request` returns.
    pub(crate) fn token(&self, letter: &[u8], iat: u64) -> Vec<u8> {
        let claims = Claims::new(letter, iat, KeyOrigin::SecureEnclave, clean_env()).unwrap();
        let payload = claims.encode();
        token::assemble(&payload, &self.sign_raw(&token::signed_bytes(&payload)))
    }
}
