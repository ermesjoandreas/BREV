//! Test-only: a P-256 signer standing in for the Secure Enclave, and good
//! facts.

use brev_proto::SIG_LEN;
use brev_vault::{EnvironmentClass, KeyOrigin};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};

use crate::facts::Env;
use crate::token::{assemble, content_hash, signed_bytes, Claims, MACOS};

/// A fixed `iat` for tests.
pub(crate) const IAT: u64 = 1_790_000_000;

/// A deterministic P-256 key (secret `[seed; 32]`) and its SEC1 public key.
pub(crate) struct TestKey {
    key: SigningKey,
    pub(crate) public: [u8; 65],
}

impl TestKey {
    pub(crate) fn new(seed: u8) -> TestKey {
        let key = SigningKey::from_slice(&[seed; 32]).unwrap();
        let public = key
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .try_into()
            .unwrap();
        TestKey { key, public }
    }

    /// Raw r ‖ s over `msg` (p256 hashes it with SHA-256).
    pub(crate) fn sign(&self, msg: &[u8]) -> [u8; SIG_LEN] {
        let sig: Signature = self.key.sign(msg);
        sig.to_bytes().into()
    }
}

/// Every fact good; admin, as on most Macs.
pub(crate) fn good_env() -> Env {
    Env {
        sip: Some(true),
        sudo: Some(0),
        admin: Some(true),
        agents: Some(0),
        pastes: 0,
        max_gap: 2,
        seconds: 60,
        windows: Some(0),
        ax_opaque: true,
        capture_off: Some(true),
        input_filter: true,
        secure_input: Some(true),
        blocked_input: 0,
        pasteboard_off: true,
    }
}

/// Class-A claims for `letter` at [`IAT`], with a fixed nonce.
pub(crate) fn claims(letter: &[u8]) -> Claims {
    Claims {
        iat: IAT,
        nonce: [7; 16],
        env: good_env(),
        key: KeyOrigin::SecureEnclave,
        class: EnvironmentClass::A,
        content: content_hash(letter),
        platform: MACOS,
        app_attest: None,
    }
}

/// `c` signed by `key` into a token.
pub(crate) fn signed(key: &TestKey, c: &Claims) -> Vec<u8> {
    let payload = c.encode();
    assemble(&payload, &key.sign(&signed_bytes(&payload)))
}
