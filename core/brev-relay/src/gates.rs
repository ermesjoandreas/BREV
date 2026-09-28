//! The registration gates (docs/PHASE4_DESIGN.md §7): App Attest (feature
//! `app-attest`, off by default) and identity verification (BankID /
//! ID-porten later). Both are stubs in Phase 4: [`DevAttest`] accepts one
//! fixed marker and [`DevVerifier`] accepts everyone.
//!
//! Future task (design §7.1, §7.3), not built: an `AppleAttestVerifier`
//! that parses the CBOR attestation and checks its X.509 chain to Apple's App
//! Attest root for both App IDs (`AV26DNQ5SC.no.brev.app` and `.b`); those
//! crates are not in CLAUDE.md §4. And an ID-porten/BankID verifier: the
//! operator runs a web login outside Brev that hands out a one-time text
//! code, the app pastes it like an invite, a registration v3 carries it, and
//! the relay keeps only SHA-256(pairwise `sub` ‖ relay salt), so one person
//! holds one identity; the relay would then link each identity to a person.

/// Decides whether an identity may register, given its evidence of being
/// one real person (design §7.3). Asked at registration after the conflict
/// check; `false` answers 428 and nothing is written.
pub trait IdentityVerifier: Send + Sync {
    /// Whether `identity` may register. `evidence` is empty in Phase 4.
    fn verify(&self, identity: &[u8; 32], evidence: &[u8]) -> bool;
}

/// Phase 4's identity verifier: accepts everyone.
pub struct DevVerifier;

impl IdentityVerifier for DevVerifier {
    fn verify(&self, _: &[u8; 32], _: &[u8]) -> bool {
        true
    }
}

/// Decides whether a registration comes from a genuine app build (design
/// §7.1). `client_data_hash` is the registration's signed digest, so an
/// attestation binds to its key, address, token and invite. Asked after
/// the signature check; `false` answers 428 before anything is read or
/// written.
#[cfg(feature = "app-attest")]
pub trait AttestVerifier: Send + Sync {
    /// Whether `attestation` vouches for `client_data_hash`.
    fn verify(&self, attestation: &[u8], client_data_hash: &[u8; 32]) -> bool;
}

/// The only attestation [`DevAttest`] accepts.
#[cfg(feature = "app-attest")]
pub const DEV_ATTESTATION: &[u8; 16] = b"BREV-DEV-ATTEST1";

/// Phase 4's attestation verifier: accepts exactly [`DEV_ATTESTATION`].
#[cfg(feature = "app-attest")]
pub struct DevAttest;

#[cfg(feature = "app-attest")]
impl AttestVerifier for DevAttest {
    fn verify(&self, attestation: &[u8], _: &[u8; 32]) -> bool {
        attestation == DEV_ATTESTATION
    }
}

/// The gates a relay asks at registration. Without the feature `app-attest`
/// the attestation is parsed (at most 8 192 bytes) and ignored.
pub struct Gates {
    /// Asked after the conflict check.
    pub identity: Box<dyn IdentityVerifier>,
    /// Asked right after the signature check.
    #[cfg(feature = "app-attest")]
    pub attest: Box<dyn AttestVerifier>,
}

impl Default for Gates {
    /// The Phase 4 stubs: [`DevVerifier`] and, with the feature,
    /// [`DevAttest`].
    fn default() -> Gates {
        Gates {
            identity: Box::new(DevVerifier),
            #[cfg(feature = "app-attest")]
            attest: Box::new(DevAttest),
        }
    }
}
