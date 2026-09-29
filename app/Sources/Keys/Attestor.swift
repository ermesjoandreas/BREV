// Attestor.swift — the app's attestation of a registration (App Attest
// stub).
//
// docs/PHASE4_DESIGN.md §7.1: a registration carries an attestation made
// over the digest the identity key signs, so it binds to this key, address,
// token and invite. Phase 4 has only NoAttestor, whose attestation is empty:
// no DCAppAttestService call and no entitlement (it contacts Apple). The
// relay ignores the field unless it is built with its `app-attest` feature.
// A real AppAttestor is a future task. Neither the digest nor an attestation
// is secret. No AppKit: Session (Shared/) uses it, and the CLI harness and
// the view host compile this file with Shared/.

/// Makes the attestation of a registration digest (32 bytes).
protocol Attestor {
    /// The attestation over `digest`; at most 8 192 bytes (Rust refuses
    /// more as `Malformed`).
    func attestation(for digest: [UInt8]) -> [UInt8]
}

/// No attestation: the stub until App Attest (docs/PHASE4_DESIGN.md §7.1).
struct NoAttestor: Attestor {
    func attestation(for digest: [UInt8]) -> [UInt8] {
        []
    }
}
