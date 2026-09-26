//! Brev relay server.
//!
//! Phase 3 turns this into a minimal axum server that registers public
//! identities, accepts envelopes and lets recipients poll for them. It stores
//! ciphertext and routing metadata only and deletes envelopes after delivery.
//!
//! In Phase 0 it is a placeholder so the workspace layout in CLAUDE.md §3
//! exists from the first commit. It takes no dependencies beyond `brev-proto`
//! until the relay is actually implemented.

#![forbid(unsafe_code)]

fn main() {
    println!(
        "brev-relay: not implemented until Phase 3 (protocol v{})",
        brev_proto::PROTOCOL_VERSION
    );
}
