//! Brev wire format.
//!
//! This crate will hold the `Envelope` type and its serialization, shared by
//! `brev-core` (client) and `brev-relay` (server). It is deliberately empty in
//! Phase 0; the envelope arrives in Phase 1 and the relay uses it in Phase 3.
//!
//! Nothing in this crate may ever hold plaintext message content: an envelope
//! carries sender id, recipient id, nonce, ciphertext and a signature, and
//! nothing else.

#![forbid(unsafe_code)]

/// Wire-format version. Bumped whenever the envelope layout changes.
pub const PROTOCOL_VERSION: u16 = 0;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_version_starts_at_zero() {
        assert_eq!(PROTOCOL_VERSION, 0);
    }
}
