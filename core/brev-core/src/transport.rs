//! Moving envelopes between identities (CLAUDE.md §3.1). Envelopes hold only
//! routing metadata and ciphertext, so no transport ever sees content.
//!
//! `poll` deletes nothing: the receiver acknowledges each envelope once it
//! is stored or permanently refused (docs/PHASE3_DESIGN.md §5.3), so a letter
//! that fails for a local reason is fetched again.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::Envelope;

/// Why a transport call failed. Content-free.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetError {
    /// The relay could not be reached, timed out, failed (5xx) or answered
    /// something that is not what the endpoint gives.
    Network,
    /// The relay refused the request with this 4xx status.
    Refused(u16),
}

impl From<NetError> for crate::Error {
    fn from(e: NetError) -> Self {
        match e {
            NetError::Network => crate::Error::Network,
            NetError::Refused(_) => crate::Error::Refused,
        }
    }
}

/// Carries envelopes for one identity.
pub trait Transport {
    /// Hands a signed envelope to the transport for delivery.
    fn send(&self, envelope: &Envelope) -> Result<(), NetError>;
    /// The envelopes waiting for this identity, oldest first. Deletes
    /// nothing.
    fn poll(&self) -> Result<Vec<Envelope>, NetError>;
    /// Deletes the waiting envelopes with these ids ([`Envelope::id`]).
    fn ack(&self, ids: &[[u8; 32]]) -> Result<(), NetError>;
}

/// In-process transport for two parties: what one end sends, the other end
/// polls and acknowledges. Used by the Phase 1 tests.
pub struct MockTransport {
    inbox: Arc<Mutex<Vec<Envelope>>>,
    peer_inbox: Arc<Mutex<Vec<Envelope>>>,
}

impl MockTransport {
    /// Two connected ends.
    pub fn pair() -> (MockTransport, MockTransport) {
        let a = Arc::new(Mutex::new(Vec::new()));
        let b = Arc::new(Mutex::new(Vec::new()));
        (
            MockTransport {
                inbox: Arc::clone(&a),
                peer_inbox: Arc::clone(&b),
            },
            MockTransport {
                inbox: b,
                peer_inbox: a,
            },
        )
    }
}

impl Transport for MockTransport {
    fn send(&self, envelope: &Envelope) -> Result<(), NetError> {
        guard(&self.peer_inbox).push(envelope.clone());
        Ok(())
    }

    fn poll(&self) -> Result<Vec<Envelope>, NetError> {
        Ok(guard(&self.inbox).clone())
    }

    fn ack(&self, ids: &[[u8; 32]]) -> Result<(), NetError> {
        guard(&self.inbox).retain(|e| !ids.contains(&e.id()));
        Ok(())
    }
}

/// A poisoned queue still holds valid envelopes (ciphertext), so keep going.
fn guard(m: &Mutex<Vec<Envelope>>) -> MutexGuard<'_, Vec<Envelope>> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}
