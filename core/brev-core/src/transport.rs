//! Moving envelopes between identities (CLAUDE.md §3.1). Envelopes hold only
//! routing metadata and ciphertext, so no transport ever sees content.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::Envelope;

/// Carries envelopes for one identity.
pub trait Transport {
    /// Hands an envelope to the transport for delivery.
    fn send(&self, envelope: Envelope);
    /// Takes every envelope waiting for this identity.
    fn poll(&self) -> Vec<Envelope>;
}

/// In-process transport for two parties: what one end sends, the other end
/// polls. Used by tests now and by the Phase 2 app's hard-coded contacts.
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
    fn send(&self, envelope: Envelope) {
        guard(&self.peer_inbox).push(envelope);
    }

    fn poll(&self) -> Vec<Envelope> {
        std::mem::take(&mut *guard(&self.inbox))
    }
}

/// A poisoned queue still holds valid envelopes (ciphertext), so keep going.
fn guard(m: &Mutex<Vec<Envelope>>) -> MutexGuard<'_, Vec<Envelope>> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}
