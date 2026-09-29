//! Moving envelopes between identities (CLAUDE.md §3.1). Envelopes hold only
//! routing metadata and ciphertext, so no transport ever sees content.
//!
//! `poll` deletes nothing: the receiver acknowledges each envelope once it
//! is stored or permanently refused (docs/PHASE3_DESIGN.md §5.3), so a letter
//! that fails for a local reason is fetched again. Each envelope comes with
//! the time the relay first stored it (`received_at`, docs/AUTHORSHIP.md
//! §2.5), which the authorship token's time check needs.

#[cfg(any(test, feature = "test-hooks"))]
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
#[cfg(any(test, feature = "test-hooks"))]
use std::time::{SystemTime, UNIX_EPOCH};

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
    /// The envelopes waiting for this identity, oldest first, each with its
    /// `received_at` (Unix seconds, the relay's clock). Deletes nothing.
    fn poll(&self) -> Result<Vec<(u64, Envelope)>, NetError>;
    /// Deletes the waiting envelopes with these ids ([`Envelope::id`]).
    fn ack(&self, ids: &[[u8; 32]]) -> Result<(), NetError>;
}

/// One end's queue: each envelope with the time it arrived.
#[cfg(any(test, feature = "test-hooks"))]
type Queue = Arc<Mutex<Vec<(u64, Envelope)>>>;

/// In-process transport for two parties: what one end sends, the other end
/// polls and acknowledges. Like the relay, it stamps each envelope with the
/// time it gets it: the system clock, or the time [`MockTransport::set_time`]
/// set. Used by the tests; test builds only (`cfg(test)` or the feature
/// `test-hooks`).
#[cfg(any(test, feature = "test-hooks"))]
pub struct MockTransport {
    inbox: Queue,
    peer_inbox: Queue,
    /// Shared by both ends.
    clock: Arc<Mutex<Option<u64>>>,
}

#[cfg(any(test, feature = "test-hooks"))]
impl MockTransport {
    /// Two connected ends.
    pub fn pair() -> (MockTransport, MockTransport) {
        let a = Queue::default();
        let b = Queue::default();
        let clock = Arc::new(Mutex::new(None));
        (
            MockTransport {
                inbox: Arc::clone(&a),
                peer_inbox: Arc::clone(&b),
                clock: Arc::clone(&clock),
            },
            MockTransport {
                inbox: b,
                peer_inbox: a,
                clock,
            },
        )
    }

    /// Stamps what both ends send from now on with `secs` (Unix seconds);
    /// `None` goes back to the system clock.
    pub fn set_time(&self, secs: Option<u64>) {
        *guard(&self.clock) = secs;
    }

    fn now(&self) -> u64 {
        guard(&self.clock).unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs())
        })
    }
}

#[cfg(any(test, feature = "test-hooks"))]
impl Transport for MockTransport {
    fn send(&self, envelope: &Envelope) -> Result<(), NetError> {
        let at = self.now();
        guard(&self.peer_inbox).push((at, envelope.clone()));
        Ok(())
    }

    fn poll(&self) -> Result<Vec<(u64, Envelope)>, NetError> {
        Ok(guard(&self.inbox).clone())
    }

    fn ack(&self, ids: &[[u8; 32]]) -> Result<(), NetError> {
        guard(&self.inbox).retain(|(_, e)| !ids.contains(&e.id()));
        Ok(())
    }
}

/// A poisoned queue still holds valid envelopes (ciphertext), and a
/// poisoned clock a valid time, so keep going.
#[cfg(any(test, feature = "test-hooks"))]
fn guard<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}
