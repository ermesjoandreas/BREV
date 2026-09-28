//! Brev relay (docs/PHASE3_DESIGN.md §4, docs/PHASE4_DESIGN.md §4): a
//! minimal axum server on `127.0.0.1` only. An identity registers an address
//! with a signed body and an invite; a token-authenticated caller looks up an
//! address, asks for contact, answers what it is told, makes and redeems
//! invites, submits its own signed envelopes, fetches its waiting envelopes
//! and acknowledges them, and an acknowledged envelope is deleted. A letter
//! is stored only if its recipient approved its sender, and only within the
//! sender's daily limit.
//!
//! The relay stores public keys, addresses (the directory), SHA-256 of each
//! relay token, envelopes as they arrived (ciphertext and routing metadata),
//! and from Phase 4 the invite graph, the approval graph, pending events,
//! SHA-256 of each invite's relay key and daily counts (design §4.5). No
//! timestamps (days only), no IP addresses, no request log. `--trace` prints
//! path and status per request to stdout and stores nothing.
//!
//! This library holds everything; `main.rs` only parses arguments. brev-core's
//! end-to-end tests run the relay in-process through [`Server`].

#![forbid(unsafe_code)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

mod gates;
mod rules;
mod server;
mod store;

#[cfg(feature = "app-attest")]
pub use gates::{AttestVerifier, DevAttest, DEV_ATTESTATION};
pub use gates::{DevVerifier, Gates, IdentityVerifier};
pub use server::Server;
pub use store::Relay;

/// Why the relay could not start or a store operation failed. Content-free.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A listen address other than `127.0.0.1:<port>`.
    #[error("the relay listens on 127.0.0.1:<port> only")]
    Listen,
    /// A database path that is not absolute (SQLite would parse `file:`
    /// names as URIs, docs/DECISIONS.md D-0023).
    #[error("the database path must be absolute")]
    Path,
    /// A database file that is not a brev-relay database of this version.
    /// A Phase 3 file (version 1) is refused too: no migration.
    #[error("not a brev-relay database (version 2)")]
    NotRelay,
    /// The system's random number generator failed.
    #[error("the system random number generator failed")]
    Rng,
    /// A file or socket operation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// SQLite failed.
    #[error(transparent)]
    Db(#[from] rusqlite::Error),
}

/// The only listen addresses: `127.0.0.1:<port>`, the port in decimal
/// digits (0 lets the system pick one, as the tests do). Refuses every other
/// address, loopback or not (`0.0.0.0`, `[::1]`, `localhost`, `127.0.0.2`),
/// so the relay is never reachable off this Mac and no resolver runs.
pub fn parse_listen(listen: &str) -> Result<SocketAddr, Error> {
    let port = listen
        .strip_prefix("127.0.0.1:")
        .filter(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|p| p.parse::<u16>().ok())
        .ok_or(Error::Listen)?;
    Ok(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
}

/// Seconds in a UTC day.
const DAY: u64 = 86_400;

/// Where the relay reads the time. It keeps only the UTC day,
/// `unix seconds / 86 400` (design §4.4), never a time of day.
#[derive(Clone, Debug, Default)]
pub enum Clock {
    /// The system clock.
    #[default]
    System,
    /// Unix seconds that the caller sets and moves (tests).
    Manual(Arc<AtomicU64>),
}

impl Clock {
    /// Today's UTC day number.
    pub fn today(&self) -> u64 {
        let secs = match self {
            Clock::System => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            Clock::Manual(secs) => secs.load(Ordering::SeqCst),
        };
        secs / DAY
    }
}

/// The relay's limits and clock (design §4.4). The defaults are the owner's
/// values (design §13, answer 3).
#[derive(Clone, Debug)]
pub struct Config {
    /// Letters stored per sender per UTC day (50).
    pub letters_per_day: u32,
    /// Contact requests per requester per UTC day (10).
    pub requests_per_day: u32,
    /// Invites made per identity per UTC day (3).
    pub invites_per_day: u32,
    /// Invites an identity may have open, not redeemed and in life (5).
    pub open_invites: u32,
    /// Requests pending at one recipient; more are answered alike but
    /// stored nowhere (16).
    pub pending_requests: u32,
    /// Days an invite lives after the day it was made (7): an invite made
    /// on day `d` works through day `d + 7`.
    pub invite_days: u32,
    /// Where today comes from.
    pub clock: Clock,
    /// Transitional, until Phase 4 WP3 and WP4 move brev-mail's client and
    /// the app to Phase 4's bodies: `/v1/register`, `/v1/lookup` and
    /// `/v1/envelopes` take and answer Phase 3's bodies under Phase 3's
    /// rules (no invite, no approval, no limit, no token on submit), and
    /// Phase 4's own endpoints do not exist. Off by default; `serve
    /// --phase3` and [`Relay::open`] turn it on. It defeats every Phase 4
    /// check, so it is for Phase 3's callers and tests only.
    pub phase3: bool,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            letters_per_day: 50,
            requests_per_day: 10,
            invites_per_day: 3,
            open_invites: 5,
            pending_requests: 16,
            invite_days: 7,
            clock: Clock::System,
            phase3: false,
        }
    }
}

/// The relay's answer from a [`Policy`] hook.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Go on.
    Allow,
    /// Refuse with 429, after authentication and before any write.
    Deny,
}

/// The token-authenticated endpoints, for [`Policy::request`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endpoint {
    /// `POST /v1/lookup`.
    Lookup,
    /// `POST /v1/inbox`.
    Inbox,
    /// `POST /v1/inbox/ack`.
    Ack,
}

/// Test hooks (Phase 3's; kept as a deny hook in Phase 4, whose own rules
/// live in [`Relay`], design §1.2). Each is asked once a request is
/// authenticated and valid, before anything is written or read for it;
/// [`Decision::Deny`] answers 429.
pub trait Policy: Send + Sync {
    /// A registration of `address` with a valid signature. In Phase 4 asked
    /// last, after the invite, conflict and identity checks.
    fn register(&self, address: &str) -> Decision;
    /// A submitted envelope of `len` wire bytes, signed by its registered
    /// `sender`, to the registered `recipient`. In Phase 4 asked after the
    /// approval and letter-limit checks.
    fn submit(&self, sender: &[u8; 32], recipient: &[u8; 32], len: usize) -> Decision;
    /// A lookup, inbox or ack request by `caller` with its valid token.
    fn request(&self, caller: &[u8; 32], endpoint: Endpoint) -> Decision;
}

/// The Phase 3 policy: allows everything.
pub struct Open;

impl Policy for Open {
    fn register(&self, _: &str) -> Decision {
        Decision::Allow
    }
    fn submit(&self, _: &[u8; 32], _: &[u8; 32], _: usize) -> Decision {
        Decision::Allow
    }
    fn request(&self, _: &[u8; 32], _: Endpoint) -> Decision {
        Decision::Allow
    }
}
