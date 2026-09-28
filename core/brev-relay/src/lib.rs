//! Brev relay (docs/PHASE3_DESIGN.md §4): a minimal axum server on
//! `127.0.0.1` only. Identities register an address with a signed body; a
//! token-authenticated caller looks up an address, fetches its waiting
//! envelopes and acknowledges them, and an acknowledged envelope is deleted.
//! Anyone may submit an envelope that carries a valid signature by its
//! registered sender.
//!
//! The relay stores only public keys, addresses (the directory), SHA-256 of
//! each relay token, and envelopes as they arrived: ciphertext and routing
//! metadata. No timestamps, no IP addresses, no request log. `--trace`
//! prints path and status per request to stdout and stores nothing.
//!
//! This library holds everything; `main.rs` only parses arguments. brev-core's
//! end-to-end tests run the relay in-process through [`Server`].

#![forbid(unsafe_code)]

use std::net::{Ipv4Addr, SocketAddr};

mod server;
mod store;

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
    #[error("not a brev-relay database (version 1)")]
    NotRelay,
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

/// Hooks for Phase 4's rules (invites, contact approval, rate limits). Each
/// is asked once a request is authenticated and valid, before anything is
/// written or read for it; [`Decision::Deny`] answers 429.
pub trait Policy: Send + Sync {
    /// A registration of `address` with a valid signature.
    fn register(&self, address: &str) -> Decision;
    /// A submitted envelope of `len` wire bytes, signed by its registered
    /// `sender`, to the registered `recipient`.
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
