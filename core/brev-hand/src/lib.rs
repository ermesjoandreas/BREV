//! Hand: the authorship token of docs/AUTHORSHIP.md.
//!
//! - [`facts`]: what the platform adapter saw, as raw samples. It turns
//!   them into the facts a token carries, and it holds the lock rule
//!   (sudo, SIP).
//! - [`requirements`]: the requirements, the same for sender and
//!   recipient.
//! - [`token`]: the claims, their fixed CBOR encoding, the COSE_Sign1
//!   token and the bytes the identity key signs.
//! - [`verify`]: the recipient's checks.
//!
//! Nothing here sees a key: the Secure Enclave signs, in the adapter, the
//! digest [`token::digest`] returns.

#![forbid(unsafe_code)]

pub mod facts;
pub mod requirements;
pub mod token;
pub mod verify;

pub use brev_vault::KeyOrigin;
pub use facts::{lock_reasons, Design, Env, FactLog, LockReason, Sample, Window};
pub use requirements::Rule;
pub use token::{content_hash, Claims};
pub use verify::{verify, Check, Outcome, Verification};

#[cfg(test)]
mod test_keys;
