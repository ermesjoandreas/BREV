//! Brev vault: the part of the core that knows nothing about mail.
//!
//! An encrypted SQLite store ([`Vault`]) whose content columns are sealed
//! under a data-encryption key (DEK) with XChaCha20-Poly1305, the
//! `Locked`/`Unlocked` state of that key with its single gate
//! ([`Vault::dek`]), the store hardening (path, pragmas, exact schema,
//! journal mode, file mode 0600, a locked directory with mode 0700), the
//! launch guard ([`launch_check`], feature `launch-guard`), the two-step
//! unlock and the idle deadline with their [`Timer`] ([`Clock`]), the
//! length-hiding padding ([`padding`]), decrypted values that wipe
//! themselves ([`Plaintext`], [`Text`]), the stack scrubs, and the zeroing
//! global allocator (feature `zeroing-allocator`).
//!
//! What a store holds is the caller's: the file name, `application_id`,
//! schema and schema version come in a [`VaultConfig`], and the rows are
//! written through [`Vault::db`]. brev-mail is the one caller today.
//!
//! No UniFFI and no network here (scripts/check-vault-deps.sh).

#![forbid(unsafe_code)]

/// Every Rust heap block is zeroed when it is freed, including the
/// `RustBuffer`s Swift frees through UniFFI (CLAUDE.md §3.1). Safe code
/// here: the `unsafe impl` is inside the approved `zeroizing-alloc` crate.
#[cfg(feature = "zeroing-allocator")]
#[global_allocator]
static ALLOC: zeroizing_alloc::ZeroAlloc<std::alloc::System> =
    zeroizing_alloc::ZeroAlloc(std::alloc::System);

mod clock;
mod crypto;
mod dirlock;
mod error;
mod launch;
pub mod padding;
mod store;
mod text;

pub use clock::{Clock, Holder, Timer, CONFIRM_WINDOW, DEFAULT_IDLE};
pub use crypto::{
    aead_open, aead_seal, column_ad, fill, is_zero, open_column, pad, random, scrub_stack,
    scrub_stack_deep, seal_column, Plaintext, NONCE_LEN, TAG_LEN,
};
pub use error::Error;
pub use launch::launch_check;
pub use store::{check_path, DekSlot, Vault, VaultConfig};
pub use text::{Text, CHUNK};

/// Test builds only (`cfg(test)` or the feature `test-hooks`): counters of
/// this thread and a compile-time wipe check, for the tests of the crates
/// built on the vault.
#[cfg(any(test, feature = "test-hooks"))]
pub mod test_hooks {
    pub use crate::crypto::{deep_scrubs, live_plaintexts, scrubs, wiped_on_drop};
}
