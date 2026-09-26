//! Thin wrapper around `uniffi::uniffi_bindgen_main` so the exact same
//! `uniffi` version that compiled `brev-core` also generates its bindings.
//!
//! Invoked by `scripts/gen-bindings.sh`; never part of the shipped app.

#![forbid(unsafe_code)]

fn main() {
    uniffi::uniffi_bindgen_main()
}
