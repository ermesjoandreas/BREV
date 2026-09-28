//! FFI spike: experimental exports that move marker-filled "plaintext" across
//! UniFFI in every shape Phase 2 might use. Not Brev code.
//!
//! The marker "BREV-SECRET-BODY" is stored XOR 0x5A, so the binary itself
//! never contains it; every hit a scanner finds is a runtime copy.

use std::sync::{Arc, Mutex};
use zeroize::{Zeroize, Zeroizing};

const MARKER_X: [u8; 16] = [
    0x18, 0x08, 0x1f, 0x0c, 0x77, 0x09, 0x1f, 0x19, 0x08, 0x1f, 0x0e, 0x77, 0x18, 0x15, 0x1e, 0x03,
];

/// A body of `len` bytes: the marker repeated. Exact capacity, wiped on drop.
/// Built straight from the XOR form, so no stray 16-byte marker copy exists.
fn make_body(len: u32) -> Zeroizing<Vec<u8>> {
    let len = len as usize;
    let key = std::hint::black_box(0x5Au8);
    let mut v = Zeroizing::new(Vec::with_capacity(len));
    for i in 0..len {
        v.push(MARKER_X[i % 16] ^ key);
    }
    v
}

// ---- allocator probe controls ------------------------------------------

/// 0 = pass-through, 1 = probe, 2 = zero, 3 = probe + zero.
#[uniffi::export]
pub fn spike_alloc_mode(mode: u8) {
    brev_alloc_spike::set_needle_xored(&MARKER_X);
    brev_alloc_spike::set_mode(mode);
}

#[uniffi::export]
pub fn spike_alloc_reset() {
    brev_alloc_spike::reset();
}

/// [released blocks holding the marker <=1024 B, >1024 B,
///  of which unwiped <=1024 B, >1024 B]
#[uniffi::export]
pub fn spike_alloc_counters() -> Vec<u64> {
    brev_alloc_spike::counters().iter().map(|c| *c as u64).collect()
}

// ---- P1: Swift -> Rust, owned Vec<u8> argument --------------------------

#[uniffi::export]
pub fn spike_owned_in(body: Vec<u8>) -> u32 {
    let body = Zeroizing::new(body); // what a careful core would do
    body.len() as u32
}

// ---- P2: Swift -> Rust, borrowed &[u8] argument (ForeignBytes) ----------

#[uniffi::export]
pub fn spike_borrowed_in(body: &[u8]) -> u32 {
    let copy = Zeroizing::new(body.to_vec()); // like unlock() copying the DEK
    copy.len() as u32
}

// ---- P3: Rust -> Swift, Vec<u8> return from a free function -------------

#[uniffi::export]
pub fn spike_owned_out(len: u32) -> Vec<u8> {
    make_body(len).to_vec() // like `Plaintext` -> Vec<u8>
}

// ---- P3s: Rust -> Swift, String return (lowered without re-serialising) --

#[uniffi::export]
pub fn spike_string_out(len: u32) -> String {
    String::from_utf8(make_body(len).to_vec()).unwrap_or_default()
}

// ---- P4: Object (Arc) methods -------------------------------------------

/// Holds one body, as a `Core` would hold decrypted state.
#[derive(uniffi::Object)]
pub struct SpikeSession {
    body: Mutex<Zeroizing<Vec<u8>>>,
    key: Mutex<Zeroizing<Vec<u8>>>,
}

#[uniffi::export]
impl SpikeSession {
    #[uniffi::constructor]
    pub fn new(len: u32) -> Arc<Self> {
        Arc::new(SpikeSession {
            body: Mutex::new(make_body(len)),
            key: Mutex::new(Zeroizing::new(Vec::new())),
        })
    }
    /// Owned bytes out of a method.
    pub fn body(&self) -> Vec<u8> {
        self.body.lock().map(|b| b.to_vec()).unwrap_or_default()
    }
    /// Same bytes as a String (whole buffer handed over, no re-serialising).
    pub fn body_string(&self) -> String {
        let v = self.body.lock().map(|b| b.to_vec()).unwrap_or_default();
        String::from_utf8(v).unwrap_or_default()
    }
    /// One chunk of the body.
    pub fn body_chunk(&self, offset: u32, len: u32) -> Vec<u8> {
        let b = match self.body.lock() {
            Ok(b) => b,
            Err(_) => return Vec::new(),
        };
        let start = (offset as usize).min(b.len());
        let end = start.saturating_add(len as usize).min(b.len());
        b[start..end].to_vec()
    }
    pub fn body_len(&self) -> u32 {
        self.body.lock().map(|b| b.len() as u32).unwrap_or(0)
    }
    /// Borrowed bytes into a method: copies the key, like `unlock`.
    pub fn unlock(&self, dek: &[u8]) -> u32 {
        if let Ok(mut k) = self.key.lock() {
            k.zeroize();
            *k = Zeroizing::new(dek.to_vec());
            return k.len() as u32;
        }
        0
    }
    /// Wipes everything the session holds.
    pub fn wipe(&self) {
        if let Ok(mut b) = self.body.lock() {
            b.zeroize();
        }
        if let Ok(mut k) = self.key.lock() {
            k.zeroize();
        }
    }
}

// ---- P5: callback interface ---------------------------------------------

/// Implemented in Swift.
#[uniffi::export(callback_interface)]
pub trait SpikeSink: Send + Sync {
    /// Rust -> Swift bytes as a callback argument.
    fn put(&self, body: Vec<u8>);
    /// Swift -> Rust bytes as a callback return value.
    fn get(&self) -> Vec<u8>;
}

#[uniffi::export]
pub fn spike_callback(sink: Box<dyn SpikeSink>, len: u32) -> u32 {
    sink.put(make_body(len).to_vec());
    let back = Zeroizing::new(sink.get());
    back.len() as u32
}
