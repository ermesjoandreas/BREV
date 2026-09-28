//! Spike only. A global allocator wrapping `System` with two switches:
//!
//! * PROBE: before a block is released (dealloc, or the old block of a
//!   realloc that moved), scan it for a 16-byte needle and count the block.
//! * ZERO:  wipe every released block (dealloc, and the old block of every
//!   realloc, which is done as alloc + copy + wipe + dealloc) before it goes
//!   back to `System`.
//!
//! The `#[global_allocator]` static lives here, so a crate that only depends
//! on this one (brev-core) needs no `unsafe` of its own.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering::Relaxed};

pub const PROBE: u8 = 1;
pub const ZERO: u8 = 2;

static MODE: AtomicU8 = AtomicU8::new(0);
static NEEDLE: [AtomicU8; 16] = [const { AtomicU8::new(0) }; 16];
static NEEDLE_SET: AtomicU8 = AtomicU8::new(0);
/// Released blocks that still held the needle, split at libmalloc's
/// zero-on-free limit measured on macOS 26.2 (<= 1024 B zeroed, > 1024 B not).
static HITS_SMALL: AtomicUsize = AtomicUsize::new(0);
static HITS_LARGE: AtomicUsize = AtomicUsize::new(0);
/// Same, but only blocks that went back to `System` unwiped.
static UNWIPED_SMALL: AtomicUsize = AtomicUsize::new(0);
static UNWIPED_LARGE: AtomicUsize = AtomicUsize::new(0);

pub fn set_mode(m: u8) {
    MODE.store(m, Relaxed);
}
/// The needle is stored XOR 0x5A so this static never holds the marker
/// itself (a heap scanner would otherwise count it).
pub fn set_needle_xored(n: &[u8; 16]) {
    for (slot, b) in NEEDLE.iter().zip(n) {
        slot.store(*b, Relaxed);
    }
    NEEDLE_SET.store(1, Relaxed);
}
pub fn reset() {
    for c in [&HITS_SMALL, &HITS_LARGE, &UNWIPED_SMALL, &UNWIPED_LARGE] {
        c.store(0, Relaxed);
    }
}
/// (hits_small, hits_large, unwiped_small, unwiped_large)
pub fn counters() -> [usize; 4] {
    [
        HITS_SMALL.load(Relaxed),
        HITS_LARGE.load(Relaxed),
        UNWIPED_SMALL.load(Relaxed),
        UNWIPED_LARGE.load(Relaxed),
    ]
}

/// # Safety
/// `p` must be valid for reads of `n` bytes.
unsafe fn holds_needle(p: *const u8, n: usize) -> bool {
    if NEEDLE_SET.load(Relaxed) == 0 || n < 16 {
        return false;
    }
    let s = std::slice::from_raw_parts(p, n);
    let first = NEEDLE[0].load(Relaxed);
    'outer: for i in 0..=n - 16 {
        if s[i] ^ 0x5A != first {
            continue;
        }
        for j in 1..16 {
            if s[i + j] ^ 0x5A != NEEDLE[j].load(Relaxed) {
                continue 'outer;
            }
        }
        return true;
    }
    false
}

/// # Safety
/// `p` must be valid for reads and writes of `n` bytes.
unsafe fn release(p: *mut u8, n: usize) {
    let mode = MODE.load(Relaxed);
    let hit = mode & PROBE != 0 && holds_needle(p, n);
    let zero = mode & ZERO != 0;
    if hit {
        if n <= 1024 { &HITS_SMALL } else { &HITS_LARGE }.fetch_add(1, Relaxed);
        if !zero {
            if n <= 1024 { &UNWIPED_SMALL } else { &UNWIPED_LARGE }.fetch_add(1, Relaxed);
        }
    }
    if zero {
        // Volatile writes + fence (zeroize's implementation), so the wipe of
        // memory that is about to be freed cannot be elided.
        zeroize::Zeroize::zeroize(std::slice::from_raw_parts_mut(p, n));
    }
}

pub struct SpikeAlloc;

unsafe impl GlobalAlloc for SpikeAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        System.alloc(layout)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        System.alloc_zeroed(layout)
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        release(p, layout.size());
        System.dealloc(p, layout)
    }
    unsafe fn realloc(&self, p: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let mode = MODE.load(Relaxed);
        if mode & ZERO != 0 {
            // Never let System move the block: it would free the old copy unwiped.
            let new_layout = Layout::from_size_align_unchecked(new_size, layout.align());
            let q = System.alloc(new_layout);
            if !q.is_null() {
                std::ptr::copy_nonoverlapping(p, q, layout.size().min(new_size));
                release(p, layout.size());
                System.dealloc(p, layout);
            }
            q
        } else {
            let hit = mode & PROBE != 0 && holds_needle(p, layout.size());
            let q = System.realloc(p, layout, new_size);
            if hit && q != p && !q.is_null() {
                let n = layout.size();
                if n <= 1024 { &HITS_SMALL } else { &HITS_LARGE }.fetch_add(1, Relaxed);
                if n <= 1024 { &UNWIPED_SMALL } else { &UNWIPED_LARGE }.fetch_add(1, Relaxed);
            }
            q
        }
    }
}

#[cfg(not(feature = "onepassword"))]
#[global_allocator]
static GLOBAL: SpikeAlloc = SpikeAlloc;

/// Variant: 1Password's zeroizing-alloc 0.1.1 instead of the spike allocator.
#[cfg(feature = "onepassword")]
#[global_allocator]
static GLOBAL: zeroizing_alloc::ZeroAlloc<System> = zeroizing_alloc::ZeroAlloc(System);
