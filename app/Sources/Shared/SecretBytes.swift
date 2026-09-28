// SecretBytes.swift — the fixed buffer every secret byte in Swift lives in.
//
// Upholds CLAUDE.md §1.10 and §6 (content is bytes, never a String, and is
// wiped when no longer needed). docs/PHASE2_DESIGN.md §6: a SecretBytes is
// allocated once at its final size and never grows, so no reallocation ever
// leaves an unwiped copy behind. Shared/ is compiled into the app and into
// the CLI harness (app/Tests), so nothing here may import AppKit.

import Foundation

/// A fixed-size buffer for secret bytes. It never grows and never copies
/// itself; `wipe()` and `deinit` overwrite it with `memset_s`. A class, so
/// there is no copy-on-write and no second storage.
final class SecretBytes {
    /// Allocation size in bytes; at least 64. Foundation stores a `Data` of
    /// 14 bytes or less inline (a copy), so a larger view of this buffer is
    /// always the buffer itself.
    let capacity: Int
    /// Bytes in use, from the start of `base`.
    private(set) var count: Int = 0
    /// Zero-filled, 16-byte aligned, `capacity` bytes.
    let base: UnsafeMutableRawPointer

    init(capacity: Int) {
        self.capacity = max(capacity, 64)
        base = UnsafeMutableRawPointer.allocate(byteCount: self.capacity, alignment: 16)
        base.initializeMemory(as: UInt8.self, repeating: 0, count: self.capacity)
    }

    deinit {
        wipe()
        base.deallocate()
    }

    /// Zeroes the whole allocation and sets `count` to 0.
    func wipe() {
        _ = memset_s(base, capacity, 0, capacity)
        count = 0
    }

    /// Appends `src`, or writes nothing and returns false if it would not fit.
    @discardableResult
    func append(_ src: UnsafeRawBufferPointer) -> Bool {
        guard src.count <= capacity - count else { return false }
        if let s = src.baseAddress { (base + count).copyMemory(from: s, byteCount: src.count) }
        count += src.count
        return true
    }

    /// Sets the used length after writing through `base` directly.
    func setCount(_ n: Int) {
        precondition(n >= 0 && n <= capacity)
        count = n
    }

    /// The used bytes, without copying.
    func withBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try body(UnsafeRawBufferPointer(start: base, count: count))
    }

    /// A `Data` over the WHOLE allocation, without copying, plus the used
    /// length: the shape of every content argument to Rust (`buf`, `len`;
    /// docs/PHASE2_DESIGN.md §2.2). The `Data` must not escape `body`.
    func withFFIView<R>(_ body: (Data, UInt32) throws -> R) rethrows -> R {
        let d = Data(bytesNoCopy: base, count: capacity, deallocator: .none)
        return try withExtendedLifetime(self) { try body(d, UInt32(count)) }
    }
}

extension Data {
    /// Zeroes this Data's storage in place. Only for a Data that nothing else
    /// references (an FFI chunk): then there is no copy-on-write, and the
    /// wiped bytes are the only ones. The unwrapped DEK is a CFData, wiped by
    /// Enclave.withWiped.
    mutating func wipe() {
        withUnsafeMutableBytes { b in
            if let p = b.baseAddress { _ = memset_s(p, b.count, 0, b.count) }
        }
    }
}
