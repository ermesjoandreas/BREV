#!/usr/bin/env python3
"""Spike: post-process UniFFI 0.32.2 Swift bindings so no content byte is left
in freed memory on the Swift side. Every patch must match exactly once, or the
script fails (so a uniffi upgrade cannot silently drop a wipe).

usage: patch_bindings.py <in BrevCore.swift> <out BrevCore.swift>
"""
import sys

PATCHES = [
    # A. Every RustBuffer Swift frees goes through here: wipe it first.
    #    rustbuffer.rs:29-30 allows foreign code to write within `capacity`.
    (
        """    func deallocate() {
        try! rustCall { ffi_brev_core_rustbuffer_free(self, $0) }
    }""",
        """    func deallocate() {
        if let d = data, capacity > 0 { _ = memset_s(d, Int(capacity), 0, Int(capacity)) }
        try! rustCall { ffi_brev_core_rustbuffer_free(self, $0) }
    }""",
    ),
    # B. lift(): free (and so wipe) the buffer on the throwing paths too.
    (
        """    public static func lift(_ buf: RustBuffer) throws -> SwiftType {
        var reader = createReader(data: Data(rustBuffer: buf))
        let value = try read(from: &reader)
        if hasRemaining(reader) {
            throw UniffiInternalError.incompleteData
        }
        buf.deallocate()
        return value
    }""",
        """    public static func lift(_ buf: RustBuffer) throws -> SwiftType {
        defer { buf.deallocate() }
        var reader = createReader(data: Data(rustBuffer: buf))
        let value = try read(from: &reader)
        if hasRemaining(reader) {
            throw UniffiInternalError.incompleteData
        }
        return value
    }""",
    ),
    # C. lower(): wipe the serialisation array after Rust has copied it.
    (
        """    public static func lower(_ value: SwiftType) -> RustBuffer {
          var writer = createWriter()
          write(value, into: &writer)
          return RustBuffer(bytes: writer)
    }""",
        """    public static func lower(_ value: SwiftType) -> RustBuffer {
          var writer = createWriter()
          write(value, into: &writer)
          let rbuf = RustBuffer(bytes: writer)
          writer.withUnsafeMutableBytes { if let p = $0.baseAddress { _ = memset_s(p, $0.count, 0, $0.count) } }
          return rbuf
    }""",
    ),
    # D. Data.read(): copy once, straight into the Data that is returned
    #    (stock code goes through a temporary [UInt8] that is freed unwiped).
    (
        """    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> Data {
        let len: Int32 = try readInt(&buf)
        return Data(try readBytes(&buf, count: Int(len)))
    }""",
        """    public static func read(from buf: inout (data: Data, offset: Data.Index)) throws -> Data {
        let len: Int32 = try readInt(&buf)
        let count = Int(len)
        guard count >= 0, buf.data.count >= buf.offset + count else {
            throw UniffiInternalError.bufferOverflow
        }
        let range = buf.offset..<(buf.offset + count)
        var value = Data(count: count)
        value.withUnsafeMutableBytes { dst in
            _ = buf.data.copyBytes(to: dst.bindMemory(to: UInt8.self), from: range)
        }
        buf.offset = range.upperBound
        return value
    }""",
    ),
]


def main() -> None:
    src = open(sys.argv[1]).read()
    for old, new in PATCHES:
        n = src.count(old)
        if n != 1:
            sys.exit(f"patch_bindings: expected 1 match, found {n}:\n{old[:120]}")
        src = src.replace(old, new)
    open(sys.argv[2], "w").write(src)


if __name__ == "__main__":
    main()
