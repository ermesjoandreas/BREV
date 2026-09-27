#!/usr/bin/env python3
"""Patches the UniFFI 0.32.2 Swift bindings so the Swift side leaves no byte
buffer unwiped (CLAUDE.md §3.1, docs/DECISIONS.md D-0032 item 5).

  A  RustBuffer.deallocate() wipes the buffer (memset_s over its capacity)
     before handing it back to Rust.
  B  FfiConverterRustBuffer.lift frees the buffer on every path, also when
     reading throws (stock code frees only on success).
  C  FfiConverterRustBuffer.lower wipes its serialisation array after Rust
     has copied it.
  D  FfiConverterData.read copies once, straight into the Data it returns
     (stock code goes through a temporary [UInt8] that is freed unwiped).

Every patch must match exactly once, every inserted line that is new to the
file must be there exactly once afterwards, and the stock Data(readBytes)
path must be gone. Anything else exits 1, so a uniffi upgrade cannot drop a
wipe silently. The first line becomes MARKER, and a file that already has it
is refused. scripts/gen-bindings.sh runs this right after bindgen and pins
the uniffi version it was written for.

usage: patch-bindings.py <BrevCore.swift>   (rewrites the file in place)
"""
import os
import sys

MARKER = "// brev: patched by scripts/patch-bindings.py"

PATCHES = [
    # A. Every RustBuffer Swift frees goes through here: wipe it first.
    #    uniffi's rustbuffer.rs lets foreign code write anywhere within
    #    `capacity`, so all of it is wiped, not only `len`.
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
    # D. Data.read(): copy once, straight into the Data that is returned.
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
            buf.data.copyBytes(to: dst.bindMemory(to: UInt8.self), from: range)
        }
        buf.offset = range.upperBound
        return value
    }""",
    ),
]


def fail(msg: str) -> None:
    sys.exit(f"patch-bindings: {msg}")


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: patch-bindings.py <BrevCore.swift>")
    path = sys.argv[1]
    with open(path, encoding="utf-8") as f:
        stock = f.read()
    if MARKER in stock:
        fail(f"{path} is already patched (run scripts/gen-bindings.sh, which regenerates it first)")

    src = stock
    for old, new in PATCHES:
        n = src.count(old)
        if n != 1:
            fail(f"expected exactly 1 match, found {n}, for:\n{old}")
        src = src.replace(old, new)

    # Post-check: each line a patch adds that the stock file did not already
    # contain is now there exactly once.
    stock_lines = set(stock.splitlines())
    patched_lines = src.splitlines()
    for _, new in PATCHES:
        for line in new.splitlines():
            if line not in stock_lines and patched_lines.count(line) != 1:
                fail(f"post-check: expected the inserted line exactly once:\n{line}")
    if "Data(try readBytes(" in src:
        fail("post-check: a Data(readBytes) copy path is still present")

    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(MARKER + "\n" + src)
    os.replace(tmp, path)


if __name__ == "__main__":
    main()
