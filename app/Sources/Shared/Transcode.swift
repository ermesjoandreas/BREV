// Transcode.swift — UTF-8 <-> UTF-16 between fixed buffers, and reading an
// OpenText out of Rust.
//
// Upholds CLAUDE.md §1.10 and §6: no String is ever made. The stdlib
// transcoder keeps its state on the stack, and every intermediate buffer is
// wiped before the function returns (docs/PHASE2_DESIGN.md §6.2, rules 2
// and 6 of §6.3). No AppKit: compiled into the app and the CLI harness.

import Foundation

enum Transcode {
    /// UTF-8 bytes into `out` (which is wiped first) as UTF-16. Invalid
    /// input becomes U+FFFD. Units past `out.maxUnits` are dropped; a
    /// `maxUnits` of at least `src.count` always fits.
    static func utf8ToUTF16(_ src: UnsafeRawBufferPointer, into out: SecretText) {
        out.wipe()
        var n = 0
        let dst = out.units
        _ = transcode(src.bindMemory(to: UInt8.self).makeIterator(), from: UTF8.self, to: UTF16.self,
                      stoppingOnError: false) { unit in
            if n < out.maxUnits { dst[n] = unit; n += 1 }
        }
        out.store.setCount(n * 2)
    }

    /// `src` into `out` (which is wiped first) as UTF-8. A unit gives at
    /// most 3 bytes (a surrogate pair gives 4 for 2 units, a lone surrogate
    /// U+FFFD), so `out` needs 3 bytes per unit.
    static func utf16ToUTF8(_ src: SecretText, into out: SecretBytes) {
        precondition(out.capacity >= 3 * src.length)
        out.wipe()
        var n = 0
        let dst = out.base.assumingMemoryBound(to: UInt8.self)
        _ = transcode(UnsafeBufferPointer(start: src.units, count: src.length).makeIterator(),
                      from: UTF16.self, to: UTF8.self, stoppingOnError: false) { b in
            dst[n] = b
            n += 1
        }
        out.setCount(n)
    }
}

enum TextReader {
    /// Reads an OpenText completely into a new SecretText and closes it, on
    /// every path, so Rust wipes its copy (§6.3 rule 6). Each 960-byte chunk
    /// is wiped in place after it is copied, and the UTF-8 staging buffer
    /// before this returns.
    static func read(_ t: OpenText) throws -> SecretText {
        defer { t.close() }
        let n = Int(t.byteLen())
        let utf8 = SecretBytes(capacity: n)
        defer { utf8.wipe() }
        var i: UInt32 = 0
        while utf8.count < n {
            var c = try t.chunk(index: i)
            let take = min(c.count, n - utf8.count)
            c.withUnsafeBytes { b in _ = utf8.append(UnsafeRawBufferPointer(rebasing: b[0..<take])) }
            c.wipe()
            guard take > 0 else { throw BrevError.Malformed }
            i += 1
        }
        let out = SecretText(maxUnits: max(n, 1))
        utf8.withBytes { Transcode.utf8ToUTF16($0, into: out) }
        return out
    }
}
