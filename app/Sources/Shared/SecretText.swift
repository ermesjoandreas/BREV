// SecretText.swift — editable UTF-16 content in one fixed SecretBytes.
//
// Upholds CLAUDE.md §1.10 and §6: names, subjects and bodies live here from
// the moment they leave Rust until they are wiped (docs/PHASE2_DESIGN.md
// §6.2). The buffer is sized once (maxUnits) and edited in place; nothing is
// ever a String. Core Foundation sees at most a no-copy window of the units
// (§6.3 rule 5). No AppKit: compiled into the app and the CLI harness.

import CoreFoundation
import Foundation

/// UTF-16 text in a fixed buffer of `2 * maxUnits` bytes. The unit of
/// drawing and editing; it becomes UTF-8 only when sent (`Transcode`).
final class SecretText {
    /// The buffer. Its `count` is twice `length`.
    let store: SecretBytes
    /// Most units this text can hold; inserts past it are refused.
    let maxUnits: Int

    init(maxUnits: Int) {
        self.maxUnits = maxUnits
        store = SecretBytes(capacity: maxUnits * 2)
    }

    /// Units in use.
    var length: Int { store.count / 2 }
    /// The units, valid for `length` (and zero up to `maxUnits`).
    var units: UnsafeMutablePointer<UInt16> { store.base.assumingMemoryBound(to: UInt16.self) }

    /// Inserts `u` at `at`, moving the tail inside the same buffer. Returns
    /// false, and changes nothing, if `at` is out of range or it would not fit.
    @discardableResult
    func insert(_ u: UnsafeBufferPointer<UInt16>, at: Int) -> Bool {
        let n = u.count, len = length
        guard at >= 0, at <= len, n <= maxUnits - len else { return false }
        guard n > 0, let src = u.baseAddress else { return true }
        (units + at + n).update(from: units + at, count: len - at)   // overlap-safe
        (units + at).update(from: src, count: n)
        store.setCount((len + n) * 2)
        return true
    }

    /// Deletes `r`, then zeroes the units freed at the end.
    func delete(_ r: Range<Int>) {
        let len = length
        guard r.lowerBound >= 0, r.upperBound <= len, !r.isEmpty else { return }
        (units + r.lowerBound).update(from: units + r.upperBound, count: len - r.upperBound)
        let newLen = len - r.count
        _ = memset_s(units + newLen, r.count * 2, 0, r.count * 2)
        store.setCount(newLen * 2)
    }

    func wipe() { store.wipe() }

    /// The composed character sequence that contains unit `i` (e + U+0301,
    /// a surrogate pair, an emoji sequence), for Delete and caret moves. CF
    /// sees a no-copy window of about `window` units around `i` that never
    /// splits a surrogate pair at either edge; an empty range if `i` is out
    /// of range.
    func composedRange(at i: Int, window: Int = 64) -> Range<Int> {
        let len = length
        guard i >= 0, i < len else { return i..<i }
        let w = min(window, TextLayout.maxLineUnits - 2)   // +2 for the edges below
        var lo = max(0, i - w / 2), hi = min(len, lo + w)
        if lo > 0, UTF16.isTrailSurrogate(units[lo]) { lo -= 1 }
        if hi < len, UTF16.isTrailSurrogate(units[hi]) { hi += 1 }
        var r = CFRange(location: 0, length: 0)
        autoreleasepool {
            let s = CFStringCreateWithCharactersNoCopy(nil, units + lo, hi - lo, kCFAllocatorNull)!
            r = CFStringGetRangeOfComposedCharactersAtIndex(s, i - lo)
        }
        return (lo + r.location)..<(lo + r.location + r.length)
    }

    /// A second, independent buffer with the same units (the compose
    /// sheet's recipient name). The caller wipes it.
    func copy() -> SecretText {
        let t = SecretText(maxUnits: maxUnits)
        store.withBytes { _ = t.store.append($0) }
        return t
    }
}
