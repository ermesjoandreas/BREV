// EditModel.swift — the caret and the edits of one compose field.
//
// Upholds CLAUDE.md §1.3 and §1.10 (docs/PHASE2_DESIGN.md §6, §7.3): a
// subject or a body lives in one fixed SecretText and is edited in place;
// nothing is ever a String. There is no selection, so nothing can be copied,
// even in principle. Text comes in one keystroke at a time (KeyTranslator)
// or as a newline (Return in the body). An insert that would pass the
// field's UTF-8 limit (Rust's limits()) is refused, and the view beeps.
// Delete and ←/→ go by composed character (SecretText.composedRange); ↑/↓,
// line start and end, and clicks use the lines of the field's TextLayout.
// No AppKit: compiled into the app and the CLI harness. Main thread only.

import CoreGraphics
import Foundation

final class EditModel {
    /// The field's text. The compose sheet sends it; `wipe` clears it.
    let text: SecretText
    /// The most UTF-8 bytes the text may have.
    let maxBytes: Int
    /// False for the subject: no newline.
    let multiline: Bool
    /// A unit index in 0...text.length, at the start of a composed character.
    private(set) var caret = 0
    /// The text's UTF-8 length, as Transcode writes it.
    private(set) var utf8Count = 0
    /// The x that ↑/↓ aim for, kept across consecutive vertical moves.
    private var goalX: CGFloat?

    /// A field of at most `maxBytes` UTF-8 bytes. A unit is at least one
    /// byte, so the text never needs more than `maxBytes` units.
    init(maxBytes: Int, multiline: Bool) {
        self.maxBytes = maxBytes
        self.multiline = multiline
        text = SecretText(maxUnits: maxBytes)
    }

    // MARK: Edits

    /// Inserts one keystroke's units at the caret and moves the caret past
    /// them. Refused, changing nothing, if a unit is a control character
    /// (Home, End and the function keys translate to those), if the text
    /// would not fit, or if it would pass `maxBytes`. No units (a dead key)
    /// is not a refusal.
    @discardableResult
    func insert(_ u: UnsafeBufferPointer<UInt16>) -> Bool {
        goalX = nil
        guard !u.contains(where: { $0 < 0x20 || $0 == 0x7F }) else { return false }
        return put(u)
    }

    /// Return in the body. Refused in a single-line field.
    @discardableResult
    func insertNewline() -> Bool {
        goalX = nil
        guard multiline else { return false }
        var newline: UInt16 = 0x0A
        return withUnsafePointer(to: &newline) { put(UnsafeBufferPointer(start: $0, count: 1)) }
    }

    /// Delete: removes the composed character before the caret.
    @discardableResult
    func deleteBackward() -> Bool {
        goalX = nil
        guard caret > 0 else { return false }
        remove(text.composedRange(at: caret - 1))
        return true
    }

    /// Forward Delete: removes the composed character after the caret.
    @discardableResult
    func deleteForward() -> Bool {
        goalX = nil
        guard caret < text.length else { return false }
        remove(text.composedRange(at: caret))
        return true
    }

    /// Send, cancel and lock: the text is wiped, the caret goes to 0.
    func wipe() {
        text.wipe()
        caret = 0
        utf8Count = 0
        goalX = nil
    }

    // MARK: Caret moves

    /// ←
    func moveLeft() {
        goalX = nil
        if caret > 0 { caret = text.composedRange(at: caret - 1).lowerBound }
    }

    /// →
    func moveRight() {
        goalX = nil
        if caret < text.length { caret = text.composedRange(at: caret).upperBound }
    }

    /// ⌘↑
    func moveToStart() {
        goalX = nil
        caret = 0
    }

    /// ⌘↓
    func moveToEnd() {
        goalX = nil
        caret = text.length
    }

    /// The line the caret is drawn on: the last line that starts at or
    /// before it. Where a soft wrap ends one line and starts the next at the
    /// same unit, that is the next line. `layout` must be laid out for this
    /// text since its last edit, here and in every method below.
    func caretLine(in layout: TextLayout) -> Int {
        layout.lines.lastIndex { $0.start <= caret } ?? 0
    }

    /// ⌘←
    func moveToLineStart(in layout: TextLayout) {
        goalX = nil
        guard !layout.lines.isEmpty else { return }
        caret = layout.lines[caretLine(in: layout)].start
    }

    /// ⌘→
    func moveToLineEnd(in layout: TextLayout) {
        goalX = nil
        guard !layout.lines.isEmpty else { return }
        caret = lineEnd(caretLine(in: layout), in: layout)
    }

    /// ↑: the nearest position on the line above; on the first line, the start.
    func moveUp(in layout: TextLayout) {
        moveVertically(by: -1, in: layout)
    }

    /// ↓: the nearest position on the line below; on the last line, the end.
    func moveDown(in layout: TextLayout) {
        moveVertically(by: 1, in: layout)
    }

    /// A click at `x` on line `i`; above the first line is the start, below
    /// the last line the end.
    func place(line i: Int, x: CGFloat, in layout: TextLayout) {
        goalX = nil
        if i < 0 || layout.lines.isEmpty {
            caret = 0
        } else if i >= layout.lines.count {
            caret = text.length
        } else {
            caret = position(line: i, x: x, in: layout)
        }
    }

    // MARK: Private

    private func put(_ u: UnsafeBufferPointer<UInt16>) -> Bool {
        guard !u.isEmpty else { return true }
        let at = caret
        guard text.insert(u, at: at) else { return false }
        let n = Self.utf8Length(text)
        guard n <= maxBytes else {
            text.delete(at..<(at + u.count))   // zeroes the units it frees
            return false
        }
        utf8Count = n
        caret = at + u.count
        return true
    }

    private func remove(_ r: Range<Int>) {
        text.delete(r)
        caret = r.lowerBound
        utf8Count = Self.utf8Length(text)
    }

    private func moveVertically(by step: Int, in layout: TextLayout) {
        guard !layout.lines.isEmpty else { return }
        let i = caretLine(in: layout), j = i + step
        guard j >= 0 && j < layout.lines.count else {
            caret = j < 0 ? 0 : text.length
            goalX = nil
            return
        }
        let x = goalX ?? layout.caretOffset(text, line: i, index: caret)
        caret = position(line: j, x: x, in: layout)
        goalX = x
    }

    /// The caret position nearest to `x` on line `i`, kept on that line and
    /// at the start of a composed character.
    private func position(line i: Int, x: CGFloat, in layout: TextLayout) -> Int {
        let k = min(layout.index(text, line: i, x: x), lineEnd(i, in: layout))
        return k < text.length ? text.composedRange(at: k).lowerBound : k
    }

    /// Where the caret stops at the end of line `i`: the line's end, or, at
    /// a soft wrap, before its last composed character (usually the space
    /// it broke after), since the end itself is drawn on the next line.
    private func lineEnd(_ i: Int, in layout: TextLayout) -> Int {
        let l = layout.lines[i], end = l.start + l.length
        guard l.length > 0, i + 1 < layout.lines.count, layout.lines[i + 1].start == end else { return end }
        return max(l.start, text.composedRange(at: end - 1).lowerBound)
    }

    /// UTF-8 bytes of `t` as Transcode.utf16ToUTF8 writes them: a surrogate
    /// pair gives 4, a lone surrogate 3 (U+FFFD).
    private static func utf8Length(_ t: SecretText) -> Int {
        let u = t.units, len = t.length
        var n = 0, i = 0
        while i < len {
            let c = u[i]
            if c < 0x80 {
                n += 1
            } else if c < 0x800 {
                n += 2
            } else if UTF16.isLeadSurrogate(c), i + 1 < len, UTF16.isTrailSurrogate(u[i + 1]) {
                n += 4
                i += 1
            } else {
                n += 3
            }
            i += 1
        }
        return n
    }
}
