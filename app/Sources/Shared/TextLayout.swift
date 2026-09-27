// TextLayout.swift — per-line Core Text layout and drawing from a SecretText.
//
// Upholds CLAUDE.md §2's accepted framework-copy risk and its mitigation:
// content is drawn one line at a time from a wipeable buffer, never laid out
// as a whole body (docs/PHASE2_DESIGN.md §6.4). Core Text only ever sees a
// no-copy window of at most 448 UTF-16 units, so each transient copy it
// makes stays under 1 KiB. Only CTLine is used: a Core Text typesetter keeps
// a live copy of recent text, and a framesetter lays out a whole body (§6.3
// rule 8). Freed framework storage is overwritten by MallocScribble=1, and
// GlyphFlush replaces what Core Text keeps alive. No AppKit: compiled into
// the app and the CLI harness.

import CoreFoundation
import CoreGraphics
import CoreText
import Foundation

/// One laid-out line: a range of units in the text. Only these integers are
/// kept between layout and drawing, never text.
struct LineRef {
    let start: Int
    let length: Int
}

final class TextLayout {
    /// 448 units = 896 bytes of UTF-16; with a CF header it stays <= 1 KiB.
    static let maxLineUnits = 448
    let font: CTFont
    let lineHeight: CGFloat
    private let attrs: CFDictionary
    private(set) var lines: [LineRef] = []

    init(font: CTFont) {
        self.font = font
        lineHeight = ceil(CTFontGetAscent(font) + CTFontGetDescent(font) + CTFontGetLeading(font)) + 2
        attrs = [kCTFontAttributeName: font,
                 kCTForegroundColorFromContextAttributeName: kCFBooleanTrue!] as CFDictionary
        if GlyphFlush.attrs == nil { GlyphFlush.attrs = attrs }   // one content font app-wide
    }

    var height: CGFloat { CGFloat(lines.count) * lineHeight }

    /// Breaks `text` into lines at most `width` points wide. Paragraphs end
    /// at U+000A. Within one, each line comes from a CTLine over a window of
    /// at most 448 units: the index at `width`, moved back to just after the
    /// last space before it if there is one. A surrogate pair is never split.
    func layout(_ text: SecretText, width: CGFloat) {
        lines.removeAll(keepingCapacity: true)
        let u = text.units, len = text.length
        var p = 0
        while p <= len {
            var end = p
            while end < len && u[end] != 0x0A { end += 1 }
            if end == p { lines.append(LineRef(start: p, length: 0)) }
            var pos = p
            while pos < end {
                var window = min(end - pos, Self.maxLineUnits)
                if window < end - pos, UTF16.isLeadSurrogate(u[pos + window - 1]) { window -= 1 }
                var k = 0
                autoreleasepool {
                    let s = CFStringCreateWithCharactersNoCopy(nil, u + pos, window, kCFAllocatorNull)!
                    let a = CFAttributedStringCreate(nil, s, attrs)!
                    k = CTLineGetStringIndexForPosition(CTLineCreateWithAttributedString(a), CGPoint(x: width, y: 0))
                }
                let n = Self.lineLength(at: u + pos, window: window, fit: k)
                lines.append(LineRef(start: pos, length: n))
                pos += n
            }
            p = end + 1
        }
    }

    /// The length of the line that starts at `u`, given the index Core Text
    /// found at the width (`fit`). Always 1...window.
    private static func lineLength(at u: UnsafePointer<UInt16>, window: Int, fit: Int) -> Int {
        guard fit != kCFNotFound, fit < window else { return window }
        var k = max(fit, 1)
        var b = k
        while b > 0 && u[b - 1] != 0x20 { b -= 1 }
        if b > 0 { k = b }
        if k < window, UTF16.isLeadSurrogate(u[k - 1]), UTF16.isTrailSurrogate(u[k]) {
            k = k > 1 ? k - 1 : 2   // keep the pair together
        }
        return k
    }

    /// Draws `range` of `lines` into a context whose y grows downward (a
    /// flipped view), with the first line's top at `top`.
    func draw(_ text: SecretText, lines range: Range<Int>, in ctx: CGContext, x: CGFloat, top: CGFloat) {
        let descent = CTFontGetDescent(font)
        ctx.textMatrix = CGAffineTransform(scaleX: 1, y: -1)
        for i in range where i >= 0 && i < lines.count {
            let l = lines[i]
            guard l.length > 0 else { continue }
            autoreleasepool {
                let s = CFStringCreateWithCharactersNoCopy(nil, text.units + l.start, l.length, kCFAllocatorNull)!
                let a = CFAttributedStringCreate(nil, s, attrs)!
                ctx.textPosition = CGPoint(x: x, y: top + CGFloat(i + 1) * lineHeight - descent - 1)
                CTLineDraw(CTLineCreateWithAttributedString(a), ctx)
            }
        }
    }

    func reset() {
        lines.removeAll()
    }
}

/// Replaces what Core Text keeps alive after drawing content. Core Text
/// reuses glyph and run storage by line length, so `flush` lays out and
/// draws filler text of every length 1...448 into a 1x1 context. Main thread
/// only; called once in the lock sequence and when a letter view is torn
/// down (docs/PHASE2_DESIGN.md §6.4, §8.4).
enum GlyphFlush {
    /// The content font's attributes, set by the first TextLayout.
    static var attrs: CFDictionary?

    static func flush() {
        guard let attrs,
              let ctx = CGContext(data: nil, width: 1, height: 1, bitsPerComponent: 8, bytesPerRow: 0,
                                  space: CGColorSpaceCreateDeviceGray(), bitmapInfo: CGImageAlphaInfo.none.rawValue)
        else { return }
        let filler = UnsafeMutablePointer<UInt16>.allocate(capacity: TextLayout.maxLineUnits)
        defer { filler.deallocate() }
        filler.initialize(repeating: 0x78, count: TextLayout.maxLineUnits)   // "x"
        for n in 1...TextLayout.maxLineUnits {
            autoreleasepool {
                let s = CFStringCreateWithCharactersNoCopy(nil, filler, n, kCFAllocatorNull)!
                let a = CFAttributedStringCreate(nil, s, attrs)!
                let line = CTLineCreateWithAttributedString(a)
                _ = CTLineGetStringIndexForPosition(line, CGPoint(x: 1e7, y: 0))
                CTLineDraw(line, ctx)
            }
        }
    }
}
