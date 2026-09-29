// SelfScan.swift — Verify configuration only: Brev counts copies of the test
// marker in its own memory at each lock.
//
// Serves docs/VERIFY.md V39 (docs/PHASE2_DESIGN.md §4.1, §8.4 step 9).
// project.yml compiles this file and app/Tests/scan.c only in the Verify
// configuration (EXCLUDED_SOURCE_FILE_NAMES in Debug and Release), and only
// Verify defines BREV_SELFSCAN, under which LockController calls it: once
// when a lock starts, while a letter may still be open (the control), and
// once when the lock sequence has finished. tools/viewhost compiles it the
// same way. It logs counts only. The marker is "BREV-SECRET-BODY", as in
// scan.c; its glyph ids in the letter body's font (ContentView.fontF4, the
// font of every letter body) are the scanner's glyph needle,
// stored XORed, as in harness case 4. A shown letter leaves no live glyph
// ids (ContentView draws each line into its pixel buffers, and Core Text
// frees a line's glyphs once it is drawn), so the control also holds a
// CTLine of the marker and counts its glyphs (`needle`): proof that the
// needle is set and seen in this process. After the lock, `glyph` shows that
// GlyphFlush cleared that line (and a long letter's lines); a short letter
// leaves no glyph ids even without scribbling, because libmalloc zeroes
// small freed blocks itself. So the end of the lock also runs the scribble
// probe (scan.c), which does not depend on Core Text: a freed 32 KiB block
// must keep no copy of its pattern (`scribble=0`), and is seen while
// allocated (`probe`, the positive control). This is the check that
// MallocScribble takes effect in this process, not only that it is set.
// Since the UI redesign subjects and names are drawn in SF (F1–F3) and
// bodies in New York (F4), so `glyph` sums one scan per content font laid
// out so far (the marker's glyph ids differ per font; the SF weights may
// share ids, so one run can count once per weight: the pass mark is 0). A font not yet laid
// out has no needle: the line says how many fonts were scanned
// (`fonts=`), and a notice says when none was, so a skipped glyph check is
// never silent.

import CoreText
import os

enum SelfScan {
    private static let log = Logger(subsystem: "no.brev.app", category: "selfscan")
    /// "BREV-SECRET-BODY" XOR 0x5A, as in scan.c.
    private static let markerX: [UInt8] = [0x18, 0x08, 0x1f, 0x0c, 0x77, 0x09, 0x1f, 0x19,
                                           0x08, 0x1f, 0x0e, 0x77, 0x18, 0x15, 0x1e, 0x03]

    /// Logs `selfscan control u8=… u16=… glyph=… needle=…` at the start of a
    /// lock, and `selfscan u8=… u16=… glyph=… scribble=… probe=…` at its end.
    static func run(control: Bool) {
        let h = scan()
        let fonts = needleFonts.count
        if fonts == 0 { log.notice("selfscan glyph check skipped: no content font laid out yet") }
        if control {
            let needle = needleControl()
            log.notice("selfscan control u8=\(h.u8, privacy: .public) u16=\(h.u16, privacy: .public) glyph=\(h.glyph, privacy: .public) fonts=\(fonts, privacy: .public) needle=\(needle, privacy: .public)")
        } else {
            let p = scribbleProbe()
            log.notice("selfscan u8=\(h.u8, privacy: .public) u16=\(h.u16, privacy: .public) glyph=\(h.glyph, privacy: .public) fonts=\(fonts, privacy: .public) scribble=\(p.left, privacy: .public) probe=\(p.live, privacy: .public)")
        }
    }

    /// The scribble probe (scan.c): the probe pattern's copies while its
    /// 32 KiB block is allocated (`live`, > 0) and after it is freed
    /// (`left`, 0 while MallocScribble takes effect).
    static func scribbleProbe() -> (live: UInt64, left: UInt64) {
        var live: UInt64 = 0
        let left = brev_scan_scribble_probe(&live)
        return (live, left)
    }

    /// The marker's copies in this process: as UTF-8, as UTF-16 and as glyph
    /// ids, summed over the content fonts laid out so far (0 before any).
    static func scan() -> (u8: UInt64, u16: UInt64, glyph: UInt64) {
        var r = brev_scan_result()
        let fonts = needleFonts
        guard !fonts.isEmpty else {
            brev_scan(&r)
            return (r.utf8_hits, r.utf16_hits, 0)
        }
        var glyph: UInt64 = 0
        for attrs in fonts {
            setGlyphNeedle(attrs)
            brev_scan(&r)
            glyph += r.glyph_hits
        }
        return (r.utf8_hits, r.utf16_hits, glyph)
    }

    /// The content fonts' attributes, as TextLayout makes them, for each one
    /// laid out so far (GlyphFlush has seen it): the body's (F4) first, then
    /// the subjects' and names' (F1–F3).
    private static var needleFonts: [CFDictionary] {
        [ContentView.fontF4, ContentView.fontF1, ContentView.fontF2, ContentView.fontF3].compactMap { font in
            GlyphFlush.fonts.first { CFEqual($0.font, font) }?.attrs
        }
    }

    /// The body font's attributes, else the first content font laid out.
    private static var attrs: CFDictionary? {
        needleFonts.first
    }

    /// The glyph count while a CTLine of the marker in the body font is
    /// alive: the glyph needle's positive control. Made as TextLayout makes a
    /// line, from a buffer wiped afterwards; the lock sequence's GlyphFlush
    /// and scribbling clear it like any other line. 0 before a body was laid
    /// out.
    static func needleControl() -> UInt64 {
        guard let attrs else { return 0 }
        setGlyphNeedle(attrs)
        var chars = [UInt16](repeating: 0, count: 16)
        for i in 0..<16 { chars[i] = UInt16(markerX[i] ^ 0x5A) }
        var r = brev_scan_result()
        chars.withUnsafeBufferPointer { p in
            autoreleasepool {
                let s = CFStringCreateWithCharactersNoCopy(nil, p.baseAddress, 16, kCFAllocatorNull)!
                let line = CTLineCreateWithAttributedString(CFAttributedStringCreate(nil, s, attrs)!)
                brev_scan(&r)
                withExtendedLifetime(line) {}
            }
        }
        _ = chars.withUnsafeMutableBytes { memset_s($0.baseAddress!, 32, 0, 32) }
        return r.glyph_hits
    }

    /// The marker's 16 glyph ids in the font of `attrs`, XORed, as the
    /// scanner's needle.
    private static func setGlyphNeedle(_ attrs: CFDictionary) {
        guard let value = CFDictionaryGetValue(attrs, Unmanaged.passUnretained(kCTFontAttributeName).toOpaque())
        else { return }
        let font = Unmanaged<CTFont>.fromOpaque(value).takeUnretainedValue()
        var chars = [UInt16](repeating: 0, count: 16), glyphs = [CGGlyph](repeating: 0, count: 16)
        for i in 0..<16 { chars[i] = UInt16(markerX[i] ^ 0x5A) }
        _ = CTFontGetGlyphsForCharacters(font, chars, &glyphs, 16)
        var x = glyphs.map { $0 ^ 0x5A5A }
        brev_scan_set_glyphs(x, 16)
        _ = chars.withUnsafeMutableBytes { memset_s($0.baseAddress!, 32, 0, 32) }
        _ = glyphs.withUnsafeMutableBytes { memset_s($0.baseAddress!, 32, 0, 32) }
        _ = x.withUnsafeMutableBytes { memset_s($0.baseAddress!, 32, 0, 32) }
    }
}
