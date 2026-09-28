// OpaqueView.swift — the base of every view that can show content.
//
// Upholds CLAUDE.md §1.2, §1.3 and §1.4 (docs/PHASE2_DESIGN.md §7.1): an
// OpaqueView is not an accessibility element and answers every text
// attribute with nothing, so the AX tree never reaches a name, a subject or
// a body. It has no context menu, offers nothing to Services, and ignores
// Look Up (quickLook). It is no drag source and registers no drag type. The
// input spike (U3, macOS 26.2; D-0060 in the shifted numbering) found that
// a plain NSView already exposes nothing and an NSScrollView around one
// shows only an empty AXScrollArea; the full set is kept as defence in
// depth, and the design's fallback of one opaque container is not needed.
//
// ContentView is where content becomes pixels. Its subclasses draw only in
// `drawContent(in:rect:)`, with Core Graphics and Core Text into the context
// they are given, never through AppKit's current context. `draw(_:)` renders
// that into a bitmap of its own and gives AppKit only the image. On macOS
// 26.2 AppKit records `draw(_:)` into a Core Graphics display list, which
// copies the glyph ids of every line drawn into it and keeps them while the
// view shows them, and after a lock until the run-loop turn ends (measured
// with tools/viewhost: 3 subject lines left after the lock sequence). Drawn
// into a bitmap, a line's glyphs exist only while Core Text draws it
// (CLAUDE.md §2; docs/PHASE2_DESIGN.md §6.4; D-0047 in the shifted
// numbering). The protected content layer (WP11; CLAUDE.md §3.2,
// docs/DECISIONS.md D-0034) takes the same bitmap into a pixel buffer behind
// an AVSampleBufferDisplayLayer, and only this class changes. No tooltips,
// popovers or other AppKit-made windows over content (capture spike).

import AppKit

class OpaqueView: NSView {
    override var isFlipped: Bool { true }

    // MARK: Accessibility: nothing

    override func isAccessibilityElement() -> Bool { false }
    override func accessibilityChildren() -> [Any]? { [] }
    override func accessibilityRole() -> NSAccessibility.Role? { nil }
    override func accessibilityRoleDescription() -> String? { nil }
    override func accessibilityValue() -> Any? { nil }
    override func accessibilityLabel() -> String? { nil }
    override func accessibilityTitle() -> String? { nil }
    override func accessibilityHelp() -> String? { nil }
    override func accessibilitySelectedText() -> String? { nil }
    override func accessibilityNumberOfCharacters() -> Int { 0 }
    override func accessibilityString(for range: NSRange) -> String? { nil }
    override func accessibilityAttributedString(for range: NSRange) -> NSAttributedString? { nil }
    override func accessibilityHitTest(_ point: NSPoint) -> Any? { nil }

    // MARK: No menu, no Services, no Look Up

    override func menu(for event: NSEvent) -> NSMenu? { nil }
    override func validRequestor(forSendType sendType: NSPasteboard.PasteboardType?,
                                 returnType: NSPasteboard.PasteboardType?) -> Any? { nil }
    override func quickLook(with event: NSEvent) {}
}

class ContentView: OpaqueView {
    /// The one content font (docs/PHASE2_DESIGN.md §6.4): every TextLayout
    /// that draws content uses it, so GlyphFlush's sweep covers them all.
    static let contentFont = NSFont.systemFont(ofSize: 13) as CTFont
    /// Metadata (dates) and nothing else.
    static let metaFont = NSFont.systemFont(ofSize: 11) as CTFont

    /// Renders `dirtyRect` with `drawContent` into a bitmap at the window's
    /// scale and draws that image. AppKit never sees a glyph.
    override func draw(_ dirtyRect: NSRect) {
        guard let ctx = NSGraphicsContext.current?.cgContext, let image = render(dirtyRect.integral) else { return }
        let r = dirtyRect.integral
        ctx.saveGState()
        ctx.interpolationQuality = .none
        // The view is flipped; the image's first row is its top.
        ctx.translateBy(x: 0, y: r.minY + r.maxY)
        ctx.scaleBy(x: 1, y: -1)
        ctx.draw(image, in: r)
        ctx.restoreGState()
    }

    /// `rect` (in this view's coordinates) drawn by `drawContent` into a new
    /// bitmap of the window's scale; nil for an empty rect.
    func render(_ rect: CGRect) -> CGImage? {
        let scale = window?.backingScaleFactor ?? 2
        let w = Int((rect.width * scale).rounded(.up)), h = Int((rect.height * scale).rounded(.up))
        guard w > 0, h > 0, let space = CGColorSpace(name: CGColorSpace.sRGB),
              let bitmap = CGContext(data: nil, width: w, height: h, bitsPerComponent: 8, bytesPerRow: 0, space: space,
                                     bitmapInfo: CGImageAlphaInfo.premultipliedFirst.rawValue
                                         | CGBitmapInfo.byteOrder32Little.rawValue)
        else { return nil }
        // View coordinates (y down, from rect's corner) onto the bitmap.
        bitmap.scaleBy(x: scale, y: -scale)
        bitmap.translateBy(x: -rect.minX, y: -rect.maxY)
        drawContent(in: bitmap, rect: rect)
        return bitmap.makeImage()
    }

    /// Draws what lies inside `rect` (in this view's flipped coordinates)
    /// into `ctx`, whose transform already maps those coordinates. Only
    /// Core Graphics and Core Text, with colours from `color(_:)`.
    func drawContent(in ctx: CGContext, rect: CGRect) {}

    /// `color` as this view's appearance shows it, whoever hosts the drawing.
    func color(_ color: NSColor) -> CGColor {
        var resolved = color.cgColor
        effectiveAppearance.performAsCurrentDrawingAppearance { resolved = color.cgColor }
        return resolved
    }

    /// One line of metadata (never content) with its baseline at `baseline`.
    func drawMeta(_ text: String, in ctx: CGContext, x: CGFloat, baseline: CGFloat, color: CGColor) {
        let attrs = [kCTFontAttributeName: Self.metaFont, kCTForegroundColorAttributeName: color] as CFDictionary
        guard let a = CFAttributedStringCreate(nil, text as CFString, attrs) else { return }
        ctx.textMatrix = CGAffineTransform(scaleX: 1, y: -1)
        ctx.textPosition = CGPoint(x: x, y: baseline)
        CTLineDraw(CTLineCreateWithAttributedString(a), ctx)
    }

    /// The width of `text` in the metadata font.
    static func metaWidth(_ text: String) -> CGFloat {
        let attrs = [kCTFontAttributeName: metaFont] as CFDictionary
        guard let a = CFAttributedStringCreate(nil, text as CFString, attrs) else { return 0 }
        return CGFloat(CTLineGetTypographicBounds(CTLineCreateWithAttributedString(a), nil, nil, nil))
    }
}
