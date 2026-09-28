// OpaqueView.swift — the base of every view that can show content.
//
// Upholds CLAUDE.md §1.2, §1.3 and §1.4 (docs/PHASE2_DESIGN.md §7.1): an
// OpaqueView is not an accessibility element and answers every text
// attribute with nothing, so the AX tree never reaches a name, a subject or
// a body. It has no context menu, offers nothing to Services, and ignores
// Look Up (quickLook). It is no drag source and registers no drag type. The
// input spike (U3, macOS 26.2; docs/DECISIONS.md D-0052) found that
// a plain NSView already exposes nothing and an NSScrollView around one
// shows only an empty AXScrollArea; the full set is kept as defence in
// depth, and the design's fallback of one opaque container is not needed.
//
// ContentView is where content becomes pixels, and the only place
// (CLAUDE.md §3.2; docs/DECISIONS.md D-0034). Its subclasses draw only in
// `drawContent(in:rect:)`, with Core Graphics and Core Text into the context
// they are given, never through AppKit's current context. That context is
// one buffer of a fixed pool of IOSurface-backed CVPixelBuffers, shown
// through an AVSampleBufferDisplayLayer with `preventsCapture = true`.
// AppKit's own drawing of the view (`draw(_:)`, which print and PDF output
// call; cacheDisplay renders the layer tree instead) draws nothing, which
// the lock probe (app/Tests/Lock) checks. On macOS 26.2
// `sharingType = .none` keeps a window out of ScreenCaptureKit and
// screencapture, but not out of CGDisplayStream or AVCaptureScreenInput; the
// protected layer is missing from all four (capture spike, re-run at Brev's
// window level 0 in WP11; D-0052). Drawing into a
// bitmap also keeps glyph ids out of AppKit's display list, which kept them
// until after a lock (WP7, tools/viewhost; D-0045),
// so a shown letter leaves no live glyph ids, and V39's glyph control is
// SelfScan's own line of the marker (docs/VERIFY.md, "Changes from the
// design"). Only the visible part of a view is drawn: again on every scroll,
// resize and content change, into the pool's next buffer. Only a view in
// sight holds a pool. The buffers are zeroed in place when the view's text
// is wiped (`blank()`), when it scrolls out of sight or leaves its window
// (`release()`, which also gives the pool up), when it is freed, and for
// every view in the lock sequence (`ContentView.blankAll()`), which also
// shows a blank frame (§2 accepts pixels in these buffers until then).
// Between `hideAll()` and `showAll()` (a Touch ID prompt that takes
// activation, docs/PHASE3_DESIGN.md §3.2) every view shows a blank frame.
// AVFoundation, CoreMedia and CoreVideo are approved for this layer only
// (§4); scripts/test.sh fails if another file in app/Sources names one of
// their symbols. No tooltips, popovers or other AppKit-made windows over
// content (capture spike).

import AppKit
import AVFoundation
import CoreMedia
import CoreVideo

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

    /// Buffers per view: one shown, one queued, one being drawn.
    private static let poolSize = 3
    /// Buffer sides are rounded up to this many pixels, so a live resize
    /// makes a new pool only every few steps.
    private static let granule = 256
    /// Every content view alive, for the lock sequence.
    private static let live = NSHashTable<ContentView>.weakObjects()

    /// Lock sequence (docs/PHASE2_DESIGN.md §8.4; D-0034): every content
    /// view zeroes its pixel buffers in place and shows a blank frame.
    static func blankAll() {
        live.allObjects.forEach { $0.blank() }
    }

    /// True between `hideAll` and `showAll`: every content view, also one
    /// made meanwhile, shows a blank frame instead of drawing.
    private(set) static var hidden = false

    /// Blanks every content view until `showAll`: for a Touch ID prompt
    /// that takes activation from Brev (docs/PHASE3_DESIGN.md §3.2; the U4
    /// switch in LockState). The texts stay; only the pixels go.
    static func hideAll() {
        hidden = true
        blankAll()
    }

    /// Ends `hideAll`: every content view draws again.
    static func showAll() {
        guard hidden else { return }
        hidden = false
        live.allObjects.forEach { $0.needsDisplay = true }
    }

    /// Shows this view's pixels, and keeps them out of screen captures.
    let protectedLayer = AVSampleBufferDisplayLayer()
    /// The fixed pool, all buffers of one size; empty while the view is out
    /// of sight.
    private(set) var pool: [CVPixelBuffer] = []
    private var nextIndex = 0
    /// Whether the layer may show a frame that `blank()` has not zeroed.
    private var showing = false
    /// The enclosing clip view's scroll and resize notifications.
    private var observers: [NSObjectProtocol] = []

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        protectedLayer.preventsCapture = true
        protectedLayer.videoGravity = .resize
        wantsLayer = true
        layerContentsRedrawPolicy = .onSetNeedsDisplay
        Self.live.add(self)
    }

    required init?(coder: NSCoder) {
        nil
    }

    deinit {
        observers.forEach { NotificationCenter.default.removeObserver($0) }
        pool.forEach(Self.zero)
    }

    override func makeBackingLayer() -> CALayer {
        let layer = super.makeBackingLayer()
        layer.masksToBounds = true
        layer.addSublayer(protectedLayer)
        return layer
    }

    // MARK: When to draw

    override var wantsUpdateLayer: Bool { true }

    /// AppKit's drawing of this view (print and PDF output; cacheDisplay
    /// and the window's display pass use the layer) gets no pixels of
    /// content.
    override func draw(_ dirtyRect: NSRect) {}

    override func updateLayer() {
        guard !Self.hidden else { return blank() }
        present()
    }

    /// Scrolling or resizing the enclosing scroll view changes what is
    /// visible, so it draws again. Leaving the window releases the pool.
    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        observers.forEach { NotificationCenter.default.removeObserver($0) }
        observers = []
        guard window != nil else { return release() }
        if let clip = enclosingScrollView?.contentView {
            for name in [NSView.boundsDidChangeNotification, NSView.frameDidChangeNotification] {
                observers.append(NotificationCenter.default.addObserver(forName: name, object: clip, queue: nil) {
                    [weak self] _ in self?.needsDisplay = true
                })
            }
        }
        needsDisplay = true
    }

    override func setFrameSize(_ newSize: NSSize) {
        super.setFrameSize(newSize)
        needsDisplay = true
    }

    override func setFrameOrigin(_ newOrigin: NSPoint) {
        super.setFrameOrigin(newOrigin)
        needsDisplay = true
    }

    override func viewDidChangeBackingProperties() {
        super.viewDidChangeBackingProperties()
        needsDisplay = true
    }

    override func viewDidChangeEffectiveAppearance() {
        super.viewDidChangeEffectiveAppearance()
        needsDisplay = true
    }

    // MARK: The protected layer

    /// Draws the visible part of the view with `drawContent` into the
    /// pool's next buffer, at the window's scale, and shows it. A view out
    /// of sight releases its pool.
    private func present() {
        // visibleRect is not clipped to the view's own bounds (views do not
        // clip to them since macOS 14): a letter below the pane's visible
        // part would get the whole pane.
        let visible = visibleRect.intersection(bounds)
        guard let window, visible.width >= 1, visible.height >= 1 else { return release() }
        let scale = window.backingScaleFactor
        // The pool fits the most the view can show at once: its bounds, at
        // most the enclosing clip view. So it keeps its size while the view
        // scrolls, and only a resize makes a new one.
        let most = enclosingScrollView?.contentView.bounds.size ?? bounds.size
        guard let buffer = nextBuffer(width: Int((min(bounds.width, most.width) * scale).rounded(.up)),
                                      height: Int((min(bounds.height, most.height) * scale).rounded(.up))),
              CVPixelBufferLockBaseAddress(buffer, []) == kCVReturnSuccess
        else { return }
        let width = CVPixelBufferGetWidth(buffer), height = CVPixelBufferGetHeight(buffer)
        guard let base = CVPixelBufferGetBaseAddress(buffer), let space = CGColorSpace(name: CGColorSpace.sRGB),
              let ctx = CGContext(data: base, width: width, height: height, bitsPerComponent: 8,
                                  bytesPerRow: CVPixelBufferGetBytesPerRow(buffer), space: space,
                                  bitmapInfo: CGImageAlphaInfo.premultipliedFirst.rawValue
                                      | CGBitmapInfo.byteOrder32Little.rawValue)
        else {
            CVPixelBufferUnlockBaseAddress(buffer, [])
            return
        }
        ctx.clear(CGRect(x: 0, y: 0, width: width, height: height))
        // View coordinates (y down, from the visible rect's corner) onto the
        // buffer, whose first row is its top.
        ctx.translateBy(x: 0, y: CGFloat(height))
        ctx.scaleBy(x: scale, y: -scale)
        ctx.translateBy(x: -visible.minX, y: -visible.minY)
        ctx.clip(to: visible)
        drawContent(in: ctx, rect: visible)
        CVPixelBufferUnlockBaseAddress(buffer, [])
        CATransaction.begin()
        CATransaction.setDisableActions(true)
        protectedLayer.frame = CGRect(x: visible.minX, y: visible.minY,
                                      width: CGFloat(width) / scale, height: CGFloat(height) / scale)
        show(buffer)
        CATransaction.commit()
        showing = true
    }

    /// Zeroes every buffer of the pool in place, removes the shown frame and
    /// shows a blank one. For a wiped text and every view in the lock
    /// sequence.
    func blank() {
        pool.forEach(Self.zero)
        protectedLayer.sampleBufferRenderer.flush(removingDisplayedImage: true, completionHandler: nil)
        if let empty = pool.first { show(empty) }
        showing = false
    }

    /// Zeroes every buffer of the pool in place, removes the shown frame and
    /// gives the pool up, for a view that scrolled out of sight or left its
    /// window. So only views in sight hold buffers, however many letters a
    /// thread has; the next frame makes a new pool.
    private func release() {
        guard !pool.isEmpty || showing else { return }
        pool.forEach(Self.zero)
        protectedLayer.sampleBufferRenderer.flush(removingDisplayedImage: true, completionHandler: nil)
        pool = []
        nextIndex = 0
        showing = false
    }

    /// The pool's next buffer for a frame of at least `width` x `height`
    /// pixels. A new size makes a new pool; the old one is zeroed first.
    private func nextBuffer(width: Int, height: Int) -> CVPixelBuffer? {
        let w = Self.roundUp(width), h = Self.roundUp(height)
        if pool.first.map({ CVPixelBufferGetWidth($0) != w || CVPixelBufferGetHeight($0) != h }) ?? true {
            pool.forEach(Self.zero)
            pool = (0..<Self.poolSize).compactMap { _ in Self.makeBuffer(width: w, height: h) }
            nextIndex = 0
            guard pool.count == Self.poolSize else {
                pool = []
                return nil
            }
        }
        defer { nextIndex = (nextIndex + 1) % pool.count }
        return pool[nextIndex]
    }

    /// Replaces the layer's frame with `buffer` at once.
    private func show(_ buffer: CVPixelBuffer) {
        var format: CMVideoFormatDescription?
        var timing = CMSampleTimingInfo(duration: .invalid, presentationTimeStamp: .zero, decodeTimeStamp: .invalid)
        var sample: CMSampleBuffer?
        guard CMVideoFormatDescriptionCreateForImageBuffer(allocator: nil, imageBuffer: buffer,
                                                           formatDescriptionOut: &format) == noErr,
              let format,
              CMSampleBufferCreateReadyWithImageBuffer(allocator: nil, imageBuffer: buffer, formatDescription: format,
                                                       sampleTiming: &timing, sampleBufferOut: &sample) == noErr,
              let sample
        else { return }
        if let attachments = CMSampleBufferGetSampleAttachmentsArray(sample, createIfNecessary: true)
            as? [NSMutableDictionary] {
            attachments.first?[kCMSampleAttachmentKey_DisplayImmediately] = true
        }
        let renderer = protectedLayer.sampleBufferRenderer
        renderer.flush()
        renderer.enqueue(sample)
    }

    private static func roundUp(_ n: Int) -> Int {
        (n + granule - 1) / granule * granule
    }

    /// An IOSurface-backed BGRA buffer that a CGContext can draw into.
    private static func makeBuffer(width: Int, height: Int) -> CVPixelBuffer? {
        let attrs = [kCVPixelBufferIOSurfacePropertiesKey: [:] as CFDictionary,
                     kCVPixelBufferCGBitmapContextCompatibilityKey: true] as CFDictionary
        var buffer: CVPixelBuffer?
        guard CVPixelBufferCreate(nil, width, height, kCVPixelFormatType_32BGRA, attrs, &buffer) == kCVReturnSuccess,
              let buffer, let space = CGColorSpace(name: CGColorSpace.sRGB)
        else { return nil }
        CVBufferSetAttachment(buffer, kCVImageBufferCGColorSpaceKey, space, .shouldPropagate)
        return buffer
    }

    /// Every pixel row of `buffer` set to 0, in place.
    private static func zero(_ buffer: CVPixelBuffer) {
        guard CVPixelBufferLockBaseAddress(buffer, []) == kCVReturnSuccess else { return }
        if let base = CVPixelBufferGetBaseAddress(buffer) {
            let n = CVPixelBufferGetBytesPerRow(buffer) * CVPixelBufferGetHeight(buffer)
            memset_s(base, n, 0, n)
        }
        CVPixelBufferUnlockBaseAddress(buffer, [])
    }

    // MARK: Drawing, for subclasses

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
}
