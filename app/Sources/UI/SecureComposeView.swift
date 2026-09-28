// SecureComposeView.swift — one compose field: the subject, the body or an
// address.
//
// Upholds CLAUDE.md §1.2, §1.3, §1.6, §1.10, §2 and §3.2
// (docs/PHASE2_DESIGN.md §6.2, §7.3, §8.5). The text is an EditModel's
// SecretText, edited in place one keystroke at a time and wiped on send,
// cancel and lock. Keys arrive only through `keyDown`: first the input
// filter (BrevApplication has already dropped synthetic input; this is the
// second check), then ComposeKey by key code and flags, and text only from
// KeyTranslator. The event's own text is never read. The view is no text
// input client and has no input context, so dictation, the emoji and
// character pickers, press-and-hold, input methods, autocorrect and inline
// predictions have nothing to deliver text to, and text sent up the
// responder chain (`insertText`) is ignored. Every text input trait is off,
// Writing Tools is .none with no coordinator, and there is no Touch Bar. As
// an OpaqueView it offers nothing to Services, has no menu and is no
// accessibility element. There is no selection, no drag and no pasteboard,
// so nothing can be copied out or pasted in. The caret is a 1 pt bar, placed
// by a click or the keys, and does not blink. Secure event input is on while
// the field has focus in the key window of the active app (SecureInput). A
// dead key waits without a mark; a named key drops it, and Delete removes
// only it. The lines are laid out by TextLayout in the one content font
// (GlyphFlush covers them) and drawn through the protected layer
// (ContentView, D-0034). The view is the document view of an NSScrollView:
// the body wraps at the scroll view's width and grows down, the subject is
// one line that grows sideways, and either scrolls to keep the caret in
// sight. An address field (docs/PHASE3_DESIGN.md §6.2, §6.5) is the same
// view with EditModel's address charset: a typed address is contact data,
// so it is handled like content.

import AppKit

final class SecureComposeView: ContentView, NSTextInputTraits {
    /// Space between the field's edge and its text.
    static let inset = NSSize(width: 6, height: 4)
    /// The body's lines are never broken narrower than this (see
    /// SecureTextView.minTextWidth).
    static let minTextWidth: CGFloat = 200

    /// The field's text and caret.
    let model: EditModel
    /// ⌘↩.
    var onSend: () -> Void = {}
    /// Escape.
    var onCancel: () -> Void = {}
    /// Tab, ⇧Tab, and Return in the subject.
    var onOtherField: () -> Void = {}
    /// Return in a single-line field that is alone on its screen (an
    /// address): when set, Return does this instead of `onOtherField`.
    var onReturn: (() -> Void)?
    /// False while the compose sheet sends a letter it has already sealed:
    /// keys that would change the text do nothing (the caret still moves).
    var isEditable = true

    private let layout = TextLayout(font: ContentView.contentFont)
    private let keys: KeyTranslator
    /// True from becomeFirstResponder until the field loses focus.
    private(set) var hasFocus = false
    /// The width the body's lines were broken for; -1 before the first.
    private var laidOutWidth: CGFloat = -1
    private var focusObservers: [NSObjectProtocol] = []

    /// A field of at most `maxBytes` UTF-8 bytes (Rust's limits()); the
    /// body is `multiline`, the subject and an address are not.
    init(maxBytes: Int, multiline: Bool, charset: EditModel.Charset = .text) {
        model = EditModel(maxBytes: maxBytes, multiline: multiline, charset: charset)
        keys = KeyTranslator(.current)!   // only a named layout can be missing
        super.init(frame: NSRect(x: 0, y: 0, width: 200, height: 24))
        if #available(macOS 15.2, *) { writingToolsCoordinator = nil }
        layOut()
    }

    required init?(coder: NSCoder) {
        nil
    }

    deinit {
        focusObservers.forEach { NotificationCenter.default.removeObserver($0) }
    }

    // MARK: - Text input traits: every text service off

    var autocorrectionType: NSTextInputTraitType { get { .no } set {} }
    var spellCheckingType: NSTextInputTraitType { get { .no } set {} }
    var grammarCheckingType: NSTextInputTraitType { get { .no } set {} }
    var smartQuotesType: NSTextInputTraitType { get { .no } set {} }
    var smartDashesType: NSTextInputTraitType { get { .no } set {} }
    var smartInsertDeleteType: NSTextInputTraitType { get { .no } set {} }
    var textReplacementType: NSTextInputTraitType { get { .no } set {} }
    var dataDetectionType: NSTextInputTraitType { get { .no } set {} }
    var linkDetectionType: NSTextInputTraitType { get { .no } set {} }
    var textCompletionType: NSTextInputTraitType { get { .no } set {} }
    var inlinePredictionType: NSTextInputTraitType { get { .no } set {} }
    @available(macOS 15.0, *)
    var mathExpressionCompletionType: NSTextInputTraitType { get { .no } set {} }
    @available(macOS 15.0, *)
    var writingToolsBehavior: NSWritingToolsBehavior { get { .none } set {} }
    @available(macOS 15.0, *)
    var allowedWritingToolsResultOptions: NSWritingToolsResultOptions { get { [] } set {} }

    // MARK: - No way in but keyDown

    override var inputContext: NSTextInputContext? { nil }

    /// Text from the responder chain never reaches the field.
    override func insertText(_ insertString: Any) {}

    /// ⌘ keys are never handled as key equivalents here: the menu gets
    /// ⌘L, ⌘Q and ⌘N, and keyDown the rest (ComposeKey).
    override func performKeyEquivalent(with event: NSEvent) -> Bool { false }

    override func makeTouchBar() -> NSTouchBar? { nil }

    // MARK: - Focus and secure event input

    override var acceptsFirstResponder: Bool { true }

    override func becomeFirstResponder() -> Bool {
        hasFocus = true
        focusChanged()
        return true
    }

    override func resignFirstResponder() -> Bool {
        loseFocus()
        return true
    }

    override func viewWillMove(toWindow newWindow: NSWindow?) {
        super.viewWillMove(toWindow: newWindow)
        if newWindow == nil { loseFocus() }
    }

    /// The window's key state and Brev's active state decide secure event
    /// input while the field has focus.
    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        focusObservers.forEach { NotificationCenter.default.removeObserver($0) }
        focusObservers = []
        guard let window else { return }
        let center = NotificationCenter.default
        let names: [(Notification.Name, AnyObject?)] = [
            (NSWindow.didBecomeKeyNotification, window), (NSWindow.didResignKeyNotification, window),
            (NSApplication.didBecomeActiveNotification, nil), (NSApplication.didResignActiveNotification, nil),
        ]
        for (name, object) in names {
            focusObservers.append(center.addObserver(forName: name, object: object, queue: .main) { [weak self] _ in
                self?.focusChanged()
            })
        }
    }

    /// Secure event input on exactly while this field has focus in the key
    /// window of the active app.
    private func focusChanged() {
        needsDisplay = true
        guard hasFocus else { return }
        if window?.isKeyWindow == true && NSApp.isActive {
            SecureInput.enable()
        } else {
            SecureInput.disable()
        }
    }

    private func loseFocus() {
        guard hasFocus else { return }
        hasFocus = false
        keys.reset()
        SecureInput.disable()
        needsDisplay = true
    }

    // MARK: - Keys

    override func keyDown(with event: NSEvent) {
        guard !InputFilter.isSynthetic(event), let flags = event.cgEvent?.flags else { return }
        let key = ComposeKey.of(keyCode: event.keyCode, flags: flags)
        if key == .text {
            if isEditable { type(keyCode: event.keyCode, flags: flags, isRepeat: event.isARepeat) }
            return
        }
        // Any other key drops a waiting dead key; Delete drops only that.
        let waiting = keys.hasDeadKey
        keys.reset()
        if waiting && key == .deleteBackward { return }
        if !isEditable && (key == .deleteBackward || key == .deleteForward || (key == .newline && model.multiline)) {
            return
        }
        switch key {
        case .send: onSend()
        case .cancel: onCancel()
        case .otherField: onOtherField()
        case .newline:
            guard model.multiline else { return (onReturn ?? onOtherField)() }
            if model.insertNewline() { edited() } else { NSSound.beep() }
        case .deleteBackward: if model.deleteBackward() { edited() }
        case .deleteForward: if model.deleteForward() { edited() }
        case .left: move(model.moveLeft)
        case .right: move(model.moveRight)
        case .up: move { model.moveUp(in: layout) }
        case .down: move { model.moveDown(in: layout) }
        case .lineStart: move { model.moveToLineStart(in: layout) }
        case .lineEnd: move { model.moveToLineEnd(in: layout) }
        case .documentStart: move(model.moveToStart)
        case .documentEnd: move(model.moveToEnd)
        case .text, .ignore: break
        }
    }

    /// One key's text at the caret. Home, End, the page keys and the
    /// function keys give control characters: nothing, and no beep. An
    /// insert past the field's limit beeps.
    private func type(keyCode: UInt16, flags: CGEventFlags, isRepeat: Bool) {
        var inserted = false, refused = false
        keys.translate(keyCode: keyCode, flags: flags, isRepeat: isRepeat) { u in
            guard !u.isEmpty, !u.contains(where: { $0 < 0x20 || $0 == 0x7F }) else { return }
            if model.insert(u) { inserted = true } else { refused = true }
        }
        if refused { NSSound.beep() }
        if inserted { edited() }
    }

    // MARK: - Mouse: the caret only

    override func mouseDown(with event: NSEvent) {
        guard !InputFilter.isSynthetic(event) else { return }
        window?.makeFirstResponder(self)
        let p = convert(event.locationInWindow, from: nil)
        let line = Int(((p.y - Self.inset.height) / layout.lineHeight).rounded(.down))
        model.place(line: line, x: p.x - Self.inset.width, in: layout)
        caretMoved()
    }

    /// No selection, so a drag does nothing.
    override func mouseDragged(with event: NSEvent) {}

    // MARK: - Wipe

    /// Send, cancel and lock: wipes the text, forgets its lines, drops a
    /// waiting dead key and zeroes the pixels.
    func wipe() {
        model.wipe()
        keys.reset()
        layout.reset()
        blank()
        layOut()
    }

    // MARK: - Layout

    override func resize(withOldSuperviewSize oldSize: NSSize) {
        fitSize()
    }

    private func edited() {
        layOut()
        caretMoved()
    }

    private func move(_ body: () -> Void) {
        body()
        caretMoved()
    }

    private func caretMoved() {
        needsDisplay = true
        scrollToVisible(caretRect().insetBy(dx: -Self.inset.width, dy: -Self.inset.height))
    }

    /// Breaks the lines again (the body at the scroll view's width, the
    /// subject as one line) and sizes the view to them.
    private func layOut() {
        let width = superview?.bounds.width ?? bounds.width
        // The subject (at most 256 units) fits one window of 448, so the
        // width that never breaks it is simply far wider than any line.
        layout.layout(model.text, width: model.multiline ? max(width - 2 * Self.inset.width, Self.minTextWidth) : 1e7)
        laidOutWidth = width
        fitSize()
        needsDisplay = true
    }

    /// The body: the scroll view's width, and the lines' height, at least
    /// the scroll view's. The subject: its line's width, at least the
    /// scroll view's, and the scroll view's height.
    private func fitSize() {
        let visible = superview?.bounds.size ?? bounds.size
        if model.multiline && visible.width != laidOutWidth { return layOut() }
        let line = model.multiline ? 0 : layout.caretOffset(model.text, line: 0, index: model.text.length)
        let size = model.multiline
            ? NSSize(width: visible.width, height: max(visible.height, layout.height + 2 * Self.inset.height))
            : NSSize(width: max(visible.width, ceil(line) + 2 * Self.inset.width + 1), height: visible.height)
        if size != frame.size { setFrameSize(size) }
    }

    /// The caret's bar, in this view's flipped coordinates.
    func caretRect() -> NSRect {
        let i = model.caretLine(in: layout)
        let x = Self.inset.width + layout.caretOffset(model.text, line: i, index: model.caret)
        return NSRect(x: floor(x), y: Self.inset.height + CGFloat(i) * layout.lineHeight, width: 1,
                      height: layout.lineHeight)
    }

    // MARK: - Drawing

    override func drawContent(in ctx: CGContext, rect: CGRect) {
        let h = layout.lineHeight, top = Self.inset.height
        let first = max(Int(((rect.minY - top) / h).rounded(.down)), 0)
        let last = min(Int(((rect.maxY - top) / h).rounded(.up)), layout.lines.count)
        ctx.saveGState()
        if first < last {
            ctx.setFillColor(color(.textColor))
            layout.draw(model.text, lines: first..<last, in: ctx, x: Self.inset.width, top: top)
        }
        if hasFocus && window?.isKeyWindow == true {
            ctx.setFillColor(color(.textInsertionPointColor))
            ctx.fill(caretRect())
        }
        ctx.restoreGState()
    }
}
