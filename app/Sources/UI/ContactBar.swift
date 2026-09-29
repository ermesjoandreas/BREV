// ContactBar.swift — the selected contact or request, over the message list.
//
// Upholds CLAUDE.md §1.2, §1.5, §1.10 and §3.2 (docs/PHASE3_DESIGN.md §6.3,
// §6.4, §6.5; docs/PHASE4_DESIGN.md §5.2, §6.1; docs/UI_REDESIGN.md §2.4).
// Addresses and identity codes are contact data, so they are drawn only by
// ContactTextViews: ContentViews, which draw through the capture-protected
// layer and are no accessibility element. Around them stand fixed labels
// from Localizable.strings (InterfaceText) and HumanButtons. For a contact:
// its address (semibold) with Blokker at the end (hidden once blocked,
// unless telling the relay failed, when net.error shows below and a press
// tells it again), its state (contact.blocked, else contact.waiting, else
// contact.verified, else nothing), «Sikkerhetskode» over its pinned code.
// While the contact's key has changed, a block below, on a faint orange
// fill with an orange bar at its edge, shows contact.changed, «Ny kode:»
// beside the new code (protected too) and Godta ny kode, and accept.error
// after a failed accept. For a contact request: the asker's address and
// code, then request.body with Godta and Avslå (one click each, no
// confirm), and net.error after a failed answer. The bar owns every text it
// draws: the addresses it is given, and a UTF-16 copy of each code, made
// from the code's SecretBytes, which it wipes, except the new code's, which
// it keeps as `newCode` for acceptNewKey: the code accepted is exactly the
// code shown. A new selection and `clear()` (the lock sequence) wipe all of
// it and zero the pixels. Its texts wrap at the column's width. No string
// here takes an address or a code. (The own address and code are on the
// Kontakter sheet since the redesign.)

import AppKit

/// Lines of contact data, one per row, in the protected layer: the first
/// line of each SecretText, clipped at the view's edge, in one content
/// font (F1 by default). Also the reading header's subject and name.
final class ContactTextView: ContentView {
    /// A row's height for 13 pt text.
    static let rowHeight: CGFloat = 20

    let rowHeight: CGFloat
    private let layout: TextLayout
    private(set) var lines: [SecretText?]

    init(rows: Int, font: CTFont = ContentView.fontF1) {
        layout = TextLayout(font: font)
        rowHeight = max(Self.rowHeight, ceil(CTFontGetAscent(font) + CTFontGetDescent(font)) + 4)
        lines = Array(repeating: nil, count: rows)
        super.init(frame: NSRect(x: 0, y: 0, width: 200, height: CGFloat(rows) * rowHeight))
    }

    required init?(coder: NSCoder) {
        nil
    }

    override var intrinsicContentSize: NSSize {
        NSSize(width: NSView.noIntrinsicMetric, height: CGFloat(lines.count) * rowHeight)
    }

    /// Shows `text` on row `i` from now on; the view owns it. The old text
    /// of that row is wiped and the pixels zeroed (until the next frame).
    func set(_ i: Int, _ text: SecretText?) {
        if let old = lines[i] {
            old.wipe()
            blank()
        }
        lines[i] = text
        needsDisplay = true
    }

    /// Wipes every line and zeroes the pixels.
    func clear() {
        for i in lines.indices { set(i, nil) }
        blank()
    }

    override func drawContent(in ctx: CGContext, rect: CGRect) {
        let ascent = CTFontGetAscent(layout.font), descent = CTFontGetDescent(layout.font)
        ctx.saveGState()
        ctx.clip(to: bounds)
        ctx.setFillColor(color(.labelColor))
        for (i, line) in lines.enumerated() {
            guard let line else { continue }
            let baseline = CGFloat(i) * rowHeight + (rowHeight - ascent - descent) / 2 + ascent
            layout.drawLine(line, TextLayout.firstLine(line), in: ctx, x: 0, baseline: baseline)
        }
        ctx.restoreGState()
    }
}

/// The key-change block's background: a faint orange fill and an orange bar
/// at its leading edge. Chrome.
private final class WarningBox: NSView {
    override func draw(_ dirtyRect: NSRect) {
        NSColor.systemOrange.withAlphaComponent(0.1).setFill()
        bounds.fill()
        NSColor.systemOrange.setFill()
        NSRect(x: 0, y: 0, width: 2, height: bounds.height).fill()
    }
}

/// A hairline at the bottom of its superview. Chrome.
final class Hairline: NSView {
    override func draw(_ dirtyRect: NSRect) {
        NSColor.separatorColor.setFill()
        bounds.fill()
    }

    override var intrinsicContentSize: NSSize { NSSize(width: NSView.noIntrinsicMetric, height: 1) }
}

final class ContactBar: NSView {
    /// A code (35 characters) in F1, with room.
    static let codeWidth: CGFloat = 300
    /// The message rows' text inset, so the bar and the rows line up.
    private static let margin = SecureListView.messageX

    /// A human pressed Godta ny kode.
    var onAccept: () -> Void = {}
    /// A human pressed Blokker.
    var onBlock: () -> Void = {}
    /// A human pressed Godta (true) or Avslå (false) on a request.
    var onAnswer: (Bool) -> Void = { _ in }

    /// The selected contact's (or asker's) address.
    let addresses = ContactTextView(rows: 1, font: ContentView.fontF2)
    /// The selected contact's pinned code (or the asker's code).
    let codes = ContactTextView(rows: 1)
    /// The code of the contact's changed key.
    let newCodeView = ContactTextView(rows: 1)
    /// The changed key's code as Rust gave it (35 ASCII bytes), while the
    /// block is shown: what acceptNewKey is given.
    private(set) var newCode: SecretBytes?
    private(set) var acceptButton: HumanButton?
    private(set) var blockButton: HumanButton?
    private(set) var approveButton: HumanButton?
    private(set) var declineButton: HumanButton?

    private let stack = NSStackView()
    private let waiting = InterfaceText(L10n.contactWaiting, style: .caption, width: 240, alignment: .left)
    private let verified = InterfaceText(L10n.contactVerified, style: .caption, width: 240, alignment: .left)
    private let blocked = InterfaceText(L10n.contactBlocked, style: .caption, width: 240, alignment: .left)
    private let blockError = InterfaceText(L10n.netError, style: .caption, width: 240, alignment: .left,
                                           color: .systemOrange)
    private let changedText = InterfaceText(L10n.contactChanged, width: 240, alignment: .left)
    private let acceptError = InterfaceText(L10n.acceptError, width: 240, alignment: .left)
    private let requestBody = InterfaceText(L10n.requestBody, width: 240, alignment: .left)
    private let answerError = InterfaceText(L10n.netError, width: 240, alignment: .left)
    /// The key-change block.
    private let changed = WarningBox()
    private let changedStack = NSStackView()
    /// A selected request: request.body, Godta, Avslå.
    private let request = NSStackView()
    private var stateRow = NSStackView()
    /// The texts that wrap at the bar's width, and how much narrower.
    private var wrapping: [(InterfaceText, CGFloat)] = []

    init() {
        super.init(frame: NSRect(x: 0, y: 0, width: 340, height: 120))
        build()
        clear()
    }

    required init?(coder: NSCoder) {
        nil
    }

    private static func row(_ views: [NSView], spacing: CGFloat = 8) -> NSStackView {
        let row = NSStackView(views: views)
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = spacing
        row.detachesHiddenViews = true
        return row
    }

    private static func column(_ views: [NSView], spacing: CGFloat) -> NSStackView {
        let column = NSStackView(views: views)
        column.orientation = .vertical
        column.alignment = .leading
        column.spacing = spacing
        column.detachesHiddenViews = true
        return column
    }

    private static func small(_ title: String, _ target: AnyObject, _ action: Selector) -> HumanButton {
        let b = HumanButton(title: title, target: target, action: action)
        b.controlSize = .small
        b.font = NSFont.systemFont(ofSize: NSFont.smallSystemFontSize)
        return b
    }

    /// The main action's look: accent-filled with a white title. No key
    /// equivalent: Return answers nothing here.
    private static func primary(_ b: HumanButton) {
        b.bezelStyle = .push
        b.bezelColor = .controlAccentColor
        b.contentTintColor = .white
    }

    private func build() {
        let block = Self.small(L10n.contactBlock, self, #selector(blockPressed(_:)))
        blockButton = block
        addresses.setContentHuggingPriority(.defaultLow, for: .horizontal)
        addresses.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        let nameRow = Self.row([addresses, block])
        stateRow = Self.column([waiting, verified, blocked, blockError], spacing: 2)
        let codeLabel = InterfaceText(L10n.contactsCode, style: .caption, width: 200, alignment: .left)
        codes.translatesAutoresizingMaskIntoConstraints = false

        let accept = Self.small(L10n.contactAccept, self, #selector(acceptPressed(_:)))
        Self.primary(accept)
        acceptButton = accept
        let newLabel = InterfaceText(L10n.contactNewCode, style: .caption, width: 200, alignment: .left)
        for v in [changedText, newLabel, newCodeView, accept, acceptError] as [NSView] {
            changedStack.addArrangedSubview(v)
        }
        changedStack.orientation = .vertical
        changedStack.alignment = .leading
        changedStack.spacing = 6
        changedStack.detachesHiddenViews = true
        changedStack.setCustomSpacing(2, after: newLabel)
        changedStack.translatesAutoresizingMaskIntoConstraints = false
        changed.addSubview(changedStack)
        NSLayoutConstraint.activate([
            changedStack.topAnchor.constraint(equalTo: changed.topAnchor, constant: 10),
            changedStack.bottomAnchor.constraint(equalTo: changed.bottomAnchor, constant: -10),
            changedStack.leadingAnchor.constraint(equalTo: changed.leadingAnchor, constant: 12),
            changedStack.trailingAnchor.constraint(equalTo: changed.trailingAnchor, constant: -10),
            newCodeView.widthAnchor.constraint(equalTo: changedStack.widthAnchor),
        ])

        let approve = HumanButton(title: L10n.requestAccept, target: self, action: #selector(approvePressed(_:)))
        Self.primary(approve)
        let decline = HumanButton(title: L10n.requestDecline, target: self, action: #selector(declinePressed(_:)))
        approveButton = approve
        declineButton = decline
        for v in [requestBody, Self.row([approve, decline]), answerError] as [NSView] { request.addArrangedSubview(v) }
        request.orientation = .vertical
        request.alignment = .leading
        request.spacing = 8
        request.detachesHiddenViews = true

        for v in [nameRow, stateRow, codeLabel, codes, changed, request] as [NSView] { stack.addArrangedSubview(v) }
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 4
        stack.detachesHiddenViews = true
        stack.setCustomSpacing(10, after: stateRow)
        stack.setCustomSpacing(2, after: codeLabel)
        stack.setCustomSpacing(12, after: codes)
        stack.translatesAutoresizingMaskIntoConstraints = false
        let line = Hairline()
        line.translatesAutoresizingMaskIntoConstraints = false
        addSubview(stack)
        addSubview(line)
        let m = Self.margin
        NSLayoutConstraint.activate([
            stack.topAnchor.constraint(equalTo: topAnchor, constant: 12),
            stack.bottomAnchor.constraint(equalTo: line.topAnchor, constant: -12),
            stack.leadingAnchor.constraint(equalTo: leadingAnchor, constant: m),
            stack.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -m),
            nameRow.widthAnchor.constraint(equalTo: stack.widthAnchor),
            codes.widthAnchor.constraint(equalTo: stack.widthAnchor),
            changed.widthAnchor.constraint(equalTo: stack.widthAnchor),
            line.leadingAnchor.constraint(equalTo: leadingAnchor),
            line.trailingAnchor.constraint(equalTo: trailingAnchor),
            line.bottomAnchor.constraint(equalTo: bottomAnchor),
            line.heightAnchor.constraint(equalToConstant: 1),
        ])
        wrapping = [(blockError, 0), (requestBody, 0), (answerError, 0), (changedText, 22), (acceptError, 22)]
    }

    /// The texts wrap at the bar's width.
    override func layout() {
        let width = bounds.width - 2 * Self.margin
        for (text, narrower) in wrapping { text.setWidth(width - narrower) }
        super.layout()
    }

    // MARK: - Showing

    /// The selected contact, or nothing. The bar owns the address and the
    /// new code, and wipes the pinned code after copying it.
    /// `acceptFailed` shows accept.error in the key-change block;
    /// `blockFailed` shows net.error under the state, and Blokker stays.
    func showContact(_ contact: ContactDetails?, acceptFailed: Bool = false, blockFailed: Bool = false) {
        clear()
        guard let contact else { return }
        addresses.set(0, contact.address)
        codes.set(0, Self.text(of: contact.code))
        contact.code.wipe()
        blocked.isHidden = !contact.blocked
        waiting.isHidden = contact.blocked || !contact.waiting
        verified.isHidden = contact.blocked || contact.waiting || !contact.verified
        blockButton?.isHidden = contact.blocked && !blockFailed
        blockButton?.isEnabled = true
        blockError.isHidden = !blockFailed
        stateRow.isHidden = false
        guard contact.newCode.count > 0 else { return contact.newCode.wipe() }
        newCode = contact.newCode
        newCodeView.set(0, Self.text(of: contact.newCode))
        acceptError.isHidden = !acceptFailed
        changed.isHidden = false
    }

    /// A contact request's asker. The bar owns `address` and wipes `code`
    /// after copying it. `failed` shows net.error under Godta and Avslå.
    func showRequest(address: SecretText, code: SecretBytes, failed: Bool = false) {
        clear()
        addresses.set(0, address)
        codes.set(0, Self.text(of: code))
        code.wipe()
        answerError.isHidden = !failed
        setAnswering(false)
        request.isHidden = false
    }

    /// Godta and Avslå off while an answer is on its way.
    func setAnswering(_ busy: Bool) {
        approveButton?.isEnabled = !busy
        declineButton?.isEnabled = !busy
    }

    /// Blokker off while the relay is being told.
    func setBlocking(_ busy: Bool) {
        blockButton?.isEnabled = !busy
    }

    /// Whether the changed-key block is shown.
    var showsKeyChange: Bool { !changed.isHidden }
    /// Whether a request's block is shown.
    var showsRequest: Bool { !request.isHidden }
    /// The state shown for the contact: "blocked", "waiting", "verified" or
    /// "" (for the tools' checks).
    var shownState: String {
        stateRow.isHidden ? "" : !blocked.isHidden ? "blocked" : !waiting.isHidden ? "waiting"
            : !verified.isHidden ? "verified" : ""
    }

    /// Everything wiped and zeroed: a new selection, a new screen or the
    /// lock sequence.
    func clear() {
        addresses.clear()
        codes.clear()
        newCodeView.clear()
        newCode?.wipe()
        newCode = nil
        blockButton?.isHidden = true
        stateRow.isHidden = true
        changed.isHidden = true
        request.isHidden = true
    }

    /// A code's 35 ASCII bytes as UTF-16 in a new SecretText, for drawing.
    private static func text(of code: SecretBytes) -> SecretText {
        let t = SecretText(maxUnits: max(code.count, 1))
        code.withBytes { Transcode.utf8ToUTF16($0, into: t) }
        return t
    }

    // MARK: - Actions (HumanButton: human input only)

    @objc private func acceptPressed(_ sender: Any?) {
        onAccept()
    }

    @objc private func blockPressed(_ sender: Any?) {
        onBlock()
    }

    @objc private func approvePressed(_ sender: Any?) {
        onAnswer(true)
    }

    @objc private func declinePressed(_ sender: Any?) {
        onAnswer(false)
    }
}
