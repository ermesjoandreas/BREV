// ContactHeaderView.swift — the own address and code, and the selected
// contact's, above the panes.
//
// Upholds CLAUDE.md §1.2, §1.5, §1.10 and §3.2 (docs/PHASE3_DESIGN.md §6.3,
// §6.4, §6.5). Addresses and identity codes are contact data, so they are
// drawn only by ContactTextViews: ContentViews, which draw through the
// capture-protected layer and are no accessibility element. Beside them
// stand fixed labels from Localizable.strings (InterfaceText): "Du:" before
// line 1, which shows the own address and code, and "Sikkerhetskode:"
// before each code. Line 2 shows the selected contact's address and pinned
// code. While the contact's key has changed, a block below shows
// contact.changed, "Ny kode:" beside the new code (protected too) and Godta
// ny kode (a HumanButton). The header owns every text it draws: the
// addresses it is given, and a UTF-16 copy of each code, made from the
// code's SecretBytes, which it wipes, except the new code's, which it keeps
// as `newCode` for acceptNewKey: the code accepted is exactly the code
// shown. `clear()` (a new selection, the lock sequence) wipes all of it and
// zeroes the pixels. No string here takes an address or a code.

import AppKit

/// Lines of contact data, one per row, in the protected layer: the first
/// line of each SecretText, clipped at the view's edge, in the content font.
final class ContactTextView: ContentView {
    static let rowHeight: CGFloat = 20

    private let layout = TextLayout(font: ContentView.contentFont)
    private(set) var lines: [SecretText?]

    init(rows: Int) {
        lines = Array(repeating: nil, count: rows)
        super.init(frame: NSRect(x: 0, y: 0, width: 200, height: CGFloat(rows) * Self.rowHeight))
    }

    required init?(coder: NSCoder) {
        nil
    }

    /// Shows `text` on row `i` from now on; the view owns it. The old text
    /// of that row is wiped.
    func set(_ i: Int, _ text: SecretText?) {
        lines[i]?.wipe()
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
            let baseline = CGFloat(i) * Self.rowHeight + (Self.rowHeight - ascent - descent) / 2 + ascent
            layout.drawLine(line, TextLayout.firstLine(line), in: ctx, x: 0, baseline: baseline)
        }
        ctx.restoreGState()
    }
}

final class ContactHeaderView: NSView {
    /// The width of a code (35 characters) in the content font, with room.
    static let codeWidth: CGFloat = 300
    private static let margin: CGFloat = 12

    /// A human pressed Godta ny kode.
    var onAccept: () -> Void = {}

    /// Row 0: the own address; row 1: the selected contact's.
    let addresses = ContactTextView(rows: 2)
    /// Row 0: the own code; row 1: the selected contact's pinned code.
    let codes = ContactTextView(rows: 2)
    /// The code of the contact's changed key.
    let newCodeView = ContactTextView(rows: 1)
    /// The changed key's code as Rust gave it (35 ASCII bytes), while the
    /// block is shown: what acceptNewKey is given.
    private(set) var newCode: SecretBytes?
    private(set) var acceptButton: HumanButton?

    private let contactCodeLabel = InterfaceText(L10n.headerCode, width: 110, alignment: .right)
    private let changed = NSStackView()
    private let acceptError = InterfaceText(L10n.acceptError, width: 560, alignment: .left)

    init() {
        super.init(frame: NSRect(x: 0, y: 0, width: 900, height: 52))
        build()
        clear()
    }

    required init?(coder: NSCoder) {
        nil
    }

    private func build() {
        let top = NSView()
        let me = InterfaceText(L10n.headerMe, width: 40, alignment: .right)
        let meCode = InterfaceText(L10n.headerCode, width: 110, alignment: .right)
        for v in [me, addresses, meCode, contactCodeLabel, codes] as [NSView] {
            v.translatesAutoresizingMaskIntoConstraints = false
            top.addSubview(v)
        }
        let row = ContactTextView.rowHeight
        addresses.setContentHuggingPriority(.defaultLow, for: .horizontal)
        addresses.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        NSLayoutConstraint.activate([
            addresses.topAnchor.constraint(equalTo: top.topAnchor),
            addresses.bottomAnchor.constraint(equalTo: top.bottomAnchor),
            addresses.heightAnchor.constraint(equalToConstant: 2 * row),
            addresses.leadingAnchor.constraint(equalTo: me.trailingAnchor, constant: 8),
            addresses.widthAnchor.constraint(greaterThanOrEqualToConstant: 80),
            me.leadingAnchor.constraint(equalTo: top.leadingAnchor),
            me.centerYAnchor.constraint(equalTo: addresses.topAnchor, constant: row / 2),
            meCode.leadingAnchor.constraint(equalTo: addresses.trailingAnchor, constant: 12),
            meCode.centerYAnchor.constraint(equalTo: me.centerYAnchor),
            contactCodeLabel.leadingAnchor.constraint(equalTo: meCode.leadingAnchor),
            contactCodeLabel.centerYAnchor.constraint(equalTo: addresses.topAnchor, constant: 1.5 * row),
            codes.leadingAnchor.constraint(equalTo: meCode.trailingAnchor, constant: 8),
            codes.topAnchor.constraint(equalTo: addresses.topAnchor),
            codes.heightAnchor.constraint(equalToConstant: 2 * row),
            codes.widthAnchor.constraint(equalToConstant: Self.codeWidth),
            codes.trailingAnchor.constraint(equalTo: top.trailingAnchor),
        ])

        let newLabel = InterfaceText(L10n.contactNewCode, width: 60, alignment: .left)
        let accept = HumanButton(title: L10n.contactAccept, target: self, action: #selector(acceptPressed(_:)))
        acceptButton = accept
        newCodeView.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            newCodeView.widthAnchor.constraint(equalToConstant: Self.codeWidth),
            newCodeView.heightAnchor.constraint(equalToConstant: row),
        ])
        let newRow = NSStackView(views: [newLabel, newCodeView, accept])
        newRow.orientation = .horizontal
        newRow.alignment = .centerY
        newRow.spacing = 8
        for v in [InterfaceText(L10n.contactChanged, width: 560, alignment: .left), newRow, acceptError] as [NSView] {
            changed.addArrangedSubview(v)
        }
        changed.orientation = .vertical
        changed.alignment = .leading
        changed.spacing = 6
        changed.detachesHiddenViews = true

        let stack = NSStackView(views: [top, changed])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 8
        stack.detachesHiddenViews = true
        stack.translatesAutoresizingMaskIntoConstraints = false
        addSubview(stack)
        let m = Self.margin
        NSLayoutConstraint.activate([
            stack.topAnchor.constraint(equalTo: topAnchor, constant: 4),
            stack.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -4),
            stack.leadingAnchor.constraint(equalTo: leadingAnchor, constant: m),
            stack.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor, constant: -m),
            top.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -m),
        ])
    }

    // MARK: - Showing

    /// Line 1: the own address and code. The header owns `address` and
    /// wipes `code` after copying it.
    func showMe(address: SecretText, code: SecretBytes) {
        addresses.set(0, address)
        codes.set(0, Self.text(of: code))
        code.wipe()
    }

    /// Line 2 and the block below it: the selected contact, or nothing.
    /// The header owns the address and the new code, and wipes the pinned
    /// code after copying it. `acceptFailed` shows accept.error in the block.
    func showContact(_ contact: ContactDetails?, acceptFailed: Bool = false) {
        clearContact()
        guard let contact else { return }
        addresses.set(1, contact.address)
        codes.set(1, Self.text(of: contact.code))
        contact.code.wipe()
        contactCodeLabel.isHidden = false
        guard contact.newCode.count > 0 else { return contact.newCode.wipe() }
        newCode = contact.newCode
        newCodeView.set(0, Self.text(of: contact.newCode))
        acceptError.isHidden = !acceptFailed
        changed.isHidden = false
    }

    /// Whether the changed-key block is shown.
    var showsKeyChange: Bool { !changed.isHidden }

    /// Line 2 and the block: wiped, their pixels zeroed.
    private func clearContact() {
        addresses.set(1, nil)
        codes.set(1, nil)
        newCodeView.clear()
        newCode?.wipe()
        newCode = nil
        contactCodeLabel.isHidden = true
        changed.isHidden = true
    }

    /// Everything wiped and zeroed: a new screen or the lock sequence.
    func clear() {
        clearContact()
        addresses.clear()
        codes.clear()
    }

    /// A code's 35 ASCII bytes as UTF-16 in a new SecretText, for drawing.
    private static func text(of code: SecretBytes) -> SecretText {
        let t = SecretText(maxUnits: max(code.count, 1))
        code.withBytes { Transcode.utf8ToUTF16($0, into: t) }
        return t
    }

    // MARK: - Action (HumanButton: human input only)

    @objc private func acceptPressed(_ sender: Any?) {
        onAccept()
    }
}
