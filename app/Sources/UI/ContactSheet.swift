// ContactSheet.swift — Kontakter: the own address and code, and a new
// contact by address.
//
// Upholds CLAUDE.md §1.2, §1.3, §1.5, §1.10, §2 and §3.2
// (docs/PHASE4_DESIGN.md §6.1, §6.2; it replaces Phase 3's AddContactSheet).
// A hardened sheet like ComposeSheet: a HardenedWindow that gets
// Hardening.apply when it is made and again from the window it joins. Its
// labels, buttons and messages are interface text. The own address and code
// (ContactTextViews) and the field (a ContactField) are contact data, drawn
// only in the protected layer. A grouped form, like System Settings
// (docs/UI_REDESIGN.md §2.7): two titled groups on rounded panels, then the
// result line and Lukk. There are no invite codes (D-0116).
// 1. «Deg»: «Adresse», the own address, and Kopier adressen min, which puts
//    the address's bytes on the pasteboard (ContactPasteboard: plain text
//    marked concealed and transient, emptied after 60 s and at quit if
//    still Brev's); «Sikkerhetskode» and the own code (a UTF-16 copy the
//    sheet owns), so a contact can compare it (it left the mail window).
// 2. «Legg til kontakt»: «Adresse:», the field (typed, or ⌘V, in a rounded
//    border) and Legg til (or Return or ⌘↩ in the field): `addContact` asks
//    the contact; the field is wiped and request.sent shows, or, if the
//    contact already takes the user's letters, the sheet closes with it.
// 3. One fixed text: the outcome or the error, or none.
// Every button is a HumanButton. While a call is on its way the field is
// read-only and the buttons are off. Lukk (or Escape) closes the sheet, and
// so does a lock. However it closes, the field, the own address and the code
// are wiped and their pixels zeroed, secure event input goes off, and a
// result that arrives after that is dropped. The pasteboard is not cleared
// on close or lock (the owner's rule: the user may paste the address into
// another app, which locks Brev). The completion gets the contact added
// last, after Lukk, Escape or an add that closes the sheet; a lock reports
// nothing (nothing may be read while the lock sequence runs, §1.10). Logs
// say only what happened, or the error's variant.

import AppKit
import os

final class ContactSheet: HardenedWindow, ContentHolder {
    private static let log = Logger(subsystem: "no.brev.app", category: "contact")
    private static let width: CGFloat = 520
    private static let margin: CGFloat = 20
    /// The width inside a group's panel.
    private static let groupInner: CGFloat = width - 2 * margin - 24

    let field = ContactField()
    /// Row 0: the own address.
    let ownAddress = ContactTextView(rows: 1)
    /// Row 0: the own identity code.
    let ownCode = ContactTextView(rows: 1)
    private(set) var copyAddressButton: HumanButton?
    private(set) var addButton: HumanButton?
    private var closeButton: HumanButton?

    private let requestSent = ContactSheet.message(L10n.requestSent)
    private let notFound = ContactSheet.message(L10n.contactErrorNotFound)
    private let duplicate = ContactSheet.message(L10n.contactErrorDuplicate)
    private let ownAddressError = ContactSheet.message(L10n.contactErrorSelf)
    private let invalidAddress = ContactSheet.message(L10n.addressErrorInvalid)
    private let requestLimit = ContactSheet.message(L10n.requestErrorLimit)
    private let keyChanged = ContactSheet.message(L10n.contactChanged)
    private let netFailure = ContactSheet.message(L10n.netError)
    private let failure = ContactSheet.message(L10n.contactErrorFailed)
    private var messages: [InterfaceText] {
        [requestSent, notFound, duplicate, ownAddressError, invalidAddress, requestLimit, keyChanged, netFailure,
         failure]
    }

    private weak var session: Session?
    /// True while a call is on `Session.net`.
    private(set) var busy = false
    /// Bumped by `wipeAll` (every close and the lock sequence): a result of
    /// a call begun before it is dropped.
    private var epoch = 0
    /// The contact added last, for the completion.
    private(set) var added: Data?

    /// Shows the sheet on `parent` with the field focused. `completion`
    /// gets the contact added last, or nil, after Lukk, Escape or an add
    /// that closes it; not after a lock.
    @discardableResult
    static func present(on parent: NSWindow, session: Session, completion: @escaping (Data?) -> Void) -> ContactSheet {
        let sheet = ContactSheet(session: session)
        parent.beginSheet(sheet) { code in
            sheet.wipeAll()
            GlyphFlush.flush()
            if code == .OK || code == .cancel { completion(sheet.added) }
        }
        sheet.makeFirstResponder(sheet.field)
        Hardening.assertAllWindows()
        return sheet
    }

    /// Made by `present`; the snapshot tool makes one to draw it offscreen,
    /// never shown.
    init(session: Session) {
        self.session = session
        super.init(contentRect: NSRect(x: 0, y: 0, width: Self.width, height: 420), styleMask: [.titled],
                   backing: .buffered, defer: false)
        Hardening.apply(self)
        isReleasedWhenClosed = false
        field.onReturn = { [weak self] in self?.add() }
        field.onSend = { [weak self] in self?.add() }
        field.onCancel = { [weak self] in self?.closeSheet(nil) }
        let content = makeContent()
        contentView = content
        setContentSize(content.fittingSize)
        initialFirstResponder = field
        showOwnAddress()
        show(nil)
    }

    private static func message(_ text: String) -> InterfaceText {
        InterfaceText(text, width: width - 2 * margin - 110, alignment: .left)
    }

    private static func sized(_ v: NSView, _ width: CGFloat, _ height: CGFloat) -> NSView {
        v.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([v.widthAnchor.constraint(equalToConstant: width),
                                     v.heightAnchor.constraint(equalToConstant: height)])
        return v
    }

    private static func row(_ views: [NSView]) -> NSStackView {
        let row = NSStackView(views: views)
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = 8
        return row
    }

    /// A titled group: an 11 pt section title over a rounded panel.
    private static func group(_ title: String, _ rows: [NSView]) -> NSStackView {
        let panel = FormPanel()
        let column = NSStackView(views: rows)
        column.orientation = .vertical
        column.alignment = .leading
        column.spacing = 10
        column.detachesHiddenViews = true
        column.translatesAutoresizingMaskIntoConstraints = false
        panel.addSubview(column)
        NSLayoutConstraint.activate([
            column.topAnchor.constraint(equalTo: panel.topAnchor, constant: 12),
            column.bottomAnchor.constraint(equalTo: panel.bottomAnchor, constant: -12),
            column.leadingAnchor.constraint(equalTo: panel.leadingAnchor, constant: 12),
            column.trailingAnchor.constraint(equalTo: panel.trailingAnchor, constant: -12),
            panel.widthAnchor.constraint(equalToConstant: width - 2 * margin),
        ])
        let section = NSStackView(views: [InterfaceText(title, style: .section, width: 300, alignment: .left), panel])
        section.orientation = .vertical
        section.alignment = .leading
        section.spacing = 6
        return section
    }

    /// A label over a value: «Adresse» over the own address, say.
    private static func labelled(_ label: String, _ value: NSView, _ width: CGFloat, _ height: CGFloat) -> NSStackView {
        let pair = NSStackView(views: [InterfaceText(label, style: .caption, width: width, alignment: .left),
                                       sized(value, width, height)])
        pair.orientation = .vertical
        pair.alignment = .leading
        pair.spacing = 2
        return pair
    }

    private func makeContent() -> NSView {
        let inner = Self.groupInner
        let line = ContactTextView.rowHeight
        let copyMe = HumanButton(title: L10n.contactsCopyMe, target: self, action: #selector(copyAddress(_:)))
        let add = HumanButton(title: L10n.contactsAdd, target: self, action: #selector(addPressed(_:)))
        let close = HumanButton(title: L10n.contactsClose, target: self, action: #selector(closeSheet(_:)))
        close.keyEquivalent = "\u{1b}"
        copyAddressButton = copyMe
        addButton = add
        closeButton = close

        let scroll = NSScrollView()
        scroll.borderType = .noBorder
        scroll.drawsBackground = false
        scroll.verticalScrollElasticity = .none
        scroll.horizontalScrollElasticity = .none
        scroll.automaticallyAdjustsContentInsets = false
        scroll.documentView = field
        let fieldBox = FieldBorder()
        scroll.translatesAutoresizingMaskIntoConstraints = false
        fieldBox.addSubview(scroll)
        NSLayoutConstraint.activate([
            scroll.topAnchor.constraint(equalTo: fieldBox.topAnchor, constant: 1),
            scroll.bottomAnchor.constraint(equalTo: fieldBox.bottomAnchor, constant: -1),
            scroll.leadingAnchor.constraint(equalTo: fieldBox.leadingAnchor, constant: 2),
            scroll.trailingAnchor.constraint(equalTo: fieldBox.trailingAnchor, constant: -2),
        ])

        // The messages share one place below the groups.
        let messageArea = NSView()
        for m in messages {
            m.translatesAutoresizingMaskIntoConstraints = false
            messageArea.addSubview(m)
            NSLayoutConstraint.activate([m.topAnchor.constraint(equalTo: messageArea.topAnchor),
                                         m.leadingAnchor.constraint(equalTo: messageArea.leadingAnchor)])
        }
        // A spacer before a trailing button, so it ends 12 pt from the panel
        // edge, as the leading inset.
        func trailing(_ views: [NSView]) -> NSStackView {
            let spacer = NSView()
            spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
            let row = Self.row(Array(views.dropLast()) + [spacer, views.last!])
            row.widthAnchor.constraint(equalToConstant: inner).isActive = true
            return row
        }
        let me = Self.group(L10n.contactsSectionMe, [
            trailing([Self.labelled(L10n.contactsAddress, ownAddress, inner - 180, line), copyMe]),
            Self.labelled(L10n.contactsCode, ownCode, inner, line),
        ])
        let addGroup = Self.group(L10n.contactsSectionAdd, [
            InterfaceText(L10n.contactsField, style: .caption, width: inner, alignment: .left),
            trailing([Self.sized(fieldBox, inner - 100, 28), add]),
        ])
        let spacer = NSView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        let bottom = Self.row([Self.sized(messageArea, Self.width - 2 * Self.margin - 110, 36), spacer, close])
        let stack = NSStackView(views: [
            InterfaceText(L10n.contactsTitle, style: .heading, width: Self.width - 2 * Self.margin, alignment: .left),
            me, addGroup, bottom,
        ])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 16
        // The messages' row keeps its place; the groups' rows collapse
        // (group()), and `show` fits the sheet to them.
        stack.detachesHiddenViews = false
        stack.edgeInsets = NSEdgeInsets(top: Self.margin, left: Self.margin, bottom: Self.margin, right: Self.margin)
        bottom.widthAnchor.constraint(equalToConstant: Self.width - 2 * Self.margin).isActive = true
        return stack
    }

    /// The own address and code in the first group (the view owns the
    /// address and a UTF-16 copy of the code; the code's bytes are wiped).
    private func showOwnAddress() {
        do {
            if let me = try session?.me() {
                ownCode.set(0, Self.text(me.code, 0..<me.code.count))
                me.code.wipe()
                ownAddress.set(0, me.address)
            }
        } catch {
            Self.log.error("me failed: \(Self.name(error), privacy: .public)")
        }
    }

    /// Shows `message` (or none), with the buttons and the field on unless
    /// a call is under way. The sheet then fits its content.
    private func show(_ message: InterfaceText?, busy: Bool = false) {
        self.busy = busy
        for m in messages { m.isHidden = m !== message }
        field.isEditable = !busy
        for b in [copyAddressButton, addButton, closeButton] { b?.isEnabled = !busy }
        if let content = contentView {
            content.layoutSubtreeIfNeeded()
            let size = content.fittingSize
            if size != content.frame.size { setContentSize(size) }
        }
    }

    // MARK: - Actions (HumanButton: only a human's press gets here; the view
    // host calls them directly as that press)

    /// Kopier adressen min: the own address's bytes on the pasteboard.
    @objc func copyAddress(_ sender: Any?) {
        guard !busy, let address = ownAddress.lines[0], address.length > 0 else { return }
        let bytes = SecretBytes(capacity: 3 * address.length)
        defer { bytes.wipe() }
        Transcode.utf16ToUTF8(address, into: bytes)
        ContactPasteboard.write(bytes)
        Self.log.notice("address copied")
    }

    @objc private func addPressed(_ sender: Any?) {
        add()
    }

    /// Legg til: the typed address is asked.
    func add() {
        guard !busy, let session, sheetParent != nil else { return }
        guard field.model.text.length > 0 else { return NSSound.beep() }
        show(nil, busy: true)
        let started = epoch
        let address = field.model.text.copy()
        Session.net.async {
            let result = Result { try session.addContact(address: address) }
            address.wipe()
            DispatchQueue.main.async { [weak self] in
                guard let self, started == self.epoch else { return }
                self.asked(result)
            }
        }
    }

    /// Whether the contact `id` does not take the user's letters yet (no
    /// I/O); its texts are wiped at once.
    private func waiting(_ id: Data) -> Bool {
        guard let info = try? session?.contactInfo(contact: id) else { return true }
        info.address.wipe()
        info.code.wipe()
        info.newCode.wipe()
        return info.waiting
    }

    private func asked(_ result: Result<Data, Error>) {
        switch result {
        case .success(let id):
            added = id
            field.wipe()
            let asked = waiting(id)
            Self.log.notice("contact added waiting=\(asked, privacy: .public)")
            guard asked else { return endWith(.OK) }
            show(requestSent)
        case .failure(let error):
            Self.log.error("add contact failed: \(Self.name(error), privacy: .public)")
            switch error {
            case BrevError.NotFound: show(notFound)
            case BrevError.Duplicate: show(duplicate)
            case BrevError.Malformed: show(isOwnAddress() ? ownAddressError : invalidAddress)
            case BrevError.RateLimited: show(requestLimit)
            case BrevError.Network: show(netFailure)
            default: show(failure)
            }
        }
    }

    /// Whether the typed address is the own one (Rust gives Malformed for
    /// both that and an address that breaks the rules). Both are lower case.
    private func isOwnAddress() -> Bool {
        guard let own = ownAddress.lines[0] else { return false }
        let typed = field.model.text
        return own.length == typed.length && (0..<own.length).allSatisfy { own.units[$0] == typed.units[$0] }
    }

    @objc func closeSheet(_ sender: Any?) {
        guard !busy else { return }
        endWith(.cancel)
    }

    private func endWith(_ code: NSApplication.ModalResponse) {
        sheetParent?.endSheet(self, returnCode: code)
    }

    // MARK: - Texts

    /// ASCII bytes `range` of `bytes` as UTF-16 in a new SecretText.
    private static func text(_ bytes: SecretBytes, _ range: Range<Int>) -> SecretText {
        let t = SecretText(maxUnits: max(range.count, 1))
        bytes.withBytes { Transcode.utf8ToUTF16(UnsafeRawBufferPointer(rebasing: $0[range]), into: t) }
        return t
    }

    /// A BrevError's variant name; never an error's message.
    private static func name(_ error: Error) -> String {
        (error as? BrevError).map { "\($0)" } ?? "other"
    }

    // MARK: - ContentHolder

    /// No field keeps focus and secure event input is off; the field, the
    /// own address and the code are wiped and their pixels zeroed; a call still under way is dropped. Every close runs it, and
    /// the lock sequence before it ends the sheet.
    func wipeAll() {
        epoch &+= 1
        _ = makeFirstResponder(nil)
        SecureInput.disable()
        field.wipe()
        ownAddress.clear()
        ownCode.clear()
        show(nil)
    }
}

/// A form group's panel: controlBackgroundColor with a 1 pt separator
/// border, rounded. Chrome.
private final class FormPanel: NSView {
    override func draw(_ dirtyRect: NSRect) {
        let path = NSBezierPath(roundedRect: bounds.insetBy(dx: 0.5, dy: 0.5), xRadius: 8, yRadius: 8)
        NSColor.controlBackgroundColor.setFill()
        path.fill()
        NSColor.separatorColor.setStroke()
        path.lineWidth = 1
        path.stroke()
    }
}

/// The rounded 1 pt border around an address or code field (the field
/// itself is a ContentView and draws only its text). Chrome.
final class FieldBorder: NSView {
    override func draw(_ dirtyRect: NSRect) {
        let path = NSBezierPath(roundedRect: bounds.insetBy(dx: 0.5, dy: 0.5), xRadius: 6, yRadius: 6)
        NSColor.textBackgroundColor.setFill()
        path.fill()
        NSColor.separatorColor.setStroke()
        path.lineWidth = 1
        path.stroke()
    }
}
