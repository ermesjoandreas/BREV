// AddContactSheet.swift — Legg til kontakt: a contact by its address.
//
// Upholds CLAUDE.md §1.2, §1.3, §1.5, §1.10, §2 and §3.2
// (docs/PHASE3_DESIGN.md §5.2, §6.2, §6.4, §6.5). A hardened sheet like
// ComposeSheet: a HardenedWindow that gets Hardening.apply when it is made
// and again from the window it joins. "Legg til kontakt" and "Adresse:" are
// interface text; the address is typed into a single-line SecureComposeView
// with the address charset (a–z, 0–9 and "-"; A–Z become a–z; anything else
// beeps), so it is typed, held and drawn like content: key events only, no
// pasteboard, secure event input while focused, pixels only in the protected
// layer. Legg til (a HumanButton, or Return or ⌘↩ in the field) looks the
// address up at the relay on `Session.net` with a copy of the typed text that
// is wiped when the call returns (Rust copies it before the lookup); the
// field is read-only and both buttons are off meanwhile. The first key the
// relay returns is pinned (trust on first use), and the sheet closes with
// the new contact's id. A failure shows one fixed text: nobody with that
// address, already a contact, the own address, an address that breaks the
// rules, no contact with the relay, or another failure. No Touch ID. Avbryt
// (a HumanButton, or Escape) closes it, and so does a lock; however it
// closes, the field is wiped and secure event input goes off, and a result
// that arrives after that is dropped. Logs say only that a contact was
// added, or the error's variant.

import AppKit
import os

final class AddContactSheet: HardenedWindow, ContentHolder {
    private static let log = Logger(subsystem: "no.brev.app", category: "contact")
    static let contentSize = NSSize(width: 460, height: 176)
    private static let margin: CGFloat = 20

    let field: SecureComposeView
    private(set) var addButton: HumanButton?
    private var cancelButton: HumanButton?
    private let notFound = AddContactSheet.message(L10n.contactErrorNotFound)
    private let duplicate = AddContactSheet.message(L10n.contactErrorDuplicate)
    private let ownAddress = AddContactSheet.message(L10n.contactErrorSelf)
    private let invalid = AddContactSheet.message(L10n.addressErrorInvalid)
    private let netFailure = AddContactSheet.message(L10n.netError)
    private let failure = AddContactSheet.message(L10n.contactErrorFailed)
    private var messages: [InterfaceText] { [notFound, duplicate, ownAddress, invalid, netFailure, failure] }
    private weak var session: Session?
    /// True while the lookup is on its way.
    private(set) var busy = false
    /// Bumped by `wipeAll` (every close and the lock sequence): a result of
    /// a lookup begun before it is dropped.
    private var epoch = 0
    /// The contact added, once it is.
    private(set) var added: Data?

    /// Shows the sheet on `parent` with the field focused. `completion`
    /// gets the new contact's local id, or nil after Avbryt, Escape or a
    /// lock.
    @discardableResult
    static func present(on parent: NSWindow, session: Session, completion: @escaping (Data?) -> Void) -> AddContactSheet {
        let sheet = AddContactSheet(session: session, limits: limits())
        parent.beginSheet(sheet) { _ in
            sheet.wipeAll()
            GlyphFlush.flush()
            completion(sheet.added)
        }
        sheet.makeFirstResponder(sheet.field)
        Hardening.assertAllWindows()
        return sheet
    }

    private init(session: Session, limits: Limits) {
        field = SecureComposeView(maxBytes: Int(limits.maxAddress), multiline: false, charset: .address)
        self.session = session
        super.init(contentRect: NSRect(origin: .zero, size: Self.contentSize), styleMask: [.titled],
                   backing: .buffered, defer: false)
        Hardening.apply(self)
        isReleasedWhenClosed = false
        field.onReturn = { [weak self] in self?.add() }
        field.onSend = { [weak self] in self?.add() }
        field.onCancel = { [weak self] in self?.cancel(nil) }
        contentView = makeContent()
        initialFirstResponder = field
        show(nil)
    }

    private static func message(_ text: String) -> InterfaceText {
        InterfaceText(text, width: contentSize.width - 2 * margin, alignment: .left)
    }

    private func makeContent() -> NSView {
        let root = NSView(frame: NSRect(origin: .zero, size: Self.contentSize))
        let title = InterfaceText(L10n.contactTitle, style: .heading, width: Self.contentSize.width - 2 * Self.margin,
                                  alignment: .left)
        let label = InterfaceText(L10n.contactField, width: 60, alignment: .right)
        let scroll = NSScrollView()
        scroll.borderType = .bezelBorder
        scroll.drawsBackground = true
        scroll.backgroundColor = .textBackgroundColor
        scroll.verticalScrollElasticity = .none
        scroll.horizontalScrollElasticity = .none
        scroll.documentView = field
        let cancel = HumanButton(title: L10n.contactCancel, target: self, action: #selector(cancel(_:)))
        cancel.keyEquivalent = "\u{1b}"
        cancelButton = cancel
        let add = HumanButton(title: L10n.contactAdd, target: self, action: #selector(addPressed(_:)))
        addButton = add
        let buttons = NSStackView(views: [cancel, add])
        buttons.spacing = 12
        for v in [title, label, scroll, buttons] + messages as [NSView] {
            v.translatesAutoresizingMaskIntoConstraints = false
            root.addSubview(v)
        }
        let m = Self.margin
        NSLayoutConstraint.activate([
            title.topAnchor.constraint(equalTo: root.topAnchor, constant: m),
            title.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: m),
            scroll.topAnchor.constraint(equalTo: title.bottomAnchor, constant: 14),
            scroll.leadingAnchor.constraint(equalTo: label.trailingAnchor, constant: 8),
            scroll.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -m),
            scroll.heightAnchor.constraint(equalToConstant: 26),
            label.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: m),
            label.centerYAnchor.constraint(equalTo: scroll.centerYAnchor),
            buttons.topAnchor.constraint(equalTo: scroll.bottomAnchor, constant: 52),
            buttons.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -m),
            buttons.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -m),
        ] + messages.flatMap { [
            $0.topAnchor.constraint(equalTo: scroll.bottomAnchor, constant: 10),
            $0.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: m),
        ] })
        return root
    }

    /// Shows `message` (or none), with the buttons and the field on unless
    /// a lookup is under way.
    private func show(_ message: InterfaceText?, busy: Bool = false) {
        self.busy = busy
        for m in messages { m.isHidden = m !== message }
        addButton?.isEnabled = !busy
        cancelButton?.isEnabled = !busy
        field.isEditable = !busy
    }

    // MARK: - Adding (docs/PHASE3_DESIGN.md §6.2)

    @objc private func addPressed(_ sender: Any?) {
        add()
    }

    /// The lookup, on `Session.net`, with a copy of the typed address.
    func add() {
        guard !busy, added == nil, let session, sheetParent != nil else { return }
        guard field.model.text.length > 0 else { return NSSound.beep() }
        let typed = field.model.text.copy()
        show(nil, busy: true)
        let started = epoch
        Session.net.async {
            let result = Result { try session.addContact(address: typed) }
            typed.wipe()
            DispatchQueue.main.async { [weak self] in self?.finished(result, started) }
        }
    }

    private func finished(_ result: Result<Data, Error>, _ started: Int) {
        guard started == epoch, let parent = sheetParent else { return }
        switch result {
        case .success(let id):
            added = id
            Self.log.notice("contact added")
            parent.endSheet(self, returnCode: .OK)
        case .failure(let error):
            Self.log.error("add contact failed: \((error as? BrevError).map { "\($0)" } ?? "other", privacy: .public)")
            switch error {
            case BrevError.NotFound: show(notFound)
            case BrevError.Duplicate: show(duplicate)
            case BrevError.Malformed: show(isOwnAddress() ? ownAddress : invalid)
            case BrevError.Network: show(netFailure)
            default: show(failure)
            }
        }
    }

    /// Whether the typed address is the own one (Rust gives Malformed for
    /// both that and an address that breaks the rules). Both are lower case.
    private func isOwnAddress() -> Bool {
        guard let me = try? session?.me() else { return false }
        defer {
            me.address.wipe()
            me.code.wipe()
        }
        let own = me.address, typed = field.model.text
        return own.length == typed.length && (0..<own.length).allSatisfy { own.units[$0] == typed.units[$0] }
    }

    @objc private func cancel(_ sender: Any?) {
        guard !busy else { return }
        sheetParent?.endSheet(self, returnCode: .cancel)
    }

    // MARK: - ContentHolder

    /// No field keeps focus and secure event input is off; the address is
    /// wiped and its pixels zeroed; a lookup still under way is dropped.
    /// Every close runs it, and the lock sequence before it ends the sheet.
    func wipeAll() {
        epoch &+= 1
        _ = makeFirstResponder(nil)
        SecureInput.disable()
        field.wipe()
        show(nil)
    }
}
