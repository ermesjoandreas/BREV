// ContactSheet.swift — Kontakter: the own address, invite codes, and a new
// contact by address or invite code.
//
// Upholds CLAUDE.md §1.2, §1.3, §1.5, §1.10, §2 and §3.2
// (docs/PHASE4_DESIGN.md §6.1, §6.2; it replaces Phase 3's AddContactSheet).
// A hardened sheet like ComposeSheet: a HardenedWindow that gets
// Hardening.apply when it is made and again from the window it joins. Its
// labels, buttons and messages are interface text. The own address, an
// invite code, an inviter's address and code (ContactTextViews) and the
// field (a ContactField) are contact data, drawn only in the protected
// layer. Rows, top to bottom:
// 1. «Din adresse:», the own address, and Kopier adressen min, which puts
//    the address's bytes on the pasteboard (ContactPasteboard: plain text
//    marked concealed and transient, emptied after 60 s and at quit if
//    still Brev's).
// 2. Lag invitasjon, one click and no Touch ID (owner answer 7):
//    `createInvite` on `Session.net`; the code shows on two lines (up to the
//    inviter's address, then the fingerprint and the secret), and Kopier
//    koden puts its bytes on the pasteboard. The sheet owns the code (a
//    SecretBytes) until the next code, a close or a lock. invite.note below.
// 3. «Adresse eller invitasjonskode:», the field (typed, or ⌘V) and Legg til
//    (or Return or ⌘↩ in the field). Text that starts with "brev1." is an
//    invite code: `openInvite` checks it against the relay's answer, the
//    field is wiped, and «Invitert av:» shows the inviter's address and code
//    with Godta invitasjonen, which redeems it (`redeemInvite`): the inviter
//    becomes an approved, verified contact and the sheet closes with it. A
//    root invite cannot be redeemed once registered (invite.error.invalid).
//    Anything else is an address: `addContact` asks the contact; the field
//    is wiped and request.sent shows, or, if the contact already takes the
//    user's letters, the sheet closes with it.
// 4. One fixed text: the outcome or the error, or none.
// Every button is a HumanButton. While a call is on its way the field is
// read-only and the buttons are off. Lukk (or Escape) closes the sheet, and
// so does a lock. However it closes, the field, the own address, the code
// and the inviter are wiped and their pixels zeroed, secure event input goes
// off, and a result that arrives after that is dropped. The pasteboard is
// not cleared on close or lock (the owner's rule: the user may paste the
// address or code into another app, which locks Brev). The completion gets
// the contact added last, after Lukk, Escape or an add or redeem that
// closes the sheet; a lock reports nothing (nothing may be read while the
// lock sequence runs, §1.10). Logs say only what happened, or the error's
// variant.

import AppKit
import os

final class ContactSheet: HardenedWindow, ContentHolder {
    private static let log = Logger(subsystem: "no.brev.app", category: "contact")
    private static let width: CGFloat = 600
    private static let margin: CGFloat = 20
    private static let codeWidth = ContactHeaderView.codeWidth

    let field = ContactField()
    /// Row 0: the own address.
    let ownAddress = ContactTextView(rows: 1)
    /// Rows 0 and 1: an invite code made here.
    let codeView = ContactTextView(rows: 2)
    /// Row 0: an opened invite's inviter's address; row 1: its code.
    let inviterView = ContactTextView(rows: 2)
    private(set) var copyAddressButton: HumanButton?
    private(set) var makeInviteButton: HumanButton?
    private(set) var copyCodeButton: HumanButton?
    private(set) var addButton: HumanButton?
    private(set) var acceptInviteButton: HumanButton?
    private var closeButton: HumanButton?
    private let inviterLabel = InterfaceText(L10n.inviteFrom, width: 90, alignment: .left)

    private let requestSent = ContactSheet.message(L10n.requestSent)
    private let notFound = ContactSheet.message(L10n.contactErrorNotFound)
    private let duplicate = ContactSheet.message(L10n.contactErrorDuplicate)
    private let ownAddressError = ContactSheet.message(L10n.contactErrorSelf)
    private let invalidAddress = ContactSheet.message(L10n.addressErrorInvalid)
    private let requestLimit = ContactSheet.message(L10n.requestErrorLimit)
    private let inviteInvalid = ContactSheet.message(L10n.inviteErrorInvalid)
    private let inviteMismatch = ContactSheet.message(L10n.inviteErrorMismatch)
    private let inviteLimit = ContactSheet.message(L10n.inviteErrorLimit)
    private let inviteFailed = ContactSheet.message(L10n.inviteErrorFailed)
    private let keyChanged = ContactSheet.message(L10n.contactChanged)
    private let netFailure = ContactSheet.message(L10n.netError)
    private let failure = ContactSheet.message(L10n.contactErrorFailed)
    private var messages: [InterfaceText] {
        [requestSent, notFound, duplicate, ownAddressError, invalidAddress, requestLimit, inviteInvalid,
         inviteMismatch, inviteLimit, inviteFailed, keyChanged, netFailure, failure]
    }

    private weak var session: Session?
    /// True while a call is on `Session.net`.
    private(set) var busy = false
    /// Bumped by `wipeAll` (every close and the lock sequence): a result of
    /// a call begun before it is dropped.
    private var epoch = 0
    /// The invite code shown (at most 96 ASCII bytes), owned here.
    private(set) var code: SecretBytes?
    /// An invite was opened and waits for Godta invitasjonen.
    private(set) var inviteOpened = false
    /// The contact added or redeemed last, for the completion.
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

    private init(session: Session) {
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
        InterfaceText(text, width: width - 2 * margin, alignment: .left)
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

    private func makeContent() -> NSView {
        let inner = Self.width - 2 * Self.margin
        let line = ContactTextView.rowHeight
        let copyMe = HumanButton(title: L10n.contactsCopyMe, target: self, action: #selector(copyAddress(_:)))
        let make = HumanButton(title: L10n.inviteMake, target: self, action: #selector(makeInvite(_:)))
        let copyCode = HumanButton(title: L10n.inviteCopy, target: self, action: #selector(copyCode(_:)))
        let add = HumanButton(title: L10n.contactsAdd, target: self, action: #selector(addPressed(_:)))
        let accept = HumanButton(title: L10n.inviteAccept, target: self, action: #selector(acceptInvite(_:)))
        let close = HumanButton(title: L10n.contactsClose, target: self, action: #selector(closeSheet(_:)))
        close.keyEquivalent = "\u{1b}"
        copyAddressButton = copyMe
        makeInviteButton = make
        copyCodeButton = copyCode
        addButton = add
        acceptInviteButton = accept
        closeButton = close

        let scroll = NSScrollView()
        scroll.borderType = .bezelBorder
        scroll.drawsBackground = true
        scroll.backgroundColor = .textBackgroundColor
        scroll.verticalScrollElasticity = .none
        scroll.horizontalScrollElasticity = .none
        scroll.documentView = field

        // The messages share one place below the field.
        let messageArea = NSView()
        for m in messages {
            m.translatesAutoresizingMaskIntoConstraints = false
            messageArea.addSubview(m)
            NSLayoutConstraint.activate([m.topAnchor.constraint(equalTo: messageArea.topAnchor),
                                         m.leadingAnchor.constraint(equalTo: messageArea.leadingAnchor)])
        }
        let spacer = NSView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        let stack = NSStackView(views: [
            InterfaceText(L10n.contactsTitle, style: .heading, width: inner, alignment: .left),
            Self.row([InterfaceText(L10n.contactsMe, width: 90, alignment: .left), Self.sized(ownAddress, 260, line),
                      copyMe]),
            Self.row([make, copyCode]),
            Self.sized(codeView, inner, 2 * line),
            InterfaceText(L10n.inviteNote, width: inner, alignment: .left),
            InterfaceText(L10n.contactsField, width: inner, alignment: .left),
            Self.row([Self.sized(scroll, inner - 110, 26), add]),
            Self.row([inviterLabel, Self.sized(inviterView, Self.codeWidth, 2 * line), accept]),
            Self.sized(messageArea, inner, 36),
            Self.row([spacer, close]),
        ])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 10
        // Hidden views keep their place, so the sheet keeps its size.
        stack.detachesHiddenViews = false
        stack.edgeInsets = NSEdgeInsets(top: Self.margin, left: Self.margin, bottom: Self.margin, right: Self.margin)
        stack.setCustomSpacing(16, after: stack.arrangedSubviews[0])
        stack.setCustomSpacing(16, after: stack.arrangedSubviews[4])
        stack.arrangedSubviews.last?.widthAnchor.constraint(equalToConstant: inner).isActive = true
        return stack
    }

    /// The own address in row 1 (the view owns it; the code is wiped).
    private func showOwnAddress() {
        do {
            if let me = try session?.me() {
                me.code.wipe()
                ownAddress.set(0, me.address)
            }
        } catch {
            Self.log.error("me failed: \(Self.name(error), privacy: .public)")
        }
    }

    /// Shows `message` (or none), with the buttons and the field on unless
    /// a call is under way. Kopier koden needs a code; Godta invitasjonen
    /// and «Invitert av:» an opened invite.
    private func show(_ message: InterfaceText?, busy: Bool = false) {
        self.busy = busy
        for m in messages { m.isHidden = m !== message }
        field.isEditable = !busy
        for b in [copyAddressButton, makeInviteButton, addButton, closeButton] { b?.isEnabled = !busy }
        copyCodeButton?.isEnabled = !busy && code != nil
        inviterLabel.isHidden = !inviteOpened
        acceptInviteButton?.isHidden = !inviteOpened
        acceptInviteButton?.isEnabled = !busy
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

    /// Lag invitasjon: a new code from the relay, shown in row 2.
    @objc func makeInvite(_ sender: Any?) {
        guard !busy, let session, sheetParent != nil else { return }
        show(nil, busy: true)
        let started = epoch
        Session.net.async {
            let result = Result { try session.createInvite() }
            DispatchQueue.main.async { [weak self] in
                guard let self, started == self.epoch else {
                    if case .success(let code) = result { code.wipe() }
                    return
                }
                self.made(result)
            }
        }
    }

    private func made(_ result: Result<SecretBytes, Error>) {
        switch result {
        case .success(let made):
            clearCode()
            code = made
            let split = Self.lines(of: made)
            codeView.set(0, split.0)
            codeView.set(1, split.1)
            Self.log.notice("invite made")
            show(nil)
        case .failure(let error):
            Self.log.error("invite failed: \(Self.name(error), privacy: .public)")
            switch error {
            case BrevError.RateLimited: show(inviteLimit)
            case BrevError.Network: show(netFailure)
            default: show(inviteFailed)
            }
        }
    }

    /// Kopier koden: the shown code's bytes on the pasteboard.
    @objc func copyCode(_ sender: Any?) {
        guard !busy, let code else { return }
        ContactPasteboard.write(code)
        Self.log.notice("invite copied")
    }

    @objc private func addPressed(_ sender: Any?) {
        add()
    }

    /// Legg til: an invite code is opened, an address asked.
    func add() {
        guard !busy, let session, sheetParent != nil else { return }
        guard field.model.text.length > 0 else { return NSSound.beep() }
        clearInviter()
        let typed = SecretBytes(capacity: 3 * field.model.text.length)
        Transcode.utf16ToUTF8(field.model.text, into: typed)
        let isCode = typed.withBytes { $0.starts(with: Self.codePrefix) }
        show(nil, busy: true)
        let started = epoch
        if isCode {
            Session.net.async {
                let result = Result { try session.openInvite(code: typed) }
                typed.wipe()
                DispatchQueue.main.async { [weak self] in
                    guard let self, started == self.epoch else {
                        if case .success(let item) = result { Self.wipe(item) }
                        return
                    }
                    self.opened(result)
                }
            }
        } else {
            typed.wipe()
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
    }

    /// "brev1." (docs/PHASE4_DESIGN.md §3.1); the field folds A–Z.
    private static let codePrefix: [UInt8] = [0x62, 0x72, 0x65, 0x76, 0x31, 0x2E]

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

    /// An opened invite: the inviter in row 3 and Godta invitasjonen; the
    /// field is wiped (Rust keeps the code's secret until it is used or
    /// the session locks).
    private func opened(_ result: Result<InviteItem, Error>) {
        switch result {
        case .success(let item) where item.root:
            Self.wipe(item)
            Self.log.error("open invite: a root invite once registered")
            show(inviteInvalid)
        case .success(let item):
            field.wipe()
            inviterView.set(0, item.address)
            inviterView.set(1, Self.text(item.code, 0..<item.code.count))
            item.code.wipe()
            inviteOpened = true
            Self.log.notice("invite opened")
            show(nil)
        case .failure(let error):
            Self.log.error("open invite failed: \(Self.name(error), privacy: .public)")
            switch error {
            case BrevError.InviteInvalid: show(inviteInvalid)
            case BrevError.InviteMismatch: show(inviteMismatch)
            case BrevError.KeyChanged: show(keyChanged)
            case BrevError.Malformed: show(ownAddressError)
            case BrevError.Network: show(netFailure)
            default: show(inviteFailed)
            }
        }
    }

    /// Godta invitasjonen: the opened invite is redeemed; the inviter is
    /// then an approved, verified contact, and the sheet closes with it.
    @objc func acceptInvite(_ sender: Any?) {
        guard !busy, inviteOpened, let session, sheetParent != nil else { return }
        show(nil, busy: true)
        let started = epoch
        Session.net.async {
            let result = Result { try session.redeemInvite() }
            DispatchQueue.main.async { [weak self] in
                guard let self, started == self.epoch else { return }
                self.redeemed(result)
            }
        }
    }

    private func redeemed(_ result: Result<Data, Error>) {
        switch result {
        case .success(let id):
            added = id
            Self.log.notice("invite redeemed")
            endWith(.OK)
        case .failure(let error):
            Self.log.error("redeem failed: \(Self.name(error), privacy: .public)")
            switch error {
            case BrevError.Network: show(netFailure)
            case BrevError.InviteInvalid:
                clearInviter()
                show(inviteInvalid)
            default:
                clearInviter()
                show(inviteFailed)
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

    /// The code's two lines: up to and with the "." after the inviter's
    /// address, then the rest (the whole code on line 1 if it has no such
    /// dot).
    private static func lines(of code: SecretBytes) -> (SecretText, SecretText?) {
        let cut = code.withBytes { b -> Int? in
            var dots = 0
            for (i, c) in b.enumerated() where c == 0x2E {
                dots += 1
                if dots == 2 { return i + 1 }
            }
            return nil
        }
        guard let cut else { return (text(code, 0..<code.count), nil) }
        return (text(code, 0..<cut), text(code, cut..<code.count))
    }

    /// ASCII bytes `range` of `bytes` as UTF-16 in a new SecretText.
    private static func text(_ bytes: SecretBytes, _ range: Range<Int>) -> SecretText {
        let t = SecretText(maxUnits: max(range.count, 1))
        bytes.withBytes { Transcode.utf8ToUTF16(UnsafeRawBufferPointer(rebasing: $0[range]), into: t) }
        return t
    }

    private static func wipe(_ item: InviteItem) {
        item.address.wipe()
        item.code.wipe()
    }

    private func clearCode() {
        code?.wipe()
        code = nil
        codeView.clear()
    }

    private func clearInviter() {
        inviteOpened = false
        inviterView.clear()
    }

    /// A BrevError's variant name; never an error's message.
    private static func name(_ error: Error) -> String {
        (error as? BrevError).map { "\($0)" } ?? "other"
    }

    // MARK: - ContentHolder

    /// No field keeps focus and secure event input is off; the field, the
    /// own address, the code and the inviter are wiped and their pixels
    /// zeroed; a call still under way is dropped. Every close runs it, and
    /// the lock sequence before it ends the sheet.
    func wipeAll() {
        epoch &+= 1
        _ = makeFirstResponder(nil)
        SecureInput.disable()
        field.wipe()
        ownAddress.clear()
        clearCode()
        clearInviter()
        show(nil)
    }
}
