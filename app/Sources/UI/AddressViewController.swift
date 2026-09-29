// AddressViewController.swift — "Lim inn invitasjonen", then "Velg adressen
// din": registering the own address with an invite code.
//
// Upholds CLAUDE.md §1.2, §1.3, §1.8, §1.10, §2 and §3.2
// (docs/PHASE3_DESIGN.md §3.2, §3.5, §6.4, §6.5; docs/PHASE4_DESIGN.md §5.3,
// §6.1). Shown after unlock while no address is registered: after
// onboarding's first unlock, and after any later unlock until a
// registration succeeds. Fixed text (InterfaceText) and two steps.
// Step 1, the invite: a ContactField (an address or invite code field: typed,
// or ⌘V), in which the code is held and drawn like content, and Fortsett (a
// HumanButton, or Return or ⌘↩ in the field): `openInvite` on
// `Session.net` checks the code against the relay's answer (no token, so it
// works before registration). An unknown, used or expired code shows
// invite.error.invalid, one that does not match the relay's key
// invite.error.mismatch (nothing is stored or sent). A checked code wipes
// the field and leads to step 2, with «Invitert av:» and the inviter's
// address and code (protected), or invite.root for the operator's invite.
// Step 2, the address: one single-line SecureComposeView with the address
// charset (32 units; a–z, 0–9 and "-"; A–Z become a–z; anything else beeps),
// in which the address is typed, held and drawn like content, and Registrer
// (a HumanButton, or Return or ⌘↩ in the field). Registrer:
// `registerRequest` on main (no I/O) gives the digest; the signer signs it
// with the identity key, which is the one Touch ID prompt, reason
// register.reason (Avbryt there returns to editing); `register` posts it on
// `Session.net`. Success wipes the field and calls `onRegistered`. When the
// relay cannot be reached after the signature, net.error shows and
// Registrer posts the same signed registration again, without a second
// prompt; Escape returns to editing instead. A taken or invalid address
// shows its text. An invite the relay no longer takes (used or expired
// meanwhile, or none kept after a lock) returns to step 1 with
// invite.error.invalid. The fields are read-only while a step is under way.
// The lock sequence wipes both fields and the inviter (ContentHolder), and
// a step whose result arrives after that is dropped. Logs say only that the
// invite was checked or the address registered, or the error's variant.

import AppKit
import os

final class AddressViewController: NSViewController, ContentHolder {
    private static let log = Logger(subsystem: "no.brev.app", category: "address")
    private static let fieldWidth: CGFloat = 320

    private enum Step {
        /// Step 1: the invite field can be edited; Fortsett checks it.
        case invite
        /// The relay checks the invite.
        case opening
        /// Step 2: the address field can be edited; Registrer asks for
        /// Touch ID.
        case editing
        /// Touch ID or the relay.
        case working
        /// Signed, but the relay could not be reached: Registrer posts again.
        case retry
    }

    /// The address was registered.
    var onRegistered: () -> Void = {}

    /// Step 1's field: the invite code.
    let inviteField = ContactField()
    /// Step 2's field: the address.
    let field: SecureComposeView
    /// Row 0: the inviter's address; row 1: its code.
    let inviterView = ContactTextView(rows: 2)
    private(set) var nextButton: HumanButton?
    private(set) var registerButton: HumanButton?
    private let inviteTitle = InterfaceText(L10n.addressInviteTitle, style: .title, width: PageView.columnWidth)
    private let inviteBody = InterfaceText(L10n.addressInviteBody, width: PageView.columnWidth)
    private let addressTitle = InterfaceText(L10n.addressTitle, style: .title, width: PageView.columnWidth)
    private let addressBody = InterfaceText(L10n.addressBody, width: PageView.columnWidth)
    private let root = InterfaceText(L10n.inviteRoot, width: PageView.columnWidth)
    private var inviter: NSStackView?
    private var inviteScroll: NSScrollView?
    private var addressScroll: NSScrollView?
    private let taken = AddressViewController.message(L10n.addressErrorTaken)
    private let invalid = AddressViewController.message(L10n.addressErrorInvalid)
    private let inviteInvalid = AddressViewController.message(L10n.inviteErrorInvalid)
    private let inviteMismatch = AddressViewController.message(L10n.inviteErrorMismatch)
    private let inviteFailed = AddressViewController.message(L10n.inviteErrorFailed)
    private let netFailure = AddressViewController.message(L10n.netError)
    private let failure = AddressViewController.message(L10n.addressErrorFailed)
    private var messages: [InterfaceText] {
        [taken, invalid, inviteInvalid, inviteMismatch, inviteFailed, netFailure, failure]
    }
    private weak var session: Session?
    private let signer: Signer
    private var step = Step.invite
    /// Which invite was checked: nil before, true for the operator's.
    private var rootInvite: Bool?
    /// Bumped by `wipeAll`: a result of a step begun before it is dropped.
    private var epoch = 0
    /// The DER signature of the registration Rust keeps after `Network`,
    /// and the digest it signs (for the attestation). Not secret.
    private var kept: (signature: Data, digest: Data)?

    /// Signs a 32-byte digest with the identity key and calls back on main
    /// with the DER signature: SignService in the app (Touch ID), a software
    /// key in the view host.
    typealias Signer = (_ digest: Data, _ done: @escaping (Result<Data, Error>) -> Void) -> Void

    init(session: Session, signer: @escaping Signer) {
        field = SecureComposeView(maxBytes: Int(limits().maxAddress), multiline: false, charset: .address)
        self.session = session
        self.signer = signer
        super.init(nibName: nil, bundle: nil)
        inviteField.onReturn = { [weak self] in self?.next() }
        inviteField.onSend = { [weak self] in self?.next() }
        field.onReturn = { [weak self] in self?.register() }
        field.onSend = { [weak self] in self?.register() }
        field.onCancel = { [weak self] in self?.backToEditing() }
    }

    required init?(coder: NSCoder) {
        nil
    }

    private static func message(_ text: String) -> InterfaceText {
        InterfaceText(text, width: PageView.columnWidth)
    }

    private static func scroll(_ document: NSView) -> NSScrollView {
        let scroll = NSScrollView()
        scroll.borderType = .bezelBorder
        scroll.drawsBackground = true
        scroll.backgroundColor = .textBackgroundColor
        scroll.verticalScrollElasticity = .none
        scroll.horizontalScrollElasticity = .none
        scroll.documentView = document
        NSLayoutConstraint.activate([
            scroll.widthAnchor.constraint(equalToConstant: Self.fieldWidth),
            scroll.heightAnchor.constraint(equalToConstant: 28),
        ])
        return scroll
    }

    override func loadView() {
        let view = NSView(frame: NSRect(x: 0, y: 0, width: 900, height: 600))
        let inviteScroll = Self.scroll(inviteField)
        let addressScroll = Self.scroll(field)
        self.inviteScroll = inviteScroll
        self.addressScroll = addressScroll
        inviterView.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            inviterView.widthAnchor.constraint(equalToConstant: ContactBar.codeWidth),
            inviterView.heightAnchor.constraint(equalToConstant: 2 * ContactTextView.rowHeight),
        ])
        let inviter = NSStackView(views: [InterfaceText(L10n.inviteFrom, width: 90, alignment: .right), inviterView])
        inviter.orientation = .horizontal
        inviter.alignment = .top
        inviter.spacing = 8
        self.inviter = inviter
        let next = PageView.button(L10n.addressInviteNext, target: self, action: #selector(nextPressed(_:)))
        let button = PageView.button(L10n.addressRegister, target: self, action: #selector(registerPressed(_:)))
        nextButton = next
        registerButton = button
        let stack = NSStackView(views: [inviteTitle, addressTitle, inviteBody, inviteScroll, inviter, root,
                                        addressBody, addressScroll] + messages + [next, button])
        stack.orientation = .vertical
        stack.alignment = .centerX
        stack.spacing = 14
        stack.detachesHiddenViews = true
        stack.setCustomSpacing(24, after: inviteTitle)
        stack.setCustomSpacing(24, after: addressTitle)
        stack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            stack.centerYAnchor.constraint(equalTo: view.centerYAnchor),
        ])
        self.view = view
        show(.invite)
    }

    /// Once shown: the invite field has focus.
    func start() {
        view.window?.makeFirstResponder(inviteField)
    }

    /// Moves to `next`, showing `message` or none: step 1's or step 2's
    /// title, text, field and button, the inviter once checked, the fields'
    /// editability and the one text above the button.
    private func show(_ next: Step, _ message: InterfaceText? = nil) {
        step = next
        let first = next == .invite || next == .opening
        for m in messages { m.isHidden = m !== message }
        for v in [inviteTitle, inviteBody, inviteScroll, nextButton] as [NSView?] { v?.isHidden = !first }
        for v in [addressTitle, addressBody, addressScroll, registerButton] as [NSView?] { v?.isHidden = first }
        inviter?.isHidden = first || rootInvite != false
        root.isHidden = first || rootInvite != true
        nextButton?.isEnabled = next == .invite
        registerButton?.isEnabled = next != .working
        inviteField.isEditable = next == .invite
        field.isEditable = next == .editing
    }

    // MARK: - The invite (docs/PHASE4_DESIGN.md §5.3)

    @objc private func nextPressed(_ sender: Any?) {
        self.next()
    }

    /// Fortsett: the code is checked at the relay (`Session.net`), with a
    /// UTF-8 copy of the field that is wiped when the call returns.
    func next() {
        guard step == .invite, let session else { return }
        guard inviteField.model.text.length > 0 else { return NSSound.beep() }
        let typed = SecretBytes(capacity: 3 * inviteField.model.text.length)
        Transcode.utf16ToUTF8(inviteField.model.text, into: typed)
        show(.opening)
        let started = epoch
        Session.net.async {
            let result = Result { try session.openInvite(code: typed) }
            typed.wipe()
            DispatchQueue.main.async { [weak self] in
                guard let self, started == self.epoch else {
                    if case .success(let item) = result {
                        item.address.wipe()
                        item.code.wipe()
                    }
                    return
                }
                self.opened(result)
            }
        }
    }

    private func opened(_ result: Result<InviteItem, Error>) {
        switch result {
        case .success(let item):
            Self.log.notice("invite checked root=\(item.root, privacy: .public)")
            _ = view.window?.makeFirstResponder(nil)
            inviteField.wipe()
            rootInvite = item.root
            inviterView.clear()
            if !item.root {
                inviterView.set(0, item.address)
                let code = SecretText(maxUnits: max(item.code.count, 1))
                item.code.withBytes { Transcode.utf8ToUTF16($0, into: code) }
                inviterView.set(1, code)
            } else {
                item.address.wipe()
            }
            item.code.wipe()
            show(.editing)
            view.window?.makeFirstResponder(field)
        case .failure(let error):
            Self.log.error("invite failed: \(Self.name(error), privacy: .public)")
            switch error {
            case BrevError.InviteInvalid, BrevError.Malformed: show(.invite, inviteInvalid)
            case BrevError.InviteMismatch: show(.invite, inviteMismatch)
            case BrevError.Network: show(.invite, netFailure)
            default: show(.invite, inviteFailed)
            }
        }
    }

    /// Back to step 1 with `message`: the inviter is forgotten here (Rust
    /// forgot the invite), the address field keeps its text.
    private func backToInvite(_ message: InterfaceText) {
        kept = nil
        rootInvite = nil
        inviterView.clear()
        show(.invite, message)
        view.window?.makeFirstResponder(inviteField)
    }

    // MARK: - Registering (docs/PHASE3_DESIGN.md §3.2)

    @objc private func registerPressed(_ sender: Any?) {
        register()
    }

    /// Registrer: the digest (no I/O), then the one Touch ID prompt; after
    /// `Network`, the same signed registration again.
    func register() {
        guard let session else { return }
        switch step {
        case .invite, .opening, .working:
            return
        case .retry:
            if let kept { post(kept.signature, kept.digest) }
        case .editing:
            guard field.model.text.length > 0 else { return NSSound.beep() }
            let digest: Data
            do {
                digest = try session.registerRequest(address: field.model.text)
            } catch BrevError.Duplicate {
                return registered()   // already registered
            } catch {
                return failed(error)
            }
            show(.working)
            let started = epoch
            signer(digest) { [weak self] result in self?.signed(result, digest, started) }
        }
    }

    /// A cancelled prompt returns to editing.
    private func signed(_ result: Result<Data, Error>, _ digest: Data, _ started: Int) {
        guard started == epoch else { return }
        switch result {
        case .success(let der):
            post(der, digest)
        case .failure(let error):
            if !(error is BrevError), UnlockFailure.classify(error, fingersChanged: false) == .cancelled {
                Self.log.notice("registration cancelled at Touch ID")
                return show(.editing)
            }
            failed(error)
        }
    }

    /// Posts the signed registration on `Session.net`.
    private func post(_ der: Data, _ digest: Data) {
        guard let session else { return }
        show(.working)
        let started = epoch
        Session.net.async {
            let result = Result { try session.register(signature: der, digest: digest) }
            DispatchQueue.main.async { [weak self] in self?.posted(result, der, digest, started) }
        }
    }

    private func posted(_ result: Result<Void, Error>, _ der: Data, _ digest: Data, _ started: Int) {
        guard started == epoch else { return }
        switch result {
        case .success:
            registered()
        case .failure(BrevError.Network):
            Self.log.error("register failed: Network (signed; Registrer posts again)")
            kept = (der, digest)
            show(.retry, netFailure)
        case .failure(let error):
            failed(error)
        }
    }

    private func registered() {
        Self.log.notice("address registered")
        kept = nil
        _ = view.window?.makeFirstResponder(nil)
        field.wipe()
        inviterView.clear()
        onRegistered()
    }

    /// Back to editing with the text that fits `error`; to step 1 if the
    /// invite is gone.
    private func failed(_ error: Error) {
        kept = nil
        let name = (error as? BrevError).map { "\($0)" }
            ?? UnlockFailure.chain(error).map { "\($0.domain) \($0.code)" }.joined(separator: ", ")
        Self.log.error("register failed: \(name, privacy: .public)")
        switch error {
        case BrevError.InviteInvalid: backToInvite(inviteInvalid)
        case BrevError.AddressTaken: show(.editing, taken)
        case BrevError.Malformed: show(.editing, invalid)
        case BrevError.Network: show(.editing, netFailure)
        default: show(.editing, failure)
        }
    }

    /// Escape after `Network`: the signed registration is dropped here (Rust
    /// replaces it at the next Registrer), and the field can be edited.
    private func backToEditing() {
        guard step == .retry else { return }
        kept = nil
        show(.editing)
    }

    /// A BrevError's variant name; never an error's message.
    private static func name(_ error: Error) -> String {
        (error as? BrevError).map { "\($0)" } ?? "other"
    }

    // MARK: - ContentHolder (lock sequence §8.4 step 3)

    /// The fields lose focus (secure event input off), the typed code and
    /// address and the inviter are wiped and their pixels zeroed, and a step
    /// under way is dropped. Rust forgets the checked invite at the lock, so
    /// the page starts again at step 1.
    func wipeAll() {
        epoch &+= 1
        kept = nil
        rootInvite = nil
        _ = view.window?.makeFirstResponder(nil)
        SecureInput.disable()
        inviteField.wipe()
        field.wipe()
        inviterView.clear()
        show(.invite)
    }
}
