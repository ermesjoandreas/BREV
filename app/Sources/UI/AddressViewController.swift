// AddressViewController.swift — "Velg adressen din": registering the own
// address. Registration is open: no invite (D-0116).
//
// Upholds CLAUDE.md §1.2, §1.3, §1.8, §1.10, §2 and §3.2
// (docs/PHASE3_DESIGN.md §3.2, §3.5, §6.4, §6.5; docs/PHASE4_DESIGN.md §5.3).
// Shown after unlock while no address is registered: after onboarding's
// first unlock, and after any later unlock until a registration succeeds.
// Fixed text (InterfaceText), one single-line SecureComposeView with the
// address charset (32 units; a–z, 0–9 and "-"; A–Z become a–z; anything
// else beeps), in which the address is typed, held and drawn like content,
// and Registrer (a HumanButton, or Return or ⌘↩ in the field). Registrer:
// `registerRequest` on main (no I/O) gives the digest; the signer signs it
// with the identity key, which is the one Touch ID prompt, reason
// register.reason (Avbryt there returns to editing); `register` posts it on
// `Session.net`. Success wipes the field and calls `onRegistered`. When the
// relay cannot be reached after the signature, net.error shows and
// Registrer posts the same signed registration again, without a second
// prompt; Escape returns to editing instead. A taken or invalid address
// shows its text. The field is read-only while a step is under way. The
// lock sequence wipes the field (ContentHolder), and a step whose result
// arrives after that is dropped. Logs say only that the address was
// registered, or the error's variant.

import AppKit
import os

final class AddressViewController: NSViewController, ContentHolder {
    private static let log = Logger(subsystem: "no.brev.app", category: "address")
    private static let fieldWidth: CGFloat = 320

    private enum Step {
        /// The address field can be edited; Registrer asks for Touch ID.
        case editing
        /// Touch ID or the relay.
        case working
        /// Signed, but the relay could not be reached: Registrer posts again.
        case retry
    }

    /// The address was registered.
    var onRegistered: () -> Void = {}

    /// The address.
    let field: SecureComposeView
    private(set) var registerButton: HumanButton?
    private let addressTitle = InterfaceText(L10n.addressTitle, style: .title, width: PageView.columnWidth)
    private let addressBody = InterfaceText(L10n.addressBody, style: .secondary, width: PageView.columnWidth)
    private let taken = AddressViewController.message(L10n.addressErrorTaken)
    private let invalid = AddressViewController.message(L10n.addressErrorInvalid)
    private let netFailure = AddressViewController.message(L10n.netError)
    private let failure = AddressViewController.message(L10n.addressErrorFailed)
    private var messages: [InterfaceText] {
        [taken, invalid, netFailure, failure]
    }
    private weak var session: Session?
    private let signer: Signer
    private var step = Step.editing
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

    /// The field's scroll view in a rounded 1 pt border (as on the Kontakter
    /// sheet; docs/UI_REDESIGN.md §2.9).
    private static func scroll(_ document: NSView) -> NSView {
        let scroll = NSScrollView()
        scroll.borderType = .noBorder
        scroll.drawsBackground = false
        scroll.verticalScrollElasticity = .none
        scroll.horizontalScrollElasticity = .none
        scroll.automaticallyAdjustsContentInsets = false
        scroll.documentView = document
        let border = FieldBorder()
        scroll.translatesAutoresizingMaskIntoConstraints = false
        border.addSubview(scroll)
        NSLayoutConstraint.activate([
            border.widthAnchor.constraint(equalToConstant: Self.fieldWidth),
            border.heightAnchor.constraint(equalToConstant: 30),
            scroll.topAnchor.constraint(equalTo: border.topAnchor, constant: 1),
            scroll.bottomAnchor.constraint(equalTo: border.bottomAnchor, constant: -1),
            scroll.leadingAnchor.constraint(equalTo: border.leadingAnchor, constant: 2),
            scroll.trailingAnchor.constraint(equalTo: border.trailingAnchor, constant: -2),
        ])
        return border
    }

    override func loadView() {
        let view = NSView(frame: NSRect(x: 0, y: 0, width: 900, height: 600))
        let addressScroll = Self.scroll(field)
        let button = PageView.button(L10n.addressRegister, target: self, action: #selector(registerPressed(_:)))
        registerButton = button
        let icon = PageView.symbol("at")
        let stack = NSStackView(views: [icon, addressTitle, addressBody, addressScroll] + messages + [button])
        stack.orientation = .vertical
        stack.alignment = .centerX
        stack.spacing = 12
        stack.detachesHiddenViews = true
        stack.setCustomSpacing(16, after: icon)
        stack.setCustomSpacing(16, after: addressTitle)
        for m in messages { stack.setCustomSpacing(24, after: m) }
        stack.setCustomSpacing(24, after: addressScroll)
        stack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            stack.centerYAnchor.constraint(equalTo: view.centerYAnchor),
        ])
        self.view = view
        show(.editing)
    }

    /// Once shown: the address field has focus.
    func start() {
        view.window?.makeFirstResponder(field)
    }

    /// Moves to `next`, showing `message` or none: the field's editability,
    /// the button and the one text above it.
    private func show(_ next: Step, _ message: InterfaceText? = nil) {
        step = next
        for m in messages { m.isHidden = m !== message }
        registerButton?.isEnabled = next != .working
        field.isEditable = next == .editing
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
        case .working:
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
        onRegistered()
    }

    /// Back to editing with the text that fits `error`.
    private func failed(_ error: Error) {
        kept = nil
        let name = (error as? BrevError).map { "\($0)" }
            ?? UnlockFailure.chain(error).map { "\($0.domain) \($0.code)" }.joined(separator: ", ")
        Self.log.error("register failed: \(name, privacy: .public)")
        switch error {
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

    // MARK: - ContentHolder (lock sequence §8.4 step 3)

    /// The field loses focus (secure event input off), the typed address is
    /// wiped and its pixels zeroed, and a step under way is dropped.
    func wipeAll() {
        epoch &+= 1
        kept = nil
        _ = view.window?.makeFirstResponder(nil)
        SecureInput.disable()
        field.wipe()
        show(.editing)
    }
}
