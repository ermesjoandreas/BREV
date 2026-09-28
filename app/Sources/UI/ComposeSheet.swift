// ComposeSheet.swift — a new letter to one contact.
//
// Upholds CLAUDE.md §1.2, §1.3, §1.5, §1.6, §1.10, §2 and §3.2
// (docs/PHASE2_DESIGN.md §4.2, §6.2, §7.3, §8.1, §8.4; docs/PHASE3_DESIGN.md
// §3.2, §6.5). An own window, presented as a sheet on the main window: a
// HardenedWindow that gets Hardening.apply when it is made and again from
// the window it joins, and takes nothing but the fields below. "Til:" and
// "Emne:" are interface text. The recipient is a copy of the contact's name
// (its address) that the sheet owns, drawn by RecipientView; the subject and
// the body are SecureComposeViews. Every one of them is a ContentView, so it
// draws through the protected layer.
// Send (a HumanButton, or ⌘↩ in a field) sends in the three steps of
// PHASE3 §3.2, with "Sender …" shown, the buttons disabled and the fields
// read-only meanwhile: `prepareSend` on `Session.net` (no content; a
// changed key shows compose.keychanged and keeps the letter), then on main
// `signRequest` (the content, no I/O), the one Touch ID prompt through the
// signer (SignService; Avbryt there returns to editing), `attachSignature`,
// and `submit` on `Session.net`, which closes the sheet. When the relay
// fails after the letter is signed, net.error and Prøv igjen show: that
// sends the same signed letter again (`submit` only, no second prompt). A
// step whose result arrives after the sheet was wiped (a close or a lock,
// which also makes Rust forget the letter) is dropped. Avbryt (a
// HumanButton, or Escape) closes it without sending; so does a lock. However
// the sheet closes, secure event input goes off, Rust forgets an unsent
// letter (`cancelSend`) and the three SecretTexts are wiped; after a send or
// a cancel GlyphFlush replaces what Core Text kept of their lines, and on a
// lock the lock sequence does. The lock sequence wipes the sheet before it
// ends it (RootViewController.wipeContent). No draft survives a close or a
// lock. Logs say only that a letter was sent, or the error's variant or
// codes.

import AppKit
import os

final class ComposeSheet: HardenedWindow, ContentHolder {
    /// Signs a 32-byte digest with the identity key and calls back on main
    /// with the DER signature: SignService in the app (Touch ID), a software
    /// key in the view host.
    typealias Signer = (_ digest: Data, _ done: @escaping (Result<Data, Error>) -> Void) -> Void

    private static let log = Logger(subsystem: "no.brev.app", category: "compose")
    static let contentSize = NSSize(width: 600, height: 460)
    private static let margin: CGFloat = 20
    private static let labelWidth: CGFloat = 52
    private static let messageWidth: CGFloat = 300

    /// Where a letter is (PHASE3 §3.2).
    private enum Step {
        /// The fields can be edited; Send and Avbryt work.
        case editing
        /// A call to the relay, or the steps on main around it.
        case sending
        /// The Touch ID prompt is up.
        case signing
        /// The signed letter did not reach the relay: Prøv igjen or Avbryt.
        case retry
    }

    let recipient = RecipientView()
    let subject: SecureComposeView
    let body: SecureComposeView
    private(set) var sendButton: HumanButton?
    private(set) var retryButton: HumanButton?
    private var cancelButton: HumanButton?
    private let failure = InterfaceText(L10n.composeError, width: messageWidth, alignment: .left)
    private let keyChanged = InterfaceText(L10n.composeKeyChanged, width: messageWidth, alignment: .left)
    private let netFailure = InterfaceText(L10n.netError, width: messageWidth, alignment: .left)
    private let sending = InterfaceText(L10n.composeSending, width: messageWidth, alignment: .left)
    private weak var session: Session?
    private let contact: Data
    private let signer: Signer
    private var step = Step.editing
    /// Bumped by `wipeAll` (every close and the lock sequence): a result of
    /// a step begun before it is dropped.
    private var epoch = 0
    /// The thread the letter started, once it is sent.
    private(set) var sentThread: Data?

    /// Shows a new letter to `contact` on `parent`, with the subject
    /// focused. `completion` gets the new thread's id after a send, and nil
    /// after Avbryt, Escape or a lock.
    @discardableResult
    static func present(on parent: NSWindow, to contact: ContactItem, session: Session, signer: @escaping Signer,
                        completion: @escaping (Data?) -> Void) -> ComposeSheet {
        let sheet = ComposeSheet(contact: contact, session: session, signer: signer, limits: limits())
        parent.beginSheet(sheet) { _ in
            if sheet.sentThread == nil { session.cancelSend() }
            sheet.wipeAll()
            GlyphFlush.flush()
            completion(sheet.sentThread)
        }
        sheet.makeFirstResponder(sheet.subject)
        Hardening.assertAllWindows()
        return sheet
    }

    private init(contact: ContactItem, session: Session, signer: @escaping Signer, limits: Limits) {
        subject = SecureComposeView(maxBytes: Int(limits.maxSubject), multiline: false)
        body = SecureComposeView(maxBytes: Int(limits.maxBody), multiline: true)
        self.contact = contact.id
        self.session = session
        self.signer = signer
        super.init(contentRect: NSRect(origin: .zero, size: Self.contentSize), styleMask: [.titled],
                   backing: .buffered, defer: false)
        Hardening.apply(self)
        isReleasedWhenClosed = false
        recipient.show(contact.name.copy())
        for field in [subject, body] {
            field.onSend = { [weak self] in self?.send() }
            field.onCancel = { [weak self] in self?.cancel(nil) }
        }
        subject.onOtherField = { [weak self] in _ = self?.makeFirstResponder(self?.body) }
        body.onOtherField = { [weak self] in _ = self?.makeFirstResponder(self?.subject) }
        contentView = makeContent()
        initialFirstResponder = subject
        show(.editing)
    }

    // MARK: - Content

    private func makeContent() -> NSView {
        let root = NSView(frame: NSRect(origin: .zero, size: Self.contentSize))
        let to = InterfaceText(L10n.composeTo, width: Self.labelWidth, alignment: .right)
        let about = InterfaceText(L10n.composeSubject, width: Self.labelWidth, alignment: .right)
        let subjectField = Self.field(subject, multiline: false)
        let bodyField = Self.field(body, multiline: true)
        let cancel = HumanButton(title: L10n.composeCancel, target: self, action: #selector(cancel(_:)))
        cancel.keyEquivalent = "\u{1b}"
        cancelButton = cancel
        let retry = HumanButton(title: L10n.composeRetry, target: self, action: #selector(retryPressed(_:)))
        retryButton = retry
        let send = HumanButton(title: L10n.composeSend, target: self, action: #selector(sendPressed(_:)))
        sendButton = send
        let buttons = NSStackView(views: [cancel, retry, send])
        buttons.spacing = 12
        let messages = [failure, keyChanged, netFailure, sending]
        for v in [to, about, recipient, subjectField, bodyField, buttons] + messages as [NSView] {
            v.translatesAutoresizingMaskIntoConstraints = false
            root.addSubview(v)
        }
        let m = Self.margin
        NSLayoutConstraint.activate([
            recipient.topAnchor.constraint(equalTo: root.topAnchor, constant: m),
            recipient.leadingAnchor.constraint(equalTo: to.trailingAnchor, constant: 8),
            recipient.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -m),
            recipient.heightAnchor.constraint(equalToConstant: 22),
            to.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: m),
            to.centerYAnchor.constraint(equalTo: recipient.centerYAnchor),

            subjectField.topAnchor.constraint(equalTo: recipient.bottomAnchor, constant: 10),
            subjectField.leadingAnchor.constraint(equalTo: recipient.leadingAnchor),
            subjectField.trailingAnchor.constraint(equalTo: recipient.trailingAnchor),
            subjectField.heightAnchor.constraint(equalToConstant: 26),
            about.leadingAnchor.constraint(equalTo: to.leadingAnchor),
            about.centerYAnchor.constraint(equalTo: subjectField.centerYAnchor),

            bodyField.topAnchor.constraint(equalTo: subjectField.bottomAnchor, constant: 12),
            bodyField.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: m),
            bodyField.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -m),

            buttons.topAnchor.constraint(equalTo: bodyField.bottomAnchor, constant: 16),
            buttons.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -m),
            buttons.bottomAnchor.constraint(equalTo: root.bottomAnchor, constant: -m),
        ] + messages.flatMap { [
            $0.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: m),
            $0.centerYAnchor.constraint(equalTo: buttons.centerYAnchor),
        ] })
        return root
    }

    /// A field's scroll view. The subject scrolls sideways, without
    /// scrollers; the body scrolls down.
    private static func field(_ view: SecureComposeView, multiline: Bool) -> NSScrollView {
        let scroll = NSScrollView()
        scroll.borderType = .bezelBorder
        scroll.drawsBackground = true
        scroll.backgroundColor = .textBackgroundColor
        scroll.hasVerticalScroller = multiline
        scroll.autohidesScrollers = true
        if !multiline {
            scroll.verticalScrollElasticity = .none
            scroll.horizontalScrollElasticity = .none
        }
        scroll.documentView = view
        return scroll
    }

    /// Moves to `next`, showing `message` (or "Sender …" while busy): the
    /// buttons, the fields' editability and the one text below the body.
    private func show(_ next: Step, _ message: InterfaceText? = nil) {
        step = next
        let busy = next == .sending || next == .signing
        let shown = busy ? sending : message
        for m in [failure, keyChanged, netFailure, sending] { m.isHidden = m !== shown }
        sendButton?.isHidden = next == .retry
        sendButton?.isEnabled = next == .editing
        retryButton?.isHidden = next != .retry
        cancelButton?.isEnabled = !busy
        subject.isEditable = next == .editing
        body.isEditable = next == .editing
    }

    // MARK: - Send (docs/PHASE3_DESIGN.md §3.2) and cancel

    @objc private func sendPressed(_ sender: Any?) {
        send()
    }

    @objc private func retryPressed(_ sender: Any?) {
        guard step == .retry else { return }
        submit()
    }

    /// Step 0 on `Session.net`: the contact's key at the relay. No content.
    func send() {
        guard step == .editing, sentThread == nil, let session, sheetParent != nil else { return }
        show(.sending)
        let contact = contact, started = epoch
        Session.net.async {
            let result = Result { try session.prepareSend(contact: contact) }
            DispatchQueue.main.async { [weak self] in self?.prepared(result, started) }
        }
    }

    /// Steps 1 and 2 on main: seal the letter (no I/O), then the one Touch
    /// ID prompt.
    private func prepared(_ result: Result<Void, Error>, _ started: Int) {
        guard started == epoch, let session else { return }
        let digest: Data
        do {
            try result.get()
            digest = try session.signRequest(contact: contact, subject: subject.model.text, body: body.model.text)
        } catch {
            return failed(error)
        }
        show(.signing)
        signer(digest) { [weak self] signed in self?.signed(signed, started) }
    }

    /// Step 3 on main: the signature, which Rust checks against the own
    /// key; then step 4. A cancelled prompt returns to editing.
    private func signed(_ result: Result<Data, Error>, _ started: Int) {
        guard started == epoch, let session else { return }
        do {
            try session.attachSignature(try result.get())
        } catch {
            session.cancelSend()
            if !(error is BrevError), UnlockFailure.classify(error, fingersChanged: false) == .cancelled {
                Self.log.notice("send cancelled at Touch ID")
                return show(.editing)
            }
            return failed(error)
        }
        submit()
    }

    /// Step 4 on `Session.net`: posts the signed letter. Accepted: the
    /// sheet closes. `Network`: Prøv igjen sends the same letter again.
    private func submit() {
        guard let session else { return }
        show(.sending)
        let started = epoch
        Session.net.async {
            let result = Result { try session.submit() }
            DispatchQueue.main.async { [weak self] in self?.submitted(result, started) }
        }
    }

    private func submitted(_ result: Result<Data, Error>, _ started: Int) {
        guard started == epoch, let parent = sheetParent else { return }
        switch result {
        case .success(let thread):
            sentThread = thread
            Self.log.notice("letter sent")
            parent.endSheet(self, returnCode: .OK)
        case .failure(BrevError.Network):
            Self.log.error("send failed: Network (signed; Prøv igjen)")
            show(.retry, netFailure)
        case .failure(let error):
            failed(error)
        }
    }

    /// Back to editing with the text that fits `error`. Rust has forgotten
    /// the ticket or the letter, or `cancelSend` does it when the sheet
    /// closes.
    private func failed(_ error: Error) {
        let name = (error as? BrevError).map { "\($0)" }
            ?? UnlockFailure.chain(error).map { "\($0.domain) \($0.code)" }.joined(separator: ", ")
        Self.log.error("send failed: \(name, privacy: .public)")
        switch error {
        case BrevError.KeyChanged: show(.editing, keyChanged)
        case BrevError.Network: show(.editing, netFailure)
        default: show(.editing, failure)
        }
    }

    @objc private func cancel(_ sender: Any?) {
        guard step == .editing || step == .retry else { return }
        sheetParent?.endSheet(self, returnCode: .cancel)
    }

    // MARK: - ContentHolder

    /// No field keeps focus and secure event input is off; the recipient,
    /// the subject and the body are wiped, and their pixels zeroed; a step
    /// still under way is dropped. Every close runs it, and the lock sequence
    /// before it ends the sheet. Repeating it is harmless.
    func wipeAll() {
        epoch &+= 1
        _ = makeFirstResponder(nil)
        SecureInput.disable()
        recipient.clear()
        subject.wipe()
        body.wipe()
        show(.editing)
    }
}

/// The recipient's name in the compose sheet: the first line of a
/// SecretText that the view owns (a copy of the contact's name), clipped at
/// the view's edge, in the content font.
final class RecipientView: ContentView {
    private let layout = TextLayout(font: ContentView.contentFont)
    private(set) var name: SecretText?

    /// Shows `name` from now on. The view owns it and wipes it in `clear()`.
    func show(_ name: SecretText) {
        clear()
        self.name = name
    }

    /// Wipes the name and zeroes its pixels.
    func clear() {
        name?.wipe()
        name = nil
        blank()
        needsDisplay = true
    }

    override func drawContent(in ctx: CGContext, rect: CGRect) {
        guard let name else { return }
        let ascent = CTFontGetAscent(layout.font), descent = CTFontGetDescent(layout.font)
        ctx.saveGState()
        ctx.clip(to: bounds)
        ctx.setFillColor(color(.labelColor))
        layout.drawLine(name, TextLayout.firstLine(name), in: ctx, x: SecureComposeView.inset.width,
                        baseline: (bounds.height - ascent - descent) / 2 + ascent)
        ctx.restoreGState()
    }
}
