// ComposeSheet.swift — a new letter to one contact.
//
// Upholds CLAUDE.md §1.2, §1.3, §1.5, §1.6, §1.10, §2 and §3.2
// (docs/PHASE2_DESIGN.md §4.2, §6.2, §7.3, §8.1, §8.4). An own window,
// presented as a sheet on the main window: a HardenedWindow that gets
// Hardening.apply when it is made and again from the window it joins, and
// takes nothing but the fields below. "Til:" and "Emne:" are interface
// text. The recipient is a copy of the contact's name that the sheet owns,
// drawn by RecipientView; the subject and the body are SecureComposeViews.
// Every one of them is a ContentView, so it draws through the protected
// layer. Send (a HumanButton, or ⌘↩ in a field) hands the subject and the
// body to Session.send and closes the sheet; if that fails, compose.error
// shows and the letter stays. Avbryt (a HumanButton, or Escape) closes it
// without sending. However the sheet closes, secure event input goes off
// and its three SecretTexts are wiped; after a send or a cancel GlyphFlush
// replaces what Core Text kept of their lines, and on a lock the lock
// sequence does. The lock sequence wipes the sheet before it ends it
// (RootViewController.wipeContent). No draft survives a close or a lock.
// Logs say only that a letter was sent, or the error's variant.

import AppKit
import os

final class ComposeSheet: HardenedWindow, ContentHolder {
    private static let log = Logger(subsystem: "no.brev.app", category: "compose")
    static let contentSize = NSSize(width: 600, height: 460)
    private static let margin: CGFloat = 20
    private static let labelWidth: CGFloat = 52

    let recipient = RecipientView()
    let subject: SecureComposeView
    let body: SecureComposeView
    private(set) var sendButton: HumanButton?
    private let failure = InterfaceText(L10n.composeError, width: 300, alignment: .left)
    private weak var session: Session?
    private let contact: Data
    /// The thread the letter started, once it is sent.
    private(set) var sentThread: Data?

    /// Shows a new letter to `contact` on `parent`, with the subject
    /// focused. `completion` gets the new thread's id after a send, and nil
    /// after Avbryt, Escape or a lock.
    @discardableResult
    static func present(on parent: NSWindow, to contact: ContactItem, session: Session,
                        completion: @escaping (Data?) -> Void) -> ComposeSheet {
        let sheet = ComposeSheet(contact: contact, session: session, limits: limits())
        parent.beginSheet(sheet) { _ in
            sheet.wipeAll()
            GlyphFlush.flush()
            completion(sheet.sentThread)
        }
        sheet.makeFirstResponder(sheet.subject)
        Hardening.assertAllWindows()
        return sheet
    }

    private init(contact: ContactItem, session: Session, limits: Limits) {
        subject = SecureComposeView(maxBytes: Int(limits.maxSubject), multiline: false)
        body = SecureComposeView(maxBytes: Int(limits.maxBody), multiline: true)
        self.contact = contact.id
        self.session = session
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
        let send = HumanButton(title: L10n.composeSend, target: self, action: #selector(sendPressed(_:)))
        sendButton = send
        failure.isHidden = true
        let buttons = NSStackView(views: [cancel, send])
        buttons.spacing = 12
        for v in [to, about, recipient, subjectField, bodyField, failure, buttons] as [NSView] {
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
            failure.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: m),
            failure.centerYAnchor.constraint(equalTo: buttons.centerYAnchor),
        ])
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

    // MARK: - Send and cancel

    @objc private func sendPressed(_ sender: Any?) {
        send()
    }

    /// Sends the letter and closes the sheet. On failure compose.error shows
    /// and the letter stays.
    func send() {
        guard sentThread == nil, let session, let parent = sheetParent else { return }
        do {
            sentThread = try session.send(to: contact, subject: subject.model.text, body: body.model.text)
            Self.log.notice("letter sent")
            parent.endSheet(self, returnCode: .OK)
        } catch {
            let name = (error as? BrevError).map { "\($0)" } ?? "other"
            Self.log.error("send failed: \(name, privacy: .public)")
            failure.isHidden = false
        }
    }

    @objc private func cancel(_ sender: Any?) {
        sheetParent?.endSheet(self, returnCode: .cancel)
    }

    // MARK: - ContentHolder

    /// No field keeps focus and secure event input is off; the recipient,
    /// the subject and the body are wiped, and their pixels zeroed. Every
    /// close runs it, and the lock sequence before it ends the sheet.
    /// Repeating it is harmless.
    func wipeAll() {
        _ = makeFirstResponder(nil)
        SecureInput.disable()
        recipient.clear()
        subject.wipe()
        body.wipe()
        failure.isHidden = true
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
