// ConfirmSheet.swift — "Slette alle brev?", the only way to a reset, and
// "Godta ny sikkerhetskode?", the only way to accept a contact's new key.
//
// Upholds CLAUDE.md §1.9 (a reset destroys the keys for good, so only a
// human can confirm it) and §2 (docs/PHASE2_DESIGN.md §5.5, §7.1, §8.1;
// docs/PHASE3_DESIGN.md §6.3: a changed key is accepted only after a human
// confirms it): an own sheet window instead of a system alert, so it goes
// through Hardening.apply like every Brev window (a default-sharing sheet on
// an excluded window was captured in the capture spike), and both buttons
// are HumanButtons. Escape is Avbryt; there is no default button, so Return
// never deletes or accepts anything. Locking ends the sheet, which counts as
// Avbryt. Its texts are fixed: the code being accepted is the one the
// contact header shows, never part of this sheet.

import AppKit

final class ConfirmSheet: HardenedWindow {
    enum Kind {
        /// Slett alt og start på nytt (docs/PHASE2_DESIGN.md §5.5).
        case reset
        /// Godta ny kode (docs/PHASE3_DESIGN.md §6.3).
        case acceptKey
    }

    private var confirmed = false
    private(set) var okButton: HumanButton?

    /// Shows the sheet on `parent`. `completion(true)` only after a human
    /// pressed Slett alt (or Godta); every other ending (Avbryt, Escape, a
    /// lock) is false.
    static func present(on parent: NSWindow, _ kind: Kind = .reset, completion: @escaping (Bool) -> Void) {
        let sheet = make(kind)
        parent.beginSheet(sheet) { _ in completion(sheet.confirmed) }
        Hardening.assertAllWindows()
    }

    /// The sheet, hardened, not shown: `present` shows it; the snapshot
    /// tool draws it offscreen.
    static func make(_ kind: Kind) -> ConfirmSheet {
        let sheet = ConfirmSheet(contentRect: NSRect(x: 0, y: 0, width: 440, height: 180),
                                 styleMask: [.titled], backing: .buffered, defer: false)
        Hardening.apply(sheet)
        sheet.isReleasedWhenClosed = false
        let content = sheet.makeContent(kind)
        sheet.contentView = content
        sheet.setContentSize(content.fittingSize)
        return sheet
    }

    private func makeContent(_ kind: Kind) -> NSView {
        let width: CGFloat = 392
        let (title, body, okTitle, cancelTitle) = kind == .reset
            ? (L10n.resetConfirmTitle, L10n.resetConfirmBody, L10n.resetConfirmOK, L10n.resetConfirmCancel)
            : (L10n.acceptConfirmTitle, L10n.acceptConfirmBody, L10n.acceptConfirmOK, L10n.acceptConfirmCancel)
        let cancel = HumanButton(title: cancelTitle, target: self, action: #selector(cancel(_:)))
        cancel.keyEquivalent = "\u{1b}"
        let ok = HumanButton(title: okTitle, target: self, action: #selector(confirm(_:)))
        ok.hasDestructiveAction = kind == .reset
        okButton = ok
        let buttons = NSStackView(views: [cancel, ok])
        buttons.spacing = 12
        let stack = NSStackView(views: [
            InterfaceText(title, style: .heading, width: width),
            InterfaceText(body, width: width),
            buttons,
        ])
        stack.orientation = .vertical
        stack.spacing = 16
        stack.edgeInsets = NSEdgeInsets(top: 24, left: 24, bottom: 20, right: 24)
        return stack
    }

    /// The OK button's action (HumanButton: only a human's press gets here;
    /// the view host calls it directly as that press).
    @objc func confirm(_ sender: Any?) {
        confirmed = true
        sheetParent?.endSheet(self, returnCode: .OK)
    }

    @objc private func cancel(_ sender: Any?) {
        sheetParent?.endSheet(self, returnCode: .cancel)
    }
}
