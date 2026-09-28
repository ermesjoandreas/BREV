// ConfirmSheet.swift — "Slette alle brev?", the only way to a reset.
//
// Upholds CLAUDE.md §1.9 (a reset destroys the keys for good, so only a
// human can confirm it) and §2 (docs/PHASE2_DESIGN.md §5.5, §7.1, §8.1): an
// own sheet window instead of a system alert, so it goes through
// Hardening.apply like every Brev window (a default-sharing sheet on an
// excluded window was captured in the capture spike), and both buttons are
// HumanButtons. Escape is Avbryt; there is no default button, so Return
// never deletes anything. Locking ends the sheet, which counts as Avbryt.

import AppKit

final class ConfirmSheet: HardenedWindow {
    private var confirmed = false

    /// Shows the sheet on `parent`. `completion(true)` only after a human
    /// pressed Slett alt; every other ending (Avbryt, Escape, a lock) is false.
    static func present(on parent: NSWindow, completion: @escaping (Bool) -> Void) {
        let sheet = ConfirmSheet(contentRect: NSRect(x: 0, y: 0, width: 440, height: 180),
                                 styleMask: [.titled], backing: .buffered, defer: false)
        Hardening.apply(sheet)
        sheet.isReleasedWhenClosed = false
        let content = sheet.makeContent()
        sheet.contentView = content
        sheet.setContentSize(content.fittingSize)
        parent.beginSheet(sheet) { _ in completion(sheet.confirmed) }
        Hardening.assertAllWindows()
    }

    private func makeContent() -> NSView {
        let width: CGFloat = 392
        let cancel = HumanButton(title: L10n.resetConfirmCancel, target: self, action: #selector(cancel(_:)))
        cancel.keyEquivalent = "\u{1b}"
        let ok = HumanButton(title: L10n.resetConfirmOK, target: self, action: #selector(confirm(_:)))
        ok.hasDestructiveAction = true
        let buttons = NSStackView(views: [cancel, ok])
        buttons.spacing = 12
        let stack = NSStackView(views: [
            InterfaceText(L10n.resetConfirmTitle, style: .heading, width: width),
            InterfaceText(L10n.resetConfirmBody, width: width),
            buttons,
        ])
        stack.orientation = .vertical
        stack.spacing = 16
        stack.edgeInsets = NSEdgeInsets(top: 24, left: 24, bottom: 20, right: 24)
        return stack
    }

    @objc private func confirm(_ sender: Any?) {
        confirmed = true
        sheetParent?.endSheet(self, returnCode: .OK)
    }

    @objc private func cancel(_ sender: Any?) {
        sheetParent?.endSheet(self, returnCode: .cancel)
    }
}
