// ProofSheet.swift — the detail behind a received letter's badge.
//
// Upholds CLAUDE.md §1.2, §1.5 and §2 and docs/AUTHORSHIP.md §6, §7 (D-0107
// item 4, D-0108, D-0111). A human's press on the badge opens it: an own
// sheet window, like ConfirmSheet, so it goes through Hardening.apply like
// every Brev window (no popover: AppKit-made windows over content are
// captured, OpaqueView.swift). It shows only fixed texts from
// Localizable.strings with Rust's fixed names and counts in them, never
// content: the badge as its title, each failed check in plain Norwegian
// (the requirements check with the facts that miss one),
// then, only for a verified letter, what the sender's app reported (key in
// hardware with Touch ID, other windows, known AI programs, admin, blocked
// input, time spent writing, SIP, sudo; «ukjent» for a fact it could not
// read), and always last that Apple did not vouch for the app. Lukk (a
// HumanButton, or Escape) ends it; so does a lock.

import AppKit

final class ProofSheet: HardenedWindow {
    private static let width: CGFloat = 392

    /// Shows the detail of `proof` on `parent`.
    static func present(on parent: NSWindow, _ proof: Proof) {
        parent.beginSheet(make(proof))
        Hardening.assertAllWindows()
    }

    /// The sheet, hardened, not shown: `present` shows it; the snapshot
    /// tool draws it offscreen.
    static func make(_ proof: Proof) -> ProofSheet {
        let sheet = ProofSheet(contentRect: NSRect(x: 0, y: 0, width: 440, height: 200),
                               styleMask: [.titled], backing: .buffered, defer: false)
        Hardening.apply(sheet)
        sheet.isReleasedWhenClosed = false
        let content = sheet.makeContent(proof)
        sheet.contentView = content
        sheet.setContentSize(content.fittingSize)
        return sheet
    }

    /// The detail's lines, in order (docs/AUTHORSHIP.md §6).
    static func lines(_ proof: Proof) -> [String] {
        var out = proof.failed.compactMap(L10n.proofCheck)
        let facts = proof.failed.filter { L10n.proofCheck($0) == nil }
        if !facts.isEmpty { out.append(L10n.proofRequirements(facts)) }
        if proof.verified { out += reported(proof) }
        if !proof.attested { out.append(L10n.proofAttest) }
        return out
    }

    /// What the sender's app reported, for a verified letter. Its key is in
    /// hardware: a verified letter met that requirement (only a test
    /// archive skips it).
    private static func reported(_ p: Proof) -> [String] {
        let unknown = L10n.proofUnknown
        func count(_ n: UInt32?) -> String { n.map { "\($0)" } ?? unknown }
        func yesNo(_ b: Bool?) -> String { b.map { $0 ? L10n.proofYes : L10n.proofNo } ?? unknown }
        return [
            L10n.proofKey(L10n.proofYes),
            L10n.proofWindows(count(p.windows)),
            L10n.proofAgents(count(p.agents)),
            L10n.proofAdmin(yesNo(p.admin)),
            L10n.proofBlocked(count(p.blockedInput)),
            L10n.proofSeconds(p.seconds.map(minutes) ?? unknown),
            L10n.proofSIP(p.sip.map { $0 ? L10n.proofOn : L10n.proofOff } ?? unknown),
            L10n.proofSudo(p.sudo.map { $0 == 0 ? L10n.proofNo : L10n.proofYes } ?? unknown),
        ]
    }

    /// Seconds as whole minutes, «under 1 min» below one.
    private static func minutes(_ seconds: UInt32) -> String {
        seconds < 60 ? L10n.proofUnderAMinute : L10n.proofMinutes((seconds + 30) / 60)
    }

    /// The badge's symbol and text as the title, the lines 8 pt apart,
    /// proof.attest last in small secondary text, Lukk bottom right
    /// (docs/UI_REDESIGN.md §2.8).
    private func makeContent(_ proof: Proof) -> NSView {
        let close = HumanButton(title: L10n.proofClose, target: self, action: #selector(closePressed(_:)))
        close.keyEquivalent = "\u{1b}"
        let icon = NSImageView()
        let config = NSImage.SymbolConfiguration(pointSize: 17, weight: .regular)
        icon.image = NSImage(systemSymbolName: proof.verified ? "checkmark.seal" : "exclamationmark.triangle",
                             accessibilityDescription: nil)?.withSymbolConfiguration(config)
        icon.contentTintColor = proof.verified ? .secondaryLabelColor : .systemOrange
        let heading = InterfaceText(L10n.badge(verified: proof.verified), style: .heading,
                                    width: Self.width - 28, alignment: .left)
        let title = NSStackView(views: [icon, heading])
        title.orientation = .horizontal
        title.alignment = .centerY
        title.spacing = 8
        let lines = Self.lines(proof)
        let body = lines.map { line -> InterfaceText in
            line == L10n.proofAttest
                ? InterfaceText(line, style: .caption, width: Self.width, alignment: .left)
                : InterfaceText(line, width: Self.width, alignment: .left)
        }
        let spacer = NSView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        let bottom = NSStackView(views: [spacer, close])
        bottom.widthAnchor.constraint(equalToConstant: Self.width).isActive = true
        let stack = NSStackView(views: [title] + body + [bottom])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 8
        stack.setCustomSpacing(16, after: title)
        if let last = body.last { stack.setCustomSpacing(20, after: last) }
        if body.count > 1 { stack.setCustomSpacing(12, after: body[body.count - 2]) }
        stack.edgeInsets = NSEdgeInsets(top: 20, left: 24, bottom: 20, right: 24)
        return stack
    }

    /// Lukk (HumanButton: only a human's press gets here).
    @objc private func closePressed(_ sender: Any?) {
        sheetParent?.endSheet(self)
    }
}
