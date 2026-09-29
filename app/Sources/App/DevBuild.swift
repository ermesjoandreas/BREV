// DevBuild.swift — the «UTVIKLER» label of a dev build.
//
// The compilation condition BREV_DEV is set in the Debug configuration only
// (app/project.yml; CLAUDE.md §2, docs/DECISIONS.md D-0115). A dev build
// has no capture protection (Hardening, ContentView) and does not lock on
// resign active, screen lock or Brev's idle clock (LockController); the
// manual Lås and Rust's own idle deadline stay. So it shows «UTVIKLER» in
// the main window's title bar (chrome, never content) on every screen, and
// is never mistaken for Brev. Release has none of it:
// scripts/check-dev-flag.sh fails if Release or Verify sets BREV_DEV, or if
// a Release binary holds `marker`.

#if BREV_DEV
import AppKit

enum DevBuild {
    /// Only a BREV_DEV binary holds this. It is longer than 15 bytes, so
    /// Swift keeps it as a C string that a byte search finds.
    static let marker = "BREV-DEV-BUILD-MARKER-1"

    /// Puts the label at the trailing end of `window`'s title bar.
    static func addLabel(to window: NSWindow) {
        let text = InterfaceText(L10n.devLabel, style: .section, width: 64, alignment: .right,
                                 color: .systemRed)
        text.identifier = NSUserInterfaceItemIdentifier(marker)
        text.translatesAutoresizingMaskIntoConstraints = false
        let holder = NSView(frame: NSRect(x: 0, y: 0, width: 76, height: 28))
        holder.addSubview(text)
        NSLayoutConstraint.activate([
            text.leadingAnchor.constraint(equalTo: holder.leadingAnchor),
            text.trailingAnchor.constraint(equalTo: holder.trailingAnchor, constant: -12),
            text.centerYAnchor.constraint(equalTo: holder.centerYAnchor),
        ])
        let accessory = NSTitlebarAccessoryViewController()
        accessory.view = holder
        accessory.layoutAttribute = .trailing
        window.addTitlebarAccessoryViewController(accessory)
    }
}
#endif
