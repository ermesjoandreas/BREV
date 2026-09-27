// Hardening.swift — the settings every Brev window gets.
//
// Upholds CLAUDE.md §2 (windows excluded from capture), §1.5 (no content in
// the Windows menu or the Dock) and §1.1 (no state restoration)
// (docs/PHASE2_DESIGN.md §8.1). `apply` runs on every window Brev creates:
// the main window, the compose sheet and ConfirmSheet. Sheets need it
// explicitly: a sheet on a `.none` window was captured with the default
// sharing type. `sharingType = .none` is the first capture defence; the
// protected content layer is the second (§3.2, D-0034).

import AppKit

enum Hardening {
    /// Once at launch, before any window exists: no automatic window tabs
    /// (and no tab bar items in any menu).
    static func applyToApp() {
        NSWindow.allowsAutomaticWindowTabbing = false
    }

    static func apply(_ window: NSWindow) {
        window.sharingType = .none
        window.isExcludedFromWindowsMenu = true
        window.isRestorable = false
        window.tabbingMode = .disallowed
    }

    /// Debug builds: after presenting a sheet, check that every window is
    /// still excluded from capture.
    static func assertAllWindows() {
        assert(NSApp.windows.allSatisfy { $0.sharingType == .none }, "a Brev window can be captured")
    }
}
