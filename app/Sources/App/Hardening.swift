// Hardening.swift — the settings every Brev window gets.
//
// Upholds CLAUDE.md §2 (windows excluded from capture), §1.5 (no content in
// the Windows menu or the Dock) and §1.1 (no state restoration)
// (docs/PHASE2_DESIGN.md §8.1). `apply` runs on every window Brev creates:
// the main window, the compose sheet and ConfirmSheet, and on their child
// windows and sheets. Sheets and child windows need it explicitly: the
// capture spike captured a default sheet and a default child window of a
// `.none` window through every path (docs/DECISIONS.md D-0052). So a
// HardenedWindow applies it to every sheet it begins and every child window
// it adds (CLAUDE.md §3.2: they get the same settings as their parent).
// `sharingType = .none` is the first capture defence; the protected content
// layer (ContentView) is the second (§3.2, D-0034). A BREV_DEV build
// (Debug only; CLAUDE.md §2, D-0115) leaves both out, so screenshots work.

import AppKit

enum Hardening {
    /// Once at launch, before any window exists: no automatic window tabs
    /// (and no tab bar items in any menu).
    static func applyToApp() {
        NSWindow.allowsAutomaticWindowTabbing = false
    }

    /// `window`, its child windows and its sheets, and theirs.
    static func apply(_ window: NSWindow) {
        #if !BREV_DEV
        window.sharingType = .none
        #endif
        window.isExcludedFromWindowsMenu = true
        window.isRestorable = false
        window.tabbingMode = .disallowed
        (window.childWindows ?? []).forEach(apply)
        window.sheets.forEach(apply)
    }

    /// Debug builds: after presenting a sheet, check that every window is
    /// still excluded from capture.
    static func assertAllWindows() {
        #if !BREV_DEV
        assert(NSApp.windows.allSatisfy { $0.sharingType == .none }, "a Brev window can be captured")
        #endif
    }
}

/// The class of every Brev window: a sheet or child window it takes gets
/// Hardening.apply first, whoever made it.
class HardenedWindow: NSWindow {
    override func beginSheet(_ sheetWindow: NSWindow,
                             completionHandler handler: ((NSApplication.ModalResponse) -> Void)? = nil) {
        Hardening.apply(sheetWindow)
        super.beginSheet(sheetWindow, completionHandler: handler)
    }

    override func beginCriticalSheet(_ sheetWindow: NSWindow,
                                     completionHandler handler: ((NSApplication.ModalResponse) -> Void)? = nil) {
        Hardening.apply(sheetWindow)
        super.beginCriticalSheet(sheetWindow, completionHandler: handler)
    }

    override func addChildWindow(_ childWin: NSWindow, ordered place: NSWindow.OrderingMode) {
        Hardening.apply(childWin)
        super.addChildWindow(childWin, ordered: place)
    }
}
