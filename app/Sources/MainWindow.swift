// MainWindow.swift — the one place where Brev's window hardening flags live.
//
// Upholds CLAUDE.md §3.2 "Main window" and, through it:
//   §2  screenshot / screen-recording exclusion  → sharingType = .none
//   §1.5 no content in window titles              → title is only the app name
//   §1.1 nothing written to disk                  → isRestorable = false,
//                                                   no frame autosave name
// Later phases must create every content-bearing window through this class so
// the flags cannot drift. If macOS ever stops honouring one of them (e.g.
// sharingType under ScreenCaptureKit), add a second defence here and record it
// in docs/DECISIONS.md (§6).

import AppKit

/// Empty content view that only paints the neutral window background.
/// It holds no content, so nothing needs to be hidden from accessibility yet.
final class BlankContentView: NSView {
    override var isOpaque: Bool { true }

    override func draw(_ dirtyRect: NSRect) {
        NSColor.windowBackgroundColor.setFill()
        dirtyRect.fill()
    }
}

final class MainWindow: NSWindow {

    /// Creates the main window with all hardening flags applied.
    ///
    /// A convenience initializer is used on purpose: the subclass declares no
    /// designated initializer, so it inherits NSWindow's and never has to deal
    /// with `init(coder:)` (which is unavailable on NSWindow).
    convenience init(contentSize: NSSize) {
        self.init(
            contentRect: NSRect(origin: .zero, size: contentSize),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )

        // §1.5: the title is the app name and must never carry message content.
        title = NSLocalizedString(
            "window.main.title",
            value: "Brev",
            comment: "Title of the main window; always the app name, never content."
        )
        titlebarAppearsTransparent = true

        // §2: exclude the window from screenshots, screen recording and sharing.
        sharingType = NSWindow.SharingType.none

        // Keep the window (and its title) out of the Window menu and out of
        // state restoration; no frame autosave name is ever set (§1.1).
        isExcludedFromWindowsMenu = true
        isRestorable = false

        // ARC owns the window via AppDelegate; AppKit must not release it on close.
        isReleasedWhenClosed = false

        backgroundColor = NSColor.windowBackgroundColor
        contentView = BlankContentView()
    }

    /// Custom windows must opt in explicitly to receive key events.
    override var canBecomeKey: Bool { true }
}
