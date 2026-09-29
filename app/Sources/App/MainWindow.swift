// MainWindow.swift — Brev's one main window.
//
// Upholds CLAUDE.md §3.2 "Main window" and, through Hardening.apply:
//   §2  screenshot / screen-recording exclusion  → sharingType = .none
//   §1.5 no content in window titles or menus    → title is only the app name,
//                                                   excluded from the Windows menu
//   §1.1 nothing written to disk                  → isRestorable = false,
//                                                   no frame autosave name
// The window cannot be minimised (no .miniaturizable; AppKit still shows the
// minimise button, disabled), so there is no Dock thumbnail of it
// (docs/PHASE2_DESIGN.md §8.1). The window holds one RootViewController for
// its whole life; screens change inside it, so the window never resizes on
// lock or unlock. The mail screen brings a unified toolbar (MailToolbar);
// adding or removing it puts the window's frame back, so the frame is the
// same on every screen, and removing it clears the subtitle (a mailbox's
// name), so the lock screen never keeps it. No .fullSizeContentView
// (docs/UI_REDESIGN.md review 1): nothing lies under the toolbar, which
// blurs what it covers.

import AppKit

/// The root's view: it only paints the neutral window background.
/// It holds no content, so nothing needs to be hidden from accessibility.
final class BlankContentView: NSView {
    override var isOpaque: Bool { true }

    override func draw(_ dirtyRect: NSRect) {
        NSColor.windowBackgroundColor.setFill()
        dirtyRect.fill()
    }
}

final class MainWindow: HardenedWindow {
    /// Holds the current screen (onboarding, lock screen or mail).
    let root = RootViewController()

    /// The smallest content size: the three panes' minimums and dividers.
    static let minContentSize = NSSize(width: 880, height: 540)

    /// Creates the main window with all hardening flags applied.
    ///
    /// A convenience initializer is used on purpose: the subclass declares no
    /// designated initializer, so it inherits NSWindow's and never has to deal
    /// with `init(coder:)` (which is unavailable on NSWindow).
    convenience init(contentSize: NSSize) {
        self.init(
            contentRect: NSRect(origin: .zero, size: contentSize),
            styleMask: [.titled, .closable, .resizable],
            backing: .buffered,
            defer: false
        )
        Hardening.apply(self)

        // §1.5: the title is the app name and must never carry message content.
        title = L10n.windowMainTitle
        titlebarAppearsTransparent = true

        // ARC owns the window via AppDelegate; AppKit must not release it on close.
        isReleasedWhenClosed = false

        backgroundColor = NSColor.windowBackgroundColor
        toolbarStyle = .unified
        contentMinSize = Self.minContentSize
        // Set once, at the content size: setting a content view controller
        // resizes the window to its view (NSWindow.h), so it never changes.
        root.view.frame = NSRect(origin: .zero, size: contentSize)
        contentViewController = root
        setContentSize(contentSize)
    }

    /// Shows `toolbar` (the mail screen's) or none, with the frame kept. A
    /// removed toolbar takes the subtitle with it.
    func setToolbar(_ next: NSToolbar?) {
        guard toolbar !== next else { return }
        let kept = frame
        toolbar = next
        if next == nil { subtitle = "" }
        setFrame(kept, display: false)
    }

    /// Custom windows must opt in explicitly to receive key events.
    override var canBecomeKey: Bool { true }
}
