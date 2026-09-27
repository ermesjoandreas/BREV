// MainMenu.swift — the menu bar, built in code: Brev and Arkiv, nothing else.
//
// Upholds CLAUDE.md §1.3, §1.4 and §1.6 (docs/PHASE2_DESIGN.md §8.5). There
// is no Edit menu, so there is no Copy or Paste item, and nowhere for macOS
// to add Dictation, Emoji or Writing Tools. There is no View, Window, Help,
// Services or Share menu, and AppKit is never told of a Services menu.
// Accessibility can press every item here; each action is harmless: lock,
// quit, or open an empty compose sheet. Anything added to these menus must
// be checked against §1 first.

import AppKit

/// Actions that the mail window answers through the responder chain. Until
/// a responder implements one, AppKit disables its menu item.
@objc protocol MailActions {
    func newLetter(_ sender: Any?)
}

enum MainMenu {
    /// Brev: Lås Brev (⌘L), Avslutt Brev (⌘Q). Arkiv: Nytt brev (⌘N).
    static func make(lock: LockController) -> NSMenu {
        let main = NSMenu()

        // AppKit shows the bundle name as the first menu's title.
        let app = NSMenu(title: L10n.menuAppTitle)
        let lockItem = NSMenuItem(title: L10n.menuAppLock, action: #selector(LockController.lockNow(_:)),
                                  keyEquivalent: "l")
        lockItem.target = lock
        app.addItem(lockItem)
        app.addItem(.separator())
        app.addItem(NSMenuItem(title: L10n.menuAppQuit, action: #selector(NSApplication.terminate(_:)),
                               keyEquivalent: "q"))
        add(app, to: main)

        // Target nil: the item works only while the mail window answers
        // newLetter(_:), which it does when unlocked with a contact selected.
        let file = NSMenu(title: L10n.menuFileTitle)
        file.addItem(NSMenuItem(title: L10n.menuFileNew, action: #selector(MailActions.newLetter(_:)),
                                keyEquivalent: "n"))
        add(file, to: main)

        return main
    }

    private static func add(_ menu: NSMenu, to main: NSMenu) {
        let item = NSMenuItem(title: menu.title, action: nil, keyEquivalent: "")
        item.submenu = menu
        main.addItem(item)
    }
}
