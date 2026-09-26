// main.swift — programmatic entry point for Brev (no @main, no nib, no storyboard).
//
// Upholds CLAUDE.md §1.4: the main menu is built here in code and contains only
// the application menu with a single "Avslutt Brev" item. There is deliberately
// no Edit menu (no Copy/Paste/Dictation items can be auto-inserted), no Services
// menu (NSApp.servicesMenu is never set), no Share menu, no Window menu, and no
// Help menu. Anything added to this menu in later phases must be checked
// against §1 first.

import AppKit

/// Builds the minimal main menu: [App menu] → "Avslutt Brev" (⌘Q → terminate:).
///
/// AppKit shows the bundle's display name as the title of the first submenu, so
/// the localized title set here is only a fallback.
private func makeMainMenu() -> NSMenu {
    let mainMenu = NSMenu()

    let appMenuTitle = NSLocalizedString(
        "menu.app.title",
        value: "Brev",
        comment: "Title of the application menu (AppKit replaces it with the bundle name)."
    )
    let appMenu = NSMenu(title: appMenuTitle)

    let quitTitle = NSLocalizedString(
        "menu.app.quit",
        value: "Avslutt Brev",
        comment: "Application menu item that quits the app (Command-Q)."
    )
    let quitItem = NSMenuItem(
        title: quitTitle,
        action: #selector(NSApplication.terminate(_:)),
        keyEquivalent: "q"
    )
    // Default key-equivalent modifier is Command, so this is ⌘Q. Target is nil:
    // the action travels the responder chain and ends at NSApplication.
    appMenu.addItem(quitItem)

    let appMenuItem = NSMenuItem()
    appMenuItem.submenu = appMenu
    mainMenu.addItem(appMenuItem)

    return mainMenu
}

let application = NSApplication.shared

// NSApplication.delegate is not a strong reference; this top-level constant
// keeps the delegate alive for the lifetime of the process.
let appDelegate = AppDelegate()
application.delegate = appDelegate

application.mainMenu = makeMainMenu()

// Regular policy: Dock icon and menu bar. Info.plist has no LSUIElement, so this
// is already the default; it is set explicitly so the intent is visible here.
_ = application.setActivationPolicy(.regular)

application.run()
