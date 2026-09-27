// main.swift — programmatic entry point for Brev (no @main, no nib, no storyboard).
//
// Order matters (docs/PHASE2_DESIGN.md §8.6, §8.5):
//   1. LaunchGuard runs before AppKit exists and before anything reads a
//      default: it refuses arguments, empties the argument domain, and
//      decides whether this launch is safe.
//   2. BrevApplication.shared creates the NSApplication subclass that drops
//      synthetic input (Info.plist names it as NSPrincipalClass too).
//   3. No automatic window tabbing, then the delegate and the menu bar,
//      which MainMenu builds in code with only Brev and Arkiv (§1.4).

import AppKit

LaunchGuard.run()

let application = BrevApplication.shared
Hardening.applyToApp()

// NSApplication.delegate is not a strong reference; this top-level constant
// keeps the delegate alive for the lifetime of the process.
let appDelegate = AppDelegate()
application.delegate = appDelegate

application.mainMenu = MainMenu.make(lock: appDelegate.lock)

// Regular policy: Dock icon and menu bar. Info.plist has no LSUIElement, so this
// is already the default; it is set explicitly so the intent is visible here.
_ = application.setActivationPolicy(.regular)

application.run()
