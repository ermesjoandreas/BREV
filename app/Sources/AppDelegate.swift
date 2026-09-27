// AppDelegate.swift — Brev's object graph and launch routing.
//
// Upholds CLAUDE.md §1.1, §1.5 and §1.10 (docs/PHASE2_DESIGN.md §4.2, §5.2,
// §8.6). Launch: an unsafe launch (LaunchGuard) shows only
// launch.error.unsafe and never opens a store. Otherwise Brev takes the
// instance lock, or hands over to the Brev that holds it and quits; then an
// installed Brev opens its stores, locked, and shows the lock screen, and a
// new one shows onboarding. Quitting locks first. Nothing here persists
// anything: no state restoration, no frame autosave, no user defaults.
// Logs are content-free: the `ping()` reply, lock and routing events, and
// error variant names (§6).
//
// FFI wiring (see docs/DECISIONS.md D-0003 and app/project.yml):
// app/Generated/BrevCore.swift is compiled into
// this same target and its C symbols come from the bridging header, so `ping()`
// is a module-level function here. No `import BrevCore` / `import BrevCoreFFI`.

import AppKit
import os

final class AppDelegate: NSObject, NSApplicationDelegate {

    /// Log channel for the Rust core boundary. Only content-free diagnostics
    /// may ever be written here.
    private static let coreLog = Logger(subsystem: "no.brev.app", category: "core")
    private static let appLog = Logger(subsystem: "no.brev.app", category: "app")

    let lock = LockController()
    private let keyStore = KeyStore()
    /// `.lock`, held with O_EXLOCK until the process ends; never closed.
    private var instanceLock: Int32 = -1
    /// The only owner of the Rust `Brev` handle (through Session).
    private var session: Session?

    /// Strong reference to the single main window. `MainWindow` sets
    /// `isReleasedWhenClosed = false`, so ARC owns the window through this.
    private var mainWindow: MainWindow?

    // MARK: - NSApplicationDelegate

    func applicationDidFinishLaunching(_ notification: Notification) {
        logCorePing()

        guard LaunchGuard.isSafe else {
            present(NoticeViewController(L10n.launchErrorUnsafe))
            return
        }
        do {
            try keyStore.prepareDirectory()
        } catch {
            Self.appLog.error("container folder failed")
            present(NoticeViewController(L10n.unlockErrorDamaged))
            return
        }
        switch keyStore.takeInstanceLock() {
        case .held(let fd):
            instanceLock = fd
        case .busy:
            Self.appLog.notice("second instance")
            handOverToRunningBrev()
            NSApp.terminate(nil)
            return
        case .failed(let code):
            Self.appLog.error("instance lock failed errno=\(code, privacy: .public)")
            present(NoticeViewController(L10n.unlockErrorDamaged))
            return
        }
        lock.showLockScreen = { [weak self] in self?.showLockScreen() }
        lock.start()
        route()
    }

    /// Quitting locks first (§8.3).
    func applicationWillTerminate(_ notification: Notification) {
        lock.lock(.terminate)
    }

    /// Secure coding for any restorable state. Brev restores nothing (every
    /// window has `isRestorable = false`), but answering `true` silences the
    /// macOS 14 warning and keeps the app on the strict path.
    func applicationSupportsSecureRestorableState(_ app: NSApplication) -> Bool {
        true
    }

    /// Closing the only window quits the app: there is nothing to keep running
    /// and no background work that could hold plaintext (§1.10).
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }

    /// No Dock menu (§1.5, design §8.1).
    func applicationDockMenu(_ sender: NSApplication) -> NSMenu? {
        nil
    }

    // MARK: - Routing (§5.2)

    /// Installed: open the stores, locked, and show the lock screen; if they
    /// do not open, the damaged state. Otherwise onboarding.
    private func route() {
        guard keyStore.isInstalled else {
            present(NoticeViewController(L10n.onboardingWelcomeTitle))
            return
        }
        do {
            let opened = try Session.open(dir: keyStore.dir.path)
            session = opened
            lock.session = opened
            showLockScreen()
        } catch {
            Self.appLog.error("open failed: \(Self.variant(error), privacy: .public)")
            present(NoticeViewController(L10n.unlockErrorDamaged))
        }
    }

    private func showLockScreen() {
        present(NoticeViewController(L10n.unlockTitle))
    }

    /// Shows `screen` in the main window, creating the window the first time.
    private func present(_ screen: NSViewController) {
        if let window = mainWindow {
            window.root.show(screen)
            return
        }
        let window = MainWindow(contentSize: NSSize(width: 900, height: 600))
        window.root.show(screen)
        window.center()
        mainWindow = window
        lock.window = window
        window.makeKeyAndOrderFront(nil)

        // macOS 14+ cooperative activation. The app was launched by the user,
        // so the system permits it to come to the front.
        NSApplication.shared.activate()
    }

    /// The Brev that holds the instance lock comes to the front.
    private func handOverToRunningBrev() {
        let me = NSRunningApplication.current
        let other = NSRunningApplication.runningApplications(withBundleIdentifier: Bundle.main.bundleIdentifier ?? "")
            .first { $0.processIdentifier != me.processIdentifier }
        guard let other else { return }
        NSApp.yieldActivation(to: other)
        _ = other.activate(from: me, options: [])
    }

    /// A BrevError's variant name, or "other"; never an error's message.
    private static func variant(_ error: Error) -> String {
        (error as? BrevError).map { "\($0)" } ?? "other"
    }

    // MARK: - Rust core

    /// Calls the Rust core's liveness check and logs its reply.
    ///
    /// `ping()` is generated by UniFFI from `brev-core` and returns a short
    /// version string ("brev-core 0.0.1 ok"). It is content-free by
    /// construction, which is the only reason `.public` privacy is acceptable.
    private func logCorePing() {
        let reply = ping()
        Self.coreLog.info("brev-core ping: \(reply, privacy: .public)")
    }
}
