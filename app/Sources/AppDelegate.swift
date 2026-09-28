// AppDelegate.swift — Brev's object graph, launch routing and key flows.
//
// Upholds CLAUDE.md §1.1, §1.5, §1.8, §1.9 and §1.10 (docs/PHASE2_DESIGN.md
// §4.2, §5, §8.6; keys per docs/DECISIONS.md D-0035). Launch: an unsafe
// launch (LaunchGuard) shows only launch.error.unsafe and never opens a
// store. Otherwise Brev takes the instance lock, or hands over to the Brev
// that holds it and quits. Then, if the wrapped-DEK keychain item exists,
// Brev opens its stores, locked, and shows the lock screen; otherwise it
// shows onboarding. Onboarding creates the keys and the stores
// (UnlockService), then asks for the first unlock, which also installs the
// wrapped DEK. Every unlock starts from a human click, runs through
// LockController's bookkeeping, and ends on the mail screen or the lock
// screen. A reset needs ConfirmSheet. Quitting locks first. Nothing here
// persists anything: no state restoration, no frame autosave, no user
// defaults. Logs are content-free: the `ping()` reply, lock and routing
// events, and error names and codes (§6).
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
    private lazy var unlocker = UnlockService(keyStore: keyStore)
    /// `.lock`, held with O_EXLOCK until the process ends; never closed.
    private var instanceLock: Int32 = -1
    /// The only owner of the Rust `Brev` handle (through Session).
    private var session: Session?
    /// Onboarding: the wrapped DEK between `Brev.create` and the first
    /// unlock, which stores it as the keychain item. Not secret.
    private var pendingWrapped: Data?

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

    /// Installed (the wrapped-DEK item exists): open the stores, locked,
    /// and show the lock screen; if they do not open, the damaged state with
    /// only the reset. Not installed: onboarding. The keychain unreadable
    /// (an unsigned build, say): only a notice.
    private func route() {
        switch keyStore.installState() {
        case .fresh:
            Self.appLog.notice("route onboarding")
            showOnboarding()
        case .installed:
            do {
                adopt(try Session.open(dir: keyStore.dir.path))
                Self.appLog.notice("route lock screen")
                showLockScreen()
            } catch {
                Self.appLog.error("open failed: \(Self.errorName(error), privacy: .public)")
                let screen = makeUnlockScreen(.lockScreen)
                screen.showDamagedStores()
                present(screen)
            }
        case .unavailable(let status):
            Self.appLog.error("keychain unavailable status=\(status, privacy: .public)")
            present(NoticeViewController(L10n.unlockErrorDamaged))
        }
    }

    private func adopt(_ opened: Session) {
        session = opened
        lock.session = opened
    }

    // MARK: - Onboarding (§5.3)

    private func showOnboarding() {
        let screen = OnboardingViewController()
        screen.onCreate = { [weak self, weak screen] in
            guard let self, let screen else { return }
            self.createKeys(on: screen)
        }
        present(screen)
    }

    /// Steps 3 to 6 on the unlock queue, then the first-unlock page.
    private func createKeys(on screen: OnboardingViewController) {
        screen.showWorking()
        unlocker.create { [weak self, weak screen] result in
            guard let self else { return }
            switch result {
            case .success(let made):
                Self.appLog.notice("keys created")
                self.adopt(made.session)
                self.pendingWrapped = made.wrapped
                self.present(self.makeUnlockScreen(.firstUnlock))
            case .failure(let error):
                Self.appLog.error("keys not created: \(Self.errorName(error), privacy: .public)")
                screen?.showFailed()
            }
        }
    }

    // MARK: - Unlock (§5.4)

    private func makeUnlockScreen(_ mode: UnlockViewController.Mode) -> UnlockViewController {
        let screen = UnlockViewController(mode: mode)
        screen.onUnlock = { [weak self, weak screen] in
            guard let self, let screen else { return }
            self.unlock(from: screen)
        }
        screen.onReset = { [weak self] in self?.confirmReset() }
        return screen
    }

    private func showLockScreen() {
        present(makeUnlockScreen(.lockScreen))
    }

    /// A human asked to unlock on `screen`: one Touch ID prompt. Mail shows
    /// only if nothing locked meanwhile and Brev is still the active app
    /// (LockController); otherwise the session is locked again and the lock
    /// screen shows. A successful first unlock installs Brev either way.
    private func unlock(from screen: UnlockViewController) {
        guard let session else { return }
        let started = lock.beginUnlock()
        screen.showWorking()
        unlocker.unlock(session, install: pendingWrapped) { [weak self, weak screen] result in
            guard let self else { return }
            switch result {
            case .success:
                self.pendingWrapped = nil
                if self.lock.endUnlock(started, succeeded: true) {
                    Self.appLog.notice("unlocked")
                    self.showMail()
                } else {
                    self.showLockScreen()
                }
            case .failure(let failure):
                _ = self.lock.endUnlock(started, succeeded: false)
                screen?.show(failure)
            }
        }
    }

    /// The unlocked screen: contacts, threads and letters, and the sync
    /// timer (docs/PHASE2_DESIGN.md §7.2). Nytt brev stays disabled until
    /// the compose sheet (WP8) sets `onNewLetter`.
    private func showMail() {
        guard let session else { return }
        let mail = MailViewController(session: session)
        mail.onLock = { [weak self] in self?.lock.lockNow(nil) }
        present(mail)
        mail.start()
    }

    // MARK: - Reset (§5.5)

    /// Only ConfirmSheet's Slett alt, pressed by a human, resets.
    private func confirmReset() {
        guard let window = mainWindow else { return }
        ConfirmSheet.present(on: window) { [weak self] confirmed in
            if confirmed { self?.reset() }
        }
    }

    /// Locks and drops the session, deletes the known names (the keychain
    /// items first) and starts onboarding again. Never while an unlock is in
    /// flight: its closure holds the old session and would store the wrapped
    /// DEK again after the deletion, and its completion would show mail. The
    /// unlock screen disables the reset button meanwhile; this refuses a
    /// sheet confirmed after an unlock began.
    private func reset() {
        guard !lock.state.authInFlight else {
            Self.appLog.notice("reset refused: unlock in flight")
            return
        }
        session?.brev.lock()
        session = nil
        lock.session = nil
        pendingWrapped = nil
        do {
            try keyStore.deleteKnownNames()
        } catch {
            Self.appLog.error("reset failed: \(Self.errorName(error), privacy: .public)")
            present(NoticeViewController(L10n.unlockErrorDamaged))
            return
        }
        Self.appLog.notice("reset")
        showOnboarding()
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

    /// A BrevError's variant name, or the domains and codes of an error and
    /// its underlying errors; never an error's message.
    private static func errorName(_ error: Error) -> String {
        if let brev = error as? BrevError { return "\(brev)" }
        return UnlockFailure.chain(error).map { "\($0.domain) \($0.code)" }.joined(separator: ", ")
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
