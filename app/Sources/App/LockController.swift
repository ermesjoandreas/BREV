// LockController.swift — when Brev locks, and the lock sequence.
//
// Upholds CLAUDE.md §3.2 (auto-lock, blank-on-lock) and §1.10 (plaintext is
// wiped on lock; docs/PHASE2_DESIGN.md §8.3, §8.4). Brev locks when it
// resigns active (not while a Touch ID unlock is in flight), when the screen
// locks, before sleep, when the displays sleep, on a user switch, after 300 s
// without input, on ⌘L or the Lås button, and on quit. The decisions are in
// LockState; this file observes the triggers and runs the sequence. Main
// thread only.

import AppKit
import os

/// A repeating timer on the main run loop in the common modes, so it also
/// fires while a menu is open or the mouse is tracked (§8.3).
func commonModeTimer(every interval: TimeInterval, _ body: @escaping () -> Void) -> Timer {
    let timer = Timer(timeInterval: interval, repeats: true) { _ in body() }
    RunLoop.main.add(timer, forMode: .common)
    return timer
}

final class LockController: NSObject {
    private static let log = Logger(subsystem: "no.brev.app", category: "lock")

    let state = LockState()
    weak var window: MainWindow?
    weak var session: Session?
    /// Shows the lock screen in the root (set by AppDelegate).
    var showLockScreen: () -> Void = {}

    private var observers: [(NotificationCenter, NSObjectProtocol)] = []
    private var idleTimer: Timer?

    /// Starts observing every lock trigger except idle, which runs only
    /// while unlocked.
    func start() {
        let app = NotificationCenter.default
        let workspace = NSWorkspace.shared.notificationCenter
        let distributed = DistributedNotificationCenter.default()
        observe(app, NSApplication.didResignActiveNotification, .resignActive)
        observe(distributed, Notification.Name("com.apple.screenIsLocked"), .screenLocked)
        observe(workspace, NSWorkspace.willSleepNotification, .sleep)
        observe(workspace, NSWorkspace.screensDidSleepNotification, .sleep)
        observe(workspace, NSWorkspace.sessionDidResignActiveNotification, .sessionResign)
    }

    private func observe(_ center: NotificationCenter, _ name: Notification.Name, _ reason: LockReason) {
        let token = center.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
            self?.lock(reason)
        }
        observers.append((center, token))
    }

    deinit {
        observers.forEach { $0.0.removeObserver($0.1) }
    }

    /// ⌘L and the menu item Lås Brev.
    @objc func lockNow(_ sender: Any?) {
        lock(.manual)
    }

    // MARK: - Unlock bookkeeping (§5.4)

    /// A human clicked unlock; returns the generation for `endUnlock`.
    func beginUnlock() -> UInt64 {
        state.beginUnlock()
    }

    /// Called on main when the unlock closure returns. True means show
    /// mail; on false after a successful unlock the session is locked again
    /// (a lock happened meanwhile, or Brev is not the active app).
    func endUnlock(_ started: UInt64, succeeded: Bool) -> Bool {
        guard state.endUnlock(started, succeeded: succeeded, appActive: NSApp.isActive) else {
            if succeeded { session?.brev.lock() }
            return false
        }
        idleTimer = commonModeTimer(every: LockState.idleCheckInterval) { [weak self] in
            if LockState.isIdle(now: clock_gettime_nsec_np(CLOCK_MONOTONIC), lastInput: BrevApplication.lastHumanInput) {
                self?.lock(.idle)
            }
        }
        return true
    }

    // MARK: - The lock sequence (§8.4)

    /// Idempotent. Every step runs on every lock; only the switch to the
    /// lock screen depends on whether Brev was unlocked.
    func lock(_ reason: LockReason) {
        dispatchPrecondition(condition: .onQueue(.main))
        guard state.shouldLock(for: reason) else { return }
        #if BREV_SELFSCAN
        SelfScan.run(control: true)
        #endif
        // 1. New generation (an unlock in flight is discarded); timers
        //    stop; secure event input off; an open menu closes.
        let wasUnlocked = state.lock()
        idleTimer?.invalidate()
        idleTimer = nil
        SecureInput.disable()
        NSApp.mainMenu?.cancelTracking()
        // 2, 3. The screen wipes its content, a compose sheet wipes its
        //    own, and every sheet ends. Every content view zeroes its pixel
        //    buffers in place and shows a blank frame (D-0034).
        window?.root.wipeContent()
        ContentView.blankAll()
        // 4. Replace what Core Text keeps alive, after every text is wiped.
        GlyphFlush.flush()
        // 5. Rust closes open texts, zeroes the three DEKs, scrubs stacks.
        session?.brev.lock()
        // 6. The lock screen replaces the mail window, which is released.
        if wasUnlocked { showLockScreen() }
        // 7. The window server's backing store gets the blank frame now.
        window?.display()
        Self.log.notice("lock reason=\(reason.rawValue, privacy: .public)")
        #if BREV_SELFSCAN
        SelfScan.run(control: false)
        #endif
    }
}
