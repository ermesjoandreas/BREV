// LockController.swift — when Brev locks, and the lock sequence.
//
// Upholds CLAUDE.md §3.2 (auto-lock, blank-on-lock) and §1.10 (plaintext is
// wiped on lock; docs/PHASE2_DESIGN.md §8.3, §8.4; D-0052 in the shifted
// numbering). Brev locks when it resigns active (not while a Touch ID unlock
// is in flight, whose panel may take activation), when the screen locks,
// before sleep, when the displays sleep, on a user switch, after 300 s
// without input on Brev's own clock, on ⌘L or the Lås button, and on quit.
// Triggers only ever lock; nothing here unlocks. The decisions are in
// LockState; this file observes the triggers and runs the sequence. Main
// thread only.
//
// Facts from the lock spike and WP10 (macOS 26.2; D-0060 in the shifted
// numbering): resign active arrived within 16 ms of another app's
// activation or a hide (real ⌘-Tab not yet measured). AppKit suspends
// distributed notifications while an app is inactive, and in the spike an
// observer with the default behaviour did not get one until later, so the
// screen-lock observer asks for immediate delivery (the Touch ID panel may
// leave Brev inactive during an unlock, when resign active does not lock);
// it is called on the main thread, also while Brev is inactive or a menu
// is tracked. A timer in the common modes fires while a menu is tracked.
// Posted events reset the system's HID idle counter, so idle is Brev's own
// clock, stamped only by input BrevApplication accepts.

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
        observe(app, NSApplication.didResignActiveNotification, .resignActive)
        observe(workspace, NSWorkspace.willSleepNotification, .sleep)
        observe(workspace, NSWorkspace.screensDidSleepNotification, .sleep)
        observe(workspace, NSWorkspace.sessionDidResignActiveNotification, .sessionResign)
        // Only the selector API takes a suspension behaviour; the block API
        // has the default, which the spike saw held back while inactive.
        DistributedNotificationCenter.default().addObserver(self, selector: #selector(screenLocked(_:)),
                                                            name: Self.screenIsLocked, object: nil,
                                                            suspensionBehavior: .deliverImmediately)
    }

    private static let screenIsLocked = Notification.Name("com.apple.screenIsLocked")

    private func observe(_ center: NotificationCenter, _ name: Notification.Name, _ reason: LockReason) {
        let token = center.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
            self?.lock(reason)
        }
        observers.append((center, token))
    }

    /// Distributed notifications arrive on the main thread.
    @objc private func screenLocked(_ note: Notification) {
        lock(.screenLocked)
    }

    deinit {
        observers.forEach { $0.0.removeObserver($0.1) }
        DistributedNotificationCenter.default().removeObserver(self)
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
        idleTimer?.invalidate()
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
        // 1. New generation (an unlock in flight is discarded); the idle
        //    timer stops (the sync timer stops with the mail screen in 3);
        //    secure event input off; an open menu closes.
        let wasUnlocked = state.lock()
        idleTimer?.invalidate()
        idleTimer = nil
        SecureInput.disable()
        NSApp.mainMenu.map(Self.menus)?.forEach { $0.cancelTracking() }
        // 2, 3. A compose sheet wipes its own content and every sheet ends,
        //    then the screen wipes its content. Every content view zeroes
        //    its pixel buffers in place, which the window server shows at
        //    once, and shows a blank frame (D-0034).
        window?.root.wipeContent()
        ContentView.blankAll()
        // 4. Replace what Core Text keeps alive, after every text is wiped.
        GlyphFlush.flush()
        // 5. Rust closes open texts, zeroes the three DEKs, scrubs stacks.
        session?.brev.lock()
        // 6. The lock screen replaces the mail window, which is released.
        if wasUnlocked { showLockScreen() }
        // 7. The window server gets the blank frame now. display() alone
        //    leaves the new layer tree uncommitted until the run-loop turn
        //    ends (measured on macOS 26.2); the flush commits it here.
        window?.display()
        CATransaction.flush()
        Self.log.notice("lock reason=\(reason.rawValue, privacy: .public)")
        #if BREV_SELFSCAN
        SelfScan.run(control: false)
        #endif
    }

    /// `menu` and all its submenus. A menu's cancelTracking() ends only its
    /// own tracking: the main menu's left its own submenu open when that was
    /// popped up (measured on macOS 26.2; a menu opened from the menu bar
    /// was not measured), so step 1 cancels every one.
    private static func menus(_ menu: NSMenu) -> [NSMenu] {
        [menu] + menu.items.compactMap(\.submenu).flatMap(menus)
    }
}
