// LockController.swift — when Brev locks, and the lock sequence.
//
// Upholds CLAUDE.md §3.2 (auto-lock, blank-on-lock) and §1.10 (plaintext is
// wiped on lock; docs/PHASE2_DESIGN.md §8.3, §8.4; docs/DECISIONS.md
// D-0050). Brev locks when it resigns active (not while a Touch ID unlock
// is in flight, whose panel may take activation, nor during a signature's
// prompt if LockState's U4 switch says that its panel does;
// docs/PHASE3_DESIGN.md §3.2), when the screen locks,
// before sleep, when the displays sleep, on a user switch, after 300 s
// without input on Brev's own clock (or once Rust has locked itself on its
// own idle clock, LockState.rustIdleSecs), on ⌘L or the Lås button, on
// quit, and when a sample of the Mac shows a running `sudo` or `su`, or SIP
// off (docs/AUTHORSHIP.md §4.3, D-0109): every 2 s while unlocked a sample
// (EnvironmentProbe: of the compose sheet while one is up, else of the main
// window) goes to Rust's `observe`, which locks itself at once and names
// the cause, and the lock screen then says why. An unlock shows mail only
// once Rust confirms it (`confirmActive`, within 2 s of `Brev.unlock`, with
// a sample of its own: `sudo` or SIP off refuses it, and the lock screen
// says so). A lock also invalidates a signature's Touch ID context in
// flight (`cancelSignature`, SignService).
// Triggers only ever lock; nothing here unlocks. The decisions are in
// LockState; this file observes the triggers and runs the sequence. Main
// thread only.
//
// Facts from the lock spike and WP10 (macOS 26.2; docs/DECISIONS.md
// D-0052): resign active arrived within 16 ms of another app's
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
    /// U4's measurement (docs/PHASE3_DESIGN.md §3.2): whether a Touch ID
    /// panel made Brev resign active.
    private static let touchIDLog = Logger(subsystem: "no.brev.app", category: "touchid")

    /// Seconds between two samples for Rust's `observe` (D-0109).
    static let observeInterval: TimeInterval = 2

    let state: LockState
    weak var window: MainWindow?
    weak var session: Session?
    /// Shows the lock screen in the root (set by AppDelegate), with
    /// `lockNotice` under its title.
    var showLockScreen: () -> Void = {}
    /// Invalidates a signature's Touch ID context in flight (SignService's
    /// `cancel`, set by AppDelegate).
    var cancelSignature: () -> Void = {}
    /// A sample of the Mac and of `window` (the compose sheet while one is
    /// up, else the main window). The lock probe passes a fixed one.
    var sampler: (NSWindow?) -> Sample = EnvironmentProbe.sample(for:)
    /// Why the last lock happened, for the lock screen, when a sample made
    /// it (`sudo`, SIP off); nil otherwise. Cleared when an unlock begins.
    private(set) var lockNotice: String?

    private var observers: [(NotificationCenter, NSObjectProtocol)] = []
    private var idleTimer: Timer?
    private var observeTimer: Timer?

    /// Brev's is `LockState()`; the lock probe passes one with the U4 switch
    /// in the other position.
    init(state: LockState = LockState()) {
        self.state = state
        super.init()
    }

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
        lockNotice = nil
        return state.beginUnlock()
    }

    /// Called on main when the unlock closure returns. True means show
    /// mail; on false after a successful unlock the session is locked again
    /// (a lock happened meanwhile, or Brev is not the active app, or Rust
    /// found the confirmation too late, or its sample shows `sudo` or SIP
    /// off, which `lockNotice` then names). Then the samples for `observe`
    /// start.
    func endUnlock(_ started: UInt64, succeeded: Bool) -> Bool {
        guard state.endUnlock(started, succeeded: succeeded, appActive: NSApp.isActive) else {
            if succeeded { session?.brev.lock() }
            return false
        }
        do {
            try session?.brev.confirmActive(sample: sampler(window))
        } catch BrevError.Environment(let facts) {
            lock(.environment, notice: L10n.unlockRefused(facts))
            return false
        } catch {
            lock(.unlockExpired)
            return false
        }
        observeTimer?.invalidate()
        observeTimer = commonModeTimer(every: Self.observeInterval) { [weak self] in self?.observeNow() }
        idleTimer?.invalidate()
        idleTimer = commonModeTimer(every: LockState.idleCheckInterval) { [weak self] in
            guard let self else { return }
            let idle = LockState.isIdle(now: clock_gettime_nsec_np(CLOCK_MONOTONIC),
                                        lastInput: BrevApplication.lastHumanInput)
            // Rust wipes on its own idle deadline; the screen is blanked here.
            if idle || (self.state.unlocked && self.session?.brev.isLocked() == true) {
                self.lock(.idle)
            }
        }
        return true
    }

    /// A sample for Rust's `observe` (every 2 s while unlocked): causes back
    /// mean Rust has locked everything already, and the lock sequence
    /// blanks Brev with the causes on the lock screen. `Locked` means Rust
    /// locked on its own (its idle deadline): the lock sequence too.
    func observeNow() {
        guard state.unlocked, let session else { return }
        do {
            let causes = try session.observe(sampler(window?.attachedSheet ?? window))
            if !causes.isEmpty { lock(.environment, notice: L10n.lockedBecause(causes)) }
        } catch {
            if (error as? BrevError) == .Locked { lock(.idle) }
        }
    }

    // MARK: - A signature's Touch ID prompt (docs/PHASE3_DESIGN.md §3.2)

    /// A human pressed Send or Registrer: the prompt starts. Returns the
    /// generation for `endSign`. If the panel takes activation (the U4
    /// switch in LockState), every content view is blanked until `endSign`.
    func beginSign() -> UInt64 {
        if state.panelTakesActivation { ContentView.hideAll() }
        return state.beginSign()
    }

    /// The prompt ended (main). True: the signature may be used. False: a
    /// lock came meanwhile, or the panel took activation and Brev is not
    /// the active app again, which locks now.
    func endSign(_ started: UInt64) -> Bool {
        let ok = state.endSign(started, appActive: NSApp.isActive)
        if !ok && started == state.generation { lock(.resignActive) }
        ContentView.showAll()
        return ok
    }

    // MARK: - The lock sequence (§8.4)

    /// Idempotent. Every step runs on every lock; only the switch to the
    /// lock screen depends on whether Brev was unlocked. `notice`: what the
    /// lock screen says about it (a sample's `sudo` or SIP off), else
    /// nothing.
    func lock(_ reason: LockReason, notice: String? = nil) {
        dispatchPrecondition(condition: .onQueue(.main))
        // U4: whether a Touch ID panel takes activation from Brev shows here,
        // in the log, with no prompt of its own (docs/PHASE3_DESIGN.md §3.2).
        if reason == .resignActive && (state.authInFlight || state.signInFlight) {
            let during = state.authInFlight ? "unlock" : "sign"
            Self.touchIDLog.notice("resign active during Touch ID (\(during, privacy: .public))")
        }
        guard state.shouldLock(for: reason) else { return }
        #if BREV_SELFSCAN
        SelfScan.run(control: true)
        #endif
        // 1. New generation (an unlock in flight is discarded); the idle
        //    and sample timers stop (the sync timer stops with the mail
        //    screen in 3); a signature's Touch ID context in flight is
        //    invalidated; secure event input off; an open menu closes.
        let wasUnlocked = state.lock()
        lockNotice = notice
        idleTimer?.invalidate()
        idleTimer = nil
        observeTimer?.invalidate()
        observeTimer = nil
        cancelSignature()
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
        // 5. Rust closes open texts, forgets a letter being sent, zeroes the
        //    DEK, scrubs stacks.
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
