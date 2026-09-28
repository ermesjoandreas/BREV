// LockState.swift — the state behind locking, without AppKit.
//
// Upholds CLAUDE.md §3.2 (auto-lock) and §1.10 (docs/PHASE2_DESIGN.md §4.3,
// §5.4, §8.3; D-0052 in the shifted numbering): every lock starts a new
// generation, so an unlock that finishes after a lock is discarded instead
// of showing mail. While a Touch ID unlock is in flight, resigning active
// does not lock, because the Touch ID panel itself may take activation
// (not yet measured; lock spike, D-0060 in the shifted numbering).
// Every other trigger still locks then, and an unlock that ends while Brev
// is not the active app is discarded.
// The Touch ID prompt of a signature (Send, Registrer; docs/PHASE3_DESIGN.md
// §3.2) keeps auto-lock: the letter panes and the draft are on screen, so
// resigning active locks as usual. That rule depends on U4 (does the panel
// take activation from Brev?), which only a human can measure; the one
// switch `signPanelTakesActivation` selects the design's rule for each
// outcome, and its default is the safe one (see there). LockController (App/)
// runs the lock sequence; this file only decides. Plain state: compiled into
// the app and the CLI harness, main thread only.

import Foundation

/// Why Brev locked; the log line is `lock reason=<rawValue>`.
enum LockReason: String {
    case resignActive, screenLocked, sleep, sessionResign, idle, manual, terminate
}

final class LockState {
    /// Brev locks after this long without accepted input (§8.3).
    static let idleLimitNanos: UInt64 = 300 * 1_000_000_000
    /// How often the idle timer looks.
    static let idleCheckInterval: TimeInterval = 15

    /// U4 (docs/PHASE3_DESIGN.md §3.2): whether the Touch ID panel of a
    /// signature makes Brev resign active. Unmeasured, so false: resigning
    /// active locks during the prompt as at any other time (nothing is sent,
    /// the draft is gone). That is the safe side: if the panel does take
    /// activation, every Send and Registrer locks Brev at once, Brev's log
    /// (category touchid) says `resign active during Touch ID (sign)`, and
    /// the lock log `lock reason=resignActive`; an unlock's panel says
    /// `(unlock)` instead, without locking. Then set this to true: before the prompt
    /// every content view is blanked and shows nothing until the prompt ends,
    /// resigning active does not lock during the prompt only, and when it
    /// ends Brev locks unless it is the active app again.
    static let signPanelTakesActivation = false

    /// This state's copy of the switch (the harness tests both).
    let panelTakesActivation: Bool
    /// Incremented by every lock.
    private(set) var generation: UInt64 = 0
    /// True between `beginUnlock` and `endUnlock`.
    private(set) var authInFlight = false
    /// True between `beginSign` and `endSign` (or a lock).
    private(set) var signInFlight = false
    /// True while the mail window may show content.
    private(set) var unlocked = false

    init(signPanelTakesActivation: Bool = LockState.signPanelTakesActivation) {
        panelTakesActivation = signPanelTakesActivation
    }

    /// Whether `reason` locks now. Everything locks, except resigning active
    /// while a Touch ID unlock is in flight, and, if the signature's panel
    /// takes activation, while a signature's prompt is up.
    func shouldLock(for reason: LockReason) -> Bool {
        guard reason == .resignActive else { return true }
        return !authInFlight && !(signInFlight && panelTakesActivation)
    }

    /// Records a lock: a new generation, not unlocked, no signature in
    /// flight. Returns whether Brev was unlocked. Repeating it is harmless.
    @discardableResult
    func lock() -> Bool {
        generation &+= 1
        signInFlight = false
        let was = unlocked
        unlocked = false
        return was
    }

    /// A human asked to unlock; returns the generation to hand to `endUnlock`.
    func beginUnlock() -> UInt64 {
        authInFlight = true
        return generation
    }

    /// Ends an unlock begun with `beginUnlock`. True only if it succeeded,
    /// nothing locked since it began, and Brev is the active app (§5.4 step
    /// 3); then Brev is unlocked. On false the caller locks the session.
    func endUnlock(_ started: UInt64, succeeded: Bool, appActive: Bool) -> Bool {
        authInFlight = false
        guard succeeded, started == generation, appActive else { return false }
        unlocked = true
        return true
    }

    /// A human pressed Send or Registrer, and the signature's Touch ID
    /// prompt starts; returns the generation to hand to `endSign`.
    func beginSign() -> UInt64 {
        signInFlight = true
        return generation
    }

    /// Ends a signature begun with `beginSign`. True if nothing locked since
    /// it began and, when the panel takes activation, Brev is the active app
    /// again: then the signature may be used. On false with `started` still
    /// the current generation (the panel took activation and Brev is not
    /// active), the caller locks.
    func endSign(_ started: UInt64, appActive: Bool) -> Bool {
        signInFlight = false
        return started == generation && (appActive || !panelTakesActivation)
    }

    /// Whether the last accepted input (monotonic nanoseconds) is at least
    /// `idleLimitNanos` before `now`.
    static func isIdle(now: UInt64, lastInput: UInt64) -> Bool {
        now >= lastInput && now - lastInput >= idleLimitNanos
    }
}
