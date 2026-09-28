// LockState.swift — the state behind locking, without AppKit.
//
// Upholds CLAUDE.md §3.2 (auto-lock) and §1.10 (docs/PHASE2_DESIGN.md §4.3,
// §5.4, §8.3; docs/DECISIONS.md D-0050): every lock starts a new
// generation, so an unlock that finishes after a lock is discarded instead
// of showing mail. While a Touch ID unlock is in flight, resigning active
// does not lock, because the Touch ID panel itself may take activation
// (not yet measured; lock spike, D-0052).
// Every other trigger still locks then, and an unlock that ends while Brev
// is not the active app is discarded. LockController (App/) runs the lock
// sequence; this file only decides. Plain state: compiled into the app and
// the CLI harness, main thread only.

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

    /// Incremented by every lock.
    private(set) var generation: UInt64 = 0
    /// True between `beginUnlock` and `endUnlock`.
    private(set) var authInFlight = false
    /// True while the mail window may show content.
    private(set) var unlocked = false

    /// Whether `reason` locks now. Everything locks, except resigning active
    /// while a Touch ID unlock is in flight.
    func shouldLock(for reason: LockReason) -> Bool {
        !(reason == .resignActive && authInFlight)
    }

    /// Records a lock: a new generation, not unlocked. Returns whether Brev
    /// was unlocked. Repeating it is harmless.
    @discardableResult
    func lock() -> Bool {
        generation &+= 1
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

    /// Whether the last accepted input (monotonic nanoseconds) is at least
    /// `idleLimitNanos` before `now`.
    static func isIdle(now: UInt64, lastInput: UInt64) -> Bool {
        now >= lastInput && now - lastInput >= idleLimitNanos
    }
}
