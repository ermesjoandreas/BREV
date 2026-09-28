// UnlockFailure.swift — what the lock screen shows after a failed unlock.
//
// Upholds CLAUDE.md §1.8 (Touch ID only; no password path is ever offered)
// and §1.9 (a fingerprint change loses the keys, and Brev says so)
// (docs/PHASE2_DESIGN.md §5.5). The errors come from the keychain lookup
// (KeyStore), from the Secure Enclave unwrap (LocalAuthentication,
// CryptoTokenKit and OSStatus codes, possibly nested as underlying errors)
// or from Rust's `unlock`, which UnlockService wraps in CoreUnlockError.
// The error Security reports for a key invalidated by a fingerprint change
// has not been measured (design §14.2 U4.3), so "fingers" is shown for any
// failure of the keychain or Enclave step that is not a cancel, lockout or
// missing Touch ID, when the enrolled-fingers hash also differs from the
// one saved at the last successful unlock (`biometry.state`, a hint;
// docs/DECISIONS.md D-0037). A hash change alone is never enough, and
// nothing is deleted without the reset confirmation. Plain logic: compiled
// into the app and the CLI harness.

import Foundation
import LocalAuthentication
import Security

/// An error thrown by `Brev.unlock` itself, after the DEK was unwrapped.
struct CoreUnlockError: Error {
    let underlying: Error
}

enum UnlockFailure: String, Error {
    /// Back to the lock screen, no text.
    case cancelled
    /// unlock.error.lockout
    case lockout
    /// unlock.error.unavailable
    case unavailable
    /// unlock.error.damaged, with the reset button.
    case damaged
    /// unlock.error.fingers, with the reset button.
    case fingers
    /// unlock.error.retry
    case retry

    /// Whether the screen offers "Slett alt og start på nytt".
    var offersReset: Bool {
        self == .damaged || self == .fingers
    }

    /// TKErrorDomain; compared by name, so CryptoTokenKit is not linked.
    static let tokenDomain = "CryptoTokenKit"

    /// `fingersChanged`: the saved enrolled-fingers hash exists and differs
    /// from the current one.
    static func classify(_ error: Error, fingersChanged: Bool) -> UnlockFailure {
        if let core = error as? CoreUnlockError {
            switch core.underlying as? BrevError {
            case .WrongKey?, .Corrupt?: return .damaged
            default: return .retry
            }
        }
        let codes = chain(error)
        func has(_ domain: String, _ list: [Int]) -> Bool {
            codes.contains { c in c.domain == domain && list.contains(c.code) }
        }
        let la = LAErrorDomain
        if has(la, [LAError.userCancel, .systemCancel, .appCancel].map(\.rawValue))
            || has(tokenDomain, [-4])                                  // TKErrorCodeCanceledByUser
            || has(NSOSStatusErrorDomain, [Int(errSecUserCanceled)]) {
            return .cancelled
        }
        if has(la, [LAError.biometryLockout.rawValue]) { return .lockout }
        if has(la, [LAError.biometryNotAvailable, .biometryNotEnrolled, .biometryNotPaired, .biometryDisconnected]
            .map(\.rawValue)) {
            return .unavailable
        }
        if fingersChanged { return .fingers }
        if (error as? Enclave.Failure) == .malformed
            || has(NSOSStatusErrorDomain, [Int(errSecItemNotFound)])    // a key or the wrapped DEK is gone
            || has(tokenDomain, [-3]) {                                 // TKErrorCodeCorruptedData
            return .damaged
        }
        return .retry
    }

    /// The domain and code of `error` and of each underlying error, outermost
    /// first (at most 8). Content-free, so the log may show them.
    static func chain(_ error: Error) -> [(domain: String, code: Int)] {
        var out: [(domain: String, code: Int)] = []
        var next: NSError? = error as NSError
        while let e = next, out.count < 8 {
            out.append((e.domain, e.code))
            next = e.userInfo[NSUnderlyingErrorKey] as? NSError
        }
        return out
    }
}
