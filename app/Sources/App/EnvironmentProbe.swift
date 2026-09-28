// EnvironmentProbe.swift — Brev's report on its own defences, for Rust's
// environment class.
//
// Upholds CLAUDE.md §2 and §3.2 (docs/VAULT_SPLIT_PLAN.md §6, §8): Rust sends
// a letter only in environment class A. ComposeSheet makes this report on
// main right before `prepareSend`, from what Brev did: the identity key's
// origin (its own kSecAttrTokenID), whether this unlock unwrapped the DEK
// with Touch ID (UnlockService, for LockController's generation), and, at
// that moment, every window excluded from capture with every content
// view's layer preventing capture, secure event input on (Brev's own flag
// and the system's), the application class that drops synthetic input,
// every content view opaque to accessibility, and no Copy, Cut or Paste
// that any responder would take. It is Brev's own word: until attestation,
// the class catches bugs in Brev, not attackers (CLAUDE.md §2). Reads no
// content. Main thread only.

import AppKit
import Carbon.HIToolbox

enum EnvironmentProbe {
    /// What the keys did for this unlock.
    struct Keys {
        /// Where the identity key lives (`origin(of:)`).
        let identityKey: KeyOrigin
        /// This unlock unwrapped the DEK with Touch ID.
        let touchID: Bool
    }

    /// The report for a letter sent now.
    static func report(_ keys: Keys) -> EnvironmentReport {
        dispatchPrecondition(condition: .onQueue(.main))
        return EnvironmentReport(
            keyOrigin: keys.identityKey,
            biometricUsed: keys.touchID,
            captureExcluded: NSApp.windows.allSatisfy { $0.sharingType == .none } && ContentView.allPreventCapture,
            secureInputActive: SecureInput.isOn && IsSecureEventInputEnabled(),
            syntheticInputRejected: NSApp is BrevApplication,
            accessibilityOpaque: ContentView.allOpaque,
            pasteboardDisabled: editActions.allSatisfy { NSApp.target(forAction: $0) == nil })
    }

    /// The Secure Enclave if `key` says it lives there, software if not,
    /// unknown without a key.
    static func origin(of key: SecKey?) -> KeyOrigin {
        guard let key else { return .unknown }
        return Enclave.isInSecureEnclave(key) ? .secureEnclave : .software
    }

    /// Copy, Cut and Paste: no responder may answer them (CLAUDE.md §1.3).
    private static let editActions = ["copy:", "cut:", "paste:"].map(NSSelectorFromString)
}
