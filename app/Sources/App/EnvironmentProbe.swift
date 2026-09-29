// EnvironmentProbe.swift — what the app hands Rust about its own window and
// build, for Hand's facts.
//
// Upholds CLAUDE.md §2 and §3.2 and docs/AUTHORSHIP.md §2.2, §3.1
// (docs/DECISIONS.md D-0111): a sample is HandSampler's raw reads of the
// Mac plus two settings of the window being sampled: its `sharingType` is
// `.none`, and every content view alive shows its pixels only through a
// layer that prevents capture. While composing, LockController and the
// compose sheet sample the compose sheet, otherwise the main window. The
// design facts go to Rust once per compose session, read at that moment
// from what Brev does: every content view opaque to accessibility, no Copy,
// Cut or Paste that any responder would take, and the application class
// that drops synthetic input. In a correct Brev all three are true; a bug
// that breaks one lowers the letter's class. The identity key's origin is
// its own kSecAttrTokenID. It is Brev's own word: until attestation, the
// class catches bugs in Brev, not attackers (CLAUDE.md §2). Reads no
// content. Main thread only.

import AppKit

enum EnvironmentProbe {
    /// A sample now (HandSampler), with `window`'s settings: the compose
    /// sheet while composing, else the main window; nil sets neither.
    static func sample(for window: NSWindow?) -> Sample {
        dispatchPrecondition(condition: .onQueue(.main))
        return HandSampler.sample(sharingNone: window.map { $0.sharingType == NSWindow.SharingType.none } ?? false,
                                  preventsCapture: ContentView.allPreventCapture)
    }

    /// How Brev is built, as it stands now, for a compose session.
    static func design() -> Design {
        dispatchPrecondition(condition: .onQueue(.main))
        return Design(axOpaque: ContentView.allOpaque,
                      pasteboardOff: editActions.allSatisfy { NSApp.target(forAction: $0) == nil },
                      inputFilter: NSApp is BrevApplication)
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
