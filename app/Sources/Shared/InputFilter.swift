// InputFilter.swift — the synthetic-input rule, over a CGEvent.
//
// Upholds CLAUDE.md §2 (synthetic input from AppleScript, CGEvent injection
// or an agent "clicking" is rejected in the app) with the rule of §3.2: an
// input event whose `.eventSourceUnixProcessID` is not 0 came from a
// process, not from the hardware. There is no exception for Brev's own PID:
// a CGEvent made in-process gets its creator's PID by default
// (docs/PHASE2_DESIGN.md §0, §8.5), and widening the rule needs the GUI
// spike's evidence and a decision entry. BrevApplication applies it to
// every input event, in `sendEvent` and in `nextEvent`. No AppKit: compiled
// into the app and the CLI harness.

import CoreGraphics

enum InputFilter {
    /// True if an input event with this CGEvent must be dropped: it has no
    /// CGEvent at all, or its source PID is not 0.
    static func isSynthetic(_ cg: CGEvent?) -> Bool {
        guard let cg else { return true }
        return cg.getIntegerValueField(.eventSourceUnixProcessID) != 0
    }

    /// The source PID for the drop log, or -1 without a CGEvent.
    static func sourcePID(_ cg: CGEvent?) -> Int64 {
        cg?.getIntegerValueField(.eventSourceUnixProcessID) ?? -1
    }
}
