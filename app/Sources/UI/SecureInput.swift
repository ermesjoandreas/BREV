// SecureInput.swift — secure event input, always balanced.
//
// Upholds CLAUDE.md §2 (keyloggers and event taps) and §3.2 (secure event
// input while composing; docs/PHASE2_DESIGN.md §7.3, §8.4). A compose field
// turns it on while it has focus in the key window of the active app, and
// off when it loses focus, its window resigns key or Brev resigns active.
// The compose sheet turns it off when it closes, and the lock sequence in
// step 1. The input spike (macOS 26.2; D-0060 in the shifted numbering)
// found that it stays on for the whole session while Brev is hidden or
// inactive, until Brev turns it off, so every way out calls `disable()`.
// The Carbon calls are counted per process, so this keeps its own Bool and
// never calls either one twice in a row. Main thread only.

import Carbon.HIToolbox
import Dispatch

enum SecureInput {
    /// Whether Brev has turned secure event input on.
    private(set) static var isOn = false

    static func enable() {
        dispatchPrecondition(condition: .onQueue(.main))
        guard !isOn else { return }
        _ = EnableSecureEventInput()
        isOn = true
    }

    static func disable() {
        dispatchPrecondition(condition: .onQueue(.main))
        guard isOn else { return }
        _ = DisableSecureEventInput()
        isOn = false
    }
}
