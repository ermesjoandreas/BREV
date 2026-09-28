// HumanButton.swift — a button whose action runs only for a human.
//
// Upholds CLAUDE.md §2 (synthetic input and agents "clicking" are rejected)
// (docs/PHASE2_DESIGN.md §7.1; docs/DECISIONS.md D-0048). Three
// layers, because the AX element of a single-cell control may be the cell:
// 1. `sendAction` runs the action only while BrevApplication dispatches an
//    accepted input event, and only if the current event is a mouse-up or a
//    key event that passes InputFilter. An AX press arrives outside
//    `sendEvent` (the input spike saw it run a plain NSButton's action with
//    no current event), so it is refused. Posted clicks never get here:
//    BrevApplication drops them in `sendEvent` and `nextEvent`.
// 2. and 3. `accessibilityPerformPress` returns false on the button and on
//    its cell, so an AX press does nothing at all. (AXUIElementPerformAction
//    still reports success; the effect is what counts.)
// Used for every button that unlocks, creates keys, confirms, resets or
// sends, including the onboarding checkbox.

import AppKit

final class HumanButtonCell: NSButtonCell {
    override func accessibilityPerformPress() -> Bool {
        false
    }
}

final class HumanButton: NSButton {
    override class var cellClass: AnyClass? {
        get { HumanButtonCell.self }
        set {}
    }

    override func accessibilityPerformPress() -> Bool {
        false
    }

    override func sendAction(_ action: Selector?, to target: Any?) -> Bool {
        guard BrevApplication.inHumanDispatch, let event = NSApp.currentEvent,
              [.leftMouseUp, .keyDown, .keyUp].contains(event.type), !InputFilter.isSynthetic(event)
        else { return false }
        return super.sendAction(action, to: target)
    }
}
