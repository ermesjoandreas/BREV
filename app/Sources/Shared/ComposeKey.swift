// ComposeKey.swift — what one key-down does in a compose field.
//
// Upholds CLAUDE.md §1.3 and §1.6 (docs/PHASE2_DESIGN.md §7.3): the compose
// view reads a key-down's key code and modifier flags, never the event's own
// text. ⌃ combinations do nothing. ⌘ combinations are never text: ⌘↩ sends,
// ⌘←/⌘→ go to the line's start or end and ⌘↑/⌘↓ to the text's, and every
// other one (⌘C, ⌘V, ⌘X, ⌘A, ⌘Z …) does nothing, so there is no copy, cut,
// paste or select-all even in principle. The menu's own key equivalents
// (⌘L, ⌘Q, ⌘N) reach the menu before a key-down. Named keys go by key code,
// whatever ⇧ or ⌥ is held; every other key is text for KeyTranslator. No
// AppKit: compiled into the app and the CLI harness.

import Carbon.HIToolbox
import CoreGraphics

enum ComposeKey: Equatable {
    /// ⌘↩ (Return or Enter).
    case send
    /// ⌘← and ⌘→.
    case lineStart, lineEnd
    /// ⌘↑ and ⌘↓.
    case documentStart, documentEnd
    /// The arrow keys.
    case left, right, up, down
    /// Delete and Forward Delete.
    case deleteBackward, deleteForward
    /// Return or Enter: a newline in the body, the next field in the subject.
    case newline
    /// Tab and ⇧Tab: the other field.
    case otherField
    /// Escape: close the sheet, discarding the letter.
    case cancel
    /// Anything else without ⌘ or ⌃: KeyTranslator makes its text.
    case text
    /// Does nothing: every ⌃ combination, and ⌘ with any other key.
    case ignore

    static func of(keyCode: UInt16, flags: CGEventFlags) -> ComposeKey {
        let k = Int(keyCode)
        if flags.contains(.maskControl) { return .ignore }
        if flags.contains(.maskCommand) {
            switch k {
            case kVK_Return, kVK_ANSI_KeypadEnter: return .send
            case kVK_LeftArrow: return .lineStart
            case kVK_RightArrow: return .lineEnd
            case kVK_UpArrow: return .documentStart
            case kVK_DownArrow: return .documentEnd
            default: return .ignore
            }
        }
        switch k {
        case kVK_Return, kVK_ANSI_KeypadEnter: return .newline
        case kVK_Delete: return .deleteBackward
        case kVK_ForwardDelete: return .deleteForward
        case kVK_LeftArrow: return .left
        case kVK_RightArrow: return .right
        case kVK_UpArrow: return .up
        case kVK_DownArrow: return .down
        case kVK_Tab: return .otherField
        case kVK_Escape: return .cancel
        default: return .text
        }
    }
}
