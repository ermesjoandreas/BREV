// ContactField.swift — the one field that takes ⌘V: an address or an
// invite code.
//
// Upholds CLAUDE.md §1.3, §2 and §5 Phase 4 (docs/PHASE4_DESIGN.md §6.2,
// spike P1's variant (a)). A SecureComposeView with EditModel's contact
// charset (a–z, 0–9, "-" and "."; A–Z become a–z), one line of at most 96
// units (Rust's longest invite code), so what it holds is typed, held and
// drawn like content: key events only, no text input client, secure event
// input while focused, synthetic events refused, pixels only in the
// protected layer. On top of that, ⌘V (the V key by key code, as ComposeKey
// reads keys, with ⌘ and no ⇧, ⌥ or ⌃; not a key repeat) reads the
// pasteboard's plain text (ContactPasteboard.read: at most 256 bytes into a
// SecretBytes, never a String) into the field at the caret by EditModel's
// paste rule, and wipes the bytes. The event passes BrevApplication's filter
// and this view's own check first, so a posted ⌘V reads nothing. No
// responder anywhere answers paste:, copy:, cut: or selectAll:, and there is
// no Edit menu, so EnvironmentProbe's pasteboardDisabled keeps its meaning;
// ⌘C, ⌘X and ⌘A do nothing here, as in every compose field. Used on the
// address page (the invite step) and in ContactSheet. P1's variant (b), the
// fallback if ⌘V in keyDown raises a pasteboard alert, is built only with
// the compilation condition BREV_PASTE_MENU: a paste: action here for
// MainMenu's «Rediger» › «Lim inn».

import AppKit
import Carbon.HIToolbox

final class ContactField: SecureComposeView {
    init() {
        super.init(maxBytes: Int(limits().maxInvite), multiline: false, charset: .contact)
    }

    required init?(coder: NSCoder) {
        nil
    }

    /// ⌘V: the V key with ⌘, without ⇧, ⌥ or ⌃.
    static func isPaste(keyCode: UInt16, flags: CGEventFlags) -> Bool {
        Int(keyCode) == kVK_ANSI_V && flags.contains(.maskCommand)
            && flags.intersection([.maskShift, .maskAlternate, .maskControl]).isEmpty
    }

    override func keyDown(with event: NSEvent) {
        guard !InputFilter.isSynthetic(event), let flags = event.cgEvent?.flags,
              Self.isPaste(keyCode: event.keyCode, flags: flags)
        else { return super.keyDown(with: event) }
        if !event.isARepeat { pasteText() }
    }

    /// The pasteboard's plain text into the field; nothing while read-only,
    /// a beep if there is none or it is refused.
    private func pasteText() {
        guard isEditable else { return }
        guard let bytes = ContactPasteboard.read() else { return NSSound.beep() }
        defer { bytes.wipe() }
        bytes.withBytes { insertPasted($0) }
    }

    #if BREV_PASTE_MENU
    /// P1's variant (b): «Rediger» › «Lim inn» (MainMenu), enabled only
    /// while a ContactField is the first responder.
    @objc func paste(_ sender: Any?) {
        pasteText()
    }
    #endif
}
