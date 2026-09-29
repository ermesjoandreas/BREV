// ContactPasteboard.swift — the pasteboard, for an address on the contact
// screen, and for nothing else.
//
// Upholds CLAUDE.md §1.3 and §5 Phase 4 (docs/PHASE4_DESIGN.md §6.2):
// addresses are not message content, so they may be copied
// and pasted, on the contact screen only. The only file in app/Sources that
// touches the pasteboard's contents (scripts/test.sh fails if this type is
// named outside ContactField, ContactSheet and AppDelegate's quit hook).
// `write` has one caller in ContactSheet: Kopier adressen min (the own
// address). It clears the
// pasteboard for this Mac only (no Universal Clipboard to other devices),
// sets nspasteboard.org's concealed and transient markers (clipboard managers
// that honour them neither show nor keep the entry), then the bytes as plain
// text, so the text is never there without the markers, and remembers the
// change count. The self-clear (the owner's rule, 2026-09-29): 60 s after
// the write, and when Brev quits, the pasteboard is cleared if its change
// count is still the one Brev's write left, so whatever another app copied
// since is never touched.
// Not at a lock: Brev locks as soon as another app is active, which would
// clear a code before it can be pasted there. `read` is for ContactField's
// ⌘V only: the plain text's bytes, at most EditModel.maxPaste, copied into a
// SecretBytes the caller wipes; never a String. AppKit's own copy of what it
// read is freed when the autorelease pool ends (MallocScribble=1 overwrites
// it; CLAUDE.md §2 accepts copies inside Apple frameworks). Logs nothing.
// Main thread only.

import AppKit

enum ContactPasteboard {
    /// The general pasteboard. The view host sets a named one: it never
    /// asks the user, and leaves the user's own untouched.
    static var board = NSPasteboard.general
    /// Seconds from a write to its self-clear (the view host shortens it).
    static var lifetime: TimeInterval = 60
    /// Beside the plain text: nspasteboard.org's markers, concealed (not
    /// shown) and transient (not kept).
    static let markers = ["org.nspasteboard.ConcealedType", "org.nspasteboard.TransientType"]
        .map(NSPasteboard.PasteboardType.init(rawValue:))

    /// The change count Brev's last write left, until it is cleared.
    private static var written: Int?
    private static var timer: Timer?

    /// Puts `bytes` (an address) on the pasteboard as
    /// plain text with the two markers, and starts the self-clear. The
    /// caller wipes `bytes`.
    static func write(_ bytes: SecretBytes) {
        dispatchPrecondition(condition: .onQueue(.main))
        guard bytes.count > 0 else { return }
        // Clears it, as clearContents does, and keeps the entry on this Mac:
        // Universal Clipboard does not offer it to the user's other devices.
        _ = board.prepareForNewContents(with: .currentHostOnly)
        // The markers first: only the clear moves the change count, so a
        // reader that looks in between must never find the text without them.
        for m in markers { _ = board.setData(Data(), forType: m) }
        // A view of Brev's buffer; the pasteboard copies it before this returns.
        bytes.withBytes { b in
            _ = board.setData(Data(bytesNoCopy: UnsafeMutableRawPointer(mutating: b.baseAddress!), count: b.count,
                                   deallocator: .none), forType: .string)
        }
        written = board.changeCount
        timer?.invalidate()
        let clear = Timer(timeInterval: lifetime, repeats: false) { _ in clearOwn() }
        RunLoop.main.add(clear, forMode: .common)
        timer = clear
    }

    /// The self-clear, after `lifetime` and at quit: empties the pasteboard
    /// if nothing was copied since Brev's write. Idempotent.
    static func clearOwn() {
        dispatchPrecondition(condition: .onQueue(.main))
        timer?.invalidate()
        timer = nil
        guard let mine = written else { return }
        written = nil
        if board.changeCount == mine { board.clearContents() }
    }

    /// ⌘V in a ContactField: the plain text's bytes in a new SecretBytes the
    /// caller wipes; nil if there is none, or more than EditModel.maxPaste.
    static func read() -> SecretBytes? {
        dispatchPrecondition(condition: .onQueue(.main))
        return autoreleasepool {
            guard let data = board.data(forType: .string), data.count <= EditModel.maxPaste else { return nil }
            let out = SecretBytes(capacity: EditModel.maxPaste)
            data.withUnsafeBytes { _ = out.append($0) }
            return out
        }
    }
}
