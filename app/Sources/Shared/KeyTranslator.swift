// KeyTranslator.swift — one key-down into text, without the text input system.
//
// Upholds CLAUDE.md §1.6 and §1.10 (docs/PHASE2_DESIGN.md §6.2, §7.3). The
// compose view is not a text input client, so dictation, the emoji and
// character pickers, press-and-hold, predictions and autocorrect have no way
// in, and the event's own text is never read. The view hands every key-down
// that is not a named key (Return, Delete, arrows, Tab, Escape) or a ⌘ or ⌃
// combination to `translate`, which runs UCKeyTranslate on the keyboard
// layout with Brev's own dead-key state. The units (at most 4) go to the
// caller in a stack buffer that is wiped before `translate` returns. A dead
// key (´ ` ¨ ^ ~ on the Norwegian layout) gives no units and waits for the
// next key; `reset` drops it when the view loses focus, and a layout switch
// before the next key drops it too. A held key repeats as UCKeyTranslate's
// auto-key action, so a held dead key stays one waiting accent. The input
// spike (macOS 26.2; D-0060 in the shifted numbering) found that the state
// keeps upper bits after a finished composition (0x10000 after ´ e), so
// "waiting" is no units with a state that is not 0, not the state alone. No
// AppKit: compiled into the app and the CLI harness, which injects a named
// layout. Main thread only (Text Input Sources).

import Carbon.HIToolbox
import CoreGraphics

final class KeyTranslator {
    /// The keyboard layout to translate with.
    enum Layout {
        /// The user's current layout, looked up for every key (the app).
        case current
        /// An installed layout by input source id, such as
        /// "com.apple.keylayout.Norwegian" (the harness).
        case named(String)
    }

    /// The named layout; nil means the current one.
    private let fixed: TISInputSource?
    private var deadKeyState: UInt32 = 0
    /// The input source id of the layout `deadKeyState` belongs to.
    private var stateLayout: CFString?

    /// nil if a named layout is not installed or Text Input Sources cannot
    /// list it.
    init?(_ layout: Layout) {
        switch layout {
        case .current:
            fixed = nil
        case .named(let id):
            let filter = [kTISPropertyInputSourceID as String: id] as CFDictionary
            guard let list = TISCreateInputSourceList(filter, true)?.takeRetainedValue() as? [TISInputSource],
                  let source = list.first
            else { return nil }
            fixed = source
        }
    }

    /// True while a dead key waits for the next key: the last key gave no
    /// units and left a state.
    private(set) var hasDeadKey = false

    /// Drops a waiting dead key.
    func reset() {
        deadKeyState = 0
        hasDeadKey = false
    }

    /// The Carbon modifier bits UCKeyTranslate takes: shift, option and caps
    /// lock. ⌘ and ⌃ never make text; the view handles them.
    static func carbonModifiers(_ flags: CGEventFlags) -> UInt32 {
        var m: UInt32 = 0
        if flags.contains(.maskShift) { m |= UInt32(shiftKey) }
        if flags.contains(.maskAlternate) { m |= UInt32(optionKey) }
        if flags.contains(.maskAlphaShift) { m |= UInt32(alphaLock) }
        return m
    }

    /// Translates one key-down (its key code and its CGEvent flags; a
    /// repeat of a held key if `isRepeat`) and calls `body` with the units
    /// it types: none for a dead key, a key without text or a layout without
    /// Unicode data, else 1 to 4. The buffer is wiped when `body` returns, so
    /// `body` copies what it keeps (EditModel.insert).
    func translate<R>(keyCode: UInt16, flags: CGEventFlags, isRepeat: Bool = false,
                      _ body: (UnsafeBufferPointer<UInt16>) -> R) -> R {
        translate(in: fixed ?? TISCopyCurrentKeyboardLayoutInputSource()?.takeRetainedValue(), keyCode: keyCode,
                  flags: flags, isRepeat: isRepeat, body)
    }

    /// `translate` in the given layout. The harness calls it to switch
    /// layouts between keys, which it must not do to the user's own.
    func translate<R>(in source: TISInputSource?, keyCode: UInt16, flags: CGEventFlags, isRepeat: Bool = false,
                      _ body: (UnsafeBufferPointer<UInt16>) -> R) -> R {
        var buf: (UInt16, UInt16, UInt16, UInt16) = (0, 0, 0, 0)
        defer { _ = withUnsafeMutableBytes(of: &buf) { memset_s($0.baseAddress, $0.count, 0, $0.count) } }
        var len = 0
        // The state indexes the records of the layout that left it; in
        // another one it means another accent (Norwegian ¨, then e in U.S.,
        // gives è). So a layout switch since the last key (the input menu,
        // ⌃Space) drops it.
        let id = source.flatMap { TISGetInputSourceProperty($0, kTISPropertyInputSourceID) }
            .map { Unmanaged<CFString>.fromOpaque($0).takeUnretainedValue() }
        if id == nil || stateLayout == nil || !CFEqual(id, stateLayout) { deadKeyState = 0 }
        stateLayout = id
        let status = withUnsafeMutablePointer(to: &buf) { tuple in
            tuple.withMemoryRebound(to: UniChar.self, capacity: 4) { out -> OSStatus in
                guard let source, let raw = TISGetInputSourceProperty(source, kTISPropertyUnicodeKeyLayoutData),
                      let bytes = CFDataGetBytePtr(Unmanaged<CFData>.fromOpaque(raw).takeUnretainedValue())
                else { return OSStatus(paramErr) }
                let action = UInt16(isRepeat ? kUCKeyActionAutoKey : kUCKeyActionDown)
                return withExtendedLifetime(source) {
                    bytes.withMemoryRebound(to: UCKeyboardLayout.self, capacity: 1) { layout in
                        UCKeyTranslate(layout, keyCode, action, (Self.carbonModifiers(flags) >> 8) & 0xFF,
                                       UInt32(LMGetKbdType()), 0, &deadKeyState, 4, &len, out)
                    }
                }
            }
        }
        if status != noErr {
            deadKeyState = 0
            len = 0
        }
        let n = min(max(len, 0), 4)
        hasDeadKey = n == 0 && deadKeyState != 0
        return withUnsafePointer(to: &buf) { tuple in
            tuple.withMemoryRebound(to: UInt16.self, capacity: 4) { body(UnsafeBufferPointer(start: $0, count: n)) }
        }
    }
}
