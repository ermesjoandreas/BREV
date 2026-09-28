// InputLab — spike app for Brev Phase 2 (U2 input, U3 accessibility). Bundle id no.brev.spike.input.
//
// One small window (top right). Views:
//   A      direct keyDown + UCKeyTranslate, NOT an NSTextInputClient, full accessibility overrides (design §7.1)
//   B      NSTextInputClient + interpretKeyEvents, full accessibility overrides
//   MIN    draws "DRAWNMIN7f3a" with Core Text; only the four overrides from CLAUDE.md §3.2
//   PLAIN  draws "DRAWNPLAIN7f3a"; no accessibility overrides at all (baseline)
//   FIELD  plain NSTextField "CTRLFIELD7f3a" (positive control)
//   Plain  NSButton (positive control for AXPress / posted clicks)
//   Human  HumanButton: sendAction gated on a human current event; accessibilityPerformPress -> false
// Every event that reaches NSApplication.sendEvent is logged with its CGEvent source fields.
// Characters of events with source PID 0 are masked unless --user is given (so nothing the owner types
// by accident during an automated run is written down).
// Commands arrive as distributed notifications named "no.brev.spike.input.cmd.<name>" (names only; a
// sandboxed receiver gets no userInfo). The app quits itself after --ttl seconds (default 90).

import AppKit
import Carbon.HIToolbox
import CoreText

setvbuf(stdout, nil, _IOLBF, 0)
let T0 = clock_gettime_nsec_np(CLOCK_UPTIME_RAW)
func log(_ s: String) {
    let ms = (clock_gettime_nsec_np(CLOCK_UPTIME_RAW) - T0) / 1_000_000
    print("t=\(ms) \(s)")
}
let ARGS = CommandLine.arguments
let USER_MODE = ARGS.contains("--user")
let EDIT_MENU = ARGS.contains("--editmenu")
// --sei A : secure input while A has focus (key window, active app). --sei AB : also while B has focus.
let SEI_VIEWS: String = { if let i = ARGS.firstIndex(of: "--sei"), i + 1 < ARGS.count { return ARGS[i + 1] }; return "" }()
func absNs() -> UInt64 { clock_gettime_nsec_np(CLOCK_UPTIME_RAW) }
// User mode only: what was typed (test text), and counts of event source fields per event type.
var typedA: [UInt16] = [], typedB: [UInt16] = []
var srcCounts: [String: Int] = [:]
let TTL: Double = { if let i = ARGS.firstIndex(of: "--ttl"), i + 1 < ARGS.count, let v = Double(ARGS[i + 1]) { return v }; return 90 }()

func hex(_ u: [UInt16]) -> String { u.map { String(format: "%04X", $0) }.joined(separator: " ") }
func hexS(_ s: String?) -> String { guard let s else { return "nil" }; return "[" + hex(Array(s.utf16)) + "]" }

struct Src { let cgNil: Bool; let pid: Int64; let state: Int64; let ud: Int64; let uid: Int64 }
func src(_ e: NSEvent) -> Src {
    guard let cg = e.cgEvent else { return Src(cgNil: true, pid: -999, state: -999, ud: -999, uid: -999) }
    return Src(cgNil: false,
               pid: cg.getIntegerValueField(.eventSourceUnixProcessID),
               state: cg.getIntegerValueField(.eventSourceStateID),
               ud: cg.getIntegerValueField(.eventSourceUserData),
               uid: cg.getIntegerValueField(.eventSourceUserID))
}
func fstr(_ s: Src) -> String { s.cgNil ? "cg=nil" : "pid=\(s.pid) state=\(s.state) ud=\(s.ud) uid=\(s.uid)" }
func mayShow(_ s: Src) -> Bool { USER_MODE || (!s.cgNil && s.pid != 0) }
func isKey(_ t: NSEvent.EventType) -> Bool { t == .keyDown || t == .keyUp || t == .flagsChanged }

// ---------------------------------------------------------------- keyboard layout (UCKeyTranslate)
final class KeyTranslator {
    private var source: TISInputSource?
    private var layoutData: CFData?
    var dead: UInt32 = 0
    var layoutID = "?"
    func reload() {
        guard let s = TISCopyCurrentKeyboardLayoutInputSource()?.takeRetainedValue() else { layoutID = "TIS=nil"; return }
        source = s
        if let p = TISGetInputSourceProperty(s, kTISPropertyInputSourceID) {
            layoutID = Unmanaged<CFString>.fromOpaque(p).takeUnretainedValue() as String
        }
        if let raw = TISGetInputSourceProperty(s, kTISPropertyUnicodeKeyLayoutData) {
            layoutData = Unmanaged<CFData>.fromOpaque(raw).takeUnretainedValue()
        } else { layoutData = nil }
    }
    /// Returns UTF-16 units, or nil on error. A dead key returns [] and keeps `dead`.
    func translate(keyCode: UInt16, flags: NSEvent.ModifierFlags, isRepeat: Bool) -> (units: [UInt16], status: OSStatus) {
        reload()
        guard let data = layoutData, let ptr = CFDataGetBytePtr(data) else { return ([], -1) }
        var mods: UInt32 = 0
        if flags.contains(.shift) { mods |= UInt32(shiftKey) }
        if flags.contains(.option) { mods |= UInt32(optionKey) }
        if flags.contains(.capsLock) { mods |= UInt32(alphaLock) }
        if flags.contains(.control) { mods |= UInt32(controlKey) }
        var buf = [UInt16](repeating: 0, count: 4)
        var len = 0
        let st = ptr.withMemoryRebound(to: UCKeyboardLayout.self, capacity: 1) { lp in
            UCKeyTranslate(lp, keyCode, UInt16(isRepeat ? kUCKeyActionAutoKey : kUCKeyActionDown), (mods >> 8) & 0xFF,
                           UInt32(LMGetKbdType()), 0, &dead, 4, &len, &buf)
        }
        let out = Array(buf[0..<len])
        for i in 0..<buf.count { buf[i] = 0 }
        return (out, st)
    }
}

// ---------------------------------------------------------------- secure event input (balanced)
enum SecureInput {
    static var on = false
    static func enable() { if !on { let st = EnableSecureEventInput(); on = true; log("SEI enable status=\(st) abs=\(absNs())") } }
    static func disable() { if on { let st = DisableSecureEventInput(); on = false; log("SEI disable status=\(st) abs=\(absNs())") } }
}

// ---------------------------------------------------------------- accessibility overrides
// Full set from docs/PHASE2_DESIGN.md §7.1 (A and B).
class OpaqueBase: NSView {
    override var isFlipped: Bool { true }
    override func isAccessibilityElement() -> Bool { false }
    override func accessibilityRole() -> NSAccessibility.Role? { nil }
    override func accessibilityRoleDescription() -> String? { nil }
    override func accessibilityValue() -> Any? { nil }
    override func accessibilityChildren() -> [Any]? { [] }
    override func accessibilityLabel() -> String? { nil }
    override func accessibilityTitle() -> String? { nil }
    override func accessibilityHelp() -> String? { nil }
    override func accessibilitySelectedText() -> String? { nil }
    override func accessibilityNumberOfCharacters() -> Int { 0 }
    override func accessibilityString(for range: NSRange) -> String? { nil }
    override func accessibilityAttributedString(for range: NSRange) -> NSAttributedString? { nil }
    override func accessibilityHitTest(_ point: NSPoint) -> Any? { nil }
    override func menu(for event: NSEvent) -> NSMenu? { nil }
    override func validRequestor(forSendType sendType: NSPasteboard.PasteboardType?, returnType: NSPasteboard.PasteboardType?) -> Any? { nil }
}

func drawUnits(_ u: ArraySlice<UInt16>, in view: NSView, y: CGFloat) {
    guard let ctx = NSGraphicsContext.current?.cgContext, !u.isEmpty else { return }
    let s = u.withUnsafeBufferPointer { CFStringCreateWithCharacters(nil, $0.baseAddress, $0.count)! }
    let attr = CFAttributedStringCreateMutable(nil, 0)!
    CFAttributedStringReplaceString(attr, CFRange(location: 0, length: 0), s)
    CFAttributedStringSetAttribute(attr, CFRange(location: 0, length: CFStringGetLength(s)), kCTFontAttributeName,
                                   CTFontCreateWithName("Helvetica" as CFString, 13, nil))
    CFAttributedStringSetAttribute(attr, CFRange(location: 0, length: CFStringGetLength(s)),
                                   kCTForegroundColorFromContextAttributeName, kCFBooleanTrue)
    let line = CTLineCreateWithAttributedString(attr)
    ctx.saveGState()
    ctx.textMatrix = .identity
    ctx.translateBy(x: 6, y: y); ctx.scaleBy(x: 1, y: -1)
    NSColor.labelColor.setFill()
    ctx.setFillColor(NSColor.labelColor.cgColor)
    CTLineDraw(line, ctx)
    ctx.restoreGState()
}

class Model {
    var buf = [UInt16](repeating: 0, count: 8192)
    var n = 0
    func append(_ u: [UInt16]) { for c in u where n < buf.count { buf[n] = c; n += 1 } }
    func backspace() { if n > 0 { n -= 1; buf[n] = 0 } }
    func wipe() { buf.withUnsafeMutableBytes { p in _ = memset_s(p.baseAddress, p.count, 0, p.count) }; n = 0 }
}

// ---------------------------------------------------------------- view A: direct key handling
final class ViewA: OpaqueBase {
    let model = Model()
    let kt = KeyTranslator()
    override var acceptsFirstResponder: Bool { true }
    override func becomeFirstResponder() -> Bool { log("A becomeFirstResponder"); needsDisplay = true; DispatchQueue.main.async { autoSEI() }; return true }
    override func resignFirstResponder() -> Bool { kt.dead = 0; log("A resignFirstResponder"); needsDisplay = true; DispatchQueue.main.async { autoSEI() }; return true }
    override func performKeyEquivalent(with e: NSEvent) -> Bool {
        if window?.firstResponder === self { log("A performKeyEquivalent kc=\(e.keyCode) -> false") }
        return false
    }
    override func keyDown(with e: NSEvent) {
        let s = src(e)
        let f = e.modifierFlags
        if f.contains(.command) || f.contains(.control) { log("A keyDown kc=\(e.keyCode) cmd/ctrl ignored \(fstr(s))"); return }
        switch e.keyCode {
        case 51: model.backspace(); log("A keyDown kc=51 backspace \(fstr(s))")
        case 36, 76: model.append([0x0A]); log("A keyDown kc=\(e.keyCode) return \(fstr(s))")
        default:
            let r = kt.translate(keyCode: e.keyCode, flags: f, isRepeat: e.isARepeat)
            model.append(r.units)
            if USER_MODE { typedA += r.units }
            let shown = mayShow(s)
            log("A keyDown kc=\(e.keyCode) mods=0x\(String(f.rawValue, radix: 16)) repeat=\(e.isARepeat) layout=\(kt.layoutID) "
                + "uck=\(shown ? "[" + hex(r.units) + "]" : "<masked n=\(r.units.count)>") st=\(r.status) dead=\(kt.dead) "
                + "chars=\(shown ? hexS(e.characters) : "<masked>") charsIgn=\(shown ? hexS(e.charactersIgnoringModifiers) : "<masked>") "
                + "\(fstr(s)) sei=\(IsSecureEventInputEnabled()) active=\(NSApp.isActive)")
        }
        needsDisplay = true
    }
    override func keyUp(with e: NSEvent) { log("A keyUp kc=\(e.keyCode) \(fstr(src(e)))") }
    override func flagsChanged(with e: NSEvent) { log("A flagsChanged kc=\(e.keyCode) mods=0x\(String(e.modifierFlags.rawValue, radix: 16)) \(fstr(src(e)))") }
    override func mouseDown(with e: NSEvent) { window?.makeFirstResponder(self); log("A mouseDown \(fstr(src(e)))") }
    override func draw(_ r: NSRect) {
        (window?.firstResponder === self ? NSColor.systemGreen : NSColor.separatorColor).setStroke()
        NSBezierPath(rect: bounds.insetBy(dx: 1, dy: 1)).stroke()
        drawUnits(model.buf[0..<model.n], in: self, y: 22)
    }
}

// ---------------------------------------------------------------- view B: NSTextInputClient
final class ViewB: OpaqueBase, NSTextInputClient {
    let model = Model()
    var inKeyDown = false
    var markedLen = 0
    override var acceptsFirstResponder: Bool { true }
    override func becomeFirstResponder() -> Bool { log("B becomeFirstResponder"); needsDisplay = true; DispatchQueue.main.async { autoSEI() }; return true }
    override func resignFirstResponder() -> Bool { log("B resignFirstResponder"); needsDisplay = true; DispatchQueue.main.async { autoSEI() }; return true }
    override func keyDown(with e: NSEvent) {
        let s = src(e)
        log("B keyDown kc=\(e.keyCode) mods=0x\(String(e.modifierFlags.rawValue, radix: 16)) repeat=\(e.isARepeat) "
            + "chars=\(mayShow(s) ? hexS(e.characters) : "<masked>") \(fstr(s)) sei=\(IsSecureEventInputEnabled())")
        inKeyDown = true
        interpretKeyEvents([e])
        inKeyDown = false
    }
    override func keyUp(with e: NSEvent) { log("B keyUp kc=\(e.keyCode) \(fstr(src(e)))") }
    override func mouseDown(with e: NSEvent) {
        window?.makeFirstResponder(self)
        let used = inputContext?.handleEvent(e) ?? false
        log("B mouseDown handledByInputContext=\(used) \(fstr(src(e)))")
    }
    private func units(_ a: Any) -> [UInt16] {
        if let s = a as? String { return Array(s.utf16) }
        if let s = a as? NSAttributedString { return Array(s.string.utf16) }
        return []
    }
    private func show() -> Bool { USER_MODE || (NSApp.currentEvent.map { src($0).pid != 0 } ?? true) }
    func insertText(_ string: Any, replacementRange: NSRange) {
        let u = units(string)
        let cur = NSApp.currentEvent
        log("B insertText inKeyDown=\(inKeyDown) n=\(u.count) units=\(show() ? "[" + hex(u) + "]" : "<masked>") repl=\(replacementRange) "
            + "currentEvent=\(cur.map { "\($0.type.rawValue)" } ?? "nil") \(cur.map { fstr(src($0)) } ?? "")")
        if markedLen > 0 { model.n = max(0, model.n - markedLen); markedLen = 0 }
        model.append(u)
        if USER_MODE { typedB += u }
        needsDisplay = true
    }
    override func doCommand(by selector: Selector) {
        log("B doCommand \(NSStringFromSelector(selector)) inKeyDown=\(inKeyDown)")
        if selector == #selector(deleteBackward(_:)) { model.backspace(); needsDisplay = true }
    }
    func setMarkedText(_ string: Any, selectedRange: NSRange, replacementRange: NSRange) {
        let u = units(string)
        log("B setMarkedText inKeyDown=\(inKeyDown) n=\(u.count) units=\(show() ? "[" + hex(u) + "]" : "<masked>") sel=\(selectedRange) repl=\(replacementRange)")
        if markedLen > 0 { model.n = max(0, model.n - markedLen) }
        model.append(u); markedLen = u.count
        needsDisplay = true
    }
    func unmarkText() { log("B unmarkText"); markedLen = 0 }
    func selectedRange() -> NSRange { NSRange(location: model.n, length: 0) }
    func markedRange() -> NSRange { markedLen > 0 ? NSRange(location: model.n - markedLen, length: markedLen) : NSRange(location: NSNotFound, length: 0) }
    func hasMarkedText() -> Bool { markedLen > 0 }
    func attributedSubstring(forProposedRange range: NSRange, actualRange: NSRangePointer?) -> NSAttributedString? {
        log("B attributedSubstring(forProposedRange: \(range)) -> nil")
        return nil
    }
    func validAttributesForMarkedText() -> [NSAttributedString.Key] { [] }
    func firstRect(forCharacterRange range: NSRange, actualRange: NSRangePointer?) -> NSRect {
        guard let w = window else { return .zero }
        return w.convertToScreen(convert(NSRect(x: 6, y: 4, width: 2, height: 16), to: nil))
    }
    func characterIndex(for point: NSPoint) -> Int { log("B characterIndex(for:)"); return NSNotFound }
    override func draw(_ r: NSRect) {
        (window?.firstResponder === self ? NSColor.systemBlue : NSColor.separatorColor).setStroke()
        NSBezierPath(rect: bounds.insetBy(dx: 1, dy: 1)).stroke()
        drawUnits(model.buf[0..<model.n], in: self, y: 22)
    }
}

// ---------------------------------------------------------------- MIN (four overrides) and PLAIN (none)
final class ViewMin: NSView {
    override var isFlipped: Bool { true }
    override func isAccessibilityElement() -> Bool { false }
    override func accessibilityRole() -> NSAccessibility.Role? { nil }
    override func accessibilityValue() -> Any? { nil }
    override func accessibilityChildren() -> [Any]? { [] }
    override func draw(_ r: NSRect) { drawUnits(ArraySlice(Array("DRAWNMIN7f3a".utf16)), in: self, y: 22) }
}
final class ViewPlain: NSView {
    override var isFlipped: Bool { true }
    override func draw(_ r: NSRect) { drawUnits(ArraySlice(Array("DRAWNPLAIN7f3a".utf16)), in: self, y: 22) }
}

// RAW: a naive NSTextInputClient with NO accessibility overrides whose text is "RAWCLIENT7f3a" (does AppKit
// expose a text input client through Accessibility on its own?).
final class ViewBRaw: NSView, NSTextInputClient {
    let text = "RAWCLIENT7f3a" as NSString
    override var acceptsFirstResponder: Bool { true }
    override func keyDown(with e: NSEvent) { interpretKeyEvents([e]) }
    func insertText(_ string: Any, replacementRange: NSRange) {}
    override func doCommand(by selector: Selector) {}
    func setMarkedText(_ string: Any, selectedRange: NSRange, replacementRange: NSRange) {}
    func unmarkText() {}
    func selectedRange() -> NSRange { NSRange(location: text.length, length: 0) }
    func markedRange() -> NSRange { NSRange(location: NSNotFound, length: 0) }
    func hasMarkedText() -> Bool { false }
    func attributedSubstring(forProposedRange range: NSRange, actualRange: NSRangePointer?) -> NSAttributedString? {
        log("RAW attributedSubstring(forProposedRange: \(range))")
        let r = NSIntersectionRange(range, NSRange(location: 0, length: text.length))
        actualRange?.pointee = r
        return NSAttributedString(string: text.substring(with: r))
    }
    func validAttributesForMarkedText() -> [NSAttributedString.Key] { [] }
    func firstRect(forCharacterRange range: NSRange, actualRange: NSRangePointer?) -> NSRect {
        window.map { $0.convertToScreen(convert(bounds, to: nil)) } ?? .zero
    }
    func characterIndex(for point: NSPoint) -> Int { 0 }
    override func draw(_ r: NSRect) { NSColor.separatorColor.setStroke(); NSBezierPath(rect: bounds.insetBy(dx: 1, dy: 1)).stroke() }
}

// ---------------------------------------------------------------- buttons
func humanEvent(_ e: NSEvent?) -> Bool {
    guard let e, let cg = e.cgEvent else { return false }
    guard [.leftMouseUp, .keyDown, .keyUp].contains(e.type) else { return false }
    return cg.getIntegerValueField(.eventSourceUnixProcessID) == 0
}
final class HumanButtonCell: NSButtonCell {
    override func accessibilityPerformPress() -> Bool { log("HumanCell accessibilityPerformPress -> false"); return false }
}
final class HumanButton: NSButton {
    override class var cellClass: AnyClass? { get { HumanButtonCell.self } set {} }
    override func sendAction(_ action: Selector?, to target: Any?) -> Bool {
        let e = NSApp.currentEvent
        let ok = humanEvent(e)
        log("Human sendAction currentEvent=\(e.map { "\($0.type.rawValue)" } ?? "nil") \(e.map { fstr(src($0)) } ?? "") accepted=\(ok)")
        return ok ? super.sendAction(action, to: target) : false
    }
    override func accessibilityPerformPress() -> Bool { log("Human accessibilityPerformPress -> false"); return false }
}

final class Target: NSObject {
    @objc func plain(_ s: Any?) {
        let e = NSApp.currentEvent
        log("ACTION plain currentEvent=\(e.map { "\($0.type.rawValue)" } ?? "nil") \(e.map { fstr(src($0)) } ?? "")")
    }
    @objc func human(_ s: Any?) { log("ACTION human (ran)") }
    @objc func menuTest(_ s: Any?) {
        let e = NSApp.currentEvent
        log("ACTION menuTest currentEvent=\(e.map { "\($0.type.rawValue)" } ?? "nil") \(e.map { fstr(src($0)) } ?? "")")
    }
}

// ---------------------------------------------------------------- application
final class LabApp: NSApplication {
    override func sendEvent(_ e: NSEvent) {
        let s = src(e)
        var extra = ""
        if isKey(e.type) {
            extra = " kc=\(e.keyCode) mods=0x\(String(e.modifierFlags.rawValue, radix: 16))"
            if e.type != .flagsChanged { extra += " repeat=\(e.isARepeat) chars=\(mayShow(s) ? hexS(e.characters) : "<masked>")" }
        } else if e.type == .appKitDefined || e.type == .systemDefined || e.type == .applicationDefined {
            extra = " subtype=\(e.subtype.rawValue)"
        } else if e.type.rawValue <= 7 || e.type == .scrollWheel || e.type == .otherMouseDown || e.type == .otherMouseUp {
            extra = " loc=\(Int(e.locationInWindow.x)),\(Int(e.locationInWindow.y)) win=\(e.windowNumber)"
        }
        log("EV type=\(e.type.rawValue)\(extra) \(fstr(s)) active=\(isActive) keyWin=\(keyWindow != nil)")
        if USER_MODE { srcCounts["type=\(e.type.rawValue) \(fstr(s).replacingOccurrences(of: " ud=0", with: ""))", default: 0] += 1 }
        super.sendEvent(e)
    }
}

let app = LabApp.shared
app.setActivationPolicy(.regular)
let target = Target()

let win = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 460, height: 250), styleMask: [.titled, .closable],
                   backing: .buffered, defer: false)
win.title = "InputLab"
win.isReleasedWhenClosed = false
let cv = NSView(frame: win.contentRect(forFrameRect: win.frame))
win.contentView = cv

let viewA = ViewA(frame: NSRect(x: 0, y: 0, width: 210, height: 56))
let scrollA = NSScrollView(frame: NSRect(x: 10, y: 180, width: 210, height: 56))
scrollA.documentView = viewA
scrollA.hasVerticalScroller = true
let viewB = ViewB(frame: NSRect(x: 240, y: 180, width: 210, height: 56))
let viewMin = ViewMin(frame: NSRect(x: 10, y: 115, width: 210, height: 56))
let viewPlain = ViewPlain(frame: NSRect(x: 240, y: 115, width: 210, height: 56))
let field = NSTextField(frame: NSRect(x: 10, y: 70, width: 210, height: 24))
field.stringValue = "CTRLFIELD7f3a"
let plainButton = NSButton(title: "Plain", target: target, action: #selector(Target.plain(_:)))
plainButton.frame = NSRect(x: 240, y: 66, width: 100, height: 32)
let viewRaw = ViewBRaw(frame: NSRect(x: 10, y: 10, width: 440, height: 40))
let humanButton = HumanButton(title: "Human", target: target, action: #selector(Target.human(_:)))
humanButton.frame = NSRect(x: 350, y: 66, width: 100, height: 32)
for v in [scrollA, viewB, viewMin, viewPlain, field, plainButton, humanButton, viewRaw] as [NSView] { cv.addSubview(v) }

// menus
let mainMenu = NSMenu()
let appItem = NSMenuItem(); mainMenu.addItem(appItem)
let appMenu = NSMenu(title: "InputLab")
appMenu.addItem(withTitle: "Avslutt InputLab", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
appItem.submenu = appMenu
let fileItem = NSMenuItem(); mainMenu.addItem(fileItem)
let fileMenu = NSMenu(title: "Arkiv")
let testItem = NSMenuItem(title: "Testvalg", action: #selector(Target.menuTest(_:)), keyEquivalent: "")
testItem.target = target
fileMenu.addItem(testItem)
fileItem.submenu = fileMenu
if EDIT_MENU {
    let editItem = NSMenuItem(); mainMenu.addItem(editItem)
    let edit = NSMenu(title: "Edit")
    edit.addItem(withTitle: "Undo", action: Selector(("undo:")), keyEquivalent: "z")
    edit.addItem(.separator())
    edit.addItem(withTitle: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
    edit.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
    edit.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
    edit.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
    editItem.submenu = edit
}
app.mainMenu = mainMenu

func dumpMenu(_ m: NSMenu, _ depth: Int) {
    for it in m.items {
        let pad = String(repeating: "  ", count: depth)
        log("MENU \(pad)'\(it.title)' action=\(it.action.map { NSStringFromSelector($0) } ?? "nil") key='\(it.keyEquivalent)' hidden=\(it.isHidden) alt=\(it.isAlternate)")
        if let s = it.submenu { dumpMenu(s, depth + 1) }
    }
}

func screenRectCG(_ v: NSView) -> String {
    guard let w = v.window else { return "?" }
    let r = w.convertToScreen(v.convert(v.bounds, to: nil))
    let h = NSScreen.screens[0].frame.maxY
    return "\(Int(r.midX)),\(Int(h - r.midY))"
}

/// With --sei: secure input exactly while a chosen view has focus in the key window of the active app.
func autoSEI() {
    guard !SEI_VIEWS.isEmpty else { return }
    let fr = win.firstResponder
    let want = NSApp.isActive && win.isKeyWindow &&
        ((fr === viewA && SEI_VIEWS.contains("A")) || (fr === viewB && SEI_VIEWS.contains("B")))
    if want { SecureInput.enable() } else { SecureInput.disable() }
}

func responderChain() -> String {
    var r: NSResponder? = win.firstResponder
    var out: [String] = []
    while let x = r { out.append(String(describing: type(of: x))); r = x.nextResponder }
    return out.joined(separator: ">")
}

func status(_ tag: String) {
    let kt = KeyTranslator(); kt.reload()
    var kbd = "?"
    if let s = TISCopyCurrentKeyboardInputSource()?.takeRetainedValue(), let p = TISGetInputSourceProperty(s, kTISPropertyInputSourceID) {
        kbd = Unmanaged<CFString>.fromOpaque(p).takeUnretainedValue() as String
    }
    log("STATUS \(tag) active=\(NSApp.isActive) hidden=\(NSApp.isHidden) keyWin=\(NSApp.keyWindow != nil) winIsKey=\(win.isKeyWindow) "
        + "fr=\(win.firstResponder.map { String(describing: type(of: $0)) } ?? "nil") seiFlag=\(SecureInput.on) "
        + "IsSecureEventInputEnabled=\(IsSecureEventInputEnabled()) layout=\(kt.layoutID) kbdSource=\(kbd) "
        + "A.inputContext=\(viewA.inputContext == nil ? "nil" : "set") B.inputContext=\(viewB.inputContext == nil ? "nil" : "set") "
        + "field.inputContext=\(field.inputContext == nil ? "nil" : "set") current=\(NSTextInputContext.current.map { String(describing: type(of: $0.client)) } ?? "nil")")
}

func services() {
    let types: [(NSPasteboard.PasteboardType?, NSPasteboard.PasteboardType?)] = [(.string, nil), (nil, .string), (.string, .string), (.rtf, .rtf)]
    for (v, name) in [(viewA as NSView, "A"), (viewB, "B"), (viewMin, "MIN"), (viewPlain, "PLAIN")] {
        let r = types.map { v.validRequestor(forSendType: $0.0, returnType: $0.1).map { String(describing: type(of: $0)) } ?? "nil" }
        log("SERVICES \(name) validRequestor(string,nil|nil,string|string,string|rtf,rtf)=\(r)")
    }
    let r = types.map { NSApp.validRequestor(forSendType: $0.0, returnType: $0.1).map { String(describing: type(of: $0)) } ?? "nil" }
    log("SERVICES NSApp validRequestor=\(r) servicesMenu=\(NSApp.servicesMenu == nil ? "nil" : "set") chain=\(responderChain())")
    if let fe = win.fieldEditor(false, for: field) as NSText? {
        log("SERVICES fieldEditor class=\(type(of: fe)) validRequestor(string,string)=\(fe.validRequestor(forSendType: .string, returnType: .string).map { String(describing: type(of: $0)) } ?? "nil")")
    }
    if #available(macOS 15.2, *) { log("WRITINGTOOLS isWritingToolsAvailable=\(NSWritingToolsCoordinator.isWritingToolsAvailable) A.coordinator=\(viewA.writingToolsCoordinator == nil ? "nil" : "set") B.coordinator=\(viewB.writingToolsCoordinator == nil ? "nil" : "set")") }
}

func scan(_ tag: String) {
    var r = brev_scan_result()
    brev_scan(&r)
    var tags: [String] = []
    withUnsafeBytes(of: &r.by_tag) { raw in
        let p = raw.bindMemory(to: UInt64.self)
        for i in 0..<256 where p[i] > 0 { tags.append("\(i):\(p[i])") }
    }
    log("SCAN \(tag) u8=\(r.utf8_hits) u16=\(r.utf16_hits) regions=\(r.regions) MB=\(r.bytes >> 20) tags=\(tags) scribble=\(ProcessInfo.processInfo.environment["MallocScribble"] ?? "unset")")
}

let commands: [String: () -> Void] = [
    "focusA": { win.makeFirstResponder(viewA); status("focusA") },
    "focusB": { win.makeFirstResponder(viewB); status("focusB") },
    "focusField": { win.makeFirstResponder(field); status("focusField") },
    "focusRaw": { win.makeFirstResponder(viewRaw); status("focusRaw") },
    "focusNone": { win.makeFirstResponder(nil); status("focusNone") },
    "seiOn": { SecureInput.enable(); status("seiOn") },
    "seiOff": { SecureInput.disable(); status("seiOff") },
    "status": { status("cmd") },
    "wipe": { viewA.model.wipe(); viewB.model.wipe(); viewA.needsDisplay = true; viewB.needsDisplay = true; log("WIPED") },
    "scan": { scan("cmd") },
    "hide": { NSApp.hide(nil); log("CMD hide issued") },
    "unhide": { NSApp.unhide(nil); log("CMD unhide issued") },
    "deactivate": { NSApp.deactivate(); log("CMD deactivate issued") },
    "activate": { if #available(macOS 14.0, *) { NSApp.activate() } else { NSApp.activate(ignoringOtherApps: true) }; log("CMD activate issued") },
    "menus": { dumpMenu(NSApp.mainMenu ?? NSMenu(), 0) },
    "services": { services() },
    "geometry": {
        log("GEOM A=\(screenRectCG(viewA)) B=\(screenRectCG(viewB)) MIN=\(screenRectCG(viewMin)) PLAIN=\(screenRectCG(viewPlain)) "
            + "FIELD=\(screenRectCG(field)) RAW=\(screenRectCG(viewRaw)) PlainBtn=\(screenRectCG(plainButton)) HumanBtn=\(screenRectCG(humanButton)) winNumber=\(win.windowNumber)")
    },
    "quit": { log("CMD quit"); SecureInput.disable(); NSApp.terminate(nil) },
]
let dnc = DistributedNotificationCenter.default()
for (name, f) in commands {
    dnc.addObserver(forName: Notification.Name("no.brev.spike.input.cmd." + name), object: nil, queue: .main) { _ in
        log("CMD \(name)"); f()
    }
}
// Deliver even while inactive (NSApplication suspends distributed notifications when inactive by default).
dnc.suspended = false

let nc = NotificationCenter.default
for (n, label) in [(NSApplication.didBecomeActiveNotification, "didBecomeActive"), (NSApplication.didResignActiveNotification, "didResignActive"),
                   (NSApplication.didHideNotification, "didHide"), (NSApplication.didUnhideNotification, "didUnhide")] {
    nc.addObserver(forName: n, object: nil, queue: .main) { _ in
        log("NOTE \(label) IsSecureEventInputEnabled=\(IsSecureEventInputEnabled()) seiFlag=\(SecureInput.on)")
    }
}
nc.addObserver(forName: NSWindow.didBecomeKeyNotification, object: win, queue: .main) { _ in log("NOTE window didBecomeKey"); autoSEI() }
nc.addObserver(forName: NSWindow.didResignKeyNotification, object: win, queue: .main) { _ in log("NOTE window didResignKey"); autoSEI() }
nc.addObserver(forName: NSApplication.didBecomeActiveNotification, object: nil, queue: .main) { _ in autoSEI() }
nc.addObserver(forName: NSApplication.didResignActiveNotification, object: nil, queue: .main) { _ in autoSEI() }

final class Delegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ n: Notification) {
        if let s = NSScreen.main?.visibleFrame {
            win.setFrameTopLeftPoint(NSPoint(x: s.maxX - win.frame.width - 20, y: s.maxY - 20))
        }
        win.makeKeyAndOrderFront(nil)
        win.makeFirstResponder(viewA)
        if #available(macOS 14.0, *) { NSApp.activate() } else { NSApp.activate(ignoringOtherApps: true) }
        log("ready pid=\(getpid()) user=\(USER_MODE) editmenu=\(EDIT_MENU) ttl=\(TTL) sandbox=\(ProcessInfo.processInfo.environment["APP_SANDBOX_CONTAINER_ID"] ?? "none")")
        commands["geometry"]!()
        status("launch")
        DispatchQueue.main.asyncAfter(deadline: .now() + TTL) { log("TTL reached, quitting"); SecureInput.disable(); NSApp.terminate(nil) }
    }
    func applicationWillTerminate(_ n: Notification) {
        SecureInput.disable()
        if USER_MODE {
            for k in srcCounts.keys.sorted() { log("SUMMARY EVSRC \(k) count=\(srcCounts[k]!)") }
            log("SUMMARY A typed: \(String(utf16CodeUnits: typedA, count: typedA.count))")
            log("SUMMARY B typed: \(String(utf16CodeUnits: typedB, count: typedB.count))")
        }
        log("terminate")
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ s: NSApplication) -> Bool { true }
}
let delegate = Delegate()
app.delegate = delegate
app.run()
