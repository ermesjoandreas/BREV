// poster — sends input ONLY to one given process id (the InputLab test app), never to the session or HID.
//   poster notify <cmd>                                  distributed notification no.brev.spike.input.cmd.<cmd>
//   poster keys <pid> <src> <pidmode> <tag> <spec...>    CGEvent.postToPid key down/up pairs
//        src: none | private | combined | hid
//        pidmode: keep (creator default) | zero (field 41 = 0) | target (= <pid>) | other (= 1) | hw (41 = 0 and 45 = 1)
//        tag: written to field 42 (eventSourceUserData)
//        spec: <keycode>[+s][+o][+r][+d][+u][+w] (shift, option, autorepeat, down only, up only, wait 100 ms) | text:<A-Z a-z - and space, explicit unicode string>
//   poster ax <pid> <keycode...>                         AXUIElementPostKeyboardEvent to the app element of <pid>
//   poster click <pid> <x> <y> <src> <pidmode> <tag>     CGEvent.postToPid left mouse down/up at global (x, y)
//   poster tap <pid> <seconds>                           listen-only event tap for <pid> only (tapCreateForPid)
import ApplicationServices
import Carbon.HIToolbox
import CoreGraphics
import Foundation

setvbuf(stdout, nil, _IOLBF, 0)
let a = CommandLine.arguments
func die(_ s: String) -> Never { print(s); exit(2) }
guard a.count >= 3 else { die("usage: see source") }

func source(_ k: String) -> CGEventSource? {
    switch k {
    case "none": return nil
    case "private": return CGEventSource(stateID: .privateState)
    case "combined": return CGEventSource(stateID: .combinedSessionState)
    case "hid": return CGEventSource(stateID: .hidSystemState)
    default: die("bad src \(k)")
    }
}
func stamp(_ e: CGEvent, _ mode: String, _ pid: pid_t, _ tag: Int64) {
    switch mode {
    case "keep": break
    case "zero": e.setIntegerValueField(.eventSourceUnixProcessID, value: 0)
    case "target": e.setIntegerValueField(.eventSourceUnixProcessID, value: Int64(pid))
    case "other": e.setIntegerValueField(.eventSourceUnixProcessID, value: 1)
    case "hw": e.setIntegerValueField(.eventSourceUnixProcessID, value: 0); e.setIntegerValueField(.eventSourceStateID, value: 1)
    default: die("bad pidmode \(mode)")
    }
    e.setIntegerValueField(.eventSourceUserData, value: tag)
}
func fields(_ e: CGEvent) -> String {
    "pid=\(e.getIntegerValueField(.eventSourceUnixProcessID)) state=\(e.getIntegerValueField(.eventSourceStateID)) ud=\(e.getIntegerValueField(.eventSourceUserData))"
}

// ASCII letters, '-' and space on the Norwegian (and US) layout, by Carbon virtual key constant.
let letterKeys: [Character: Int] = [
    "a": kVK_ANSI_A, "b": kVK_ANSI_B, "c": kVK_ANSI_C, "d": kVK_ANSI_D, "e": kVK_ANSI_E, "f": kVK_ANSI_F, "g": kVK_ANSI_G,
    "h": kVK_ANSI_H, "i": kVK_ANSI_I, "j": kVK_ANSI_J, "k": kVK_ANSI_K, "l": kVK_ANSI_L, "m": kVK_ANSI_M, "n": kVK_ANSI_N,
    "o": kVK_ANSI_O, "p": kVK_ANSI_P, "q": kVK_ANSI_Q, "r": kVK_ANSI_R, "s": kVK_ANSI_S, "t": kVK_ANSI_T, "u": kVK_ANSI_U,
    "v": kVK_ANSI_V, "w": kVK_ANSI_W, "x": kVK_ANSI_X, "y": kVK_ANSI_Y, "z": kVK_ANSI_Z,
    "-": kVK_ANSI_Slash /* '-' on the Norwegian layout */, " ": kVK_Space,
]

switch a[1] {
case "notify":
    DistributedNotificationCenter.default().postNotificationName(Notification.Name("no.brev.spike.input.cmd." + a[2]), object: nil,
                                                                userInfo: nil, deliverImmediately: true)
    print("notified \(a[2])")

case "keys":
    guard a.count >= 6, let pid = pid_t(a[2]), let tag = Int64(a[5]) else { die("keys <pid> <src> <pidmode> <tag> <spec...>") }
    let src = source(a[3]); let mode = a[4]
    var sent = 0
    func post(_ kc: CGKeyCode, flags: CGEventFlags, rep: Bool, uni: UniChar?, phases: [Bool] = [true, false], wait: UInt32 = 25_000) {
        for down in phases {
            guard let e = CGEvent(keyboardEventSource: src, virtualKey: kc, keyDown: down) else { die("no event") }
            e.flags = flags
            if rep { e.setIntegerValueField(.keyboardEventAutorepeat, value: 1) }
            if var u = uni { e.keyboardSetUnicodeString(stringLength: 1, unicodeString: &u) }
            stamp(e, mode, pid, tag)
            if sent == 0 { print("first event before post: \(fields(e))") }
            e.postToPid(pid); sent += 1
            usleep(wait)
            if rep { break }  // autorepeat: key down only
        }
    }
    for spec in a[6...] {
        if spec.hasPrefix("text:") {
            for ch in spec.dropFirst(5) {
                let lower = Character(ch.lowercased())
                guard let kc = letterKeys[lower] else { die("no key for \(ch)") }
                let shift = ch.isUppercase
                post(CGKeyCode(kc), flags: shift ? .maskShift : [], rep: false, uni: ch.utf16.first)
            }
        } else {
            let parts = spec.split(separator: "+")
            guard let kc = UInt16(parts[0]) else { die("bad spec \(spec)") }
            var f: CGEventFlags = []
            var rep = false
            var phases = [true, false]
            var wait: UInt32 = 25_000
            for p in parts.dropFirst() {
                if p.contains("s") { f.insert(.maskShift) }
                if p.contains("o") { f.insert(.maskAlternate) }
                if p.contains("r") { rep = true }
                if p.contains("d") { phases = [true] }
                if p.contains("u") { phases = [false] }
                if p.contains("w") { wait = 100_000 }
            }
            post(kc, flags: f, rep: rep, uni: nil, phases: phases, wait: wait)
        }
    }
    print("posted \(sent) key events to pid \(pid) src=\(a[3]) pidmode=\(mode) tag=\(tag)")

case "ax":
    guard let pid = pid_t(a[2]) else { die("ax <pid> <kc...>") }
    _ = AXUIElementCreateApplication(pid)
    for s in a[3...] {
        guard let kc = UInt16(s) else { die("bad kc") }
        let r1 = axpost_key(pid, kc, 1)
        usleep(25_000)
        let r2 = axpost_key(pid, kc, 0)
        usleep(25_000)
        print("AXUIElementPostKeyboardEvent kc=\(kc) down=\(r1) up=\(r2)")
    }

case "click":
    guard a.count >= 8, let pid = pid_t(a[2]), let x = Double(a[3]), let y = Double(a[4]), let tag = Int64(a[7]) else {
        die("click <pid> <x> <y> <src> <pidmode> <tag>")
    }
    let src = source(a[5])
    let p = CGPoint(x: x, y: y)
    for t in [CGEventType.leftMouseDown, .leftMouseUp] {
        guard let e = CGEvent(mouseEventSource: src, mouseType: t, mouseCursorPosition: p, mouseButton: .left) else { die("no event") }
        e.setIntegerValueField(.mouseEventClickState, value: 1)
        if a.count >= 9, let wn = Int64(a[8]) {  // optional: the target window number (fields 91 and 92)
            e.setIntegerValueField(.mouseEventWindowUnderMousePointer, value: wn)
            e.setIntegerValueField(.mouseEventWindowUnderMousePointerThatCanHandleThisEvent, value: wn)
        }
        stamp(e, a[6], pid, tag)
        e.postToPid(pid)
        usleep(60_000)
    }
    print("posted click to pid \(pid) at \(x),\(y) src=\(a[5]) pidmode=\(a[6]) tag=\(tag)")

case "tap":
    guard a.count >= 4, let pid = pid_t(a[2]), let secs = Double(a[3]) else { die("tap <pid> <seconds>") }
    let mask = (1 << CGEventType.keyDown.rawValue) | (1 << CGEventType.keyUp.rawValue)
    let cb: CGEventTapCallBack = { _, type, e, _ in
        if type == .keyDown || type == .keyUp {
            var len = 0
            var buf = [UniChar](repeating: 0, count: 8)
            e.keyboardGetUnicodeString(maxStringLength: 8, actualStringLength: &len, unicodeString: &buf)
            let u = buf[0..<len].map { String(format: "%04X", $0) }.joined(separator: " ")
            print("TAP type=\(type.rawValue) kc=\(e.getIntegerValueField(.keyboardEventKeycode)) uni=[\(u)] pid=\(e.getIntegerValueField(.eventSourceUnixProcessID)) ud=\(e.getIntegerValueField(.eventSourceUserData))")
        } else {
            print("TAP other type=\(type.rawValue)")
        }
        return Unmanaged.passUnretained(e)
    }
    guard let tap = CGEvent.tapCreateForPid(pid: pid, place: .headInsertEventTap, options: .listenOnly,
                                            eventsOfInterest: CGEventMask(mask), callback: cb, userInfo: nil) else {
        die("tapCreateForPid failed")
    }
    let rls = CFMachPortCreateRunLoopSource(nil, tap, 0)
    CFRunLoopAddSource(CFRunLoopGetCurrent(), rls, .commonModes)
    CGEvent.tapEnable(tap: tap, enable: true)
    print("tap ready for pid \(pid) for \(secs)s")
    CFRunLoopRunInMode(.defaultMode, secs, false)
    CGEvent.tapEnable(tap: tap, enable: false)
    print("tap done")

default:
    die("unknown command \(a[1])")
}
