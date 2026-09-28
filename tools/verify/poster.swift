// poster — docs/VERIFY.md V32 and V33: synthetic keys and clicks, sent every
// way the rows list, so the target can show it drops them.
//
// A verification tool, never linked into Brev.app. From the input spike's
// poster (tools/verify/spikes/input). Ways, with --via:
//   topid    CGEventPostToPid to the target only (the default)
//   ax       AXUIElementPostKeyboardEvent to the target's app element (keys)
//   session  CGEventPost at the session tap     \ these three reach whatever
//   hid      CGEventPost at the HID tap          } has focus, so they need
//   iohid    IOHIDPostEvent                     / --global, and each event is
//            sent only while the target is the frontmost app (and, for a
//            click, owns the top window at that point); otherwise skipped
//   all      every way above that the flags allow
// Each CGEvent way is sent three times: field 41 (eventSourceUnixProcessID)
// untouched, set to 0, and set to the target's PID. Field 42
// (eventSourceUserData) carries a tag, 0x4252 plus a running number.
//
// usage: poster key <pid> [--via <way>] [--keys <keycode>,...] [--global]
//          default keys 0,11 (a, b on the Norwegian layout: no Return, Space,
//          Tab or Escape, so nothing a posted key could press)
//        poster click <pid> <x> <y> [--via <way>] [--global]
//          a left click at global point (x, y), origin top left
// Exit 0 when every requested post was sent or skipped as above; 2 on bad
// arguments. It never asks for a permission; a missing one shows as an error
// code in the post's line.

import AppKit
import ApplicationServices

setvbuf(stdout, nil, _IOLBF, 0)
let a = Array(CommandLine.arguments.dropFirst())
func die(_ s: String) -> Never { print(s); exit(2) }
func value(_ flag: String) -> String? {
    a.firstIndex(of: flag).flatMap { a.indices.contains($0 + 1) ? a[$0 + 1] : nil }
}
guard a.count >= 2, ["key", "click"].contains(a[0]), let pid = pid_t(a[1]) else {
    die("usage: poster key <pid> [--via topid|ax|session|hid|iohid|all] [--keys kc,...] [--global]\n"
        + "       poster click <pid> <x> <y> [--via topid|session|hid|iohid|all] [--global]")
}
let global = a.contains("--global")
let via = value("--via") ?? "topid"
let known = ["topid", "ax", "session", "hid", "iohid"]
let ways = via == "all" ? known : [via]
guard ways.allSatisfy(known.contains) else { die("unknown way \(via)") }
if ways.contains(where: { ["session", "hid", "iohid"].contains($0) }) && !global {
    die("session, hid and iohid reach whatever has focus: add --global, and bring pid \(pid) to the front")
}

var tag: Int64 = 0x4252_0000
var sent = 0, skipped = 0

/// Whether `pid` is the frontmost app, and (for a point) owns the top window there.
func targetInFront(at point: CGPoint? = nil) -> Bool {
    guard NSWorkspace.shared.frontmostApplication?.processIdentifier == pid else { return false }
    guard let point else { return true }
    let info = CGWindowListCopyWindowInfo([.optionOnScreenOnly], kCGNullWindowID) as? [[String: Any]] ?? []
    for d in info where (d[kCGWindowLayer as String] as? Int ?? 0) < 1000 {
        let r = CGRect(dictionaryRepresentation: d[kCGWindowBounds as String] as! CFDictionary) ?? .zero
        if r.contains(point) { return (d[kCGWindowOwnerPID as String] as? pid_t) == pid }
    }
    return false
}

func stamp(_ e: CGEvent, _ field41: String) {
    switch field41 {
    case "zero": e.setIntegerValueField(.eventSourceUnixProcessID, value: 0)
    case "target": e.setIntegerValueField(.eventSourceUnixProcessID, value: Int64(pid))
    default: break
    }
    tag += 1
    e.setIntegerValueField(.eventSourceUserData, value: tag)
}

func post(_ e: CGEvent, way: String, field41: String, what: String, at point: CGPoint? = nil) {
    stamp(e, field41)
    switch way {
    case "topid":
        e.postToPid(pid)
    default:
        guard targetInFront(at: point) else {
            print("SKIP \(what) via=\(way) field41=\(field41): pid \(pid) is not in front\(point == nil ? "" : " at that point")")
            skipped += 1
            return
        }
        e.post(tap: way == "hid" ? .cghidEventTap : .cgSessionEventTap)
    }
    sent += 1
    print("POST \(what) via=\(way) field41=\(field41) tag=0x\(String(tag, radix: 16))")
    usleep(40_000)
}

let source = CGEventSource(stateID: .hidSystemState)
if a[0] == "key" {
    let keys = (value("--keys") ?? "0,11").split(separator: ",").compactMap { CGKeyCode($0) }
    for way in ways {
        switch way {
        case "ax":
            for kc in keys {
                let d = poster_ax_key(pid, kc, 1)
                usleep(25_000)
                let u = poster_ax_key(pid, kc, 0)
                sent += 2
                print("POST key \(kc) via=ax AXError down=\(d) up=\(u)")
            }
        case "iohid":
            for kc in keys {
                guard targetInFront() else { print("SKIP key \(kc) via=iohid: pid \(pid) is not in front"); skipped += 1; continue }
                let d = poster_iohid_key(kc, 1)
                usleep(25_000)
                let u = poster_iohid_key(kc, 0)
                sent += 2
                print("POST key \(kc) via=iohid kern_return down=0x\(String(UInt32(bitPattern: d), radix: 16)) up=0x\(String(UInt32(bitPattern: u), radix: 16))")
            }
        default:
            for field41 in ["untouched", "zero", "target"] {
                for kc in keys {
                    for down in [true, false] {
                        guard let e = CGEvent(keyboardEventSource: source, virtualKey: kc, keyDown: down) else { continue }
                        post(e, way: way, field41: field41, what: "key \(kc) \(down ? "down" : "up")")
                    }
                }
            }
        }
    }
} else {
    guard a.count >= 4, let x = Double(a[2]), let y = Double(a[3]) else { die("click <pid> <x> <y>") }
    let p = CGPoint(x: x, y: y)
    for way in ways where way != "ax" {
        if way == "iohid" {
            guard targetInFront(at: p) else { print("SKIP click via=iohid: pid \(pid) is not in front at that point"); skipped += 1; continue }
            let d = poster_iohid_click(Int32(x), Int32(y), 1)
            usleep(60_000)
            let u = poster_iohid_click(Int32(x), Int32(y), 0)
            sent += 2
            print("POST click via=iohid kern_return down=0x\(String(UInt32(bitPattern: d), radix: 16)) up=0x\(String(UInt32(bitPattern: u), radix: 16))")
            continue
        }
        for field41 in ["untouched", "zero", "target"] {
            for type in [CGEventType.leftMouseDown, .leftMouseUp] {
                guard let e = CGEvent(mouseEventSource: source, mouseType: type, mouseCursorPosition: p, mouseButton: .left) else { continue }
                e.setIntegerValueField(.mouseEventClickState, value: 1)
                post(e, way: way, field41: field41, what: "click \(type == .leftMouseDown ? "down" : "up") at \(Int(x)),\(Int(y))", at: p)
            }
        }
    }
}
print("posted \(sent) events to pid \(pid), skipped \(skipped); poster pid \(getpid())")
