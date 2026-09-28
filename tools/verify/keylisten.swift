// keylisten — docs/VERIFY.md V31: a keylogger stand-in. A listen-only
// session event tap plus IOHIDManager on keyboards, run while a human types
// in Brev's compose view with secure event input on, and, as the control,
// in TextEdit.
//
// A verification tool, never linked into Brev.app; the input spike's
// keylisten unchanged below this header (tools/verify/spikes/input). It
// NEVER records which key was pressed: each line holds only a time
// (CLOCK_UPTIME_RAW ns) and whether a key value was visible ("keyDown
// uniLen=<n>" from the tap: n > 0 means the tap saw the character; "keyPress"
// from IOHIDManager: it saw a key). Never requests a permission: without
// Input Monitoring for its responsible app it stops.
//   keylisten <seconds>      listen, print "KL tap|hid abs=<ns> ..." lines
//   keylisten --check        open both listeners and close them at once (no event is processed)
// V31 passes when no "KL" line appears while the marker is typed in Brev,
// and "KL tap … uniLen=1" lines appear while typing in TextEdit. If
// "KL hid" lines appear while typing in Brev, stop and ask the owner.
import CoreGraphics
import Foundation
import IOKit.hid

setvbuf(stdout, nil, _IOLBF, 0)
func absNs() -> UInt64 { clock_gettime_nsec_np(CLOCK_UPTIME_RAW) }
let args = CommandLine.arguments
let check = args.contains("--check")
let secs = Double(args.dropFirst().first(where: { !$0.hasPrefix("--") }) ?? "") ?? 0

let hidAccess = IOHIDCheckAccess(kIOHIDRequestTypeListenEvent)
print("preflight CGPreflightListenEventAccess=\(CGPreflightListenEventAccess()) IOHIDCheckAccess=\(hidAccess.rawValue) (0=granted)")
guard CGPreflightListenEventAccess(), hidAccess == kIOHIDAccessTypeGranted else { print("no listen access: skipped (nothing requested)"); exit(0) }

// Session-level listen-only tap (what an ordinary keylogger uses).
let mask = (1 << CGEventType.keyDown.rawValue) | (1 << CGEventType.keyUp.rawValue)
let cb: CGEventTapCallBack = { _, type, e, _ in
    if type == .keyDown {
        var len = 0
        var buf = [UniChar](repeating: 0, count: 4)
        e.keyboardGetUnicodeString(maxStringLength: 4, actualStringLength: &len, unicodeString: &buf)
        for i in 0..<buf.count { buf[i] = 0 }
        print("KL tap abs=\(absNs()) keyDown uniLen=\(len)")
    } else if type == .tapDisabledByTimeout || type == .tapDisabledByUserInput {
        print("KL tap abs=\(absNs()) disabled type=\(type.rawValue)")
    }
    return Unmanaged.passUnretained(e)
}
let tap = CGEvent.tapCreate(tap: .cgSessionEventTap, place: .headInsertEventTap, options: .listenOnly,
                            eventsOfInterest: CGEventMask(mask), callback: cb, userInfo: nil)
print("session tap created=\(tap != nil)")

// IOHIDManager on keyboards: raw HID key presses (usage page 7).
let mgr = IOHIDManagerCreate(kCFAllocatorDefault, IOOptionBits(kIOHIDOptionsTypeNone))
IOHIDManagerSetDeviceMatching(mgr, [kIOHIDDeviceUsagePageKey: kHIDPage_GenericDesktop,
                                    kIOHIDDeviceUsageKey: kHIDUsage_GD_Keyboard] as CFDictionary)
IOHIDManagerRegisterInputValueCallback(mgr, { _, _, _, value in
    let el = IOHIDValueGetElement(value)
    let page = IOHIDElementGetUsagePage(el), usage = IOHIDElementGetUsage(el)
    if page == UInt32(kHIDPage_KeyboardOrKeypad) && usage >= 4 && usage <= 231 && IOHIDValueGetIntegerValue(value) == 1 {
        print("KL hid abs=\(absNs()) keyPress")
    }
}, nil)
IOHIDManagerScheduleWithRunLoop(mgr, CFRunLoopGetCurrent(), CFRunLoopMode.defaultMode.rawValue)
let openResult = IOHIDManagerOpen(mgr, IOOptionBits(kIOHIDOptionsTypeNone))
print("IOHIDManagerOpen=0x\(String(UInt32(bitPattern: openResult), radix: 16)) (0=ok)")

if check || secs <= 0 {
    IOHIDManagerClose(mgr, IOOptionBits(kIOHIDOptionsTypeNone))
    print("check only: listeners opened and closed, no events processed")
    exit(0)
}
if let tap {
    CFRunLoopAddSource(CFRunLoopGetCurrent(), CFMachPortCreateRunLoopSource(nil, tap, 0), .commonModes)
    CGEvent.tapEnable(tap: tap, enable: true)
}
print("listening abs=\(absNs()) for \(secs)s")
CFRunLoopRunInMode(.defaultMode, secs, false)
IOHIDManagerClose(mgr, IOOptionBits(kIOHIDOptionsTypeNone))
print("done abs=\(absNs())")
