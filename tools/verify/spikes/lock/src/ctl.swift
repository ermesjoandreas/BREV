// ctl — drives the LockLab spike apps. Unsandboxed CLI.
//   ctl notify <bundleid> <cmd>          distributed notification <bundleid>.cmd.<cmd> (deliverImmediately)
//   ctl probe <0|1>                      posts no.brev.spike.lock.probe with deliverImmediately false/true
//   ctl key <pid> <keycode> <cmd 0|1> <src combined|hid|private>
//                                        CGEvent.postToPid key down+up; REFUSES any pid that is not a LockLab spike app
//   ctl activate <bundleid>              NSRunningApplication.activate(options: []) (spike apps only)
//   ctl hide <bundleid>                  NSRunningApplication.hide() (spike apps only)
//   ctl idle                             CGEventSource idle seconds as seen by this (unsandboxed) process
import AppKit

let a = CommandLine.arguments
let allowed: Set<String> = ["no.brev.spike.lock", "no.brev.spike.lockother"]
func spikeApp(pid: pid_t) -> NSRunningApplication? {
    guard let r = NSRunningApplication(processIdentifier: pid), let b = r.bundleIdentifier, allowed.contains(b) else { return nil }
    return r
}
func spikeApp(bundle: String) -> NSRunningApplication? {
    guard allowed.contains(bundle) else { return nil }
    return NSRunningApplication.runningApplications(withBundleIdentifier: bundle).first
}
func die(_ s: String) -> Never { print(s); exit(2) }

guard a.count >= 2 else { die("usage: see source") }
switch a[1] {
case "notify":
    guard a.count == 4, allowed.contains(a[2]) else { die("notify: bad args") }
    DistributedNotificationCenter.default().postNotificationName(Notification.Name(a[2] + ".cmd." + a[3]), object: nil,
                                                                 userInfo: nil, deliverImmediately: true)
    print("posted \(a[2]).cmd.\(a[3])")
case "probe":
    let imm = a.count > 2 && a[2] == "1"
    DistributedNotificationCenter.default().postNotificationName(Notification.Name("no.brev.spike.lock.probe"), object: nil,
                                                                 userInfo: nil, deliverImmediately: imm)
    print("posted no.brev.spike.lock.probe deliverImmediately=\(imm)")
case "key":
    guard a.count == 6, let pid = pid_t(a[2]), let kc = CGKeyCode(a[3]) else { die("key: bad args") }
    guard spikeApp(pid: pid) != nil else { die("refused: pid \(a[2]) is not a LockLab spike app") }
    let sid: CGEventSourceStateID = a[5] == "hid" ? .hidSystemState : (a[5] == "private" ? .privateState : .combinedSessionState)
    let src = CGEventSource(stateID: sid)
    guard let down = CGEvent(keyboardEventSource: src, virtualKey: kc, keyDown: true),
          let up = CGEvent(keyboardEventSource: src, virtualKey: kc, keyDown: false) else { die("CGEvent failed") }
    if a[4] == "1" { down.flags = .maskCommand; up.flags = .maskCommand }
    down.postToPid(pid); usleep(40_000); up.postToPid(pid)
    print("posted key \(kc) cmd=\(a[4]) src=\(a[5]) to pid \(pid)")
case "click":   // ctl click <pid> <x> <y> <win> — left mouse down+up at CG global (x, y), postToPid to a spike app only
    guard a.count == 6, let pid = pid_t(a[2]), let x = Double(a[3]), let y = Double(a[4]), let wn = Int64(a[5]) else { die("click: bad args") }
    guard spikeApp(pid: pid) != nil else { die("refused: pid \(a[2]) is not a LockLab spike app") }
    let src = CGEventSource(stateID: .combinedSessionState)
    let p = CGPoint(x: x, y: y)
    guard let d = CGEvent(mouseEventSource: src, mouseType: .leftMouseDown, mouseCursorPosition: p, mouseButton: .left),
          let u = CGEvent(mouseEventSource: src, mouseType: .leftMouseUp, mouseCursorPosition: p, mouseButton: .left) else { die("CGEvent failed") }
    for e in [d, u] {
        e.setIntegerValueField(.mouseEventClickState, value: 1)
        e.setIntegerValueField(.mouseEventWindowUnderMousePointer, value: wn)
        e.setIntegerValueField(.mouseEventWindowUnderMousePointerThatCanHandleThisEvent, value: wn)
    }
    d.postToPid(pid); usleep(60_000); u.postToPid(pid)
    print("posted click at \(x),\(y) to pid \(pid)")
case "appleprobe":
    DistributedNotificationCenter.default().postNotificationName(Notification.Name("com.apple.brevspike.lockprobe"), object: nil,
                                                                 userInfo: nil, deliverImmediately: true)
    print("posted com.apple.brevspike.lockprobe")
case "activate":
    guard a.count == 3, let r = spikeApp(bundle: a[2]) else { die("activate: not a running spike app") }
    let ok = r.activate(options: [])
    print("NSRunningApplication.activate returned \(ok)")
case "hide":
    guard a.count == 3, let r = spikeApp(bundle: a[2]) else { die("hide: not a running spike app") }
    print("NSRunningApplication.hide returned \(r.hide())")
case "idle":
    let any = CGEventType(rawValue: ~0)!
    print(String(format: "unsandboxed idleC=%.2f idleH=%.2f",
                 CGEventSource.secondsSinceLastEventType(.combinedSessionState, eventType: any),
                 CGEventSource.secondsSinceLastEventType(.hidSystemState, eventType: any)))
default:
    die("unknown command")
}
