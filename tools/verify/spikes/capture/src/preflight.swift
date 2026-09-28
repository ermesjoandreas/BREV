import AppKit
import CoreGraphics
print("CGPreflightScreenCaptureAccess:", CGPreflightScreenCaptureAccess())
for s in NSScreen.screens {
    let id = s.deviceDescription[NSDeviceDescriptionKey("NSScreenNumber")] as? NSNumber
    print("NSScreen id=\(id ?? 0) frame=\(s.frame) visible=\(s.visibleFrame) scale=\(s.backingScaleFactor)")
}
var ids = [CGDirectDisplayID](repeating: 0, count: 8); var n: UInt32 = 0
CGGetActiveDisplayList(8, &ids, &n)
for i in 0..<Int(n) { print("CGDisplay \(ids[i]) bounds=\(CGDisplayBounds(ids[i])) main=\(CGDisplayIsMain(ids[i]) != 0) px=\(CGDisplayPixelsWide(ids[i]))x\(CGDisplayPixelsHigh(ids[i])) asleep=\(CGDisplayIsAsleep(ids[i]) != 0)") }
if let d = CGSessionCopyCurrentDictionary() as? [String: Any] {
    for k in ["kCGSSessionOnConsoleKey", "CGSSessionScreenIsLocked"] { print(k, d[k] ?? "absent") }
}
print("frontmost app:", NSWorkspace.shared.frontmostApplication?.bundleIdentifier ?? "nil")
let info = CGWindowListCopyWindowInfo([.optionOnScreenOnly], kCGNullWindowID) as? [[String: Any]] ?? []
var owners: [String: Int] = [:]
for w in info { owners[w[kCGWindowOwnerName as String] as? String ?? "?", default: 0] += 1 }
print("on-screen windows:", info.count, owners.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: " "))
