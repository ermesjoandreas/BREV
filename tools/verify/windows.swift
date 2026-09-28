// windows — docs/VERIFY.md V5 and V9: every window of an app, with its id,
// level and kCGWindowSharingState (0 = none: other processes may not read
// it; 1 = read-only, capturable).
//
// A verification tool, never linked into Brev.app. Reads the window server's
// list only; it asks for no permission.
//
// usage: windows [<app name> | --pid <n>]   (default Brev)
//   One line per window of that app, on screen or not, then a summary. Exit
//   0 when the app has at least one window and every one has sharing state
//   0; 1 when one does not; 3 when no such app or window exists. Titles are
//   printed for that app's windows only. A window of the menu bar's size
//   that is off screen is marked "(menu-bar sized, off screen)"; it still
//   counts.

import AppKit

setvbuf(stdout, nil, _IOLBF, 0)
let args = Array(CommandLine.arguments.dropFirst())
let pids: [pid_t]
let name: String
if let i = args.firstIndex(of: "--pid"), args.indices.contains(i + 1), let p = pid_t(args[i + 1]) {
    pids = [p]
    name = "pid \(p)"
} else {
    name = args.first ?? "Brev"
    pids = NSWorkspace.shared.runningApplications.filter { $0.localizedName == name }.map(\.processIdentifier)
}
guard !pids.isEmpty else {
    print("no running app named \(name)")
    exit(3)
}

// The menu bar's rect on the main display (global points, origin top left).
// On macOS 26.2 every regular app owns four off-screen windows of exactly
// this size with sharing state 1 (the system's menu bar windows for that
// app); they are marked, not excused.
let menuBar: CGRect = {
    guard let s = NSScreen.screens.first else { return .null }
    return CGRect(x: 0, y: 0, width: s.frame.width, height: s.frame.maxY - s.visibleFrame.maxY)
}()
let info = CGWindowListCopyWindowInfo([.optionAll], kCGNullWindowID) as? [[String: Any]] ?? []
var count = 0, shared = 0
for d in info {
    guard let owner = d[kCGWindowOwnerPID as String] as? pid_t, pids.contains(owner) else { continue }
    let r = CGRect(dictionaryRepresentation: d[kCGWindowBounds as String] as! CFDictionary) ?? .zero
    let sharing = d[kCGWindowSharingState as String] as? Int ?? -1
    count += 1
    if sharing != 0 { shared += 1 }
    print("id=\(d[kCGWindowNumber as String] ?? 0) pid=\(owner) owner=\(d[kCGWindowOwnerName as String] ?? "?")"
        + " layer=\(d[kCGWindowLayer as String] ?? "?") kCGWindowSharingState=\(sharing)"
        + " onscreen=\(d[kCGWindowIsOnscreen as String] as? Bool ?? false)"
        + " bounds=\(Int(r.minX)),\(Int(r.minY)),\(Int(r.width)),\(Int(r.height))"
        + " title=\"\(d[kCGWindowName as String] as? String ?? "")\""
        + (r == menuBar && !(d[kCGWindowIsOnscreen as String] as? Bool ?? false) ? " (menu-bar sized, off screen)" : ""))
}
print("\(name): windows=\(count) sharingState!=0: \(shared)")
exit(count == 0 ? 3 : shared == 0 ? 0 : 1)
