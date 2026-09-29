// main.swift — Snapshot: Brev's screens drawn offscreen to PNG files.
//
// docs/UI_REDESIGN.md §5. A test app only (tools/snapshot/build.sh), never
// linked into Brev.app. It never shows a window: the activation policy is
// .prohibited, no window is ever ordered in, and observers abort the run at
// once if a window becomes key, main or visible, or the app active.
// Scenes: prototype of the offscreen capture (baseline).

import AppKit
import Carbon.HIToolbox

setvbuf(stdout, nil, _IOLBF, 0)

// MARK: - Offscreen, always (§5.2)

let application = BrevApplication.shared
_ = application.setActivationPolicy(.prohibited)
Hardening.applyToApp()
let secureInputAtStart = IsSecureEventInputEnabled()

var failures = 0
func check(_ what: String, _ ok: Bool, _ detail: @autoclosure () -> String = "") {
    let d = ok ? "" : detail()
    let line = (ok ? "ok   " : "FAIL ") + what + (d.isEmpty ? "" : "  [\(d)]")
    print(line)
    report.append(line)
    if !ok { failures += 1 }
}
var report: [String] = []

/// A window became key, main or visible, or the app active: stop at once,
/// before anything else can happen on screen.
func abortShown(_ what: String) -> Never {
    print("FAIL offscreen: \(what); stopping at once")
    exit(1)
}
let center = NotificationCenter.default
for name in [NSWindow.didBecomeKeyNotification, NSWindow.didBecomeMainNotification] {
    center.addObserver(forName: name, object: nil, queue: nil) { _ in abortShown("a window became key or main") }
}
center.addObserver(forName: NSWindow.didChangeOcclusionStateNotification, object: nil, queue: nil) { n in
    if let w = n.object as? NSWindow, w.occlusionState.contains(.visible) { abortShown("a window became visible") }
}
center.addObserver(forName: NSApplication.didBecomeActiveNotification, object: nil, queue: nil) { _ in
    abortShown("the app became active")
}

/// The guard of §5.2, after every scene.
func guardOffscreen(_ scene: String) {
    let pid = Int(getpid())
    let info = (CGWindowListCopyWindowInfo(.optionOnScreenOnly, kCGNullWindowID) as? [[String: Any]]) ?? []
    let onScreen = info.contains { ($0[kCGWindowOwnerPID as String] as? Int) == pid }
    let ok = NSApp.windows.allSatisfy { !$0.isVisible } && !NSApp.isActive && !onScreen
    if !ok { abortShown("\(scene): a window is visible or on screen, or the app is active") }
}

// MARK: - Arguments

let args = Array(CommandLine.arguments.dropFirst())
func value(_ flag: String) -> String? {
    args.firstIndex(of: flag).flatMap { args.indices.contains($0 + 1) ? args[$0 + 1] : nil }
}
let checkOnly = args.contains("--check")
let outDir = value("--out").map { URL(fileURLWithPath: $0, isDirectory: true) }
let onlyScene = value("--scene")
let appearanceArg = value("--appearance") ?? "both"
guard ["light", "dark", "both"].contains(appearanceArg), checkOnly || outDir != nil else {
    print("usage: Snapshot (--out <dir> | --check) [--scene <name>] [--appearance light|dark|both]")
    exit(2)
}
let appearances: [(String, NSAppearance.Name)] = [("light", .aqua), ("dark", .darkAqua)]
    .filter { appearanceArg == "both" || appearanceArg == $0.0 }
if let outDir {
    try? FileManager.default.createDirectory(at: outDir, withIntermediateDirectories: true)
}

// MARK: - Data folder and relay

let dir = FileManager.default.temporaryDirectory.appendingPathComponent("brev-snapshot-\(getpid())")
if dir.standardizedFileURL.path.contains("/Library/Containers/no.brev.app") {
    print("FAIL the data folder would be Brev's container")
    exit(2)
}
try? FileManager.default.removeItem(at: dir)
try! FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                         attributes: [.posixPermissions: 0o700])
var relayProcess: Process?
func finish() -> Never {
    relayProcess?.terminate()
    relayProcess?.waitUntilExit()
    try? FileManager.default.removeItem(at: dir)
    NSApp.windows.forEach { $0.close() }
    guardOffscreen("exit")
    if let outDir {
        try? (report.joined(separator: "\n") + "\n").write(to: outDir.appendingPathComponent("report.txt"),
                                                          atomically: true, encoding: .utf8)
    }
    print(failures == 0 ? "PASS" : "FAIL: \(failures) check(s)")
    exit(failures == 0 ? 0 : 1)
}
guard let relayRun = startRelay(in: dir) else {
    check("the relay starts on 127.0.0.1 (build.sh builds it)", false)
    finish()
}
relayProcess = relayRun.0
let relayURL = relayRun.1

/// Runs the main run loop until `done` or `seconds` pass.
func spin(until done: () -> Bool, _ seconds: TimeInterval = 10) -> Bool {
    let end = Date(timeIntervalSinceNow: seconds)
    while !done() && Date() < end {
        _ = RunLoop.main.run(mode: .default, before: Date(timeIntervalSinceNow: 0.02))
    }
    return done()
}

// MARK: - Capture

func all<T: NSView>(_ type: T.Type, in view: NSView) -> [T] {
    var out: [T] = []
    if let v = view as? T { out.append(v) }
    for s in view.subviews { out += all(type, in: s) }
    return out
}

/// `view` (and what it contains) drawn by cacheDisplay at 2×.
func capture(_ view: NSView) -> NSBitmapImageRep? {
    let size = view.bounds.size
    guard size.width >= 1, size.height >= 1,
          let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(size.width * 2),
                                     pixelsHigh: Int(size.height * 2), bitsPerSample: 8, samplesPerPixel: 4,
                                     hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
                                     bytesPerRow: 0, bitsPerPixel: 0)
    else { return nil }
    rep.size = size
    view.cacheDisplay(in: view.bounds, to: rep)
    return rep
}

func write(_ image: CGImage, _ name: String) {
    guard let outDir else { return }
    let rep = NSBitmapImageRep(cgImage: image)
    do {
        try rep.representation(using: .png, properties: [:])?.write(to: outDir.appendingPathComponent(name))
    } catch {
        check("\(name) written", false, "\(error)")
    }
}

/// The chrome PNG with every visible ContentView outlined and hatched, and
/// the preview PNG with the fake content drawn in by each view's own
/// drawContent (docs/UI_REDESIGN.md §5.5).
func render(_ root: NSView, _ name: String) {
    guard let rep = capture(root), let chrome = rep.cgImage else {
        return check("\(name): captured", false)
    }
    let w = chrome.width, h = chrome.height, s = CGFloat(w) / root.bounds.width
    let views = all(ContentView.self, in: root).filter { !$0.isHiddenOrHasHiddenAncestor }
    func context() -> CGContext {
        let ctx = CGContext(data: nil, width: w, height: h, bitsPerComponent: 8, bytesPerRow: 0,
                            space: CGColorSpace(name: CGColorSpace.sRGB)!,
                            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
        ctx.draw(chrome, in: CGRect(x: 0, y: 0, width: w, height: h))
        return ctx
    }
    /// A view's visible rect, and where it lies in `root` (unflipped points).
    func place(_ v: ContentView) -> (CGRect, CGRect)? {
        let visible = v.visibleRect.intersection(v.bounds)
        guard visible.width >= 1, visible.height >= 1 else { return nil }
        var r = v.convert(visible, to: root)
        if root.isFlipped { r.origin.y = root.bounds.height - r.maxY }
        return (visible, r)
    }
    let outline = context()
    for v in views {
        guard let (_, r) = place(v) else { continue }
        let px = CGRect(x: r.minX * s, y: r.minY * s, width: r.width * s, height: r.height * s)
        outline.saveGState()
        outline.clip(to: px)
        outline.setStrokeColor(NSColor.systemPink.withAlphaComponent(0.18).cgColor)
        outline.setLineWidth(s)
        var x = px.minX - px.height
        while x < px.maxX {
            outline.move(to: CGPoint(x: x, y: px.minY))
            outline.addLine(to: CGPoint(x: x + px.height, y: px.maxY))
            x += 10 * s
        }
        outline.strokePath()
        outline.restoreGState()
        outline.setStrokeColor(NSColor.systemPink.cgColor)
        outline.setLineWidth(s)
        outline.setLineDash(phase: 0, lengths: [3 * s, 2 * s])
        outline.stroke(px.insetBy(dx: s / 2, dy: s / 2))
    }
    if let image = outline.makeImage() { write(image, "\(name).png") }
    let preview = context()
    for v in views {
        guard let (visible, r) = place(v) else { continue }
        preview.saveGState()
        preview.translateBy(x: r.minX * s, y: r.maxY * s)
        preview.scaleBy(x: s, y: -s)
        preview.translateBy(x: -visible.minX, y: -visible.minY)
        preview.clip(to: visible)
        v.drawContent(in: preview, rect: visible)
        preview.restoreGState()
    }
    if let image = preview.makeImage() { write(image, "\(name)-preview.png") }
}

// MARK: - Prototype

let window = MainWindow(contentSize: NSSize(width: 1080, height: 680))
let lock = LockController()
lock.window = window
func scene(_ name: String, _ build: () -> NSView) {
    guard onlyScene == nil || onlyScene == name else { return }
    for (label, appearance) in appearances {
        window.appearance = NSAppearance(named: appearance)
        let root = build()
        root.layoutSubtreeIfNeeded()
        root.displayIfNeeded()
        if !checkOnly { render(root, "\(name)-\(label)") }
        guardOffscreen(name)
    }
    print("scene \(name)")
}

scene("lock") {
    window.root.show(UnlockViewController(mode: .lockScreen))
    return window.contentView!.superview!
}
finish()
