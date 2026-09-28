// capture-probe — docs/VERIFY.md V5, V6 and V7: captures the screen through
// the ways another app can, and says for each whether Brev's content shows.
//
// A verification tool, never linked into Brev.app (tools/verify/build.sh
// builds it for macOS 14.0, so the CoreGraphics captures that the 15.0 SDK
// obsoletes still compile). Built from the capture spike's probe and WP11's
// vprobe (tools/verify/spikes/capture).
//
// It sets a stage around the target app's largest window: a green backdrop
// right behind that window and a cyan control window with plain AppKit text
// beside it, both capturable. Every capture is cut down to that area; only
// the cut is saved (<out>/<path>.png). Whole screens (screencapture's files)
// exist only in a private temporary folder while they are cut, which is
// removed on every exit, the watchdog's too. Per path it prints the control
// (it must be visible, with its text), each target window (excluded = the
// backdrop shows through), and the ink in each content pane: the pixels that
// differ from the pane's most common colour, which is where letter text
// would be. A pane shows content when its ink covers at least
// Ink.minArea square points, whatever the pane's size: one short word at
// Brev's 13 pt has several times that. Panes are the target's AX scroll
// areas (no prompt; if Terminal is not trusted for Accessibility, give them
// with --pane); those are read again after the last capture, and a change
// (Brev locked, say) makes the run INVALID. A window-level capture (window
// filter, -l, one window's CGWindowListCreateImage) is also taken of the
// control window: an empty result for the target counts only if the same
// method shows the control. Where the control has to lie over the window's
// right edge (no room beside it), panes are judged left of it. Some paths
// draw the pointer, so a pointer over a pane is noted.
//
// usage: capture-probe [--legacy | --screencapture] [--app <name> | --pid <n>]
//                      [--out <dir>] [--pane <name>=<x,y,w,h>]... [--hold <s>]
//        capture-probe --selftest
//   (default)        ScreenCaptureKit (V6): display filter, window filter with
//                    includeChildWindows, captureImage(in:) (15.2),
//                    captureScreenshot(contentFilter:) and (rect:) (26), and one
//                    SCStream frame each with a display and a window filter
//   --legacy         V7: CGWindowListCreateImage (screen and per window),
//                    CGDisplayCreateImage (display and rect), CGDisplayStream,
//                    AVCaptureScreenInput, and CGDisplayStream through dlsym
//                    from capture-probe-26 (built for macOS 26.0)
//   --screencapture  V5: screencapture -x, -R, -l<id> per window, -V 3
//   --app <name>     the target's name (default Brev); --pid picks one process
//   --out <dir>      where the cuts go (made 0700 if new; default a new 0700
//                    folder under $TMPDIR, never the current directory)
//   --pane n=r       a pane rect in global points, origin top left (repeatable)
//   --hold <s>       seconds to wait after the stage is up (default 1)
//   --selftest       checks the verdict rules on drawn panes: no window, no
//                    capture, no permission (scripts/test.sh runs it)
// Rects are global points with the origin at the top left of the main display.
//
// Exit: 0 every path passed (the window excluded, or captured with no ink in
// any pane); 1 a pane showed ink (content may be visible: look at the cut);
// 2 INVALID, a path proved nothing: a control failed, the window was captured
// but no pane is known (Brev not on its mail window, or no AX trust and no
// --pane), the panes changed during the run, or the display is not listed;
// 3 not runnable (no Screen Recording access, no target). It never asks for a
// permission.

import AppKit
import AVFoundation
import CoreImage
import CoreMedia
import ScreenCaptureKit
import UniformTypeIdentifiers

setvbuf(stdout, nil, _IOLBF, 0)
DispatchQueue.global().asyncAfter(deadline: .now() + 180) { print("WATCHDOG: 180 s, exiting"); exit(3) }

/// A new folder under $TMPDIR that only this user can open (mkdtemp: 0700).
func privateTempDir(_ prefix: String) -> URL? {
    var template = Array((NSTemporaryDirectory() + prefix + "-XXXXXX").utf8CString)
    return template.withUnsafeMutableBufferPointer { b in
        mkdtemp(b.baseAddress!).map { URL(fileURLWithPath: String(cString: $0), isDirectory: true) }
    }
}

/// Where the cuts go: `given`, or a new private folder. Never a default in
/// the current directory, which may be a checkout that a later commit sweeps
/// up with the cuts in it.
func cutsFolder(_ given: String?) -> URL? {
    guard let given else { return privateTempDir("capture-probe") }
    let url = URL(fileURLWithPath: given, isDirectory: true)
    try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    return url
}

/// Whole screens and the dlsym tool's file, only while they are cut. Removed
/// on every exit through exit(), the watchdog's included.
let scratch = privateTempDir("capture-probe-tmp")
atexit { if let scratch { try? FileManager.default.removeItem(at: scratch) } }

let args = Array(CommandLine.arguments.dropFirst())
func value(_ flag: String) -> String? {
    args.firstIndex(of: flag).flatMap { args.indices.contains($0 + 1) ? args[$0 + 1] : nil }
}
func values(_ flag: String) -> [String] {
    args.indices.filter { args[$0] == flag && args.indices.contains($0 + 1) }.map { args[$0 + 1] }
}
func rect(_ s: String) -> CGRect? {
    let n = s.split(separator: ",").compactMap { Double($0) }
    return n.count == 4 ? CGRect(x: n[0], y: n[1], width: n[2], height: n[3]) : nil
}
func text(_ r: CGRect) -> String { "\(Int(r.minX)),\(Int(r.minY)),\(Int(r.width)),\(Int(r.height))" }

if args.contains("--selftest") { exit(selftest() ? 0 : 1) }

let mode = args.contains("--legacy") ? "legacy" : args.contains("--screencapture") ? "screencapture" : "sck"
let appName = value("--app") ?? "Brev"
let hold = value("--hold").flatMap(Double.init) ?? 1

_ = CGMainDisplayID()   // connect to the window server before any ScreenCaptureKit call
guard CGPreflightScreenCaptureAccess() else {
    print("no Screen Recording access for this process (its responsible app): not runnable, nothing requested")
    exit(3)
}
guard let outDir = cutsFolder(value("--out")), let tmpDir = scratch else {
    print("cannot make a folder for the cuts: not runnable")
    exit(3)
}

// MARK: - The target

let pid: pid_t
if let p = value("--pid").flatMap({ pid_t($0) }) {
    pid = p
} else {
    let running = NSWorkspace.shared.runningApplications.filter { $0.localizedName == appName }
    guard running.count == 1, let only = running.first else {
        print("\(running.count) running apps named \(appName)\(running.isEmpty ? "" : " (pids \(running.map { $0.processIdentifier })); use --pid"): not runnable")
        exit(3)
    }
    pid = only.processIdentifier
}

struct Win { let id: CGWindowID; let bounds: CGRect; let layer: Int; let sharing: Int; let onscreen: Bool }

func windows(of owner: pid_t) -> [Win] {
    let info = CGWindowListCopyWindowInfo([.optionAll], kCGNullWindowID) as? [[String: Any]] ?? []
    return info.filter { ($0[kCGWindowOwnerPID as String] as? Int32) == owner }.map { d in
        Win(id: d[kCGWindowNumber as String] as? CGWindowID ?? 0,
            bounds: CGRect(dictionaryRepresentation: d[kCGWindowBounds as String] as! CFDictionary) ?? .zero,
            layer: d[kCGWindowLayer as String] as? Int ?? -1,
            sharing: d[kCGWindowSharingState as String] as? Int ?? -1,
            onscreen: d[kCGWindowIsOnscreen as String] as? Bool ?? false)
    }
}

let targetWindows = windows(of: pid).filter { $0.onscreen && $0.layer == 0 && $0.bounds.width > 40 && $0.bounds.height > 40 }
print("== capture-probe \(mode) (macOS \(ProcessInfo.processInfo.operatingSystemVersionString)) target \(appName) pid \(pid)")
for w in windows(of: pid) {
    print("   window \(w.id) layer=\(w.layer) sharingState=\(w.sharing) onscreen=\(w.onscreen) bounds=\(text(w.bounds))")
}
guard let main = targetWindows.max(by: { $0.bounds.width * $0.bounds.height < $1.bounds.width * $1.bounds.height }) else {
    print("no on-screen window of pid \(pid) at the normal level: not runnable")
    exit(3)
}

// MARK: - Panes: --pane, else the target's AX scroll areas

func axAttr(_ e: AXUIElement, _ n: String) -> CFTypeRef? {
    var v: CFTypeRef?
    return AXUIElementCopyAttributeValue(e, n as CFString, &v) == .success ? v : nil
}
func axFrame(_ e: AXUIElement) -> CGRect? {
    guard let p = axAttr(e, kAXPositionAttribute), let s = axAttr(e, kAXSizeAttribute) else { return nil }
    var pt = CGPoint.zero, sz = CGSize.zero
    AXValueGetValue(p as! AXValue, .cgPoint, &pt)
    AXValueGetValue(s as! AXValue, .cgSize, &sz)
    return CGRect(origin: pt, size: sz)
}
func scrollAreas(_ e: AXUIElement, _ depth: Int, _ out: inout [CGRect]) {
    if depth > 12 { return }
    if (axAttr(e, kAXRoleAttribute) as? String) == kAXScrollAreaRole, let f = axFrame(e), f.width > 20, f.height > 20 { out.append(f) }
    for k in (axAttr(e, kAXChildrenAttribute) as? [AXUIElement]) ?? [] { scrollAreas(k, depth + 1, &out) }
}

/// The target's AX scroll areas now; nil if this process is not trusted for
/// Accessibility (asking would prompt, so it never asks).
func axPanes() -> [(String, CGRect)]? {
    guard AXIsProcessTrustedWithOptions([kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String: false] as CFDictionary) else { return nil }
    let app = AXUIElementCreateApplication(pid)
    AXUIElementSetMessagingTimeout(app, 2)
    var found: [CGRect] = []
    for w in (axAttr(app, kAXWindowsAttribute) as? [AXUIElement]) ?? [] { scrollAreas(w, 0, &found) }
    return found.enumerated().map { ("pane\($0.offset + 1)", $0.element) }
}

var panes: [(String, CGRect)] = values("--pane").compactMap { kv in
    let p = kv.split(separator: "=", maxSplits: 1)
    guard p.count == 2, let r = rect(String(p[1])) else { return nil }
    return (String(p[0]), r)
}
let panesFromAX = panes.isEmpty
if panesFromAX {
    if let found = axPanes() {
        panes = found
        print("   panes from AX: \(panes.isEmpty ? "none" : panes.map { "\($0.0)=\(text($0.1))" }.joined(separator: " "))")
    } else {
        print("   not trusted for Accessibility: no panes found (none requested); give them with --pane")
    }
}
if panes.isEmpty { print("   no content pane is known: a path that captures the window proves nothing (INVALID)") }

// MARK: - The stage: a backdrop behind the target, a control beside it

let display: CGDirectDisplayID = {
    var ids = [CGDirectDisplayID](repeating: 0, count: 8)
    var n: UInt32 = 0
    CGGetDisplaysWithPoint(CGPoint(x: main.bounds.midX, y: main.bounds.midY), 8, &ids, &n)
    return n > 0 ? ids[0] : CGMainDisplayID()
}()
let displayBounds = CGDisplayBounds(display)
let backdropRect = main.bounds.insetBy(dx: -24, dy: -24).intersection(displayBounds)
let controlWidth: CGFloat = 260
let controlRect: CGRect = {
    let x: CGFloat
    if backdropRect.maxX + controlWidth <= displayBounds.maxX { x = backdropRect.maxX }
    else if backdropRect.minX - controlWidth >= displayBounds.minX { x = backdropRect.minX - controlWidth }
    else { x = backdropRect.maxX - controlWidth }   // no room: over the backdrop's right edge
    return CGRect(x: x, y: backdropRect.minY, width: controlWidth, height: backdropRect.height)
}()
// Every cut covers exactly this: the backdrop and the control, side by side
// and of the same height, so a cut holds no other app's window (only what the
// system puts above every app, such as its own dialogs).
let area = backdropRect.union(controlRect)
print("   stage: backdrop=\(text(backdropRect)) control=\(text(controlRect)) area=\(text(area)) display=\(display)")

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let mainScreenTop = NSScreen.screens.first?.frame.maxY ?? displayBounds.height
func cocoa(_ r: CGRect) -> NSRect { NSRect(x: r.minX, y: mainScreenTop - r.maxY, width: r.width, height: r.height) }
func stageWindow(_ r: CGRect, _ color: NSColor) -> NSWindow {
    let w = NSWindow(contentRect: cocoa(r), styleMask: [.borderless], backing: .buffered, defer: false)
    w.isReleasedWhenClosed = false
    w.backgroundColor = color
    w.hasShadow = false
    w.ignoresMouseEvents = true
    return w
}
let backdrop = stageWindow(backdropRect, NSColor(srgbRed: 0, green: 0.63, blue: 0, alpha: 1))
let control = stageWindow(controlRect, NSColor(srgbRed: 0, green: 1, blue: 1, alpha: 1))
control.level = .floating
let label = NSTextField(labelWithString: "CONTROL 7f3a\ncapture-probe")
label.font = NSFont.systemFont(ofSize: 24, weight: .bold)
label.textColor = .black
label.frame = NSRect(x: 16, y: controlRect.height / 2 - 40, width: controlWidth - 32, height: 80)
control.contentView?.addSubview(label)
control.orderFrontRegardless()
backdrop.orderFrontRegardless()
backdrop.order(.below, relativeTo: Int(main.id))
for w in [backdrop, control] { w.display() }
CATransaction.flush()
/// Lets the main run loop turn for `seconds` (the stage windows commit).
func settle(_ seconds: Double) { RunLoop.main.run(until: Date(timeIntervalSinceNow: seconds)) }
settle(max(hold, 0.3))

do {   // is the backdrop right behind the target's window?
    let front = (CGWindowListCopyWindowInfo([.optionOnScreenOnly], kCGNullWindowID) as? [[String: Any]] ?? [])
        .compactMap { $0[kCGWindowNumber as String] as? CGWindowID }
    let i = front.firstIndex(of: main.id), j = front.firstIndex(of: CGWindowID(backdrop.windowNumber))
    print("   backdrop right behind window \(main.id): \(i != nil && j == i! + 1 ? "yes" : "NO (window list order \(i ?? -1), \(j ?? -1)): an excluded window may not show green")")
}
// Some paths draw the pointer; over a pane it counts as ink.
let pointerNote: String? = CGEvent(source: nil).flatMap { e in
    panes.first { $0.1.contains(e.location) }.map { "NOTE the pointer was over \($0.0) at the start: some paths draw it, and it counts as ink there; move it off the window and run again if that pane shows ink" }
}
if let pointerNote { print("   \(pointerNote)") }

// MARK: - Pixels

func rgba(_ img: CGImage) -> (UnsafeMutablePointer<UInt8>, Int, Int) {
    let w = img.width, h = img.height
    let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: w * h * 4)
    buf.initialize(repeating: 0, count: w * h * 4)
    let ctx = CGContext(data: buf, width: w, height: h, bitsPerComponent: 8, bytesPerRow: w * 4,
                        space: CGColorSpace(name: CGColorSpace.sRGB)!, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    ctx.draw(img, in: CGRect(x: 0, y: 0, width: w, height: h))
    return (buf, w, h)
}

struct Stats { var n = 0, green = 0, cyan = 0, black = 0, clear = 0, ink = 0; var mode = (0, 0, 0)
    func pc(_ k: Int) -> Double { 100 * Double(k) / Double(max(n, 1)) }
    var line: String { String(format: "ink=%.2f%% G=%.1f%% C=%.1f%% K=%.1f%% clear=%.1f%% mode=(%d,%d,%d) px=%d",
                              pc(ink), pc(green), pc(cyan), pc(black), pc(clear), mode.0, mode.1, mode.2, n) }
}

/// When a pane counts as showing content: by the area its ink covers, not by
/// its share of the pane. One line of 13 pt text (Brev's content font) is
/// under 0.5 % of a pane at the default window size and far less in a large
/// window, but a single short word such as "Ekko" covers several times
/// `minArea`; a pane the protected layer keeps empty has none.
enum Ink {
    /// Square points: about one glyph at 13 pt.
    static let minArea: Double = 12
    /// The ink of `s` in square points, for an image of `scale` pixels per point.
    static func area(_ s: Stats, scale: CGFloat) -> Double { Double(s.ink) / Double(scale * scale) }
    static func shown(_ s: Stats, scale: CGFloat) -> Bool { area(s, scale: scale) >= minArea }
}

/// Statistics of `r` (pixel rect) in a decoded image. Ink: pixels that differ
/// from the most common colour by more than 60 in some channel.
func stats(_ p: UnsafeMutablePointer<UInt8>, _ w: Int, _ h: Int, _ r0: CGRect) -> Stats {
    var s = Stats()
    let r = r0.integral.intersection(CGRect(x: 0, y: 0, width: w, height: h))
    if r.isNull || r.isEmpty { return s }
    var hist: [Int: Int] = [:]
    for y in Int(r.minY)..<Int(r.maxY) { for x in Int(r.minX)..<Int(r.maxX) {
        let i = (y * w + x) * 4
        let red = Int(p[i]), g = Int(p[i + 1]), b = Int(p[i + 2]), a = Int(p[i + 3])
        s.n += 1
        if a == 0 { s.clear += 1 }
        if red <= 110 && b <= 110 && g >= 100 && g - red > 60 { s.green += 1 }
        if red <= 140 && g >= 170 && b >= 170 { s.cyan += 1 }
        if a > 0 && red <= 20 && g <= 20 && b <= 20 { s.black += 1 }
        hist[(red >> 4) << 8 | (g >> 4) << 4 | (b >> 4), default: 0] += 1
    } }
    let m = hist.max { $0.value < $1.value }!.key
    s.mode = ((m >> 8 & 15) * 16 + 8, (m >> 4 & 15) * 16 + 8, (m & 15) * 16 + 8)
    for y in Int(r.minY)..<Int(r.maxY) { for x in Int(r.minX)..<Int(r.maxX) {
        let i = (y * w + x) * 4
        if abs(Int(p[i]) - s.mode.0) > 60 || abs(Int(p[i + 1]) - s.mode.1) > 60 || abs(Int(p[i + 2]) - s.mode.2) > 60 { s.ink += 1 }
    } }
    return s
}

func save(_ img: CGImage, _ name: String) {
    let url = outDir.appendingPathComponent("\(name).png")
    guard let d = CGImageDestinationCreateWithURL(url as CFURL, UTType.png.identifier as CFString, 1, nil) else { return }
    CGImageDestinationAddImage(d, img, nil)
    CGImageDestinationFinalize(d)
    print("   saved \(img.width)x\(img.height) -> \(url.lastPathComponent)")
}

/// The image in `url`, decoded now (a lazy image would read the file after
/// it is deleted).
func load(_ url: URL) -> CGImage? {
    CGImageSourceCreateWithURL(url as CFURL, nil).flatMap {
        CGImageSourceCreateImageAtIndex($0, 0, [kCGImageSourceShouldCacheImmediately: true] as CFDictionary)
    }
}

/// The cut of `img` (which covers `covered`, global points) to the stage area.
func cut(_ img: CGImage, covered: CGRect) -> CGImage? {
    let s = CGFloat(img.width) / covered.width
    let px = CGRect(x: (area.minX - covered.minX) * s, y: (area.minY - covered.minY) * s,
                    width: area.width * s, height: area.height * s).integral
    return img.cropping(to: px.intersection(CGRect(x: 0, y: 0, width: img.width, height: img.height)))
}

enum Verdict: Int, Comparable { case pass = 0, content = 1, invalid = 2
    static func < (a: Verdict, b: Verdict) -> Bool { a.rawValue < b.rawValue }
}
var worst = Verdict.pass
var summary: [String] = []

func record(_ path: String, _ v: Verdict, _ why: String) {
    worst = max(worst, v)
    let tag = v == .pass ? "pass" : v == .content ? "INK IN A PANE: look at the cut" : "INVALID"
    summary.append("RESULT \(path.padding(toLength: 34, withPad: " ", startingAt: 0)) \(tag): \(why)")
    print("   -> \(tag): \(why)")
}

/// The verdict on a path whose image shows the window (`captured`) or the
/// backdrop in its place, from each known pane and whether it shows ink.
/// A captured window with no known pane proves nothing: "no ink" would only
/// mean "nothing was looked at".
func paneVerdict(_ window: String, captured: Bool, _ judged: [(name: String, ink: Bool)]) -> (Verdict, String) {
    if judged.isEmpty {
        return captured ? (.invalid, "\(window), but no content pane is known (Brev not on its mail window, or no AX trust and no --pane): nothing judged")
                        : (.pass, "\(window); no content pane known")
    }
    let inked = judged.filter(\.ink).map(\.name)
    return inked.isEmpty ? (.pass, "\(window), every pane empty") : (.content, "\(window), ink in \(inked.joined(separator: ", "))")
}

/// The verdict on a window-level capture of the target that gave no image or
/// an empty one: the window is excluded only if the same method shows the
/// control window; otherwise the method may simply not work.
func emptyWindowVerdict(_ what: String, controlShown: Bool) -> (Verdict, String) {
    controlShown ? (.pass, "\(what); the same method shows the control window")
                 : (.invalid, "\(what), and the same method does not show the control window either: nothing judged")
}

/// A capture of the screen (or part of it) covering `covered`: cut to the
/// stage, saved, and judged.
func judgeArea(_ path: String, _ img: CGImage?, covered: CGRect) {
    print("-- \(path)")
    guard let img, let c = cut(img, covered: covered) else { record(path, .invalid, "no image"); return }
    save(c, path)
    let (p, w, h) = rgba(c); defer { p.deallocate() }
    let s = CGFloat(w) / area.width
    func px(_ r: CGRect) -> CGRect { CGRect(x: (r.minX - area.minX) * s, y: (r.minY - area.minY) * s, width: r.width * s, height: r.height * s) }
    let ctl = stats(p, w, h, px(controlRect.insetBy(dx: 6, dy: 6)))
    print("   control   \(ctl.line)")
    guard ctl.pc(ctl.cyan) >= 50, ctl.pc(ctl.ink) >= 0.2 else { record(path, .invalid, "the control window or its text is not visible"); return }
    var body = main.bounds.insetBy(dx: 8, dy: 8)
    body.origin.y += 28; body.size.height -= 28   // below the title bar
    let win = stats(p, w, h, px(body))
    print("   window    \(win.line)")
    // The panes are judged either way: an excluded window shows the
    // backdrop there, which has no ink either. Where the control window lies
    // over the target (no room beside it), that part is the control's.
    let excluded = win.pc(win.green) >= 50
    judgePanes(path, p, w, h, scale: s, { px(besideControl($0)) },
               window: excluded ? "window excluded (the backdrop shows)" : "window captured", captured: !excluded)
}

/// The part of `r` left of the control window, when the control lies over
/// its right edge (it spans the stage's height, so this is all it covers),
/// 8 points clear of that edge, which a video frame (-V) blurs.
func besideControl(_ r: CGRect) -> CGRect {
    let edge = controlRect.minX - 8
    guard r.maxX > edge, controlRect.maxY > r.minY, controlRect.minY < r.maxY else { return r }
    return CGRect(x: r.minX, y: r.minY, width: max(0, edge - r.minX), height: r.height)
}

func judgePanes(_ path: String, _ p: UnsafeMutablePointer<UInt8>, _ w: Int, _ h: Int, scale: CGFloat, _ px: (CGRect) -> CGRect,
                window: String = "window captured", captured: Bool = true) {
    let judged = panes.map { (name, r) -> (name: String, ink: Bool) in
        let st = stats(p, w, h, px(r.insetBy(dx: 6, dy: 6)))
        print("   \(name.padding(toLength: 9, withPad: " ", startingAt: 0)) \(st.line) ink area=\(Int(Ink.area(st, scale: scale))) pt²")
        return (name, Ink.shown(st, scale: scale))
    }
    let (v, why) = paneVerdict(window, captured: captured, judged)
    record(path, v, why)
}

/// Whether an image of the control window alone, taken by a window-level
/// method, shows it: mostly cyan, with its text.
func controlShown(_ img: CGImage?) -> Bool {
    guard let img else { print("   control window: no image"); return false }
    let (p, w, h) = rgba(img); defer { p.deallocate() }
    let s = stats(p, w, h, CGRect(x: 0, y: 0, width: w, height: h))
    print("   control window \(s.line)")
    return s.pc(s.cyan) >= 50 && Ink.shown(s, scale: CGFloat(w) / controlRect.width)
}

/// An image of one window (a window filter or -l): excluded if it is missing,
/// transparent or black while the same method shows the control window
/// (`control`); otherwise its panes are judged.
func judgeWindow(_ path: String, _ img: CGImage?, window: Win, control: Bool) {
    print("-- \(path)")
    guard let img else {
        let (v, why) = emptyWindowVerdict("no image of window \(window.id)", controlShown: control)
        record(path, v, why)
        return
    }
    save(img, path)
    let (p, w, h) = rgba(img); defer { p.deallocate() }
    let all = stats(p, w, h, CGRect(x: 0, y: 0, width: w, height: h))
    print("   image     \(all.line)")
    if all.pc(all.clear) >= 95 || all.pc(all.black) >= 95 {
        let (v, why) = emptyWindowVerdict("window \(window.id) excluded (image empty)", controlShown: control)
        record(path, v, why)
        return
    }
    let s = CGFloat(w) / window.bounds.width
    judgePanes(path, p, w, h, scale: s) { r in
        CGRect(x: (r.minX - window.bounds.minX) * s, y: (r.minY - window.bounds.minY) * s, width: r.width * s, height: r.height * s)
    }
}

// MARK: - ScreenCaptureKit (V6)

func scale(of id: CGDirectDisplayID) -> CGFloat {
    NSScreen.screens.first { ($0.deviceDescription[NSDeviceDescriptionKey("NSScreenNumber")] as? NSNumber)?.uint32Value == id }?
        .backingScaleFactor ?? 2
}

/// Keeps the image of each complete frame, up to the third. A window that
/// does not change gets one complete frame and then only idle ones, so the
/// last complete frame is what counts when fewer arrive.
final class FrameGrabber: NSObject, SCStreamOutput {
    var image: CGImage?
    var frames = 0
    func stream(_ stream: SCStream, didOutputSampleBuffer sb: CMSampleBuffer, of type: SCStreamOutputType) {
        guard type == .screen, frames < 3,
              let att = CMSampleBufferGetSampleAttachmentsArray(sb, createIfNecessary: false) as? [[SCStreamFrameInfo: Any]],
              let raw = att.first?[.status] as? Int, SCFrameStatus(rawValue: raw) == .complete,
              let pb = sb.imageBuffer else { return }
        frames += 1
        let ci = CIImage(cvPixelBuffer: pb)
        image = CIContext().createCGImage(ci, from: ci.extent)
    }
}

@MainActor func oneFrame(_ filter: SCContentFilter, _ cfg: SCStreamConfiguration) async -> CGImage? {
    let g = FrameGrabber()
    let s = SCStream(filter: filter, configuration: cfg, delegate: nil)
    do {
        try s.addStreamOutput(g, type: .screen, sampleHandlerQueue: DispatchQueue(label: "grab"))
        try await s.startCapture()
        for _ in 0..<40 where g.frames < 3 { try await Task.sleep(nanoseconds: 100_000_000) }
        try await s.stopCapture()
    } catch { print("   stream error: \(error)") }
    print("   stream: \(g.frames) complete frame(s)")
    return g.image
}

@MainActor func sck() async {
    let content: SCShareableContent
    do { content = try await SCShareableContent.excludingDesktopWindows(false, onScreenWindowsOnly: false) } catch {
        print("SCShareableContent error: \(error)"); record("sck", .invalid, "SCShareableContent failed: no path ran"); return
    }
    for w in targetWindows { print("   window \(w.id) listed by SCShareableContent: \(content.windows.contains { $0.windowID == w.id })") }
    guard let d = content.displays.first(where: { $0.displayID == display }) else {
        record("sck", .invalid, "display \(display) not listed by SCShareableContent: no path ran"); return
    }
    let sc = scale(of: display)
    let cfg = SCStreamConfiguration()
    cfg.width = Int(CGFloat(d.width) * sc); cfg.height = Int(CGFloat(d.height) * sc); cfg.showsCursor = false
    let byDisplay = SCContentFilter(display: d, excludingWindows: [])

    do { judgeArea("sck-display", try await SCScreenshotManager.captureImage(contentFilter: byDisplay, configuration: cfg), covered: displayBounds) }
    catch { print("   error \(error)"); judgeArea("sck-display", nil, covered: displayBounds) }
    let noApps = SCContentFilter(display: d, excludingApplications: [], exceptingWindows: [])
    do { judgeArea("sck-display-excluding-no-apps", try await SCScreenshotManager.captureImage(contentFilter: noApps, configuration: cfg), covered: displayBounds) }
    catch { print("   error \(error)"); judgeArea("sck-display-excluding-no-apps", nil, covered: displayBounds) }
    /// A window filter and its configuration, for `sw`.
    func windowFilter(_ sw: SCWindow) -> (SCContentFilter, SCStreamConfiguration) {
        let wc = SCStreamConfiguration()
        wc.width = Int(sw.frame.width * sc); wc.height = Int(sw.frame.height * sc); wc.showsCursor = false
        if #available(macOS 14.2, *) { wc.includeChildWindows = true }
        return (SCContentFilter(desktopIndependentWindow: sw), wc)
    }
    // The window-filter methods' positive control: the same captures of the
    // control window.
    var controlImage = false, controlStream = false
    if let cw = content.windows.first(where: { $0.windowID == CGWindowID(control.windowNumber) }) {
        let (f, wc) = windowFilter(cw)
        print("-- control window through a window filter")
        do { controlImage = controlShown(try await SCScreenshotManager.captureImage(contentFilter: f, configuration: wc)) }
        catch { print("   error \(error)") }
        controlStream = controlShown(await oneFrame(f, wc))
    } else { print("-- control window not listed by SCShareableContent") }
    for w in targetWindows {
        let name = "sck-window-\(w.id)"
        guard let sw = content.windows.first(where: { $0.windowID == w.id }) else {
            print("-- \(name)"); record(name, .pass, "window \(w.id) not listed, so no window filter can name it"); continue
        }
        let (f, wc) = windowFilter(sw)
        do { judgeWindow(name, try await SCScreenshotManager.captureImage(contentFilter: f, configuration: wc), window: w, control: controlImage) }
        catch { print("   error \(error)"); judgeWindow(name, nil, window: w, control: controlImage) }
        judgeWindow("\(name)-stream", await oneFrame(f, wc), window: w, control: controlStream)
    }
    if #available(macOS 15.2, *) {
        do { judgeArea("sck-captureImage-in-rect", try await SCScreenshotManager.captureImage(in: area), covered: area) }
        catch { print("   error \(error)"); judgeArea("sck-captureImage-in-rect", nil, covered: area) }
    } else { print("-- sck-captureImage-in-rect: needs macOS 15.2") }
    if #available(macOS 26.0, *) {
        do { judgeArea("sck-captureScreenshot-filter", try await SCScreenshotManager.captureScreenshot(contentFilter: byDisplay, configuration: SCScreenshotConfiguration()).sdrImage, covered: displayBounds) }
        catch { print("   error \(error)"); judgeArea("sck-captureScreenshot-filter", nil, covered: displayBounds) }
        do { judgeArea("sck-captureScreenshot-rect", try await SCScreenshotManager.captureScreenshot(rect: area, configuration: SCScreenshotConfiguration()).sdrImage, covered: area) }
        catch { print("   error \(error)"); judgeArea("sck-captureScreenshot-rect", nil, covered: area) }
    } else { print("-- sck-captureScreenshot: needs macOS 26") }
    let scfg = SCStreamConfiguration()
    scfg.width = cfg.width; scfg.height = cfg.height; scfg.showsCursor = false
    scfg.minimumFrameInterval = CMTime(value: 1, timescale: 30)
    judgeArea("sck-stream-display", await oneFrame(byDisplay, scfg), covered: displayBounds)
}

// MARK: - Legacy CoreGraphics, CGDisplayStream, AVCaptureScreenInput (V7)

@available(macOS, deprecated: 14.0)
func legacyCG() {
    var ids = [CGDirectDisplayID](repeating: 0, count: 8)
    var n: UInt32 = 0
    CGGetActiveDisplayList(8, &ids, &n)
    let desktop = ids.prefix(Int(n)).reduce(CGRect.null) { $0.union(CGDisplayBounds($1)) }
    judgeArea("cg-WindowListCreateImage-screen",
              CGWindowListCreateImage(.infinite, .optionOnScreenOnly, kCGNullWindowID, [.bestResolution]), covered: desktop)
    print("-- control window through CGWindowListCreateImage")
    let ctl = controlShown(CGWindowListCreateImage(.null, .optionIncludingWindow, CGWindowID(control.windowNumber), [.boundsIgnoreFraming, .bestResolution]))
    for w in targetWindows {
        judgeWindow("cg-WindowListCreateImage-window-\(w.id)",
                    CGWindowListCreateImage(.null, .optionIncludingWindow, w.id, [.boundsIgnoreFraming, .bestResolution]), window: w, control: ctl)
    }
    judgeArea("cg-DisplayCreateImage", CGDisplayCreateImage(display), covered: displayBounds)
    let local = area.offsetBy(dx: -displayBounds.minX, dy: -displayBounds.minY)
    judgeArea("cg-DisplayCreateImage-rect", CGDisplayCreateImage(display, rect: local), covered: area)
}

func pixelSize(_ d: CGDirectDisplayID) -> (Int, Int) {
    if let m = CGDisplayCopyDisplayMode(d) { return (m.pixelWidth, m.pixelHeight) }
    return (CGDisplayPixelsWide(d) * 2, CGDisplayPixelsHigh(d) * 2)
}

@available(macOS, deprecated: 14.0)
func cgDisplayStream() {
    var got: CGImage?
    let sem = DispatchSemaphore(value: 0)
    let (pw, ph) = pixelSize(display)
    let props = [CGDisplayStream.showCursor: false] as CFDictionary
    let s = CGDisplayStream(dispatchQueueDisplay: display, outputWidth: pw, outputHeight: ph,
                            pixelFormat: Int32(kCVPixelFormatType_32BGRA), properties: props, queue: DispatchQueue(label: "cgds"),
                            handler: { status, _, surf, _ in
        guard status == .frameComplete, got == nil, let surf else { return }
        let ci = CIImage(ioSurface: surf)
        got = CIContext().createCGImage(ci, from: ci.extent)
        sem.signal()
    })
    if let s {
        print("   CGDisplayStream start=\(s.start().rawValue)")
        _ = sem.wait(timeout: .now() + 5)
        _ = s.stop()
    } else { print("   CGDisplayStream create returned NULL") }
    judgeArea("cg-DisplayStream", got, covered: displayBounds)
}

final class AVGrab: NSObject, AVCaptureVideoDataOutputSampleBufferDelegate {
    var image: CGImage?
    var n = 0
    let sem = DispatchSemaphore(value: 0)
    func captureOutput(_ o: AVCaptureOutput, didOutput sb: CMSampleBuffer, from c: AVCaptureConnection) {
        n += 1
        guard image == nil, n >= 5, let pb = sb.imageBuffer else { return }
        let ci = CIImage(cvPixelBuffer: pb)
        image = CIContext().createCGImage(ci, from: ci.extent)
        sem.signal()
    }
}

func avCapture() {
    var img: CGImage?
    if let input = AVCaptureScreenInput(displayID: display) {
        input.capturesCursor = false
        let session = AVCaptureSession(), out = AVCaptureVideoDataOutput(), g = AVGrab()
        out.setSampleBufferDelegate(g, queue: DispatchQueue(label: "av"))
        if session.canAddInput(input), session.canAddOutput(out) {
            session.addInput(input); session.addOutput(out)
            session.startRunning()
            let r = g.sem.wait(timeout: .now() + 6)
            session.stopRunning()
            print("   AVCaptureScreenInput frames=\(g.n) \(r == .success ? "ok" : "timeout")")
            img = g.image
        } else { print("   AVCaptureScreenInput: cannot add input or output") }
    } else { print("   AVCaptureScreenInput init returned nil") }
    judgeArea("avcapture-ScreenInput", img, covered: displayBounds)
}

/// CGDisplayStream through dlsym, from capture-probe-26 next to this tool.
func cgDisplayStream26() {
    let tool = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent().appendingPathComponent("capture-probe-26")
    let file = tmpDir.appendingPathComponent("tmp-cgds26.png")
    let p = Process()
    p.executableURL = tool
    p.arguments = [file.path, "\(display)"] + [area.minX, area.minY, area.width, area.height].map { "\(Double($0))" }
    do { try p.run(); p.waitUntilExit() } catch { print("   \(tool.path): \(error)") }
    judgeArea("cg-DisplayStream-dlsym-26", load(file), covered: area)
    try? FileManager.default.removeItem(at: file)
}

// MARK: - screencapture (V5)

@discardableResult
func run(_ path: String, _ arguments: [String]) -> (Int32, String) {
    let p = Process(), err = Pipe()
    p.executableURL = URL(fileURLWithPath: path)
    p.arguments = arguments
    p.standardError = err
    p.standardOutput = FileHandle.nullDevice
    do { try p.run() } catch { return (-1, "\(error)") }
    p.waitUntilExit()
    let msg = String(decoding: err.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    return (p.terminationStatus, msg.trimmingCharacters(in: .whitespacesAndNewlines))
}

func movieFrame(_ url: URL, at seconds: Double) async -> CGImage? {
    let gen = AVAssetImageGenerator(asset: AVURLAsset(url: url))
    gen.requestedTimeToleranceBefore = .zero
    gen.requestedTimeToleranceAfter = .zero
    return try? await gen.image(at: CMTime(seconds: seconds, preferredTimescale: 600)).image
}

@MainActor func screencapture() async {
    // Whole screens go to a file only for as long as it takes to cut them,
    // in the private temporary folder.
    let full = tmpDir.appendingPathComponent("tmp-full.png")
    var r = run("/usr/sbin/screencapture", ["-x", full.path])
    print("   screencapture -x exit=\(r.0) \(r.1)")
    judgeArea("screencapture-x", load(full), covered: displayBounds)
    try? FileManager.default.removeItem(at: full)
    let part = tmpDir.appendingPathComponent("tmp-R.png")
    r = run("/usr/sbin/screencapture", ["-x", "-R\(text(area))", part.path])
    print("   screencapture -R\(text(area)) exit=\(r.0) \(r.1)")
    judgeArea("screencapture-R", load(part), covered: area)
    try? FileManager.default.removeItem(at: part)
    let file = tmpDir.appendingPathComponent("tmp-l.png")
    r = run("/usr/sbin/screencapture", ["-x", "-o", "-l\(control.windowNumber)", file.path])
    print("-- control window through screencapture -l\(control.windowNumber) exit=\(r.0) \(r.1)")
    let ctl = controlShown(load(file))
    try? FileManager.default.removeItem(at: file)
    for w in targetWindows {
        r = run("/usr/sbin/screencapture", ["-x", "-o", "-l\(w.id)", file.path])
        print("   screencapture -l\(w.id) exit=\(r.0) \(r.1)")
        judgeWindow("screencapture-l-\(w.id)", load(file), window: w, control: ctl)
        try? FileManager.default.removeItem(at: file)
    }
    let movie = tmpDir.appendingPathComponent("tmp-V.mov")
    r = run("/usr/sbin/screencapture", ["-x", "-V", "3", movie.path])
    print("   screencapture -V 3 exit=\(r.0) \(r.1)")
    judgeArea("screencapture-V", await movieFrame(movie, at: 1.5), covered: displayBounds)
    try? FileManager.default.removeItem(at: movie)
}

// MARK: - Self-test (--selftest): the verdict rules on drawn panes

/// Statistics of a white pane of `size` points at `scale`, with one line of
/// `text` in black at 13 pt (Brev's content font), or empty; cut as a pane is.
func drawnPane(_ size: CGSize, scale: CGFloat, _ text: String?) -> Stats {
    let w = Int(size.width * scale), h = Int(size.height * scale)
    let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: w * h * 4)
    buf.initialize(repeating: 0, count: w * h * 4)
    defer { buf.deallocate() }
    let ctx = CGContext(data: buf, width: w, height: h, bitsPerComponent: 8, bytesPerRow: w * 4,
                        space: CGColorSpace(name: CGColorSpace.sRGB)!, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    ctx.setFillColor(CGColor(srgbRed: 1, green: 1, blue: 1, alpha: 1))
    ctx.fill(CGRect(x: 0, y: 0, width: w, height: h))
    if let text {
        ctx.scaleBy(x: scale, y: scale)
        let line = CTLineCreateWithAttributedString(NSAttributedString(string: text, attributes: [
            NSAttributedString.Key(kCTFontAttributeName as String): NSFont.systemFont(ofSize: 13) as CTFont,
            NSAttributedString.Key(kCTForegroundColorAttributeName as String): CGColor(srgbRed: 0, green: 0, blue: 0, alpha: 1)]))
        ctx.textPosition = CGPoint(x: 16, y: size.height - 30)
        CTLineDraw(line, ctx)
    }
    return stats(buf, w, h, CGRect(x: 0, y: 0, width: w, height: h).insetBy(dx: 6 * scale, dy: 6 * scale))
}

func selftest() -> Bool {
    print("capture-probe --selftest: the verdict rules on drawn panes (no window, no capture)")
    var ok = true
    func expect(_ what: String, _ cond: Bool, _ detail: String = "") {
        print((cond ? "ok   " : "FAIL ") + what + (detail.isEmpty ? "" : "  [\(detail)]"))
        if !cond { ok = false }
    }
    // VERIFY's letter: the contact names, and a one-line subject and body as
    // long as the marker (not the marker itself, which V17, V19 and V21
    // search for), in panes of Brev's default window (900×600) and of one
    // that fills a 1512×982 screen.
    let line = "ONE-LINE-SUBJECT æøå"
    let cases: [(String, CGSize, String)] = [
        ("contacts pane (default)", CGSize(width: 200, height: 540), "Ekko"),
        ("contacts pane (default)", CGSize(width: 200, height: 540), "Speil"),
        ("threads pane (default)", CGSize(width: 280, height: 540), line),
        ("letters pane (default)", CGSize(width: 418, height: 540), line),
        ("contacts pane (full screen)", CGSize(width: 330, height: 900), "Ekko"),
        ("letters pane (full screen)", CGSize(width: 800, height: 900), line),
    ]
    for scale: CGFloat in [1, 2] {
        for (pane, size, text) in cases {
            let s = drawnPane(size, scale: scale, text)
            expect("\(pane) at \(Int(scale))x: one line of \(text.count) characters counts as content", Ink.shown(s, scale: scale),
                   String(format: "ink %.0f pt², %.2f%% of the pane", Ink.area(s, scale: scale), s.pc(s.ink)))
        }
        let empty = drawnPane(CGSize(width: 418, height: 540), scale: scale, nil)
        expect("an empty pane at \(Int(scale))x counts as empty", !Ink.shown(empty, scale: scale),
               String(format: "ink %.0f pt²", Ink.area(empty, scale: scale)))
    }
    expect("window captured, no pane known: INVALID", paneVerdict("window captured", captured: true, []).0 == .invalid)
    expect("window excluded, no pane known: pass", paneVerdict("window excluded", captured: false, []).0 == .pass)
    expect("window captured, ink in a pane: content",
           paneVerdict("window captured", captured: true, [("a", false), ("b", true)]).0 == .content)
    expect("window captured, every pane empty: pass", paneVerdict("window captured", captured: true, [("a", false)]).0 == .pass)
    expect("no image of the window, none of the control either: INVALID", emptyWindowVerdict("none", controlShown: false).0 == .invalid)
    expect("no image of the window, the control shown: pass", emptyWindowVerdict("none", controlShown: true).0 == .pass)
    if let d = cutsFolder(nil) {
        let perms = (try? FileManager.default.attributesOfItem(atPath: d.path))?[.posixPermissions] as? Int
        let parent = d.deletingLastPathComponent().standardizedFileURL.path
        expect("the cuts' default folder: new, 0700, directly under $TMPDIR (never the current directory)",
               parent == URL(fileURLWithPath: NSTemporaryDirectory()).standardizedFileURL.path && perms == 0o700,
               "\(d.path) \(String(perms ?? 0, radix: 8))")
        try? FileManager.default.removeItem(at: d)
    } else { expect("the cuts' default folder is made", false) }
    print(ok ? "PASS" : "FAIL")
    return ok
}

// MARK: - main

switch mode {
case "legacy":
    legacyCG()
    cgDisplayStream()
    avCapture()
    cgDisplayStream26()
case "screencapture":
    await screencapture()
default:
    await sck()
}
// Were the panes the same through the run? A lock (the lock screen has no
// scroll area) or a changed window would leave later paths judging pixels
// that are not the panes.
if panesFromAX && !panes.isEmpty {
    let now = axPanes() ?? []
    print("   panes from AX after the captures: \(now.isEmpty ? "none" : now.map { "\($0.0)=\(text($0.1))" }.joined(separator: " "))")
    let same = now.count == panes.count && zip(now, panes).allSatisfy { a, b in
        abs(a.1.minX - b.1.minX) < 2 && abs(a.1.minY - b.1.minY) < 2 && abs(a.1.width - b.1.width) < 2 && abs(a.1.height - b.1.height) < 2
    }
    if !same { record("panes-after-the-run", .invalid, "the content panes changed during the run (Brev locked, or its window changed): the paths prove nothing") }
} else if !panes.isEmpty {
    print("   panes given with --pane: not read again after the captures")
}
backdrop.orderOut(nil)
control.orderOut(nil)
print("== summary (\(mode), target pid \(pid), cuts in \(outDir.path))")
if let pointerNote { print(pointerNote) }
summary.forEach { print($0) }
exit(Int32(worst.rawValue))
