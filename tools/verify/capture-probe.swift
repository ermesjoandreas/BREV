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
// the cut is saved (<out>/<path>.png), never a whole screen. Per path it
// prints the control (it must be visible, with its text), each target window
// (excluded = the backdrop shows through), and the ink in each content pane:
// the pixels that differ from the pane's most common colour, which is where
// letter text would be. Panes are the target's AX scroll areas (no prompt; if
// Terminal is not trusted for Accessibility, give them with --pane).
//
// usage: capture-probe [--legacy | --screencapture] [--app <name> | --pid <n>]
//                      [--out <dir>] [--pane <name>=<x,y,w,h>]... [--hold <s>]
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
//   --out <dir>      where the cuts go (default ./capture-probe-out)
//   --pane n=r       a pane rect in global points, origin top left (repeatable)
//   --hold <s>       seconds to wait after the stage is up (default 1)
// Rects are global points with the origin at the top left of the main display.
//
// Exit: 0 every path passed (no ink in any pane, whether the window was
// excluded or captured); 1 a pane showed ink (content may be visible: look at the cut);
// 2 a control failed (that path proves nothing); 3 not runnable (no Screen
// Recording access, no target). It never asks for a permission.

import AppKit
import AVFoundation
import CoreImage
import CoreMedia
import ScreenCaptureKit
import UniformTypeIdentifiers

setvbuf(stdout, nil, _IOLBF, 0)
DispatchQueue.global().asyncAfter(deadline: .now() + 180) { print("WATCHDOG: 180 s, exiting"); exit(3) }

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

let mode = args.contains("--legacy") ? "legacy" : args.contains("--screencapture") ? "screencapture" : "sck"
let appName = value("--app") ?? "Brev"
let outDir = URL(fileURLWithPath: value("--out") ?? "capture-probe-out", isDirectory: true)
let hold = value("--hold").flatMap(Double.init) ?? 1

_ = CGMainDisplayID()   // connect to the window server before any ScreenCaptureKit call
guard CGPreflightScreenCaptureAccess() else {
    print("no Screen Recording access for this process (its responsible app): not runnable, nothing requested")
    exit(3)
}
try? FileManager.default.createDirectory(at: outDir, withIntermediateDirectories: true)

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

var panes: [(String, CGRect)] = values("--pane").compactMap { kv in
    let p = kv.split(separator: "=", maxSplits: 1)
    guard p.count == 2, let r = rect(String(p[1])) else { return nil }
    return (String(p[0]), r)
}
if panes.isEmpty {
    if AXIsProcessTrustedWithOptions([kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String: false] as CFDictionary) {
        let app = AXUIElementCreateApplication(pid)
        AXUIElementSetMessagingTimeout(app, 2)
        var found: [CGRect] = []
        for w in (axAttr(app, kAXWindowsAttribute) as? [AXUIElement]) ?? [] { scrollAreas(w, 0, &found) }
        panes = found.enumerated().map { ("pane\($0.offset + 1)", $0.element) }
        print("   panes from AX: \(panes.isEmpty ? "none" : panes.map { "\($0.0)=\(text($0.1))" }.joined(separator: " "))")
    } else {
        print("   not trusted for Accessibility: no panes found (none requested); give them with --pane")
    }
}

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
    // backdrop there, which has no ink either.
    judgePanes(path, p, w, h, px, window: win.pc(win.green) >= 50 ? "window excluded (the backdrop shows)" : "window captured")
}

func judgePanes(_ path: String, _ p: UnsafeMutablePointer<UInt8>, _ w: Int, _ h: Int, _ px: (CGRect) -> CGRect,
                window: String = "window captured") {
    if panes.isEmpty { record(path, .pass, "\(window); no content panes to check"); return }
    var inked: [String] = []
    for (name, r) in panes {
        let st = stats(p, w, h, px(r.insetBy(dx: 6, dy: 6)))
        print("   \(name.padding(toLength: 9, withPad: " ", startingAt: 0)) \(st.line)")
        if st.pc(st.ink) >= 0.5 { inked.append(name) }
    }
    if inked.isEmpty { record(path, .pass, "\(window), every pane empty") }
    else { record(path, .content, "\(window), ink in \(inked.joined(separator: ", "))") }
}

/// An image of one window (a window filter or -l): excluded if it is
/// transparent or black; otherwise its panes are judged.
func judgeWindow(_ path: String, _ img: CGImage?, window: Win) {
    print("-- \(path)")
    guard let img else { record(path, .pass, "no image of window \(window.id)"); return }
    save(img, path)
    let (p, w, h) = rgba(img); defer { p.deallocate() }
    let all = stats(p, w, h, CGRect(x: 0, y: 0, width: w, height: h))
    print("   image     \(all.line)")
    if all.pc(all.clear) >= 95 || all.pc(all.black) >= 95 { record(path, .pass, "window \(window.id) excluded (image empty)"); return }
    let s = CGFloat(w) / window.bounds.width
    judgePanes(path, p, w, h) { r in
        CGRect(x: (r.minX - window.bounds.minX) * s, y: (r.minY - window.bounds.minY) * s, width: r.width * s, height: r.height * s)
    }
}

// MARK: - ScreenCaptureKit (V6)

func scale(of id: CGDirectDisplayID) -> CGFloat {
    NSScreen.screens.first { ($0.deviceDescription[NSDeviceDescriptionKey("NSScreenNumber")] as? NSNumber)?.uint32Value == id }?
        .backingScaleFactor ?? 2
}

final class FrameGrabber: NSObject, SCStreamOutput {
    var image: CGImage?
    var frames = 0
    func stream(_ stream: SCStream, didOutputSampleBuffer sb: CMSampleBuffer, of type: SCStreamOutputType) {
        guard type == .screen, image == nil,
              let att = CMSampleBufferGetSampleAttachmentsArray(sb, createIfNecessary: false) as? [[SCStreamFrameInfo: Any]],
              let raw = att.first?[.status] as? Int, SCFrameStatus(rawValue: raw) == .complete,
              let pb = sb.imageBuffer else { return }
        frames += 1
        if frames < 3 { return }
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
        for _ in 0..<40 where g.image == nil { try await Task.sleep(nanoseconds: 100_000_000) }
        try await s.stopCapture()
    } catch { print("   stream error: \(error)") }
    return g.image
}

@MainActor func sck() async {
    let content: SCShareableContent
    do { content = try await SCShareableContent.excludingDesktopWindows(false, onScreenWindowsOnly: false) } catch {
        print("SCShareableContent error: \(error)"); worst = max(worst, .invalid); return
    }
    for w in targetWindows { print("   window \(w.id) listed by SCShareableContent: \(content.windows.contains { $0.windowID == w.id })") }
    guard let d = content.displays.first(where: { $0.displayID == display }) else { print("display \(display) not listed"); return }
    let sc = scale(of: display)
    let cfg = SCStreamConfiguration()
    cfg.width = Int(CGFloat(d.width) * sc); cfg.height = Int(CGFloat(d.height) * sc); cfg.showsCursor = false
    let byDisplay = SCContentFilter(display: d, excludingWindows: [])

    do { judgeArea("sck-display", try await SCScreenshotManager.captureImage(contentFilter: byDisplay, configuration: cfg), covered: displayBounds) }
    catch { print("   error \(error)"); judgeArea("sck-display", nil, covered: displayBounds) }
    let noApps = SCContentFilter(display: d, excludingApplications: [], exceptingWindows: [])
    do { judgeArea("sck-display-excluding-no-apps", try await SCScreenshotManager.captureImage(contentFilter: noApps, configuration: cfg), covered: displayBounds) }
    catch { print("   error \(error)"); judgeArea("sck-display-excluding-no-apps", nil, covered: displayBounds) }
    for w in targetWindows {
        let name = "sck-window-\(w.id)"
        guard let sw = content.windows.first(where: { $0.windowID == w.id }) else {
            print("-- \(name)"); record(name, .pass, "window \(w.id) not listed, so no window filter can name it"); continue
        }
        let wc = SCStreamConfiguration()
        wc.width = Int(sw.frame.width * sc); wc.height = Int(sw.frame.height * sc); wc.showsCursor = false
        if #available(macOS 14.2, *) { wc.includeChildWindows = true }
        let f = SCContentFilter(desktopIndependentWindow: sw)
        do { judgeWindow(name, try await SCScreenshotManager.captureImage(contentFilter: f, configuration: wc), window: w) }
        catch { print("   error \(error)"); judgeWindow(name, nil, window: w) }
        judgeWindow("\(name)-stream", await oneFrame(f, wc), window: w)
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
    for w in targetWindows {
        judgeWindow("cg-WindowListCreateImage-window-\(w.id)",
                    CGWindowListCreateImage(.null, .optionIncludingWindow, w.id, [.boundsIgnoreFraming, .bestResolution]), window: w)
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
    let file = outDir.appendingPathComponent("tmp-cgds26.png")
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
    // Whole screens go to a file only for as long as it takes to cut them.
    let full = outDir.appendingPathComponent("tmp-full.png")
    var r = run("/usr/sbin/screencapture", ["-x", full.path])
    print("   screencapture -x exit=\(r.0) \(r.1)")
    judgeArea("screencapture-x", load(full), covered: displayBounds)
    try? FileManager.default.removeItem(at: full)
    let part = outDir.appendingPathComponent("tmp-R.png")
    r = run("/usr/sbin/screencapture", ["-x", "-R\(text(area))", part.path])
    print("   screencapture -R\(text(area)) exit=\(r.0) \(r.1)")
    judgeArea("screencapture-R", load(part), covered: area)
    try? FileManager.default.removeItem(at: part)
    for w in targetWindows {
        let file = outDir.appendingPathComponent("tmp-l.png")
        r = run("/usr/sbin/screencapture", ["-x", "-o", "-l\(w.id)", file.path])
        print("   screencapture -l\(w.id) exit=\(r.0) \(r.1)")
        judgeWindow("screencapture-l-\(w.id)", load(file), window: w)
        try? FileManager.default.removeItem(at: file)
    }
    let movie = outDir.appendingPathComponent("tmp-V.mov")
    r = run("/usr/sbin/screencapture", ["-x", "-V", "3", movie.path])
    print("   screencapture -V 3 exit=\(r.0) \(r.1)")
    judgeArea("screencapture-V", await movieFrame(movie, at: 1.5), covered: displayBounds)
    try? FileManager.default.removeItem(at: movie)
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
backdrop.orderOut(nil)
control.orderOut(nil)
print("== summary (\(mode), target pid \(pid), cuts in \(outDir.path))")
summary.forEach { print($0) }
exit(Int32(worst.rawValue))
