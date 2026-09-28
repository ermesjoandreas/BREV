// capture-probe (v2) — tries every capture path against SpikeCapture (no.brev.spike.capture).
// Built with deployment target 14.0 so the CG calls obsoleted in 15.0 still compile directly.
//
//   probe windows | syswins
//   probe sck-list | sck-shots | sck-stream | cg | cgstream | avcap | spi
//   probe analyze-display <png> <label> | analyze-window <png> <label> | frame <mov> <sec> <label>
//
// Pixel classes (sRGB 8-bit): M magenta (EXCL/HOSTA/HOSTB content), C cyan (CTRL), Y yellow (SHA),
// O orange (SHB), B blue (CHILD), P purple (PROT/PROTX), G green (BACKDROP), K black, - other.
// Only the spike's own area is ever saved (crop of the BACKDROP rect); full-display images are
// analysed in memory, or deleted by the runner right after analysis.

import AppKit
import AVFoundation
import CoreImage
import CoreMedia
import Foundation
import ScreenCaptureKit
import UniformTypeIdentifiers

let outDir = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent()
    .deletingLastPathComponent().appendingPathComponent("out")
let cropDir = outDir.appendingPathComponent("crops")
try? FileManager.default.createDirectory(at: cropDir, withIntermediateDirectories: true)
let bundleID = "no.brev.spike.capture"
let order = ["BACKDROP", "EXCL", "CTRL", "HOSTA", "SHA", "CHILD", "HOSTB", "SHB", "PROT", "PROTX"]
let ownColor: [String: Character] = ["EXCL": "M", "CTRL": "C", "HOSTA": "M", "HOSTB": "M", "SHA": "Y",
                                     "SHB": "O", "CHILD": "B", "PROT": "P", "PROTX": "P", "BACKDROP": "G"]

// MARK: - windows

struct Win { let id: CGWindowID; let title: String; let bounds: CGRect; let layer: Int; let sharing: Int; let onscreen: Bool }

func spikePID() -> pid_t? {
    NSRunningApplication.runningApplications(withBundleIdentifier: bundleID).first?.processIdentifier
}

func spikeWindows() -> [Win] {
    guard let pid = spikePID() else { return [] }
    let info = CGWindowListCopyWindowInfo([.optionAll], kCGNullWindowID) as? [[String: Any]] ?? []
    return info.filter { ($0[kCGWindowOwnerPID as String] as? Int32) == pid }.map { d in
        let r = CGRect(dictionaryRepresentation: d[kCGWindowBounds as String] as! CFDictionary) ?? .zero
        return Win(id: d[kCGWindowNumber as String] as! CGWindowID, title: d[kCGWindowName as String] as? String ?? "",
                   bounds: r, layer: d[kCGWindowLayer as String] as? Int ?? -99,
                   sharing: d[kCGWindowSharingState as String] as? Int ?? -1,
                   onscreen: d[kCGWindowIsOnscreen as String] as? Bool ?? false)
    }.filter { $0.bounds.width > 20 }
}

// MARK: - pixels

func rgba(_ img: CGImage) -> (UnsafeMutablePointer<UInt8>, Int, Int) {
    let w = img.width, h = img.height
    let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: w * h * 4)
    buf.initialize(repeating: 0, count: w * h * 4)
    let ctx = CGContext(data: buf, width: w, height: h, bitsPerComponent: 8, bytesPerRow: w * 4,
                        space: CGColorSpace(name: CGColorSpace.sRGB)!,
                        bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    ctx.draw(img, in: CGRect(x: 0, y: 0, width: w, height: h))
    return (buf, w, h)
}

func classify(_ r: Int, _ g: Int, _ b: Int) -> Character {
    if r >= 170 && g <= 110 && b >= 170 { return "M" }
    if r >= 90 && b >= 90 && g <= 45 && abs(r - b) < 25 { return "M" }  // magenta dimmed by an attached sheet (113,26,113)
    if r <= 140 && g >= 170 && b >= 170 { return "C" }
    if r >= 170 && g >= 170 && b <= 110 { return "Y" }
    if r >= 170 && g >= 70 && g < 170 && b <= 90 { return "O" }
    if r <= 110 && g <= 140 && b >= 170 && b - r > 100 { return "B" }
    if r <= 80 && b >= 90 && b - r > 50 && b - g > 40 { return "B" }  // CHILD renders dimmed (29,44,113)
    if r >= 90 && r <= 170 && g <= 70 && b >= 170 { return "P" }
    if r <= 110 && b <= 110 && g >= 100 && g - r > 60 { return "G" }
    if r <= 20 && g <= 20 && b <= 20 { return "K" }
    return "-"
}

let classes: [Character] = ["M", "C", "Y", "O", "B", "P", "G", "K", "-"]

func counts(_ p: UnsafeMutablePointer<UInt8>, _ w: Int, _ h: Int, _ rect: CGRect, opaqueOnly: Bool = false) -> [Character: Double] {
    let r = rect.integral.intersection(CGRect(x: 0, y: 0, width: w, height: h))
    if r.isNull || r.isEmpty { return [:] }
    var c: [Character: Int] = [:]; var n = 0
    for y in Int(r.minY)..<Int(r.maxY) {
        for x in Int(r.minX)..<Int(r.maxX) {
            let i = (y * w + x) * 4
            if opaqueOnly && p[i + 3] < 200 { continue }
            c[classify(Int(p[i]), Int(p[i + 1]), Int(p[i + 2])), default: 0] += 1; n += 1
        }
    }
    var out: [Character: Double] = [:]
    for k in classes { out[k] = 100.0 * Double(c[k] ?? 0) / Double(max(n, 1)) }
    return out
}

func fmt(_ c: [Character: Double]) -> String {
    if c.isEmpty { return "outside image" }
    return classes.compactMap { k in (c[k] ?? 0) >= 0.1 ? "\(k)=\(String(format: "%.1f", c[k]!))%" : nil }.joined(separator: " ")
}

/// Verdict for one window region: its own colour visible → CAPTURED; else EXCLUDED.
func verdict(_ title: String, _ c: [Character: Double]) -> String {
    guard !c.isEmpty, let own = ownColor[title] else { return "" }
    let v = c[own] ?? 0
    if title == "BACKDROP" || title == "CTRL" { return v > 5 ? "visible (control ok)" : "NOT VISIBLE (control failed)" }
    return v > 2 ? "CAPTURED" : "excluded"
}

func save(_ img: CGImage, _ url: URL) {
    let d = CGImageDestinationCreateWithURL(url as CFURL, UTType.png.identifier as CFString, 1, nil)!
    CGImageDestinationAddImage(d, img, nil); CGImageDestinationFinalize(d)
}

/// Image covering global rect `area` (points, top-left origin). Prints per-window verdicts,
/// saves a crop of the BACKDROP rect only.
func analyzeArea(_ img: CGImage, label: String, area: CGRect) {
    let wins = spikeWindows()
    let sx = CGFloat(img.width) / area.width, sy = CGFloat(img.height) / area.height
    let (p, w, h) = rgba(img); defer { p.deallocate() }
    print("[\(label)] image \(img.width)x\(img.height) covering \(area) scale=\(sx)")
    for t in order {
        guard let wd = wins.first(where: { $0.title == t }) else { continue }
        // Sheets and titled windows: inset to skip frames/shadows; for titled windows skip the title bar.
        var b = wd.bounds.insetBy(dx: 8, dy: 6)
        if ["EXCL", "CTRL", "HOSTA", "HOSTB", "BACKDROP", "PROT", "PROTX"].contains(t) { b.origin.y += 28; b.size.height -= 28 }
        if t == "BACKDROP" { b = CGRect(x: wd.bounds.minX + 4, y: wd.bounds.maxY - 16, width: wd.bounds.width - 8, height: 10) }
        let pr = CGRect(x: (b.minX - area.minX) * sx, y: (b.minY - area.minY) * sy, width: b.width * sx, height: b.height * sy)
        let c = counts(p, w, h, pr)
        print("   \(t.padding(toLength: 9, withPad: " ", startingAt: 0)) \(verdict(t, c).padding(toLength: 22, withPad: " ", startingAt: 0)) \(fmt(c))")
    }
    if let bd = wins.first(where: { $0.title == "BACKDROP" }), bd.onscreen {
        let cr = CGRect(x: (bd.bounds.minX - area.minX) * sx, y: (bd.bounds.minY - area.minY) * sy,
                        width: bd.bounds.width * sx, height: bd.bounds.height * sy).integral
            .intersection(CGRect(x: 0, y: 0, width: img.width, height: img.height))
        if !cr.isNull, !cr.isEmpty, let crop = img.cropping(to: cr) {
            let u = cropDir.appendingPathComponent("\(label).png"); save(crop, u); print("   crop -> \(u.lastPathComponent)")
        }
    } else { print("   BACKDROP missing or off screen: no crop saved") }
}

func analyzeDisplay(_ img: CGImage, label: String) {
    analyzeArea(img, label: label, area: CGDisplayBounds(CGMainDisplayID()))
}

/// A single-window image: classify the whole image.
func analyzeWindowImage(_ img: CGImage, label: String, title: String) {
    let (p, w, h) = rgba(img); defer { p.deallocate() }
    let c = counts(p, w, h, CGRect(x: 0, y: 0, width: w, height: h), opaqueOnly: true)
    var alpha0 = 0
    for i in stride(from: 3, to: w * h * 4, by: 4) where p[i] == 0 { alpha0 += 1 }
    print("[\(label)] image \(img.width)x\(img.height) \(verdict(title, c)) opaque px: \(fmt(c)) transparent=\(String(format: "%.1f", 100.0 * Double(alpha0) / Double(max(w * h, 1))))%")
    let u = cropDir.appendingPathComponent("\(label).png"); save(img, u); print("   saved -> \(u.lastPathComponent)")
}

func load(_ path: String) -> CGImage? {
    guard let src = CGImageSourceCreateWithURL(URL(fileURLWithPath: path) as CFURL, nil) else { return nil }
    return CGImageSourceCreateImageAtIndex(src, 0, nil)
}

// MARK: - ScreenCaptureKit

func sckList() async throws -> SCShareableContent {
    let all = try await SCShareableContent.excludingDesktopWindows(false, onScreenWindowsOnly: false)
    let on = try await SCShareableContent.excludingDesktopWindows(false, onScreenWindowsOnly: true)
    let pid = spikePID() ?? -1
    print("SCShareableContent: \(all.windows.count) windows (onScreenOnly \(on.windows.count)); spike pid \(pid); app listed=\(all.applications.contains { $0.processID == pid })")
    for w in spikeWindows().sorted(by: { order.firstIndex(of: $0.title) ?? 99 < order.firstIndex(of: $1.title) ?? 99 }) {
        print("   CG \(w.id) \(w.title.padding(toLength: 9, withPad: " ", startingAt: 0)) kCGWindowSharingState=\(w.sharing) layer=\(w.layer) onscreen=\(w.onscreen) -> SCK listed(all)=\(all.windows.contains { $0.windowID == w.id }) listed(onScreenOnly)=\(on.windows.contains { $0.windowID == w.id })")
    }
    return all
}

func sckShots() async {
    do {
        let all = try await sckList()
        let pid = spikePID() ?? -1
        let cg = spikeWindows()
        guard let display = all.displays.first(where: { $0.displayID == CGMainDisplayID() }) else { print("no display"); return }
        let cfg = SCStreamConfiguration()
        cfg.width = display.width * 2; cfg.height = display.height * 2; cfg.showsCursor = false

        let fDisplay = SCContentFilter(display: display, excludingWindows: [])
        do { analyzeDisplay(try await SCScreenshotManager.captureImage(contentFilter: fDisplay, configuration: cfg), label: "sck-a-display") }
        catch { print("[sck-a-display] error: \(error)") }

        for w in all.windows where w.owningApplication?.processID == pid {
            let t = cg.first { $0.id == w.windowID }?.title ?? "id\(w.windowID)"
            let wc = SCStreamConfiguration()
            wc.width = Int(w.frame.width * 2); wc.height = Int(w.frame.height * 2); wc.showsCursor = false
            if #available(macOS 14.2, *) { wc.includeChildWindows = true }
            do { analyzeWindowImage(try await SCScreenshotManager.captureImage(contentFilter: SCContentFilter(desktopIndependentWindow: w), configuration: wc), label: "sck-b-window-\(t)", title: t) }
            catch { print("[sck-b-window-\(t)] error: \(error)") }
        }

        if let app = all.applications.first(where: { $0.processID == pid }) {
            do { analyzeDisplay(try await SCScreenshotManager.captureImage(contentFilter: SCContentFilter(display: display, including: [app], exceptingWindows: []), configuration: cfg), label: "sck-c-app-include") }
            catch { print("[sck-c-app-include] error: \(error)") }
        } else { print("[sck-c-app-include] spike app not in SCShareableContent.applications") }

        let others = all.applications.filter { $0.processID != pid }
        do { analyzeDisplay(try await SCScreenshotManager.captureImage(contentFilter: SCContentFilter(display: display, excludingApplications: others, exceptingWindows: []), configuration: cfg), label: "sck-c2-display-excluding-other-apps") }
        catch { print("[sck-c2] error: \(error)") }

        let listed = all.windows.filter { $0.owningApplication?.processID == pid }
        do { analyzeDisplay(try await SCScreenshotManager.captureImage(contentFilter: SCContentFilter(display: display, including: listed), configuration: cfg), label: "sck-d-display-including-listed-windows") }
        catch { print("[sck-d] error: \(error)") }

        if let bd = cg.first(where: { $0.title == "BACKDROP" }) {
            if #available(macOS 15.2, *) {
                do { analyzeArea(try await SCScreenshotManager.captureImage(in: bd.bounds), label: "sck-e-captureImage-in-rect", area: bd.bounds) }
                catch { print("[sck-e] error: \(error)") }
            }
            if #available(macOS 26.0, *) {
                do {
                    let out = try await SCScreenshotManager.captureScreenshot(contentFilter: fDisplay, configuration: SCScreenshotConfiguration())
                    if let img = out.sdrImage { analyzeDisplay(img, label: "sck-f-captureScreenshot-filter-26") } else { print("[sck-f] no sdrImage") }
                } catch { print("[sck-f] error: \(error)") }
                do {
                    let out = try await SCScreenshotManager.captureScreenshot(rect: bd.bounds, configuration: SCScreenshotConfiguration())
                    if let img = out.sdrImage { analyzeArea(img, label: "sck-g-captureScreenshot-rect-26", area: bd.bounds) } else { print("[sck-g] no sdrImage") }
                } catch { print("[sck-g] error: \(error)") }
            }
        }
    } catch { print("SCK error: \(error)") }
}

final class FrameGrabber: NSObject, SCStreamOutput {
    var image: CGImage?; var frames = 0
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

func oneFrame(_ filter: SCContentFilter, _ cfg: SCStreamConfiguration) async throws -> CGImage? {
    let g = FrameGrabber()
    let s = SCStream(filter: filter, configuration: cfg, delegate: nil)
    try s.addStreamOutput(g, type: .screen, sampleHandlerQueue: DispatchQueue(label: "grab"))
    try await s.startCapture()
    for _ in 0..<40 where g.image == nil { try await Task.sleep(nanoseconds: 100_000_000) }
    if let h = ProcessInfo.processInfo.environment["HOLD"], let v = Double(h) { print("[sck-stream] holding \(v) s"); try await Task.sleep(nanoseconds: UInt64(v * 1e9)) }
    try await s.stopCapture()
    return g.image
}

func sckStream() async {
    do {
        let all = try await sckList()
        let pid = spikePID() ?? -1
        let cg = spikeWindows()
        guard let display = all.displays.first(where: { $0.displayID == CGMainDisplayID() }) else { return }
        let cfg = SCStreamConfiguration()
        cfg.width = display.width * 2; cfg.height = display.height * 2; cfg.showsCursor = false
        cfg.minimumFrameInterval = CMTime(value: 1, timescale: 30)
        if let img = try await oneFrame(SCContentFilter(display: display, excludingWindows: []), cfg) {
            analyzeDisplay(img, label: "sck-stream-display")
        } else { print("[sck-stream-display] no frame") }
        for w in all.windows where w.owningApplication?.processID == pid {
            let t = cg.first { $0.id == w.windowID }?.title ?? "id\(w.windowID)"
            guard ["HOSTA", "HOSTB", "EXCL", "CTRL", "PROT", "PROTX"].contains(t) else { continue }
            let wc = SCStreamConfiguration()
            wc.width = Int(w.frame.width * 2); wc.height = Int(w.frame.height * 2); wc.showsCursor = false
            if #available(macOS 14.2, *) { wc.includeChildWindows = true }
            if let img = try await oneFrame(SCContentFilter(desktopIndependentWindow: w), wc) {
                analyzeWindowImage(img, label: "sck-stream-window-\(t)-children", title: t)
            } else { print("[sck-stream-window-\(t)] no frame") }
        }
    } catch { print("SCK stream error: \(error)") }
}

func opaqueStats(_ img: CGImage) -> String {
    let (p, w, h) = rgba(img); defer { p.deallocate() }
    var n = 0, minX = w, minY = h, maxX = -1, maxY = -1
    for y in stride(from: 0, to: h, by: 2) { for x in stride(from: 0, to: w, by: 2) where p[(y * w + x) * 4 + 3] > 0 {
        n += 1; minX = min(minX, x); minY = min(minY, y); maxX = max(maxX, x); maxY = max(maxY, y) } }
    return "\(img.width)x\(img.height) opaque samples=\(n) bbox px=\(minX),\(minY)..\(maxX),\(maxY)"
}

func sckInc() async {
    do {
        let all = try await SCShareableContent.excludingDesktopWindows(false, onScreenWindowsOnly: false)
        let pid = spikePID() ?? -1
        let cg = spikeWindows()
        guard let display = all.displays.first(where: { $0.displayID == CGMainDisplayID() }),
              let app = all.applications.first(where: { $0.processID == pid }) else { print("no display/app"); return }
        print("app: \(app.bundleIdentifier) pid \(app.processID)")
        let cfg = SCStreamConfiguration()
        cfg.width = display.width * 2; cfg.height = display.height * 2; cfg.showsCursor = false
        let ctrl = all.windows.filter { w in cg.first { $0.id == w.windowID }?.title == "CTRL" }
        let mine = all.windows.filter { $0.owningApplication?.processID == pid }
        let tries: [(String, SCContentFilter)] = [
            ("including-app", SCContentFilter(display: display, including: [app], exceptingWindows: [])),
            ("including-CTRL-window", SCContentFilter(display: display, including: ctrl)),
            ("including-all-my-windows", SCContentFilter(display: display, including: mine)),
            ("excludingApplications-none", SCContentFilter(display: display, excludingApplications: [], exceptingWindows: [])),
        ]
        for (name, f) in tries {
            print("   filter \(name): contentRect=\(f.contentRect) scale=\(f.pointPixelScale) style=\(f.style.rawValue)")
            do {
                let img = try await SCScreenshotManager.captureImage(contentFilter: f, configuration: cfg)
                print("   [sck-inc-\(name)] screenshot \(opaqueStats(img))")
                // Screenshots with an including filter are cropped to the union of the included
                // windows and placed at the image origin; shift the analysis area accordingly.
                let incIDs: Set<CGWindowID>
                switch name {
                case "including-CTRL-window": incIDs = Set(ctrl.map { $0.windowID })
                case "including-app", "including-all-my-windows": incIDs = Set(mine.map { $0.windowID })
                default: incIDs = []
                }
                if incIDs.isEmpty { analyzeDisplay(img, label: "sck-inc-\(name)") } else {
                    let u = cg.filter { incIDs.contains($0.id) }.map { $0.bounds }.reduce(CGRect.null) { $0.union($1) }
                    analyzeArea(img, label: "sck-inc-\(name)", area: CGRect(x: u.minX, y: u.minY, width: CGFloat(img.width) / 2, height: CGFloat(img.height) / 2))
                }
            } catch { print("   [sck-inc-\(name)] error \(error)") }
            do {
                if let img = try await oneFrame(f, cfg) {
                    print("   [sck-inc-\(name)-stream] frame \(opaqueStats(img))")
                    analyzeDisplay(img, label: "sck-inc-\(name)-stream")
                } else { print("   [sck-inc-\(name)-stream] no frame") }
            } catch { print("   [sck-inc-\(name)-stream] error \(error)") }
        }
    } catch { print("SCK error: \(error)") }
}

// MARK: - CoreGraphics (deprecated 14.x, obsoleted in the 15.0 SDK; this binary targets 14.0)

@available(macOS, deprecated: 14.0)
func cgTests() {
    let screen = CGDisplayBounds(CGMainDisplayID())
    if let img = CGWindowListCreateImage(.infinite, .optionOnScreenOnly, kCGNullWindowID, [.bestResolution]) {
        analyzeDisplay(img, label: "cg-WindowListCreateImage-screen")
    } else { print("[cg-WindowListCreateImage-screen] NULL") }
    for w in spikeWindows() where w.title != "BACKDROP" {
        if let img = CGWindowListCreateImage(.null, .optionIncludingWindow, w.id, [.boundsIgnoreFraming, .bestResolution]) {
            analyzeWindowImage(img, label: "cg-WindowListCreateImage-window-\(w.title)", title: w.title)
        } else { print("[cg-WindowListCreateImage-window-\(w.title)] NULL") }
    }
    let ids = spikeWindows().map { $0.id }
    var ptrs: [UnsafeRawPointer?] = ids.map { UnsafeRawPointer(bitPattern: UInt($0)) }
    let arr = CFArrayCreate(nil, &ptrs, ptrs.count, nil)!
    if let img = CGImage(windowListFromArrayScreenBounds: screen, windowArray: arr, imageOption: [.bestResolution]) {
        analyzeDisplay(img, label: "cg-WindowListCreateImageFromArray")
    } else { print("[cg-WindowListCreateImageFromArray] NULL") }
    if let img = CGDisplayCreateImage(CGMainDisplayID()) { analyzeDisplay(img, label: "cg-DisplayCreateImage") }
    else { print("[cg-DisplayCreateImage] NULL") }
    if let bd = spikeWindows().first(where: { $0.title == "BACKDROP" }) {
        if let img = CGDisplayCreateImage(CGMainDisplayID(), rect: bd.bounds) { analyzeArea(img, label: "cg-DisplayCreateImageForRect", area: bd.bounds) }
        else { print("[cg-DisplayCreateImageForRect] NULL") }
    }
}

@available(macOS, deprecated: 14.0)
func cgStream() {
    let d = CGMainDisplayID()
    let w = CGDisplayPixelsWide(d) * 2, h = CGDisplayPixelsHigh(d) * 2
    var got: CGImage?
    let sem = DispatchSemaphore(value: 0)
    let q = DispatchQueue(label: "cgds")
    guard let s = CGDisplayStream(dispatchQueueDisplay: d, outputWidth: w, outputHeight: h, pixelFormat: Int32(kCVPixelFormatType_32BGRA), properties: nil, queue: q, handler: { status, _, surf, _ in
        guard status == .frameComplete, got == nil, let surf = surf else { return }
        let ci = CIImage(ioSurface: surf)
        got = CIContext().createCGImage(ci, from: ci.extent); sem.signal()
    }) else { print("[cg-DisplayStream] create returned NULL"); return }
    print("[cg-DisplayStream] start=\(s.start().rawValue)")
    _ = sem.wait(timeout: .now() + 5)
    if let h = ProcessInfo.processInfo.environment["HOLD"], let v = Double(h) { print("[cg-DisplayStream] holding \(v) s"); Thread.sleep(forTimeInterval: v) }
    _ = s.stop()
    if let img = got { analyzeDisplay(img, label: "cg-DisplayStream") } else { print("[cg-DisplayStream] no frame in 5 s") }
}

// MARK: - AVCaptureScreenInput

final class AVGrab: NSObject, AVCaptureVideoDataOutputSampleBufferDelegate {
    var image: CGImage?; var n = 0; let sem = DispatchSemaphore(value: 0)
    func captureOutput(_ o: AVCaptureOutput, didOutput sb: CMSampleBuffer, from c: AVCaptureConnection) {
        n += 1
        guard image == nil, n >= 5, let pb = sb.imageBuffer else { return }
        let ci = CIImage(cvPixelBuffer: pb)
        image = CIContext().createCGImage(ci, from: ci.extent); sem.signal()
    }
}

func avcap() {
    guard let input = AVCaptureScreenInput(displayID: CGMainDisplayID()) else { print("[avcap] AVCaptureScreenInput init returned nil"); return }
    let session = AVCaptureSession()
    let out = AVCaptureVideoDataOutput()
    let g = AVGrab()
    out.setSampleBufferDelegate(g, queue: DispatchQueue(label: "av"))
    guard session.canAddInput(input), session.canAddOutput(out) else { print("[avcap] cannot add input/output"); return }
    session.addInput(input); session.addOutput(out)
    session.startRunning()
    let r = g.sem.wait(timeout: .now() + 6)
    if let h = ProcessInfo.processInfo.environment["HOLD"], let v = Double(h) { print("[avcap] holding \(v) s"); Thread.sleep(forTimeInterval: v) }
    session.stopRunning()
    print("[avcap] frames=\(g.n) wait=\(r == .success ? "ok" : "timeout")")
    if let img = g.image { analyzeDisplay(img, label: "avcap-ScreenInput") }
}

// MARK: - private SkyLight SPI (what a determined attacker would try)

typealias MainConn = @convention(c) () -> Int32
typealias HWCapture = @convention(c) (Int32, UnsafeMutablePointer<UInt32>, Int32, UInt32) -> Unmanaged<CFArray>?
let RTLD_DEFAULT_ = UnsafeMutableRawPointer(bitPattern: -2)

func spi() {
    _ = dlopen("/System/Library/PrivateFrameworks/SkyLight.framework/SkyLight", RTLD_NOW)
    guard let c = dlsym(RTLD_DEFAULT_, "SLSMainConnectionID"), let h = dlsym(RTLD_DEFAULT_, "SLSHWCaptureWindowList") else {
        print("[spi] SkyLight symbols missing"); return
    }
    let cid = unsafeBitCast(c, to: MainConn.self)()
    let cap = unsafeBitCast(h, to: HWCapture.self)
    for w in spikeWindows() where w.title != "BACKDROP" {
        var id = w.id
        let arr = cap(cid, &id, 1, (1 << 11) | (1 << 8))?.takeRetainedValue()
        if let arr = arr, CFArrayGetCount(arr) > 0 {
            let img = unsafeBitCast(CFArrayGetValueAtIndex(arr, 0), to: CGImage.self)
            analyzeWindowImage(img, label: "spi-SLSHWCaptureWindowList-\(w.title)", title: w.title)
        } else { print("[spi-SLSHWCaptureWindowList-\(w.title)] no image (count \(arr.map { CFArrayGetCount($0) } ?? -1))") }
    }
}

// MARK: - system windows (to notice any dialog)

func sysWins() {
    let info = CGWindowListCopyWindowInfo([.optionOnScreenOnly], kCGNullWindowID) as? [[String: Any]] ?? []
    let spid = spikePID() ?? -2
    for d in info where (d[kCGWindowOwnerPID as String] as? Int32) != spid {
        let owner = d[kCGWindowOwnerName as String] as? String ?? ""
        let layer = d[kCGWindowLayer as String] as? Int ?? 0
        let r = CGRect(dictionaryRepresentation: d[kCGWindowBounds as String] as! CFDictionary) ?? .zero
        print("owner=\(owner) layer=\(layer) id=\(d[kCGWindowNumber as String] ?? 0) bounds=\(Int(r.minX)),\(Int(r.minY)),\(Int(r.width))x\(Int(r.height))")
    }
}

// MARK: - main

DispatchQueue.global().asyncAfter(deadline: .now() + 45) { print("WATCHDOG: 45 s timeout, exiting"); exit(3) }
let args = CommandLine.arguments
switch args.count > 1 ? args[1] : "" {
case "windows":
    for w in spikeWindows() { print("id=\(w.id) title=\(w.title) layer=\(w.layer) kCGWindowSharingState=\(w.sharing) onscreen=\(w.onscreen) bounds=\(w.bounds)") }
case "syswins": sysWins()
case "sck-list": _ = try? await sckList()
case "sck-shots": await sckShots()
case "sck-inc": await sckInc()
case "sck-stream": await sckStream()
case "sck-stream1":
    do {
        let all = try await SCShareableContent.excludingDesktopWindows(false, onScreenWindowsOnly: false)
        if let display = all.displays.first(where: { $0.displayID == CGMainDisplayID() }) {
            let cfg = SCStreamConfiguration()
            cfg.width = display.width * 2; cfg.height = display.height * 2; cfg.showsCursor = false
            if let img = try await oneFrame(SCContentFilter(display: display, excludingWindows: []), cfg) { analyzeDisplay(img, label: "sck-stream1-display") }
        }
    } catch { print("SCK error: \(error)") }
case "cg": cgTests()
case "cgstream": cgStream()
case "avcap": avcap()
case "spi": spi()
case "analyze-display":
    if let img = load(args[2]) { analyzeDisplay(img, label: args[3]) } else { print("cannot load \(args[2])") }
case "analyze-backdrop-rect":
    if let img = load(args[2]), let bd = spikeWindows().first(where: { $0.title == "BACKDROP" }) {
        analyzeArea(img, label: args[3], area: bd.bounds)
    } else { print("cannot load \(args[2]) or no BACKDROP") }
case "backdrop-rect":
    if let bd = spikeWindows().first(where: { $0.title == "BACKDROP" }) {
        print("\(Int(bd.bounds.minX)),\(Int(bd.bounds.minY)),\(Int(bd.bounds.width)),\(Int(bd.bounds.height))")
    }
case "ids":
    for w in spikeWindows() where w.title != "BACKDROP" { print("\(w.id) \(w.title)") }
case "analyze-window":
    if let img = load(args[2]) { analyzeWindowImage(img, label: args[3], title: args.count > 4 ? args[4] : "") } else { print("cannot load \(args[2])") }
case "frame":
    let asset = AVURLAsset(url: URL(fileURLWithPath: args[2]))
    let gen = AVAssetImageGenerator(asset: asset)
    gen.requestedTimeToleranceBefore = .zero; gen.requestedTimeToleranceAfter = .zero
    let dur = try await asset.load(.duration)
    print("movie duration \(String(format: "%.2f", CMTimeGetSeconds(dur))) s")
    let (img, actual) = try await gen.image(at: CMTime(seconds: Double(args[3]) ?? 1, preferredTimescale: 600))
    print("frame at \(String(format: "%.2f", CMTimeGetSeconds(actual))) s")
    analyzeDisplay(img, label: args[4])
default:
    print("usage: see header")
}
