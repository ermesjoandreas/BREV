// SpikeCapture (v2) — test app for the U1 capture spike. Bundle id no.brev.spike.capture.
//
// Small cluster in the top-right corner of the main display. Never activates, never takes
// key focus (accessory policy + orderFrontRegardless), quits itself after --ttl seconds.
//
//   BACKDROP  green   (0,160,0)    default sharing, level 3   what shows through an excluded window
//   EXCL      magenta (255,0,255)  .none,           level 4   "SPIKE-7f3a"
//   CTRL      cyan    (0,255,255)  default,         level 4   "CTRL-7f3a"  (positive control)
//   HOSTA     magenta               .none,           level 4   hosts SHA and CHILD
//     SHA     yellow  (255,255,0)  sheet, sharingType set to .none before beginSheet
//     CHILD   blue    (40,80,255)  borderless child window, default sharing
//   HOSTB     magenta               .none,           level 4   hosts SHB
//     SHB     orange  (255,128,0)  sheet, sharingType left at the default
//
// --variant protected adds two windows (no sheets) whose content is an
// AVSampleBufferDisplayLayer with preventsCapture = true:
//   PROT      purple  (128,0,255)  default sharing  "PROT-7f3a"
//   PROTX     purple               .none            "PROTX-7f3a"

import AppKit
import AVFoundation
import CoreMedia
import CoreVideo

func srgb(_ r: CGFloat, _ g: CGFloat, _ b: CGFloat) -> NSColor {
    NSColor(srgbRed: r / 255, green: g / 255, blue: b / 255, alpha: 1)
}

final class MarkerView: NSView {
    let color: NSColor, text: String, size: CGFloat
    init(color: NSColor, text: String, size: CGFloat) {
        self.color = color; self.text = text; self.size = size
        super.init(frame: .zero)
    }
    required init?(coder: NSCoder) { fatalError() }
    override var isOpaque: Bool { true }
    override func draw(_ dirtyRect: NSRect) {
        color.setFill(); bounds.fill()
        let s = NSAttributedString(string: text, attributes: [
            .font: NSFont.boldSystemFont(ofSize: size), .foregroundColor: NSColor.black])
        let sz = s.size()
        s.draw(at: NSPoint(x: (bounds.width - sz.width) / 2, y: (bounds.height - sz.height) / 2))
    }
}

/// Content drawn into an IOSurface-backed CVPixelBuffer and shown through an
/// AVSampleBufferDisplayLayer with preventsCapture = true (second-defence candidate).
final class ProtectedView: NSView {
    let layerRef = AVSampleBufferDisplayLayer()
    let color: NSColor, text: String, size: CGFloat
    init(color: NSColor, text: String, size: CGFloat) {
        self.color = color; self.text = text; self.size = size
        super.init(frame: .zero)
        wantsLayer = true
        layer = CALayer()
        layerRef.videoGravity = .resize
        layerRef.preventsCapture = !CommandLine.arguments.contains("nocp")
        layer!.addSublayer(layerRef)
    }
    required init?(coder: NSCoder) { fatalError() }
    override func layout() {
        super.layout()
        layerRef.frame = bounds
        enqueue()
    }
    func enqueue() {
        let scale = window?.backingScaleFactor ?? 2
        let w = Int(bounds.width * scale), h = Int(bounds.height * scale)
        guard w > 0, h > 0 else { return }
        var pb: CVPixelBuffer?
        let attrs: [CFString: Any] = [kCVPixelBufferIOSurfacePropertiesKey: [:] as CFDictionary,
                                      kCVPixelBufferCGBitmapContextCompatibilityKey: true]
        guard CVPixelBufferCreate(nil, w, h, kCVPixelFormatType_32BGRA, attrs as CFDictionary, &pb) == kCVReturnSuccess,
              let buf = pb else { print("protected: CVPixelBufferCreate failed"); return }
        CVPixelBufferLockBaseAddress(buf, [])
        let ctx = CGContext(data: CVPixelBufferGetBaseAddress(buf), width: w, height: h, bitsPerComponent: 8,
                            bytesPerRow: CVPixelBufferGetBytesPerRow(buf), space: CGColorSpace(name: CGColorSpace.sRGB)!,
                            bitmapInfo: CGImageAlphaInfo.premultipliedFirst.rawValue | CGBitmapInfo.byteOrder32Little.rawValue)!
        let g = NSGraphicsContext(cgContext: ctx, flipped: false)
        NSGraphicsContext.saveGraphicsState(); NSGraphicsContext.current = g
        color.setFill(); NSRect(x: 0, y: 0, width: w, height: h).fill()
        let s = NSAttributedString(string: text, attributes: [
            .font: NSFont.boldSystemFont(ofSize: size * scale), .foregroundColor: NSColor.black])
        let sz = s.size()
        s.draw(at: NSPoint(x: (CGFloat(w) - sz.width) / 2, y: (CGFloat(h) - sz.height) / 2))
        NSGraphicsContext.restoreGraphicsState()
        CVPixelBufferUnlockBaseAddress(buf, [])
        var fmt: CMVideoFormatDescription?
        CMVideoFormatDescriptionCreateForImageBuffer(allocator: nil, imageBuffer: buf, formatDescriptionOut: &fmt)
        var timing = CMSampleTimingInfo(duration: .invalid, presentationTimeStamp: .zero, decodeTimeStamp: .invalid)
        var sb: CMSampleBuffer?
        CMSampleBufferCreateReadyWithImageBuffer(allocator: nil, imageBuffer: buf, formatDescription: fmt!,
                                                 sampleTiming: &timing, sampleBufferOut: &sb)
        if let sb = sb,
           let att = CMSampleBufferGetSampleAttachmentsArray(sb, createIfNecessary: true) as? [NSMutableDictionary] {
            att.first?[kCMSampleAttachmentKey_DisplayImmediately] = true
            layerRef.sampleBufferRenderer.flush()
            layerRef.sampleBufferRenderer.enqueue(sb)
        }
        print("protected: enqueued \(w)x\(h) preventsCapture=\(layerRef.preventsCapture) status=\(layerRef.sampleBufferRenderer.status.rawValue)")
        fflush(stdout)
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    var all: [NSWindow] = []
    var flatLevel = false
    var dy: CGFloat = 0   // WP11 re-run: --dy <pt> moves the cluster (clear of on-screen system dialogs)

    func make(_ title: String, _ r: NSRect, _ view: NSView, level: Int, excluded: Bool,
              style: NSWindow.StyleMask = [.titled]) -> NSWindow {
        let w = NSWindow(contentRect: r.offsetBy(dx: 0, dy: dy), styleMask: style, backing: .buffered, defer: false)
        w.title = title
        w.isReleasedWhenClosed = false
        w.isRestorable = false
        w.level = NSWindow.Level(rawValue: flatLevel ? 0 : level)
        if excluded { w.sharingType = .none }
        w.contentView = view
        w.orderFrontRegardless()
        all.append(w)
        return w
    }

    func applicationDidFinishLaunching(_ n: Notification) {
        let a = CommandLine.arguments
        var ttl = 90.0
        if let i = a.firstIndex(of: "--ttl"), i + 1 < a.count, let v = Double(a[i + 1]) { ttl = v }
        if let i = a.firstIndex(of: "--dy"), i + 1 < a.count, let v = Double(a[i + 1]) { dy = CGFloat(v) }
        DispatchQueue.main.asyncAfter(deadline: .now() + ttl) { print("ttl reached"); NSApp.terminate(nil) }
        let protected = a.contains("protected")
        flatLevel = a.contains("level0")   // every window at the normal level, like Brev

        let magenta = srgb(255, 0, 255), cyan = srgb(0, 255, 255), green = srgb(0, 160, 0)
        let yellow = srgb(255, 255, 0), orange = srgb(255, 128, 0), blue = srgb(40, 80, 255)
        let purple = srgb(128, 0, 255)

        // AppKit coordinates, main display 1512 x 982 (visible y 44...949).
        _ = make("BACKDROP", NSRect(x: 842, y: 610, width: 650, height: 300),
                 MarkerView(color: green, text: "", size: 12), level: 3, excluded: false)
        _ = make("EXCL", NSRect(x: 857, y: 770, width: 300, height: 70),
                 MarkerView(color: magenta, text: "SPIKE-7f3a", size: 40), level: 4, excluded: true)
        if a.contains("flags"), let ex = all.first(where: { $0.title == "EXCL" }) {
            ex.collectionBehavior = [.transient, .ignoresCycle, .stationary, .fullScreenAuxiliary, .canJoinAllSpaces]
            ex.level = .statusBar
            ex.hasShadow = false
            ex.isExcludedFromWindowsMenu = true
            ex.displaysWhenScreenProfileChanges = false
            print("flags: EXCL collectionBehavior=\(ex.collectionBehavior.rawValue) level=\(ex.level.rawValue)")
        }
        if a.contains("watch") { startWatcher() }
        _ = make("CTRL", NSRect(x: 1177, y: 770, width: 300, height: 70),
                 MarkerView(color: cyan, text: "CTRL-7f3a", size: 40), level: 4, excluded: false)
        if protected {
            _ = make("PROT", NSRect(x: 857, y: 625, width: 300, height: 110),
                     ProtectedView(color: purple, text: "PROT-7f3a", size: 36), level: 4, excluded: false)
            _ = make("PROTX", NSRect(x: 1177, y: 625, width: 300, height: 110),
                     ProtectedView(color: purple, text: "PROTX-7f3a", size: 36), level: 4, excluded: true)
        } else {
            let hostA = make("HOSTA", NSRect(x: 857, y: 625, width: 300, height: 110),
                             MarkerView(color: magenta, text: "", size: 12), level: 4, excluded: true)
            let hostB = make("HOSTB", NSRect(x: 1177, y: 625, width: 300, height: 110),
                             MarkerView(color: magenta, text: "", size: 12), level: 4, excluded: true)

            let sha = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 260, height: 56), styleMask: [.titled],
                               backing: .buffered, defer: false)
            sha.title = "SHA"; sha.isReleasedWhenClosed = false
            sha.contentView = MarkerView(color: yellow, text: "SHA-7f3a", size: 30)
            sha.sharingType = .none
            hostA.beginSheet(sha) { _ in }
            all.append(sha)

            let shb = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 260, height: 56), styleMask: [.titled],
                               backing: .buffered, defer: false)
            shb.title = "SHB"; shb.isReleasedWhenClosed = false
            shb.contentView = MarkerView(color: orange, text: "SHB-7f3a", size: 30)
            hostB.beginSheet(shb) { _ in }
            all.append(shb)

            let child = NSWindow(contentRect: NSRect(x: 907, y: 632 + dy, width: 200, height: 28), styleMask: [.borderless],
                                 backing: .buffered, defer: false)
            child.title = "CHILD"; child.isReleasedWhenClosed = false
            child.contentView = MarkerView(color: blue, text: "CHILD", size: 18)
            hostA.addChildWindow(child, ordered: .above)
            all.append(child)
        }

        DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
            for w in self.all {
                print("window title=\(w.title) number=\(w.windowNumber) sharingType=\(w.sharingType.rawValue) level=\(w.level.rawValue) visible=\(w.isVisible) frame=\(w.frame)")
            }
            print("ready pid=\(getpid()) active=\(NSApp.isActive)")
            fflush(stdout)
        }
    }
}

// Watcher: what a sandboxed app can observe while another process captures the screen.
// Logs changes in (a) on-screen windows at layer >= 20 not owned by this app, (b) the
// CGSessionCopyCurrentDictionary keys, with monotonic milliseconds.
var lastSet = Set<String>()
var lastSession = ""
let t0 = DispatchTime.now().uptimeNanoseconds
let wall: DateFormatter = { let f = DateFormatter(); f.dateFormat = "HH:mm:ss.SSS"; return f }()
func ms() -> String { "\(Int((DispatchTime.now().uptimeNanoseconds - t0) / 1_000_000)) [\(wall.string(from: Date()))]" }
func startWatcher() {
    let me = getpid()
    let t = Timer(timeInterval: 0.05, repeats: true) { _ in
        let info = CGWindowListCopyWindowInfo([.optionOnScreenOnly], kCGNullWindowID) as? [[String: Any]] ?? []
        var set = Set<String>()
        for d in info where (d[kCGWindowOwnerPID as String] as? Int32) != me {
            let layer = d[kCGWindowLayer as String] as? Int ?? 0
            guard layer >= 20 else { continue }
            let r = CGRect(dictionaryRepresentation: d[kCGWindowBounds as String] as! CFDictionary) ?? .zero
            set.insert("owner=\(d[kCGWindowOwnerName as String] as? String ?? "?") layer=\(layer) id=\(d[kCGWindowNumber as String] ?? 0) bounds=\(Int(r.minX)),\(Int(r.minY)),\(Int(r.width))x\(Int(r.height))")
        }
        for x in set.subtracting(lastSet).sorted() { print("watch t=\(ms()) + \(x)") }
        for x in lastSet.subtracting(set).sorted() { print("watch t=\(ms()) - \(x)") }
        lastSet = set
        let sd = (CGSessionCopyCurrentDictionary() as? [String: Any] ?? [:]).map { "\($0.key)=\($0.value)" }.sorted().joined(separator: " ")
        if sd != lastSession { print("watch t=\(ms()) session: \(sd)"); lastSession = sd }
        fflush(stdout)
    }
    RunLoop.main.add(t, forMode: .common)
    print("watch t=0 started (sandboxed=\(ProcessInfo.processInfo.environment["APP_SANDBOX_CONTAINER_ID"] != nil))")
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
