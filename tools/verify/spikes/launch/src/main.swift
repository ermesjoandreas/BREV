// LaunchSpike: launch hygiene (L) and malloc scribbling (M) in a sandboxed,
// hardened, ad-hoc-signed app. Output lines start with "SPIKE " and go to
// stdout (open --stdout) and os_log (public, notice). They never contain the
// typed marker: key events are reported by length and source PID only.
//
// SPIKE_MODE (environment, comma-separated):
//   guard        removeVolatileDomain + setVolatileDomain([:]) on the argument domain (Brev's LaunchGuard)
//   rmonly       removeVolatileDomain only
//   override     argument domain := every candidate debug key set to false/0
//   reexec       if not yet re-executed: execve own binary with cleaned env + MallocScribble=1
//   reexec0      if not yet re-executed: execve own binary with MallocScribble removed (control)
//   noapp        no NSApplication: report, scribble test, exit
//   setdefault   write NSTraceEvents=YES into this app's own defaults domain, then exit
//   cleardefault remove it again, then exit
//   draw         draw text with Core Text in the window (scribbling + AppKit flow)
// SPIKE_SECS: seconds to stay up after launch (default 6).

import AppKit
import CoreText
import os

let spikeLog = Logger(subsystem: "no.brev.spike.launch", category: "spike")
setvbuf(stdout, nil, _IOLBF, 0)
func out(_ s: String) {
    print("SPIKE " + s)
    fflush(stdout)
    spikeLog.notice("SPIKE \(s, privacy: .public)")
}

let env0 = ProcessInfo.processInfo.environment
let mode = Set((env0["SPIKE_MODE"] ?? "").split(separator: ",").map(String.init))
let reexeced = env0["SPIKE_REEXECED"] != nil
let debugPrefixes = ["NSZombie", "CFZombie", "NSDebug", "NSTrace", "NSDeallocateZombies",
                     "NSObjCMessageLogging", "OBJC_", "MallocStackLogging", "CFLOG", "OS_ACTIVITY_DT_MODE"]

// MARK: - Reports

func csReport(_ tag: String) {
    var flags: UInt32 = 0
    let rc = spike_cs_status(&flags)
    let runtime = flags & 0x10000 != 0, gta = flags & 0x4 != 0, valid = flags & 0x1 != 0, kill = flags & 0x200 != 0,
        hard = flags & 0x100 != 0, restrict = flags & 0x800 != 0
    out("\(tag) csops rc=\(rc) flags=0x\(String(flags, radix: 16)) valid=\(valid) runtime=\(runtime) hard=\(hard) kill=\(kill) restrict=\(restrict) get-task-allow=\(gta)")
    let probe = env0["SPIKE_PROBE"] ?? ""
    let openErr = probe.isEmpty ? -1 : spike_try_open(probe)
    out("\(tag) sandbox_check=\(spike_sandboxed()) APP_SANDBOX_CONTAINER_ID=\(env0["APP_SANDBOX_CONTAINER_ID"] ?? "<unset>") home=\(NSHomeDirectory()) open(scratch probe) errno=\(openErr)")
    let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].path
    out("\(tag) appsupport=\(support) CFFIXED_USER_HOME=\(ProcessInfo.processInfo.environment["CFFIXED_USER_HOME"] ?? "<unset>")")
}

func envReport(_ tag: String) {
    let e = ProcessInfo.processInfo.environment
    let g = getenv("MallocScribble").map { String(cString: $0) } ?? "<unset>"
    out("\(tag) env MallocScribble=\(e["MallocScribble"] ?? "<unset>") getenv=\(g) count=\(e.count)")
    out("\(tag) env names=\(e.keys.sorted().joined(separator: ","))")
    let interesting = e.keys.filter { k in
        k.hasPrefix("Malloc") || k.hasPrefix("SPIKE") || k.hasPrefix("__CF") || k == "XPC_SERVICE_NAME"
            || debugPrefixes.contains { k.hasPrefix($0) } || candidateKeys.contains(k) || k.hasPrefix("DYLD")
    }.sorted()
    for k in interesting { out("\(tag) env \(k)=\(e[k] ?? "")") }
}

func defaultsReport(_ tag: String) {
    let d = UserDefaults.standard
    let arg = d.volatileDomain(forName: UserDefaults.argumentDomain)
    out("\(tag) argdomain count=\(arg.count) keys=\(arg.keys.sorted().prefix(12).joined(separator: ","))")
    var on: [String] = []
    for k in candidateKeys where d.object(forKey: k) != nil {
        on.append("\(k)=\(d.object(forKey: k)!)")
    }
    out("\(tag) defaults set: \(on.isEmpty ? "none" : on.joined(separator: " "))")
    let cf = CFPreferencesCopyAppValue("NSTraceEvents" as CFString, kCFPreferencesCurrentApplication)
    let cfb = CFPreferencesGetAppBooleanValue("NSTraceEvents" as CFString, kCFPreferencesCurrentApplication, nil)
    out("\(tag) CFPreferences NSTraceEvents value=\(cf.map { "\($0)" } ?? "nil") bool=\(cfb)")
    let app = d.persistentDomain(forName: "no.brev.spike.launch") ?? [:]
    out("\(tag) persistent app domain keys=\(app.keys.sorted().joined(separator: ","))")
    out("\(tag) global domain visible (AppleLocale or AppleLanguages)=\(d.object(forKey: "AppleLocale") != nil || d.object(forKey: "AppleLanguages") != nil)")
}

// MARK: - Scribble test

func scribbleTest(_ tag: String) {
    var r = brev_scan_result()
    brev_scan(&r)
    let base = r.utf8_hits
    let sizes = [32, 128, 256, 1024, 4096, 32768, 262144]
    var blocks: [(UnsafeMutableRawPointer, Int)] = []
    for s in sizes {
        let p = malloc(s)!
        spike_fill_marker(p, s)
        blocks.append((p, s))
    }
    brev_scan(&r)
    let live = r.utf8_hits
    let expected = sizes.reduce(0) { $0 + $1 / 16 }
    for (p, _) in blocks { free(p) }
    brev_scan(&r)
    let after = r.utf8_hits
    out("\(tag) scribble scan base=\(base) live=\(live) (expect base+\(expected)) afterfree=\(after) regions=\(r.regions) MB=\(r.bytes >> 20)")
    for (p, s) in blocks {
        var n55: UInt64 = 0, nz: UInt64 = 0, nm: UInt64 = 0
        let n = spike_probe(p, min(s, 65536), &n55, &nz, &nm)
        out("\(tag) freed block size=\(s) read=\(n) byte55=\(n55) zero=\(nz) markerbytes=\(nm)")
    }
}

/// A framework-owned copy: a CFString holding the marker four times, then released.
func cfReleaseTest(_ tag: String) {
    var r = brev_scan_result()
    func makeAndDrop() {
        let tmp = malloc(64)!
        spike_fill_marker(tmp, 64)
        let s = CFStringCreateWithBytes(nil, tmp.assumingMemoryBound(to: UInt8.self), 64,
                                        CFStringBuiltInEncodings.UTF8.rawValue, false)
        memset_s(tmp, 64, 0, 64); free(tmp)
        brev_scan(&r)
        out("\(tag) cfstring(64B) live u8=\(r.utf8_hits) (expect 4)")
        withExtendedLifetime(s) {}
    }
    makeAndDrop()
    brev_scan(&r)
    out("\(tag) cfstring(64B) after release u8=\(r.utf8_hits)")
}

// MARK: - Early phase (before AppKit)

out("start pid=\(getpid()) ppid=\(getppid()) reexeced=\(reexeced) mode=\(mode.sorted().joined(separator: ","))")
out("argv count=\(CommandLine.arguments.count) argv0=\(CommandLine.arguments.first ?? "") rest=[\(CommandLine.arguments.dropFirst().joined(separator: " "))]")
out("psn arg present=\(CommandLine.arguments.contains { $0.hasPrefix("-psn_") })")
envReport("early")
csReport("early")
defaultsReport("early")

if mode.contains("setdefault") {
    UserDefaults.standard.set(true, forKey: "NSTraceEvents")
    out("setdefault synchronize=\(UserDefaults.standard.synchronize())")
    defaultsReport("setdefault")
    exit(0)
}
if mode.contains("cleardefault") {
    UserDefaults.standard.removeObject(forKey: "NSTraceEvents")
    out("cleardefault synchronize=\(UserDefaults.standard.synchronize())")
    defaultsReport("cleardefault")
    exit(0)
}

if mode.contains("rmonly") {
    UserDefaults.standard.removeVolatileDomain(forName: UserDefaults.argumentDomain)
    defaultsReport("after-rmonly")
}
if mode.contains("guard") {
    UserDefaults.standard.removeVolatileDomain(forName: UserDefaults.argumentDomain)
    UserDefaults.standard.setVolatileDomain([:], forName: UserDefaults.argumentDomain)
    defaultsReport("after-guard")
}
if mode.contains("override") {
    var dom: [String: Any] = [:]
    for k in candidateKeys { dom[k] = k.hasSuffix("LogLevel") ? 0 : false }
    UserDefaults.standard.removeVolatileDomain(forName: UserDefaults.argumentDomain)
    UserDefaults.standard.setVolatileDomain(dom, forName: UserDefaults.argumentDomain)
    defaultsReport("after-override")
}

if (mode.contains("reexec") || mode.contains("reexec0")) && !reexeced {
    var e = ProcessInfo.processInfo.environment.filter { k, _ in !debugPrefixes.contains { k.hasPrefix($0) } && !candidateKeys.contains(k) }
    if mode.contains("reexec0") { e["MallocScribble"] = nil } else { e["MallocScribble"] = "1" }
    e["SPIKE_REEXECED"] = "1"
    let path = Bundle.main.executablePath ?? CommandLine.arguments[0]
    out("reexec: execve \(path) argc=\(CommandLine.arguments.count) envc=\(e.count) MallocScribble=\(e["MallocScribble"] ?? "<unset>")")
    let argv: [UnsafeMutablePointer<CChar>?] = [strdup(path)] + CommandLine.arguments.dropFirst().map { strdup($0) } + [nil]
    let envp: [UnsafeMutablePointer<CChar>?] = e.map { strdup("\($0.key)=\($0.value)") } + [nil]
    let err = spike_execve(path, argv, envp)
    out("reexec: execve FAILED errno=\(err) (\(String(cString: strerror(err))))")
}

scribbleTest("early")
cfReleaseTest("early")

if mode.contains("noapp") {
    out("done noapp")
    exit(0)
}

// MARK: - AppKit phase

@objc(SpikeApplication)
final class SpikeApplication: NSApplication {
    override func sendEvent(_ event: NSEvent) {
        if event.type == .keyDown || event.type == .keyUp {
            let pid = event.cgEvent?.getIntegerValueField(.eventSourceUnixProcessID) ?? -1
            let units = event.characters?.utf16.count ?? -1
            out("event \(event.type == .keyDown ? "keyDown" : "keyUp") units=\(units) srcpid=\(pid) keyWindow=\(keyWindow != nil) active=\(isActive)")
        }
        super.sendEvent(event)
    }
}

final class KeyView: NSView {
    var keyDowns = 0
    override var acceptsFirstResponder: Bool { true }
    override func keyDown(with event: NSEvent) { keyDowns += 1; out("view keyDown n=\(keyDowns)") }
    override func keyUp(with event: NSEvent) {}
    override func draw(_ dirtyRect: NSRect) {
        NSColor.windowBackgroundColor.setFill()
        dirtyRect.fill()
        guard mode.contains("draw"), let ctx = NSGraphicsContext.current?.cgContext else { return }
        // Filler text (not the marker) through CTLine, as Brev draws.
        let s = "spike æøå ÆØÅ 1234" as CFString
        let font = CTFontCreateWithName("Helvetica" as CFString, 12, nil)
        let attr = CFAttributedStringCreate(nil, s, [kCTFontAttributeName: font] as CFDictionary)!
        let line = CTLineCreateWithAttributedString(attr)
        ctx.textPosition = CGPoint(x: 6, y: 12)
        CTLineDraw(line, ctx)
    }
}

final class Delegate: NSObject, NSApplicationDelegate {
    var window: NSWindow?
    func applicationDidFinishLaunching(_ n: Notification) {
        let w = NSWindow(contentRect: NSRect(x: 30, y: 30, width: 150, height: 36),
                         styleMask: [.titled], backing: .buffered, defer: false)
        w.title = "spike"
        w.isRestorable = false
        let v = KeyView(frame: w.contentLayoutRect)
        w.contentView = v
        w.makeFirstResponder(v)
        w.orderFrontRegardless()
        w.makeKey()
        window = w
        defaultsReport("launched")
        envReport("launched")
        csReport("launched")
        scribbleTest("launched")
        let secs = Double(env0["SPIKE_SECS"] ?? "6") ?? 6
        out("ready pid=\(getpid()) secs=\(secs) keyWindow=\(NSApp.keyWindow != nil) active=\(NSApp.isActive)")
        let t = Timer(timeInterval: secs, repeats: false) { _ in
            scribbleTest("final")
            out("terminating")
            NSApp.terminate(nil)
        }
        RunLoop.main.add(t, forMode: .common)
    }
    func applicationWillTerminate(_ n: Notification) { out("willTerminate") }
}

let app = SpikeApplication.shared
let delegate = Delegate()
app.delegate = delegate
_ = app.setActivationPolicy(.regular)
out("NSApp class=\(type(of: NSApp!)) running")
app.run()
