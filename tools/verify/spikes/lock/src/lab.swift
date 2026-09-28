// LockLab — spike for Brev Phase 2 U4 (auto-lock triggers), macOS 26.2.
// One binary, two bundles:
//   LockLab.app   (no.brev.spike.lock)       the probe: logs every lock-related signal
//   LockOther.app (no.brev.spike.lockother)  a second small app to switch to (⌘-Tab stand-in)
// Modes (LockLab only): --mode auto | human | touchid ; --ttl <s> ; --quit-after-wake
// Logs to stdout (the scripts redirect it with `open --stdout`) and to a file in the container.
// It never reads NSEvent.characters; key codes are logged only for ⌘/⌃ chords and synthetic events.
// Touch ID is used only in --mode touchid, and only after a human (PID 0) click on the button.
import AppKit
import CryptoKit
import LocalAuthentication
import LocalAuthenticationEmbeddedUI   // spike only: LAAuthenticationView (not in CLAUDE.md §4)
import Security

setvbuf(stdout, nil, _IOLBF, 0)

let T0 = clock_gettime_nsec_np(CLOCK_MONOTONIC)     // counts during sleep (man clock_gettime)
let U0 = clock_gettime_nsec_np(CLOCK_UPTIME_RAW)    // stops during sleep
func monoMs() -> Double { Double(clock_gettime_nsec_np(CLOCK_MONOTONIC) &- T0) / 1e6 }
func upMs() -> Double { Double(clock_gettime_nsec_np(CLOCK_UPTIME_RAW) &- U0) / 1e6 }
let wallFmt: DateFormatter = {
    let f = DateFormatter(); f.locale = Locale(identifier: "en_US_POSIX"); f.dateFormat = "HH:mm:ss.SSS"; return f
}()

var fileLog: FileHandle?
func log(_ s: String) {
    let line = String(format: "t=%.1f up=%.1f ", monoMs(), upMs()) + "wall=" + wallFmt.string(from: Date()) + " " + s
    print(line)
    if let h = fileLog, let d = (line + "\n").data(using: .utf8) { h.write(d) }
}

let argv = CommandLine.arguments
func argValue(_ k: String) -> String? {
    if let i = argv.firstIndex(of: k), i + 1 < argv.count { return argv[i + 1] }
    return nil
}
let BUNDLE = Bundle.main.bundleIdentifier ?? "unknown"
let IS_OTHER = BUNDLE == "no.brev.spike.lockother"
let MODE = IS_OTHER ? "other" : (argValue("--mode") ?? "auto")
let TTL = Double(argValue("--ttl") ?? "90") ?? 90
let QUIT_AFTER_WAKE = argv.contains("--quit-after-wake")
let DRY = argv.contains("--dry")   // touchid mode without any LAContext prompt (for the automated gate test)
let CMD_PREFIX = BUNDLE + ".cmd."
let PROBE = "no.brev.spike.lock.probe"
let APPLE_PROBE = "com.apple.brevspike.lockprobe"   // a com.apple.* name nobody else listens to
let SYS_DIST = ["com.apple.screenIsLocked", "com.apple.screenIsUnlocked",
                "com.apple.screensaver.didstart", "com.apple.screensaver.willstop", "com.apple.screensaver.didstop"]

func errStr(_ e: Error) -> String {
    let ns = e as NSError
    var s = "swift=\(String(reflecting: e)) domain=\(ns.domain) code=\(ns.code)"
    if let u = ns.userInfo[NSUnderlyingErrorKey] as? NSError { s += " underlying=(domain=\(u.domain) code=\(u.code))" }
    return s
}

// MARK: - Principal class: sees every event before AppKit dispatches it

@objc(LabApp) final class LabApp: NSApplication {
    override func sendEvent(_ event: NSEvent) {
        Lab.shared?.noteEvent(event)
        super.sendEvent(event)
    }
}

final class SinkView: NSView {   // takes key focus and swallows keys, so a posted key never beeps
    override var acceptsFirstResponder: Bool { true }
    override func keyDown(with event: NSEvent) {}
    override func keyUp(with event: NSEvent) {}
}

final class Lab: NSObject {
    static var shared: Lab?
    var window: NSWindow!
    var status: NSTextField!
    var unlockButton: NSButton?
    var tokens: [NSObjectProtocol] = []
    var lastInputMono: Double = 0
    var prevIdleC: Double = -1
    var prevLocked = "", prevActive: Bool?, prevKey: Bool?
    var authInFlight = false
    var attempt = 0
    var wakeQuit: Timer?
    let unlockQueue = DispatchQueue(label: "no.brev.spike.lock.unlock")

    // MARK: setup
    func start() {
        Lab.shared = self
        openFileLog()
        buildMenu()
        buildWindow()
        observe()
        let poll = Timer(timeInterval: 1.0, repeats: true) { [weak self] _ in self?.tick() }
        RunLoop.main.add(poll, forMode: .common)
        let ttl = Timer(timeInterval: TTL, repeats: false) { _ in log("TTL reached \(TTL)s"); NSApp.terminate(nil) }
        RunLoop.main.add(ttl, forMode: .common)
        log("ready pid=\(getpid()) bundle=\(BUNDLE) mode=\(MODE) ttl=\(TTL) sandbox=\(ProcessInfo.processInfo.environment["APP_SANDBOX_CONTAINER_ID"] ?? "none") home=\(NSHomeDirectory()) filelog=\(fileLog != nil)")
        tick()
    }

    func openFileLog() {
        let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("LockLab")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let f = dir.appendingPathComponent("locklab.log")
        if !FileManager.default.fileExists(atPath: f.path) { FileManager.default.createFile(atPath: f.path, contents: nil) }
        fileLog = try? FileHandle(forWritingTo: f)
        _ = try? fileLog?.seekToEnd()
        print("filelog path=\(f.path)")
    }

    func buildMenu() {
        let main = NSMenu()
        let appItem = NSMenuItem(); main.addItem(appItem)
        let m = NSMenu(title: IS_OTHER ? "LockOther" : "LockLab")
        m.addItem(withTitle: "Skjul", action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        m.addItem(withTitle: "Avslutt", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        appItem.submenu = m
        NSApp.mainMenu = main
    }

    func buildWindow() {
        let w: CGFloat = 340, h: CGFloat = MODE == "touchid" ? 160 : 110
        let vf = NSScreen.main?.visibleFrame ?? NSRect(x: 0, y: 0, width: 1440, height: 900)
        let y = IS_OTHER ? vf.maxY - 2 * h - 40 : vf.maxY - h - 10
        window = NSWindow(contentRect: NSRect(x: vf.maxX - w - 10, y: y, width: w, height: h),
                          styleMask: [.titled, .closable], backing: .buffered, defer: false)
        window.title = IS_OTHER ? "LockOther" : "LockLab"
        window.isReleasedWhenClosed = false
        window.isRestorable = false
        let v = SinkView(frame: NSRect(x: 0, y: 0, width: w, height: h))
        window.contentView = v
        status = NSTextField(wrappingLabelWithString: IS_OTHER ? "LockOther (test-app). Lukker seg selv." : "LockLab")
        status.frame = NSRect(x: 12, y: MODE == "touchid" ? 90 : 10, width: w - 24 - (MODE == "touchid" ? 60 : 0), height: MODE == "touchid" ? 60 : h - 20)
        status.font = NSFont.systemFont(ofSize: 11)
        v.addSubview(status)
        if MODE == "touchid" {
            let b = NSButton(title: "Lås opp (test)", target: self, action: #selector(unlockClicked(_:)))
            b.frame = NSRect(x: 12, y: 12, width: 140, height: 30)
            v.addSubview(b)
            unlockButton = b
            let e = NSButton(title: "Innebygd (test)", target: self, action: #selector(embeddedClicked(_:)))
            e.frame = NSRect(x: 12, y: 50, width: 140, height: 30)
            v.addSubview(e)
            let f = NSButton(title: "Ferdig", target: self, action: #selector(doneClicked(_:)))
            f.frame = NSRect(x: 168, y: 12, width: 100, height: 30)
            v.addSubview(f)
        }
        window.makeKeyAndOrderFront(nil)
        window.makeFirstResponder(v)
        if let b = unlockButton, let screenH = NSScreen.screens.first?.frame.height {
            let r = window.convertToScreen(b.convert(b.bounds, to: nil))
            log(String(format: "BUTTON-CG x=%.0f y=%.0f win=%ld", r.midX, screenH - r.midY, window.windowNumber))   // CG global coords (top-left origin)
        }
    }

    // MARK: observers
    func observe() {
        let nc = NotificationCenter.default
        let appNames: [Notification.Name] = [
            NSApplication.willBecomeActiveNotification, NSApplication.didBecomeActiveNotification,
            NSApplication.willResignActiveNotification, NSApplication.didResignActiveNotification,
            NSApplication.willHideNotification, NSApplication.didHideNotification, NSApplication.didUnhideNotification,
            NSApplication.didChangeOcclusionStateNotification, NSApplication.willTerminateNotification]
        for n in appNames {
            tokens.append(nc.addObserver(forName: n, object: nil, queue: .main) { [weak self] _ in
                guard let self else { return }
                log("APP \(n.rawValue) isActive=\(NSApp.isActive) key=\(self.window.isKeyWindow) authInFlight=\(self.authInFlight)")
            })
        }
        let winNames: [Notification.Name] = [
            NSWindow.didBecomeKeyNotification, NSWindow.didResignKeyNotification,
            NSWindow.didBecomeMainNotification, NSWindow.didResignMainNotification, NSWindow.didChangeOcclusionStateNotification]
        for n in winNames {
            tokens.append(nc.addObserver(forName: n, object: window, queue: .main) { [weak self] _ in
                guard let self else { return }
                log("WIN \(n.rawValue) visible=\(self.window.occlusionState.contains(.visible)) authInFlight=\(self.authInFlight)")
            })
        }
        let ws = NSWorkspace.shared.notificationCenter
        let wsNames: [Notification.Name] = [
            NSWorkspace.willSleepNotification, NSWorkspace.didWakeNotification,
            NSWorkspace.screensDidSleepNotification, NSWorkspace.screensDidWakeNotification,
            NSWorkspace.sessionDidBecomeActiveNotification, NSWorkspace.sessionDidResignActiveNotification,
            NSWorkspace.willPowerOffNotification]
        for n in wsNames {
            tokens.append(ws.addObserver(forName: n, object: nil, queue: .main) { [weak self] _ in
                log("WS \(n.rawValue) isActive=\(NSApp.isActive)")
                if [NSWorkspace.didWakeNotification, NSWorkspace.screensDidWakeNotification,
                    NSWorkspace.sessionDidBecomeActiveNotification].contains(n) { self?.wakeSignal(n.rawValue) }
            })
        }
        for n in [NSWorkspace.didActivateApplicationNotification, NSWorkspace.didDeactivateApplicationNotification] {
            tokens.append(ws.addObserver(forName: n, object: nil, queue: .main) { note in
                let app = note.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication
                log("WSAPP \(n.rawValue) app=\(app?.bundleIdentifier ?? "nil") pid=\(app?.processIdentifier ?? -1)")
            })
        }
        // Distributed notifications, each name twice:
        //   [block]     addObserver(forName:object:queue:using:) — default suspension behaviour (what the design sketch used)
        //   [immediate] addObserver(_:selector:name:object:suspensionBehavior: .deliverImmediately)
        let dnc = DistributedNotificationCenter.default()
        for n in SYS_DIST + [PROBE, APPLE_PROBE] {
            tokens.append(dnc.addObserver(forName: Notification.Name(n), object: nil, queue: .main) { [weak self] note in
                log("DIST[block] \(n) userInfo=\(note.userInfo?.count ?? -1) suspended=\(dnc.suspended) isActive=\(NSApp.isActive)")
                if n == "com.apple.screenIsUnlocked" { self?.wakeSignal(n) }
            })
            dnc.addObserver(self, selector: #selector(distImmediate(_:)), name: Notification.Name(n), object: nil,
                            suspensionBehavior: .deliverImmediately)
        }
        for c in ["quit", "hide", "unhide", "activate", "activate14", "menutest", "sessdict", "dump", "gatecheck", "dryunlock"] {
            dnc.addObserver(self, selector: #selector(command(_:)), name: Notification.Name(CMD_PREFIX + c), object: nil,
                            suspensionBehavior: .deliverImmediately)
        }
    }

    @objc func distImmediate(_ note: Notification) {
        let dnc = DistributedNotificationCenter.default()
        log("DIST[immediate] \(note.name.rawValue) userInfo=\(note.userInfo?.count ?? -1) suspended=\(dnc.suspended) isActive=\(NSApp.isActive)")
        if note.name.rawValue == "com.apple.screenIsUnlocked" { wakeSignal(note.name.rawValue) }
    }

    func wakeSignal(_ why: String) {
        guard QUIT_AFTER_WAKE else { return }
        let d = CGSessionCopyCurrentDictionary() as? [String: Any]
        if let v = d?["CGSSessionScreenIsLocked"], "\(v)" == "1" { log("WAKE-SIGNAL \(why) ignored: screen still locked"); return }
        wakeQuit?.invalidate()
        log("WAKE-SIGNAL \(why): quitting in 8 s unless another signal arrives")
        let t = Timer(timeInterval: 8, repeats: false) { _ in log("quit after wake/unlock"); NSApp.terminate(nil) }
        RunLoop.main.add(t, forMode: .common)
        wakeQuit = t
    }

    // MARK: commands (from bin/ctl, an unsandboxed CLI)
    @objc func command(_ note: Notification) {
        let c = String(note.name.rawValue.dropFirst(CMD_PREFIX.count))
        log("CMD \(c) isActive=\(NSApp.isActive)")
        switch c {
        case "quit": NSApp.terminate(nil)
        case "hide": NSApp.hide(nil)
        case "unhide": NSApp.unhide(nil)
        case "activate":
            NSApp.activate(ignoringOtherApps: true)
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.7) { log("CMD activate +0.7s isActive=\(NSApp.isActive)") }
        case "activate14":
            NSApp.activate()
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.7) { log("CMD activate14 +0.7s isActive=\(NSApp.isActive)") }
        case "menutest": menuTest()
        case "gatecheck": unlockClicked(nil)            // not a click: the gate must refuse
        case "dryunlock": if DRY && MODE == "touchid" { runUnlock() } else { log("dryunlock refused: not DRY") }
        case "sessdict":
            if let d = CGSessionCopyCurrentDictionary() as? [String: Any] {
                log("SESSDICT keys=\(d.keys.sorted().joined(separator: ","))")
            } else { log("SESSDICT nil") }
        case "dump":
            let p = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
                .appendingPathComponent("LockLab/locklab.log").path
            let attrs = try? FileManager.default.attributesOfItem(atPath: p)
            log("DUMP filelog=\(p) bytes=\((attrs?[.size] as? Int) ?? -1)")
        default: break
        }
    }

    /// V25/§8.3: timers in .common mode keep firing while a menu is tracked; .default ones do not.
    func menuTest() {
        var common = 0, deflt = 0, ticksBefore = 0
        let tc = Timer(timeInterval: 0.25, repeats: true) { _ in common += 1 }
        let td = Timer(timeInterval: 0.25, repeats: true) { _ in deflt += 1 }
        RunLoop.main.add(tc, forMode: .common)
        RunLoop.main.add(td, forMode: .default)
        let menu = NSMenu()
        menu.addItem(withTitle: "LockLab menytest (lukker seg selv)", action: nil, keyEquivalent: "")
        let closer = Timer(timeInterval: 3, repeats: false) { _ in
            ticksBefore = common
            log("MENUTEST closer fired in mode=\(RunLoop.current.currentMode?.rawValue ?? "nil") common=\(common) default=\(deflt)")
            menu.cancelTracking()
        }
        RunLoop.main.add(closer, forMode: .common)
        let t0 = monoMs()
        log("MENUTEST popUp start")
        _ = menu.popUp(positioning: nil, at: NSPoint(x: 20, y: 20), in: window.contentView)
        log(String(format: "MENUTEST popUp returned after %.0f ms; during tracking: common=%d default=%d", monoMs() - t0, ticksBefore, deflt))
        tc.invalidate(); td.invalidate()
    }

    // MARK: events
    func noteEvent(_ e: NSEvent) {
        let t = e.type
        let interesting: [NSEvent.EventType] = [.keyDown, .keyUp, .flagsChanged, .leftMouseDown, .leftMouseUp,
                                                .rightMouseDown, .rightMouseUp, .otherMouseDown, .scrollWheel,
                                                .mouseMoved, .leftMouseDragged]
        guard interesting.contains(t) else { return }
        lastInputMono = monoMs()
        if t == .mouseMoved || t == .scrollWheel || t == .leftMouseDragged { return }
        let pid = e.cgEvent?.getIntegerValueField(.eventSourceUnixProcessID) ?? -1
        let st = e.cgEvent?.getIntegerValueField(.eventSourceStateID) ?? -1
        var kc = ""
        if t == .keyDown || t == .keyUp {
            let chord = e.modifierFlags.intersection([.command, .control])
            kc = (!chord.isEmpty || pid != 0) ? " keyCode=\(e.keyCode)" : " keyCode=(not logged)"
        }
        if t == .leftMouseDown || t == .leftMouseUp {
            let hit = window.contentView?.hitTest(window.contentView!.convert(e.locationInWindow, from: nil))
            log("EVMOUSE win=\(e.windowNumber) mine=\(window.windowNumber) loc=\(e.locationInWindow) clickCount=\(e.clickCount) hit=\(hit.map { String(describing: type(of: $0)) } ?? "nil")")
        }
        log("EV type=\(t.rawValue)\(kc) cmd=\(e.modifierFlags.contains(.command)) ctrl=\(e.modifierFlags.contains(.control)) srcpid=\(pid) stateID=\(st)")
    }

    // MARK: 1 s poll: idle counters, session dictionary, activation
    func tick() {
        let any = CGEventType(rawValue: ~0)!    // kCGAnyInputEventType
        let idleC = CGEventSource.secondsSinceLastEventType(.combinedSessionState, eventType: any)
        let idleH = CGEventSource.secondsSinceLastEventType(.hidSystemState, eventType: any)
        let dict = CGSessionCopyCurrentDictionary() as? [String: Any]
        let locked: String = dict.map { d in d["CGSSessionScreenIsLocked"].map { "\($0)" } ?? "absent" } ?? "nodict"
        let onConsole: String = dict.map { d in d["kCGSSessionOnConsoleKey"].map { "\($0)" } ?? "absent" } ?? "nodict"
        let own = lastInputMono == 0 ? -1 : (monoMs() - lastInputMono) / 1000
        let active = NSApp.isActive, key = window.isKeyWindow
        let vis = window.occlusionState.contains(.visible)
        log(String(format: "TICK idleC=%.2f idleH=%.2f own=%.1f", idleC, idleH, own)
            + " scrLocked=\(locked) console=\(onConsole) active=\(active) key=\(key) visible=\(vis)")
        if prevIdleC >= 0 && idleC + 0.5 < prevIdleC { log(String(format: "IDLE-RESET idleC %.2f -> %.2f", prevIdleC, idleC)) }
        prevIdleC = idleC
        if locked != prevLocked {
            if !prevLocked.isEmpty { log("CHANGE scrLocked \(prevLocked) -> \(locked)") }
            if prevLocked == "1" { wakeSignal("CGSSessionScreenIsLocked cleared") }
            prevLocked = locked
        }
        if prevActive != active { if prevActive != nil { log("CHANGE active \(prevActive!) -> \(active) (seen by poll)") }; prevActive = active }
        if prevKey != key { if prevKey != nil { log("CHANGE key \(prevKey!) -> \(key) (seen by poll)") }; prevKey = key }
        if !IS_OTHER {
            let base = String(format: "aktiv=%@  idle=%.0f s  skjerm låst=%@", active ? "ja" : "nei", idleC, locked)
            status.stringValue = MODE == "touchid" ? base + "\nForsøk: \(attempt)" + (authInFlight ? " (venter på Touch ID)" : "") : base
        }
    }

    // MARK: Touch ID mode (U4.1, U4.3) — only after a human click
    @objc func doneClicked(_ sender: Any?) {
        let pid = NSApp.currentEvent?.cgEvent?.getIntegerValueField(.eventSourceUnixProcessID) ?? -1
        guard pid == 0 else { log("DONE refused srcpid=\(pid)"); return }
        log("DONE clicked"); NSApp.terminate(nil)
    }

    @objc func unlockClicked(_ sender: Any?) {
        let ev = NSApp.currentEvent
        let pid = ev?.cgEvent?.getIntegerValueField(.eventSourceUnixProcessID) ?? -1
        guard MODE == "touchid", pid == 0, ev?.type == .leftMouseUp else {
            log("AUTH click refused: not a human click (type=\(ev.map { String($0.type.rawValue) } ?? "nil") srcpid=\(pid))"); return
        }
        runUnlock()
    }

    /// Variant B: LAAuthenticationView (macOS 12+) inside our own window. evaluateAccessControl on the paired context
    /// shows the UI in the view instead of the system alert (LAAuthenticationView.h); the key op then reuses the context.
    @objc func embeddedClicked(_ sender: Any?) {
        let ev = NSApp.currentEvent
        let pid = ev?.cgEvent?.getIntegerValueField(.eventSourceUnixProcessID) ?? -1
        guard MODE == "touchid", !DRY, pid == 0, ev?.type == .leftMouseUp else {
            log("AUTH-EMB click refused (type=\(ev.map { String($0.type.rawValue) } ?? "nil") srcpid=\(pid) dry=\(DRY))"); return
        }
        guard !authInFlight else { log("AUTH-EMB click ignored: already in flight"); return }
        attempt += 1; authInFlight = true
        let n = attempt
        log("AUTH-EMB-START attempt=\(n) isActive=\(NSApp.isActive) key=\(window.isKeyWindow)")
        var err: Unmanaged<CFError>?
        guard let acl = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                        [.privateKeyUsage, .biometryCurrentSet], &err) else {
            log("AUTH-EMB acl failed"); authInFlight = false; return
        }
        do {
            let noUI = LAContext(); noUI.interactionNotAllowed = true
            let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: acl, authenticationContext: noUI)
            let blob = key.dataRepresentation
            var dekBytes = [UInt8](repeating: 0, count: 32)
            _ = SecRandomCopyBytes(kSecRandomDefault, 32, &dekBytes)
            let dek = Data(dekBytes)
            let suite = HPKE.Ciphersuite.P256_SHA256_AES_GCM_256
            let info = Data("brev-spike lock u4 v1".utf8)
            var sender = try HPKE.Sender(recipientKey: key.publicKey, ciphersuite: suite, info: info)
            let ct = try sender.seal(dek)
            let enc = sender.encapsulatedKey
            let ctx = LAContext(); ctx.localizedFallbackTitle = ""; ctx.localizedCancelTitle = "Avbryt"
            let view = LAAuthenticationView(context: ctx, controlSize: .regular)
            view.frame = NSRect(x: window.contentView!.bounds.width - 60, y: 95, width: 48, height: 48)
            window.contentView!.addSubview(view)
            let t0 = monoMs()
            log("AUTH-EMB attempt=\(n) key made and DEK wrapped without a prompt; evaluateAccessControl via the embedded view")
            ctx.evaluateAccessControl(acl, operation: .useKeyKeyExchange, localizedReason: "låse opp LockLab (test)") { ok, e in
                log(String(format: "AUTH-EMB attempt=%d evaluateAccessControl ok=%@ after %.0f ms ", n, ok ? "true" : "false", monoMs() - t0)
                    + (e.map { errStr($0) } ?? ""))
                self.unlockQueue.async {
                    if ok {
                        do {
                            let kek = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob, authenticationContext: ctx)
                            var r = try HPKE.Recipient(privateKey: kek, ciphersuite: suite, info: info, encapsulatedKey: enc)
                            let back = try r.open(ct)
                            log(String(format: "AUTH-EMB-UNWRAP attempt=%d OK match=%@ after %.0f ms", n, back == dek ? "yes" : "NO", monoMs() - t0))
                        } catch { log("AUTH-EMB-UNWRAP attempt=\(n) ERROR " + errStr(error)) }
                    }
                    DispatchQueue.main.async {
                        view.removeFromSuperview()
                        self.authInFlight = false
                        log("AUTH-END-ON-MAIN attempt=\(n) variant=embedded isActive=\(NSApp.isActive) key=\(self.window.isKeyWindow)")
                        for d in [0.25, 1.0, 2.0] {
                            DispatchQueue.main.asyncAfter(deadline: .now() + d) {
                                log("AUTH-END+\(d)s attempt=\(n) isActive=\(NSApp.isActive) key=\(self.window.isKeyWindow)")
                            }
                        }
                    }
                }
            }
        } catch {
            log("AUTH-EMB setup error " + errStr(error)); authInFlight = false
        }
    }

    func runUnlock() {
        guard !authInFlight else { log("AUTH click ignored: already in flight"); return }
        attempt += 1
        authInFlight = true
        let n = attempt
        log("AUTH-START attempt=\(n) isActive=\(NSApp.isActive) key=\(window.isKeyWindow)")
        unlockQueue.async {
            var t0 = monoMs()
            do {
                var err: Unmanaged<CFError>?
                guard let acl = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                                [.privateKeyUsage, .biometryCurrentSet], &err) else {
                    throw (err!.takeRetainedValue() as Error)
                }
                let noUI = LAContext(); noUI.interactionNotAllowed = true
                let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: acl, authenticationContext: noUI)
                let blob = key.dataRepresentation
                var dekBytes = [UInt8](repeating: 0, count: 32)
                guard SecRandomCopyBytes(kSecRandomDefault, 32, &dekBytes) == errSecSuccess else { throw CocoaError(.featureUnsupported) }
                let dek = Data(dekBytes)
                let suite = HPKE.Ciphersuite.P256_SHA256_AES_GCM_256
                let info = Data("brev-spike lock u4 v1".utf8)
                var sender = try HPKE.Sender(recipientKey: key.publicKey, ciphersuite: suite, info: info)
                let ct = try sender.seal(dek)
                let enc = sender.encapsulatedKey
                log("AUTH attempt=\(n) key made and DEK wrapped without a prompt; now the prompt")
                if DRY { log("AUTH attempt=\(n) DRY: would prompt here; no LAContext is evaluated"); throw CocoaError(.userCancelled) }
                let ctx = LAContext()
                ctx.localizedFallbackTitle = ""
                ctx.localizedCancelTitle = "Avbryt"
                ctx.localizedReason = "låse opp LockLab (test)"
                t0 = monoMs()
                let kek = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob, authenticationContext: ctx)
                log(String(format: "AUTH attempt=%d init(dataRepresentation:) returned after %.0f ms", n, monoMs() - t0))
                var r = try HPKE.Recipient(privateKey: kek, ciphersuite: suite, info: info, encapsulatedKey: enc)
                let back = try r.open(ct)
                log(String(format: "AUTH-UNWRAP attempt=%d OK match=%@ after %.0f ms (on unlock queue) isActive(read off-main)=%@",
                           n, back == dek ? "yes" : "NO", monoMs() - t0, NSApp.isActive ? "true" : "false"))
            } catch {
                log(String(format: "AUTH-UNWRAP attempt=%d ERROR after %.0f ms ", n, monoMs() - t0) + errStr(error))
            }
            DispatchQueue.main.async {
                self.authInFlight = false
                log("AUTH-END-ON-MAIN attempt=\(n) isActive=\(NSApp.isActive) key=\(self.window.isKeyWindow)")
                for d in [0.25, 1.0, 2.0] {
                    DispatchQueue.main.asyncAfter(deadline: .now() + d) {
                        log("AUTH-END+\(d)s attempt=\(n) isActive=\(NSApp.isActive) key=\(self.window.isKeyWindow)")
                    }
                }
            }
        }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    let lab = Lab()
    func applicationDidFinishLaunching(_ n: Notification) { lab.start() }
    func applicationShouldTerminateAfterLastWindowClosed(_ s: NSApplication) -> Bool { true }
    func applicationSupportsSecureRestorableState(_ app: NSApplication) -> Bool { true }
    func applicationWillTerminate(_ n: Notification) { log("terminating"); try? fileLog?.synchronize() }
}

let app = LabApp.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.run()
