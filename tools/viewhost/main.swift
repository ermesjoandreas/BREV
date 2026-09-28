// main.swift — ViewHost: Brev's mail window with fake letters, for tests.
//
// A test app, never linked into Brev.app (tools/viewhost/build.sh builds it
// from app/Sources/{Shared,App,UI}). It needs no keychain and no Touch ID:
// the stores live in a temporary folder, each DEK is wrapped to a software
// P-256 key and each identity key is a software key, as in the CLI harness
// (app/Tests). It starts its own relay (brev-relay, built by build.sh, on
// 127.0.0.1 with a port the OS picks and a database in the temporary folder;
// stopped at the end) and makes three users: this host ("testvert") and the
// contacts Ekko and Speil ("ekko", "speil"), which live in this process
// without a window. The host sends fake, non-secret letters to Ekko and
// Speil, Ekko sends a long one back, and the host shows the real
// MailViewController in a hardened MainWindow without activating itself
// (with --compose it asks to be active). Every letter carries the test
// marker of app/Tests/scan.c, built from its XORed bytes, so no String copy
// of it exists here. Since Phase 3 a thread holds one letter.
//
// Timeline: ready → (hold) → checks, a wider window, a divider dragged right
// and a narrow window, a posted ↓ key, the letter pane scrolled down (its
// header leaves sight) and back up, Ekko sends a new letter → the sync timer
// fetches it → the real lock sequence → exit.
// With --compose: Nytt brev opens the real compose sheet, wired as
// AppDelegate wires it (the signer is this host's software key instead of
// SignService), and the marker is typed into the subject and the body by
// key-downs made here with source PID 0, delivered as AppKit delivers a real
// key (key codes found with KeyTranslator). The ways in that must fail are
// tried (events with a source PID, ⌘C ⌘X ⌘A ⌘V ⌘Z, ⌃V, insertText, a click
// made in code, an AX press, and with --post keys posted to this process),
// and secure event input is checked → ready → (hold) → ⌘↩ sends through the
// relay → Ekko fetches it → Escape discards a second letter → the lock
// sequence discards a third → exit.
// With --triggers: the real lock triggers (LockController.start) and the
// real unlock bookkeeping, with this app active; switch: an unlock in
// flight, the Finder becomes active (no lock), this app is active again and
// the unlock ends, the Finder becomes active (the lock sequence runs);
// idle: no input, the Brev menu opened shortly before the limit, the lock
// sequence runs after 300 s and closes it. The lock's log line is read back
// from this process's log. Then exit.
// Output is check names and counts only; "ready pid=<n> window=<n>
// frame=<x,y,w,h>" tells a driver when to run an AX dump, AX presses or a
// capture against the window during the hold, and the "rect <name>
// <x,y,w,h>" lines after it (global points, origin top left) name the
// three panes, with --control the backdrop and the control window, and
// with --compose the recipient, subject and body fields.
// SelfScan is compiled in with BREV_SELFSCAN, as in the Verify build: the
// lock sequence runs it, and --scan counts with it. The content views draw
// into the protected layer (ContentView, D-0034), so a capture shows their
// panes without content, and so do the snapshots below.
//
// usage: ViewHost [--hold <s>] [--frame <x,y,w,h>] [--control] [--snapshot <dir>]
//                 [--capturable] [--unprotected] [--scan] [--post] [--compose]
//                 [--triggers switch|idle]
//   --hold <s>      seconds to wait after ready before the checks (default 3)
//   --frame <r>     the window's frame (global points, origin top left)
//                   instead of centred
//   --control       a green backdrop window behind the window and a cyan
//                   control window with plain AppKit text to its right, both
//                   capturable: an excluded window shows the backdrop, and
//                   the control shows that the capture sees text
//   --snapshot <d>  write unlocked.png, after-sync.png and locked.png (drawn
//                   offscreen with cacheDisplay; no screen capture)
//   --capturable    sharingType .readOnly (the default keeps Hardening's
//                   .none), for the compose sheet too: only the protected
//                   layer keeps content out
//   --unprotected   preventsCapture = false on every content view's layer,
//                   also those made later and the compose sheet's; with
//                   --capturable, the negative control: a capture must see
//                   the fake letters
//   --scan          scan this process for the marker before and after the
//                   lock, with SelfScan's needle control while the letters
//                   are shown and its scribble probe after the lock (run
//                   with MallocScribble=1, as Brev runs)
//   --post          post a ↓ key to this process (CGEventPostToPid): the
//                   input filter must drop it; with --compose, a, ⌘↩ and
//                   Escape while the body has focus
//   --compose       the compose sheet's timeline instead (above)
//   --triggers <t>  the lock triggers' timeline instead (above): switch
//                   (about 5 s; the Finder comes to the front) or idle
//                   (about 5.5 min; no input meanwhile). With --post, idle
//                   also posts a ↓ key to this process every 20 s, which
//                   must not count as input. At the end, the app that was
//                   in front before is asked to be active again

import AppKit
import AVFoundation
import Carbon.HIToolbox
import OSLog
import Security

setvbuf(stdout, nil, _IOLBF, 0)

var failures = 0
func check(_ what: String, _ ok: Bool, _ detail: @autoclosure () -> String = "") {
    let d = ok ? "" : detail()
    print((ok ? "ok   " : "FAIL ") + what + (d.isEmpty ? "" : "  [\(d)]"))
    if !ok { failures += 1 }
}

let args = Array(CommandLine.arguments.dropFirst())
func value(_ flag: String) -> String? {
    args.firstIndex(of: flag).flatMap { args.indices.contains($0 + 1) ? args[$0 + 1] : nil }
}
let hold = value("--hold").flatMap(Double.init) ?? 3
let snapshotDir = value("--snapshot").map { URL(fileURLWithPath: $0, isDirectory: true) }
let capturable = args.contains("--capturable")
let unprotected = args.contains("--unprotected")
let control = args.contains("--control")
/// A rect given as x,y,w,h in global points with the origin at the top
/// left, in AppKit's screen coordinates.
func screenRect(_ text: String) -> NSRect? {
    let n = text.split(separator: ",").compactMap { Double($0) }
    guard n.count == 4, let top = NSScreen.screens.first?.frame.maxY else { return nil }
    return NSRect(x: n[0], y: top - n[1] - n[3], width: n[2], height: n[3])
}
let frameArg = value("--frame").flatMap(screenRect)
let scanning = args.contains("--scan")
let posting = args.contains("--post")
let composing = args.contains("--compose")
let triggers = value("--triggers")
if let triggers, !["switch", "idle"].contains(triggers) {
    print("usage: --triggers switch|idle")
    exit(2)
}
/// Brev's idle limit in seconds, and how often its timer looks.
let idleLimit = Double(LockState.idleLimitNanos) / 1e9, idleTick = LockState.idleCheckInterval

// MARK: - Fake letters

/// "BREV-SECRET-BODY" XOR 0x5A, as in app/Tests/scan.c.
let markerX: [UInt8] = [0x18, 0x08, 0x1f, 0x0c, 0x77, 0x09, 0x1f, 0x19,
                        0x08, 0x1f, 0x0e, 0x77, 0x18, 0x15, 0x1e, 0x03]

/// `parts` joined into one SecretText; `nil` parts are the marker.
func fake(_ parts: [String?]) -> SecretText {
    let t = SecretText(maxUnits: 8192)
    for p in parts {
        if let p {
            let u = Array(p.utf16)
            u.withUnsafeBufferPointer { _ = t.insert($0, at: t.length) }
        } else {
            for i in 0..<16 {
                var unit = UInt16(markerX[i] ^ 0x5A)
                withUnsafePointer(to: &unit) { _ = t.insert(UnsafeBufferPointer(start: $0, count: 1), at: t.length) }
                unit = 0
            }
        }
    }
    return t
}

let paragraph = "Kjære deg, dette er et testbrev med æ, ø og å, skrevet av testverten. Det har mange ord, "
    + "så linjene brytes ved mellomrom når vinduet er smalt. "
let longWord = String(repeating: "x", count: 600)

func letterBody(_ n: Int) -> SecretText {
    fake(["Hei!\n\n", String(repeating: paragraph, count: n), "\n\n", nil, " ", longWord, "\n\nHilsen\ntestverten 😀"])
}

// MARK: - The relay and the users, as the app makes them, with software keys

/// This run's relay: build.sh's brev-relay (Info.plist BrevRelayBinary) on
/// 127.0.0.1:0 with a database in `dir`; nil if it did not start.
func startRelay(in dir: URL) -> (Process, String)? {
    guard let path = Bundle.main.object(forInfoDictionaryKey: "BrevRelayBinary") as? String else { return nil }
    let port = dir.appendingPathComponent("relay.port")
    let relay = Process()
    relay.executableURL = URL(fileURLWithPath: path)
    relay.arguments = ["serve", "--db", dir.appendingPathComponent("relay.db").path,
                       "--listen", "127.0.0.1:0", "--port-file", port.path]
    relay.standardError = FileHandle.nullDevice
    do { try relay.run() } catch { return nil }
    for _ in 0..<100 {
        if let text = try? String(contentsOf: port, encoding: .utf8), let n = Int(text.trimmingCharacters(in: .newlines)) {
            return (relay, "http://127.0.0.1:\(n)")
        }
        guard relay.isRunning else { return nil }
        usleep(50_000)
    }
    relay.terminate()
    return nil
}

/// One user, unlocked: a store in its own folder under a DEK wrapped to a
/// software KEK, and a software identity key that signs its digests
/// through Enclave.sign (in Brev, SignService adds the keychain lookup and
/// Touch ID).
final class User {
    let session: Session
    let identity: SecKey

    init(in dir: URL, relay: String) throws {
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let attrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                                    kSecAttrKeySizeInBits as String: 256]
        guard let kek = SecKeyCreateRandomKey(attrs as CFDictionary, nil), let kekPublic = SecKeyCopyPublicKey(kek),
              let identity = SecKeyCreateRandomKey(attrs as CFDictionary, nil),
              let identityPublic = SecKeyCopyPublicKey(identity)
        else { throw BrevError.Crypto }
        self.identity = identity
        let dek = SecretBytes(capacity: 64)
        guard SecRandomCopyBytes(kSecRandomDefault, 32, dek.base) == errSecSuccess else { throw BrevError.Rng }
        dek.setCount(32)
        let wrapped = try Enclave.wrap(dek: dek, to: kekPublic)
        session = try Session.create(dir: dir.path, relay: relay, dek: dek,
                                     signingKey: try Enclave.publicKeyBytes(of: identityPublic))
        do {
            try Enclave.unwrap(wrapped, with: kek) { try session.brev.unlock(dek: $0) }
        } catch {
            session.brev.lock()
            throw error
        }
    }

    func register(_ address: String) throws {
        let typed = fake([address])
        defer { typed.wipe() }
        try session.register(signature: try Enclave.sign(digest: try session.registerRequest(address: typed),
                                                         key: identity))
    }

    /// Adds the contact with `address`; returns its local id.
    func add(_ address: String) throws -> Data {
        let typed = fake([address])
        defer { typed.wipe() }
        return try session.addContact(address: typed)
    }

    /// One letter in the app's steps, all on this thread; wipes the texts.
    func send(to contact: Data, subject: SecretText, body: SecretText) throws {
        defer { subject.wipe(); body.wipe() }
        try session.prepareSend(contact: contact)
        let digest = try session.signRequest(contact: contact, subject: subject, body: body)
        try session.attachSignature(try Enclave.sign(digest: digest, key: identity))
        _ = try session.submit()
    }

    /// The compose sheet's signer: the software key, answered on main as
    /// SignService answers.
    func sign(_ digest: Data, _ done: @escaping (Result<Data, Error>) -> Void) {
        let result = Result { try Enclave.sign(digest: digest, key: identity) }
        DispatchQueue.main.async { done(result) }
    }
}

// MARK: - Looking at the views

func all<T: NSView>(_ type: T.Type, in view: NSView) -> [T] {
    var out: [T] = []
    if let v = view as? T { out.append(v) }
    for s in view.subviews { out += all(type, in: s) }
    return out
}

/// OpaqueView's promises, in process (docs/PHASE2_DESIGN.md §7.1).
func checkOpaque(_ name: String, _ v: NSView) {
    let click = NSEvent.mouseEvent(with: .rightMouseDown, location: .zero, modifierFlags: [], timestamp: 0,
                                   windowNumber: 0, context: nil, eventNumber: 0, clickCount: 1, pressure: 1)!
    let text = NSPasteboard.PasteboardType.string
    let ax = !v.isAccessibilityElement() && (v.accessibilityChildren() ?? []).isEmpty
        && v.accessibilityRole() == nil && v.accessibilityValue() == nil && v.accessibilityLabel() == nil
        && v.accessibilityTitle() == nil && v.accessibilityHelp() == nil && v.accessibilitySelectedText() == nil
        && v.accessibilityNumberOfCharacters() == 0
        && v.accessibilityString(for: NSRange(location: 0, length: 64)) == nil
        && v.accessibilityAttributedString(for: NSRange(location: 0, length: 64)) == nil
        && v.accessibilityHitTest(NSPoint(x: 5, y: 5)) == nil
    check("\(name): no accessibility element, text or children", ax)
    check("\(name): no menu, no Services, no drag types, flipped",
          v.menu(for: click) == nil && v.validRequestor(forSendType: text, returnType: nil) == nil
              && v.validRequestor(forSendType: nil, returnType: text) == nil
              && v.registeredDraggedTypes.isEmpty && v.isFlipped)
}

func snapshot(_ view: NSView, _ name: String) {
    guard let dir = snapshotDir, let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { return }
    view.cacheDisplay(in: view.bounds, to: rep)
    do {
        try rep.representation(using: .png, properties: [:])?.write(to: dir.appendingPathComponent(name))
        print("snapshot \(name)")
    } catch {
        check("snapshot \(name) written", false, "\(error)")
    }
}

/// Whether a pixel row of `buffer` holds a byte that is not 0.
func hasPixels(_ buffer: CVPixelBuffer) -> Bool {
    guard CVPixelBufferLockBaseAddress(buffer, .readOnly) == kCVReturnSuccess else { return true }
    defer { CVPixelBufferUnlockBaseAddress(buffer, .readOnly) }
    guard let base = CVPixelBufferGetBaseAddress(buffer) else { return true }
    let bytes = UnsafeRawBufferPointer(start: base, count: CVPixelBufferGetBytesPerRow(buffer) * CVPixelBufferGetHeight(buffer))
    return bytes.contains { $0 != 0 }
}

/// Whether AppKit's own drawing of `v` inside `rect` puts ink into an empty
/// bitmap: `draw(_:)` into a current NSGraphicsContext, as print and PDF
/// output call it. cacheDisplay does not call `draw(_:)` for a view that
/// updates its layer (it renders the layer tree), so it cannot show this.
func drawInks(_ v: NSView, _ rect: NSRect) -> Bool {
    let w = Int(rect.width.rounded(.up)), h = Int(rect.height.rounded(.up))
    guard w > 0, h > 0 else { return false }
    guard let ctx = CGContext(data: nil, width: w, height: h, bitsPerComponent: 8, bytesPerRow: 0,
                              space: CGColorSpaceCreateDeviceRGB(),
                              bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)
    else { return true }
    // The view's coordinates inside `rect` onto the bitmap.
    if v.isFlipped {
        ctx.translateBy(x: 0, y: CGFloat(h))
        ctx.scaleBy(x: 1, y: -1)
    }
    ctx.translateBy(x: -rect.minX, y: -rect.minY)
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(cgContext: ctx, flipped: v.isFlipped)
    v.draw(rect)
    NSGraphicsContext.restoreGraphicsState()
    guard let data = ctx.data else { return true }
    return UnsafeRawBufferPointer(start: data, count: ctx.bytesPerRow * h).contains { $0 != 0 }
}

/// Whether the frame `v`'s protected layer shows holds a pixel that is not
/// 0 (false when it shows none).
func showsPixels(_ v: ContentView) -> Bool {
    guard #available(macOS 14.4, *), let shown = v.protectedLayer.sampleBufferRenderer.displayedPixelBuffer()
    else { return false }
    return hasPixels(shown)
}

/// A capturable window at `rect` that AppKit draws: green, or cyan with
/// lines of plain text (the control).
final class PlainView: NSView {
    let color: NSColor, lines: Int
    init(color: NSColor, lines: Int) {
        self.color = color
        self.lines = lines
        super.init(frame: .zero)
    }

    required init?(coder: NSCoder) {
        nil
    }

    override func draw(_ dirtyRect: NSRect) {
        color.setFill()
        bounds.fill()
        let attrs: [NSAttributedString.Key: Any] = [.font: NSFont.systemFont(ofSize: 13), .foregroundColor: NSColor.black]
        for i in 0..<lines {
            ("KONTROLL \(i + 1): synlig tekst i et vindu som kan tas opp" as NSString)
                .draw(at: NSPoint(x: 16, y: bounds.height - 40 - CGFloat(i) * 20), withAttributes: attrs)
        }
    }
}

func plainWindow(_ rect: NSRect, _ view: NSView) -> NSWindow {
    let w = NSWindow(contentRect: rect, styleMask: [.borderless], backing: .buffered, defer: false)
    w.isReleasedWhenClosed = false
    w.isRestorable = false
    w.contentView = view
    w.orderFrontRegardless()
    return w
}

/// `rect` (AppKit screen coordinates) as x,y,w,h with the origin at the top
/// left.
func globalText(_ rect: NSRect) -> String {
    let top = NSScreen.screens.first?.frame.maxY ?? 0
    return "\(Int(rect.minX)),\(Int(top - rect.maxY)),\(Int(rect.width)),\(Int(rect.height))"
}

// MARK: - Main

let application = BrevApplication.shared
Hardening.applyToApp()
_ = application.setActivationPolicy(.accessory)
let lock = LockController()
application.mainMenu = MainMenu.make(lock: lock)

if scanning && getenv("MallocScribble").map({ String(cString: $0) }) != "1" {
    print("FAIL --scan needs MallocScribble=1, as Brev runs")
    exit(2)
}

let dir = FileManager.default.temporaryDirectory.appendingPathComponent("brev-viewhost-\(getpid())")
try? FileManager.default.removeItem(at: dir)
try! FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
var relayProcess: Process?
func finish() -> Never {
    relayProcess?.terminate()
    relayProcess?.waitUntilExit()
    try? FileManager.default.removeItem(at: dir)
    print(failures == 0 ? "PASS" : "FAIL: \(failures) check(s)")
    exit(failures == 0 ? 0 : 1)
}
// A safety net: the host never outlives its run by much.
DispatchQueue.main.asyncAfter(deadline: .now() + hold + 60 + (triggers == "idle" ? idleLimit + idleTick + 30 : 0)) {
    check("finished in time", false)
    finish()
}

guard let relayRun = startRelay(in: dir) else {
    check("the relay starts on 127.0.0.1 (build.sh builds it)", false)
    finish()
}
relayProcess = relayRun.0
let relayURL = relayRun.1
let me: User, ekkoUser: User
let session: Session
/// Ekko's local id here, and this host's at Ekko.
var ekko = Data(), meAtEkko = Data()
do {
    me = try User(in: dir.appendingPathComponent("testvert"), relay: relayURL)
    ekkoUser = try User(in: dir.appendingPathComponent("ekko"), relay: relayURL)
    let speilUser = try User(in: dir.appendingPathComponent("speil"), relay: relayURL)
    session = me.session
    try me.register("testvert")
    try ekkoUser.register("ekko")
    try speilUser.register("speil")
    ekko = try me.add("ekko")
    let speil = try me.add("speil")
    meAtEkko = try ekkoUser.add("testvert")
    // Two threads with Ekko, one with Speil: a letter to each, and Ekko's
    // long letter, which arrives on sync.
    try me.send(to: ekko, subject: fake(["Det første brevet ", nil]), body: letterBody(3))
    try me.send(to: speil, subject: fake(["Et brev til Speil ", nil]), body: letterBody(1))
    try ekkoUser.send(to: meAtEkko, subject: fake(["Hei fra Ekko ", nil, "\nandre linje"]), body: letterBody(12))
    speilUser.session.brev.lock()
    let arrived = try session.sync()
    check("Ekko's letter arrives through the relay", arrived == 1, "\(arrived)")
    // Ekko takes the first letter now, so its sync after a compose send
    // counts only the composed letter.
    let atEkko = try ekkoUser.session.sync()
    check("the first letter arrives at Ekko", atEkko == 1, "\(atEkko)")
} catch {
    check("fake letters sent", false, "\((error as? BrevError).map { "\($0)" } ?? "other")")
    finish()
}

// In-process checks of every content view class.
let probeText = SecureTextView(frame: NSRect(x: 0, y: 0, width: 100, height: 40))
let probeList = SecureListView(rowHeight: 30)
let probeStack = LetterStackView(frame: NSRect(x: 0, y: 0, width: 100, height: 40))
checkOpaque("SecureTextView", probeText)
checkOpaque("SecureListView", probeList)
checkOpaque("LetterStackView", probeStack)
check("SecureTextView takes no focus (no caret, no selection)", !probeText.acceptsFirstResponder)
check("no Services menu", NSApp.servicesMenu == nil)

let window = MainWindow(contentSize: NSSize(width: 900, height: 600))
if capturable { window.sharingType = .readOnly }
let mail = MailViewController(session: session)
var events: [String] = []
mail.onLock = { events.append("lock") }
mail.onNewLetter = { _ in events.append("new letter") }
window.root.show(mail)
if let frameArg { window.setFrame(frameArg, display: false) } else { window.center() }
// Behind the window, a backdrop that shows where the window is excluded;
// to its right, the control.
var plainWindows: [NSWindow] = []
if control {
    let screen = NSScreen.screens.first?.visibleFrame ?? .zero
    let f = window.frame
    let backdrop = NSRect(x: f.minX - 8, y: f.minY - 8, width: screen.maxX - f.minX + 8, height: f.height + 16)
    plainWindows.append(plainWindow(backdrop, PlainView(color: NSColor(srgbRed: 0, green: 160 / 255, blue: 0, alpha: 1),
                                                        lines: 0)))
    plainWindows.append(plainWindow(NSRect(x: f.maxX + 8, y: f.minY, width: backdrop.maxX - f.maxX - 16,
                                           height: f.height),
                                    PlainView(color: NSColor(srgbRed: 0, green: 1, blue: 1, alpha: 1), lines: 12)))
}
window.orderFrontRegardless()
plainWindows.dropFirst().forEach { $0.orderFrontRegardless() }
mail.start()
// Every content view draws through a layer with preventsCapture = true.
let contentViews = all(ContentView.self, in: mail.view)
check("every content view has a protected layer", !contentViews.isEmpty && contentViews.allSatisfy {
    $0.protectedLayer.preventsCapture && $0.protectedLayer.superlayer === $0.layer && $0.wantsUpdateLayer
})
// The negative control reaches the letter views a reload makes later, too.
func unprotect() {
    let sheetViews = window.attachedSheet?.contentView.map { all(ContentView.self, in: $0) } ?? []
    (all(ContentView.self, in: mail.view) + sheetViews).forEach { $0.protectedLayer.preventsCapture = false }
}
if unprotected {
    unprotect()
    _ = commonModeTimer(every: 0.05, unprotect)
}

lock.window = window
lock.session = session
lock.showLockScreen = { window.root.show(NoticeViewController(L10n.unlockTitle)) }
// Unlocked, as LockController.endUnlock records it, without asking whether
// this (inactive) app is active; the idle timer and the triggers stay off.
// --triggers goes through LockController itself.
if triggers == nil {
    let generation = lock.state.beginUnlock()
    _ = lock.state.endUnlock(generation, succeeded: true, appActive: true)
}

let lists = all(SecureListView.self, in: mail.view)
let letters = all(LetterStackView.self, in: mail.view).first!
func shownLetters() -> Int { all(SecureTextView.self, in: letters).count }

/// Prints the ready line and the panes' rects for a driver, then calls
/// `next` after the hold.
func announceReady(then next: @escaping () -> Void) {
    // The window's frame in global display coordinates (origin top left),
    // for a driver's AX hit tests.
    let screenTop = NSScreen.screens.first?.frame.maxY ?? 0
    let f = window.frame
    print("ready pid=\(getpid()) window=\(window.windowNumber) frame=\(Int(f.minX)),\(Int(screenTop - f.maxY)),\(Int(f.width)),\(Int(f.height))")
    mail.view.layoutSubtreeIfNeeded()
    for (name, v) in zip(["contacts", "threads", "letters"], [lists[0], lists[1], letters] as [NSView]) {
        if let scroll = v.enclosingScrollView {
            print("rect \(name) \(globalText(window.convertToScreen(scroll.convert(scroll.bounds, to: nil))))")
        }
    }
    for (name, w) in zip(["backdrop", "control"], plainWindows) { print("rect \(name) \(globalText(w.frame))") }
    if let sheet = window.attachedSheet as? ComposeSheet {
        for (name, v) in [("recipient", sheet.recipient), ("subject", sheet.subject), ("body", sheet.body)] as [(String, NSView)] {
            let shown = v.enclosingScrollView ?? v
            print("rect \(name) \(globalText(sheet.convertToScreen(shown.convert(shown.bounds, to: nil))))")
        }
        print("state active=\(NSApp.isActive) sheetKey=\(sheet.isKeyWindow) secureInput=\(SecureInput.isOn)"
              + " sessionSecureInput=\(IsSecureEventInputEnabled())")
    }
    DispatchQueue.main.asyncAfter(deadline: .now() + hold, execute: next)
}

// MARK: - The compose sheet (--compose)

/// "sent" or "closed" for each compose sheet that ended.
var composeEvents: [String] = []
/// Secure event input is session-wide: another app's counts too.
let secureInputBefore = IsSecureEventInputEnabled()

/// The key code and flags that type each unit on the current layout, found
/// with KeyTranslator (the view's own translator), and Return for U+000A.
/// Single units only: no copy of the marker.
let keyMap: [UInt16: (UInt16, CGEventFlags)] = {
    var map: [UInt16: (UInt16, CGEventFlags)] = [0x0A: (36, [])]
    guard let t = KeyTranslator(.current) else { return map }
    for f in [CGEventFlags(), .maskShift] {
        for k in UInt16(0)..<51 {
            t.reset()
            t.translate(keyCode: k, flags: f) { u in
                if u.count == 1, map[u[0]] == nil { map[u[0]] = (k, f) }
            }
        }
    }
    return map
}()

/// The current keyboard layout's input source id (not content).
let layoutID: String = TISCopyCurrentKeyboardLayoutInputSource().flatMap { source in
    TISGetInputSourceProperty(source.takeRetainedValue(), kTISPropertyInputSourceID)
        .map { Unmanaged<CFString>.fromOpaque($0).takeUnretainedValue() as String }
} ?? "none"

/// A key-down made in this process as the hardware's arrives, with source
/// PID 0; or with `pid` (a CGEvent made in a process gets that process's
/// PID, docs/PHASE2_DESIGN.md §0).
func hardwareKey(_ code: UInt16, _ flags: CGEventFlags = [], pid: Int64 = 0) -> NSEvent? {
    guard let cg = CGEvent(keyboardEventSource: nil, virtualKey: code, keyDown: true) else { return nil }
    cg.flags = flags
    cg.setIntegerValueField(.eventSourceUnixProcessID, value: pid)
    return NSEvent(cgEvent: cg)
}

/// `e` into AppKit: through BrevApplication.sendEvent when this app is
/// active and `w` is its key window, as a real key arrives; otherwise to
/// `w.sendEvent`, which hands it to the first responder.
func deliver(_ e: NSEvent?, to w: NSWindow) {
    guard let e else { return }
    if NSApp.isActive && NSApp.keyWindow === w { NSApp.sendEvent(e) } else { w.sendEvent(e) }
}

/// Types `t` into `w`'s focused field, one key-down per unit; false if the
/// layout has no key for one of them.
func typeKeys(_ t: SecretText, into w: NSWindow) -> Bool {
    for i in 0..<t.length {
        guard let k = keyMap[t.units[i]] else { return false }
        deliver(hardwareKey(k.0, k.1), to: w)
    }
    return true
}

func same(_ a: SecretText, _ b: SecretText) -> Bool {
    a.length == b.length && (0..<a.length).allSatisfy { a.units[$0] == b.units[$0] }
}

/// Empty, and every unit of the buffer 0.
func zeroed(_ t: SecretText) -> Bool {
    t.length == 0 && (0..<t.maxUnits).allSatisfy { t.units[$0] == 0 }
}

/// Whether a responder from `w`'s first responder up answers `action`.
func chainAnswers(_ w: NSWindow, _ action: Selector) -> Bool {
    var r: NSResponder? = w.firstResponder
    while let x = r {
        if x.responds(to: action) { return true }
        r = x.nextResponder
    }
    return false
}

func composeSheet() -> ComposeSheet? { window.attachedSheet as? ComposeSheet }

/// Secure event input is on: Brev's flag, and the session's.
func secureInputOn() -> Bool { SecureInput.isOn && IsSecureEventInputEnabled() }
/// Secure event input is off: Brev's flag, and the session's unless another
/// app had it on before this run.
func secureInputOff() -> Bool { !SecureInput.isOn && (secureInputBefore || !IsSecureEventInputEnabled()) }

/// The first compose sheet, once it is sent: it must be freed.
weak var sentSheet: ComposeSheet?

/// --compose: Nytt brev opens the real compose sheet on Ekko, wired as
/// AppDelegate wires it. Keys are key-downs made here with source PID 0,
/// delivered as AppKit delivers a real key. This app asks to be active, so
/// that the sheet is key and secure event input can go on.
func composeStart() {
    print("layout \(layoutID)")
    mail.onNewLetter = { contact in
        let id = contact.id
        ComposeSheet.present(on: window, to: contact, session: session, signer: me.sign) { thread in
            composeEvents.append(thread == nil ? "closed" : "sent")
            if let thread { mail.showSent(thread: thread, contact: id) }
        }
    }
    NSApp.activate(ignoringOtherApps: true)
    DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
        guard let sheet = composeOpen() else { finish() }
        let after = { announceReady { composeAfterHold(sheet) } }
        guard posting else { return after() }
        composePost(sheet, then: after)
    }
}

/// The sheet opens with the marker typed; everything that needs no driver.
func composeOpen() -> ComposeSheet? {
    if !NSApp.isActive {
        print("skip compose: this app is not active, so keys go to the sheet's sendEvent and secure input stays off")
    }
    mail.newLetter(nil)
    guard let sheet = composeSheet() else {
        check("compose: Nytt brev opens the compose sheet", false)
        return nil
    }
    check("compose: Nytt brev opens the compose sheet with the subject focused", sheet.firstResponder === sheet.subject)
    mail.newLetter(nil)
    check("compose: Nytt brev does nothing while the sheet is up", window.sheets.count == 1)
    check("compose: the sheet has Hardening's settings",
          sheet.sharingType == .none && !sheet.isRestorable && sheet.isExcludedFromWindowsMenu
              && sheet.tabbingMode == .disallowed)
    if capturable { sheet.sharingType = .readOnly }
    let ekkoName = Array("ekko".utf16)
    check("compose: the recipient is the contact's name (its address)",
          sheet.recipient.name.map { n in n.length == 4 && (0..<4).allSatisfy { n.units[$0] == ekkoName[$0] } } ?? false)
    checkOpaque("SecureComposeView", sheet.body)
    checkOpaque("RecipientView", sheet.recipient)
    let f = sheet.body
    var off = [f.autocorrectionType, f.spellCheckingType, f.grammarCheckingType, f.smartQuotesType,
               f.smartDashesType, f.smartInsertDeleteType, f.textReplacementType, f.dataDetectionType,
               f.linkDetectionType, f.textCompletionType, f.inlinePredictionType].allSatisfy { $0 == .no }
    if #available(macOS 15.0, *) { off = off && f.writingToolsBehavior == .none && f.mathExpressionCompletionType == .no }
    if #available(macOS 15.2, *) { off = off && f.writingToolsCoordinator == nil && sheet.subject.writingToolsCoordinator == nil }
    check("compose: every text input trait off, Writing Tools none, no coordinator, no input context, no Touch Bar",
          off && f.inputContext == nil && sheet.subject.inputContext == nil && f.makeTouchBar() == nil)
    let edits = ["copy:", "cut:", "paste:", "pasteAsPlainText:", "selectAll:", "startSpeaking:"]
    check("compose: no responder from a field up answers " + edits.joined(separator: " "),
          edits.allSatisfy { !chainAnswers(sheet, NSSelectorFromString($0)) })

    // Typing: the subject, Tab, the body, through keyDown and KeyTranslator.
    let norwegian = layoutID == "com.apple.keylayout.Norwegian"
    if !norwegian { print("skip compose: the layout is \(layoutID); the æøå and dead-key checks need Norwegian") }
    let subject = fake(["Hei ", nil]), body = fake(norwegian ? ["Kjære deg,\n\n", nil, " æøå\nHilsen"] : ["Hei,\n\n", nil])
    defer { subject.wipe(); body.wipe() }
    let typedSubject = typeKeys(subject, into: sheet)
    deliver(hardwareKey(48), to: sheet)
    let tabbed = sheet.firstResponder === sheet.body
    let typedBody = typeKeys(body, into: sheet)
    check("compose: keys type the subject, Tab goes to the body, keys type the body",
          typedSubject && tabbed && typedBody && same(sheet.subject.model.text, subject)
              && same(sheet.body.model.text, body))
    if norwegian {
        deliver(hardwareKey(24), to: sheet)   // ´, then Delete
        deliver(hardwareKey(51), to: sheet)
        let dropped = same(sheet.body.model.text, body)
        deliver(hardwareKey(24), to: sheet)   // ´, then e
        deliver(hardwareKey(14), to: sheet)
        let b = sheet.body.model.text
        let acute = b.length == body.length + 1 && b.units[b.length - 1] == 0xE9
        deliver(hardwareKey(51), to: sheet)
        check("compose: ´ then Delete drops only the accent; ´ then e gives é, and Delete removes it",
              dropped && acute && same(sheet.body.model.text, body))
    }
    if NSApp.isActive && sheet.isKeyWindow {
        check("compose: secure event input is on while a field has focus in the key sheet", secureInputOn())
        check("compose: no text input context is current while a field has focus", NSTextInputContext.current == nil)
        _ = sheet.makeFirstResponder(nil)
        let offWithoutField = secureInputOff()
        _ = sheet.makeFirstResponder(sheet.body)
        check("compose: secure event input goes off when no field has focus, and on again with the body",
              offWithoutField && secureInputOn())
    }

    // No other way in: events made here that keep this process's PID (the
    // app's filter, and the view's own check when the window gets them
    // directly), ⌘C ⌘X ⌘A ⌘V ⌘Z and ⌃V, insertText up the responder chain,
    // and the pasteboard.
    let pasteboard = NSPasteboard.general.changeCount
    deliver(hardwareKey(0, pid: Int64(getpid())), to: sheet)
    sheet.sendEvent(hardwareKey(0, pid: Int64(getpid()))!)
    sheet.sendEvent(hardwareKey(0, pid: 1)!)
    for k: UInt16 in [8, 7, 0, 9, 6] { deliver(hardwareKey(k, .maskCommand), to: sheet) }
    deliver(hardwareKey(9, .maskControl), to: sheet)
    sheet.body.insertText("x")
    _ = sheet.firstResponder?.tryToPerform(#selector(NSResponder.insertText(_:)), with: "x")
    check("compose: nothing else types: events with a source PID, ⌘C ⌘X ⌘A ⌘V ⌘Z, ⌃V, insertText; pasteboard untouched",
          same(sheet.subject.model.text, subject) && same(sheet.body.model.text, body)
              && NSPasteboard.general.changeCount == pasteboard)

    // Send refuses what no human did: a click made in code, an AX press.
    sheet.sendButton?.performClick(nil)
    let pressed = sheet.sendButton?.accessibilityPerformPress() ?? true
    check("compose: Send refuses a click made in code and an AX press",
          !pressed && composeSheet() === sheet && composeEvents.isEmpty && sheet.body.model.text.length == body.length)
    return sheet
}

/// --post: keys posted to this process (CGEventPostToPid) while the body
/// has focus: a, ⌘↩ and Escape. Nothing may type, send or close. That they
/// arrived and were dropped shows in the log (BrevApplication:
/// "dropped synthetic 10 pid=<this process>").
func composePost(_ sheet: ComposeSheet, then next: @escaping () -> Void) {
    guard CGPreflightPostEventAccess() else {
        print("skip --post: this process may not post events")
        return next()
    }
    let length = (sheet.subject.model.text.length, sheet.body.model.text.length)
    let keys: [(UInt16, CGEventFlags)] = [(0, []), (36, .maskCommand), (53, [])]
    for (k, f) in keys {
        for down in [true, false] {
            guard let e = CGEvent(keyboardEventSource: nil, virtualKey: k, keyDown: down) else { continue }
            e.flags = f
            e.postToPid(getpid())
        }
    }
    DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
        check("compose: posted a, ⌘↩ and Escape did nothing (no text, no send, no close)",
              composeSheet() === sheet && composeEvents.isEmpty
                  && (sheet.subject.model.text.length, sheet.body.model.text.length) == length)
        next()
    }
}

/// After the hold: the driver changed nothing; the fields are pixels in
/// the protected layer; ⌘↩ sends in the three steps (the relay, the
/// signature, the relay); Ekko fetches the letter.
func composeAfterHold(_ sheet: ComposeSheet) {
    check("compose: the hold changed nothing (a driver's AX dump and presses): no send, no close",
          composeSheet() === sheet && composeEvents.isEmpty && sheet.body.model.text.length > 0)
    let wanted = NSApp.isActive && sheet.isKeyWindow && sheet.firstResponder === sheet.body
    check("compose: secure event input is on exactly while a field has focus in the key sheet of the active app",
          wanted ? secureInputOn() : secureInputOff(),
          "active=\(NSApp.isActive) key=\(sheet.isKeyWindow) on=\(SecureInput.isOn)")
    let views: [ContentView] = [sheet.recipient, sheet.subject, sheet.body]
    check("compose: the recipient, subject and body are pixels in their buffers and on their layers",
          views.allSatisfy { $0.pool.contains(where: hasPixels) && showsPixels($0) })
    if let rep = sheet.body.bitmapImageRepForCachingDisplay(in: sheet.body.visibleRect) {
        sheet.body.cacheDisplay(in: sheet.body.visibleRect, to: rep)
        let data = rep.bitmapData.map { UnsafeBufferPointer(start: $0, count: rep.bytesPerPlane) }
        check("compose: cacheDisplay of the body (its layer tree) draws nothing",
              data.map { !$0.contains { $0 != 0 } } ?? false)
    }
    check("compose: draw(_:) of the recipient, subject and body (print and PDF output) draws nothing",
          views.allSatisfy { !drawInks($0, $0.visibleRect.intersection($0.bounds)) })
    if scanning {
        let h = SelfScan.scan()
        check("compose: the typed marker is in memory (positive control)", h.u16 > 0, "\(h)")
    }
    let threads = lists[1].count
    let buffers = views.flatMap { $0.pool }
    deliver(hardwareKey(36, .maskCommand), to: sheet)
    check("compose: ⌘↩ starts the send: the sheet stays, read-only, Send and Avbryt disabled",
          composeSheet() === sheet && sheet.sendButton?.isEnabled == false && !sheet.body.isEditable)
    waitFor(15, { composeSheet() == nil }) { closed in
        check("compose: the letter is sent: the sheet closes, the new thread is selected and its letter shown",
              closed && composeEvents == ["sent"] && lists[1].count == threads + 1
                  && lists[1].selected == 0 && shownLetters() == 1,
              "events \(composeEvents), threads \(threads) -> \(lists[1].count), letters \(shownLetters())")
        check("compose: after the send the recipient, subject and body are wiped, their pixels zero, secure input off",
              sheet.recipient.name == nil && zeroed(sheet.subject.model.text) && zeroed(sheet.body.model.text)
                  && !buffers.contains(where: hasPixels) && secureInputOff() && !sheet.subject.hasFocus
                  && !sheet.body.hasFocus)
        sentSheet = sheet
        let fetched = try? ekkoUser.session.sync()
        check("compose: Ekko fetches the letter from the relay", fetched == 1, "\(String(describing: fetched))")
        ekkoUser.session.brev.lock()
        composeCancelAndLock()
    }
}

/// The sent sheet must be freed. AppKit keeps the last event it dequeued in
/// NSApp.currentEvent, and that event's window with it: after ⌘↩, which
/// reaches the sheet through sendEvent without being dequeued, a key-up of
/// the sent sheet can stay there until the next event arrives, which with
/// nobody at the Mac may be never (review round 1). One event posted here,
/// in process, replaces it; what still holds the sheet after that is Brev's.
func composeCancelAndLock() {
    let tick = NSEvent.otherEvent(with: .applicationDefined, location: .zero, modifierFlags: [], timestamp: 0,
                                  windowNumber: 0, context: nil, subtype: 0, data1: 0, data2: 0)
    tick.map { NSApp.postEvent($0, atStart: false) }
    waitFor(3, { sentSheet == nil }) { freed in
        check("compose: a sent sheet is freed", freed)
        composeSecondAndThird()
    }
}

/// Escape discards a letter; the lock sequence discards another.
func composeSecondAndThird() {
    let threads = lists[1].count
    mail.newLetter(nil)
    guard let second = composeSheet() else {
        check("compose: a second sheet opens", false)
        finish()
    }
    let ekkoName = Array("ekko".utf16)
    check("compose: the name the first sheet wiped was its own copy (the second sheet shows it again)",
          second.recipient.name.map { n in n.length == 4 && (0..<4).allSatisfy { n.units[$0] == ekkoName[$0] } } ?? false)
    let draft = fake(["Utkast"])
    let typed = typeKeys(draft, into: second)
    draft.wipe()
    deliver(hardwareKey(53), to: second)
    check("compose: Escape closes the sheet without sending, and wipes it",
          typed && composeSheet() == nil && composeEvents.last == "closed" && lists[1].count == threads
              && second.recipient.name == nil && zeroed(second.subject.model.text) && secureInputOff())

    mail.newLetter(nil)
    guard let third = composeSheet() else {
        check("compose: a third sheet opens", false)
        finish()
    }
    let body = fake(["Til låsen: ", nil])
    deliver(hardwareKey(48), to: third)
    let typedBody = typeKeys(body, into: third)
    let typedRight = same(third.body.model.text, body)
    body.wipe()
    check("compose: the marker is typed into the third sheet's body", typedBody && typedRight)
    let wasOn = NSApp.isActive && third.isKeyWindow ? secureInputOn() : true
    // One display pass, so the fields hold pixels before the lock.
    DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
        let views: [ContentView] = [third.recipient, third.subject, third.body]
        let buffers = views.flatMap { $0.pool }
        check("before lock: the sheet's fields hold pixels (control), secure input on if active",
              buffers.contains(where: hasPixels) && wasOn)
        lock.lock(.manual)
        check("lock: the compose sheet ended without sending, wiped, its pixels zero, secure input off",
              composeSheet() == nil && composeEvents.last == "closed" && composeEvents.filter { $0 == "sent" }.count == 1
                  && third.recipient.name == nil && zeroed(third.subject.model.text) && zeroed(third.body.model.text)
                  && !buffers.contains(where: hasPixels) && views.allSatisfy { !$0.pool.contains(where: hasPixels) }
                  && secureInputOff())
        check("lock: the session is locked and the lock screen shows",
              session.brev.isLocked() && window.root.child is NoticeViewController)
        if scanning {
            let h = SelfScan.scan()
            check("after lock: no copy (UTF-8, UTF-16, glyphs), compose included", h.u8 == 0 && h.u16 == 0 && h.glyph == 0,
                  "\(h)")
            checkScribbled()
        }
        finish()
    }
}

// MARK: - The lock triggers (--triggers)

/// The app in front before this one asked to be active.
let frontBefore = NSWorkspace.shared.frontmostApplication

/// `body` once, after `seconds`, from a timer in the common modes. Not a
/// block on the main queue: that serial queue waits while a menu is tracked
/// inside one of its blocks.
func later(_ seconds: TimeInterval, _ body: @escaping () -> Void) {
    RunLoop.main.add(Timer(timeInterval: seconds, repeats: false) { _ in body() }, forMode: .common)
}

/// `next(true)` as soon as `done()` holds (polled every 0.1 s in the common
/// modes), or `next(false)` after `seconds`.
func waitFor(_ seconds: TimeInterval, _ done: @escaping () -> Bool, then next: @escaping (Bool) -> Void) {
    let end = Date(timeIntervalSinceNow: seconds)
    RunLoop.main.add(Timer(timeInterval: 0.1, repeats: true) { t in
        let ok = done()
        guard ok || Date() >= end else { return }
        t.invalidate()
        next(ok)
    }, forMode: .common)
}

/// Asks to be the active app, with its window key. The deprecated call:
/// the macOS 14 one does not activate an app in the background (lock spike).
func becomeActive(then next: @escaping (Bool) -> Void) {
    NSApp.activate(ignoringOtherApps: true)
    waitFor(5, { NSApp.isActive }) { ok in
        if ok { window.makeKeyAndOrderFront(nil) }
        next(ok)
    }
}

/// The Finder becomes the active app, as when a human switches to it.
func switchAway() {
    guard let finder = NSRunningApplication.runningApplications(withBundleIdentifier: "com.apple.finder").first
    else { return }
    NSApp.yieldActivation(to: finder)
    _ = finder.activate(from: .current, options: [])
}

/// What this process logged in `category` of Brev's subsystem since `since`.
func logged(_ category: String, since: Date) -> [String] {
    guard let store = try? OSLogStore(scope: .currentProcessIdentifier),
          let entries = try? store.getEntries(at: store.position(date: since),
                                              matching: NSPredicate(format: "subsystem == %@ AND category == %@",
                                                                    "no.brev.app", category))
    else { return ["(this process's log could not be read)"] }
    return entries.compactMap { ($0 as? OSLogEntryLog)?.composedMessage }
}

/// The app that was in front is asked to be active again; then exit.
func triggersEnd() {
    if let front = frontBefore, front != .current, !front.isTerminated {
        if NSApp.isActive {
            NSApp.yieldActivation(to: front)
            _ = front.activate(from: .current, options: [])
        } else {
            _ = front.activate(options: [])
        }
    }
    later(0.3) { finish() }
}

/// --triggers switch: resigning active while an unlock is in flight does
/// not lock (the Touch ID panel may take activation); once unlocked, it
/// runs the lock sequence.
func triggersSwitch() {
    becomeActive { active in
        check("switch: this app became active", active)
        guard active else { return triggersEnd() }
        let before = lock.state.generation
        let started = lock.beginUnlock()
        switchAway()
        waitFor(3, { !NSApp.isActive }) { away in
            later(0.3) {
                check("switch: while an unlock is in flight, the Finder becoming active does not lock",
                      away && lock.state.generation == before && !session.brev.isLocked() && shownLetters() > 0,
                      "away=\(away), generation \(before) -> \(lock.state.generation)")
                becomeActive { back in
                    let unlocked = back && lock.endUnlock(started, succeeded: true)
                    check("switch: the unlock ends with this app active, and Brev is unlocked", unlocked)
                    guard unlocked else { return triggersEnd() }
                    later(0.5, switchWhileUnlocked)
                }
            }
        }
    }
}

func switchWhileUnlocked() {
    let views = all(ContentView.self, in: mail.view), buffers = views.flatMap { $0.pool }
    check("before the switch: content views hold pixels (control)", buffers.contains(where: hasPixels))
    let since = Date(), before = lock.state.generation
    switchAway()
    waitFor(3, { lock.state.generation != before }) { locked in
        check("switch: the Finder became active, and Brev locked", locked && !NSApp.isActive)
        checkLocked("switch", views, buffers)
        later(1) {
            let lines = logged("lock", since: since)
            check("switch: the log says lock reason=resignActive, once", lines == ["lock reason=resignActive"],
                  "\(lines)")
            triggersEnd()
        }
    }
}

/// --triggers idle: no input on Brev's own clock for 300 s runs the lock
/// sequence, also while the Brev menu is open, which the lock closes. With
/// --post, keys posted to this process are dropped and do not count.
func triggersIdle() {
    becomeActive { active in
        check("idle: this app became active", active)
        guard active else { return triggersEnd() }
        let lastInput = BrevApplication.lastHumanInput
        let started = lock.beginUnlock()
        let unlocked = lock.endUnlock(started, succeeded: true)
        check("idle: the unlock ends with this app active, and Brev is unlocked", unlocked)
        guard unlocked else { return triggersEnd() }
        let since = Date(), before = lock.state.generation
        print("idle: no input from now; the lock is due in \(Int(idleLimit)) to \(Int(idleLimit + idleTick)) s")
        var views: [ContentView] = [], buffers: [CVPixelBuffer] = []
        later(1) {
            views = all(ContentView.self, in: mail.view)
            buffers = views.flatMap { $0.pool }
            check("idle: content views hold pixels (control)", buffers.contains(where: hasPixels))
        }
        // Posts stop before the menu opens: its tracking loop takes events
        // without BrevApplication, so a dropped key would not be logged.
        var posts = 0, poster: Timer?
        if posting && !CGPreflightPostEventAccess() { print("skip --post: this process may not post events") }
        if posting && CGPreflightPostEventAccess() {
            poster = commonModeTimer(every: 20) {
                guard Date().timeIntervalSince(since) < idleLimit - 20 else { return }
                for down in [true, false] {
                    CGEvent(keyboardEventSource: nil, virtualKey: 125, keyDown: down)?.postToPid(getpid())
                }
                posts += 1
            }
        }
        // The Brev menu left open for the last seconds, as V25 asks.
        var menuOpen = false, menuClosedByLock = false
        later(idleLimit - 10) {
            guard lock.state.generation == before, let menu = NSApp.mainMenu?.items.first?.submenu else { return }
            menuOpen = true
            menu.popUp(positioning: nil, at: NSPoint(x: 20, y: 20), in: window.contentView)
            menuClosedByLock = lock.state.generation != before
            menuOpen = false
        }
        waitFor(idleLimit + idleTick + 20, { lock.state.generation != before }) { locked in
            poster?.invalidate()
            let idle = Double(clock_gettime_nsec_np(CLOCK_MONOTONIC) - lastInput) / 1e9
            // The checks wait for the menu's tracking loop to end.
            waitFor(5, { !menuOpen }) { closed in
                check("idle: Brev locked \(Int(idle)) s after the last input",
                      locked && idle >= idleLimit && idle <= idleLimit + idleTick + 1)
                check("idle: no input counted meanwhile\(posts > 0 ? " (\(posts) posted keys)" : "")",
                      BrevApplication.lastHumanInput == lastInput)
                check("idle: the Brev menu was open, and the lock closed it", closed && menuClosedByLock)
                checkLocked("idle", views, buffers)
                later(1) {
                    let lines = logged("lock", since: since)
                    check("idle: the log says lock reason=idle, once", lines == ["lock reason=idle"], "\(lines)")
                    if posts > 0 {
                        let dropped = logged("input", since: since).filter { $0.hasPrefix("dropped synthetic 10 ") }.count
                        check("idle: every posted key-down arrived and was dropped", dropped == posts,
                              "\(dropped) of \(posts)")
                    }
                    triggersEnd()
                }
            }
        }
    }
}

if let triggers {
    lock.start()
    if triggers == "switch" { triggersSwitch() } else { triggersIdle() }
} else if composing {
    composeStart()
} else {
    announceReady(then: mailChecks)
}

func mailChecks() {
    snapshot(mail.view, "unlocked.png")
    check("no button action ran during the hold (a driver's AX presses)", events.isEmpty, "\(events)")
    check("two contacts, the first selected", lists.count == 2 && lists[0].count == 2 && lists[0].selected == 0)
    check("Ekko's two threads, the newest selected", lists[1].count == 2 && lists[1].selected == 0)
    check("its letter is shown", shownLetters() == 1)
    // The shown letters are pixels in the protected layer's buffers. Neither
    // cacheDisplay (the layer tree) nor draw(_:) (print and PDF output)
    // gets any of them.
    let bodies = all(SecureTextView.self, in: letters).filter { !$0.visibleRect.intersection($0.bounds).isEmpty }
    check("while shown: each visible letter's frame is in its buffers and on its layer",
          !bodies.isEmpty && bodies.allSatisfy { $0.pool.contains(where: hasPixels) && showsPixels($0) })
    if let body = bodies.first, case let shown = body.visibleRect.intersection(body.bounds),
       let rep = body.bitmapImageRepForCachingDisplay(in: shown) {
        body.cacheDisplay(in: shown, to: rep)
        let data = rep.bitmapData.map { UnsafeBufferPointer(start: $0, count: rep.bytesPerPlane) }
        check("cacheDisplay of a shown letter (its layer tree) draws nothing",
              data.map { !$0.contains { $0 != 0 } } ?? false)
    }
    let inSight = all(ContentView.self, in: mail.view).filter { !$0.visibleRect.intersection($0.bounds).isEmpty }
    check("draw(_:) of every content view in sight (print and PDF output) draws nothing",
          inSight.count > 2 && inSight.allSatisfy { !drawInks($0, $0.visibleRect.intersection($0.bounds)) })
    if scanning {
        // The letters' own glyph ids are not live while shown (ContentView
        // draws into its pixel buffers), so the glyph needle's control is
        // SelfScan's CTLine of the marker, as in V39.
        let h = SelfScan.scan(), needle = SelfScan.needleControl()
        check("while shown: the marker is in memory (positive control)", h.u16 > 0, "\(h)")
        check("while shown: the glyph needle sees a live line of the marker (positive control)", needle > 0,
              "needle=\(needle)")
    }
    // Wider window: only the letter pane grows, and every document view
    // follows its scroll view's width.
    let before = lists.map { $0.frame.width }, lettersBefore = letters.frame.width
    let grown = 1100 - window.contentView!.frame.width
    window.setContentSize(NSSize(width: 1100, height: 640))
    mail.view.layoutSubtreeIfNeeded()
    let fits = (lists + [letters]).allSatisfy { $0.frame.width == $0.superview?.bounds.width }
    check("resize: the lists keep their width, the documents follow their scroll views",
          lists.map { $0.frame.width } == before && fits && letters.frame.width == lettersBefore + grown,
          "lists \(before) -> \(lists.map { $0.frame.width }), letters \(lettersBefore) -> \(letters.frame.width)")
    // A divider dragged to the right edge, then a window narrower than the
    // panes: no pane gets narrower than its minimum, the window grows back
    // to their sum, and no letter is laid out narrower than SecureTextView's
    // minimum (at width 1 every unit is a line of its own: seconds per
    // resize step for a long letter).
    let split = all(NSSplitView.self, in: mail.view).first!
    func paneWidths() -> [CGFloat] { split.subviews.map { $0.frame.width } }
    func atLeastMinimum(_ w: [CGFloat]) -> Bool { zip(w, MailViewController.minPaneWidths).allSatisfy { $0 >= $1 } }
    let placed = paneWidths()
    split.setPosition(split.bounds.width, ofDividerAt: 1)
    let dragged = paneWidths()
    window.setContentSize(NSSize(width: 480, height: 640))
    window.layoutIfNeeded()
    let narrow = paneWidths(), narrowWindow = window.contentView!.frame.width
    let minWindow = MailViewController.minPaneWidths.reduce(0, +) + 2 * split.dividerThickness
    check("a divider dragged right, a narrow window: every pane keeps its minimum width, the window their sum",
          atLeastMinimum(dragged) && atLeastMinimum(narrow) && narrowWindow >= minWindow,
          "dragged \(dragged), narrow \(narrow), window \(narrowWindow)")
    let probe = SecureTextView()
    probe.show(fake([String(repeating: paragraph, count: 3)]))
    let atMinimum = probe.height(forWidth: SecureTextView.minTextWidth + 2 * SecureTextView.inset)
    check("SecureTextView: a narrower width lays out at the minimum text width",
          probe.height(forWidth: 1) == atMinimum, "\(probe.height(forWidth: 1)) vs \(atMinimum)")
    probe.clear()
    window.setContentSize(NSSize(width: 1100, height: 640))
    split.setPosition(placed[0], ofDividerAt: 0)
    split.setPosition(placed[0] + split.dividerThickness + placed[1], ofDividerAt: 1)
    window.layoutIfNeeded()
    guard posting else { return checkScrolledPools(then: sendAndLock) }
    window.makeFirstResponder(lists[1])
    guard CGPreflightPostEventAccess(), let down = CGEvent(keyboardEventSource: nil, virtualKey: 125, keyDown: true),
          let up = CGEvent(keyboardEventSource: nil, virtualKey: 125, keyDown: false) else {
        print("skip --post: this process may not post events")
        return checkScrolledPools(then: sendAndLock)
    }
    down.postToPid(getpid())
    up.postToPid(getpid())
    DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
        check("a posted ↓ key did not move the thread selection", lists[1].selected == 0)
        checkScrolledPools(then: sendAndLock)
    }
}

/// Only content views in sight hold pixel buffers (ContentView): the views
/// shown at the top of the letter pane give their pools back, zeroed, once
/// scrolled out of sight, and a view keeps one pool while it scrolls into
/// sight, 10 pt per display pass. A thread holds one letter since Phase 3,
/// so the view that leaves and comes back is the letter's header: the pane
/// scrolls down until the header is out of sight, then back up.
func checkScrolledPools(then next: @escaping () -> Void) {
    let clip = letters.enclosingScrollView!.contentView
    func inSight(_ v: ContentView) -> Bool { !v.visibleRect.intersection(v.bounds).isEmpty }
    let header = all(ContentView.self, in: letters).first { !($0 is SecureTextView) }!
    let out = header.frame.maxY + 20, steps = 6
    let ys = [0, out] + (1...steps).map { out - CGFloat($0 * 10) }
    var top: [ContentView] = [], pools: [[CVPixelBuffer]] = [], drawn = false
    var left: [(ContentView, [CVPixelBuffer])] = [], gone = false, entering: CVPixelBuffer?, kept = true
    let room = letters.frame.height - clip.bounds.height >= out
    var i = 0
    // Each tick checks the frame the last scroll drew, then scrolls on.
    _ = Timer.scheduledTimer(withTimeInterval: 0.05, repeats: true) { timer in
        switch i {
        case 0: break
        case 1:
            top = all(ContentView.self, in: letters).filter(inSight)
            pools = top.map { $0.pool }
            drawn = !pools.isEmpty && pools.allSatisfy { $0.contains(where: hasPixels) }
        case 2:
            left = zip(top, pools).filter { !inSight($0.0) }
            gone = !left.isEmpty && left.allSatisfy { $0.0.pool.isEmpty && !$0.1.contains(where: hasPixels) }
        default:
            guard inSight(header) else { break }
            if let entering { kept = kept && header.pool.first === entering } else { entering = header.pool.first }
        }
        guard i < ys.count else {
            timer.invalidate()
            check("scrolled out of sight: a content view holds no pixel buffers, and its old ones are zero",
                  room && drawn && gone,
                  "room=\(room), drawn=\(drawn), left \(left.count), holding \(left.filter { !$0.0.pool.isEmpty }.count), "
                      + "with pixels \(left.filter { $0.1.contains(where: hasPixels) }.count)")
            check("scrolling in: a view keeps one pool", entering != nil && kept && inSight(header),
                  "header \(header.frame), pane \(clip.bounds)")
            return next()
        }
        clip.scroll(to: NSPoint(x: 0, y: ys[i]))
        i += 1
    }
}

/// Ekko sends a new letter; it arrives with the next sync tick, and the
/// thread pane keeps its selection and the letter pane its scroll position.
/// Then the lock sequence.
func sendAndLock() {
    letters.scroll(NSPoint(x: 0, y: 200))
    let scrolled = letters.visibleRect.minY
    do {
        try ekkoUser.send(to: meAtEkko, subject: fake(["Et nytt brev ", nil]), body: letterBody(2))
    } catch {
        check("Ekko's new letter is sent", false)
    }
    ekkoUser.session.brev.lock()
    DispatchQueue.main.asyncAfter(deadline: .now() + MailViewController.syncInterval + 1) {
        check("after sync: three threads, the selected one kept by id", lists[1].count == 3 && lists[1].selected == 1,
              "count=\(lists[1].count) selected=\(String(describing: lists[1].selected))")
        check("the kept thread's letter is shown again", shownLetters() == 1)
        check("after sync: the letter pane keeps its scroll position",
              scrolled > 0 && letters.visibleRect.minY == scrolled, "\(scrolled) -> \(letters.visibleRect.minY)")
        snapshot(mail.view, "after-sync.png")
        // Every content view the lock reaches, including the letters that
        // letters.clear() removes from the window. Their buffers are kept
        // here: a view that leaves its window gives its pool back.
        let views = all(ContentView.self, in: mail.view)
        let buffers = views.flatMap { $0.pool }
        check("before lock: content views hold pixels (control)", buffers.contains(where: hasPixels))
        lock.lock(.manual)
        checkLocked("lock", views, buffers)
        // Brev releases the mail screen at the end of this run-loop turn;
        // this host keeps its views alive, which makes the scan stricter.
        // The lock sequence ran SelfScan's needle control at its start.
        if scanning {
            let h = SelfScan.scan()
            check("after lock: no copy (UTF-8, UTF-16, glyphs)", h.u8 == 0 && h.u16 == 0 && h.glyph == 0, "\(h)")
            checkScribbled()
        }
        snapshot(window.contentView!, "locked.png")
        checkHardenedChildren()
        finish()
    }
}

/// SelfScan's scribble probe, as the lock sequence logs it for V39: a freed
/// 32 KiB block keeps no copy of its pattern, which it shows while allocated.
func checkScribbled() {
    let p = SelfScan.scribbleProbe()
    check("after lock: freed memory is scribbled (the probe's freed block keeps nothing; seen while allocated)",
          p.live > 0 && p.left == 0, "\(p)")
}

/// What the lock sequence leaves, whatever ran it: `views` and `buffers`
/// were taken while the letters were shown (a view that leaves its window
/// gives its pool back, so they are kept here).
func checkLocked(_ label: String, _ views: [ContentView], _ buffers: [CVPixelBuffer]) {
    check("\(label): every pixel buffer of every content view is zero",
          !buffers.contains(where: hasPixels) && views.allSatisfy { !$0.pool.contains(where: hasPixels) },
          "\(buffers.filter(hasPixels).count) of \(buffers.count) buffers")
    check("\(label): no content view's layer shows a pixel", !views.contains(where: showsPixels))
    check("\(label): lists and letters wiped", lists.allSatisfy { $0.count == 0 } && letters.isEmpty)
    check("\(label): the session is locked", session.brev.isLocked())
    check("\(label): the lock screen replaced the mail screen", window.root.child is NoticeViewController)
}

/// A sheet and a child window made with the default sharing type get
/// Hardening's settings from the window they join (CLAUDE.md §3.2).
func checkHardenedChildren() {
    let sheet = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 200, height: 80), styleMask: [.titled],
                         backing: .buffered, defer: false)
    let child = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 120, height: 40), styleMask: [.borderless],
                         backing: .buffered, defer: false)
    for w in [sheet, child] { w.isReleasedWhenClosed = false }
    window.beginSheet(sheet)
    window.addChildWindow(child, ordered: .above)
    check("a sheet and a child window get Hardening's settings",
          [sheet, child].allSatisfy { $0.sharingType == .none && !$0.isRestorable && $0.isExcludedFromWindowsMenu })
    window.endSheet(sheet)
    window.removeChildWindow(child)
    child.orderOut(nil)
}

application.run()
