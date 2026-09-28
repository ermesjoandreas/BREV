// main.swift — ViewHost: Brev's mail window with fake letters, for tests.
//
// A test app, never linked into Brev.app (tools/viewhost/build.sh builds it
// from app/Sources/{Shared,App,UI}). It needs no keychain and no Touch ID:
// the stores live in a temporary folder and the DEK is wrapped to a software
// P-256 key, as in the CLI harness (app/Tests). It sends fake, non-secret
// letters to Ekko and Speil, lets them echo, and shows the real
// MailViewController in a hardened MainWindow without activating itself.
// Every letter carries the test marker of app/Tests/scan.c, built from its
// XORed bytes, so no String copy of it exists here.
//
// Timeline: ready → (hold) → checks, a wider window, a posted ↓ key, a new
// letter → the sync timer shows its echo → the real lock sequence → exit.
// Output is check names and counts only; "ready pid=<n> window=<n>
// frame=<x,y,w,h>" tells a driver when to run an AX dump, AX presses or a
// capture against the window during the hold.
//
// usage: ViewHost [--hold <s>] [--snapshot <dir>] [--capturable] [--scan] [--post]
//   --hold <s>      seconds to wait after ready before the checks (default 3)
//   --snapshot <d>  write unlocked.png, after-sync.png and locked.png (drawn
//                   offscreen with cacheDisplay; no screen capture)
//   --capturable    sharingType .readOnly, so screencapture can see the fake
//                   letters (the default keeps Hardening's .none)
//   --scan          scan this process for the marker before and after the
//                   lock (run with MallocScribble=1, as Brev runs)
//   --post          post a ↓ key to this process (CGEventPostToPid): the
//                   input filter must drop it

import AppKit
import CoreText
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
let scanning = args.contains("--scan")
let posting = args.contains("--post")

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

// MARK: - A session as the app makes it, with a software KEK

func makeSession(in dir: URL) throws -> Session {
    let dek = SecretBytes(capacity: 64)
    guard SecRandomCopyBytes(kSecRandomDefault, 32, dek.base) == errSecSuccess else { throw BrevError.Rng }
    dek.setCount(32)
    var err: Unmanaged<CFError>?
    let attrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                                kSecAttrKeySizeInBits as String: 256]
    guard let kek = SecKeyCreateRandomKey(attrs as CFDictionary, &err), let pub = SecKeyCopyPublicKey(kek)
    else { throw BrevError.Crypto }
    let wrapped = try Enclave.wrap(dek: dek, to: pub)
    let session = try Session.create(dir: dir.path, dek: dek, signingKey: Data(repeating: 4, count: 65))
    do {
        try Enclave.unwrap(wrapped, with: kek) { try session.brev.unlock(dek: $0) }
    } catch {
        session.brev.lock()
        throw error
    }
    return session
}

func send(_ session: Session, to contact: Data, subject: SecretText, body: SecretText) throws {
    defer { subject.wipe(); body.wipe() }
    _ = try session.send(to: contact, subject: subject, body: body)
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

func scanCounts() -> (u8: UInt64, u16: UInt64, glyph: UInt64) {
    var r = brev_scan_result()
    brev_scan(&r)
    return (r.utf8_hits, r.utf16_hits, r.glyph_hits)
}

/// The marker's glyph ids in the content font, XORed, as SelfScan does.
func setGlyphNeedle() {
    var chars = [UInt16](repeating: 0, count: 16), glyphs = [CGGlyph](repeating: 0, count: 16)
    for i in 0..<16 { chars[i] = UInt16(markerX[i] ^ 0x5A) }
    _ = CTFontGetGlyphsForCharacters(ContentView.contentFont, chars, &glyphs, 16)
    var x = glyphs.map { $0 ^ 0x5A5A }
    brev_scan_set_glyphs(x, 16)
    _ = chars.withUnsafeMutableBytes { memset_s($0.baseAddress!, 32, 0, 32) }
    _ = glyphs.withUnsafeMutableBytes { memset_s($0.baseAddress!, 32, 0, 32) }
    _ = x.withUnsafeMutableBytes { memset_s($0.baseAddress!, 32, 0, 32) }
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
func finish() -> Never {
    try? FileManager.default.removeItem(at: dir)
    print(failures == 0 ? "PASS" : "FAIL: \(failures) check(s)")
    exit(failures == 0 ? 0 : 1)
}
// A safety net: the host never outlives its run by much.
DispatchQueue.main.asyncAfter(deadline: .now() + hold + 60) {
    check("finished in time", false)
    finish()
}

let session: Session
/// The first contact (Ekko).
var ekko = Data()
do {
    session = try makeSession(in: dir)
    let contacts = try session.contacts()
    ekko = contacts[0].id
    // Two threads with Ekko, one with Speil; each echo arrives on sync.
    try send(session, to: ekko, subject: fake(["Det første brevet ", nil]), body: letterBody(3))
    try send(session, to: contacts[1].id, subject: fake(["Et brev til Speil ", nil]), body: letterBody(1))
    try send(session, to: ekko, subject: fake(["Hei fra testverten ", nil, "\nandre linje"]), body: letterBody(12))
    let echoed = try session.sync()
    check("the echoes arrive", echoed == 3, "\(echoed)")
    contacts.forEach { $0.name.wipe() }
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
window.center()
window.orderFrontRegardless()
mail.start()

lock.window = window
lock.session = session
lock.showLockScreen = { window.root.show(NoticeViewController(L10n.unlockTitle)) }
// Unlocked, as LockController.endUnlock records it, without asking whether
// this (inactive) app is active; the idle timer and the triggers stay off.
let generation = lock.state.beginUnlock()
_ = lock.state.endUnlock(generation, succeeded: true, appActive: true)

let lists = all(SecureListView.self, in: mail.view)
let letters = all(LetterStackView.self, in: mail.view).first!
func shownLetters() -> Int { all(SecureTextView.self, in: letters).count }
// The window's frame in global display coordinates (origin top left), for
// a driver's AX hit tests.
let screenTop = NSScreen.screens.first?.frame.maxY ?? 0
let f = window.frame
print("ready pid=\(getpid()) window=\(window.windowNumber) frame=\(Int(f.minX)),\(Int(screenTop - f.maxY)),\(Int(f.width)),\(Int(f.height))")

DispatchQueue.main.asyncAfter(deadline: .now() + hold) {
    snapshot(mail.view, "unlocked.png")
    check("no button action ran during the hold (a driver's AX presses)", events.isEmpty, "\(events)")
    check("two contacts, the first selected", lists.count == 2 && lists[0].count == 2 && lists[0].selected == 0)
    check("Ekko's two threads, the newest selected", lists[1].count == 2 && lists[1].selected == 0)
    check("its letter and the echo are shown", shownLetters() == 2)
    if scanning {
        setGlyphNeedle()
        let h = scanCounts()
        check("while shown: the marker is in memory (positive control)", h.u16 > 0, "\(h)")
    }
    // Wider window: only the letter pane grows, and every document view
    // follows its scroll view's width.
    let before = lists.map { $0.frame.width }, lettersBefore = letters.frame.width
    window.setContentSize(NSSize(width: 1100, height: 640))
    mail.view.layoutSubtreeIfNeeded()
    let fits = (lists + [letters]).allSatisfy { $0.frame.width == $0.superview?.bounds.width }
    check("resize: the lists keep their width, the documents follow their scroll views",
          lists.map { $0.frame.width } == before && fits && letters.frame.width == lettersBefore + 200,
          "lists \(before) -> \(lists.map { $0.frame.width }), letters \(lettersBefore) -> \(letters.frame.width)")
    guard posting else { return sendAndLock() }
    window.makeFirstResponder(lists[1])
    guard CGPreflightPostEventAccess(), let down = CGEvent(keyboardEventSource: nil, virtualKey: 125, keyDown: true),
          let up = CGEvent(keyboardEventSource: nil, virtualKey: 125, keyDown: false) else {
        print("skip --post: this process may not post events")
        return sendAndLock()
    }
    down.postToPid(getpid())
    up.postToPid(getpid())
    DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
        check("a posted ↓ key did not move the thread selection", lists[1].selected == 0)
        sendAndLock()
    }
}

/// A new thread with Ekko; its echo arrives with the next sync tick, and the
/// thread pane keeps its selection. Then the lock sequence.
func sendAndLock() {
    do {
        try send(session, to: ekko, subject: fake(["Et nytt brev ", nil]), body: letterBody(2))
    } catch {
        check("the new letter is sent", false)
    }
    DispatchQueue.main.asyncAfter(deadline: .now() + MailViewController.syncInterval + 1) {
        check("after sync: three threads, the selected one kept by id", lists[1].count == 3 && lists[1].selected == 1,
              "count=\(lists[1].count) selected=\(String(describing: lists[1].selected))")
        check("the kept thread's letters are shown again", shownLetters() == 2)
        snapshot(mail.view, "after-sync.png")
        lock.lock(.manual)
        check("lock: lists and letters wiped", lists.allSatisfy { $0.count == 0 } && letters.isEmpty)
        check("lock: the session is locked", session.brev.isLocked())
        check("lock: the lock screen replaced the mail screen", window.root.child is NoticeViewController)
        // Brev releases the mail screen at the end of this run-loop turn;
        // this host keeps its views alive, which makes the scan stricter.
        if scanning {
            let h = scanCounts()
            check("after lock: no copy (UTF-8, UTF-16, glyphs)", h.u8 == 0 && h.u16 == 0 && h.glyph == 0, "\(h)")
        }
        snapshot(window.contentView!, "locked.png")
        finish()
    }
}

application.run()
