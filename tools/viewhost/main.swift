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
// Timeline: ready → (hold) → checks, a wider window, a divider dragged right
// and a narrow window, a posted ↓ key, the letter pane scrolled down, a new
// letter → the sync timer shows its echo → the real lock sequence → exit.
// Output is check names and counts only; "ready pid=<n> window=<n>
// frame=<x,y,w,h>" tells a driver when to run an AX dump, AX presses or a
// capture against the window during the hold, and the "rect <name>
// <x,y,w,h>" lines after it (global points, origin top left) name the
// three panes and, with --control, the backdrop and the control window.
// SelfScan is compiled in with BREV_SELFSCAN, as in the Verify build: the
// lock sequence runs it, and --scan counts with it. The content views draw
// into the protected layer (ContentView, D-0034), so a capture shows their
// panes without content, and so do the snapshots below.
//
// usage: ViewHost [--hold <s>] [--frame <x,y,w,h>] [--control] [--snapshot <dir>]
//                 [--capturable] [--unprotected] [--scan] [--post]
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
//                   .none): only the protected layer keeps content out
//   --unprotected   preventsCapture = false on every content view's layer,
//                   also those made later; with --capturable, the negative
//                   control: a capture must see the fake letters
//   --scan          scan this process for the marker before and after the
//                   lock, with SelfScan's needle control while the letters
//                   are shown (run with MallocScribble=1, as Brev runs)
//   --post          post a ↓ key to this process (CGEventPostToPid): the
//                   input filter must drop it

import AppKit
import AVFoundation
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

/// Whether a pixel row of `buffer` holds a byte that is not 0.
func hasPixels(_ buffer: CVPixelBuffer) -> Bool {
    guard CVPixelBufferLockBaseAddress(buffer, .readOnly) == kCVReturnSuccess else { return true }
    defer { CVPixelBufferUnlockBaseAddress(buffer, .readOnly) }
    guard let base = CVPixelBufferGetBaseAddress(buffer) else { return true }
    let bytes = UnsafeRawBufferPointer(start: base, count: CVPixelBufferGetBytesPerRow(buffer) * CVPixelBufferGetHeight(buffer))
    return bytes.contains { $0 != 0 }
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
func unprotect() { all(ContentView.self, in: mail.view).forEach { $0.protectedLayer.preventsCapture = false } }
if unprotected {
    unprotect()
    _ = commonModeTimer(every: 0.05, unprotect)
}

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
mail.view.layoutSubtreeIfNeeded()
for (name, v) in zip(["contacts", "threads", "letters"], [lists[0], lists[1], letters] as [NSView]) {
    if let scroll = v.enclosingScrollView {
        print("rect \(name) \(globalText(window.convertToScreen(scroll.convert(scroll.bounds, to: nil))))")
    }
}
for (name, w) in zip(["backdrop", "control"], plainWindows) { print("rect \(name) \(globalText(w.frame))") }

DispatchQueue.main.asyncAfter(deadline: .now() + hold) {
    snapshot(mail.view, "unlocked.png")
    check("no button action ran during the hold (a driver's AX presses)", events.isEmpty, "\(events)")
    check("two contacts, the first selected", lists.count == 2 && lists[0].count == 2 && lists[0].selected == 0)
    check("Ekko's two threads, the newest selected", lists[1].count == 2 && lists[1].selected == 0)
    check("its letter and the echo are shown", shownLetters() == 2)
    // The shown letters are pixels in the protected layer's buffers, and
    // AppKit's own drawing of a letter view gets none.
    let bodies = all(SecureTextView.self, in: letters).filter { !$0.visibleRect.intersection($0.bounds).isEmpty }
    check("while shown: each visible letter's frame is in its buffers and on its layer",
          !bodies.isEmpty && bodies.allSatisfy { $0.pool.contains(where: hasPixels) && showsPixels($0) })
    if let body = bodies.first, case let shown = body.visibleRect.intersection(body.bounds),
       let rep = body.bitmapImageRepForCachingDisplay(in: shown) {
        body.cacheDisplay(in: shown, to: rep)
        let data = rep.bitmapData.map { UnsafeBufferPointer(start: $0, count: rep.bytesPerPlane) }
        check("cacheDisplay of a shown letter draws nothing", data.map { !$0.contains { $0 != 0 } } ?? false)
    }
    if scanning {
        // The letters' own glyph ids are not live while shown (ContentView
        // draws through a bitmap), so the glyph needle's control is
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
/// thread pane keeps its selection and the letter pane its scroll position.
/// Then the lock sequence.
func sendAndLock() {
    letters.scroll(NSPoint(x: 0, y: 200))
    let scrolled = letters.visibleRect.minY
    do {
        try send(session, to: ekko, subject: fake(["Et nytt brev ", nil]), body: letterBody(2))
    } catch {
        check("the new letter is sent", false)
    }
    DispatchQueue.main.asyncAfter(deadline: .now() + MailViewController.syncInterval + 1) {
        check("after sync: three threads, the selected one kept by id", lists[1].count == 3 && lists[1].selected == 1,
              "count=\(lists[1].count) selected=\(String(describing: lists[1].selected))")
        check("the kept thread's letters are shown again", shownLetters() == 2)
        check("after sync: the letter pane keeps its scroll position",
              scrolled > 0 && letters.visibleRect.minY == scrolled, "\(scrolled) -> \(letters.visibleRect.minY)")
        snapshot(mail.view, "after-sync.png")
        // Every content view the lock reaches, including the letters that
        // letters.clear() removes from the window.
        let views = all(ContentView.self, in: mail.view)
        check("before lock: content views hold pixels (control)", views.contains { $0.pool.contains(where: hasPixels) })
        lock.lock(.manual)
        check("lock: every pixel buffer of every content view is zero",
              views.allSatisfy { !$0.pool.contains(where: hasPixels) },
              "\(views.filter { $0.pool.contains(where: hasPixels) }.count) of \(views.count) views")
        check("lock: no content view's layer shows a pixel", !views.contains(where: showsPixels))
        check("lock: lists and letters wiped", lists.allSatisfy { $0.count == 0 } && letters.isEmpty)
        check("lock: the session is locked", session.brev.isLocked())
        check("lock: the lock screen replaced the mail screen", window.root.child is NoticeViewController)
        // Brev releases the mail screen at the end of this run-loop turn;
        // this host keeps its views alive, which makes the scan stricter.
        // The lock sequence ran SelfScan's needle control at its start.
        if scanning {
            let h = SelfScan.scan()
            check("after lock: no copy (UTF-8, UTF-16, glyphs)", h.u8 == 0 && h.u16 == 0 && h.glyph == 0, "\(h)")
        }
        snapshot(window.contentView!, "locked.png")
        checkHardenedChildren()
        finish()
    }
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
