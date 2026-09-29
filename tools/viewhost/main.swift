// main.swift — ViewHost: Brev's mail window with fake letters, for tests.
//
// A test app, never linked into Brev.app (tools/viewhost/build.sh builds it
// from app/Sources/{Shared,App,UI} and Keys/Attestor.swift). It needs no
// keychain and no Touch ID:
// the stores live in a temporary folder, each DEK is wrapped to a software
// P-256 key and each identity key is a software key, as in the CLI harness
// (app/Tests). It starts its own relay (brev-relay, built by build.sh, on
// 127.0.0.1 with a port the OS picks and a database in the temporary folder;
// stopped at the end) and makes three users: this host ("testvert") and the
// contacts Ekko and Speil ("ekko", "speil"), which live in this process
// without a window. The host registers with a root invite (the relay's
// `invite` command, run here) and invites Ekko and Speil with its own
// codes, so all are approved and verified contacts (docs/PHASE4_DESIGN.md
// §3.4). The host sends fake, non-secret letters to Ekko and
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
// and secure event input is checked → ready → (hold) → the environment
// sample and design (EnvironmentProbe) are checked → ⌘↩ sends through the relay → Ekko
// fetches it → Escape discards a second letter → the lock
// sequence discards a third → exit.
// With --triggers: the real lock triggers (LockController.start) and the
// real unlock bookkeeping, with this app active; switch: an unlock in
// flight, the Finder becomes active (no lock), this app is active again and
// the unlock ends, the Finder becomes active (the lock sequence runs);
// idle: no input, the Brev menu opened shortly before the limit, the lock
// sequence runs after 300 s and closes it. The lock's log line is read back
// from this process's log. Then exit.
// With --contacts (docs/PHASE3_DESIGN.md §6, docs/PHASE4_DESIGN.md §6;
// docs/VERIFY.md V67, V68, V69, V72, V73, V79): the host starts
// unregistered; its contact ($ADDR_B), an inviter ($ADDR_C) and two askers
// ($ADDR_D, $ADDR_E) register with root invites. ContactPasteboard uses a
// named pasteboard (no pasteboard alert, the user's own untouched) that
// records how each write began and what the text was set beside, with its
// self-clear shortened to 1.5 s; "another app's copy" is this host writing
// to that pasteboard. The address page's invite step (the real
// AddressViewController, signing with this host's software key) → ⌘V of a
// refused text, ⌘V with a source PID, ⌘⇧V and ⌘⌥V paste nothing → ⌘V
// pastes an unknown code: Return, one /v1/invites/open 404 → ⌘V pastes
// the root code → Fortsett refuses a click made in code and an AX press →
// ready → (hold) → Return: the address step → the address marker $ADDR_A
// typed by key-downs → Registrer refuses the same → ready → (hold) → Return
// registers → the mail screen and its header → Kontakter opens the real
// ContactSheet: no responder answers copy:, cut:, paste:, pasteAsPlainText:
// or selectAll: → Kopier adressen min, Lag invitasjon and Kopier koden
// refuse the same → Kopier adressen min (called as a human's press): the
// address, concealed and transient, on the pasteboard (for this Mac only,
// the text set after both markers; the same for Kopier koden) → another
// app's copy survives the self-clear → Lag invitasjon: a code on two lines
// → Kopier koden → the self-clear empties the pasteboard → ⌘V of
// $ADDR_C's code with one fingerprint character changed: InviteMismatch
// after one /v1/invites/open, no redeem (V77) → ⌘V of the right code:
// «Invitert av:»
// → Legg til and Godta invitasjonen refuse the same → ready → (hold) →
// Godta invitasjonen redeems it («Bekreftet med invitasjon») → Kontakter,
// $ADDR_B typed, Return asks it (request.sent) → Escape («Venter på svar»)
// → $ADDR_D and $ADDR_E ask the host → the next sync lists them under
// «Forespørsler» → ↓ selects the first: the header shows it with Godta and
// Avslå, which refuse the same → ready → (hold) → Godta (as a human's
// press) → the second, Avslå → Blokker on $ADDR_D refuses the same, then
// blocks («Blokkert») → the relay releases $ADDR_B and a new identity
// registers it with a root invite → Send in a compose sheet finds the
// changed key → Escape → the header shows the warning, both codes and Godta
// ny kode, which refuses the same → ConfirmSheet → its Godta refuses the
// same → ready → (hold) → Godta accepts the shown code → a ContactSheet with
// a code, $ADDR_B typed and the address copied → the lock sequence: all of
// it wiped, the pasteboard kept → the self-clear empties it while locked →
// exit. At each step: the windows' hardening, the relay's trace (the relay
// runs with --trace: no request that a refused press would have made), the
// in-process accessibility tree (no address marker, identity code or
// invite code; control: the fixed labels), and the protected layer
// (contact data in its buffers, draw(_:) and cacheDisplay empty; the layer's
// displayed frame too, unless the screen is locked or the display sleeps,
// which a "skip layer" line says).
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
//                 [--triggers switch|idle] [--contacts]
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
//                   .none), for the compose sheet too (with --contacts, and
//                   --unprotected, for every sheet): only the protected
//                   layer keeps content out
//   --unprotected   preventsCapture = false on every content view's layer,
//                   also those made later, the compose sheet's and, with
//                   --contacts, the address page's and the sheets'; with
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
//   --contacts      the address page's, the contact sheet's, the
//                   requests' and the key change's timeline instead
//                   (above); each "ready" line names its stage (invite,
//                   address, contacts, request, accept)
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
let contactsMode = args.contains("--contacts")
let triggers = value("--triggers")
if let triggers, !["switch", "idle"].contains(triggers) {
    print("usage: --triggers switch|idle")
    exit(2)
}
/// Brev's idle limit in seconds, and how often its timer looks.
let idleLimit = Double(LockState.idleLimitNanos) / 1e9, idleTick = LockState.idleCheckInterval

// MARK: - Fake letters (fake(_:), the relay and User: tools/fixture/Fixture.swift)

let paragraph = "Kjære deg, dette er et testbrev med æ, ø og å, skrevet av testverten. Det har mange ord, "
    + "så linjene brytes ved mellomrom når vinduet er smalt. "
let longWord = String(repeating: "x", count: 600)

func letterBody(_ n: Int) -> SecretText {
    fake(["Hei!\n\n", String(repeating: paragraph, count: n), "\n\n", nil, " ", longWord, "\n\nHilsen\ntestverten 😀"])
}

// MARK: - Looking at the views

/// The contact address markers of docs/VERIFY.md ($ADDR_A to $ADDR_D, and
/// one more of the same kind): the host's own address and its contacts',
/// with --contacts. Every one starts with `addrPrefix`.
let addrA = "brev-secret-me", addrB = "brev-secret-peer", addrC = "brev-secret-new"
let addrD = "brev-secret-last", addrE = "brev-secret-more"
let addrPrefix = "brev-secret-"

/// Whether `v` draws through a layer with preventsCapture = true.
func protected(_ v: ContentView) -> Bool {
    v.protectedLayer.preventsCapture && v.protectedLayer.superlayer === v.layer && v.wantsUpdateLayer
}

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
try! FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                         attributes: [.posixPermissions: 0o700])
var relayProcess: Process?
/// The contacts mode's pasteboard: a named one (ContactPasteboard.board),
/// so no pasteboard alert can ask and the user's own is never touched;
/// released at the end.
var namedBoard: RecordingBoard?

/// A named pasteboard that records how each new contents began (a clear,
/// or a prepare with its options) and which types it held each time plain
/// text was set: ContactPasteboard's write must be for this Mac only (no
/// Universal Clipboard) and set the text after both markers (WP5 review).
final class RecordingBoard: NSPasteboard {
    private(set) var starts: [String] = []
    private(set) var beforeText: [Set<String>] = []

    func reset() {
        starts = []
        beforeText = []
    }

    /// Since `reset()`: one write, begun with prepareForNewContents(with:
    /// .currentHostOnly), whose plain text was set once, with both markers
    /// already there.
    var wroteHostOnlyMarkersFirst: Bool {
        let markers = Set(ContactPasteboard.markers.map(\.rawValue))
        return starts == ["hostOnly"] && beforeText.count == 1 && beforeText[0].isSuperset(of: markers)
    }

    @discardableResult
    override func clearContents() -> Int {
        starts.append("clear")
        return super.clearContents()
    }

    @discardableResult
    override func prepareForNewContents(with options: NSPasteboard.ContentsOptions = []) -> Int {
        starts.append(options == .currentHostOnly ? "hostOnly" : "prepare \(options.rawValue)")
        return super.prepareForNewContents(with: options)
    }

    @discardableResult
    override func declareTypes(_ newTypes: [NSPasteboard.PasteboardType], owner newOwner: Any?) -> Int {
        starts.append("declare")
        return super.declareTypes(newTypes, owner: newOwner)
    }

    @discardableResult
    override func setData(_ data: Data?, forType dataType: NSPasteboard.PasteboardType) -> Bool {
        if dataType == .string { beforeText.append(Set((types ?? []).map(\.rawValue))) }
        return super.setData(data, forType: dataType)
    }
}
func finish() -> Never {
    relayProcess?.terminate()
    relayProcess?.waitUntilExit()
    namedBoard?.releaseGlobally()
    try? FileManager.default.removeItem(at: dir)
    print(failures == 0 ? "PASS" : "FAIL: \(failures) check(s)")
    exit(failures == 0 ? 0 : 1)
}

// A safety net: the host never outlives its run by much.
DispatchQueue.main.asyncAfter(deadline: .now() + hold * (contactsMode ? 6 : 1) + (contactsMode ? 150 : 60)
                              + (triggers == "idle" ? idleLimit + idleTick + 30 : 0)) {
    check("finished in time", false)
    finish()
}

/// The relay's --trace lines, with --contacts.
let relayTrace = RelayTrace()
guard let relayRun = startRelay(in: dir, trace: contactsMode ? relayTrace : nil) else {
    check("the relay starts on 127.0.0.1 (build.sh builds it)", false)
    finish()
}
relayProcess = relayRun.0
let relayURL = relayRun.1
let me: User, ekkoUser: User
/// With --contacts: the users at $ADDR_C (an inviter), $ADDR_D and $ADDR_E
/// (two askers), each registered with a root invite.
var others: [User] = []
let session: Session
/// Ekko's local id here, and this host's at Ekko.
var ekko = Data(), meAtEkko = Data()
do {
    me = try User(in: dir.appendingPathComponent("testvert"), relay: relayURL)
    ekkoUser = try User(in: dir.appendingPathComponent("ekko"), relay: relayURL)
    session = me.session
    if contactsMode {
        for (name, address) in [("ekko", addrB), ("inviter", addrC), ("asker1", addrD), ("asker2", addrE)] {
            let user = name == "ekko" ? ekkoUser : try User(in: dir.appendingPathComponent(name), relay: relayURL)
            guard let root = rootInvite(in: dir) else { throw BrevError.InviteInvalid }
            defer { root.wipe() }
            try user.register(address, invite: root)
            if user !== ekkoUser { others.append(user) }
        }
    }
} catch {
    check("the users are made", false, "\((error as? BrevError).map { "\($0)" } ?? "other")")
    finish()
}
if !contactsMode {
    do {
        let speilUser = try User(in: dir.appendingPathComponent("speil"), relay: relayURL)
        guard let root = rootInvite(in: dir) else { throw BrevError.InviteInvalid }
        defer { root.wipe() }
        try me.register("testvert", invite: root)
        try me.invite(ekkoUser, as: "ekko")
        try me.invite(speilUser, as: "speil")
        // The host pins its invitees (their invited events), Ekko first.
        _ = try session.sync()
        ekko = try me.contact("ekko")
        let speil = try me.contact("speil")
        meAtEkko = try ekkoUser.contact("testvert")
        // Two threads with Ekko, one with Speil: a letter to each, and Ekko's
        // long letter, which arrives on sync.
        try me.send(to: ekko, subject: fake(["Det første brevet ", nil]), body: letterBody(3))
        try me.send(to: speil, subject: fake(["Et brev til Speil ", nil]), body: letterBody(1))
        try ekkoUser.send(to: meAtEkko, subject: fake(["Hei fra Ekko ", nil, "\nandre linje"]), body: letterBody(12))
        speilUser.session.brev.lock()
        let arrived = try session.sync().letters
        check("Ekko's letter arrives through the relay", arrived == 1, "\(arrived)")
        // Ekko takes the first letter now, so its sync after a compose send
        // counts only the composed letter.
        let atEkko = try ekkoUser.session.sync().letters
        check("the first letter arrives at Ekko", atEkko == 1, "\(atEkko)")
    } catch {
        check("fake letters sent", false, "\((error as? BrevError).map { "\($0)" } ?? "other")")
        finish()
    }
}

// In-process checks of every content view class.
let probeText = SecureTextView(frame: NSRect(x: 0, y: 0, width: 100, height: 40))
let probeList = SecureListView(style: .messages)
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
if !contactsMode { window.root.show(mail) }
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
if !contactsMode {
    mail.start()
    // Brev opens no letter by itself (docs/UI_REDESIGN.md §2.4): a human's
    // ↓ in the message list opens the newest, as the checks below expect.
    hardwareKey(125).map(mail.messageList.keyDown)
    // Every content view draws through a layer with preventsCapture = true.
    let contentViews = all(ContentView.self, in: mail.view)
    check("every content view has a protected layer", !contentViews.isEmpty && contentViews.allSatisfy(protected))
}
// The negative control reaches the letter views a reload makes later, too,
// and with --contacts the address page and every sheet (with --capturable,
// the sheets' sharing type too).
func unprotect() {
    let sheet = window.attachedSheet
    if capturable && contactsMode { sheet?.sharingType = .readOnly }
    let sheetViews = sheet?.contentView.map { all(ContentView.self, in: $0) } ?? []
    let screen = contactsMode ? window.contentView! : mail.view
    (all(ContentView.self, in: screen) + sheetViews).forEach { $0.protectedLayer.preventsCapture = false }
}
if unprotected {
    unprotect()
    _ = commonModeTimer(every: 0.05, unprotect)
}

lock.window = window
lock.session = session
lock.showLockScreen = { window.root.show(NoticeViewController(L10n.unlockTitle)) }
// Accepted input reaches Rust's idle clock, as AppDelegate wires it.
BrevApplication.noteActivity = { session.brev.noteActivity() }
// Unlocked, as LockController.endUnlock records it, without asking whether
// this (inactive) app is active; the idle timer and the triggers stay off.
// --triggers goes through LockController itself.
if triggers == nil {
    let generation = lock.state.beginUnlock()
    _ = lock.state.endUnlock(generation, succeeded: true, appActive: true)
}

/// The contacts list and the thread list (the requests list is
/// mail.requestList).
let lists = all(SecureListView.self, in: mail.view).filter { $0 !== mail.requestList }
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

/// "sent" or "closed" for each compose sheet that reported its end (a lock
/// reports none).
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

/// Nytt brev opens the real compose sheet, wired as AppDelegate wires it
/// (the signer is this host's software key instead of SignService).
func wireCompose() {
    mail.onNewLetter = { contact in
        let id = contact.id
        ComposeSheet.present(on: window, to: contact, session: session, keyOrigin: me.keyOrigin,
                             signer: me.signLetter) { thread in
            composeEvents.append(thread == nil ? "closed" : "sent")
            if let thread { mail.showSent(thread: thread, contact: id) } else { mail.reloadContacts(selecting: id) }
        }
    }
}

/// --compose: Nytt brev opens the real compose sheet on Ekko, wired as
/// AppDelegate wires it. Keys are key-downs made here with source PID 0,
/// delivered as AppKit delivers a real key. This app asks to be active, so
/// that the sheet is key and secure event input can go on.
func composeStart() {
    print("layout \(layoutID)")
    wireCompose()
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
    // What ⌘↩ hands Rust (EnvironmentProbe), in a real window: a software
    // key, which the test archive allows; the sheet's sample
    // and the design facts as this run set them up.
    let sample = EnvironmentProbe.sample(for: sheet), design = EnvironmentProbe.design()
    check("compose: Hand's sample and design: a software key; capture excluded unless --capturable, "
            + "--unprotected or --control; secure input as above; BrevApplication; opaque; no Copy, Cut or Paste",
          me.keyOrigin == .software
              && (sample.sharingNone && sample.preventsCapture) == !(capturable || unprotected || control)
              && sample.secureInput == wanted
              && design.inputFilter && design.axOpaque && design.pasteboardOff,
          "\(sample.sharingNone) \(sample.preventsCapture) \(sample.secureInput) \(design)")
    let threads = lists[1].count
    let buffers = views.flatMap { $0.pool }
    deliver(hardwareKey(36, .maskCommand), to: sheet)
    check("compose: ⌘↩ starts the send: the sheet stays, read-only, Send and Avbryt disabled",
          composeSheet() === sheet && sheet.sendButton?.isEnabled == false && !sheet.body.isEditable)
    waitFor(15, { composeSheet() == nil }) { closed in
        check("compose: the letter is sent: the sheet closes, the list is read again with the open letter kept "
                + "by its thread (the new one is not opened)",
              closed && composeEvents == ["sent"] && lists[1].count == threads + 1
                  && lists[1].selected == 1 && shownLetters() == 1,
              "events \(composeEvents), threads \(threads) -> \(lists[1].count), letters \(shownLetters())")
        check("compose: after the send the recipient, subject and body are wiped, their pixels zero, secure input off",
              sheet.recipient.name == nil && zeroed(sheet.subject.model.text) && zeroed(sheet.body.model.text)
                  && !buffers.contains(where: hasPixels) && secureInputOff() && !sheet.subject.hasFocus
                  && !sheet.body.hasFocus)
        sentSheet = sheet
        let fetched = try? ekkoUser.session.sync().letters
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
        let events = composeEvents
        lock.lock(.manual)
        check("lock: the compose sheet ended without sending or reporting a close, wiped, its pixels zero, secure input off",
              composeSheet() == nil && composeEvents == events && composeEvents.filter { $0 == "sent" }.count == 1
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

// MARK: - Addresses and contacts (--contacts)

/// An identity code as the header draws it: 6 groups of 5 of A–Z and 2–7.
let codePattern = try! NSRegularExpression(pattern: "[A-Z2-7]{5}( [A-Z2-7]{5}){5}")

/// Hardening.apply's settings (CLAUDE.md §3.2; V9, V67).
func hardened(_ w: NSWindow) -> Bool {
    w.sharingType == .none && !w.isRestorable && w.isExcludedFromWindowsMenu && w.tabbingMode == .disallowed
}

/// Every string the accessibility tree of `root` offers in this process, as
/// V11's dump reads it from outside: each element's value, title, label,
/// help, placeholder, role description and identifier, from `root` down its
/// accessibility children, and down every subview and content view too (a
/// superset of what AX reaches).
func axStrings(_ root: NSObject) -> [String] {
    let reads = ["accessibilityValue", "accessibilityTitle", "accessibilityLabel", "accessibilityHelp",
                 "accessibilityPlaceholderValue", "accessibilityRoleDescription", "accessibilityIdentifier"]
        .map(NSSelectorFromString)
    var out: [String] = []
    var seen = Set<ObjectIdentifier>()
    func call(_ o: NSObject, _ sel: Selector) -> Any? {
        o.responds(to: sel) ? o.perform(sel)?.takeUnretainedValue() : nil
    }
    func walk(_ o: NSObject, _ depth: Int) {
        guard depth < 64, seen.insert(ObjectIdentifier(o)).inserted else { return }
        out += reads.compactMap { call(o, $0).map { "\($0)" } }
        var next = (call(o, NSSelectorFromString("accessibilityChildren")) as? [NSObject]) ?? []
        if let v = o as? NSView { next += v.subviews }
        if let w = o as? NSWindow, let c = w.contentView { next.append(c) }
        next.forEach { walk($0, depth + 1) }
    }
    walk(root, 0)
    return out
}

/// V68's and V79's rule in process: the accessibility trees of `windows`
/// have no address marker, no identity code and no invite code ("brev1.");
/// `control`, a fixed label, is there.
func checkAX(_ label: String, _ windows: [NSWindow], control: String) {
    let strings = windows.flatMap { axStrings($0) }
    let leaks = strings.filter { s in
        s.contains(addrPrefix) || s.contains("brev1.")
            || codePattern.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) != nil
    }
    check("\(label): the accessibility tree has no address marker, identity code or invite code (control: a fixed label)",
          leaks.isEmpty && strings.contains(control), "\(leaks.count) leaking of \(strings.count)")
}

/// V13's rule in process: a click made in code and an AX press on `button`
/// and on its cell do nothing (HumanButton). The effect is checked after.
func pressRefused(_ button: NSButton?) -> Bool {
    guard let button else { return false }
    button.performClick(nil)
    return !button.accessibilityPerformPress() && !(button.cell?.accessibilityPerformPress() ?? true)
}

/// Whether cacheDisplay of `v` inside `rect` (its layer tree) puts ink
/// into the bitmap.
func cachesInk(_ v: NSView, _ rect: NSRect) -> Bool {
    guard !rect.isEmpty, let rep = v.bitmapImageRepForCachingDisplay(in: rect) else { return true }
    v.cacheDisplay(in: rect, to: rep)
    guard let data = rep.bitmapData else { return true }
    return UnsafeBufferPointer(start: data, count: rep.bytesPerPlane).contains { $0 != 0 }
}

/// Whether the window server shows frames now: not while the screen is
/// locked or the main display sleeps, when an AVSampleBufferDisplayLayer
/// displays none (seen on macOS 26.2 with nobody at the Mac), though its
/// view's buffers hold the pixels.
func framesShown() -> Bool {
    let current = CGSessionCopyCurrentDictionary() as? [String: Any]
    let locked = (current?["CGSSessionScreenIsLocked"] as? Bool) ?? false
    return !locked && CGDisplayIsAsleep(CGMainDisplayID()) == 0
}
var layerSkipNoted = false

/// Contact data only in the protected layer (V68): each of `views` draws
/// through a protected layer, holds pixels in its buffers and on its layer,
/// and gives cacheDisplay and draw(_:) nothing.
func checkProtected(_ label: String, _ views: [ContentView]) {
    let layer = framesShown()
    if !layer && !layerSkipNoted {
        layerSkipNoted = true
        print("skip layer: the screen is locked or the display sleeps, so no protected layer displays a frame; "
              + "the checks of the protected layer look at its buffers, draw(_:) and cacheDisplay only")
    }
    let parts = views.map { v -> [Bool] in
        let shown = v.visibleRect.intersection(v.bounds)
        return [protected(v), v.pool.contains(where: hasPixels), !layer || showsPixels(v), !drawInks(v, shown),
                !cachesInk(v, shown)]
    }
    check("\(label): pixels only through the protected layer (its buffers and layer hold them; cacheDisplay and draw(_:) none)",
          parts.allSatisfy { !$0.contains(false) },
          "protected, buffers, layer, draw, cache per view: \(parts.map { $0.map { $0 ? 1 : 0 } })")
}

/// Whether the host's own address is registered.
func registered() -> Bool {
    guard let m = try? session.me() else { return false }
    defer { m.address.wipe(); m.code.wipe() }
    return m.registered
}

/// The contacts: how many, and whether one has a changed key.
func contactState() -> (count: Int, changed: Bool) {
    guard let items = try? session.contacts() else { return (-1, false) }
    defer { items.forEach { $0.name.wipe() } }
    return (items.count, items.contains { $0.keyChanged })
}

/// `s`'s own identity code (35 ASCII bytes), as its own header shows it.
func ownCode(_ s: Session) -> [UInt8] {
    guard let m = try? s.me() else { return [] }
    defer { m.address.wipe(); m.code.wipe() }
    return m.code.withBytes { Array($0) }
}

/// Whether the drawn `text` is the code `code`.
func shows(_ text: SecretText?, _ code: [UInt8]) -> Bool {
    guard let text, code.count == 35, text.length == 35 else { return false }
    return (0..<35).allSatisfy { text.units[$0] == UInt16(code[$0]) }
}

/// Whether the drawn `text` is the address `address`.
func shows(_ text: SecretText?, _ address: String) -> Bool {
    let u = Array(address.utf16)
    guard let text, text.length == u.count else { return false }
    return (0..<u.count).allSatisfy { text.units[$0] == u[$0] }
}

/// Prints "ready <stage> …" and the rects of `views` for a driver (windows,
/// axdump --press), then calls `next` after the hold.
func announceStage(_ stage: String, _ views: [(String, NSView?)], then next: @escaping () -> Void) {
    let screenTop = NSScreen.screens.first?.frame.maxY ?? 0
    let f = window.frame
    print("ready \(stage) pid=\(getpid()) window=\(window.windowNumber) frame=\(Int(f.minX)),\(Int(screenTop - f.maxY)),\(Int(f.width)),\(Int(f.height))")
    for case let (name, v?) in views {
        guard let w = v.window else { continue }
        print("rect \(name) \(globalText(w.convertToScreen(v.convert(v.bounds, to: nil))))")
    }
    DispatchQueue.main.asyncAfter(deadline: .now() + hold, execute: next)
}

/// ContactPasteboard's self-clear, shortened from Brev's 60 s.
let boardLifetime: TimeInterval = 1.5
/// What ContactPasteboard writes: plain text, concealed, transient.
let writtenTypes: Set<String> = ["public.utf8-plain-text", "org.nspasteboard.ConcealedType",
                                 "org.nspasteboard.TransientType"]

/// Another app's copy: `bytes` as plain text on the pasteboard.
func copyElsewhere(_ bytes: [UInt8]) {
    guard let board = namedBoard else { return }
    board.clearContents()
    board.setData(Data(bytes), forType: .string)
}

/// The pasteboard's types, without the legacy name AppKit adds beside
/// plain text ("NSStringPboardType").
func boardTypes() -> Set<String> {
    Set((namedBoard?.types ?? []).map(\.rawValue)).subtracting(["NSStringPboardType"])
}
func boardText() -> [UInt8] { namedBoard?.data(forType: .string).map { Array($0) } ?? [] }
func boardCount() -> Int { namedBoard?.changeCount ?? -1 }

/// ⌘V (the V key by key code) into `w`'s focused field, from the hardware
/// or with `pid`.
func pasteKey(into w: NSWindow, _ flags: CGEventFlags = .maskCommand, pid: Int64 = 0) {
    deliver(hardwareKey(9, flags, pid: pid), to: w)
}

/// Whether `t` holds exactly the ASCII bytes `bytes`.
func holds(_ t: SecretText?, _ bytes: some Collection<UInt8>) -> Bool {
    guard let t, t.length == bytes.count else { return false }
    return zip(0..<t.length, bytes).allSatisfy { t.units[$0] == UInt16($1) }
}

/// Whether `code` is an invite code of the user with `address` and
/// identity code `identity` (35 bytes, as the header shows it; design
/// §3.1): `brev1.<address>.<fingerprint>.<secret>`, the fingerprint being
/// the identity code without spaces, in lower case.
func isInvite(_ code: [UInt8], of address: String, identity: [UInt8]) -> Bool {
    let head = Array("brev1.\(address).".utf8)
    let fingerprint = identity.filter { $0 != 0x20 }.map { $0 >= 0x41 && $0 <= 0x5A ? $0 + 0x20 : $0 }
    return code.count == head.count + 30 + 1 + 26 && code.starts(with: head) && fingerprint.count == 30
        && Array(code[head.count..<head.count + 30]) == fingerprint && code[head.count + 30] == 0x2E
}

func contactSheet() -> ContactSheet? { window.attachedSheet as? ContactSheet }

/// The edit actions no responder may answer under P1's variant (a).
let editActions = ["copy:", "cut:", "paste:", "pasteAsPlainText:", "selectAll:"]

/// --contacts: the address page first, as AppDelegate routes an unlocked
/// Brev without an address, at its invite step; Registrer signs with this
/// host's software key.
func contactsStart() {
    if scanning { print("skip --scan: --contacts shows no letters") }
    guard let board = RecordingBoard.withUniqueName() as? RecordingBoard else {
        check("contacts: a named pasteboard that records the writes", false)
        finish()
    }
    namedBoard = board
    ContactPasteboard.board = board
    ContactPasteboard.lifetime = boardLifetime
    wireCompose()
    let page = AddressViewController(session: session, signer: me.sign)
    page.onRegistered = {
        window.root.show(mail)
        mail.start()
    }
    window.root.show(page)
    page.start()
    later(0.3) { inviteStage(page) }
}

func inviteStage(_ page: AddressViewController) {
    guard let root = rootInvite(in: dir) else {
        check("invite step: a root invite for the host", false)
        finish()
    }
    let code = root.withBytes { Array($0) }
    root.wipe()
    let f = page.inviteField
    check("invite step: in the main window, with Hardening's settings (V79)", hardened(window))
    check("invite step: the invite field has focus and a protected layer; Fortsett shows, Registrer does not",
          window.firstResponder === f && protected(f) && page.nextButton?.isHidden == false
              && page.registerButton?.isHidden == true)
    checkOpaque("invite field (ContactField)", f)
    check("invite step: no responder from the field up answers " + editActions.joined(separator: " ") + " (P1's variant (a))",
          editActions.allSatisfy { !chainAnswers(window, NSSelectorFromString($0)) })
    // Another app's copy with a refused character; then the code, which a
    // ⌘V with a source PID, ⌘⇧V and ⌘⌥V leave on the pasteboard.
    copyElsewhere(Array("Hei, deg".utf8))
    pasteKey(into: window)
    let refused = f.model.text.length == 0
    copyElsewhere(code)
    let count = boardCount()
    pasteKey(into: window, pid: Int64(getpid()))
    window.sendEvent(hardwareKey(9, .maskCommand, pid: 1)!)
    pasteKey(into: window, [.maskCommand, .maskShift])
    pasteKey(into: window, [.maskCommand, .maskAlternate])
    let untouched = f.model.text.length == 0
    // A code the relay does not know: its secret's first character changed.
    var unknown = code
    unknown[6] = unknown[6] == 0x61 ? 0x62 : 0x61
    copyElsewhere(unknown)
    pasteKey(into: window)
    let pastedUnknown = holds(f.model.text, unknown)
    check("invite step: ⌘V pastes the pasteboard's text; a refused character, a ⌘V with a source PID, ⌘⇧V and ⌘⌥V paste nothing; reading writes nothing",
          refused && untouched && pastedUnknown && boardCount() == count + 1)
    let opens = relayTrace.count("/v1/invites/open"), opens200 = relayTrace.count("/v1/invites/open", 200)
    let opens404 = relayTrace.count("/v1/invites/open", 404)
    deliver(hardwareKey(36), to: window)
    waitFor(10, { relayTrace.count("/v1/invites/open") == opens + 1 && page.nextButton?.isEnabled == true }) { back in
        check("invite step: an unknown code: one /v1/invites/open 404, the step stays with the code in the field",
              back && relayTrace.count("/v1/invites/open", 404) == opens404 + 1 && page.registerButton?.isHidden == true
                  && holds(f.model.text, unknown))
        f.wipe()
        copyElsewhere(code)
        pasteKey(into: window)
        check("invite step: the root code pasted", holds(f.model.text, code))
        check("invite step: Fortsett refuses a click made in code and an AX press", pressRefused(page.nextButton))
        later(0.5) {
            check("invite step: so no /v1/invites/open, the step stays",
                  relayTrace.count("/v1/invites/open") == opens + 1 && page.registerButton?.isHidden == true)
            checkAX("invite step", [window], control: L10n.addressInviteTitle)
            checkProtected("invite step: the pasted code", [f])
            announceStage("invite", [("field", f.enclosingScrollView), ("next", page.nextButton)]) {
                check("invite step: the hold changed nothing (a driver's AX presses): no /v1/invites/open",
                      relayTrace.count("/v1/invites/open") == opens + 1 && page.registerButton?.isHidden == true)
                deliver(hardwareKey(36), to: window)
                waitFor(10, { page.registerButton?.isHidden == false }) { next in
                    check("invite step: Return checks the root code (one /v1/invites/open 200), wipes the field; the address step, its field focused, no inviter",
                          next && relayTrace.count("/v1/invites/open", 200) == opens200 + 1 && zeroed(f.model.text)
                              && window.firstResponder === page.field
                              && page.inviterView.lines.allSatisfy { $0 == nil })
                    later(0.3) { addressStage(page) }
                }
            }
        }
    }
}

func addressStage(_ page: AddressViewController) {
    check("address page: in the main window, with Hardening's settings (V67)", hardened(window))
    check("address page: the field has focus and a protected layer", window.firstResponder === page.field && protected(page.field))
    checkOpaque("address field", page.field)
    let probe = fake(["Q!"])
    let typedProbe = typeKeys(probe, into: window)
    probe.wipe()
    let folded = page.field.model.text.length == 1 && page.field.model.text.units[0] == 0x71
    deliver(hardwareKey(51), to: window)
    check("address page: key-downs type; Q becomes q, ! is refused, Delete removes q",
          typedProbe && folded && page.field.model.text.length == 0)
    let a = fake([addrA])
    let typed = typeKeys(a, into: window)
    a.wipe()
    check("address page: $ADDR_A typed by key-downs", typed && shows(page.field.model.text, addrA))
    // The other users' registrations are the only ones so far.
    let signs = me.signatures, registers = relayTrace.count("/v1/register")
    check("address page: Registrer refuses a click made in code and an AX press", pressRefused(page.registerButton))
    later(0.5) {
        check("address page: so no signature, no /v1/register, not registered, the page stays",
              registers == 1 + others.count && me.signatures == signs && relayTrace.count("/v1/register") == registers
                  && !registered() && window.root.child === page)
        checkAX("address page", [window], control: L10n.addressTitle)
        checkProtected("address page: the typed address", [page.field])
        announceStage("address", [("field", page.field.enclosingScrollView), ("register", page.registerButton)]) {
            check("address page: the hold changed nothing (a driver's AX presses): no signature, no /v1/register",
                  me.signatures == signs && relayTrace.count("/v1/register") == registers && window.root.child === page)
            deliver(hardwareKey(36), to: window)
            waitFor(10, { window.root.child === mail }) { shown in
                check("address page: Return registers: one signature, one /v1/register 201, the mail screen, the field wiped",
                      shown && me.signatures == signs + 1 && relayTrace.count("/v1/register", 201) == registers + 1
                          && relayTrace.count("/v1/register") == registers + 1 && registered()
                          && zeroed(page.field.model.text),
                      "shown=\(shown) signatures=\(me.signatures - signs) register=\(relayTrace.count("/v1/register"))")
                later(0.5, headerStage)
            }
        }
    }
}

func headerStage() {
    let h = mail.header
    check("bar: no contact yet, so Innboks and an empty bar: no address, code, warning or request (the own "
            + "address and code are on the Kontakter sheet since the redesign)",
          mail.selection == .inbox && h.addresses.lines[0] == nil && h.codes.lines[0] == nil && !h.showsKeyChange
              && !h.showsRequest && h.shownState == "")
    for (name, v) in [("addresses", h.addresses), ("codes", h.codes), ("new code", h.newCodeView)] {
        checkOpaque("bar \(name) (ContactTextView)", v)
    }
    checkOpaque("requests list (SecureListView)", mail.requestList)
    mail.newLetter(nil)
    check("bar: Nytt brev does nothing without a contact", window.attachedSheet == nil)
    checkAX("mail screen", [window], control: L10n.mailboxInbox)
    contactSheetStage()
}

/// Kontakter: the own address and Kopier adressen min, Lag invitasjon and
/// Kopier koden, and the pasteboard's self-clear.
func contactSheetStage() {
    mail.showContacts(nil)
    guard let sheet = contactSheet() else {
        check("contact sheet: Kontakter opens ContactSheet", false)
        finish()
    }
    check("contact sheet: Kontakter opens it, the field focused, with a protected layer",
          sheet.firstResponder === sheet.field && protected(sheet.field))
    mail.showContacts(nil)
    check("contact sheet: Kontakter does nothing while it is up", window.sheets.count == 1)
    check("contact sheet: Hardening's settings (V79)", hardened(sheet))
    for (name, v) in [("field (ContactField)", sheet.field), ("own address", sheet.ownAddress),
                      ("own code", sheet.ownCode), ("code", sheet.codeView),
                      ("inviter", sheet.inviterView)] as [(String, ContentView)] {
        checkOpaque("contact sheet \(name)", v)
    }
    check("contact sheet: row 1 shows the own address; no code, no inviter",
          shows(sheet.ownAddress.lines[0], addrA) && sheet.code == nil && !sheet.inviteOpened)
    check("contact sheet: no responder from the field up answers " + editActions.joined(separator: " ")
            + " (P1's variant (a)), and the environment report's pasteboardDisabled holds (design §5.5)",
          editActions.allSatisfy { !chainAnswers(sheet, NSSelectorFromString($0)) }
              && EnvironmentProbe.design().pasteboardOff)
    let count = boardCount(), invites = relayTrace.count("/v1/invites")
    let refused = pressRefused(sheet.copyAddressButton) && pressRefused(sheet.makeInviteButton)
        && pressRefused(sheet.copyCodeButton)
    later(0.5) {
        check("contact sheet: Kopier adressen min, Lag invitasjon and Kopier koden refuse a click made in code and an AX press: no pasteboard write, no /v1/invites, no code",
              refused && boardCount() == count && relayTrace.count("/v1/invites") == invites && sheet.code == nil)
        namedBoard?.reset()
        sheet.copyAddress(nil)   // as a human's press of Kopier adressen min
        check("Kopier adressen min: the pasteboard holds the own address as plain text, concealed and transient",
              boardTypes() == writtenTypes && boardText() == Array(addrA.utf8), "\(boardTypes())")
        check("Kopier adressen min: written for this Mac only (no Universal Clipboard), the text after both markers",
              namedBoard?.wroteHostOnlyMarkersFirst == true,
              "\(namedBoard?.starts ?? []) \(namedBoard?.beforeText ?? [])")
        copyElsewhere(Array("annen app".utf8))
        later(boardLifetime + 0.5) {
            check("self-clear: after the lifetime, a later copy by another app is left alone",
                  boardText() == Array("annen app".utf8))
            sheet.makeInvite(nil)   // as a human's press of Lag invitasjon
            waitFor(10, { sheet.code != nil && !sheet.busy }) { made in
                let code = sheet.code?.withBytes { Array($0) } ?? []
                let cut = 6 + addrA.utf8.count + 1
                check("Lag invitasjon: one /v1/invites 201, no Touch ID; the host's code on two lines (to the address, then the rest)",
                      made && relayTrace.count("/v1/invites", 201) == invites + 1 && me.signatures == 1
                          && isInvite(code, of: addrA, identity: ownCode(session))
                          && holds(sheet.codeView.lines[0], code[..<cut]) && holds(sheet.codeView.lines[1], code[cut...]))
                namedBoard?.reset()
                sheet.copyCode(nil)   // as a human's press of Kopier koden
                check("Kopier koden: the pasteboard holds the code as plain text, concealed and transient",
                      boardTypes() == writtenTypes && boardText() == code)
                check("Kopier koden: written for this Mac only (no Universal Clipboard), the text after both markers",
                      namedBoard?.wroteHostOnlyMarkersFirst == true,
                      "\(namedBoard?.starts ?? []) \(namedBoard?.beforeText ?? [])")
                checkAX("contact sheet with a code", [window, sheet], control: L10n.contactsTitle)
                checkProtected("contact sheet: the own address and the code", [sheet.ownAddress, sheet.codeView])
                later(boardLifetime + 0.5) {
                    check("self-clear: after the lifetime (60 s in Brev) the pasteboard is empty", boardTypes().isEmpty,
                          "\(boardTypes())")
                    inviteStageInSheet(sheet)
                }
            }
        }
    }
}

/// ContactField and Legg til with an invite code of another user's: one
/// with an edited fingerprint (V77), then the right one and Godta
/// invitasjonen.
func inviteStageInSheet(_ sheet: ContactSheet) {
    guard let inviter = others.first, let made = try? inviter.session.createInvite() else {
        check("contact sheet: the inviter makes a code", false)
        finish()
    }
    let code = made.withBytes { Array($0) }
    made.wipe()
    var edited = code
    let at = 6 + addrC.utf8.count + 1   // the fingerprint's first character
    edited[at] = edited[at] == 0x61 ? 0x62 : 0x61
    copyElsewhere(edited)
    pasteKey(into: sheet)
    let opens = relayTrace.count("/v1/invites/open"), opens200 = relayTrace.count("/v1/invites/open", 200)
    let redeems = relayTrace.count("/v1/invites/redeem"), lookups = relayTrace.count("/v1/lookup")
    check("contact sheet: ⌘V pastes a code into the field", holds(sheet.field.model.text, edited))
    let refused = pressRefused(sheet.addButton) && pressRefused(sheet.acceptInviteButton)
    later(0.5) {
        check("contact sheet: Legg til refuses a click made in code and an AX press: no /v1/invites/open, no /v1/lookup",
              refused && relayTrace.count("/v1/invites/open") == opens && relayTrace.count("/v1/lookup") == lookups
                  && !sheet.busy && !sheet.inviteOpened)
        deliver(hardwareKey(36), to: sheet)
        waitFor(10, { relayTrace.count("/v1/invites/open") == opens + 1 && !sheet.busy }) { done in
            check("wrong fingerprint (V77): one /v1/invites/open 200, then nothing: no inviter, no /v1/invites/redeem, no contact; the code stays in the field",
                  done && relayTrace.count("/v1/invites/open", 200) == opens200 + 1
                      && relayTrace.count("/v1/invites/redeem") == redeems && !sheet.inviteOpened
                      && contactState().count == 0 && holds(sheet.field.model.text, edited))
            sheet.field.wipe()
            copyElsewhere(code)
            pasteKey(into: sheet)
            deliver(hardwareKey(36), to: sheet)
            waitFor(10, { sheet.inviteOpened && !sheet.busy }) { opened in
                check("the right code: «Invitert av:» with the inviter's address and code (its own header's), Godta invitasjonen; the field wiped",
                      opened && shows(sheet.inviterView.lines[0], addrC)
                          && shows(sheet.inviterView.lines[1], ownCode(inviter.session)) && zeroed(sheet.field.model.text)
                          && sheet.acceptInviteButton?.isHidden == false)
                checkProtected("contact sheet: the inviter's address and code", [sheet.inviterView])
                checkAX("contact sheet with an inviter", [window, sheet], control: L10n.inviteFrom)
                check("contact sheet: Godta invitasjonen refuses a click made in code and an AX press",
                      pressRefused(sheet.acceptInviteButton))
                later(0.5) {
                    check("contact sheet: so no /v1/invites/redeem, the sheet stays",
                          relayTrace.count("/v1/invites/redeem") == redeems && contactSheet() === sheet)
                    let written = boardCount()
                    announceStage("contacts", [("field", sheet.field.enclosingScrollView),
                                               ("copyme", sheet.copyAddressButton), ("make", sheet.makeInviteButton),
                                               ("copycode", sheet.copyCodeButton), ("add", sheet.addButton),
                                               ("accept", sheet.acceptInviteButton)]) {
                        check("contact sheet: the hold changed nothing (a driver's AX presses): no /v1/invites/redeem, no pasteboard write, the sheet stays",
                              relayTrace.count("/v1/invites/redeem") == redeems && contactSheet() === sheet
                                  && boardCount() == written)
                        sheet.acceptInvite(nil)   // as a human's press of Godta invitasjonen
                        waitFor(10, { contactSheet() == nil }) { closed in
                            let h = mail.header
                            check("Godta invitasjonen: one /v1/invites/redeem 200, the sheet closes wiped; the inviter selected, «Bekreftet med invitasjon»",
                                  closed && relayTrace.count("/v1/invites/redeem", 200) == redeems + 1
                                      && contactState().count == 1 && shows(h.addresses.lines[0], addrC)
                                      && h.shownState == "verified" && zeroed(sheet.field.model.text) && sheet.code == nil
                                      && sheet.ownAddress.lines[0] == nil && sheet.ownCode.lines[0] == nil
                                      && sheet.codeView.lines.allSatisfy { $0 == nil }
                                      && sheet.inviterView.lines.allSatisfy { $0 == nil })
                            later(0.5, addByAddressStage)
                        }
                    }
                }
            }
        }
    }
}

/// Legg til with an address: a request, «Venter på svar».
func addByAddressStage() {
    mail.showContacts(nil)
    guard let sheet = contactSheet() else {
        check("contact sheet: opens again", false)
        finish()
    }
    let b = fake([addrB])
    let typed = typeKeys(b, into: sheet)
    b.wipe()
    let lookups = relayTrace.count("/v1/lookup"), asks = relayTrace.count("/v1/requests")
    deliver(hardwareKey(36), to: sheet)
    waitFor(10, { sheet.added != nil && !sheet.busy }) { done in
        check("Legg til an address: one /v1/lookup 200, one /v1/requests 202; the sheet stays (request.sent), the field wiped",
              typed && done && relayTrace.count("/v1/lookup", 200) == lookups + 1
                  && relayTrace.count("/v1/requests", 202) == asks + 1 && contactSheet() === sheet
                  && zeroed(sheet.field.model.text))
        deliver(hardwareKey(53), to: sheet)
        later(0.5) {
            let h = mail.header
            check("Escape closes the sheet; the new contact is selected, «Venter på svar»; line 2 its address and code, the code its own header shows (V61's rule)",
                  contactSheet() == nil && contactState().count == 2 && shows(h.addresses.lines[0], addrB)
                      && shows(h.codes.lines[0], ownCode(ekkoUser.session)) && h.shownState == "waiting"
                      && !h.showsKeyChange)
            checkProtected("header: both addresses and codes", [h.addresses, h.codes])
            checkAX("mail screen with contacts", [window], control: L10n.contactWaiting)
            requestsStage()
        }
    }
}

/// Two users ask the host; «Forespørsler»; Godta for the first, Avslå for
/// the second.
func requestsStage() {
    let h = mail.header
    for asker in others.dropFirst() {
        let a = fake([addrA])
        let asked = (try? asker.session.addContact(address: a)) != nil
        a.wipe()
        if !asked { check("requests: another user asks the host", false) }
    }
    waitFor(MailViewController.syncInterval + 7, { mail.requestList.count == 2 }) { listed in
        check("requests: the next sync lists both askers under «Forespørsler»; no contact added, none selected there",
              listed && contactState().count == 2 && mail.requestList.selected == nil)
        window.makeFirstResponder(mail.requestList)
        deliver(hardwareKey(125), to: window)   // ↓: the first, the oldest
        mail.newLetter(nil)
        check("requests: the first selected: the asker's address and code (its own header's), request.body, Godta and Avslå; no threads, Nytt brev does nothing",
              h.showsRequest && shows(h.addresses.lines[0], addrD) && shows(h.codes.lines[0], ownCode(others[1].session))
                  && lists[0].selected == nil && lists[1].count == 0 && window.attachedSheet == nil)
        let answers = relayTrace.count("/v1/events/answer")
        check("requests: Godta and Avslå refuse a click made in code and an AX press",
              pressRefused(h.approveButton) && pressRefused(h.declineButton))
        later(0.5) {
            check("requests: so no /v1/events/answer, both still listed",
                  relayTrace.count("/v1/events/answer") == answers && mail.requestList.count == 2)
            checkProtected("header: a request's address and code", [h.addresses, h.codes])
            checkAX("mail screen with a request selected", [window], control: L10n.requestBody)
            announceStage("request", [("header", h), ("godta", h.approveButton), ("avsla", h.declineButton)]) {
                check("requests: the hold changed nothing (a driver's AX presses): no /v1/events/answer",
                      relayTrace.count("/v1/events/answer") == answers && mail.requestList.count == 2)
                mail.answerSelected(approve: true)   // as a human's press of Godta
                waitFor(10, { mail.requestList.count == 1 && !h.showsRequest }) { done in
                    check("Godta: one /v1/events/answer 204, no Touch ID: the asker is a contact, selected, not waiting; one request left",
                          done && relayTrace.count("/v1/events/answer", 204) == answers + 1 && contactState().count == 3
                              && shows(h.addresses.lines[0], addrD) && h.shownState == "")
                    window.makeFirstResponder(mail.requestList)
                    deliver(hardwareKey(125), to: window)
                    let second = h.showsRequest && shows(h.addresses.lines[0], addrE)
                    mail.answerSelected(approve: false)   // as a human's press of Avslå
                    waitFor(10, { mail.requestList.count == 0 && !h.showsRequest }) { done in
                        check("Avslå: one more /v1/events/answer 204: the request is gone, no contact added",
                              second && done && relayTrace.count("/v1/events/answer", 204) == answers + 2
                                  && contactState().count == 3)
                        later(0.3, blockStage)
                    }
                }
            }
        }
    }
}

/// Blokker on the contact that was approved: one click.
func blockStage() {
    let h = mail.header
    guard let asker = try? me.contact(addrD) else {
        check("block: the approved asker is a contact", false)
        finish()
    }
    mail.reloadContacts(selecting: asker)
    let blocks = relayTrace.count("/v1/block")
    check("header: Blokker shows for a contact, and refuses a click made in code and an AX press",
          shows(h.addresses.lines[0], addrD) && h.blockButton?.isHidden == false && pressRefused(h.blockButton))
    later(0.5) {
        check("block: so no /v1/block, the contact not blocked", relayTrace.count("/v1/block") == blocks && h.shownState == "")
        mail.blockSelected()   // as a human's press of Blokker
        waitFor(10, { h.shownState == "blocked" }) { done in
            mail.newLetter(nil)
            check("Blokker: one /v1/block 204, no Touch ID: «Blokkert», Blokker gone, Nytt brev does nothing",
                  done && relayTrace.count("/v1/block", 204) == blocks + 1 && h.blockButton?.isHidden == true
                      && window.attachedSheet == nil)
            guard let peer = try? me.contact(addrB) else {
                check("block: back to $ADDR_B", false)
                finish()
            }
            mail.reloadContacts(selecting: peer)
            later(0.3, keyChangeStage)
        }
    }
}


/// The relay's operator frees $ADDR_B (`brev-relay release`), and a new
/// identity registers it with a root invite: the host's pinned key for it
/// has changed.
func replaceContact() -> User? {
    guard let path = relayBinary else { return nil }
    let release = Process()
    release.executableURL = URL(fileURLWithPath: path)
    release.arguments = ["release", "--db", dir.appendingPathComponent("relay.db").path, addrB]
    release.standardError = FileHandle.nullDevice
    guard (try? release.run()) != nil else { return nil }
    release.waitUntilExit()
    guard release.terminationStatus == 0, let user = try? User(in: dir.appendingPathComponent("ekko2"), relay: relayURL),
          let root = rootInvite(in: dir)
    else { return nil }
    defer { root.wipe() }
    guard (try? user.register(addrB, invite: root)) != nil else { return nil }
    return user
}

func keyChangeStage() {
    let h = mail.header
    guard let newPeer = replaceContact() else {
        check("key change: the relay releases $ADDR_B and a new identity registers it", false)
        finish()
    }
    let oldCode = ownCode(ekkoUser.session), newCode = ownCode(newPeer.session)
    let envelopes = relayTrace.count("/v1/envelopes"), signs = me.signatures
    mail.newLetter(nil)
    guard let compose = window.attachedSheet as? ComposeSheet else {
        check("key change: Nytt brev opens a compose sheet", false)
        finish()
    }
    // ⌘V reads no pasteboard outside ContactField (V73): not in the
    // compose sheet's fields, nor with a list focused.
    copyElsewhere(Array(addrB.utf8))
    pasteKey(into: compose)
    _ = compose.makeFirstResponder(compose.body)
    pasteKey(into: compose)
    window.makeFirstResponder(lists[0])
    pasteKey(into: window)
    check("key change: ⌘V pastes nothing into the compose sheet's subject and body, nor into the contacts list",
          compose.subject.model.text.length == 0 && compose.body.model.text.length == 0 && window.attachedSheet === compose)
    _ = compose.makeFirstResponder(compose.subject)
    deliver(hardwareKey(36, .maskCommand), to: compose)
    waitFor(10, { compose.sendButton?.isEnabled == true }) { back in
        check("key change: Send finds the changed key, keeps the sheet: no signature, no /v1/envelopes",
              back && window.attachedSheet === compose && me.signatures == signs
                  && relayTrace.count("/v1/envelopes") == envelopes)
        deliver(hardwareKey(53), to: compose)
        later(0.5) {
            check("key change: then the header shows the warning, the pinned code on line 2 and the new code",
                  window.attachedSheet == nil && h.showsKeyChange && shows(h.codes.lines[0], oldCode)
                      && shows(h.newCodeView.lines[0], newCode) && h.newCode?.withBytes({ Array($0) }) == newCode
                      && oldCode != newCode && contactState().changed)
            mail.newLetter(nil)
            check("key change: Nytt brev does nothing for this contact", window.attachedSheet == nil)
            check("key change: Godta ny kode refuses a click made in code and an AX press", pressRefused(h.acceptButton))
            later(0.5) {
                check("key change: so no sheet, the key still changed", window.attachedSheet == nil && contactState().changed)
                checkProtected("header: the pinned and the new code", [h.codes, h.newCodeView])
                acceptStage(h, newCode)
            }
        }
    }
}

func acceptStage(_ h: ContactBar, _ newCode: [UInt8]) {
    mail.acceptNewKey()
    guard let confirm = window.attachedSheet as? ConfirmSheet else {
        check("accept sheet: Godta ny kode opens ConfirmSheet", false)
        finish()
    }
    check("accept sheet: Hardening's settings (V67)", hardened(confirm))
    check("accept sheet: Godta refuses a click made in code and an AX press", pressRefused(confirm.okButton))
    later(0.5) {
        check("accept sheet: so the sheet stays, the key still changed", window.attachedSheet === confirm && contactState().changed)
        checkAX("accept sheet", [window, confirm], control: L10n.acceptConfirmTitle)
        announceStage("accept", [("header", h), ("accept", h.acceptButton), ("godta", confirm.okButton)]) {
            check("accept sheet: the hold changed nothing (a driver's AX presses): the sheet stays, the key still changed",
                  window.attachedSheet === confirm && contactState().changed)
            confirm.confirm(nil)   // as a human's press of Godta
            later(0.5) {
                check("accept: the shown code is now the contact's, no warning",
                      window.attachedSheet == nil && !contactState().changed && !h.showsKeyChange
                          && shows(h.codes.lines[0], newCode) && h.newCode == nil)
                mail.newLetter(nil)
                let reopened = window.attachedSheet is ComposeSheet
                if let compose = window.attachedSheet { deliver(hardwareKey(53), to: compose) }
                check("accept: Nytt brev opens a compose sheet again (Escape closes it)", reopened && window.attachedSheet == nil)
                later(0.5, contactsLock)
            }
        }
    }
}

/// The lock sequence with ContactSheet open: a code shown, $ADDR_B typed,
/// the own address just copied.
func contactsLock() {
    mail.showContacts(nil)
    guard let sheet = contactSheet() else {
        check("before lock: a contact sheet opens", false)
        finish()
    }
    sheet.makeInvite(nil)
    waitFor(10, { sheet.code != nil && !sheet.busy }) { made in
        let b = fake([addrB])
        let typed = typeKeys(b, into: sheet)
        b.wipe()
        sheet.copyAddress(nil)   // as a human's press of Kopier adressen min
        later(0.5) {
            let views = all(ContentView.self, in: mail.view) + all(ContentView.self, in: sheet.contentView!)
            let buffers = views.flatMap { $0.pool }
            check("before lock: the header and the sheet's own address, code and typed address hold pixels (control)",
                  made && typed && [sheet.field, sheet.ownAddress, sheet.codeView].allSatisfy { $0.pool.contains(where: hasPixels) }
                      && mail.header.addresses.pool.contains(where: hasPixels))
            lock.lock(.manual)
            check("lock: the contact sheet ended; its field, own address and code wiped; secure input off",
                  window.attachedSheet == nil && zeroed(sheet.field.model.text) && sheet.code == nil
                      && sheet.ownAddress.lines[0] == nil && sheet.codeView.lines.allSatisfy { $0 == nil } && secureInputOff())
            check("lock: the header's addresses and codes are wiped",
                  all(ContactTextView.self, in: mail.header).allSatisfy { $0.lines.allSatisfy { $0 == nil } }
                      && mail.header.newCode == nil)
            check("lock: every pixel buffer is zero, and no layer shows a pixel",
                  !buffers.contains(where: hasPixels) && !views.contains(where: showsPixels),
                  "\(buffers.filter(hasPixels).count) of \(buffers.count) buffers")
            check("lock: the session is locked and the lock screen shows",
                  session.brev.isLocked() && window.root.child is NoticeViewController)
            check("lock: the pasteboard keeps the copied address (the owner's rule: no clear at a lock)",
                  boardText() == Array(addrA.utf8) && boardTypes() == writtenTypes)
            later(boardLifetime + 0.5) {
                check("self-clear while locked: after the lifetime the pasteboard is empty", boardTypes().isEmpty)
                finish()
            }
        }
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

/// When the switch run's unlock began.
var switchStarted = Date()

/// --triggers switch: resigning active while an unlock is in flight does
/// not lock (the Touch ID panel may take activation), and says so in the
/// log (U4's measurement line); once unlocked, it runs the lock sequence.
func triggersSwitch() {
    becomeActive { active in
        check("switch: this app became active", active)
        guard active else { return triggersEnd() }
        let before = lock.state.generation
        let started = lock.beginUnlock()
        switchStarted = Date()
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
            let u4 = logged("touchid", since: switchStarted)
            check("switch: the log says resign active during Touch ID (unlock), once (U4's measurement line)",
                  u4 == ["resign active during Touch ID (unlock)"], "\(u4)")
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
} else if contactsMode {
    contactsStart()
} else {
    announceReady(then: mailChecks)
}

func mailChecks() {
    snapshot(mail.view, "unlocked.png")
    check("no button action ran during the hold (a driver's AX presses): no event, no sheet",
          events.isEmpty && window.attachedSheet == nil, "\(events)")
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
/// sight, 10 pt per display pass. The view that leaves and comes back is a
/// letter's header: the pane scrolls down until the header is out of sight,
/// then back up. Since the UI redesign a one-letter thread's pane holds only
/// the body (its header is the reading header, outside the scroll view), so
/// the check needs an older thread with more letters and says "skip" here.
func checkScrolledPools(then next: @escaping () -> Void) {
    let clip = letters.enclosingScrollView!.contentView
    func inSight(_ v: ContentView) -> Bool { !v.visibleRect.intersection(v.bounds).isEmpty }
    guard let header = all(ContentView.self, in: letters).first(where: { !($0 is SecureTextView) && !$0.isHidden })
    else {
        print("skip scrolled pools: the open thread has one letter, so its pane holds one content view")
        return next()
    }
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
