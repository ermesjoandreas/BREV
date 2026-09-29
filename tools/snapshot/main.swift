// main.swift — Snapshot: Brev's screens drawn offscreen to PNG files.
//
// docs/UI_REDESIGN.md §5. A test app only (tools/snapshot/build.sh), never
// linked into Brev.app. It never shows a window: the activation policy is
// .prohibited, no window is ever ordered in, and observers abort the run at
// once if a window becomes key, main or visible, or the app active.
// Each scene is built once, drawn in light and dark (chrome PNG with the
// content views outlined, and a preview with the fake content drawn in by
// each view's own drawContent), and checked (§5.6); --check runs the
// checks only. Everything runs on fake data with software keys.

import AppKit
import Carbon.HIToolbox

setvbuf(stdout, nil, _IOLBF, 0)

// MARK: - Offscreen, always (§5.2)

let application = BrevApplication.shared
_ = application.setActivationPolicy(.prohibited)
Hardening.applyToApp()
let secureInputAtStart = IsSecureEventInputEnabled()

var failures = 0
func check(_ what: String, _ ok: Bool, _ detail: @autoclosure () -> String = "") {
    let d = ok ? "" : detail()
    let line = (ok ? "ok   " : "FAIL ") + what + (d.isEmpty ? "" : "  [\(d)]")
    print(line)
    report.append(line)
    if !ok { failures += 1 }
}
var report: [String] = []

/// A window became key, main or visible, or the app active: stop at once,
/// before anything else can happen on screen.
func abortShown(_ what: String) -> Never {
    print("FAIL offscreen: \(what); stopping at once")
    exit(1)
}
let center = NotificationCenter.default
for name in [NSWindow.didBecomeKeyNotification, NSWindow.didBecomeMainNotification] {
    center.addObserver(forName: name, object: nil, queue: nil) { _ in abortShown("a window became key or main") }
}
center.addObserver(forName: NSWindow.didChangeOcclusionStateNotification, object: nil, queue: nil) { n in
    if let w = n.object as? NSWindow, w.occlusionState.contains(.visible) { abortShown("a window became visible") }
}
center.addObserver(forName: NSApplication.didBecomeActiveNotification, object: nil, queue: nil) { _ in
    abortShown("the app became active")
}

/// The guard of §5.2, after every scene.
func guardOffscreen(_ scene: String) {
    let pid = Int(getpid())
    let info = (CGWindowListCopyWindowInfo(.optionOnScreenOnly, kCGNullWindowID) as? [[String: Any]]) ?? []
    let onScreen = info.contains { ($0[kCGWindowOwnerPID as String] as? Int) == pid }
    let ok = NSApp.windows.allSatisfy { !$0.isVisible } && !NSApp.isActive && !onScreen
    if !ok { abortShown("\(scene): a window is visible or on screen, or the app is active") }
}

// MARK: - Arguments

let args = Array(CommandLine.arguments.dropFirst())
func value(_ flag: String) -> String? {
    args.firstIndex(of: flag).flatMap { args.indices.contains($0 + 1) ? args[$0 + 1] : nil }
}
let checkOnly = args.contains("--check")
let outDir = value("--out").map { URL(fileURLWithPath: $0, isDirectory: true) }
let onlyScene = value("--scene")
let appearanceArg = value("--appearance") ?? "both"
guard ["light", "dark", "both"].contains(appearanceArg), checkOnly || outDir != nil else {
    print("usage: Snapshot (--out <dir> | --check) [--scene <name>] [--appearance light|dark|both]")
    exit(2)
}
let appearances: [(String, NSAppearance.Name)] = [("light", .aqua), ("dark", .darkAqua)]
    .filter { appearanceArg == "both" || appearanceArg == $0.0 }
if let outDir {
    try? FileManager.default.createDirectory(at: outDir, withIntermediateDirectories: true)
}

// MARK: - Data folder and relay

let dir = FileManager.default.temporaryDirectory.appendingPathComponent("brev-snapshot-\(getpid())")
if dir.standardizedFileURL.path.contains("/Library/Containers/no.brev.app") {
    print("FAIL the data folder would be Brev's container")
    exit(2)
}
try? FileManager.default.removeItem(at: dir)
try! FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                         attributes: [.posixPermissions: 0o700])
var relayProcess: Process?
func finish() -> Never {
    relayProcess?.terminate()
    relayProcess?.waitUntilExit()
    try? FileManager.default.removeItem(at: dir)
    NSApp.windows.forEach { $0.close() }
    guardOffscreen("exit")
    if let outDir {
        try? (report.joined(separator: "\n") + "\n").write(to: outDir.appendingPathComponent("report.txt"),
                                                          atomically: true, encoding: .utf8)
    }
    print(failures == 0 ? "PASS" : "FAIL: \(failures) check(s)")
    exit(failures == 0 ? 0 : 1)
}
guard let relayRun = startRelay(in: dir) else {
    check("the relay starts on 127.0.0.1 (build.sh builds it)", false)
    finish()
}
relayProcess = relayRun.0
let relayURL = relayRun.1

/// Runs the main run loop until `done` or `seconds` pass.
func spin(until done: () -> Bool, _ seconds: TimeInterval = 10) -> Bool {
    let end = Date(timeIntervalSinceNow: seconds)
    while !done() && Date() < end {
        _ = RunLoop.main.run(mode: .default, before: Date(timeIntervalSinceNow: 0.02))
    }
    return done()
}

// MARK: - Capture

func all<T: NSView>(_ type: T.Type, in view: NSView) -> [T] {
    var out: [T] = []
    if let v = view as? T { out.append(v) }
    for s in view.subviews { out += all(type, in: s) }
    return out
}

/// Whether a pixel row of `buffer` holds a byte that is not 0.
func hasPixels(_ buffer: CVPixelBuffer) -> Bool {
    guard CVPixelBufferLockBaseAddress(buffer, .readOnly) == kCVReturnSuccess else { return true }
    defer { CVPixelBufferUnlockBaseAddress(buffer, .readOnly) }
    guard let base = CVPixelBufferGetBaseAddress(buffer) else { return true }
    let bytes = UnsafeRawBufferPointer(start: base, count: CVPixelBufferGetBytesPerRow(buffer) * CVPixelBufferGetHeight(buffer))
    return bytes.contains { $0 != 0 }
}

/// `view` (and what it contains) drawn by cacheDisplay at 2×.
func capture(_ view: NSView) -> NSBitmapImageRep? {
    let size = view.bounds.size
    guard size.width >= 1, size.height >= 1,
          let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(size.width * 2),
                                     pixelsHigh: Int(size.height * 2), bitsPerSample: 8, samplesPerPixel: 4,
                                     hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
                                     bytesPerRow: 0, bitsPerPixel: 0)
    else { return nil }
    rep.size = size
    view.cacheDisplay(in: view.bounds, to: rep)
    return rep
}

func write(_ image: CGImage, _ name: String) {
    guard let outDir else { return }
    let rep = NSBitmapImageRep(cgImage: image)
    do {
        try rep.representation(using: .png, properties: [:])?.write(to: outDir.appendingPathComponent(name))
    } catch {
        check("\(name) written", false, "\(error)")
    }
}

/// The chrome PNG with every visible ContentView outlined and hatched, and
/// the preview PNG with the fake content drawn in by each view's own
/// drawContent (docs/UI_REDESIGN.md §5.5).
func render(_ root: NSView, _ name: String) {
    guard let rep = capture(root), let chrome = rep.cgImage else {
        return check("\(name): captured", false)
    }
    let w = chrome.width, h = chrome.height, s = CGFloat(w) / root.bounds.width
    let views = all(ContentView.self, in: root).filter { !$0.isHiddenOrHasHiddenAncestor }
    func context() -> CGContext {
        let ctx = CGContext(data: nil, width: w, height: h, bitsPerComponent: 8, bytesPerRow: 0,
                            space: CGColorSpace(name: CGColorSpace.sRGB)!,
                            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
        ctx.draw(chrome, in: CGRect(x: 0, y: 0, width: w, height: h))
        return ctx
    }
    /// A view's visible rect, and where it lies in `root` (unflipped points).
    func place(_ v: ContentView) -> (CGRect, CGRect)? {
        let visible = v.visibleRect.intersection(v.bounds)
        guard visible.width >= 1, visible.height >= 1 else { return nil }
        var r = v.convert(visible, to: root)
        if root.isFlipped { r.origin.y = root.bounds.height - r.maxY }
        return (visible, r)
    }
    let outline = context()
    for v in views {
        guard let (_, r) = place(v) else { continue }
        let px = CGRect(x: r.minX * s, y: r.minY * s, width: r.width * s, height: r.height * s)
        outline.saveGState()
        outline.clip(to: px)
        outline.setStrokeColor(NSColor.systemPink.withAlphaComponent(0.18).cgColor)
        outline.setLineWidth(s)
        var x = px.minX - px.height
        while x < px.maxX {
            outline.move(to: CGPoint(x: x, y: px.minY))
            outline.addLine(to: CGPoint(x: x + px.height, y: px.maxY))
            x += 10 * s
        }
        outline.strokePath()
        outline.restoreGState()
        outline.setStrokeColor(NSColor.systemPink.cgColor)
        outline.setLineWidth(s)
        outline.setLineDash(phase: 0, lengths: [3 * s, 2 * s])
        outline.stroke(px.insetBy(dx: s / 2, dy: s / 2))
    }
    if let image = outline.makeImage() { write(image, "\(name).png") }
    let preview = context()
    for v in views {
        guard let (visible, r) = place(v) else { continue }
        preview.saveGState()
        preview.translateBy(x: r.minX * s, y: r.maxY * s)
        preview.scaleBy(x: s, y: -s)
        preview.translateBy(x: -visible.minX, y: -visible.minY)
        preview.clip(to: visible)
        v.drawContent(in: preview, rect: visible)
        preview.restoreGState()
    }
    if let image = preview.makeImage() { write(image, "\(name)-preview.png") }
}

// MARK: - Fake world: users, letters, requests, a key change

/// Fake addresses (contact names are content: they show only in previews).
let hostAddress = "andreas", kariAddress = "kari-nordmann", olaAddress = "ola-hansen"
let ingridAddress = "ingrid-berg", perAddress = "per-olsen", liseAddress = "lise-dahl"
let fakeAddresses = [hostAddress, kariAddress, olaAddress, ingridAddress, perAddress, liseAddress, "ny-bruker"]
/// Fake subjects and bodies (Norwegian, long and short).
let subjects = ["Middag på lørdag?", "Bildene fra turen", "Takk for sist", "Nøklene til hytta",
                "Bursdagen til mor", "En ting til"]
let longBody = """
Hei Andreas!

Takk for en fin kveld sist. Jeg har tenkt mye på det vi snakket om, og jeg tror du har rett: \
vi burde ta den turen til Lofoten i sommer, før ungene blir for store til å gidde å bli med oss.

Jeg har sett på noen hytter i Reine og Hamnøy. De fleste er ledige i uke 28, men vi må bestemme \
oss snart. Si fra hva du synes, så booker jeg.

Ellers er alt vel her. Hagen står i full blomst, og katten har lært seg å åpne kjøkkenskapet. \
Vi får se hvor lenge det varer før hun finner fram til kattematen på egen hånd.

Klem fra Kari
"""
let shortBody = "Hei!\n\nHar du lyst til å komme på middag på lørdag klokka seks? Ta gjerne med deg noe å drikke.\n\nKari"
func body(_ text: String) -> SecretText { fake([text]) }

/// Registers `user` at `address` with a root invite.
func registerRoot(_ user: User, _ address: String) throws {
    guard let root = rootInvite(in: dir) else { throw BrevError.InviteInvalid }
    defer { root.wipe() }
    try user.register(address, invite: root)
}

/// The relay's operator frees `address`, and a new identity registers it.
func replaceIdentity(_ address: String) throws -> User {
    guard let path = Bundle.main.object(forInfoDictionaryKey: "BrevRelayBinary") as? String else {
        throw BrevError.NotFound
    }
    let release = Process()
    release.executableURL = URL(fileURLWithPath: path)
    release.arguments = ["release", "--db", dir.appendingPathComponent("relay.db").path, address]
    release.standardError = FileHandle.nullDevice
    try release.run()
    release.waitUntilExit()
    guard release.terminationStatus == 0 else { throw BrevError.NotFound }
    let user = try User(in: dir.appendingPathComponent("\(address)-2"), relay: relayURL)
    try registerRoot(user, address)
    return user
}

let host: User, kari: User, newUser: User, unregistered: User
var kariAtHost = Data()
do {
    host = try User(in: dir.appendingPathComponent("host"), relay: relayURL)
    kari = try User(in: dir.appendingPathComponent("kari"), relay: relayURL)
    let ola = try User(in: dir.appendingPathComponent("ola"), relay: relayURL)
    let ingrid = try User(in: dir.appendingPathComponent("ingrid"), relay: relayURL)
    try registerRoot(host, hostAddress)
    try host.invite(kari, as: kariAddress)
    try host.invite(ola, as: olaAddress)
    try host.invite(ingrid, as: ingridAddress)
    _ = try host.session.sync()
    kariAtHost = try host.contact(kariAddress)
    let olaAtHost = try host.contact(olaAddress)
    let hostAtKari = try kari.contact(hostAddress), hostAtOla = try ola.contact(hostAddress)
    try ola.send(to: hostAtOla, subject: fake([subjects[3]]), body: body("Hei!\n\nNøklene ligger under blomsterpotta ved døra.\n\nOla"))
    try host.send(to: olaAtHost, subject: fake([subjects[4]]), body: body("Hei Ola,\n\nHusk bursdagen til mor på søndag.\n\nAndreas"))
    try host.send(to: kariAtHost, subject: fake([subjects[2]]), body: body("Hei Kari,\n\nTakk for sist! Det var en fin kveld.\n\nAndreas"))
    try kari.send(to: hostAtKari, subject: fake([subjects[1]]), body: body(longBody))
    try kari.send(to: hostAtKari, subject: fake([subjects[0], " ", nil]), body: fake([shortBody, "\n\n", nil]))
    // Two requests: two others ask the host.
    for (name, address) in [("per", perAddress), ("lise", liseAddress)] {
        let asker = try User(in: dir.appendingPathComponent(name), relay: relayURL)
        try registerRoot(asker, address)
        let typed = fake([hostAddress])
        defer { typed.wipe() }
        _ = try asker.session.addContact(address: typed)
        asker.session.brev.lock()
    }
    let arrived = try host.session.sync().letters
    check("fixture: three letters arrive at the host through the relay", arrived == 3, "\(arrived)")
    // Ola's key changes: a new identity takes the address, and the host's
    // next send finds it.
    ola.session.brev.lock()
    ingrid.session.brev.lock()
    let newOla = try replaceIdentity(olaAddress)
    newOla.session.brev.lock()
    try host.session.composeStarted(design: EnvironmentProbe.design(), admin: nil, keyOrigin: host.keyOrigin)
    do {
        try host.session.prepareSend(contact: olaAtHost, sample: cleanSample)
        check("fixture: Ola's changed key is found", false)
    } catch BrevError.KeyChanged {
    }
    host.session.cancelSend()
    try host.session.composeClosed()
    newUser = try User(in: dir.appendingPathComponent("new"), relay: relayURL)
    try registerRoot(newUser, "ny-bruker")
    unregistered = try User(in: dir.appendingPathComponent("unregistered"), relay: relayURL)
} catch {
    check("fixture: users, letters, requests and a key change", false, "\((error as? BrevError).map { "\($0)" } ?? "\(error)")")
    finish()
}

// MARK: - Checks (§5.6)

/// A key-down made here as the hardware's arrives (source PID 0), handed
/// to a view as a human's key: the tool's only way to select a row.
func hardwareKey(_ code: UInt16) -> NSEvent {
    let cg = CGEvent(keyboardEventSource: nil, virtualKey: code, keyDown: true)!
    cg.setIntegerValueField(.eventSourceUnixProcessID, value: 0)
    return NSEvent(cgEvent: cg)!
}
let down: UInt16 = 125

/// Every string the accessibility tree of `root` offers in this process
/// (value, title, label, help, placeholder, role description, identifier),
/// down its accessibility children and its subviews.
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
        if let w = o as? NSWindow, let c = w.contentView?.superview ?? w.contentView { next.append(c) }
        next.forEach { walk($0, depth + 1) }
    }
    walk(root, 0)
    return out
}

let codePattern = try! NSRegularExpression(pattern: "[A-Z2-7]{5}( [A-Z2-7]{5}){5}")
/// The fake texts that must never reach accessibility: addresses, subjects,
/// words of the bodies, the marker.
let secrets = fakeAddresses + subjects + ["Lofoten", "blomsterpotta", "Takk for sist! Det", "BREV-SECRET-BODY"]

func all<T: NSView>(_ type: T.Type, in window: NSWindow) -> [T] {
    all(type, in: window.contentView?.superview ?? window.contentView!)
}

func alphaInk(_ rep: NSBitmapImageRep) -> Bool {
    guard let data = rep.bitmapData else { return true }
    return UnsafeBufferPointer(start: data, count: rep.bytesPerPlane).contains { $0 != 0 }
}

/// The per-scene checks of §5.6 on `window`.
func checkWindow(_ scene: String, _ window: NSWindow, control: String?) {
    let root = window.contentView?.superview ?? window.contentView!
    check("\(scene): hardened (sharingType .none, not restorable, not in the Windows menu, no tabs)",
          window.sharingType == .none && !window.isRestorable && window.isExcludedFromWindowsMenu
              && window.tabbingMode == .disallowed)
    check("\(scene): no .fullSizeContentView", !window.styleMask.contains(.fullSizeContentView))
    if let toolbar = window.toolbar {
        check("\(scene): the toolbar saves nothing and cannot be customised",
              !toolbar.autosavesConfiguration && !toolbar.allowsUserCustomization
                  && toolbar.items.allSatisfy { $0.toolTip == nil })
    }
    let views = all(ContentView.self, in: root).filter { !$0.isHiddenOrHasHiddenAncestor }
    let layout = window.contentLayoutRect
    let under = views.filter { v in
        let r = v.convert(v.visibleRect.intersection(v.bounds), to: nil)
        return !r.isEmpty && !layout.insetBy(dx: -0.5, dy: -0.5).contains(r)
    }
    check("\(scene): every content view lies inside the content layout rect (none under the title bar or toolbar)",
          under.isEmpty, "\(under.count) of \(views.count)")
    check("\(scene): every content view: protected layer, opaque to accessibility, no tooltip, no menu",
          views.allSatisfy { $0.protectedLayer.preventsCapture && $0.toolTip == nil && $0.menu == nil }
              && ContentView.allOpaque)
    let forbidden: [AnyClass] = [NSTextField.self, NSTextView.self, NSTableView.self, NSOutlineView.self,
                                 NSSearchField.self, NSCollectionView.self, NSBrowser.self, NSTokenField.self,
                                 NSComboBox.self]
    // The content view's tree: the title bar's own title fields are AppKit's,
    // and so is the label inside an NSButton (its fixed title).
    func inButton(_ v: NSView) -> Bool { v.superview.map { $0 is NSButton || inButton($0) } ?? false }
    let found = all(NSView.self, in: window.contentView!).filter { v in
        forbidden.contains { v.isKind(of: $0) } && !inButton(v)
    }
    check("\(scene): no text field, text view, table, outline, search field, collection, browser, token field "
            + "or combo box", found.isEmpty, found.map { "\(type(of: $0))" }.joined(separator: ","))
    let inked = views.filter { v in
        let r = v.visibleRect.intersection(v.bounds)
        guard !r.isEmpty, let rep = v.bitmapImageRepForCachingDisplay(in: r) else { return false }
        v.cacheDisplay(in: r, to: rep)
        return alphaInk(rep)
    }
    check("\(scene): cacheDisplay of each content view alone draws nothing", inked.isEmpty, "\(inked.count)")
    let strings = axStrings(window)
    let leaks = strings.filter { s in
        secrets.contains { s.contains($0) } || codePattern.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) != nil
    }
    check("\(scene): accessibility has no fake name, subject, body or code" + (control.map { " (control: «\($0)»)" } ?? ""),
          leaks.isEmpty && control.map { strings.contains($0) } ?? true, "\(leaks.count) of \(strings.count)")
    if window === mainWindow {
        check("\(scene): title «Brev», subtitle empty or a mailbox",
              window.title == L10n.windowMainTitle
                  && ["", L10n.mailboxInbox, L10n.mailboxSent].contains(window.subtitle))
    }
}

// MARK: - Scenes

let mainWindow = MainWindow(contentSize: NSSize(width: 1080, height: 680))
let window = mainWindow
let lock = LockController()
lock.window = window
lock.showLockScreen = { window.root.show(UnlockViewController(mode: .lockScreen)) }
var frames: [String: NSRect] = [:]

/// Builds a scene once, then draws it in each appearance and checks it.
func scene(_ name: String, in target: NSWindow = window, control: String? = nil, _ build: () -> Void) {
    guard onlyScene == nil || onlyScene == name else { return }
    build()
    for (label, appearance) in appearances {
        target.appearance = NSAppearance(named: appearance)
        let root = target === window ? target.contentView!.superview! : target.contentView!
        root.layoutSubtreeIfNeeded()
        root.displayIfNeeded()
        if !checkOnly { render(root, "\(name)-\(label)") }
    }
    checkWindow(name, target, control: control)
    if target === window { frames[name] = window.frame }
    guardOffscreen(name)
    print("scene \(name)")
}

/// A check of a state that earlier scenes built: skipped with --scene.
func expect(_ what: String, _ ok: @autoclosure () -> Bool, _ detail: @autoclosure () -> String = "") {
    guard onlyScene == nil else { return }
    check(what, ok(), detail())
}

func unlock(_ user: User) {
    lock.session = user.session
    _ = lock.state.endUnlock(lock.state.beginUnlock(), succeeded: true, appActive: true)
}

// Pages.
scene("onboarding-welcome", control: L10n.onboardingWelcomeTitle) { window.root.show(OnboardingViewController()) }
scene("onboarding-rules", control: L10n.onboardingRulesTitle) {
    let page = OnboardingViewController()
    window.root.show(page)
    page.perform(NSSelectorFromString("welcomeDone:"), with: nil)   // as a human's press
}
scene("onboarding-working", control: L10n.onboardingWorking) {
    let page = OnboardingViewController()
    window.root.show(page)
    page.showWorking()
}
scene("first-unlock", control: L10n.onboardingFirstTitle) { window.root.show(UnlockViewController(mode: .firstUnlock)) }
scene("lock", control: L10n.unlockTitle) { window.root.show(UnlockViewController(mode: .lockScreen)) }
scene("lock-notice", control: L10n.lockedBecause([.sudo])) {
    window.root.show(UnlockViewController(mode: .lockScreen, notice: L10n.lockedBecause([.sudo])))
}
scene("notice-damaged") { window.root.show(NoticeViewController(L10n.unlockErrorDamaged)) }
scene("notice-unsafe") { window.root.show(NoticeViewController(L10n.launchErrorUnsafe)) }
let addressPage = AddressViewController(session: unregistered.session) { _, done in done(.failure(BrevError.Signing)) }
scene("address-invite", control: L10n.addressInviteTitle) {
    window.root.show(addressPage)
}
scene("address-register", control: L10n.addressTitle) {
    if window.root.child !== addressPage { window.root.show(addressPage) }
    if let root = rootInvite(in: dir) {
        root.withBytes { _ = addressPage.inviteField.model.insertPasted($0) }
        root.wipe()
        addressPage.inviteField.relayout()
    }
    addressPage.next()   // Fortsett, as a human's press
    expect("address page: the invite opens and step 2 shows",
          spin(until: { addressPage.registerButton?.isHidden == false }))
    let typed = fake(["andreas-2"])
    _ = Array(UnsafeBufferPointer(start: typed.units, count: typed.length)).withUnsafeBufferPointer {
        addressPage.field.model.insert($0)
    }
    typed.wipe()
    addressPage.field.relayout()
}

// The mail window.
unlock(host)
let mail = MailViewController(session: host.session)
mail.onNewLetter = { _ in }
mail.onLock = { lock.lockNow(nil) }
window.root.show(mail)
mail.start()
_ = spin(until: { false }, 1.5)
expect("start: the first contact is selected, its list read, no letter open (no auto-open)",
      mail.selection == .contact(kariAtHost) && mail.messageList.count == 3 && mail.letters.isEmpty
          && mail.openThread == nil && mail.readingHeader.isHidden,
      "\(String(describing: mail.selection)) \(mail.messageList.count) \(mail.letters.isEmpty)")
let split = mail.split
expect("the three panes cannot be collapsed and save nothing",
      split.splitViewItems.count == 3 && split.splitViewItems.allSatisfy { !$0.canCollapse }
          && split.splitView.autosaveName == nil)
scene("mail-contact", control: L10n.mailboxInbox) {
    mail.messageList.keyDown(with: hardwareKey(down))
    window.makeFirstResponder(mail.messageList)
}
expect("a human's ↓ opens the newest letter; the reading header shows it",
      mail.openThread != nil && !mail.letters.isEmpty && !mail.readingHeader.isHidden)
scene("mail-contact-keychanged", control: L10n.contactAccept) {
    mail.contactList.keyDown(with: hardwareKey(down))
    window.makeFirstResponder(mail.contactList)
}
expect("a contact with a changed key: the bar shows the warning; Nytt brev is off",
      mail.header.showsKeyChange && !mail.canWriteNewLetter)
scene("mail-request", control: L10n.requestAccept) {
    mail.requestList.keyDown(with: hardwareKey(down))
}
expect("a request: the bar shows Godta and Avslå, no list, no empty state, a blank reading pane",
      mail.header.showsRequest && mail.messageList.count == 0 && mail.letters.isEmpty)

// The mailbox rows: accessibility can neither select nor press (review 3).
let mailboxes = mail.mailboxes
let rowsAX = mailboxes.accessibilityChildren() as? [NSAccessibilityElement] ?? []
for e in rowsAX {
    e.setAccessibilitySelected(true)
    _ = e.accessibilityPerformPress()
    _ = e.accessibilityPerformPick()
}
_ = mailboxes.accessibilityPerformPress()
mailboxes.setAccessibilitySelectedChildren(rowsAX)
expect("Innboks and Sendt are static text to accessibility; selecting or pressing them does nothing",
      rowsAX.count == 2 && rowsAX.allSatisfy { $0.accessibilityRole() == .staticText && !$0.isAccessibilitySelected() }
          && !mailboxes.isAccessibilityElement() && mailboxes.selected == nil && mail.selection != .inbox
          && mail.messageList.count == 0)

scene("mail-inbox", control: L10n.mailboxInbox) {
    mailboxes.keyDown(with: hardwareKey(down))
    window.makeFirstResponder(mailboxes)
}
expect("Innboks, by a human's ↓: every received letter, newest first, none open; the subtitle says «Innboks»",
      mail.selection == .inbox && mail.messageList.count == 3 && mail.letters.isEmpty
          && window.subtitle == L10n.mailboxInbox)
scene("mail-inbox-letter", control: L10n.mailboxInbox) {
    mail.messageList.keyDown(with: hardwareKey(down))
    window.makeFirstResponder(mail.messageList)
}
let openBeforeSync = mail.openThread
do {
    // A sync with a new letter keeps the open letter by its thread (review 2).
    let hostAtKari = try kari.contact(hostAddress)
    try kari.send(to: hostAtKari, subject: fake([subjects[5]]), body: body("Og en ting til: ta med paraply!"))
    mail.syncOnce()
    let grew = spin(until: { mail.messageList.count == 4 })
    expect("a sync with a new letter keeps the open letter by its thread id and opens nothing else",
          grew && openBeforeSync != nil && mail.openThread == openBeforeSync && mail.messageList.selected == 1)
} catch {
    expect("a new letter from Kari", false, "\(error)")
}
scene("mail-inbox-keychanged", control: L10n.contactAccept) {
    for _ in 0..<2 { mail.messageList.keyDown(with: hardwareKey(down)) }
}
expect("Innboks, a letter from a contact whose key changed: the bar above the reading header",
      mail.header.showsKeyChange && !mail.readingHeader.isHidden && mail.header.superview !== nil)
scene("mail-sent", control: L10n.mailboxSent) {
    mailboxes.keyDown(with: hardwareKey(down))
}
expect("Sendt: every sent letter, none open", mail.selection == .sent && mail.messageList.count == 2
          && mail.letters.isEmpty)

// A new user: no contacts, Innboks with «Legg til kontakt».
let emptyMail = MailViewController(session: newUser.session)
scene("mail-empty", control: L10n.sidebarAdd) {
    lock.session = newUser.session
    window.root.show(emptyMail)
    emptyMail.start()
}
expect("a new user: Innboks, empty, nothing read", emptyMail.selection == .inbox && emptyMail.messageList.count == 0)
emptyMail.wipeAll()

// The real lock sequence on the mail window, with a letter open.
scene("locked-after", control: L10n.unlockTitle) {
    lock.session = host.session
    window.root.show(mail)
    mail.start()
    mail.messageList.keyDown(with: hardwareKey(down))
    let views = all(ContentView.self, in: window)
    views.forEach { $0.updateLayer() }
    let open = !mail.letters.isEmpty
    lock.lock(.manual)
    check("locked-after: the lock wiped the lists, letters, bar and header, zeroed every buffer and locked Rust "
            + "(control: a letter was open)",
          open && mail.messageList.count == 0 && mail.contactList.count == 0 && mail.letters.isEmpty
              && mail.header.newCode == nil && mail.readingHeader.subjectView.lines.allSatisfy { $0 == nil }
              && views.allSatisfy { v in !v.pool.contains { hasPixels($0) } } && host.session.brev.isLocked()
              && window.toolbar == nil && window.subtitle == "")
}
if onlyScene == nil {
    let distinct = Set(frames.values.map { "\($0)" })
    check("the window frame is the same on every screen (toolbar on and off)", distinct.count == 1,
          distinct.joined(separator: " | "))
}

// GlyphFlush: its time per content font (a budget of 50 ms each).
expect("GlyphFlush knows the four content fonts", GlyphFlush.fonts.count >= 4, "\(GlyphFlush.fonts.count)")
for f in GlyphFlush.fonts {
    let start = DispatchTime.now().uptimeNanoseconds
    GlyphFlush.flush(f.attrs)
    let ms = Double(DispatchTime.now().uptimeNanoseconds - start) / 1e6
    let name = CTFontCopyPostScriptName(f.font) as String
    check("GlyphFlush \(name) \(Int(CTFontGetSize(f.font))) pt: \(String(format: "%.1f", ms)) ms (budget 50)", ms < 50)
}

finish()
