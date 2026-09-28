// main.swift — the lock probe: the app's own code locks the Rust session and
// zeroes the pixels (review round 1).
//
// A CLI process that scripts/test.sh builds and runs: no window on screen, no
// prompt, no keychain, no posted event. It is built from
// app/Sources/{Shared,App,UI,Keys}, the patched bindings and the release
// archive, never linked into Brev.app. The DEK is wrapped to a software P-256
// key and the identity key is a software key too, as in the heap-scan
// harness (app/Tests/main.swift). The letters on the mail screen come from a
// second user through the relay scripts/test.sh starts (BREV_RELAY_URL). It
// runs the real LockController and UnlockService, and checks what the
// harness (Shared/ only) and the view host (a window, never run by test.sh)
// cannot:
// - a successful unlock that LockController discards (Brev not the active
//   app, or a lock meanwhile) leaves Rust locked (design §5.4 step 3);
// - the lock sequence on the mail screen wipes it, the contact header's
//   addresses and codes included, zeroes every content view's pixel buffers
//   in place, locks Rust and shows the lock screen (design §8.4; D-0034;
//   docs/PHASE3_DESIGN.md §6.4);
// - the lock sequence on the address page wipes the typed address and
//   zeroes its pixels (docs/PHASE3_DESIGN.md §6.5);
// - a replaced line of the contact header has its pixels zeroed, and a
//   lock ends a compose sheet without reporting a close, so AppDelegate
//   reads nothing again while Brev locks (WP5 review);
// - a signature's Touch ID prompt with LockState's U4 switch in both
//   positions (docs/PHASE3_DESIGN.md §3.2): on, every content view is blank
//   during the prompt, and as this process is never the active app, its end
//   locks Brev and drops the signature; off, the content stays and the
//   signature is used;
// - AppKit's own drawing of a content view (draw(_:), for print and PDF
//   output) draws nothing (design §7.1);
// - UnlockService locks Rust again when its closure fails after
//   Brev.unlock succeeded (installing the wrapped DEK fails).
// The mail screen lives in a MainWindow that is never ordered onto the
// screen; each content view draws its visible part into its pixel buffers
// as AppKit's display pass would make it. Output is check names only.
//
// usage: BREV_RELAY_URL=http://127.0.0.1:<port> lock-probe

import AppKit
import LocalAuthentication
import Security

setvbuf(stdout, nil, _IOLBF, 0)

var failures = 0
func check(_ what: String, _ ok: Bool, _ detail: @autoclosure () -> String = "") {
    let d = ok ? "" : detail()
    print((ok ? "ok   " : "FAIL ") + what + (d.isEmpty ? "" : "  [\(d)]"))
    if !ok { failures += 1 }
}

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

/// Whether `v.draw(rect)` into a current NSGraphicsContext over an empty
/// bitmap puts ink into it (as tools/viewhost checks it).
func drawInks(_ v: NSView, _ rect: NSRect) -> Bool {
    let w = Int(rect.width.rounded(.up)), h = Int(rect.height.rounded(.up))
    guard w > 0, h > 0 else { return false }
    guard let ctx = CGContext(data: nil, width: w, height: h, bitsPerComponent: 8, bytesPerRow: 0,
                              space: CGColorSpaceCreateDeviceRGB(),
                              bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)
    else { return true }
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

/// Non-content text for the fake letter.
func text(_ s: String) -> SecretText {
    let u = Array(s.utf16)
    let t = SecretText(maxUnits: max(u.count, 1))
    u.withUnsafeBufferPointer { _ = t.insert($0, at: 0) }
    return t
}

// MARK: - A session, as the app makes it, with software keys

_ = BrevApplication.shared
_ = NSApp.setActivationPolicy(.prohibited)

guard let relay = getenv("BREV_RELAY_URL").map({ String(cString: $0) }), !relay.isEmpty else {
    print("FAIL the lock probe needs BREV_RELAY_URL (the relay scripts/test.sh starts)")
    exit(2)
}
let dir = FileManager.default.temporaryDirectory.appendingPathComponent("brev-lock-probe-\(getpid())")
try? FileManager.default.removeItem(at: dir)
try! FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
func finish() -> Never {
    try? FileManager.default.removeItem(at: dir)
    print(failures == 0 ? "PASS" : "FAIL: \(failures) check(s)")
    exit(failures == 0 ? 0 : 1)
}

func softwareKey() -> SecKey {
    let attrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                                kSecAttrKeySizeInBits as String: 256]
    return SecKeyCreateRandomKey(attrs as CFDictionary, nil)!
}

/// A store in `sub` under a random DEK wrapped to `kek`, locked; returns
/// the session and the wrapped DEK.
func makeSession(_ sub: String, kek: SecKey, identity: SecKey) throws -> (Session, Data) {
    let path = dir.appendingPathComponent(sub)
    try FileManager.default.createDirectory(at: path, withIntermediateDirectories: true)
    let dek = SecretBytes(capacity: 64)
    guard SecRandomCopyBytes(kSecRandomDefault, 32, dek.base) == errSecSuccess else { throw BrevError.Rng }
    dek.setCount(32)
    let wrapped = try Enclave.wrap(dek: dek, to: SecKeyCopyPublicKey(kek)!)
    let signingKey = try Enclave.publicKeyBytes(of: SecKeyCopyPublicKey(identity)!)
    return (try Session.create(dir: path.path, relay: relay, dek: dek, signingKey: signingKey), wrapped)
}

/// A fresh address: the relay lives through the whole test.sh run.
func freshAddress(_ who: String) -> String { "\(who)-\(getpid())-\(UInt32.random(in: 0...UInt32.max))" }

/// Registers `address`, typed as the app passes it.
func register(_ s: Session, _ identity: SecKey, _ address: String) throws {
    let typed = text(address)
    defer { typed.wipe() }
    try s.register(signature: try Enclave.sign(digest: try s.registerRequest(address: typed), key: identity))
}

/// Adds the contact with `address`; returns its local id.
func add(_ s: Session, _ address: String) throws -> Data {
    let typed = text(address)
    defer { typed.wipe() }
    return try s.addContact(address: typed)
}

/// One letter in the app's steps (prepare, seal, sign, attach, submit).
func send(_ s: Session, _ identity: SecKey, to contact: Data, subject: String, body: String) throws {
    let st = text(subject), bt = text(body)
    defer { st.wipe(); bt.wipe() }
    try s.prepareSend(contact: contact)
    try s.attachSignature(try Enclave.sign(digest: try s.signRequest(contact: contact, subject: st, body: bt),
                                           key: identity))
    _ = try s.submit()
}

let softwareKEK = softwareKey(), identity = softwareKey()
let wrappedDEK: Data
let session: Session
do {
    (session, wrappedDEK) = try makeSession("a", kek: softwareKEK, identity: identity)
} catch {
    check("a session with a software KEK", false, "\(error)")
    finish()
}

/// The unlock closure's core: unwrap with the software KEK, Brev.unlock.
func unlockRust() -> Bool {
    do { try Enclave.unwrap(wrappedDEK, with: softwareKEK) { try session.brev.unlock(dek: $0) } } catch { return false }
    return !session.brev.isLocked()
}

let lock = LockController()
lock.session = session
var lockScreens = 0
lock.showLockScreen = { lockScreens += 1 }

// MARK: - A discarded unlock locks Rust (LockController.endUnlock)

check("precondition: this process is not the active app", !NSApp.isActive)
var started = lock.beginUnlock()
let unlocked = unlockRust()
check("an unlock that ends while Brev is not the active app is discarded, and Rust is locked again",
      unlocked && !lock.endUnlock(started, succeeded: true) && session.brev.isLocked(),
      "closure unlocked \(unlocked), locked \(session.brev.isLocked())")
started = lock.beginUnlock()
lock.lock(.manual)
let unlockedAfterLock = unlockRust()
check("an unlock that ends after a lock is discarded, and Rust is locked again",
      unlockedAfterLock && !lock.endUnlock(started, succeeded: true) && session.brev.isLocked())

// MARK: - The lock sequence on the mail screen (LockController.lock)

guard unlockRust() else {
    check("unlock for the mail screen", false)
    finish()
}
do {
    // A second user, and a letter each way through the relay.
    let peerKEK = softwareKey(), peerIdentity = softwareKey()
    let (peer, peerWrapped) = try makeSession("b", kek: peerKEK, identity: peerIdentity)
    try Enclave.unwrap(peerWrapped, with: peerKEK) { try peer.brev.unlock(dek: $0) }
    let me = freshAddress("a"), other = freshAddress("b")
    try register(session, identity, me)
    try register(peer, peerIdentity, other)
    let peerAtMe = try add(session, other), meAtPeer = try add(peer, me)
    try send(session, identity, to: peerAtMe, subject: "Et testbrev",
             body: "Hei!\n\nDette er et testbrev fra låseprøven, med æ, ø og å.\n\nHilsen")
    try send(peer, peerIdentity, to: meAtPeer, subject: "Et svar",
             body: "Hei igjen!\n\nDette er svaret, gjennom reléet.\n\nHilsen")
    peer.brev.lock()
    let arrived = try session.sync()
    check("a letter each way through the relay", arrived == 1, "\(arrived)")
} catch {
    check("a letter each way through the relay", false, "\(error)")
    finish()
}
let window = MainWindow(contentSize: NSSize(width: 900, height: 600))   // never ordered onto the screen
lock.window = window
_ = lock.state.endUnlock(lock.state.beginUnlock(), succeeded: true, appActive: true)
let mail = MailViewController(session: session)
window.root.show(mail)
mail.start()
mail.view.layoutSubtreeIfNeeded()
let views = all(ContentView.self, in: mail.view)
let inSight = views.filter { !$0.visibleRect.intersection($0.bounds).isEmpty }
inSight.forEach { $0.updateLayer() }   // the display pass: each draws into its pool
let buffers = views.flatMap { $0.pool }
let drawn = inSight.filter { $0.pool.contains(where: hasPixels) }
check("control: the contacts, threads and letters are pixels in their buffers",
      drawn.contains { $0 is SecureListView } && drawn.contains { $0 is SecureTextView },
      "\(drawn.count) of \(inSight.count) views in sight drew")
let header = mail.header
check("control: the header shows both addresses and codes, as pixels in their buffers",
      [header.addresses, header.codes].allSatisfy { (v: ContactTextView) in
          v.lines.allSatisfy { $0 != nil } && drawn.contains { $0 === v }
      }
          && header.codes.lines.allSatisfy { $0?.length == 35 } && !header.showsKeyChange)
check("draw(_:) of every content view in sight draws nothing (print and PDF output)",
      !inSight.isEmpty && inSight.allSatisfy { !drawInks($0, $0.visibleRect.intersection($0.bounds)) })

lock.lock(.manual)
check("lock: every pixel buffer of every content view is zero, also those of letters it removed",
      !buffers.isEmpty && !buffers.contains(where: hasPixels) && views.allSatisfy { !$0.pool.contains(where: hasPixels) },
      "\(buffers.filter(hasPixels).count) of \(buffers.count) buffers")
check("lock: the lists and letters are wiped",
      all(SecureListView.self, in: mail.view).allSatisfy { $0.count == 0 }
          && all(LetterStackView.self, in: mail.view).allSatisfy { $0.isEmpty })
check("lock: the header's addresses and codes are wiped",
      all(ContactTextView.self, in: header).allSatisfy { $0.lines.allSatisfy { $0 == nil } } && header.newCode == nil)
check("lock: Rust is locked", session.brev.isLocked())
check("lock: the lock screen is shown", lockScreens == 1, "\(lockScreens)")

// MARK: - The lock sequence on the address page

guard unlockRust() else {
    check("unlock for the address page", false)
    finish()
}
_ = lock.state.endUnlock(lock.state.beginUnlock(), succeeded: true, appActive: true)
let page = AddressViewController(session: session) { _, done in done(.failure(BrevError.Signing)) }
window.root.show(page)
page.view.layoutSubtreeIfNeeded()
// Typed as a key-down with source PID 0 per unit, as the hardware's arrive,
// with key codes KeyTranslator finds on this Mac's layout.
var keyFor: [UInt16: (UInt16, CGEventFlags)] = [:]
if let t = KeyTranslator(.current) {
    for f in [CGEventFlags(), .maskShift] {
        for k in UInt16(0)..<51 {
            t.reset()
            t.translate(keyCode: k, flags: f) { u in if u.count == 1, keyFor[u[0]] == nil { keyFor[u[0]] = (k, f) } }
        }
    }
}
for u in "brev-address".utf16 {
    guard let (k, f) = keyFor[u], let cg = CGEvent(keyboardEventSource: nil, virtualKey: k, keyDown: true) else { continue }
    cg.flags = f
    cg.setIntegerValueField(.eventSourceUnixProcessID, value: 0)
    NSEvent(cgEvent: cg).map(page.field.keyDown)
}
page.field.updateLayer()
let fieldPool = page.field.pool
check("control: the address typed on the address page is pixels in the field's buffers",
      page.field.model.text.length == 12 && fieldPool.contains(where: hasPixels))
lock.lock(.manual)
check("lock: the address page's field is wiped, its pixels zero, Rust locked",
      page.field.model.text.length == 0 && (0..<page.field.model.text.maxUnits).allSatisfy { page.field.model.text.units[$0] == 0 }
          && !fieldPool.contains(where: hasPixels) && session.brev.isLocked() && lockScreens == 2,
      "length \(page.field.model.text.length), lock screens \(lockScreens)")

// MARK: - A new header line, and the lock sequence with a compose sheet open

guard unlockRust() else {
    check("unlock for the compose sheet", false)
    finish()
}
_ = lock.state.endUnlock(lock.state.beginUnlock(), succeeded: true, appActive: true)
let composing = MailViewController(session: session)
window.root.show(composing)
composing.start()
composing.view.layoutSubtreeIfNeeded()
let headerLines = [composing.header.addresses, composing.header.codes]
headerLines.forEach { $0.updateLayer() }
let linePools = headerLines.flatMap { $0.pool }
check("control: the header's line 2 (the contact's address and code) is pixels in its buffers",
      headerLines.allSatisfy { $0.lines[1] != nil } && linePools.contains(where: hasPixels))
// What a new selection, an added contact, an accepted key or a closed
// compose sheet does to the header: line 2 is replaced.
composing.reloadContacts(selecting: nil)
check("a replaced header line has its pixels zeroed in every buffer of the pool, until the next frame",
      headerLines.allSatisfy { $0.lines[1] != nil } && !linePools.contains(where: hasPixels),
      "\(linePools.filter(hasPixels).count) of \(linePools.count) buffers")
headerLines.forEach { $0.updateLayer() }
check("control: the next frame draws the header again", headerLines.allSatisfy { $0.pool.contains(where: hasPixels) })

// AppDelegate's compose wiring: after a close it reads the contacts, the
// subjects and the letters again. `reports` notes whether Brev was unlocked
// each time the sheet reported a close.
var reports: [String] = []
composing.onNewLetter = { [weak composing] contact in
    let id = contact.id
    ComposeSheet.present(on: window, to: contact, session: session,
                         signer: { _, done in done(.failure(BrevError.Signing)) }) { thread in
        reports.append(lock.state.unlocked ? "unlocked" : "locking")
        if let thread { composing?.showSent(thread: thread, contact: id) } else { composing?.reloadContacts(selecting: id) }
    }
}
composing.newLetter(nil)
let cancelled = window.attachedSheet as? ComposeSheet
cancelled?.subject.onCancel()   // Avbryt or Escape
check("control: Avbryt closes the compose sheet and reports the close",
      cancelled != nil && window.attachedSheet == nil && reports == ["unlocked"], "reports \(reports)")
composing.newLetter(nil)
let sheetAtLock = window.attachedSheet as? ComposeSheet
lock.lock(.manual)
check("lock: the compose sheet ends without reporting a close, so nothing is read or laid out again while Brev locks",
      sheetAtLock != nil && window.attachedSheet == nil && reports == ["unlocked"] && session.brev.isLocked(),
      "reports \(reports)")

// MARK: - A signature's prompt, with the U4 switch on and off

for takes in [true, false] {
    let signLock = LockController(state: LockState(signPanelTakesActivation: takes))
    signLock.window = window
    signLock.session = session
    var screens = 0
    signLock.showLockScreen = { screens += 1 }
    guard unlockRust() else {
        check("unlock for the prompt (U4 \(takes ? "on" : "off"))", false)
        finish()
    }
    _ = signLock.state.endUnlock(signLock.state.beginUnlock(), succeeded: true, appActive: true)
    let shown = MailViewController(session: session)
    window.root.show(shown)
    shown.start()
    shown.view.layoutSubtreeIfNeeded()
    let seen = all(ContentView.self, in: shown.view).filter { !$0.visibleRect.intersection($0.bounds).isEmpty }
    seen.forEach { $0.updateLayer() }
    let before = seen.filter { $0.pool.contains(where: hasPixels) }.count
    let started = signLock.beginSign()
    seen.forEach { $0.updateLayer() }   // a display pass while the prompt is up
    let during = seen.filter { $0.pool.contains(where: hasPixels) }.count
    let used = signLock.endSign(started)
    if takes {
        check("U4 on: during the prompt every content view is blank, also after a display pass; it ends with Brev "
                + "not active, which locks Brev and drops the signature",
              before > 2 && during == 0 && !used && session.brev.isLocked() && screens == 1,
              "before \(before), during \(during), used \(used), screens \(screens)")
    } else {
        seen.forEach { $0.updateLayer() }
        let after = seen.filter { $0.pool.contains(where: hasPixels) }.count
        check("U4 off: the content stays on screen during the prompt, and with no lock since, the signature is used",
              before > 2 && during == before && used && after == before && !session.brev.isLocked() && screens == 0,
              "before \(before), during \(during), after \(after), used \(used)")
        signLock.lock(.manual)
    }
}

// MARK: - UnlockService locks Rust when its closure fails

/// UnlockService's keychain calls without the keychain: the KEK is the
/// software key, and installing the wrapped DEK fails after Brev.unlock
/// succeeded (onboarding's first unlock, design §5.3 step 8).
final class FailingInstall: KeyStore {
    /// Whether Rust was unlocked when the install was tried (the control).
    var unlockedAtInstall = false
    override func kek(context: LAContext) throws -> SecKey { softwareKEK }
    override func readWrapped() throws -> Data { wrappedDEK }
    override func storeWrapped(_ wrapped: Data) throws {
        unlockedAtInstall = !session.brev.isLocked()
        throw KeyStore.error(errSecIO)
    }
    override func readBiometryState() -> Data? { nil }
    override func writeBiometryState(_ hash: Data) throws {}
}

let keys = FailingInstall()
var outcome: Result<Void, UnlockFailure>?
UnlockService(keyStore: keys).unlock(session, install: wrappedDEK) { outcome = $0 }
let deadline = Date(timeIntervalSinceNow: 10)
while outcome == nil && Date() < deadline { _ = RunLoop.main.run(mode: .default, before: Date(timeIntervalSinceNow: 0.05)) }
var failed = false
if case .failure? = outcome { failed = true }
check("UnlockService: a failure after Brev.unlock succeeded is reported, and Rust is locked again",
      failed && keys.unlockedAtInstall && session.brev.isLocked(),
      "outcome \(String(describing: outcome)), unlocked at install \(keys.unlockedAtInstall)")

finish()
