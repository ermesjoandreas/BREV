// main.swift — the lock probe: the app's own code locks the Rust session and
// zeroes the pixels (review round 1).
//
// A CLI process that scripts/test.sh builds and runs: no window on screen, no
// prompt, no keychain, no posted event. It is built from
// app/Sources/{Shared,App,UI,Keys}, the patched bindings and the release
// archive, never linked into Brev.app. The DEK is wrapped to a software P-256
// key, as in the heap-scan harness (app/Tests/main.swift). It runs the real
// LockController and UnlockService, and checks what the harness (Shared/
// only) and the view host (a window, never run by test.sh) cannot:
// - a successful unlock that LockController discards (Brev not the active
//   app, or a lock meanwhile) leaves Rust locked (design §5.4 step 3);
// - the lock sequence on the mail screen wipes it, zeroes every content
//   view's pixel buffers in place, locks Rust and shows the lock screen
//   (design §8.4; D-0034);
// - AppKit's own drawing of a content view (draw(_:), for print and PDF
//   output) draws nothing (design §7.1);
// - UnlockService locks Rust again when its closure fails after
//   Brev.unlock succeeded (installing the wrapped DEK fails).
// The mail screen lives in a MainWindow that is never ordered onto the
// screen; each content view draws its visible part into its pixel buffers
// as AppKit's display pass would make it. Output is check names only.
//
// usage: lock-probe

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

// MARK: - A session, as the app makes it, with a software KEK

_ = BrevApplication.shared
_ = NSApp.setActivationPolicy(.prohibited)

let dir = FileManager.default.temporaryDirectory.appendingPathComponent("brev-lock-probe-\(getpid())")
try? FileManager.default.removeItem(at: dir)
try! FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
func finish() -> Never {
    try? FileManager.default.removeItem(at: dir)
    print(failures == 0 ? "PASS" : "FAIL: \(failures) check(s)")
    exit(failures == 0 ? 0 : 1)
}

let kekAttrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                               kSecAttrKeySizeInBits as String: 256]
let softwareKEK = SecKeyCreateRandomKey(kekAttrs as CFDictionary, nil)!
let wrappedDEK: Data
let session: Session
do {
    let dek = SecretBytes(capacity: 64)
    guard SecRandomCopyBytes(kSecRandomDefault, 32, dek.base) == errSecSuccess else { throw BrevError.Rng }
    dek.setCount(32)
    wrappedDEK = try Enclave.wrap(dek: dek, to: SecKeyCopyPublicKey(softwareKEK)!)
    session = try Session.create(dir: dir.path, dek: dek, signingKey: Data(repeating: 4, count: 65))
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
    let ekko = try session.contacts()[0]
    _ = try session.send(to: ekko.id, subject: text("Et testbrev"),
                         body: text("Hei!\n\nDette er et testbrev fra låseprøven, med æ, ø og å.\n\nHilsen"))
    ekko.name.wipe()
    _ = try session.sync()
} catch {
    check("a letter and its echo", false, "\(error)")
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
check("draw(_:) of every content view in sight draws nothing (print and PDF output)",
      !inSight.isEmpty && inSight.allSatisfy { !drawInks($0, $0.visibleRect.intersection($0.bounds)) })

lock.lock(.manual)
check("lock: every pixel buffer of every content view is zero, also those of letters it removed",
      !buffers.isEmpty && !buffers.contains(where: hasPixels) && views.allSatisfy { !$0.pool.contains(where: hasPixels) },
      "\(buffers.filter(hasPixels).count) of \(buffers.count) buffers")
check("lock: the lists and letters are wiped",
      all(SecureListView.self, in: mail.view).allSatisfy { $0.count == 0 }
          && all(LetterStackView.self, in: mail.view).allSatisfy { $0.isEmpty })
check("lock: Rust is locked", session.brev.isLocked())
check("lock: the lock screen is shown", lockScreens == 1, "\(lockScreens)")

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
