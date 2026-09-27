// main.swift — the Swift heap-scan harness (docs/PHASE2_DESIGN.md §11).
//
// A CLI process: no AppKit, no window, no Secure Enclave, no prompt. It is
// built from app/Sources/Shared, the patched bindings and libbrev_core.a,
// drives the content path the app uses, and counts copies of secrets in its
// own memory with scan.c. scripts/test.sh runs every case five times (the
// content case at four sizes) under MallocScribble=1, as the app runs, plus
// case 6's control without scribbling, with TMPDIR under core/target/harness.
//
// usage: harness units | shell | dek | content <units> [--no-scribble] | kept | control
//        harness needles <file>     (the helper run that `dek` starts)
//        harness argdomain -NSTraceEvents YES -NSZombieEnabled YES
//                                   (the helper run that `shell` starts)
//
// Case numbers are those of §11. Case 2's app-shell part (InputFilter,
// LockState, LaunchGuard) is `shell`; its EditModel and KeyTranslator parts
// arrive with those files. Output is content-free: check names and hit
// counts only.

import CoreGraphics
import CoreText
import CryptoKit
import Foundation
import Security

// MARK: - Checks and scanning

var failures = 0

func check(_ what: String, _ ok: Bool, _ detail: @autoclosure () -> String = "") {
    let d = ok ? "" : detail()
    print((ok ? "ok   " : "FAIL ") + what + (d.isEmpty ? "" : "  [\(d)]"))
    if !ok { failures += 1 }
}

struct Hits: CustomStringConvertible {
    let r: brev_scan_result
    var u8: UInt64 { r.utf8_hits }
    var u16: UInt64 { r.utf16_hits }
    var glyph: UInt64 { r.glyph_hits }
    func needle(_ i: Int) -> UInt64 {
        withUnsafeBytes(of: r.needle_hits) { $0.load(fromByteOffset: i * 8, as: UInt64.self) }
    }
    var description: String {
        var tags: [String] = []
        withUnsafeBytes(of: r.by_tag) { b in
            for i in 0..<256 {
                let n = b.load(fromByteOffset: i * 8, as: UInt64.self)
                if n > 0 { tags.append("\(i):\(n)") }
            }
        }
        let needles = (0..<Int(BREV_SCAN_NEEDLES)).map { String(needle($0)) }.joined(separator: ",")
        return "u8=\(u8) u16=\(u16) glyph=\(glyph) needles=[\(needles)] by_tag=[\(tags.joined(separator: " "))]"
            + " regions=\(r.regions) MiB=\(r.bytes >> 20)"
    }
}

@inline(never) func scan() -> Hits {
    var r = brev_scan_result()
    brev_scan(&r)
    return Hits(r: r)
}

/// libmalloc turns scribbling on when the variable exists, whatever its
/// value, so "off" means unset.
func requireScribble(_ on: Bool) {
    let value = getenv("MallocScribble").map { String(cString: $0) }
    if on ? value != "1" : value != nil {
        print("FAIL this case must run with MallocScribble \(on ? "=1" : "unset")")
        exit(2)
    }
}

// MARK: - Test content

/// "BREV-SECRET-BODY" XOR 0x5A, as in scan.c. Plain marker units exist only
/// inside SecretTexts (and single units on the stack).
let MARKER_X: [UInt8] = [0x18, 0x08, 0x1f, 0x0c, 0x77, 0x09, 0x1f, 0x19,
                         0x08, 0x1f, 0x0e, 0x77, 0x18, 0x15, 0x1e, 0x03]
func markerUnit(_ i: Int) -> UInt16 { UInt16(MARKER_X[i % 16] ^ 0x5A) }

/// `units` units of the repeated marker, then U+1F600 if `emoji` (which
/// makes CF keep the text as UTF-16).
func markerText(units: Int, emoji: Bool) -> SecretText {
    let t = SecretText(maxUnits: units + 2)
    for i in 0..<units { t.units[i] = markerUnit(i) }
    var n = units
    if emoji { t.units[n] = 0xD83D; t.units[n + 1] = 0xDE00; n += 2 }
    t.store.setCount(n * 2)
    return t
}

/// The marker's 16 glyph ids in `font`, XORed, as the scanner's glyph needle.
func setGlyphNeedle(_ font: CTFont) {
    var chars = [UInt16](repeating: 0, count: 16), glyphs = [CGGlyph](repeating: 0, count: 16)
    for i in 0..<16 { chars[i] = markerUnit(i) }
    _ = CTFontGetGlyphsForCharacters(font, chars, &glyphs, 16)
    var x = glyphs.map { $0 ^ 0x5A5A }
    brev_scan_set_glyphs(x, 16)
    _ = chars.withUnsafeMutableBytes { memset_s($0.baseAddress!, 32, 0, 32) }
    _ = glyphs.withUnsafeMutableBytes { memset_s($0.baseAddress!, 32, 0, 32) }
    _ = x.withUnsafeMutableBytes { memset_s($0.baseAddress!, 32, 0, 32) }
}

/// Non-content test text for the unit checks.
func secret(_ s: String, maxUnits: Int? = nil) -> SecretText {
    let u = Array(s.utf16)
    let t = SecretText(maxUnits: maxUnits ?? max(u.count, 1))
    u.withUnsafeBufferPointer { _ = t.insert($0, at: 0) }
    return t
}

func unitsOf(_ t: SecretText) -> [UInt16] { Array(UnsafeBufferPointer(start: t.units, count: t.length)) }

func throwsLocked<R>(_ f: () throws -> R) -> Bool {
    do { _ = try f(); return false } catch BrevError.Locked { return true } catch { return false }
}

// MARK: - Sessions, as the app makes them (software KEK)

let signingKey = Data(repeating: 4, count: 65)

/// A fresh directory in TMPDIR for one run's stores, removed afterwards.
func withStoreDir(_ body: (URL) -> Void) {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("brev-harness-\(getpid())")
    try? FileManager.default.removeItem(at: dir)
    try! FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: dir) }
    body(dir)
}

/// The unlock closure of §5.4: open the wrapped DEK, unlock on the same
/// thread, wipe. Returns whether the DEK's Data kept its address (no copy)
/// and ended all zero.
func unlock(_ session: Session, wrapped: Data, kek: P256.KeyAgreement.PrivateKey) throws -> (Bool, Bool) {
    var dek = try Enclave.open(wrapped, with: kek)
    let before = dek.withUnsafeBytes { UInt(bitPattern: $0.baseAddress) }
    do { try session.brev.unlock(dek: dek) } catch { dek.wipe(); session.brev.lock(); throw error }
    dek.wipe()
    let after = dek.withUnsafeBytes { UInt(bitPattern: $0.baseAddress) }
    return (before == after, dek.allSatisfy { $0 == 0 })
}

/// Onboarding steps 6 and 7 with a software KEK: a random DEK in a
/// SecretBytes, wrapped, `Session.create` (which wipes it), then the unlock.
func makeUnlockedSession(in dir: URL) throws -> Session {
    let dek = SecretBytes(capacity: 64)
    guard SecRandomCopyBytes(kSecRandomDefault, 32, dek.base) == errSecSuccess else { throw BrevError.Rng }
    dek.setCount(32)
    let kek = P256.KeyAgreement.PrivateKey()
    let wrapped = try Enclave.wrap(dek: dek, to: kek.publicKey)
    let session = try Session.create(dir: dir.path, dek: dek, signingKey: signingKey)
    _ = try unlock(session, wrapped: wrapped, kek: kek)
    return session
}

// MARK: - Case 1: units

func caseUnits() {
    // SecretBytes
    check("SecretBytes: capacity is at least 64",
          SecretBytes(capacity: 1).capacity == 64 && SecretBytes(capacity: 100).capacity == 100)
    let b = SecretBytes(capacity: 64)
    let seven = [UInt8](repeating: 7, count: 65)
    let filled = seven.withUnsafeBytes { src in
        b.append(UnsafeRawBufferPointer(rebasing: src[0..<60])) && b.append(UnsafeRawBufferPointer(rebasing: src[0..<4]))
    }
    check("SecretBytes: append fills up to capacity", filled && b.count == 64)
    let refused = seven.withUnsafeBytes { !b.append(UnsafeRawBufferPointer(rebasing: $0[0..<1])) }
    check("SecretBytes: append past capacity is refused and writes nothing", refused && b.count == 64)
    b.wipe()
    _ = seven.withUnsafeBytes { b.append(UnsafeRawBufferPointer(rebasing: $0[0..<10])) }
    let view = b.withFFIView { d, n in
        (d.withUnsafeBytes { $0.baseAddress } == UnsafeRawPointer(b.base), d.count, n)
    }
    check("SecretBytes: the FFI view is the buffer itself (no copy), whole capacity plus used length",
          view.0 && view.1 == 64 && view.2 == 10, "\(view)")
    b.wipe()
    check("SecretBytes: wipe zeroes the whole buffer",
          b.count == 0 && UnsafeRawBufferPointer(start: b.base, count: b.capacity).allSatisfy { $0 == 0 })

    var d = Data(repeating: 0xAB, count: 960)
    let before = d.withUnsafeBytes { $0.baseAddress }
    d.wipe()
    check("Data.wipe: same storage, all zero",
          d.withUnsafeBytes { $0.baseAddress } == before && d.count == 960 && d.allSatisfy { $0 == 0 })

    // SecretText
    let t = secret("abc", maxUnits: 8)
    Array("XY".utf16).withUnsafeBufferPointer { _ = t.insert($0, at: 1) }
    check("SecretText: insert in the middle", unitsOf(t) == Array("aXYbc".utf16))
    let bad = Array("1234".utf16).withUnsafeBufferPointer { !t.insert($0, at: 5) && !t.insert($0, at: 6) }
    check("SecretText: insert past maxUnits or out of range is refused", bad && unitsOf(t) == Array("aXYbc".utf16))
    Array("123".utf16).withUnsafeBufferPointer { _ = t.insert($0, at: 5) }
    check("SecretText: insert fills to maxUnits", unitsOf(t) == Array("aXYbc123".utf16))
    t.delete(1..<3)
    check("SecretText: delete moves the tail and zeroes the freed units",
          unitsOf(t) == Array("abc123".utf16) && t.units[6] == 0 && t.units[7] == 0)
    t.delete(4..<9)
    t.delete(2..<2)
    check("SecretText: an empty or out-of-range delete changes nothing", unitsOf(t) == Array("abc123".utf16))
    let c = t.copy()
    t.wipe()
    check("SecretText: copy is an independent buffer",
          unitsOf(c) == Array("abc123".utf16) && c.store.base != t.store.base && t.length == 0)

    let comp = secret("e\u{301}x")
    check("composedRange: e + U+0301 is one character",
          comp.composedRange(at: 0) == 0..<2 && comp.composedRange(at: 1) == 0..<2 && comp.composedRange(at: 2) == 2..<3)
    let emoji = secret("a\u{1F600}b\u{1F469}\u{200D}\u{1F4BB}")
    check("composedRange: a surrogate pair and a ZWJ sequence",
          emoji.composedRange(at: 2) == 1..<3 && emoji.composedRange(at: 1) == 1..<3 && emoji.composedRange(at: 5) == 4..<9)
    check("composedRange: out of range is empty",
          emoji.composedRange(at: 9) == 9..<9 && emoji.composedRange(at: -1) == -1 ..< -1)
    // 1000 units, a pair at 500..<502 and one at each end; the 64-unit
    // window's edges land on the middle pair from both sides.
    let long = secret("\u{1F600}" + String(repeating: "a", count: 498) + "\u{1F600}"
                      + String(repeating: "a", count: 496) + "\u{1F600}")
    check("composedRange: windowed, with a pair at either window edge",
          long.composedRange(at: 533) == 533..<534 && long.composedRange(at: 469) == 469..<470
            && long.composedRange(at: 501) == 500..<502 && long.composedRange(at: 500) == 500..<502)
    check("composedRange: windowed at both ends of the text",
          long.composedRange(at: 1) == 0..<2 && long.composedRange(at: 999) == 998..<1000
            && long.composedRange(at: 2) == 2..<3)

    // Transcode
    let sample = "Kjære Åse, ØØ é e\u{301} \u{1F600} 中文 \u{0}!"
    let u8 = Array(sample.utf8)
    let t16 = SecretText(maxUnits: u8.count)
    u8.withUnsafeBytes { Transcode.utf8ToUTF16($0, into: t16) }
    let back = SecretBytes(capacity: 3 * t16.length)
    Transcode.utf16ToUTF8(t16, into: back)
    check("Transcode: UTF-8 -> UTF-16 -> UTF-8 round trip",
          unitsOf(t16) == Array(sample.utf16) && back.withBytes { Array($0) } == u8)
    let invalid: [UInt8] = [0x61, 0xFF, 0x62, 0xE2, 0x82]
    let bad16 = SecretText(maxUnits: invalid.count)
    invalid.withUnsafeBytes { Transcode.utf8ToUTF16($0, into: bad16) }
    check("Transcode: invalid UTF-8 becomes U+FFFD", unitsOf(bad16) == [0x61, 0xFFFD, 0x62, 0xFFFD], "\(unitsOf(bad16))")
    let lone = SecretText(maxUnits: 2)
    [UInt16(0xD83D), 0x61].withUnsafeBufferPointer { _ = lone.insert($0, at: 0) }
    let lone8 = SecretBytes(capacity: 6)
    Transcode.utf16ToUTF8(lone, into: lone8)
    check("Transcode: a lone surrogate becomes U+FFFD", lone8.withBytes { Array($0) } == [0xEF, 0xBF, 0xBD, 0x61])

    // TextLayout
    let words = String(repeating: "Kjære deg, dette er et brev med noen ord. ", count: 40)
    let paragraphs = [words, "", String(repeating: "x", count: 1000), String(repeating: "\u{1F600}", count: 300),
                      "e\u{301}e\u{301} \u{1F469}\u{200D}\u{1F4BB} slutt", ""]
    let text = secret(paragraphs.joined(separator: "\n"))
    let wordsEnd = words.utf16.count
    let layout = TextLayout(font: CTFontCreateWithName("Helvetica" as CFString, 13, nil))
    let u = text.units, len = text.length
    let nonNewline = (0..<len).filter { u[$0] != 0x0A }.count
    for width: CGFloat in [1, 30, 200, 600, 1e6] {
        layout.layout(text, width: width)
        var covered = 0, prevEnd = 0, ordered = true, noNewline = true, max448 = true, noSplit = true, spaces = true
        for (i, l) in layout.lines.enumerated() {
            let end = l.start + l.length
            if l.start < prevEnd || end > len { ordered = false }
            if (l.start..<end).contains(where: { u[$0] == 0x0A }) { noNewline = false }
            if l.length > TextLayout.maxLineUnits { max448 = false }
            if l.length > 0, end < len, UTF16.isLeadSurrogate(u[end - 1]), UTF16.isTrailSurrogate(u[end]) { noSplit = false }
            let next = i + 1 < layout.lines.count ? layout.lines[i + 1].start : len
            if width >= 200, width < 1e6, l.length > 0, end < wordsEnd, next < wordsEnd, u[end - 1] != 0x20 {
                spaces = false
            }
            covered += l.length
            prevEnd = end
        }
        let w = "width \(Int(width))"
        check("TextLayout \(w): every unit on exactly one line", ordered && noNewline && covered == nonNewline,
              "\(covered) of \(nonNewline)")
        check("TextLayout \(w): lines of at most 448 units", max448)
        check("TextLayout \(w): no surrogate pair split", noSplit)
        check("TextLayout \(w): lines of words break after a space", spaces)
    }
    check("TextLayout: an empty paragraph is an empty line", layout.lines.contains { $0.length == 0 && $0.start == wordsEnd + 1 })

    // Enclave wrap and open (software KEK)
    let dek = SecretBytes(capacity: 64)
    _ = SecRandomCopyBytes(kSecRandomDefault, 32, dek.base)
    dek.setCount(32)
    let kek = P256.KeyAgreement.PrivateKey()
    let wrapped = try? Enclave.wrap(dek: dek, to: kek.publicKey)
    var opened = wrapped.flatMap { try? Enclave.open($0, with: kek) }
    check("Enclave: wrap gives 113 bytes, open gives the DEK back",
          wrapped?.count == Enclave.wrappedLength && opened.map { o in dek.withBytes { Data($0) == o } } == true)
    opened?.wipe()
    dek.wipe()
    check("Enclave: a wrapped DEK of the wrong length is refused",
          (try? Enclave.open(Data(count: 112), with: kek)) == nil)
}

// MARK: - Case 2, the app shell's part: InputFilter, LockState, LaunchGuard

func caseShell() {
    // InputFilter on CGEvents made in memory; nothing is posted.
    let me = Int64(getpid())
    let events: [(String, CGEvent?)] = [
        ("key", CGEvent(keyboardEventSource: nil, virtualKey: 0, keyDown: true)),
        ("click", CGEvent(mouseEventSource: nil, mouseType: .leftMouseDown, mouseCursorPosition: .zero,
                          mouseButton: .left)),
        ("scroll", CGEvent(scrollWheelEvent2Source: nil, units: .pixel, wheelCount: 1, wheel1: 1, wheel2: 0, wheel3: 0)),
    ]
    for (name, event) in events {
        guard let e = event else {
            check("InputFilter: a \(name) event can be made", false)
            continue
        }
        check("InputFilter: a \(name) event made here has this process's PID and is dropped",
              e.getIntegerValueField(.eventSourceUnixProcessID) == me && InputFilter.isSynthetic(e))
        e.setIntegerValueField(.eventSourceUnixProcessID, value: 0)
        check("InputFilter: \(name) with PID 0 is kept", !InputFilter.isSynthetic(e))
        e.setIntegerValueField(.eventSourceUnixProcessID, value: 1)
        check("InputFilter: \(name) with another PID is dropped", InputFilter.isSynthetic(e))
        e.setIntegerValueField(.eventSourceUnixProcessID, value: me)
        check("InputFilter: \(name) with Brev's own PID is dropped (no exception)", InputFilter.isSynthetic(e))
    }
    check("InputFilter: an event without a CGEvent is dropped",
          InputFilter.isSynthetic(nil) && InputFilter.sourcePID(nil) == -1)

    // LockState
    let all: [LockReason] = [.resignActive, .screenLocked, .sleep, .sessionResign, .idle, .manual, .terminate]
    let s = LockState()
    check("LockState: starts locked, generation 0, no auth",
          !s.unlocked && !s.authInFlight && s.generation == 0 && all.allSatisfy { s.shouldLock(for: $0) })
    var token = s.beginUnlock()
    check("LockState: resign-active during auth does not lock; every other reason does",
          s.authInFlight && !s.shouldLock(for: .resignActive) && all.dropFirst().allSatisfy { s.shouldLock(for: $0) })
    check("LockState: an unlock that ends while Brev is active unlocks",
          s.endUnlock(token, succeeded: true, appActive: true) && s.unlocked && !s.authInFlight)
    check("LockState: lock reports that Brev was unlocked; a second lock is harmless",
          s.lock() && !s.lock() && !s.unlocked && s.generation == 2)
    token = s.beginUnlock()
    s.lock()
    check("LockState: a stale generation discards an unlock",
          !s.endUnlock(token, succeeded: true, appActive: true) && !s.unlocked && !s.authInFlight)
    token = s.beginUnlock()
    check("LockState: an unlock that ends while Brev is inactive is discarded",
          !s.endUnlock(token, succeeded: true, appActive: false) && !s.unlocked)
    token = s.beginUnlock()
    check("LockState: a failed unlock ends the auth; resign-active locks again",
          !s.endUnlock(token, succeeded: false, appActive: true) && !s.unlocked && !s.authInFlight
            && s.shouldLock(for: .resignActive))
    let t0: UInt64 = 1_000_000_000_000, limit = LockState.idleLimitNanos
    check("LockState: idle at 300 s, not before, not with a clock behind the last input",
          limit == 300_000_000_000 && !LockState.isIdle(now: t0 + limit - 1, lastInput: t0)
            && LockState.isIdle(now: t0 + limit, lastInput: t0) && !LockState.isIdle(now: t0 - 1, lastInput: t0))

    // LaunchGuard on injected environments and defaults
    check("LaunchGuard: only argv[0] is allowed",
          LaunchGuard.argumentsAllowed(["/Applications/Brev.app/Contents/MacOS/Brev"])
            && !LaunchGuard.argumentsAllowed(["Brev", "-NSTraceEvents", "YES"]) && !LaunchGuard.argumentsAllowed(["Brev", "x"]))
    let defaults = UserDefaults.standard
    check("LaunchGuard: no unsafe default in this process to begin with", LaunchGuard.unsafeDefaults(defaults).isEmpty)
    let safe = ["PATH": "/usr/bin:/bin", "HOME": "/Users/x", "MallocScribble": "1",
                "__CFBundleIdentifier": "no.brev.app", "XPC_SERVICE_NAME": "application.no.brev.app"]
    check("LaunchGuard: a clean environment with MallocScribble=1 is safe",
          LaunchGuard.verdict(environment: safe, defaults: defaults) == .safe)
    var scribble = safe
    scribble["MallocScribble"] = nil
    let missing = LaunchGuard.verdict(environment: scribble, defaults: defaults)
    scribble["MallocScribble"] = "0"
    check("LaunchGuard: MallocScribble missing or not 1 re-executes",
          missing == .reexec && LaunchGuard.verdict(environment: scribble, defaults: defaults) == .reexec)
    for prefix in LaunchGuard.unsafePrefixes {
        var env = safe
        env[prefix + "Enabled"] = "YES"
        let first = LaunchGuard.verdict(environment: env, defaults: defaults)
        env[LaunchGuard.reexecMarker] = "1"
        let again = LaunchGuard.verdict(environment: env, defaults: defaults)
        let cleaned = LaunchGuard.cleanedEnvironment(env)
        check("LaunchGuard: \(prefix)… re-executes once, then is unsafe; the cleaned environment is safe",
              LaunchGuard.unsafeVariables(env) == [prefix + "Enabled"] && first == .reexec && again == .unsafe
                && LaunchGuard.verdict(environment: cleaned, defaults: defaults) == .safe)
    }
    var dirty = safe
    dirty["NSZombieEnabled"] = "YES"
    dirty["OBJC_PRINT_LOAD_METHODS"] = "YES"
    dirty["MallocScribble"] = "0"
    let cleaned = LaunchGuard.cleanedEnvironment(dirty)
    check("LaunchGuard: cleaning drops the unsafe variables and keeps the rest",
          LaunchGuard.unsafeVariables(dirty) == ["NSZombieEnabled", "OBJC_PRINT_LOAD_METHODS"]
            && cleaned["MallocScribble"] == "1" && cleaned[LaunchGuard.reexecMarker] == "1"
            && cleaned.count == safe.count + 1 && safe.allSatisfy { k, v in k == "MallocScribble" || cleaned[k] == v })
    // Defaults, through the registration domain (in memory only).
    for key in LaunchGuard.unsafeDefaultKeys {
        defaults.register(defaults: [key: true])
        let on = LaunchGuard.verdict(environment: safe, defaults: defaults)
        let onDirty = LaunchGuard.verdict(environment: dirty, defaults: defaults)
        defaults.register(defaults: [key: false])
        check("LaunchGuard: the default \(key) makes a launch unsafe, and re-executing cannot help",
              on == .unsafe && onDirty == .unsafe && LaunchGuard.verdict(environment: safe, defaults: defaults) == .safe)
    }
    // Arguments reach the argument domain: a helper run started with two.
    let helper = Process()
    helper.executableURL = Bundle.main.executableURL
    helper.arguments = ["argdomain", "-NSTraceEvents", "YES", "-NSZombieEnabled", "YES"]
    let pipe = Pipe()
    helper.standardOutput = pipe
    do { try helper.run() } catch {
        check("the argument-domain helper run starts", false, "\(error)")
        return
    }
    let out = pipe.fileHandleForReading.readDataToEndOfFile()
    helper.waitUntilExit()
    for line in String(decoding: out, as: UTF8.self).split(separator: "\n") { print("  helper: " + line) }
    check("the argument-domain helper run passes", helper.terminationStatus == 0, "status \(helper.terminationStatus)")
}

/// The helper run of `shell`, started with -NSTraceEvents YES -NSZombieEnabled YES.
func caseArgumentDomain() {
    let defaults = UserDefaults.standard
    check("launched with two debugging arguments: both defaults are true",
          LaunchGuard.unsafeDefaults(defaults) == ["NSTraceEvents", "NSZombieEnabled"])
    defaults.removeVolatileDomain(forName: UserDefaults.argumentDomain)
    print("note removeVolatileDomain alone leaves \(LaunchGuard.unsafeDefaults(defaults).count) of 2")
    LaunchGuard.clearArgumentDomain()
    let cf = CFPreferencesCopyAppValue("NSTraceEvents" as CFString, kCFPreferencesCurrentApplication)
    check("after clearArgumentDomain: neither default is set (UserDefaults and CFPreferences)",
          LaunchGuard.unsafeDefaults(defaults).isEmpty && cf == nil)
}

// MARK: - Case 3: the DEK hand-off and HPKE needles

func caseDEK() {
    requireScribble(true)
    withStoreDir { dir in
        let file = dir.appendingPathComponent("needles.bin")
        let helper = Process()
        helper.executableURL = Bundle.main.executableURL
        helper.arguments = ["needles", file.path]
        do { try helper.run() } catch { check("the helper run starts", false, "\(error)"); return }
        helper.waitUntilExit()
        guard helper.terminationStatus == 0, var blob = try? Data(contentsOf: file), blob.count == NeedleFile.size else {
            check("the helper run made the needles", false, "status \(helper.terminationStatus)")
            return
        }
        try? FileManager.default.removeItem(at: file)
        let kek = try! P256.KeyAgreement.PrivateKey(rawRepresentation: blob[0..<32])
        let wrapped = Data(blob[32..<(32 + Enclave.wrappedLength)])
        let xored = Data(blob[(32 + Enclave.wrappedLength)...])   // XORed needles only
        blob.wipe()
        let offsets = NeedleFile.lengths.indices.map { NeedleFile.lengths[..<$0].reduce(0, +) }
        for (i, n) in NeedleFile.lengths.enumerated() {
            let set = xored[offsets[i]..<(offsets[i] + n)].withUnsafeBytes {
                brev_scan_set_needle(i, $0.bindMemory(to: UInt8.self).baseAddress, n)
            }
            check("scanner takes needle \(NeedleFile.names[i])", set == 0)
        }
        /// Needle `i` un-XORed into a new SecretBytes (as SecRandomCopyBytes would fill it).
        func materialise(_ i: Int) -> SecretBytes {
            let b = SecretBytes(capacity: 64)
            for j in 0..<NeedleFile.lengths[i] {
                b.base.storeBytes(of: xored[offsets[i] + j] ^ 0x5A, toByteOffset: j, as: UInt8.self)
            }
            b.setCount(NeedleFile.lengths[i])
            return b
        }
        let dek = materialise(0)

        var h = scan()
        check("baseline: the DEK is in its SecretBytes only (positive control); no HPKE secret",
              h.needle(0) == 1 && (1..<5).allSatisfy { h.needle($0) == 0 }, "\(h)")
        let session: Session
        do { session = try Session.create(dir: dir.path, dek: dek, signingKey: signingKey) } catch {
            check("create", false, "\(error)")
            return
        }
        h = scan()
        check("after create: the DEK is nowhere; the session is locked", h.needle(0) == 0 && session.brev.isLocked(), "\(h)")

        // The unlock closure on its own serial queue, as UnlockService runs it.
        var result: Result<(Bool, Bool), Error>?
        let done = DispatchSemaphore(value: 0)
        DispatchQueue(label: "no.brev.unlock").async {
            result = Result { try unlock(session, wrapped: wrapped, kek: kek) }
            done.signal()
        }
        done.wait()
        switch result {
        case .success(let (sameAddress, zeroed))?:
            check("unlock: the DEK's Data is wiped in place (same address, all zero)", sameAddress && zeroed)
        case .failure(let error)?:
            check("unlock", false, "\(error)")
        case nil:
            check("unlock ran", false)
        }
        h = scan()
        check("while unlocked: the DEK is in Rust's box only", h.needle(0) == 1 && !session.brev.isLocked(), "\(h)")
        for i in 1..<5 {
            check("after the unlock closure: no \(NeedleFile.names[i])", h.needle(i) == 0, "\(h)")
        }
        session.brev.lock()
        h = scan()
        check("after lock: no DEK and no HPKE secret anywhere", (0..<5).allSatisfy { h.needle($0) == 0 }, "\(h)")
        for i in 1..<5 {
            let b = materialise(i)
            h = scan()
            b.wipe()
            check("positive control: one copy of \(NeedleFile.names[i]) is found", h.needle(i) == 1, "\(h)")
        }
    }
}

// MARK: - Case 4 (and the no-scribble half of case 6): the content path

func caseContent(units bodyUnits: Int, scribble: Bool) {
    requireScribble(scribble)
    let font = CTFontCreateWithName("Helvetica" as CFString, 13, nil)
    setGlyphNeedle(font)
    withStoreDir { dir in
        var h = scan()
        check("baseline: no marker, no glyph needle", h.u8 == 0 && h.u16 == 0 && h.glyph == 0, "\(h)")
        let session = try! makeUnlockedSession(in: dir)
        let contacts = try! session.contacts()
        check("two contacts", contacts.count == 2)

        let subject = markerText(units: 32, emoji: false)
        let body = markerText(units: bodyUnits, emoji: true)
        let thread = try! session.send(to: contacts[0].id, subject: subject, body: body)
        subject.wipe()
        body.wipe()
        let arrived = try! session.sync()
        check("the echo arrives", arrived == 1, "\(arrived)")

        let threads = try! session.threads(contact: contacts[0].id)
        let msgs = try! session.messages(thread: thread)
        check("one thread with the letter and its echo",
              threads.count == 1 && msgs.count == 2 && msgs.contains { !$0.outgoing })
        let letters = msgs.map { try! session.body(message: $0.id) }
        check("both letters read back at full length", letters.allSatisfy { $0.length == bodyUnits + 2 })

        let layout = TextLayout(font: font)
        let ctx = CGContext(data: nil, width: 800, height: 600, bitsPerComponent: 8, bytesPerRow: 0,
                            space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
        func drawAll(_ t: SecretText) {
            layout.layout(t, width: 600)
            layout.draw(t, lines: 0..<layout.lines.count, in: ctx, x: 4, top: 0)
        }
        letters.forEach(drawAll)
        // What the compose view does: composed-range lookups (Delete, arrows)
        // and a text laid out and drawn again after every keystroke.
        var sum = 0
        for k in 0..<200 { sum &+= letters[0].composedRange(at: (k * 331) % letters[0].length).count }
        let typed = SecretText(maxUnits: 512)
        for i in 0..<300 {
            var unit = markerUnit(i)
            withUnsafePointer(to: &unit) { _ = typed.insert(UnsafeBufferPointer(start: $0, count: 1), at: typed.length) }
            unit = 0
            drawAll(typed)
        }
        letters.forEach(drawAll)   // the letters' lines are the last ones drawn
        h = scan()
        check("while open: the text is in memory (positive control)", h.u16 > 0 && sum > 0, "\(h)")
        // Core Text frees a line's glyphs as soon as it is drawn, and with
        // scribbling nothing of them is left, even while a letter is shown. So
        // the glyph needle's positive control scans with one line kept alive.
        autoreleasepool {
            let n = min(letters[0].length, TextLayout.maxLineUnits)
            let s = CFStringCreateWithCharactersNoCopy(nil, letters[0].units, n, kCFAllocatorNull)!
            let attrs = [kCTFontAttributeName: font] as CFDictionary
            let line = CTLineCreateWithAttributedString(CFAttributedStringCreate(nil, s, attrs)!)
            h = scan()
            withExtendedLifetime(line) {}
        }
        check("while a line of it is alive: the glyph needle sees it (positive control)", h.glyph > 0, "\(h)")

        // The lock sequence (§8.4): wipe every text, flush, lock.
        letters.forEach { $0.wipe() }
        threads.forEach { $0.subject.wipe() }
        contacts.forEach { $0.name.wipe() }
        typed.wipe()
        GlyphFlush.flush()
        layout.reset()
        session.brev.lock()
        h = scan()
        if scribble {
            check("after wipe, flush and lock: no copy (UTF-8, UTF-16, glyphs)",
                  h.u8 == 0 && h.u16 == 0 && h.glyph == 0 && session.brev.isLocked(), "\(h)")
        } else {
            check("without MallocScribble: glyph ids are left after lock (the needle works; scribbling clears them)",
                  h.glyph > 0, "\(h)")
        }
    }
}

// MARK: - Case 5: a kept OpenText after lock

func caseKept() {
    requireScribble(true)
    withStoreDir { dir in
        let session = try! makeUnlockedSession(in: dir)
        let rows = try! session.brev.contacts()   // names deliberately left open
        let subject = markerText(units: 16, emoji: false)
        let body = markerText(units: 64, emoji: false)
        let thread = try! session.send(to: rows[0].id, subject: subject, body: body)
        subject.wipe()
        body.wipe()
        let msg = try! session.messages(thread: thread)[0]
        let kept = try! session.brev.openBody(message: msg.id)   // deliberately not closed
        check("an open body has its length", kept.byteLen() == 64 && rows[0].name.byteLen() > 0)
        session.brev.lock()
        check("after lock: a kept body throws Locked and is empty",
              throwsLocked { try kept.chunk(index: 0) } && kept.byteLen() == 0)
        check("after lock: a kept name throws Locked and is empty",
              throwsLocked { try rows[0].name.chunk(index: 0) } && rows[0].name.byteLen() == 0)
        check("after lock: every read throws Locked",
              throwsLocked { try session.contacts() } && throwsLocked { try session.body(message: msg.id) })
        let h = scan()
        check("after lock: no marker anywhere, although the handles are kept", h.u8 == 0 && h.u16 == 0, "\(h)")
        withExtendedLifetime((kept, rows)) {}
    }
}

// MARK: - Case 6: negative control

func caseControl() {
    requireScribble(true)
    var h = scan()
    check("baseline: no marker", h.u8 == 0 && h.u16 == 0, "\(h)")
    let t = markerText(units: 65_000, emoji: false)
    let b = SecretBytes(capacity: 3 * t.length)
    Transcode.utf16ToUTF8(t, into: b)
    let s = b.withBytes { String(decoding: $0, as: UTF8.self) }
    t.wipe()
    b.wipe()
    h = scan()
    check("a live String of a 64 KiB letter is visible to the scanner", h.u8 > 0, "\(h)")
    withExtendedLifetime(s) {}
}

// MARK: - Main

let args = Array(CommandLine.arguments.dropFirst())
switch (args.first, args.count) {
case ("units", 1): caseUnits()
case ("shell", 1): caseShell()
case ("argdomain", 5): caseArgumentDomain()
case ("needles", 2):
    do { try NeedleFile.make(at: URL(fileURLWithPath: args[1])) } catch {
        print("FAIL needles: \(error)")
        exit(1)
    }
    exit(0)
case ("dek", 1): caseDEK()
case ("content", 2), ("content", 3):
    guard let n = Int(args[1]), n > 0, args.count == 2 || args[2] == "--no-scribble" else {
        print("usage: harness content <units> [--no-scribble]")
        exit(2)
    }
    caseContent(units: n, scribble: args.count == 2)
case ("kept", 1): caseKept()
case ("control", 1): caseControl()
default:
    print("usage: harness units | shell | dek | content <units> [--no-scribble] | kept | control | needles <file>")
    exit(2)
}
print(failures == 0 ? "PASS" : "FAIL: \(failures) check(s)")
exit(failures == 0 ? 0 : 1)
