// main.swift — the Swift heap-scan harness (docs/PHASE2_DESIGN.md §11).
//
// A CLI process: no AppKit, no window, no Secure Enclave, no keychain, no
// prompt. It is built from app/Sources/Shared, the patched bindings and
// libbrev_core.a, drives the content path the app uses, and counts copies of
// secrets in its own memory with scan.c. scripts/test.sh runs every case five
// times (the content case at four sizes) under MallocScribble=1, as the app
// runs, plus case 6's control without scribbling, with TMPDIR under
// core/target/harness.
//
// usage: harness units | shell | compose | dek | content <units> [--no-scribble] | kept | control
//        harness scribble [--no-scribble] | network | invite
//        harness needles <file>     (the helper run that `dek` starts: ECIES needles)
//        harness argdomain -NSTraceEvents YES -NSZombieEnabled YES
//                                   (the helper run that `shell` starts)
// content, kept, network and invite need BREV_RELAY_URL: the relay
// scripts/test.sh starts on 127.0.0.1 for the whole run (docs/PHASE3_DESIGN.md
// §8), and BREV_ROOT_INVITE: a root invite test.sh mints for each run
// (`brev-relay invite`), the only way in for a run's first user
// (docs/PHASE4_DESIGN.md §4.6).
//
// Case numbers are those of §11; case 7 (SelfScan's scribble probe) came
// with review round 1 (docs/DECISIONS.md D-0063), case 8 (`network`, the
// round trip through the relay) with Phase 3, case 9 (`invite`: invites,
// approval, letters and Blokker) with Phase 4. Case 2 has two parts: the app shell's
// (InputFilter, LockState, LaunchGuard, UnlockFailure) is `shell`, the compose core's
// (EditModel, ComposeKey, KeyTranslator) is `compose`. Since Phase 3 there are no
// built-in contacts: every letter goes through the relay between users made
// here (software KEK and identity key; `Enclave.sign` signs the digests, as in
// the app). Since Phase 4 a run's first user registers with the root invite
// and brings in the others with its own invite codes. Since Hand
// (docs/AUTHORSHIP.md; D-0111) a letter goes out with its authorship token:
// a compose session, a fixed clean sample (so a sudo or SIP state of the Mac
// running the tests cannot lock the harness's sessions; HandSampler's own
// reads are checked in case 2), and two signatures; case 8 also reads the
// recipient's proof and locks a session with a sudo sample. Output is
// content-free: check names and hit counts only.

import Carbon.HIToolbox
import CoreGraphics
import CoreText
import CryptoKit
import Foundation
import LocalAuthentication
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

// MARK: - Sessions, as the app makes them (software keys)

/// A new software P-256 key pair, as a SecKey (not in any keychain): the
/// stand-in for the KEK and for the identity key.
func newSoftwareKey() throws -> SecKey {
    let attrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                                kSecAttrKeySizeInBits as String: 256]
    var err: Unmanaged<CFError>?
    guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &err)
    else { throw err.map { $0.takeRetainedValue() as Error } ?? Enclave.Failure.unknown }
    return key
}

/// The public key of `key` as `Brev.create` takes it (65 bytes, X9.63).
func publicKeyBytes(_ key: SecKey) throws -> Data {
    guard let pub = SecKeyCopyPublicKey(key) else { throw Enclave.Failure.unknown }
    return try Enclave.publicKeyBytes(of: pub)
}

/// A relay URL that is never contacted: for a session that makes no request.
let offlineRelay = "http://127.0.0.1:9"

/// The relay scripts/test.sh started for this run.
func relayURL() -> String {
    guard let url = getenv("BREV_RELAY_URL").map({ String(cString: $0) }), !url.isEmpty else {
        print("FAIL this case needs BREV_RELAY_URL (the relay scripts/test.sh starts)")
        exit(2)
    }
    return url
}

/// The root invite scripts/test.sh minted for this run (BREV_ROOT_INVITE),
/// copied into a SecretBytes without a String. Each is good for one
/// registration.
func rootInvite() -> SecretBytes {
    guard let p = getenv("BREV_ROOT_INVITE"), strlen(p) > 0 else {
        print("FAIL this case needs BREV_ROOT_INVITE (the root invite scripts/test.sh mints)")
        exit(2)
    }
    let code = SecretBytes(capacity: Int(limits().maxInvite))
    guard code.append(UnsafeRawBufferPointer(start: p, count: strlen(p))) else {
        print("FAIL BREV_ROOT_INVITE is longer than an invite code")
        exit(2)
    }
    return code
}

/// An address no run used before: the relay lives through every run of
/// test.sh, and an address is taken for good.
func freshAddress(_ who: String) -> String {
    "\(who)-\(getpid())-\(UInt32.random(in: 0...UInt32.max))"
}

/// The mode Rust requires of a store's folder.
let privateFolder: [FileAttributeKey: Any] = [.posixPermissions: 0o700]

/// A sample of a Mac with nothing wrong (docs/AUTHORSHIP.md §3.1): fixed,
/// so that the Mac running the tests (a sudo in a terminal, say) cannot lock
/// the harness's sessions.
let cleanSample = Sample(secureInput: true, sharingNone: true, preventsCapture: true, csrConfig: 0,
                         processes: ["launchd", "harness"], windows: [])

/// What this CLI process is by design: no content views, no BrevApplication.
let harnessDesign = Design(axOpaque: false, pasteboardOff: false, inputFilter: false)

/// A fresh directory (mode 0700) in TMPDIR for one run's stores, removed
/// afterwards.
func withStoreDir(_ body: (URL) -> Void) {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("brev-harness-\(getpid())")
    try? FileManager.default.removeItem(at: dir)
    try! FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: privateFolder)
    defer { try? FileManager.default.removeItem(at: dir) }
    body(dir)
}

/// The unlock closure of §5.4 (UnlockService): unwrap the DEK, unlock on
/// the same thread without a copy, and the CFData is zeroed in place when
/// `unwrap` returns; then the confirmation LockController makes on main.
/// Any error locks the session. Returns whether `Brev.unlock`
/// got the bytes of the CFData Security returned (no copy) and whether that
/// CFData is all zero after `unwrap`; the harness keeps it alive to look.
@discardableResult
func unlock(_ session: Session, wrapped: Data, kek: SecKey) throws -> (sameAddress: Bool, zeroed: Bool) {
    var plain: CFData?
    var seen: UnsafeRawPointer?
    do {
        try Enclave.unwrap(wrapped, with: kek, decrypt: {
            plain = SecKeyCreateDecryptedData($0, $1, $2, $3)
            return plain
        }) { dek in
            seen = dek.withUnsafeBytes { $0.baseAddress }
            do { try session.brev.unlock(dek: dek, idleSecs: LockState.rustIdleSecs) } catch {
                throw CoreUnlockError(underlying: error)
            }
        }
        try session.brev.confirmActive(sample: cleanSample)
    } catch {
        session.brev.lock()
        throw error
    }
    guard let plain, let p = CFDataGetBytePtr(plain) else { return (false, false) }
    return (seen == UnsafeRawPointer(p), allZero(plain))
}

/// Whether `data` holds 32 bytes, all zero.
func allZero(_ data: CFData) -> Bool {
    guard CFDataGetLength(data) == 32, let p = CFDataGetBytePtr(data) else { return false }
    return UnsafeBufferPointer(start: p, count: 32).allSatisfy { $0 == 0 }
}

/// One user, unlocked, as onboarding makes one with software keys: the
/// KEK wraps the DEK (the unlock closure unwraps it), and the identity key
/// signs digests through Enclave.sign, the code the app signs with
/// (SignService adds only the keychain lookup and Touch ID).
final class User {
    let session: Session
    let identity: SecKey

    /// Onboarding steps 6 and 7 in `dir`: a random DEK in a SecretBytes,
    /// wrapped, `Session.create` (which wipes it), then the unlock.
    init(in dir: URL, relay: String) throws {
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: privateFolder)
        identity = try newSoftwareKey()
        let dek = SecretBytes(capacity: 64)
        guard SecRandomCopyBytes(kSecRandomDefault, 32, dek.base) == errSecSuccess else { throw BrevError.Rng }
        dek.setCount(32)
        let kek = try newSoftwareKey()
        guard let kekPublic = SecKeyCopyPublicKey(kek) else { throw Enclave.Failure.unknown }
        let wrapped = try Enclave.wrap(dek: dek, to: kekPublic)
        session = try Session.create(dir: dir.path, relay: relay, dek: dek, signingKey: try publicKeyBytes(identity))
        try unlock(session, wrapped: wrapped, kek: kek)
    }

    /// Registers `address` with the invite opened last, typed as the app
    /// passes it: the digest, the signature, the post (with NoAttestor's
    /// empty attestation).
    func register(_ address: String) throws {
        let typed = secret(address)
        defer { typed.wipe() }
        let digest = try session.registerRequest(address: typed)
        try session.register(signature: try Enclave.sign(digest: digest, key: identity), digest: digest)
    }

    /// Opens the invite `code` (the caller wipes it), then registers
    /// `address` with it.
    func register(_ address: String, invite code: SecretBytes) throws {
        let opened = try session.openInvite(code: code)
        opened.address.wipe()
        opened.code.wipe()
        try register(address)
    }

    /// Adds the contact with `address`; returns its local id.
    func add(_ address: String) throws -> Data {
        let typed = secret(address)
        defer { typed.wipe() }
        return try session.addContact(address: typed)
    }

    /// The local id and state of the contact with `address`; NotFound if
    /// there is none. The names read are wiped.
    func contact(_ address: String) throws -> Seen {
        let items = try session.contacts()
        defer { items.forEach { $0.name.wipe() } }
        guard let c = items.first(where: { unitsOf($0.name) == Array(address.utf16) }) else { throw BrevError.NotFound }
        return Seen(id: c.id, waiting: c.waiting, verified: c.verified, blocked: c.blocked)
    }

    /// Where the identity key lives, as the key says: software. Class C,
    /// which the test archive (allow-software-keys) sends in.
    var keyOrigin: KeyOrigin {
        Enclave.isInSecureEnclave(identity) ? .secureEnclave : .software
    }

    /// One letter in the app's steps (PHASE3 §3.2, AUTHORSHIP §3): a
    /// compose session, prepare, the token's digest, its signature, the
    /// envelope's digest, its signature, submit. Returns the thread id. The
    /// caller wipes the texts.
    func send(to contact: Data, subject: SecretText, body: SecretText) throws -> Data {
        try session.composeStarted(design: harnessDesign, admin: nil, keyOrigin: keyOrigin)
        try session.prepareSend(contact: contact, sample: cleanSample)
        let token = try session.signRequest(contact: contact, subject: subject, body: body, sample: cleanSample)
        let envelope = try session.attachTokenSignature(try Enclave.sign(digest: token, key: identity))
        try session.attachSignature(try Enclave.sign(digest: envelope, key: identity))
        let thread = try session.submit()
        try session.composeClosed()
        return thread
    }

    func lock() { session.brev.lock() }
}

/// A contact's local id and state (docs/PHASE4_DESIGN.md §5.2).
struct Seen {
    let id: Data
    let waiting: Bool, verified: Bool, blocked: Bool
}

/// Two registered users who are each other's contacts.
struct Pair {
    let a: User, b: User
    /// B's local id at A, and A's at B.
    let aSeesB: Data, bSeesA: Data
    let addressA: String, addressB: String
}

/// A registers with the run's root invite and B with an invite code A made;
/// B pins A as it registers, and A's sync pins B (its invited event), as two
/// people who meet through an invite (docs/PHASE4_DESIGN.md §3.4, §5.3).
func makePair(in dir: URL, relay: String) throws -> Pair {
    let a = try User(in: dir.appendingPathComponent("a"), relay: relay)
    let b = try User(in: dir.appendingPathComponent("b"), relay: relay)
    let addressA = freshAddress("a"), addressB = freshAddress("b")
    let root = rootInvite()
    defer { root.wipe() }
    try a.register(addressA, invite: root)
    let code = try a.session.createInvite()
    defer { code.wipe() }
    try b.register(addressB, invite: code)
    _ = try a.session.sync()
    return Pair(a: a, b: b, aSeesB: try a.contact(addressB).id, bSeesA: try b.contact(addressA).id,
                addressA: addressA, addressB: addressB)
}

func throwsError<R>(_ expected: BrevError, _ f: () throws -> R) -> Bool {
    do { _ = try f(); return false } catch let e as BrevError { return e == expected } catch { return false }
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

    // TextLayout.firstLine and drawLine: what a list row shows (§7.2)
    func firstLength(_ s: String) -> Int { TextLayout.firstLine(secret(s)).length }
    let head = TextLayout.firstLine(text)
    check("TextLayout.firstLine: a long first paragraph gives 448 units from the start",
          head.start == 0 && head.length == TextLayout.maxLineUnits)
    check("TextLayout.firstLine: stops at the first line break", firstLength("Ekko\nSpeil") == 4)
    check("TextLayout.firstLine: empty text and a leading line break give an empty line",
          firstLength("") == 0 && firstLength("\nx") == 0)
    check("TextLayout.firstLine: never ends on the lead surrogate of a pair",
          firstLength(String(repeating: "x", count: 447) + "\u{1F600}") == 447)
    let row = CGContext(data: nil, width: 200, height: 20, bitsPerComponent: 8, bytesPerRow: 0,
                        space: CGColorSpaceCreateDeviceGray(), bitmapInfo: CGImageAlphaInfo.none.rawValue)!
    func inked(_ draw: () -> Void) -> Int {
        row.setFillColor(gray: 0, alpha: 1)
        row.fill(CGRect(x: 0, y: 0, width: 200, height: 20))
        row.setFillColor(gray: 1, alpha: 1)
        draw()
        let p = row.data!.assumingMemoryBound(to: UInt8.self)
        return (0..<(row.bytesPerRow * row.height)).filter { p[$0] != 0 }.count
    }
    let name = secret("Ekko\nSpeil")
    check("TextLayout.drawLine: draws the first line", inked {
        layout.drawLine(name, TextLayout.firstLine(name), in: row, x: 2, baseline: 15)
    } > 0)
    check("TextLayout.drawLine: a line outside the text draws nothing", inked {
        layout.drawLine(name, LineRef(start: 6, length: 8), in: row, x: 2, baseline: 15)
    } == 0)

    // Enclave: ECIES wrap and unwrap with a software KEK
    caseEnclaveUnits()
}

func caseEnclaveUnits() {
    guard let kek = try? newSoftwareKey(), let kekPublic = SecKeyCopyPublicKey(kek) else {
        check("a software P-256 key can be made", false)
        return
    }
    let raw = try? Enclave.publicKeyBytes(of: kekPublic)
    check("Enclave: a public key is 65 bytes in X9.63 form", raw?.count == 65 && raw?.first == 0x04)
    let dek = SecretBytes(capacity: 64)
    _ = SecRandomCopyBytes(kSecRandomDefault, 32, dek.base)
    dek.setCount(32)
    let wrapped = try? Enclave.wrap(dek: dek, to: kekPublic)
    let equal = wrapped.flatMap { w in try? Enclave.unwrap(w, with: kek) { d in dek.withBytes { Data($0) == d } } }
    check("Enclave: wrap gives 113 bytes, unwrap gives the DEK back",
          wrapped?.count == Enclave.wrappedLength && equal == true)
    let short = SecretBytes(capacity: 64)
    short.setCount(31)
    check("Enclave: only a 32-byte DEK is wrapped",
          { do { _ = try Enclave.wrap(dek: short, to: kekPublic); return false } catch Enclave.Failure.malformed { return true } catch { return false } }())
    dek.wipe()
    var ran = false
    let refused: Bool
    do { try Enclave.unwrap(Data(count: 112), with: kek) { _ in ran = true }; refused = false } catch Enclave.Failure.malformed {
        refused = true
    } catch { refused = false }
    check("Enclave: a wrapped DEK of the wrong length is refused before Security sees it", refused && !ran)
    if var bad = wrapped {
        bad[bad.count - 1] ^= 1
        do {
            try Enclave.unwrap(bad, with: kek) { _ in ran = true }
            check("Enclave: a tampered wrapped DEK is refused", false)
        } catch {
            let codes = UnlockFailure.chain(error).map { "\($0.domain) \($0.code)" }.joined(separator: ", ")
            // Security reports errSecParam (-50) here; it reads as retry.
            check("Enclave: a tampered wrapped DEK is refused and reads as retry [\(codes)]",
                  !ran && UnlockFailure.classify(error, fingersChanged: false) == .retry)
        }
    }

    // withWiped: the view is the CFData's own bytes, zeroed in place on
    // every path.
    let filled = [UInt8](repeating: 0xAB, count: 32)
    let cf = CFDataCreate(nil, filled, 32)!
    let p = CFDataGetBytePtr(cf)!
    let seen = Enclave.withWiped(cf) { v in
        (v.withUnsafeBytes { $0.baseAddress } == UnsafeRawPointer(p), v.count, v.allSatisfy { $0 == 0xAB })
    }
    check("Enclave.withWiped: the Data is the CFData's bytes (no copy), zeroed afterwards",
          seen.0 && seen.1 == 32 && seen.2 && UnsafeBufferPointer(start: p, count: 32).allSatisfy { $0 == 0 })
    let cf2 = CFDataCreate(nil, filled, 32)!
    let p2 = CFDataGetBytePtr(cf2)!
    let threw = (try? Enclave.withWiped(cf2) { _ in throw Enclave.Failure.malformed }) == nil
    check("Enclave.withWiped: zeroed also when the body throws",
          threw && UnsafeBufferPointer(start: p2, count: 32).allSatisfy { $0 == 0 })

    // unwrap zeroes the CFData Security returned also when the body throws
    // (a failed Brev.unlock); case 3 checks the unlock that succeeds.
    if let wrapped {
        var plain: CFData?
        let failed = (try? Enclave.unwrap(wrapped, with: kek, decrypt: {
            plain = SecKeyCreateDecryptedData($0, $1, $2, $3)
            return plain
        }) { _ in throw Enclave.Failure.unknown }) == nil
        check("Enclave.unwrap: Security's CFData is zeroed also when the body throws",
              failed && plain.map(allZero) == true)
    }

    // sign: the signature over a digest is the message signature over the
    // bytes it was made from (PHASE3 §3.1), in DER.
    let message = Data("brev/v1/register\u{0}harness".utf8)
    let digest = Data(SHA256.hash(data: message))
    let signature = try? Enclave.sign(digest: digest, key: kek)
    let verifies = signature.map { SecKeyVerifySignature(kekPublic, .ecdsaSignatureMessageX962SHA256, message as CFData,
                                                         $0 as CFData, nil) } ?? false
    check("Enclave.sign: a DER signature over the digest that verifies as the message signature",
          verifies && signature?.first == 0x30 && (8...72).contains(signature?.count ?? 0))
    var other = message
    other[0] ^= 1
    check("Enclave.sign: it does not verify for another message",
          signature.map { !SecKeyVerifySignature(kekPublic, .ecdsaSignatureMessageX962SHA256, other as CFData,
                                                  $0 as CFData, nil) } ?? false)
    check("Enclave.sign: only a 32-byte digest is signed",
          { do { _ = try Enclave.sign(digest: digest.prefix(31), key: kek); return false } catch Enclave.Failure.malformed { return true } catch { return false } }())
}

// MARK: - Case 2, the app shell's part: InputFilter, LockState, UnlockFailure, LaunchGuard

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
    let all: [LockReason] = [.resignActive, .screenLocked, .sleep, .sessionResign, .idle, .manual, .terminate,
                             .unlockExpired]
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
    // A signature's Touch ID prompt (Send, Registrer; docs/PHASE3_DESIGN.md
    // §3.2), with the U4 switch in both positions.
    check("LockState: the U4 switch is off (a signature's prompt keeps auto-lock), the safe side",
          !LockState.signPanelTakesActivation && !LockState().panelTakesActivation)
    let off = LockState()
    var sign = off.beginSign()
    check("LockState, U4 off: resign-active during a signature's prompt locks, like every other reason",
          off.signInFlight && all.allSatisfy { off.shouldLock(for: $0) })
    check("LockState, U4 off: a signature that ends with no lock since may be used, Brev active or not",
          off.endSign(sign, appActive: false) && !off.signInFlight)
    sign = off.beginSign()
    off.lock()
    check("LockState, U4 off: a lock during the prompt ends it and discards the signature",
          !off.signInFlight && !off.endSign(sign, appActive: true))
    let on = LockState(signPanelTakesActivation: true)
    sign = on.beginSign()
    check("LockState, U4 on: resign-active during a signature's prompt does not lock; every other reason does",
          !on.shouldLock(for: .resignActive) && all.dropFirst().allSatisfy { on.shouldLock(for: $0) })
    check("LockState, U4 on: a signature that ends while Brev is inactive is discarded, the generation unchanged"
            + " (the caller locks); resign-active locks again",
          !on.endSign(sign, appActive: false) && on.generation == sign && on.shouldLock(for: .resignActive))
    sign = on.beginSign()
    check("LockState, U4 on: a signature that ends while Brev is active may be used", on.endSign(sign, appActive: true))
    sign = on.beginSign()
    on.lock()
    check("LockState, U4 on: a lock during the prompt ends it (resign-active locks again) and discards the signature",
          on.shouldLock(for: .resignActive) && !on.endSign(sign, appActive: true))
    let u4 = LockState(signPanelTakesActivation: true)
    _ = u4.beginUnlock()
    check("LockState, U4 on: an unlock's exemption is unchanged, and a signature is not an unlock",
          !u4.shouldLock(for: .resignActive) && !u4.signInFlight
            && u4.endUnlock(u4.generation, succeeded: true, appActive: true) && u4.shouldLock(for: .resignActive))

    let t0: UInt64 = 1_000_000_000_000, limit = LockState.idleLimitNanos
    check("LockState: idle at 300 s, not before, not with a clock behind the last input",
          limit == 300_000_000_000 && !LockState.isIdle(now: t0 + limit - 1, lastInput: t0)
            && LockState.isIdle(now: t0 + limit, lastInput: t0) && !LockState.isIdle(now: t0 - 1, lastInput: t0))
    check("LockState: Rust's idle deadline (320 s) comes after Swift's last idle check (300 s + 15 s)",
          UInt64(LockState.rustIdleSecs) * 1_000_000_000 > limit + UInt64(LockState.idleCheckInterval) * 1_000_000_000)

    caseUnlockFailure()

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
    // The loop above only tests the keys that are listed. HIToolbox's
    // key-event trace works in Release (launch spike, D-0064), so it must be.
    defaults.register(defaults: ["TSMEventTracing": true])
    let tsm = LaunchGuard.verdict(environment: safe, defaults: defaults)
    defaults.register(defaults: ["TSMEventTracing": false])
    check("LaunchGuard: the default TSMEventTracing (HIToolbox's key-event trace) makes a launch unsafe",
          tsm == .unsafe && LaunchGuard.verdict(environment: safe, defaults: defaults) == .safe)
    // HandSampler (docs/AUTHORSHIP.md §3.1): its raw reads work in a
    // process like Brev's, without a prompt. Nothing here reads a value that
    // depends on this Mac (SIP's bits, whether a sudo runs), only that each
    // read gives one.
    let sample = HandSampler.sample(sharingNone: true, preventsCapture: false)
    check("HandSampler: SIP's bits, every process name (this one's among them) and admin membership are read",
          HandSampler.csrConfig() != nil && sample.csrConfig != nil
              && sample.processes?.contains("harness") == true && sample.processes?.count ?? 0 > 10
              && HandSampler.isAdmin() != nil,
          "csr \(HandSampler.csrConfig() != nil), processes \(sample.processes?.count ?? -1), admin \(HandSampler.isAdmin() != nil)")
    check("HandSampler: the window settings the caller read go into the sample as they are",
          sample.sharingNone && !sample.preventsCapture)
    if let windows = HandSampler.windows() {
        check("HandSampler: the on-screen windows are read as owner pid and layer (\(windows.count))",
              windows.allSatisfy { $0.ownerPid >= 0 })
    } else {
        print("skip HandSampler's window list: no window server session here")
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

/// UnlockFailure.classify (design §5.5) on errors made in memory.
func caseUnlockFailure() {
    func ns(_ domain: String, _ code: Int, under: Error? = nil) -> NSError {
        NSError(domain: domain, code: code, userInfo: under.map { [NSUnderlyingErrorKey: $0 as NSError] } ?? [:])
    }
    let os = NSOSStatusErrorDomain, tk = UnlockFailure.tokenDomain
    let table: [(String, Error, Bool, UnlockFailure)] = [
        ("LA userCancel", LAError(.userCancel), false, .cancelled),
        ("LA systemCancel", LAError(.systemCancel), true, .cancelled),
        ("LA appCancel", LAError(.appCancel), false, .cancelled),
        ("TK canceledByUser", ns(tk, -4), true, .cancelled),
        ("errSecUserCanceled", ns(os, Int(errSecUserCanceled)), false, .cancelled),
        ("a cancel under an OSStatus", ns(os, Int(errSecAuthFailed), under: LAError(.userCancel)), true, .cancelled),
        ("LA biometryLockout, fingers changed", LAError(.biometryLockout), true, .lockout),
        ("LA biometryNotAvailable", LAError(.biometryNotAvailable), false, .unavailable),
        ("LA biometryNotEnrolled", LAError(.biometryNotEnrolled), true, .unavailable),
        ("LA biometryNotPaired", LAError(.biometryNotPaired), false, .unavailable),
        ("LA biometryDisconnected", LAError(.biometryDisconnected), false, .unavailable),
        ("Rust WrongKey", CoreUnlockError(underlying: BrevError.WrongKey), false, .damaged),
        ("Rust Corrupt, fingers changed", CoreUnlockError(underlying: BrevError.Corrupt), true, .damaged),
        ("Rust Io, fingers changed", CoreUnlockError(underlying: BrevError.Io), true, .retry),
        ("a missing key or item", ns(os, Int(errSecItemNotFound)), false, .damaged),
        ("a missing key or item, fingers changed", ns(os, Int(errSecItemNotFound)), true, .fingers),
        ("a malformed wrapped DEK", Enclave.Failure.malformed, false, .damaged),
        ("TK corruptedData", ns(tk, -3), false, .damaged),
        ("TK authenticationFailed", ns(tk, -5), false, .retry),
        ("TK authenticationFailed, fingers changed", ns(tk, -5), true, .fingers),
        ("LA authenticationFailed", LAError(.authenticationFailed), false, .retry),
        ("LA notInteractive", LAError(.notInteractive), false, .retry),
        ("another OSStatus", ns(os, Int(errSecInteractionNotAllowed)), false, .retry),
    ]
    for (name, error, changed, expected) in table {
        let got = UnlockFailure.classify(error, fingersChanged: changed)
        check("UnlockFailure: \(name) → \(expected.rawValue)", got == expected, got.rawValue)
    }
    let resets = [UnlockFailure.cancelled, .lockout, .unavailable, .damaged, .fingers, .retry].filter(\.offersReset)
    check("UnlockFailure: only damaged and fingers offer the reset", resets == [.damaged, .fingers])
    let chain = UnlockFailure.chain(ns(os, -1, under: ns(tk, -2, under: LAError(.userCancel))))
    check("UnlockFailure: the error chain is read outermost first",
          chain.map(\.code) == [-1, -2, LAError.userCancel.rawValue] && chain.last?.domain == LAErrorDomain)
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

// MARK: - Case 2, the compose core's part: EditModel, ComposeKey, KeyTranslator

/// Non-content test units into `m`, as one keystroke.
func typeUnits(_ m: EditModel, _ s: String) -> Bool {
    Array(s.utf16).withUnsafeBufferPointer { m.insert($0) }
}

/// Whether the caret is at the start of a composed character (or the end).
func atBoundary(_ m: EditModel) -> Bool {
    m.caret == m.text.length || m.text.composedRange(at: m.caret).lowerBound == m.caret
}

func caseCompose() {
    requireScribble(true)
    caseEditModel()
    caseComposeKey()
    caseKeyTranslator()
}

func caseComposeKey() {
    let none: CGEventFlags = [], cmd = CGEventFlags.maskCommand, ctrl = CGEventFlags.maskControl
    let shift = CGEventFlags.maskShift, opt = CGEventFlags.maskAlternate
    // Arrow keys carry the fn and numeric-pad flags from the hardware.
    let arrow: CGEventFlags = [.maskSecondaryFn, .maskNumericPad]
    func of(_ k: Int, _ f: CGEventFlags) -> ComposeKey { ComposeKey.of(keyCode: UInt16(k), flags: f) }
    check("ComposeKey: ⌘↩ and ⌘Enter send", of(kVK_Return, cmd) == .send && of(kVK_ANSI_KeypadEnter, cmd) == .send)
    check("ComposeKey: ⌘← ⌘→ go to the line's start and end, ⌘↑ ⌘↓ to the text's",
          of(kVK_LeftArrow, cmd.union(arrow)) == .lineStart && of(kVK_RightArrow, cmd.union(arrow)) == .lineEnd
            && of(kVK_UpArrow, cmd.union(arrow)) == .documentStart && of(kVK_DownArrow, cmd.union(arrow)) == .documentEnd)
    let editing = [kVK_ANSI_C, kVK_ANSI_V, kVK_ANSI_X, kVK_ANSI_A, kVK_ANSI_Z, kVK_ANSI_W, kVK_Delete, kVK_Tab, kVK_Space]
    check("ComposeKey: every other ⌘ key does nothing (⌘C ⌘V ⌘X ⌘A ⌘Z ⌘⇧Z ⌘⌥V ⌘⌫ ⌘Tab ⌘Space)",
          editing.allSatisfy { of($0, cmd) == .ignore } && of(kVK_ANSI_Z, cmd.union(shift)) == .ignore
            && of(kVK_ANSI_V, cmd.union(opt)) == .ignore)
    check("ComposeKey: every ⌃ key does nothing, ⌘ or not",
          [kVK_ANSI_A, kVK_ANSI_V, kVK_Return, kVK_Tab, kVK_Delete, kVK_LeftArrow, kVK_Escape].allSatisfy {
              of($0, ctrl) == .ignore && of($0, ctrl.union(cmd)) == .ignore
          })
    var named = true
    for f in [none, shift, opt, shift.union(opt), .maskAlphaShift] {
        named = named && of(kVK_Return, f) == .newline && of(kVK_ANSI_KeypadEnter, f) == .newline
            && of(kVK_Delete, f) == .deleteBackward && of(kVK_ForwardDelete, f.union(arrow)) == .deleteForward
            && of(kVK_LeftArrow, f.union(arrow)) == .left && of(kVK_RightArrow, f.union(arrow)) == .right
            && of(kVK_UpArrow, f.union(arrow)) == .up && of(kVK_DownArrow, f.union(arrow)) == .down
            && of(kVK_Tab, f) == .otherField && of(kVK_Escape, f) == .cancel
    }
    check("ComposeKey: named keys go by key code, whatever ⇧, ⌥ or Caps Lock is held", named)
    check("ComposeKey: letters, digits, space, the dead keys and the function keys are text for KeyTranslator",
          [kVK_ANSI_A, kVK_ANSI_4, kVK_Space, kVK_ANSI_Equal, kVK_ANSI_RightBracket, kVK_Home, kVK_F5].allSatisfy {
              of($0, none) == .text && of($0, shift) == .text && of($0, opt) == .text && of($0, .maskAlphaShift) == .text
          })
}

func caseEditModel() {
    // Inserts, the byte limit and refused units, in a single-line field.
    let s = EditModel(maxBytes: 8, multiline: false)
    check("EditModel: a new field is empty, with room for maxBytes units",
          s.text.length == 0 && s.caret == 0 && s.utf8Count == 0 && s.text.maxUnits == 8)
    check("EditModel: an insert goes in at the caret, which moves past it",
          typeUnits(s, "abc") && unitsOf(s.text) == Array("abc".utf16) && s.caret == 3)
    check("EditModel: no newline in a single-line field", !s.insertNewline() && unitsOf(s.text) == Array("abc".utf16))
    s.moveLeft()
    check("EditModel: an insert in the middle",
          typeUnits(s, "æ") && unitsOf(s.text) == Array("abæc".utf16) && s.caret == 3 && s.utf8Count == 5)
    check("EditModel: an insert up to the byte limit", typeUnits(s, "€") && s.utf8Count == 8 && s.caret == 4)
    let full = unitsOf(s.text)
    check("EditModel: an insert past the byte limit is refused, changes nothing and leaves the tail zero",
          !typeUnits(s, "x") && unitsOf(s.text) == full && s.caret == 4 && s.utf8Count == 8
            && (full.count..<s.text.maxUnits).allSatisfy { s.text.units[$0] == 0 })
    let b = EditModel(maxBytes: 64, multiline: true)
    let controls: [UInt16] = [0x00, 0x01, 0x04, 0x09, 0x0A, 0x0D, 0x10, 0x1B, 0x1F, 0x7F]
    let refused = controls.allSatisfy { c in [c].withUnsafeBufferPointer { !b.insert($0) } }
    check("EditModel: control characters are refused (Home, End, function keys), also a newline as text",
          refused && b.text.length == 0)
    check("EditModel: an empty insert (a dead key) is no refusal", [UInt16]().withUnsafeBufferPointer { b.insert($0) })
    check("EditModel: a newline in a multi-line field",
          typeUnits(b, "a") && b.insertNewline() && unitsOf(b.text) == [0x61, 0x0A] && b.caret == 2)

    // An address field (docs/PHASE3_DESIGN.md §6.5): a–z, 0–9 and "-";
    // A–Z become a–z; every other keystroke is refused whole.
    let a = EditModel(maxBytes: 32, multiline: false, charset: .address)
    check("EditModel, address: a–z, 0–9 and - are taken, A–Z become a–z",
          typeUnits(a, "Brev-2") && typeUnits(a, "X") && unitsOf(a.text) == Array("brev-2x".utf16) && a.caret == 7)
    let kept = unitsOf(a.text)
    check("EditModel, address: anything else is refused and changes nothing (æ Ø é space . _ @ + emoji)",
          ["æ", "Ø", "é", "e\u{301}", " ", ".", "_", "@", "+", "\u{1F600}"].allSatisfy { !typeUnits(a, $0) }
            && unitsOf(a.text) == kept && a.caret == 7)
    check("EditModel, address: a keystroke with one refused unit is refused whole", !typeUnits(a, "a.") && unitsOf(a.text) == kept)
    check("EditModel, address: no newline", !a.insertNewline() && unitsOf(a.text) == kept)
    a.wipe()
    check("EditModel, address: at most 32 characters",
          typeUnits(a, String(repeating: "a", count: 32)) && !typeUnits(a, "b") && a.text.length == 32)
    let map = (UInt16(0)...UInt16(0x7F)).allSatisfy { c in
        let want: UInt16? = (0x41...0x5A).contains(c) ? c + 0x20
            : ((0x61...0x7A).contains(c) || (0x30...0x39).contains(c) || c == 0x2D) ? c : nil
        return EditModel.addressUnit(c) == want
    } && (UInt16(0x80)...UInt16(0xFFFF)).allSatisfy { EditModel.addressUnit($0) == nil }
    check("EditModel, address: the unit rule over every UTF-16 unit", map)
    check("EditModel, address: no paste", Array("abc".utf8).withUnsafeBytes { !a.insertPasted($0) }
            && a.text.length == 32)

    // A contact field (docs/PHASE4_DESIGN.md §6.2): an address or an invite
    // code, so also "."; the only field a paste goes into.
    let f = EditModel(maxBytes: 96, multiline: false, charset: .contact)
    let contactMap = (UInt16(0)...UInt16(0xFFFF)).allSatisfy { u in
        EditModel.contactUnit(u) == (u == 0x2E ? u : EditModel.addressUnit(u))
    }
    check("EditModel, contact: the address rule and \".\", over every UTF-16 unit", contactMap)
    check("EditModel, contact: keys type a code, A–Z become a–z; æ, space, _ and a newline are refused",
          typeUnits(f, "brev1.Ab-2") && unitsOf(f.text) == Array("brev1.ab-2".utf16)
            && ["æ", " ", "_", "@"].allSatisfy { !typeUnits(f, $0) } && !f.insertNewline())
    f.wipe()
    func paste(_ m: EditModel, _ bytes: [UInt8]) -> Bool { bytes.withUnsafeBytes { m.insertPasted($0) } }
    let code = "brev1.brev-secret-me.abcdefghijklmnopqrstuvwxyz2345.abcdefghijklmnopqrstuvwxyz"
    check("EditModel, contact: a paste goes in at the caret as one insert, folded; spaces, tabs and line breaks left out",
          paste(f, Array(" \t\(code.uppercased())\r\n".utf8)) && unitsOf(f.text) == Array(code.utf16)
            && f.caret == code.utf16.count)
    f.moveToStart()
    check("EditModel, contact: a paste in the middle", paste(f, Array("x.".utf8)) && f.caret == 2
            && unitsOf(f.text) == Array(("x." + code).utf16))
    let pasted = unitsOf(f.text)
    check("EditModel, contact: a paste with one refused byte (æ in UTF-8, a comma, a NUL, a control) changes nothing",
          [Array("abcæ".utf8), Array("ab,c".utf8), [0x61, 0x00], [0x61, 0x1B]].allSatisfy { !paste(f, $0) }
            && unitsOf(f.text) == pasted && f.caret == 2)
    check("EditModel, contact: only whitespace, or nothing, is refused", !paste(f, Array(" \n".utf8)) && !paste(f, []))
    f.wipe()
    check("EditModel, contact: a paste past 96 bytes of text, or of more than 256 bytes, is refused whole",
          !paste(f, Array(repeating: 0x61, count: 97)) && f.text.length == 0
            && !paste(f, Array(repeating: 0x20, count: 256) + [0x61]) && f.text.length == 0
            && paste(f, Array(repeating: 0x20, count: 255) + [0x61]) && unitsOf(f.text) == [0x61])
    check("EditModel: a body takes no paste", Array("abc".utf8).withUnsafeBytes { !b.insertPasted($0) })

    // The UTF-8 count is Transcode's, also as surrogates pair up and split.
    let u = EditModel(maxBytes: 64, multiline: true)
    func countIsTranscode() -> Bool {
        let out = SecretBytes(capacity: 3 * u.text.length)
        Transcode.utf16ToUTF8(u.text, into: out)
        return out.count == u.utf8Count
    }
    var counts = typeUnits(u, "a\u{1F600}é™") && countIsTranscode() && u.utf8Count == 1 + 4 + 2 + 3
    counts = counts && [UInt16(0xD83D)].withUnsafeBufferPointer { u.insert($0) } && countIsTranscode() && u.utf8Count == 13
    counts = counts && [UInt16(0xDE00)].withUnsafeBufferPointer { u.insert($0) } && countIsTranscode() && u.utf8Count == 14
    u.moveLeft()   // over the pair the two surrogates now make
    counts = counts && u.caret == 5 && u.deleteForward() && countIsTranscode() && u.utf8Count == 10
    check("EditModel: the UTF-8 count equals Transcode's output (pairs 4, lone surrogates 3)", counts, "\(u.utf8Count)")

    // Composed characters: ←/→ and both deletes step over them whole.
    let c = EditModel(maxBytes: 64, multiline: true)
    _ = typeUnits(c, "a\u{1F600}e\u{301}\u{1F469}\u{200D}\u{1F4BB}b")   // boundaries 0 1 3 5 10 11
    c.moveToStart()
    var stops = [c.caret]
    for _ in 0..<6 { c.moveRight(); stops.append(c.caret) }
    check("EditModel: → moves by composed character and stops at the end", stops == [0, 1, 3, 5, 10, 11, 11], "\(stops)")
    stops = [c.caret]
    for _ in 0..<6 { c.moveLeft(); stops.append(c.caret) }
    check("EditModel: ← moves by composed character and stops at the start", stops == [11, 10, 5, 3, 1, 0, 0], "\(stops)")
    c.moveToEnd()
    var lengths = [c.text.length]
    while c.deleteBackward() { lengths.append(c.text.length) }
    check("EditModel: Delete removes one composed character at a time",
          lengths == [11, 10, 5, 3, 1, 0] && c.caret == 0 && (0..<c.text.maxUnits).allSatisfy { c.text.units[$0] == 0 },
          "\(lengths)")
    _ = typeUnits(c, "e\u{301}\u{1F600}x")
    c.moveToStart()
    lengths = [c.text.length]
    while c.deleteForward() { lengths.append(c.text.length) }
    check("EditModel: Forward Delete removes one composed character at a time",
          lengths == [5, 3, 1, 0] && c.caret == 0, "\(lengths)")

    // Lines: ↑/↓, line start and end, clicks, over a laid-out text with
    // soft wraps, a short line and an empty one.
    let layout = TextLayout(font: CTFontCreateWithName("Helvetica" as CFString, 13, nil))
    let m = EditModel(maxBytes: 4096, multiline: true)
    _ = typeUnits(m, "Kjære deg, dette er et brev med noen ord som må brytes over flere linjer, e\u{301} \u{1F600} og så videre.")
    _ = m.insertNewline()
    _ = typeUnits(m, "kort")
    _ = m.insertNewline()
    _ = m.insertNewline()
    _ = typeUnits(m, "siste linje er lengre")
    layout.layout(m.text, width: 120)
    let lines = layout.lines, len = m.text.length
    func end(_ i: Int) -> Int { lines[i].start + lines[i].length }
    let wrapped = lines.indices.filter { $0 + 1 < lines.count && lines[$0 + 1].start == end($0) }
    let short = lines.firstIndex { $0.length == 4 } ?? -1
    guard wrapped.count >= 2, short > 0, lines[short + 1].length == 0, short + 2 == lines.count - 1 else {
        check("the test text lays out as expected", false, "\(lines.map { ($0.start, $0.length) })")
        return
    }
    var boundary = true
    m.moveToEnd()
    m.moveToStart()
    check("EditModel: ⌘↑ and ⌘↓ go to the start and the end", m.caret == 0)
    var visited: [Int] = []
    for _ in lines.indices.dropFirst() {
        m.moveDown(in: layout)
        visited.append(m.caretLine(in: layout))
        boundary = boundary && atBoundary(m)
    }
    m.moveDown(in: layout)
    check("EditModel: ↓ from the start visits every line in turn, then the end",
          visited == Array(lines.indices.dropFirst()) && m.caret == len, "\(visited)")
    visited = []
    for _ in lines.indices.dropFirst() {
        m.moveUp(in: layout)
        visited.append(m.caretLine(in: layout))
        boundary = boundary && atBoundary(m)
    }
    m.moveUp(in: layout)
    check("EditModel: ↑ from the end visits every line in turn, then the start",
          visited == Array(lines.indices.dropFirst().reversed().dropFirst()) + [0] && m.caret == 0, "\(visited)")

    m.place(line: 0, x: 60, in: layout)
    let x0 = layout.caretOffset(m.text, line: 0, index: m.caret)
    m.moveDown(in: layout)
    let x1 = layout.caretOffset(m.text, line: 1, index: m.caret)
    check("EditModel: ↓ keeps the caret's x (within a character)",
          m.caretLine(in: layout) == 1 && abs(x1 - x0) < 10 && x0 > 40, "\(x0) \(x1)")
    m.place(line: short - 1, x: 70, in: layout)
    let xs = layout.caretOffset(m.text, line: short - 1, index: m.caret)
    m.moveDown(in: layout)
    let onShort = m.caret == end(short)
    m.moveDown(in: layout)
    let onEmpty = m.caret == lines[short + 1].start
    m.moveDown(in: layout)
    let xl = layout.caretOffset(m.text, line: short + 2, index: m.caret)
    check("EditModel: ↓ through a short and an empty line comes back to the same x",
          onShort && onEmpty && m.caretLine(in: layout) == short + 2 && abs(xl - xs) < 10, "\(xs) \(xl)")

    let w = wrapped[0] == 0 ? wrapped[1] : wrapped[0]
    m.place(line: w, x: 30, in: layout)
    let inside = m.caret > lines[w].start && m.caret < end(w)
    m.moveToLineStart(in: layout)
    let atStart = m.caret == lines[w].start
    m.moveToLineEnd(in: layout)
    check("EditModel: ⌘← and ⌘→ on a soft-wrapped line stop before the space it broke after, on that line",
          inside && atStart && m.caret == end(w) - 1 && m.text.units[m.caret] == 0x20 && m.caretLine(in: layout) == w)
    m.place(line: short, x: 2, in: layout)
    m.moveToLineEnd(in: layout)
    check("EditModel: ⌘→ on a line that ends a paragraph goes to its end", m.caret == end(short))
    m.moveToLineStart(in: layout)
    check("EditModel: ⌘← goes to the line's start", m.caret == lines[short].start)

    var clicks = true
    for i in lines.indices {
        m.place(line: i, x: -5, in: layout)
        clicks = clicks && m.caret == lines[i].start
        m.place(line: i, x: 1e6, in: layout)
        clicks = clicks && m.caret == (wrapped.contains(i) ? end(i) - 1 : end(i)) && m.caretLine(in: layout) == i
        boundary = boundary && atBoundary(m)
    }
    m.place(line: -1, x: 50, in: layout)
    let above = m.caret == 0
    m.place(line: lines.count, x: 50, in: layout)
    check("EditModel: a click goes to the nearest position on its line; above and below go to start and end",
          clicks && above && m.caret == len)
    for i in lines.indices {
        for x in stride(from: CGFloat(0), through: 130, by: 3) {
            m.place(line: i, x: x, in: layout)
            boundary = boundary && atBoundary(m) && m.caretLine(in: layout) == i
        }
    }
    check("EditModel: every caret after a vertical move or a click is at a composed-character start, on its line",
          boundary)

    let one = EditModel(maxBytes: 64, multiline: false)
    _ = typeUnits(one, "emne")
    layout.layout(one.text, width: 1e6)
    one.place(line: 0, x: 10, in: layout)
    one.moveUp(in: layout)
    let up = one.caret == 0
    one.moveDown(in: layout)
    check("EditModel: in a single line, ↑ goes to the start and ↓ to the end", up && one.caret == 4)

    m.wipe()
    check("EditModel: wipe zeroes the text and resets the caret and count",
          m.text.length == 0 && m.caret == 0 && m.utf8Count == 0 && (0..<m.text.maxUnits).allSatisfy { m.text.units[$0] == 0 })
}

func caseKeyTranslator() {
    let none: CGEventFlags = [], shift = CGEventFlags.maskShift, opt = CGEventFlags.maskAlternate
    check("KeyTranslator: only shift, option and caps lock reach UCKeyTranslate",
          KeyTranslator.carbonModifiers([.maskShift, .maskAlternate, .maskAlphaShift]) == UInt32(shiftKey | optionKey | alphaLock)
            && KeyTranslator.carbonModifiers([.maskCommand, .maskControl, .maskSecondaryFn, .maskNumericPad]) == 0)
    if TISCopyCurrentKeyboardLayoutInputSource() != nil, let current = KeyTranslator(.current) {
        let n = current.translate(keyCode: UInt16(kVK_Space), flags: none) { Array($0) }
        check("KeyTranslator: the current layout types a space with the space bar", n == [0x20])
    } else {
        print("skip KeyTranslator on the current layout: Text Input Sources has none")
    }
    guard let nb = KeyTranslator(.named("com.apple.keylayout.Norwegian")) else {
        print("skip KeyTranslator on the Norwegian layout: Text Input Sources cannot find it")
        return
    }
    func typed(_ keys: [(UInt16, CGEventFlags)]) -> [UInt16] {
        nb.reset()
        var out: [UInt16] = []
        for (k, f) in keys { nb.translate(keyCode: k, flags: f) { out += $0 } }
        return out
    }
    // docs/VERIFY.md V35, and the dead keys of design §0.
    let table: [(String, [(UInt16, CGEventFlags)], String)] = [
        ("æ ø å are keys 39 41 33", [(39, none), (41, none), (33, none)], "æøå"),
        ("⇧ gives Æ Ø Å", [(39, shift), (41, shift), (33, shift)], "ÆØÅ"),
        ("´ then e gives é", [(24, none), (14, none)], "é"),
        ("¨ then u gives ü", [(30, none), (32, none)], "ü"),
        ("⇧´ then e gives è", [(24, shift), (14, none)], "è"),
        ("⇧¨ then e gives ê", [(30, shift), (14, none)], "ê"),
        ("⌥¨ then n gives ñ", [(30, opt), (45, none)], "ñ"),
        ("´ then space gives ´", [(24, none), (49, none)], "´"),
        ("´ then k gives ´k", [(24, none), (40, none)], "´k"),
        ("@ is key 42 without a modifier", [(42, none)], "@"),
        ("⇧4 gives $", [(21, shift)], "$"),
        ("⌥7 gives |", [(26, opt)], "|"),
        ("⇧⌥7 gives \\", [(26, [shift, opt])], "\\"),
        ("⌥8 ⌥9 give [ ]", [(28, opt), (25, opt)], "[]"),
        ("⇧⌥8 ⇧⌥9 give { }", [(28, [shift, opt]), (25, [shift, opt])], "{}"),
        ("⌥2 gives ™, not @", [(19, opt)], "™"),
        ("Caps Lock gives A and Æ", [(0, .maskAlphaShift), (39, .maskAlphaShift)], "AÆ"),
    ]
    for (name, keys, expected) in table {
        let got = typed(keys)
        check("KeyTranslator (Norwegian): " + name, got == Array(expected.utf16), got.map { String($0, radix: 16) }.joined(separator: " "))
    }
    nb.reset()
    let dead = nb.translate(keyCode: 24, flags: none) { $0.count }
    check("KeyTranslator: a dead key gives no units and waits", dead == 0 && nb.hasDeadKey)
    nb.reset()
    let plain = nb.translate(keyCode: 14, flags: none) { Array($0) }
    check("KeyTranslator: reset drops the dead key, so e stays e", plain == Array("e".utf16) && !nb.hasDeadKey)
    // The state keeps upper bits after ´ e (input spike): nothing waits then.
    _ = typed([(24, none), (14, none)])
    check("KeyTranslator: nothing waits after a finished composition (´ then e)", !nb.hasDeadKey)
    // A held key repeats as the auto-key action: a held ´ stays one waiting
    // accent, a held letter repeats it.
    nb.reset()
    var held: [UInt16] = []
    nb.translate(keyCode: 24, flags: none) { held += $0 }
    for _ in 0..<3 { nb.translate(keyCode: 24, flags: none, isRepeat: true) { held += $0 } }
    let waits = nb.hasDeadKey
    nb.translate(keyCode: 14, flags: none) { held += $0 }
    nb.translate(keyCode: 0, flags: none) { held += $0 }
    for _ in 0..<2 { nb.translate(keyCode: 0, flags: none, isRepeat: true) { held += $0 } }
    check("KeyTranslator: a held ´ waits as one accent (´ held, e gives é); a held a repeats a",
          waits && held == Array("éaaa".utf16), held.map { String($0, radix: 16) }.joined(separator: " "))
    // A layout switch between a dead key and the next key (the input menu,
    // ⌃Space): the state Norwegian ¨ leaves makes U.S. e give è.
    let usFilter = [kTISPropertyInputSourceID as String: "com.apple.keylayout.US"] as CFDictionary
    if let us = (TISCreateInputSourceList(usFilter, true)?.takeRetainedValue() as? [TISInputSource])?.first {
        nb.reset()
        var got: [UInt16] = []
        nb.translate(keyCode: 30, flags: none) { got += $0 }
        nb.translate(in: us, keyCode: 14, flags: none) { got += $0 }
        check("KeyTranslator: a layout switch drops a waiting dead key (Norwegian ¨, then U.S. e gives e)",
              got == Array("e".utf16), got.map { String($0, radix: 16) }.joined(separator: " "))
    } else {
        print("skip KeyTranslator's layout switch: Text Input Sources cannot find the U.S. layout")
    }

    // Typing the marker key by key through KeyTranslator into an EditModel:
    // the text is in the model's SecretText only, and wipe leaves no copy.
    var keyFor: [UInt16: (UInt16, CGEventFlags)] = [:]
    for f in [none, shift] {
        for k in UInt16(0)..<51 {
            nb.reset()
            nb.translate(keyCode: k, flags: f) { u in
                if u.count == 1, keyFor[u[0]] == nil { keyFor[u[0]] = (k, f) }
            }
        }
    }
    nb.reset()
    guard (0..<16).allSatisfy({ keyFor[markerUnit($0)] != nil }) else {
        check("every marker character has a key on the Norwegian layout", false)
        return
    }
    var h = scan()
    check("typing: baseline, no marker", h.u8 == 0 && h.u16 == 0, "\(h)")
    let body = EditModel(maxBytes: 1024, multiline: true)
    var all = true
    for i in 0..<256 {
        let key = keyFor[markerUnit(i)]!
        all = nb.translate(keyCode: key.0, flags: key.1) { body.insert($0) } && all
    }
    h = scan()
    check("typing: the typed marker is in the model's text (positive control)",
          all && body.text.length == 256 && h.u16 > 0, "\(h)")
    body.wipe()
    h = scan()
    check("typing: after wipe, no copy of the typed marker (UTF-8, UTF-16)", h.u8 == 0 && h.u16 == 0, "\(h)")
}

// MARK: - Case 3: the DEK hand-off and ECIES needles

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
        let k = NeedleFile.keyLength, w = Enclave.wrappedLength
        guard let kek = try? softwareKEK(Data(blob[0..<k])) else {
            check("the helper's KEK loads", false)
            return
        }
        let wrapped = Data(blob[k..<(k + w)])
        let xored = Data(blob[(k + w)...])   // XORed needles only
        blob.wipe()
        let n = NeedleFile.names.count
        let offsets = NeedleFile.lengths.indices.map { NeedleFile.lengths[..<$0].reduce(0, +) }
        for (i, len) in NeedleFile.lengths.enumerated() {
            let set = xored[offsets[i]..<(offsets[i] + len)].withUnsafeBytes {
                brev_scan_set_needle(i, $0.bindMemory(to: UInt8.self).baseAddress, len)
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
        check("baseline: the DEK is in its SecretBytes only (positive control); no ECIES secret",
              h.needle(0) == 1 && (1..<n).allSatisfy { h.needle($0) == 0 }, "\(h)")
        // Onboarding wraps the new DEK before Brev.create (UnlockService):
        // Security reads it through a no-copy view and keeps no copy.
        let wrappedAgain = SecKeyCopyPublicKey(kek).flatMap { try? Enclave.wrap(dek: dek, to: $0) }
        h = scan()
        check("after Enclave.wrap (onboarding): the DEK is still in its SecretBytes only",
              wrappedAgain?.count == Enclave.wrappedLength && h.needle(0) == 1, "\(h)")
        let session: Session
        do {
            session = try Session.create(dir: dir.path, relay: offlineRelay, dek: dek,
                                         signingKey: try publicKeyBytes(try newSoftwareKey()))
        } catch {
            check("create", false, "\(error)")
            return
        }
        h = scan()
        check("after create: the DEK is nowhere; the session is locked", h.needle(0) == 0 && session.brev.isLocked(), "\(h)")

        // The unlock closure on its own serial queue, as UnlockService runs it.
        var result: Result<(sameAddress: Bool, zeroed: Bool), Error>?
        let done = DispatchSemaphore(value: 0)
        DispatchQueue(label: "no.brev.unlock").async {
            result = Result { try unlock(session, wrapped: wrapped, kek: kek) }
            done.signal()
        }
        done.wait()
        switch result {
        case .success(let handOff)?:
            check("unlock: Brev.unlock got Security's CFData, wiped in place (same address, all zero)",
                  handOff.sameAddress && handOff.zeroed)
        case .failure(let error)?: check("unlock with the software KEK", false, "\(error)")
        case nil: check("unlock ran", false)
        }
        h = scan()
        check("while unlocked: the DEK is in Rust's box only", h.needle(0) == 1 && !session.brev.isLocked(), "\(h)")
        for i in 1..<n {
            check("after the unlock closure: no \(NeedleFile.names[i])", h.needle(i) == 0, "\(h)")
        }
        session.brev.lock()
        h = scan()
        check("after lock: no DEK and no ECIES secret anywhere", (0..<n).allSatisfy { h.needle($0) == 0 }, "\(h)")
        for i in 1..<n {
            let b = materialise(i)
            h = scan()
            b.wipe()
            check("positive control: one copy of \(NeedleFile.names[i]) is found", h.needle(i) == 1, "\(h)")
        }
    }
}

// MARK: - Case 4 (and the no-scribble half of case 6): the content path

/// The letters' lines drawn as the letter view draws them, and a text typed
/// and drawn after every keystroke as the compose view does.
struct Drawing {
    let layout: TextLayout
    let ctx: CGContext

    init(font: CTFont) {
        layout = TextLayout(font: font)
        ctx = CGContext(data: nil, width: 800, height: 600, bitsPerComponent: 8, bytesPerRow: 0,
                        space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    }

    func draw(_ t: SecretText) {
        layout.layout(t, width: 600)
        layout.draw(t, lines: 0..<layout.lines.count, in: ctx, x: 4, top: 0)
    }

    /// Composed-range lookups (Delete, arrows) on `letter`, then 300 marker
    /// units typed one by one into a new text, drawn after each. Returns
    /// the typed text (the caller wipes it) and a sum that keeps the
    /// lookups alive.
    func edit(_ letter: SecretText) -> (typed: SecretText, sum: Int) {
        var sum = 0
        for k in 0..<200 { sum &+= letter.composedRange(at: (k * 331) % letter.length).count }
        let typed = SecretText(maxUnits: 512)
        for i in 0..<300 {
            var unit = markerUnit(i)
            withUnsafePointer(to: &unit) { _ = typed.insert(UnsafeBufferPointer(start: $0, count: 1), at: typed.length) }
            unit = 0
            draw(typed)
        }
        return (typed, sum)
    }

    /// A scan while one line of `letter` is alive as a CTLine. Core Text
    /// frees a line's glyphs as soon as it is drawn, and with scribbling
    /// nothing of them is left, even while a letter is shown. So the glyph
    /// needle's positive control scans with one line kept alive.
    func scanWithLiveLine(_ letter: SecretText, font: CTFont) -> Hits {
        var h = scan()
        autoreleasepool {
            let n = min(letter.length, TextLayout.maxLineUnits)
            let s = CFStringCreateWithCharactersNoCopy(nil, letter.units, n, kCFAllocatorNull)!
            let attrs = [kCTFontAttributeName: font] as CFDictionary
            let line = CTLineCreateWithAttributedString(CFAttributedStringCreate(nil, s, attrs)!)
            h = scan()
            withExtendedLifetime(line) {}
        }
        return h
    }
}

func caseContent(units bodyUnits: Int, scribble: Bool) {
    requireScribble(scribble)
    let relay = relayURL()
    let font = CTFontCreateWithName("Helvetica" as CFString, 13, nil)
    setGlyphNeedle(font)
    withStoreDir { dir in
        var h = scan()
        check("baseline: no marker, no glyph needle", h.u8 == 0 && h.u16 == 0 && h.glyph == 0, "\(h)")
        let pair = try! makePair(in: dir, relay: relay)
        let (a, b) = (pair.a, pair.b)
        let contacts = try! a.session.contacts()
        check("one contact, the other user", contacts.count == 1 && contacts[0].id == pair.aSeesB)

        let subject = markerText(units: 32, emoji: false)
        let body = markerText(units: bodyUnits, emoji: true)
        let thread = try! a.send(to: pair.aSeesB, subject: subject, body: body)
        subject.wipe()
        body.wipe()
        let arrived = try! b.session.sync().letters
        check("the letter arrives through the relay", arrived == 1, "\(arrived)")

        let aThreads = try! a.session.threads(contact: pair.aSeesB)
        let bThreads = try! b.session.threads(contact: pair.bSeesA)
        let sent = try! a.session.messages(thread: thread)
        let received = bThreads.first.map { try! b.session.messages(thread: $0.id) } ?? []
        check("one thread on each side with the same id: the sent copy and the received letter",
              aThreads.count == 1 && bThreads.count == 1 && bThreads[0].id == thread
                  && sent.count == 1 && sent[0].outgoing && received.count == 1 && !received[0].outgoing)
        let letters = [try! a.session.body(message: sent[0].id), try! b.session.body(message: received[0].id)]
        check("both letters read back at full length", letters.allSatisfy { $0.length == bodyUnits + 2 })

        let drawing = Drawing(font: font)
        letters.forEach(drawing.draw)
        let (typed, sum) = drawing.edit(letters[0])
        letters.forEach(drawing.draw)   // the letters' lines are the last ones drawn
        h = scan()
        check("while open: the text is in memory (positive control)", h.u16 > 0 && sum > 0, "\(h)")
        h = drawing.scanWithLiveLine(letters[0], font: font)
        check("while a line of it is alive: the glyph needle sees it (positive control)", h.glyph > 0, "\(h)")

        // The lock sequence (§8.4): wipe every text, flush, lock.
        letters.forEach { $0.wipe() }
        (aThreads + bThreads).forEach { $0.subject.wipe() }
        contacts.forEach { $0.name.wipe() }
        typed.wipe()
        GlyphFlush.flush()
        drawing.layout.reset()
        a.lock()
        b.lock()
        h = scan()
        if scribble {
            check("after wipe, flush and lock: no copy (UTF-8, UTF-16, glyphs)",
                  h.u8 == 0 && h.u16 == 0 && h.glyph == 0 && a.session.brev.isLocked() && b.session.brev.isLocked(),
                  "\(h)")
        } else {
            check("without MallocScribble: glyph ids are left after lock (the needle works; scribbling clears them)",
                  h.glyph > 0, "\(h)")
        }
    }
}

// MARK: - Case 5: a kept OpenText after lock

func caseKept() {
    requireScribble(true)
    let relay = relayURL()
    withStoreDir { dir in
        let pair = try! makePair(in: dir, relay: relay)
        let session = pair.a.session
        let rows = try! session.brev.contacts()   // names (the other user's address) deliberately left open
        let subject = markerText(units: 16, emoji: false)
        let body = markerText(units: 64, emoji: false)
        let thread = try! pair.a.send(to: pair.aSeesB, subject: subject, body: body)
        subject.wipe()
        body.wipe()
        let msg = try! session.messages(thread: thread)[0]
        let kept = try! session.brev.openBody(message: msg.id)   // deliberately not closed
        check("an open body has its length", kept.byteLen() == 64 && rows[0].name.byteLen() > 0)
        session.brev.lock()
        pair.b.lock()
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

// MARK: - Case 7: the scribble probe

/// SelfScan's scribble probe (docs/VERIFY.md V39), which does not depend
/// on Core Text: a freed 32 KiB block keeps no copy of its pattern under
/// MallocScribble=1. Without scribbling (the negative control) it keeps
/// them, so the probe can fail on this Mac.
func caseScribble(scribble: Bool) {
    requireScribble(scribble)
    var live: UInt64 = 0
    let left = brev_scan_scribble_probe(&live)
    check("scribble probe: the allocated block is seen (positive control)", live > 0, "live=\(live)")
    if scribble {
        check("scribble probe: nothing of the block is left after free", left == 0, "left=\(left) live=\(live)")
    } else {
        check("without MallocScribble: the freed block keeps its pattern (the probe can fail)", left > 0,
              "left=\(left) live=\(live)")
    }
}

// MARK: - Case 8: the network round trip (docs/PHASE3_DESIGN.md §8)

/// Two users register at the relay test.sh started (A with the run's root
/// invite, B with A's invite code), are each other's contacts and compare
/// codes; a letter cancelled after signing goes nowhere; A sends a
/// marker letter in the app's steps, B syncs and reads it (acknowledged, so
/// a second sync gets nothing), B answers and A reads that. While the
/// letters are open the scanner sees them (positive controls); after the
/// wipe, the flush and both locks, nothing: no UTF-8, UTF-16 or glyph copy.
func caseNetwork() {
    requireScribble(true)
    let relay = relayURL()
    let font = CTFontCreateWithName("Helvetica" as CFString, 13, nil)
    setGlyphNeedle(font)
    withStoreDir { dir in
        var h = scan()
        check("baseline: no marker, no glyph needle", h.u8 == 0 && h.u16 == 0 && h.glyph == 0, "\(h)")
        let a = try! User(in: dir.appendingPathComponent("a"), relay: relay)
        let b = try! User(in: dir.appendingPathComponent("b"), relay: relay)
        let before = try! a.session.me()
        check("before registration: not registered, no address, a 35-byte code; sync is NotFound; "
                + "registering without an opened invite is InviteInvalid",
              !before.registered && before.address.length == 0 && before.code.count == 35
                  && throwsError(.NotFound) { try a.session.sync() }
                  && throwsError(.InviteInvalid) { try a.register(freshAddress("a")) })
        before.address.wipe()
        before.code.wipe()

        let addressA = freshAddress("a"), addressB = freshAddress("b")
        let root = rootInvite()
        do {
            try a.register(addressA, invite: root)
            let code = try a.session.createInvite()
            defer { code.wipe() }
            try b.register(addressB, invite: code)
        } catch {
            check("both users register (A with the root invite, B with A's invite code)", false, "\(error)")
            return
        }
        root.wipe()
        let pinned = try? a.session.sync()
        check("A's sync pins B, whose invite it made: a contact changed, no letter, no request",
              pinned?.contactsChanged == true && pinned?.letters == 0 && pinned?.requests == 0)
        let meA = try! a.session.me(), meB = try! b.session.me()
        check("registered: the own address as typed", meA.registered && meB.registered
                  && unitsOf(meA.address) == Array(addressA.utf16) && unitsOf(meB.address) == Array(addressB.utf16))
        check("registering again is Duplicate", throwsError(.Duplicate) { try a.register(freshAddress("a")) })
        let aSeesB = try! a.contact(addressB).id, bSeesA = try! b.contact(addressA).id
        check("adding a known address again is Duplicate, an unknown one NotFound",
              throwsError(.Duplicate) { try a.add(addressB) } && throwsError(.NotFound) { try a.add(freshAddress("n")) })
        let infoB = try! a.session.contactInfo(contact: aSeesB), infoA = try! b.session.contactInfo(contact: bSeesA)
        let rowsA = try! a.session.contacts()
        check("each pinned the other's own code, verified by the invite and approved; no key changed",
              infoB.code.withBytes { Array($0) } == meB.code.withBytes { Array($0) }
                  && infoA.code.withBytes { Array($0) } == meA.code.withBytes { Array($0) }
                  && infoB.newCode.count == 0 && unitsOf(infoB.address) == Array(addressB.utf16)
                  && rowsA.count == 1 && !rowsA[0].keyChanged && rowsA[0].verified && !rowsA[0].waiting
                  && infoA.verified && !infoA.waiting && !infoA.blocked)
        for t in [meA.address, meB.address, infoA.address, infoB.address] + rowsA.map(\.name) { t.wipe() }
        for c in [meA.code, meB.code, infoA.code, infoB.code, infoA.newCode, infoB.newCode] { c.wipe() }

        // A letter given up after it was signed goes nowhere.
        let draft = secret("Utkast"), draftBody = secret("Et utkast som ikke sendes.")
        var cancelled = false
        check("the identity key is a software key, and says so", a.keyOrigin == .software)
        check("without a compose session, a send is refused with no fact named (Environment)",
              throwsError(.Environment(failed: [])) { try a.session.prepareSend(contact: aSeesB, sample: cleanSample) })
        do {
            try a.session.composeStarted(design: harnessDesign, admin: nil, keyOrigin: a.keyOrigin)
            try a.session.prepareSend(contact: aSeesB, sample: cleanSample)
            let token = try a.session.signRequest(contact: aSeesB, subject: draft, body: draftBody, sample: cleanSample)
            let tokenDER = try Enclave.sign(digest: token, key: a.identity)
            let envelope = try a.session.attachTokenSignature(tokenDER)
            let der = try Enclave.sign(digest: envelope, key: a.identity)
            a.session.cancelSend()
            cancelled = throwsError(.NotFound) { try a.session.attachSignature(der) }
                && throwsError(.NotFound) { try a.session.attachTokenSignature(tokenDER) }
                && throwsError(.Malformed) {
                    try a.session.signRequest(contact: aSeesB, subject: draft, body: draftBody, sample: cleanSample)
                }
                && throwsError(.NotFound) { try a.session.submit() }
            try a.session.composeClosed()
        } catch {
            check("a letter up to its signatures", false, "\(error)")
        }
        draft.wipe()
        draftBody.wipe()
        check("cancelSend forgets the letter: attach NotFound, no ticket left (Malformed), submit NotFound; nothing arrives",
              cancelled && (try? b.session.sync())?.letters == 0)

        // A to B, then B to A: marker letters.
        let subject = markerText(units: 32, emoji: false), body = markerText(units: 1000, emoji: true)
        let thread = try? a.send(to: aSeesB, subject: subject, body: body)
        let arrived = try? b.session.sync().letters, again = try? b.session.sync().letters
        check("A's letter is sent and arrives at B once (acknowledged: the next sync gets nothing)",
              thread != nil && arrived == 1 && again == 0, "\(String(describing: arrived)), \(String(describing: again))")
        let reply = try? b.send(to: bSeesA, subject: subject, body: body)
        subject.wipe()
        body.wipe()
        let back = try? a.session.sync().letters
        check("B's answer is sent and arrives at A", reply != nil && back == 1)
        // docs/AUTHORSHIP.md §6: B's core checked A's token and kept the
        // result; A's own copy has none.
        let received = (try? b.session.threads(contact: bSeesA))?.first { $0.id == thread }
        let inB = received.flatMap { try? b.session.messages(thread: $0.id).first }
        let proof = inB.flatMap { try? b.session.letterProof(message: $0.id) }
        let own = thread.flatMap { try? a.session.messages(thread: $0).first }
        check("B's proof of A's letter: verified, class C (a software key), not attested, nothing failed, "
                + "the counts of the clean sample; A's own copy has no proof",
              proof?.verified == true && proof?.class == 3 && proof?.attested == false && proof?.failed == []
                  && proof?.windows == 0 && proof?.agents == 0 && proof?.sudo == 0 && proof?.sip == true
                  && proof?.admin == nil && proof?.blockedInput == 0
                  && own.map { (try? a.session.letterProof(message: $0.id)) == .some(nil) } == true,
              "\(String(describing: proof))")
        received?.subject.wipe()

        let bThreads = try! b.session.threads(contact: bSeesA), aThreads = try! a.session.threads(contact: aSeesB)
        let bRows = bThreads.flatMap { try! b.session.messages(thread: $0.id) }
        let aRows = aThreads.flatMap { try! a.session.messages(thread: $0.id) }
        check("B has A's letter and its own answer; A its letter and B's answer, in their threads",
              bThreads.count == 2 && aThreads.count == 2 && bThreads.contains { $0.id == thread }
                  && aThreads.contains { $0.id == reply } && bRows.filter { !$0.outgoing }.count == 1
                  && aRows.filter { !$0.outgoing }.count == 1 && bRows.count == 2 && aRows.count == 2)
        let letters = bRows.map { try! b.session.body(message: $0.id) } + aRows.map { try! a.session.body(message: $0.id) }
        check("every letter reads back at full length", letters.count == 4 && letters.allSatisfy { $0.length == 1002 })

        let drawing = Drawing(font: font)
        letters.forEach(drawing.draw)
        h = scan()
        check("while open: the letters are in memory (positive control)", h.u16 > 0, "\(h)")
        h = drawing.scanWithLiveLine(letters[0], font: font)
        check("while a line of one is alive: the glyph needle sees it (positive control)", h.glyph > 0, "\(h)")

        letters.forEach { $0.wipe() }
        (aThreads + bThreads).forEach { $0.subject.wipe() }
        GlyphFlush.flush()
        drawing.layout.reset()
        // docs/AUTHORSHIP.md §4.3: a sample with a running sudo locks the
        // session in Rust at once and names the cause.
        let sudo = Sample(secureInput: true, sharingNone: true, preventsCapture: true, csrConfig: 0,
                          processes: ["launchd", "sudo"], windows: [])
        let causes = try? b.session.observe(sudo)
        check("a sample with sudo running locks B's session and names the cause",
              causes == [.sudo] && b.session.brev.isLocked())
        a.lock()
        b.lock()
        check("after lock: sync is Locked (no request)", throwsLocked { try a.session.sync() })
        h = scan()
        check("after wipe, flush and lock: no copy (UTF-8, UTF-16, glyphs)",
              h.u8 == 0 && h.u16 == 0 && h.glyph == 0 && a.session.brev.isLocked() && b.session.brev.isLocked(), "\(h)")
    }
}

// MARK: - Case 9: invites, approval, letters and Blokker (docs/PHASE4_DESIGN.md §8)

/// Whether `code` is an invite code of the user with `address` and identity
/// code `identity` (design §3.1): `brev1.<address>.<fingerprint>.<secret>`,
/// at most `Limits.maxInvite` ASCII bytes, the fingerprint the identity
/// code in lower case without its spaces, the secret 26 of a–z and 2–7.
func isInviteCode(_ code: SecretBytes, address: String, identity: SecretBytes) -> Bool {
    let head = Array("brev1.\(address).".utf8)
    let fingerprint = identity.withBytes { $0.filter { $0 != 0x20 }.map { $0 | 0x20 } }
    let base32 = { (c: UInt8) in (0x61...0x7A).contains(c) || (0x32...0x37).contains(c) }
    return code.withBytes { b in
        b.count <= Int(limits().maxInvite) && b.count == head.count + 30 + 1 + 26 && b.starts(with: head)
            && fingerprint.count == 30 && b[head.count..<head.count + 30].elementsEqual(fingerprint)
            && b[head.count + 30] == UInt8(ascii: ".") && b[(head.count + 31)...].allSatisfy(base32)
    }
}

/// Scanner needles 0 and 1: the code's secret as text, its last 26 bytes,
/// and as Rust keeps it once the code is parsed, the 16 bytes that base32
/// text decodes to (design §3.1; the last 2 of its 130 bits are zero). Both
/// XORed as scan.c takes them; each byte is XORed as it is decoded, so no
/// plain copy is made here.
func setSecretNeedles(_ code: SecretBytes) -> Bool {
    var text = code.withBytes { $0.suffix(26).map { $0 ^ 0x5A } }
    var raw = [UInt8](repeating: 0, count: 16)
    defer {
        _ = text.withUnsafeMutableBytes { memset_s($0.baseAddress!, $0.count, 0, $0.count) }
        _ = raw.withUnsafeMutableBytes { memset_s($0.baseAddress!, $0.count, 0, $0.count) }
    }
    var bits: UInt32 = 0, pending = 0, n = 0
    for x in text {
        let c = x ^ 0x5A
        guard (0x61...0x7A).contains(c) || (0x32...0x37).contains(c) else { return false }
        bits = (bits << 5) | UInt32(c >= 0x61 ? c - 0x61 : c - 0x32 + 26)
        pending += 5
        if pending >= 8 {
            pending -= 8
            if n < 16 { raw[n] = UInt8(truncatingIfNeeded: bits >> pending) ^ 0x5A }
            n += 1
        }
    }
    return text.count == 26 && n == 16 && brev_scan_set_needle(0, text, text.count) == 0
        && brev_scan_set_needle(1, raw, raw.count) == 0
}

/// Scanner needles 2 and 3: `address`'s units as UTF-16LE bytes and
/// `code`'s bytes (an identity code), each XORed as scan.c takes them, so no
/// plain copy is made here.
func setContactNeedles(address: SecretText, code: SecretBytes) -> Bool {
    var a = UnsafeRawBufferPointer(start: address.units, count: 2 * address.length).map { $0 ^ 0x5A }
    var c = code.withBytes { $0.map { $0 ^ 0x5A } }
    defer {
        _ = a.withUnsafeMutableBytes { memset_s($0.baseAddress!, $0.count, 0, $0.count) }
        _ = c.withUnsafeMutableBytes { memset_s($0.baseAddress!, $0.count, 0, $0.count) }
    }
    return c.count == 35 && brev_scan_set_needle(2, a, a.count) == 0 && brev_scan_set_needle(3, c, c.count) == 0
}

/// A copy of `code` with the first character of its fingerprint changed
/// (still base32, so it parses). The caller wipes it.
func editedFingerprint(_ code: SecretBytes, address: String) -> SecretBytes {
    let copy = SecretBytes(capacity: code.capacity)
    code.withBytes { _ = copy.append($0) }
    let at = copy.base.assumingMemoryBound(to: UInt8.self) + ("brev1.".utf8.count + address.utf8.count + 1)
    at.pointee = at.pointee == UInt8(ascii: "a") ? UInt8(ascii: "b") : UInt8(ascii: "a")
    return copy
}

/// The Phase 4 round trip through the relay test.sh started, in the app's
/// calls: A opens the run's root invite and registers with it; A makes an
/// invite code (A's address and fingerprint); a copy with one character of
/// the fingerprint changed is InviteMismatch at B, and nothing is kept; the
/// real code shows A's address and code, B registers with it, and the used
/// code is refused after that; A's sync pins B; both are approved and
/// verified; a marker letter goes each way. C, brought in by B's invite,
/// adds A by address: a request without text, and C cannot send to A
/// (NotApproved, before any digest); A's sync shows the request with C's
/// address and code, one answer approves it, C's sync learns it, and C's
/// letter arrives. Then A blocks C (Blokker): A cannot send to C, and C's
/// letters no longer reach A. D opens A's code too and holds it opened
/// until the lock, never registering. While the letters are open, the code
/// is kept and an opened invite is held the scanner sees them (positive
/// controls: the code's secret as text in Swift, as 16 bytes in Rust);
/// after the wipe, the flush and the locks, nothing: no UTF-8, UTF-16 or
/// glyph copy of the marker, and no copy of the code's secret, as text or
/// as bytes. The same holds for contact data (docs/SWIFT_MEMORY_REVIEW.md):
/// B's address as UTF-16 and B's identity code, seen while B's own and A's
/// reads of them are held, and gone after the wipe and the locks.
func caseInvite() {
    requireScribble(true)
    let relay = relayURL()
    let font = CTFontCreateWithName("Helvetica" as CFString, 13, nil)
    setGlyphNeedle(font)
    withStoreDir { dir in
        var h = scan()
        check("baseline: no marker, no glyph needle", h.u8 == 0 && h.u16 == 0 && h.glyph == 0, "\(h)")
        let a = try! User(in: dir.appendingPathComponent("a"), relay: relay)
        let b = try! User(in: dir.appendingPathComponent("b"), relay: relay)
        let c = try! User(in: dir.appendingPathComponent("c"), relay: relay)
        let d = try! User(in: dir.appendingPathComponent("d"), relay: relay)
        let addressA = freshAddress("a"), addressB = freshAddress("b"), addressC = freshAddress("c")

        // A: the root invite.
        let root = rootInvite()
        let opened = try? a.session.openInvite(code: root)
        root.wipe()
        check("the root invite opens as one: no inviter, no address, no code",
              opened.map { $0.root && $0.address.length == 0 && $0.code.count == 0 } ?? false)
        opened?.address.wipe()
        opened?.code.wipe()
        do { try a.register(addressA) } catch {
            check("A registers with the root invite", false, "\(error)")
            return
        }

        // A's invite code; an edited copy is refused at B, the real one names A.
        let meA = try! a.session.me()
        guard let code = try? a.session.createInvite() else {
            check("A makes an invite code", false)
            return
        }
        check("the invite code is brev1.<A's address>.<A's code as fingerprint>.<secret>, at most 96 ASCII bytes",
              isInviteCode(code, address: addressA, identity: meA.code))
        check("scanner takes the code's secret as needles 0 (text) and 1 (its 16 bytes)", setSecretNeedles(code))
        let edited = editedFingerprint(code, address: addressA)
        check("a copy with one character of the fingerprint changed is InviteMismatch at B, which keeps nothing",
              throwsError(.InviteMismatch) { try b.session.openInvite(code: edited) }
                  && throwsError(.InviteInvalid) { try b.register(addressB) })
        edited.wipe()
        let held = try? d.session.openInvite(code: code)
        check("D opens the real code and holds it opened (D never registers)", held.map { !$0.root } ?? false)
        held?.address.wipe()
        held?.code.wipe()
        let invited = try? b.session.openInvite(code: code)
        check("the real code shows A as the inviter: A's address and code",
              invited.map { !$0.root && unitsOf($0.address) == Array(addressA.utf16)
                  && $0.code.withBytes { Array($0) } == meA.code.withBytes { Array($0) } } ?? false)
        invited?.address.wipe()
        invited?.code.wipe()
        h = scan()
        check("while B and D hold the opened invite: the scanner sees Rust's 16 bytes of the secret (positive control)",
              h.needle(1) > 0, "\(h)")
        do { try b.register(addressB) } catch {
            check("B registers with A's invite code", false, "\(error)")
            return
        }
        check("the used code is InviteInvalid", throwsError(.InviteInvalid) { try c.session.openInvite(code: code) })
        h = scan()
        check("while the code is kept: the scanner sees its secret (positive control)", h.needle(0) > 0, "\(h)")
        code.wipe()
        meA.address.wipe()
        meA.code.wipe()
        let pinned = try? a.session.sync()
        check("A's sync pins B through the invite: a contact changed, no request",
              pinned?.contactsChanged == true && pinned?.requests == 0)
        let aSeesB = try? a.contact(addressB), bSeesA = try? b.contact(addressA)
        check("A and B are approved and verified contacts of each other",
              [aSeesB, bSeesA].allSatisfy { $0.map { !$0.waiting && $0.verified && !$0.blocked } ?? false })
        guard let aSeesB, let bSeesA else { return }

        // A marker letter each way.
        let subject = markerText(units: 32, emoji: false), body = markerText(units: 1000, emoji: true)
        let thread = try? a.send(to: aSeesB.id, subject: subject, body: body)
        let arrived = try? b.session.sync().letters
        let reply = try? b.send(to: bSeesA.id, subject: subject, body: body)
        let back = try? a.session.sync().letters
        subject.wipe()
        body.wipe()
        check("a marker letter goes each way", thread != nil && arrived == 1 && reply != nil && back == 1,
              "\(String(describing: arrived)), \(String(describing: back))")

        // C, brought in by B, asks A by address.
        do {
            let codeB = try b.session.createInvite()
            defer { codeB.wipe() }
            try c.register(addressC, invite: codeB)
        } catch {
            check("C registers with B's invite code", false, "\(error)")
            return
        }
        let cSeesA = try? c.add(addressA)
        let asking = try? c.contact(addressA)
        check("C adds A by address: a request goes out, and A waits at C (not verified)",
              cSeesA != nil && asking.map { $0.waiting && !$0.verified && !$0.blocked } ?? false)
        guard let cSeesA else { return }
        let note = secret("Hei"), noteBody = secret("Et brev fra C.")
        defer { note.wipe(); noteBody.wipe() }
        check("C cannot send to A before A approves: NotApproved, before any digest",
              throwsError(.NotApproved) { try c.send(to: cSeesA, subject: note, body: noteBody) })
        let asked = try? a.session.sync()
        let requests = (try? a.session.requests()) ?? []
        let meC = try! c.session.me()
        check("A's sync shows one request, with C's address and code and no text",
              asked?.requests == 1 && requests.count == 1 && unitsOf(requests[0].address) == Array(addressC.utf16)
                  && requests[0].code.withBytes { Array($0) } == meC.code.withBytes { Array($0) },
              "\(String(describing: asked))")
        let aSeesC = requests.first.flatMap { try? a.session.answerRequest(peer: $0.peer, approve: true) }
        requests.forEach { $0.address.wipe(); $0.code.wipe() }
        meC.address.wipe()
        meC.code.wipe()
        check("one answer approves C: C is A's contact, approved, and no request is left",
              aSeesC?.count == 16 && (try? a.session.requests())?.isEmpty == true
                  && (try? a.contact(addressC)).map { !$0.waiting && !$0.verified } ?? false)
        let approved = try? c.session.sync()
        check("C's sync learns the approval: A no longer waits at C",
              approved?.contactsChanged == true && (try? c.contact(addressA))?.waiting == false)
        let sent = try? c.send(to: cSeesA, subject: note, body: noteBody)
        let fromC = try? a.session.sync().letters
        check("then C's letter reaches A", sent != nil && fromC == 1)
        guard let aSeesC else { return }

        // Blokker: A blocks C.
        let blocked = (try? a.session.blockContact(contact: aSeesC)) != nil
        check("A blocks C (Blokker): C shows as blocked at A",
              blocked && (try? a.contact(addressC))?.blocked == true
                  && (try? a.session.contactInfo(contact: aSeesC)).map { i in
                      defer { i.address.wipe(); i.code.wipe(); i.newCode.wipe() }
                      return i.blocked
                  } ?? false)
        check("A cannot send to C: NotApproved, before any digest",
              throwsError(.NotApproved) { try a.send(to: aSeesC, subject: note, body: noteBody) })
        check("C's letters no longer reach A: NotApproved at C, and A's sync gets nothing",
              throwsError(.NotApproved) { try c.send(to: cSeesA, subject: note, body: noteBody) }
                  && (try? a.session.sync())?.letters == 0)

        // The marker letters open, then the lock sequence.
        let aThreads = try! a.session.threads(contact: aSeesB.id), bThreads = try! b.session.threads(contact: bSeesA.id)
        let letters = aThreads.flatMap { try! a.session.messages(thread: $0.id) }.map { try! a.session.body(message: $0.id) }
            + bThreads.flatMap { try! b.session.messages(thread: $0.id) }.map { try! b.session.body(message: $0.id) }
        check("A and B each hold both marker letters at full length",
              letters.count == 4 && letters.allSatisfy { $0.length == 1002 })
        // Contact data, as the screens hold it: B's own address and code
        // (the header's line 1), A's contacts (the list's names) and B's
        // details at A (line 2). Needle 2 is B's address as UTF-16, the form
        // SecretText keeps (the harness's own Strings are UTF-8); needle 3
        // B's identity code.
        let meB = try! b.session.me(), infoB = try! a.session.contactInfo(contact: aSeesB.id)
        let namesA = try! a.session.contacts()
        check("scanner takes B's address (UTF-16) and identity code as needles 2 and 3",
              setContactNeedles(address: meB.address, code: meB.code))
        let drawing = Drawing(font: font)
        letters.forEach(drawing.draw)
        h = scan()
        check("while open: the letters are in memory (positive control)", h.u16 > 0, "\(h)")
        check("before the lock: D's opened invite still holds the secret's 16 bytes (positive control)",
              h.needle(1) > 0, "\(h)")
        check("while read: B's address and identity code are in memory (positive control)",
              h.needle(2) >= 3 && h.needle(3) >= 2, "\(h)")
        h = drawing.scanWithLiveLine(letters[0], font: font)
        check("while a line of one is alive: the glyph needle sees it (positive control)", h.glyph > 0, "\(h)")
        letters.forEach { $0.wipe() }
        (aThreads + bThreads).forEach { $0.subject.wipe() }
        for t in [meB.address, infoB.address] + namesA.map(\.name) { t.wipe() }
        for s in [meB.code, infoB.code, infoB.newCode] { s.wipe() }
        GlyphFlush.flush()
        drawing.layout.reset()
        for u in [a, b, c, d] { u.lock() }
        check("after lock: the invite calls are Locked (no request)",
              throwsLocked { try a.session.createInvite() } && throwsLocked { try a.session.requests() }
                  && throwsLocked { try a.session.sync() })
        h = scan()
        check("after wipe, flush and lock: no copy of the marker (UTF-8, UTF-16, glyphs) or of the code's secret (text, bytes)",
              h.u8 == 0 && h.u16 == 0 && h.glyph == 0 && h.needle(0) == 0 && h.needle(1) == 0
                  && [a, b, c, d].allSatisfy { $0.session.brev.isLocked() }, "\(h)")
        check("after wipe and lock: no copy of B's address (UTF-16) or identity code",
              h.needle(2) == 0 && h.needle(3) == 0, "\(h)")
    }
}

// MARK: - Main

let args = Array(CommandLine.arguments.dropFirst())
switch (args.first, args.count) {
case ("units", 1): caseUnits()
case ("shell", 1): caseShell()
case ("compose", 1): caseCompose()
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
case ("scribble", 1), ("scribble", 2):
    guard args.count == 1 || args[1] == "--no-scribble" else {
        print("usage: harness scribble [--no-scribble]")
        exit(2)
    }
    caseScribble(scribble: args.count == 1)
case ("network", 1): caseNetwork()
case ("invite", 1): caseInvite()
default:
    print("usage: harness units | shell | compose | dek | content <units> [--no-scribble] | kept | control"
          + " | scribble [--no-scribble] | network | invite | needles <file>")
    exit(2)
}
print(failures == 0 ? "PASS" : "FAIL: \(failures) check(s)")
exit(failures == 0 ? 0 : 1)
