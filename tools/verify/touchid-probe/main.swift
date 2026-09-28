// touchid-probe — docs/VERIFY.md V51 (design §14.2 K, with ECIES per
// docs/DECISIONS.md D-0035): after Brev's unlock closure with the real
// Secure Enclave KEK, is any copy of the DEK, of the ECIES secrets or of the
// echo peers' DEKs (which Brev.unlock derives from the DEK) left in the
// process?
//
// A verification tool, never linked into Brev.app. Built by
// tools/verify/build.sh as TouchIDProbe.app with Brev's bundle id, team
// signature and keychain group (so it can make and use Enclave keys the way
// Brev does), sandboxed and hardened, with LSEnvironment MallocScribble=1 as
// Brev. It compiles Brev's own Keys/ and Shared/ code: the unlock is
// UnlockService.unlock, unchanged (KEK lookup with the LAContext that has no
// password button, SecKeyCreateDecryptedData with ECIES, Brev.unlock on the
// same thread without a copy, the CFData wiped in place), on its own queue.
//
// Because it uses Brev's own keychain names and folder, it runs only when
// Brev is not installed on this Mac (no wrapped-DEK item) and not running (it
// holds Brev's instance lock), and it deletes every name it made when it
// ends, as onboarding's cleanup does. Its stores live in a temporary folder.
//
// The ECIES secrets are needles: a helper run of this same binary wraps a
// random DEK to the KEK's public key with its own X9.63 ECIES sender
// (app/Tests/ecies_needles.swift, checked against Security with a software
// key first) and writes the wrapped DEK plus the DEK, the ECDH output, the
// AES key, the IV and the two peer DEKs, XORed. This process only ever holds
// them XORed, until
// the positive controls at the end. app/Tests/scan.c counts copies in every
// readable and writable region (every heap and thread stack).
//
// usage (from Terminal, Brev quit and not installed):
//   open -W --stdout <log> --stderr <err> TouchIDProbe.app --args --dry
//       everything except the unwrap: no prompt
//   open -W --stdout <log> --stderr <err> TouchIDProbe.app --args --unlock
//       the full closure: exactly one Touch ID prompt ("låse opp brevene
//       dine", no password button); a human answers it
// Output: check lines ("ok"/"FAIL") with hit counts only, then PASS or FAIL.
// V51 passes when --unlock prints PASS: after the closure only Rust's copies
// of the DEK and the peer DEKs are found (1 hit each, the positive control
// while unlocked), no ECDH output, AES key or IV, and after lock nothing.
//
// Design §14.2 K runs the closure with brev-core's unlock scrub at 64 KiB
// (as shipped), at 128 KiB and disabled. build.sh builds one probe per
// depth; the Info.plist key BrevScrubKiB says which. The build with the
// scrub disabled is the negative control: its residue checks print "info"
// lines instead of failing, and it ends with "NEGATIVE CONTROL: residue …"
// (the scrub is what removes it) or "NEGATIVE CONTROL EMPTY" (nothing is left
// even without the scrub, so the shipped build's PASS does not show that the
// scrub works).

import CryptoKit
import Foundation
import LocalAuthentication
import Security

setvbuf(stdout, nil, _IOLBF, 0)
let args = Array(CommandLine.arguments.dropFirst())
var failures = 0

func check(_ what: String, _ ok: Bool, _ detail: @autoclosure () -> String = "") {
    let d = ok ? "" : detail()
    print((ok ? "ok   " : "FAIL ") + what + (d.isEmpty ? "" : "  [\(d)]"))
    if !ok { failures += 1 }
}

/// A check on what the unlock leaves behind; in the build with the scrub
/// disabled, only a count of it.
func residueCheck(_ what: String, _ ok: Bool, _ detail: String) {
    guard negativeControl else { return check(what, ok, detail) }
    print("info " + what + (ok ? "" : ": RESIDUE") + "  [\(detail)]")
    if !ok { residue += 1 }
}

func needleHits(_ r: brev_scan_result, _ i: Int) -> UInt64 {
    withUnsafeBytes(of: r.needle_hits) { $0.load(fromByteOffset: i * 8, as: UInt64.self) }
}

@inline(never) func scan() -> [UInt64] {
    var r = brev_scan_result()
    brev_scan(&r)
    return (0..<NeedleFile.names.count).map { needleHits(r, $0) }
}

func show(_ h: [UInt64]) -> String {
    zip(NeedleFile.names, h).map { "\($0)=\($1)" }.joined(separator: " ")
}

// MARK: - The helper run: the needles

/// `--needles <public key file> <out file>`: a random DEK wrapped to the
/// 65-byte X9.63 public key, written as wrapped (113) || XORed needles.
func makeNeedles(publicKey: URL, out: URL) throws {
    // The sender is checked against Security first, with a software key.
    let probe = P256.KeyAgreement.PrivateKey()
    let secret = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
    let w0 = try X963ECIES.wrap(secret, to: probe.publicKey, ephemeral: P256.KeyAgreement.PrivateKey())
    let opened = try Enclave.unwrap(w0.wrapped, with: try softwareKEK(probe.x963Representation)) { Data($0) }
    guard opened == secret else { throw CryptoKitError.authenticationFailure }

    let pk = try P256.KeyAgreement.PublicKey(x963Representation: try Data(contentsOf: publicKey))
    var dek = Data(count: 32)
    guard dek.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }) == errSecSuccess
    else { throw CryptoKitError.incorrectParameterSize }
    let w = try X963ECIES.wrap(dek, to: pk, ephemeral: P256.KeyAgreement.PrivateKey())
    var blob = w.wrapped
    for s in [dek, w.sharedSecret, w.key, w.iv, peerDEK(dek, index: 0), peerDEK(dek, index: 1)] {
        blob += Data(s.map { $0 ^ 0x5A })
    }
    try blob.write(to: out)
    dek.resetBytes(in: 0..<32)
}

if args.first == "--needles" {
    guard args.count == 3 else { exit(2) }
    do { try makeNeedles(publicKey: URL(fileURLWithPath: args[1]), out: URL(fileURLWithPath: args[2])) } catch {
        print("needles failed: \(error)")
        exit(1)
    }
    exit(0)
}

// MARK: - The probe

let unlocking = args.contains("--unlock")
guard unlocking || args.contains("--dry") else {
    print("usage: TouchIDProbe --dry | --unlock   (see the header of tools/verify/touchid-probe/main.swift)")
    exit(2)
}
/// The depth of the deep scrub at the end of Brev.unlock in the brev-core
/// this build links, in KiB (64 as shipped; 0 and 128 are V51's variants).
guard let scrubKiB = (Bundle.main.object(forInfoDictionaryKey: "BrevScrubKiB") as? String).flatMap({ Int($0) }) else {
    print("FAIL the build does not say its scrub depth (Info.plist BrevScrubKiB)")
    exit(2)
}
/// With the scrub disabled, residue is what the build should show: counted, not failed.
let negativeControl = scrubKiB == 0
var residue = 0
print("touchid-probe \(unlocking ? "--unlock" : "--dry") pid=\(getpid()) scrub=\(scrubKiB) KiB\(negativeControl ? " (disabled: the negative control)" : "") MallocScribble=\(getenv("MallocScribble").map { String(cString: $0) } ?? "unset")")
guard getenv("MallocScribble").map({ String(cString: $0) }) == "1" else {
    print("FAIL MallocScribble=1 is not in effect (launch with open, as Brev is launched)")
    exit(2)
}

let keyStore = KeyStore()
do { try keyStore.prepareDirectory() } catch {
    print("FAIL Brev's folder: \(error)")
    exit(2)
}
guard case .held = keyStore.takeInstanceLock() else {
    print("REFUSED: Brev is running (its instance lock is held). Quit Brev first.")
    exit(3)
}
guard case .fresh = keyStore.installState() else {
    print("REFUSED: Brev is installed on this Mac (or its keychain cannot be asked); this probe would delete its keys. Run it before onboarding or after a reset.")
    exit(3)
}

let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("touchid-probe-\(getpid())")
try? FileManager.default.removeItem(at: tmp)
try? FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)

/// Deletes every name the probe made (Brev's known names) and its files.
func cleanup() {
    do { try keyStore.deleteKnownNames(); print("cleanup: Brev's keychain names and known files deleted") } catch {
        print("FAIL cleanup: \(error)")
        failures += 1
    }
    if case .fresh = keyStore.installState() {} else { check("cleanup: Brev is not installed afterwards", false) }
    try? FileManager.default.removeItem(at: tmp)
}

func finish() -> Never {
    cleanup()
    if negativeControl && unlocking && failures == 0 {
        print(residue > 0 ? "NEGATIVE CONTROL: residue without the scrub in \(residue) check(s); the scrub is what removes it"
                          : "NEGATIVE CONTROL EMPTY: nothing is left even without the scrub; a PASS at 64 KiB does not show that the scrub works")
    }
    print(failures == 0 ? "PASS" : "FAIL: \(failures) check(s)")
    exit(failures == 0 ? 0 : 1)
}

let names = NeedleFile.names, lengths = NeedleFile.lengths
let offsets = lengths.indices.map { lengths[..<$0].reduce(0, +) }
var xored = Data()
var wrapped = Data()
let session: Session
do {
    // Onboarding's steps, with Brev's own code: known-name cleanup, both keys.
    try keyStore.deleteKnownNames()
    let keys = try keyStore.makeKeys()
    print("ok   keys made in the Secure Enclave (no prompt)")
    let kekPublic = try Enclave.publicKeyBytes(of: keys.kekPublic)
    let signingKey = try Enclave.publicKeyBytes(of: keys.identityPublic)

    // The helper wraps a DEK to the KEK and hands over the needles XORed.
    let pubFile = tmp.appendingPathComponent("kek.pub"), blobFile = tmp.appendingPathComponent("needles.bin")
    try kekPublic.write(to: pubFile)
    let helper = Process()
    helper.executableURL = Bundle.main.executableURL
    helper.arguments = ["--needles", pubFile.path, blobFile.path]
    try helper.run()
    helper.waitUntilExit()
    guard helper.terminationStatus == 0 else { throw CocoaError(.executableLoad) }
    let blob = try Data(contentsOf: blobFile)
    try? FileManager.default.removeItem(at: blobFile)
    guard blob.count == Enclave.wrappedLength + lengths.reduce(0, +) else { throw CocoaError(.fileReadCorruptFile) }
    wrapped = Data(blob.prefix(Enclave.wrappedLength))
    xored = Data(blob.suffix(from: Enclave.wrappedLength))
    print("ok   the helper wrapped a DEK to the KEK (X9.63 ECIES, checked against Security) and made the needles")
    for (i, len) in lengths.enumerated() {
        let set = xored[offsets[i]..<(offsets[i] + len)].withUnsafeBytes {
            brev_scan_set_needle(i, $0.bindMemory(to: UInt8.self).baseAddress, len)
        }
        check("scanner takes needle \(names[i])", set == 0)
    }

    // Onboarding step 6: the stores under the DEK, in a temporary folder.
    let dek = materialise(0)
    let h = scan()
    check("before create: the DEK is in its SecretBytes only (positive control); no ECIES secret",
          h[0] == 1 && h.dropFirst().allSatisfy { $0 == 0 }, show(h))
    session = try Session.create(dir: tmp.path, dek: dek, signingKey: signingKey)
} catch {
    check("setup", false, "\(error)")
    finish()
}
let h0 = scan()
check("after create: no DEK, peer DEK or ECIES secret; locked", h0.allSatisfy { $0 == 0 } && session.brev.isLocked(),
      show(h0))

/// Needle `i` un-XORed into a new SecretBytes.
func materialise(_ i: Int) -> SecretBytes {
    let b = SecretBytes(capacity: 64)
    for j in 0..<lengths[i] { b.base.storeBytes(of: xored[offsets[i] + j] ^ 0x5A, toByteOffset: j, as: UInt8.self) }
    b.setCount(lengths[i])
    return b
}

/// The checks after the unlock closure, then lock, then the positive controls.
func afterUnlock(_ result: Result<Void, UnlockFailure>) -> Never {
    switch result {
    case .success:
        let h = scan()
        check("while unlocked: the DEK is in Rust's box (positive control)", h[0] >= 1 && !session.brev.isLocked(), show(h))
        residueCheck("while unlocked: no copy of the DEK besides Rust's box", h[0] == 1, show(h))
        for i in 1..<names.count {
            if NeedleFile.heldWhileUnlocked.contains(i) {
                residueCheck("while unlocked: no copy of \(names[i]) besides Rust's box", h[i] == 1, show(h))
            } else {
                residueCheck("after the unlock closure: no \(names[i])", h[i] == 0, show(h))
            }
        }
    case .failure(let f):
        check("the unlock (Touch ID) succeeded", false, "\(f.rawValue)")
    }
    session.brev.lock()
    let h = scan()
    residueCheck("after lock: no DEK, peer DEK or ECIES secret anywhere", h.allSatisfy { $0 == 0 }, show(h))
    for i in 0..<names.count {
        let b = materialise(i)
        let c = scan()
        b.wipe()
        check("positive control: one copy of \(names[i]) is found", c[i] == 1, show(c))
    }
    finish()
}

if !unlocking {
    print("dry: the unlock would prompt for Touch ID here; stopping before it")
    for i in 0..<names.count {
        let b = materialise(i)
        let c = scan()
        b.wipe()
        check("positive control: one copy of \(names[i]) is found", c[i] == 1, show(c))
    }
    finish()
}

// Brev's unlock closure, unchanged: one Touch ID prompt. The result comes
// back on the main queue.
print("unlock: Touch ID is asked for now")
UnlockService(keyStore: keyStore).unlock(session, install: wrapped) { afterUnlock($0) }
dispatchMain()
