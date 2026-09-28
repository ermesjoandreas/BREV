// Brev Phase 2 spike "enclave" (v2): Secure Enclave keys from an ad-hoc signed,
// sandboxed, Hardened Runtime app. Deliberately NO AppKit: the process never
// connects to the window server, so it cannot show a window, a Dock icon or
// take focus. The Info.plist also sets LSUIElement.
//
// Modes (first argument):
//   probe       automated, no prompt possible: tests 1-7
//   restore     automated, no prompt possible: second launch, restores blobs
//   rogue-nobio automated, CLI build only: uses the NO-biometry test key blob
//               from another code identity (argument 2 = probe stdout file)
//   cleanup     removes the key blobs this spike wrote into its container
//   setup       user script, no prompt: fresh biometric KEK + signing key, wraps a DEK
//   gatecheck   user script, no prompt: unwrap with interaction disallowed must FAIL
//   unwrap      user script: exactly ONE Touch ID prompt, unwraps the DEK once
//   reuse       user script, optional: unwrap + sign with one LAContext
//   rogue       user script, optional, CLI build only: unwrap from another binary
//
// Every call in the automated modes gets an LAContext with
// interactionNotAllowed = true (LAContext.h: fails with errSecInteractionNotAllowed
// "instead of displaying the authentication UI"), and no automated mode ever
// USES a biometric key: only the no-biometry key of test 7 is used.

import CryptoKit
import Foundation
import LocalAuthentication
import Security

// MARK: - Logging (stdout, redirected by the runner into the scratch dir, plus a
// log file inside the app's own container)

var logURL: URL?

func log(_ s: String) {
    let line = s + "\n"
    FileHandle.standardOutput.write(line.data(using: .utf8)!)
    guard let u = logURL else { return }
    if let h = try? FileHandle(forWritingTo: u) {
        h.seekToEndOfFile()
        h.write(line.data(using: .utf8)!)
        try? h.close()
    } else {
        try? line.data(using: .utf8)!.write(to: u)
    }
}

func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }
func fp(_ d: Data) -> String { String(hex(Data(SHA256.hash(data: d))).prefix(16)) }

func cfErr(_ e: Unmanaged<CFError>?) -> String {
    guard let e else { return "nil error" }
    let ns = e.takeRetainedValue() as Error as NSError
    return "domain=\(ns.domain) code=\(ns.code) desc=\"\(ns.localizedDescription)\""
}

func errStr(_ e: Error) -> String {
    let ns = e as NSError
    var s = "swift=\(String(reflecting: e)) domain=\(ns.domain) code=\(ns.code)"
    if let u = ns.userInfo[NSUnderlyingErrorKey] as? NSError {
        s += " underlying=(domain=\(u.domain) code=\(u.code))"
    }
    return s
}

// MARK: - Shared helpers

func noUI() -> LAContext {
    let c = LAContext()
    c.interactionNotAllowed = true
    return c
}

/// CLAUDE.md §3.2: WhenPasscodeSetThisDeviceOnly + [.privateKeyUsage, .biometryCurrentSet].
/// biometry=false gives [.privateKeyUsage] only: used by test 7 so the spike can
/// exercise a real Secure Enclave decrypt without any prompt.
func brevACL(biometry: Bool = true) -> SecAccessControl {
    var err: Unmanaged<CFError>?
    let flags: SecAccessControlCreateFlags = biometry ? [.privateKeyUsage, .biometryCurrentSet] : [.privateKeyUsage]
    guard let acl = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, flags, &err) else {
        log("FATAL SecAccessControlCreateWithFlags failed: \(cfErr(err))")
        exit(2)
    }
    return acl
}

func randomDEK() -> Data {
    var b = [UInt8](repeating: 0, count: 32)
    let st = SecRandomCopyBytes(kSecRandomDefault, 32, &b)
    precondition(st == errSecSuccess)
    return Data(b)
}

let hpkeSuite = HPKE.Ciphersuite.P256_SHA256_AES_GCM_256
let hpkeInfo = Data("brev-spike dek wrap v1".utf8)
let eciesAlg = SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM

func secPublicKey(x963: Data) -> SecKey? {
    let attrs: [CFString: Any] = [
        kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeyClass: kSecAttrKeyClassPublic,
        kSecAttrKeySizeInBits: 256,
    ]
    var err: Unmanaged<CFError>?
    let k = SecKeyCreateWithData(x963 as CFData, attrs as CFDictionary, &err)
    if k == nil { log("  SecKeyCreateWithData(public) failed: \(cfErr(err))") }
    return k
}

func hpkeWrap(_ dek: Data, to pub: P256.KeyAgreement.PublicKey) throws -> Data {
    var sender = try HPKE.Sender(recipientKey: pub, ciphersuite: hpkeSuite, info: hpkeInfo)
    let ct = try sender.seal(dek)
    return sender.encapsulatedKey + ct // 65 + 32 + 16 = 113 bytes
}

func hpkeUnwrap<K: HPKEDiffieHellmanPrivateKey>(_ blob: Data, with key: K) throws -> Data {
    let enc = blob.prefix(65)
    let ct = blob.dropFirst(65)
    var r = try HPKE.Recipient(privateKey: key, ciphersuite: hpkeSuite, info: hpkeInfo, encapsulatedKey: Data(enc))
    return try r.open(Data(ct))
}

func eciesWrap(_ dek: Data, toX963 pub: Data) -> Data? {
    guard let k = secPublicKey(x963: pub) else { return nil }
    var err: Unmanaged<CFError>?
    guard let ct = SecKeyCreateEncryptedData(k, eciesAlg, dek as CFData, &err) else {
        log("  SecKeyCreateEncryptedData failed: \(cfErr(err))")
        return nil
    }
    return ct as Data
}

/// Opens Apple's ECIES (cofactor, variable IV, X9.63 SHA-256, AES-GCM) blob with a
/// CryptoKit key agreement: X9.63 KDF, sharedInfo = ephemeral public key,
/// AES key = first 16 bytes, IV = last 16 bytes, 16-byte tag. Hand-assembled on
/// purpose, only to show what that option would require.
func eciesOpenWithKeyAgreement(_ blob: Data, agree: (P256.KeyAgreement.PublicKey) throws -> SharedSecret) throws -> Data {
    let eph = Data(blob.prefix(65))
    let body = Data(blob.dropFirst(65).dropLast(16))
    let tag = Data(blob.suffix(16))
    let shared = try agree(P256.KeyAgreement.PublicKey(x963Representation: eph))
    let kdf = shared.x963DerivedSymmetricKey(using: SHA256.self, sharedInfo: eph, outputByteCount: 32)
    let raw = kdf.withUnsafeBytes { Data($0) }
    let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: raw.suffix(16)), ciphertext: body, tag: tag)
    return try AES.GCM.open(box, using: SymmetricKey(data: raw.prefix(16)))
}

/// UNDOCUMENTED: a SecKey for a CryptoKit Secure Enclave blob, via the private
/// attribute "toid" (kSecAttrTokenOID) seen in SecKeyCopyAttributes output.
func secKeyFromBlob(_ blob: Data) -> SecKey? {
    let attrs: [CFString: Any] = [
        kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeyClass: kSecAttrKeyClassPrivate,
        kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
        kSecUseAuthenticationContext: noUI(),
        "toid" as CFString: blob,
    ]
    var err: Unmanaged<CFError>?
    let k = SecKeyCreateWithData(Data() as CFData, attrs as CFDictionary, &err)
    if k == nil { log("  SecKeyCreateWithData(toid) failed: \(cfErr(err))") }
    return k
}

// MARK: - Container directories

func spikeDir(_ sub: String) -> URL {
    var base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        .appendingPathComponent("spike")
    if !sub.isEmpty { base = base.appendingPathComponent(sub) }
    try? FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
    return base
}

func write(_ d: Data, _ dir: URL, _ name: String) {
    do { try d.write(to: dir.appendingPathComponent(name), options: .atomic) } catch {
        log("  write \(name) failed: \(errStr(error))")
    }
}

func read(_ dir: URL, _ name: String) -> Data? { try? Data(contentsOf: dir.appendingPathComponent(name)) }

/// Hands test data to the CLI twin through stdout (the runner redirects stdout
/// into the scratch dir), so nothing outside the app ever reads its container.
func export(_ name: String, _ d: Data) { log("EXPORT \(name) \(d.base64EncodedString())") }

// MARK: - Environment

func environment() {
    log("== ENV")
    log("  pid=\(getpid()) ppid=\(getppid()) bundle=\(Bundle.main.bundleIdentifier ?? "nil")")
    log("  exe=\(CommandLine.arguments[0])")
    log("  NSHomeDirectory=\(NSHomeDirectory())")
    log("  sandboxed(container home)=\(NSHomeDirectory().contains("/Library/Containers/"))")
    let pw = getpwuid(getuid())
    let realHome = pw.map { String(cString: $0.pointee.pw_dir) } ?? "?"
    do {
        _ = try FileManager.default.contentsOfDirectory(atPath: realHome + "/BREV")
        log("  list \(realHome)/BREV: ALLOWED (not sandboxed?)")
    } catch {
        log("  list \(realHome)/BREV: denied: \((error as NSError).domain) \((error as NSError).code)")
    }
    log("  AppKit loaded in process: \(NSClassFromString("NSApplication") != nil)")
    log("  os=\(ProcessInfo.processInfo.operatingSystemVersionString)")
    log("  SecureEnclave.isAvailable=\(SecureEnclave.isAvailable)")
}

// MARK: - Test 1: permanent SE key (keychain)

func test1() {
    log("== TEST 1: SecKeyCreateRandomKey, kSecAttrIsPermanent=true")
    struct Case { let name: String; let se: Bool; let bio: Bool; let dp: Bool? }
    let cases = [
        Case(name: "1a SE + Brev ACL, no kSecUseDataProtectionKeychain", se: true, bio: true, dp: nil),
        Case(name: "1b SE + Brev ACL, kSecUseDataProtectionKeychain=true", se: true, bio: true, dp: true),
        Case(name: "1c SE + ACL .privateKeyUsage only (no biometry), DP=true", se: true, bio: false, dp: true),
        Case(name: "1d control: software P-256 (no SE, no ACL), DP=true", se: false, bio: false, dp: true),
    ]
    for c in cases {
        let tag = Data("no.brev.spike.enclave.t1.\(UUID().uuidString)".utf8)
        var priv: [CFString: Any] = [
            kSecAttrIsPermanent: true,
            kSecAttrApplicationTag: tag,
            kSecAttrLabel: "brev-spike-t1",
        ]
        if c.se { priv[kSecAttrAccessControl] = brevACL(biometry: c.bio) }
        var attrs: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecPrivateKeyAttrs: priv,
            kSecUseAuthenticationContext: noUI(),
        ]
        if c.se { attrs[kSecAttrTokenID] = kSecAttrTokenIDSecureEnclave }
        if let dp = c.dp { attrs[kSecUseDataProtectionKeychain] = dp }
        var err: Unmanaged<CFError>?
        let key = SecKeyCreateRandomKey(attrs as CFDictionary, &err)
        log("  \(c.name): " + (key != nil ? "CREATED (OSStatus 0)" : "FAILED \(cfErr(err))"))
        // Remove anything that might have been stored. Only the data protection
        // keychain is queried, unless a key was created without the DP flag.
        for dp in (key != nil && c.dp == nil) ? [true, false] : [true] {
            var q: [CFString: Any] = [
                kSecClass: kSecClassKey,
                kSecAttrApplicationTag: tag,
                kSecUseAuthenticationContext: noUI(),
            ]
            if dp { q[kSecUseDataProtectionKeychain] = true }
            let st = SecItemDelete(q as CFDictionary)
            log("    cleanup SecItemDelete(dp=\(dp)) = \(st)\(st == errSecItemNotFound ? " errSecItemNotFound" : st == errSecSuccess ? " deleted" : "")")
        }
    }
}

// MARK: - Test 2: non-permanent SE SecKey

func test2(dek: Data) {
    log("== TEST 2: SecKeyCreateRandomKey SE, kSecAttrIsPermanent=false")
    for bio in [true, false] {
        let label = bio ? "2a Brev ACL (biometry)" : "2b ACL .privateKeyUsage only (no biometry)"
        let attrs: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs: [kSecAttrIsPermanent: false, kSecAttrAccessControl: brevACL(biometry: bio)] as [CFString: Any],
            kSecUseAuthenticationContext: noUI(),
        ]
        var err: Unmanaged<CFError>?
        guard let priv = SecKeyCreateRandomKey(attrs as CFDictionary, &err) else {
            log("  \(label): FAILED \(cfErr(err))"); continue
        }
        log("  \(label): CREATED")
        guard let pub = SecKeyCopyPublicKey(priv) else { log("    SecKeyCopyPublicKey nil"); continue }
        if bio, let a = SecKeyCopyAttributes(priv) as? [String: Any] {
            let desc = a.keys.sorted().map { k -> String in
                let v = a[k]!
                if let d = v as? Data { return "\(k)=<Data \(d.count)B>" }
                return "\(k)=\(v)"
            }
            log("    private key attributes: " + desc.joined(separator: ", "))
            log("    public attribute to persist it: none documented; kSecAttrIsPermanent=false keys live only in this process")
        }
        log("    SecKeyIsAlgorithmSupported(pub, .encrypt, ECIES cofactor X963SHA256 AESGCM) = \(SecKeyIsAlgorithmSupported(pub, .encrypt, eciesAlg))")
        var e3: Unmanaged<CFError>?
        guard let ct = SecKeyCreateEncryptedData(pub, eciesAlg, dek as CFData, &e3) as Data? else {
            log("    WRAP failed: \(cfErr(e3))"); continue
        }
        log("    WRAP (SecKeyCreateEncryptedData, ECIES, public key only): OK, \(ct.count) bytes")
        if bio {
            log("    unwrap NOT run (biometric key: would prompt) -> USER_TEST.md covers the biometric unwrap")
        } else {
            var e4: Unmanaged<CFError>?
            let pt = SecKeyCreateDecryptedData(priv, eciesAlg, ct as CFData, &e4) as Data?
            log("    UNWRAP (SecKeyCreateDecryptedData in the Secure Enclave, no-biometry key): \(pt == dek ? "EQUAL to DEK" : "FAILED \(cfErr(e4))")")
        }
    }
}

// MARK: - Test 3: CryptoKit SE keys (Brev ACL)

func test3(dir: URL) -> SecureEnclave.P256.KeyAgreement.PrivateKey? {
    log("== TEST 3: CryptoKit SecureEnclave.P256 keys with the Brev ACL (biometry)")
    do {
        let s = try SecureEnclave.P256.Signing.PrivateKey(accessControl: brevACL(), authenticationContext: noUI())
        log("  Signing.PrivateKey(accessControl:): CREATED; dataRepresentation \(s.dataRepresentation.count) bytes; pub fp \(fp(s.publicKey.x963Representation))")
        let k = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: brevACL(), authenticationContext: noUI())
        log("  KeyAgreement.PrivateKey(accessControl:): CREATED; dataRepresentation \(k.dataRepresentation.count) bytes; pub fp \(fp(k.publicKey.x963Representation))")
        write(s.dataRepresentation, dir, "sign.blob")
        write(s.publicKey.x963Representation, dir, "sign.pub")
        write(k.dataRepresentation, dir, "kek.blob")
        write(k.publicKey.x963Representation, dir, "kek.pub")
        log("  blobs + public keys written to the container: \(dir.path)")
        return k
    } catch {
        log("  FAILED \(errStr(error))")
        return nil
    }
}

// MARK: - Test 4: wrap to the biometric KEK (public key only)

func test4(kek: SecureEnclave.P256.KeyAgreement.PrivateKey, dek: Data, dir: URL) {
    log("== TEST 4: DEK wrap to the biometric CryptoKit KEK (no prompt: only the public key is used)")
    do {
        let blob = try hpkeWrap(dek, to: kek.publicKey)
        write(blob, dir, "dek.hpke")
        log("  4a HPKE (RFC 9180, P256_SHA256_AES_GCM_256) to the SE KEK: OK, \(blob.count) bytes")
    } catch { log("  4a HPKE wrap FAILED \(errStr(error))") }
    if let ct = eciesWrap(dek, toX963: kek.publicKey.x963Representation) {
        log("  4b SecKeyCreateEncryptedData ECIES to the SE KEK's public key (via SecKeyCreateWithData): OK, \(ct.count) bytes")
    }
    log("  unwrap NOT run (biometric key) -> USER_TEST.md")
}

// MARK: - Test 5: LAContext

func test5() {
    log("== TEST 5: LAContext (canEvaluatePolicy only; evaluatePolicy is never called)")
    let c = LAContext()
    var err: NSError?
    let ok = c.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err)
    log("  canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics) = \(ok)\(err.map { " error domain=\($0.domain) code=\($0.code)" } ?? "")")
    let names: [LABiometryType: String] = [.none: "none", .touchID: "touchID", .faceID: "faceID", .opticID: "opticID"]
    log("  biometryType = \(c.biometryType.rawValue) (\(names[c.biometryType] ?? "?"))")
    if #available(macOS 15.0, *) {
        log("  domainState.biometry.stateHash = \(c.domainState.biometry.stateHash.map { "\($0.count) bytes" } ?? "nil")")
    }
    c.localizedFallbackTitle = ""
    log("  localizedFallbackTitle = \"\" set (LAContext.h: empty string hides the button); visible check -> USER_TEST.md")
}

// MARK: - Test 6: CryptoKit <-> SecKey

func test6(kek: SecureEnclave.P256.KeyAgreement.PrivateKey) {
    log("== TEST 6: can a CryptoKit SE key be used as a SecKey?")
    log("  documented API: none (CryptoKit SE keys expose publicKey, dataRepresentation, sharedSecretFromKeyAgreement / signature only)")
    if let k = secKeyFromBlob(kek.dataRepresentation) {
        let pub = SecKeyCopyPublicKey(k).flatMap { SecKeyCopyExternalRepresentation($0, nil) as Data? }
        log("  6a UNDOCUMENTED SecKeyCreateWithData(attrs{tokenID=SE, \"toid\"=blob}): SecKey CREATED; public key equals CryptoKit KEK: \(pub == kek.publicKey.x963Representation)")
    }
}

// MARK: - Test 7: full round trip with a NO-biometry SE key (no prompt possible)

func test7(dir: URL) {
    log("== TEST 7: CryptoKit SE KeyAgreement key WITHOUT biometry (.privateKeyUsage only): real Secure Enclave unwrap, no prompt")
    do {
        let kek = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: brevACL(biometry: false), authenticationContext: noUI())
        let dek = randomDEK()
        let wrapped = try hpkeWrap(dek, to: kek.publicKey)
        let back = try hpkeUnwrap(wrapped, with: kek)
        log("  7a HPKE wrap + unwrap (key agreement in the SE): \(back == dek ? "EQUAL" : "MISMATCH")")
        if let e = eciesWrap(dek, toX963: kek.publicKey.x963Representation) {
            do {
                let b2 = try eciesOpenWithKeyAgreement(e) { try kek.sharedSecretFromKeyAgreement(with: $0) }
                log("  7b SecKey-ECIES blob opened with CryptoKit SE key agreement + hand-assembled X9.63 KDF/AES-GCM: \(b2 == dek ? "EQUAL" : "MISMATCH")")
            } catch { log("  7b FAILED \(errStr(error))") }
            if let sk = secKeyFromBlob(kek.dataRepresentation) {
                var e5: Unmanaged<CFError>?
                let pt = SecKeyCreateDecryptedData(sk, eciesAlg, e as CFData, &e5) as Data?
                log("  7c UNDOCUMENTED toid-SecKey + SecKeyCreateDecryptedData(ECIES): \(pt == dek ? "EQUAL" : "FAILED \(cfErr(e5))")")
            }
        }
        // Persist for the restore launch and export for the other-identity test.
        write(kek.dataRepresentation, dir, "nobio.blob")
        write(wrapped, dir, "nobio.dek.hpke")
        write(Data(SHA256.hash(data: dek)), dir, "nobio.dek.sha256")
        export("nobio.blob", kek.dataRepresentation)
        export("nobio.dek.hpke", wrapped)
        export("nobio.dek.sha256", Data(SHA256.hash(data: dek)))

        // Tamper: init(dataRepresentation:) vs actual use.
        let blob = kek.dataRepresentation
        for pos in [8, blob.count / 2, blob.count - 8] {
            var t = blob
            t[pos] ^= 0x01
            var initRes = "accepted", useRes = "n/a"
            do {
                let k2 = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: t, authenticationContext: noUI())
                do { let x = try hpkeUnwrap(wrapped, with: k2); useRes = x == dek ? "UNWRAPPED (tamper NOT detected)" : "wrong output" }
                catch { useRes = "rejected (\((error as NSError).domain) \((error as NSError).code))" }
            } catch { initRes = "rejected (\((error as NSError).domain) \((error as NSError).code))" }
            log("  7d tampered blob, bit flipped at byte \(pos)/\(blob.count): init \(initRes); use \(useRes)")
        }
    } catch {
        log("  FAILED \(errStr(error))")
    }
}

// MARK: - Modes

func probe() -> Int32 {
    let dir = spikeDir("probe")
    environment()
    test5()
    test1()
    let dek = randomDEK()
    test2(dek: dek)
    guard let kek = test3(dir: dir) else { return 1 }
    test4(kek: kek, dek: dek, dir: dir)
    test6(kek: kek)
    test7(dir: dir)
    return 0
}

func restore() -> Int32 {
    let dir = spikeDir("probe")
    environment()
    log("== RESTORE (second launch) from \(dir.path); every call has interactionNotAllowed, so a prompt would make it FAIL")
    guard let sb = read(dir, "sign.blob"), let sp = read(dir, "sign.pub"),
          let kb = read(dir, "kek.blob"), let kp = read(dir, "kek.pub") else {
        log("  blobs missing"); return 1
    }
    var rc: Int32 = 0
    do {
        let s = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: sb, authenticationContext: noUI())
        log("  R1 biometric signing key restored: OK; public key equals saved: \(s.publicKey.x963Representation == sp)")
    } catch { log("  R1 FAILED \(errStr(error))"); rc = 1 }
    do {
        let k = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: kb, authenticationContext: noUI())
        log("  R2 biometric KEK restored: OK; public key equals saved: \(k.publicKey.x963Representation == kp)")
        let b = try hpkeWrap(randomDEK(), to: k.publicKey)
        log("  R3 HPKE wrap to the restored KEK: OK, \(b.count) bytes")
    } catch { log("  R2 FAILED \(errStr(error))"); rc = 1 }
    if let nb = read(dir, "nobio.blob"), let w = read(dir, "nobio.dek.hpke"), let h = read(dir, "nobio.dek.sha256") {
        do {
            let k = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: nb, authenticationContext: noUI())
            var d = try hpkeUnwrap(w, with: k)
            log("  R4 no-biometry KEK restored from file + HPKE unwrap of the DEK wrapped in the FIRST launch: \(Data(SHA256.hash(data: d)) == h ? "DEK MATCHES" : "MISMATCH")")
            d.resetBytes(in: 0..<d.count)
        } catch { log("  R4 FAILED \(errStr(error))"); rc = 1 }
    } else { log("  R4 no-biometry files missing"); rc = 1 }
    return rc
}

/// CLI twin only: another code identity (not sandboxed, different identifier)
/// uses the no-biometry blob that the sandboxed app exported.
func rogueNobio(_ path: String?) -> Int32 {
    environment()
    log("== ROGUE-NOBIO: other code identity uses the sandboxed app's exported no-biometry KEK blob")
    guard let path, let text = try? String(contentsOfFile: path, encoding: .utf8) else { log("  no probe stdout file"); return 1 }
    var ex: [String: Data] = [:]
    for line in text.split(separator: "\n") where line.hasPrefix("EXPORT ") {
        let p = line.split(separator: " ")
        if p.count == 3, let d = Data(base64Encoded: String(p[2])) { ex[String(p[1])] = d }
    }
    guard let nb = ex["nobio.blob"], let w = ex["nobio.dek.hpke"], let h = ex["nobio.dek.sha256"] else { log("  exports missing"); return 1 }
    do {
        let k = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: nb, authenticationContext: noUI())
        log("  restore in other process: OK")
        let d = try hpkeUnwrap(w, with: k)
        log("  HPKE unwrap in other process: \(Data(SHA256.hash(data: d)) == h ? "DEK MATCHES (blob is NOT bound to the creating app)" : "MISMATCH")")
        return 0
    } catch {
        log("  FAILED \(errStr(error))")
        return 1
    }
}

func userDir() -> URL { spikeDir("user") }

func setup() -> Int32 {
    environment()
    test5()
    let dir = userDir()
    log("== SETUP (no prompt): fresh biometric KEK + signing key in the Secure Enclave, fresh DEK, HPKE wrap")
    do {
        let kek = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: brevACL(), authenticationContext: noUI())
        let sign = try SecureEnclave.P256.Signing.PrivateKey(accessControl: brevACL(), authenticationContext: noUI())
        let dek = randomDEK()
        let wrapped = try hpkeWrap(dek, to: kek.publicKey)
        write(kek.dataRepresentation, dir, "kek.blob")
        write(sign.dataRepresentation, dir, "sign.blob")
        write(sign.publicKey.x963Representation, dir, "sign.pub")
        write(wrapped, dir, "dek.hpke")
        write(Data(SHA256.hash(data: dek)), dir, "dek.sha256")
        // For the optional "rogue" step only (another binary tries the same key).
        export("kek.blob", kek.dataRepresentation)
        export("dek.hpke", wrapped)
        export("dek.sha256", Data(SHA256.hash(data: dek)))
        log("  OK. KEK pub fp \(fp(kek.publicKey.x963Representation)); the test DEK is kept only as its SHA-256")
        return 0
    } catch {
        log("  FAILED \(errStr(error))")
        return 1
    }
}

func gatecheck() -> Int32 {
    log("== GATECHECK (no prompt expected): unwrap with interactionNotAllowed must FAIL")
    let dir = userDir()
    guard let kb = read(dir, "kek.blob"), let wrapped = read(dir, "dek.hpke") else { log("  run setup first"); return 1 }
    do {
        let k = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: kb, authenticationContext: noUI())
        _ = try hpkeUnwrap(wrapped, with: k)
        log("  UNEXPECTED: unwrap succeeded WITHOUT Touch ID. The key is not gated!")
        return 3
    } catch {
        log("  GOOD: unwrap refused without interaction: \(errStr(error))")
        return 0
    }
}

func unwrap(blobs: [String: Data], alsoSign: Bool) -> Int32 {
    log("== UNWRAP (exactly ONE Touch ID prompt expected)")
    guard let kb = blobs["kek.blob"], let wrapped = blobs["dek.hpke"], let want = blobs["dek.sha256"] else {
        log("  run setup first"); return 1
    }
    let ctx = LAContext()
    ctx.localizedFallbackTitle = ""          // LAContext.h: empty string hides "Use Password…"
    ctx.localizedCancelTitle = "Avbryt"
    ctx.localizedReason = "låse opp Brev-spike (test)"
    do {
        let k = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: kb, authenticationContext: ctx)
        let t0 = Date()
        var dek = try hpkeUnwrap(wrapped, with: k)
        let ok = Data(SHA256.hash(data: dek)) == want
        log("  HPKE unwrap after Touch ID: \(ok ? "DEK MATCHES (round trip OK)" : "DEK MISMATCH") (\(String(format: "%.1f", Date().timeIntervalSince(t0))) s incl. prompt)")
        dek.resetBytes(in: 0..<dek.count)
        if alsoSign, let sb = blobs["sign.blob"], let sp = blobs["sign.pub"] {
            let s = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: sb, authenticationContext: ctx)
            let msg = Data("brev-spike envelope".utf8)
            let t1 = Date()
            let sig = try s.signature(for: msg)
            let pub = try P256.Signing.PublicKey(x963Representation: sp)
            log("  sign with the SAME LAContext: valid=\(pub.isValidSignature(sig, for: msg)) (\(String(format: "%.1f", Date().timeIntervalSince(t1))) s; near 0 = no 2nd prompt)")
        }
        return ok ? 0 : 4
    } catch {
        log("  FAILED \(errStr(error))  (LAError: userCancel=-2 userFallback=-3 biometryLockout=-8 notInteractive=-1004)")
        return 5
    }
}

func userBlobs() -> [String: Data] {
    var m: [String: Data] = [:]
    for n in ["kek.blob", "dek.hpke", "dek.sha256", "sign.blob", "sign.pub"] { m[n] = read(userDir(), n) }
    return m
}

func cleanup() -> Int32 {
    for sub in ["probe", "user"] {
        let u = spikeDir(sub)
        do { try FileManager.default.removeItem(at: u); log("cleanup: removed \(u.path)") } catch { log("cleanup: \(errStr(error))") }
    }
    return 0
}

func run(_ mode: String, _ extra: String?) -> Int32 {
    log("---- mode=\(mode) at \(ISO8601DateFormatter().string(from: Date()))")
    switch mode {
    case "probe": return probe()
    case "restore": return restore()
    case "setup": return setup()
    case "gatecheck": return gatecheck()
    case "unwrap": return unwrap(blobs: userBlobs(), alsoSign: false)
    case "reuse": return unwrap(blobs: userBlobs(), alsoSign: true)
    case "cleanup": return cleanup()
    default: log("unknown mode \(mode)"); return 64
    }
}

// MARK: - Entry

let positional = CommandLine.arguments.dropFirst().filter { !$0.hasPrefix("-") }
let mode = positional.first ?? "probe"
let extra = positional.dropFirst().first
let interactive: Set<String> = ["unwrap", "reuse", "rogue"]

// Watchdog: never hang around.
let watchdog = DispatchWorkItem { log("WATCHDOG: timeout, exiting"); exit(99) }
DispatchQueue.global().asyncAfter(deadline: .now() + (interactive.contains(mode) ? 90 : 25), execute: watchdog)

#if CLI
switch mode {
case "rogue-nobio":
    exit(rogueNobio(extra))
case "rogue":
    // Optional user step: the biometric blob exported by `setup`, used by this
    // other binary. Shows what the Touch ID prompt says for another process.
    guard let extra, let text = try? String(contentsOfFile: extra, encoding: .utf8) else { log("usage: rogue <setup stdout file>"); exit(64) }
    var ex: [String: Data] = [:]
    for line in text.split(separator: "\n") where line.hasPrefix("EXPORT ") {
        let p = line.split(separator: " ")
        if p.count == 3, let d = Data(base64Encoded: String(p[2])) { ex[String(p[1])] = d }
    }
    log("== ROGUE (optional user step): a different binary uses Brev-spike's biometric KEK blob")
    exit(unwrap(blobs: ex, alsoSign: false))
default:
    log("CLI build supports only rogue-nobio and rogue"); exit(64)
}
#else
logURL = spikeDir("").appendingPathComponent("spike.log")
exit(run(mode, extra))
#endif
