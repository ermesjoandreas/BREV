// Spike: does Security.framework leave copies of the DEK (ECIES unwrap) or of
// the ECDH shared secret in this process after the returned CFData is wiped?
// Command-line only. Keys are ephemeral (kSecAttrIsPermanent = false).
// ecies_sw/ecdh_sw: software keys. ecies_se/ecdh_se: Secure Enclave keys with
// .privateKeyUsage only -- no Touch ID / password prompt can appear.
// ecies_bio/ecdh_bio: Secure Enclave keys with .biometryCurrentSet -- these
// SHOW A TOUCH ID PROMPT and only run with BREV_ALLOW_TOUCH_ID=1 (user script).
// usage: probe ecies_sw | ecdh_sw | ecies_se | ecdh_se | ecies_bio | ecdh_bio
import Foundation
import Security

let mode = CommandLine.arguments[1]
let bio = mode.hasSuffix("_bio")
let se = mode.hasSuffix("_se") || bio
if bio && ProcessInfo.processInfo.environment["BREV_ALLOW_TOUCH_ID"] != "1" {
    print("\(mode): refused: needs BREV_ALLOW_TOUCH_ID=1 (it shows a Touch ID prompt)"); exit(9)
}
let alg = SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM

func needle(_ p: UnsafeRawPointer) -> [UInt8] { (0..<16).map { p.load(fromByteOffset: $0, as: UInt8.self) ^ 0x5A } }
func count(_ nx: [UInt8]) -> String {
    var r = scan2_result()
    nx.withUnsafeBufferPointer { scan2($0.baseAddress, &r) }
    var tags: [String] = []
    withUnsafeBytes(of: &r.by_tag) { raw in
        let a = raw.bindMemory(to: UInt64.self)
        for i in 0..<256 where a[i] > 0 { tags.append("\(i):\(a[i])") }
    }
    return "\(r.hits){\(tags.joined(separator: ","))}"
}
func wipe(_ d: CFData) {
    let n = CFDataGetLength(d)
    if n > 0 { _ = memset_s(UnsafeMutableRawPointer(mutating: CFDataGetBytePtr(d)!), n, 0, n) }
}
func makeKey(secureEnclave: Bool) -> SecKey {
    var attrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                                kSecAttrKeySizeInBits as String: 256]
    var priv: [String: Any] = [kSecAttrIsPermanent as String: false]
    if secureEnclave {
        attrs[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        // Without .biometryCurrentSet using this key never prompts; with it
        // (bio modes, user script only) every use shows Touch ID.
        let flags: SecAccessControlCreateFlags = bio ? [.privateKeyUsage, .biometryCurrentSet] : [.privateKeyUsage]
        priv[kSecAttrAccessControl as String] = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, nil)!
    }
    attrs[kSecPrivateKeyAttrs as String] = priv
    var err: Unmanaged<CFError>?
    guard let k = SecKeyCreateRandomKey(attrs as CFDictionary, &err) else {
        print("\(mode): key creation failed: \(err!.takeRetainedValue())"); exit(2)
    }
    return k
}

var err: Unmanaged<CFError>?
let key = makeKey(secureEnclave: se)
if mode.hasPrefix("ecies") {
    let pub = SecKeyCopyPublicKey(key)!
    var nA: [UInt8] = [], nB: [UInt8] = []
    var wrapped: CFData? = nil
    autoreleasepool {
        let dek = UnsafeMutableRawBufferPointer.allocate(byteCount: 32, alignment: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, 32, dek.baseAddress!)
        nA = needle(dek.baseAddress!); nB = needle(dek.baseAddress! + 16)
        let plain = CFDataCreate(nil, dek.baseAddress!.assumingMemoryBound(to: UInt8.self), 32)!
        _ = memset_s(dek.baseAddress!, 32, 0, 32); dek.deallocate()
        wrapped = SecKeyCreateEncryptedData(pub, alg, plain, &err)
        wipe(plain)
    }
    guard let w = wrapped else { print("\(mode): wrap failed \(err!.takeRetainedValue())"); exit(3) }
    let afterWrap = "A=\(count(nA)) B=\(count(nB))"
    var live = ""
    autoreleasepool {
        guard let out = SecKeyCreateDecryptedData(key, alg, w, &err) else {
            print("\(mode): unwrap failed \(err!.takeRetainedValue())"); exit(4)
        }
        live = "A=\(count(nA)) B=\(count(nB))"
        wipe(out)
    }
    scrub_stack_c(64)
    print("\(mode): (64 KiB stack scrubbed before this count) DEK hits after wrap (setup) [\(afterWrap)] | live after unwrap [\(live)] | after wiping returned CFData [A=\(count(nA)) B=\(count(nB))]")
} else {
    let peer = makeKey(secureEnclave: false)
    let peerPub = SecKeyCopyPublicKey(peer)!
    var nA: [UInt8] = [], nB: [UInt8] = []
    var live = ""
    autoreleasepool {
        guard let ss = SecKeyCopyKeyExchangeResult(key, .ecdhKeyExchangeStandard, peerPub, [:] as CFDictionary, &err) else {
            print("\(mode): ECDH failed \(err!.takeRetainedValue())"); exit(5)
        }
        let p = UnsafeRawPointer(CFDataGetBytePtr(ss)!)
        nA = needle(p); nB = needle(p + 16)
        live = "A=\(count(nA)) B=\(count(nB)) len=\(CFDataGetLength(ss))"
        wipe(ss)
    }
    let afterWipe = "A=\(count(nA)) B=\(count(nB))"
    scrub_stack_c(16)
    let afterScrub16 = "A=\(count(nA)) B=\(count(nB))"
    scrub_stack_c(64)
    print("\(mode): shared-secret hits live [\(live)] | after wiping returned CFData [\(afterWipe)] | after 16 KiB stack scrub [\(afterScrub16)] | after 64 KiB [A=\(count(nA)) B=\(count(nB))]")
}
