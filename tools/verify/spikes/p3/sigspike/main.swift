// Phase 3 spike: P-256 signatures from Security.framework, verified in Rust
// with p256. No keychain item is created (non-permanent keys), no biometry
// flag is set, and every context forbids interaction, so nothing can prompt.
// Output lines: kind variant pubhex msghex derhex
import CryptoKit
import Foundation
import LocalAuthentication
import Security

func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

func noUI() -> LAContext { let c = LAContext(); c.interactionNotAllowed = true; return c }

func makeKey(enclave: Bool) -> SecKey? {
    var attrs: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecUseAuthenticationContext as String: noUI(),
    ]
    var priv: [String: Any] = [kSecAttrIsPermanent as String: false]
    if enclave {
        attrs[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        var e: Unmanaged<CFError>?
        guard let ac = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                       [.privateKeyUsage], &e) else { return nil }
        priv[kSecAttrAccessControl as String] = ac
    }
    attrs[kSecPrivateKeyAttrs as String] = priv
    var err: Unmanaged<CFError>?
    let k = SecKeyCreateRandomKey(attrs as CFDictionary, &err)
    if k == nil { FileHandle.standardError.write("create enclave=\(enclave) failed: \(String(describing: err?.takeRetainedValue()))\n".data(using: .utf8)!) }
    return k
}

func emit(kind: String, key: SecKey, count: Int) {
    let pub = SecKeyCopyExternalRepresentation(SecKeyCopyPublicKey(key)!, nil)! as Data
    var t0 = DispatchTime.now().uptimeNanoseconds, tot: UInt64 = 0
    for i in 0..<count {
        var msg = Data(count: 94 + 256 + 16 + (i % 3) * 1024)
        _ = msg.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }
        for (variant, alg, input) in [("message", SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256, msg),
                                      ("digest", SecKeyAlgorithm.ecdsaSignatureDigestX962SHA256, Data(SHA256.hash(data: msg)))] {
            var err: Unmanaged<CFError>?
            t0 = DispatchTime.now().uptimeNanoseconds
            guard let sig = SecKeyCreateSignature(key, alg, input as CFData, &err) as Data? else {
                FileHandle.standardError.write("sign failed \(kind) \(variant): \(String(describing: err?.takeRetainedValue()))\n".data(using: .utf8)!)
                exit(2)
            }
            tot += DispatchTime.now().uptimeNanoseconds - t0
            print(kind, variant, hex(pub), hex(msg), hex(sig))
        }
    }
    FileHandle.standardError.write("\(kind): \(2 * count) signatures, mean \(tot / UInt64(2 * count) / 1000) us\n".data(using: .utf8)!)
}

let n = Int(CommandLine.arguments.dropFirst().first ?? "200") ?? 200
if let k = makeKey(enclave: false) { emit(kind: "software", key: k, count: n) }
if let k = makeKey(enclave: true) { emit(kind: "enclave-seckey", key: k, count: n / 4) }
// CryptoKit Secure Enclave key (same hardware signer), as a second path.
if SecureEnclave.isAvailable {
    do {
        var e: Unmanaged<CFError>?
        let ac = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage], &e)!
        let k = try SecureEnclave.P256.Signing.PrivateKey(compactRepresentable: false, accessControl: ac,
                                                          authenticationContext: noUI())
        let pub = k.publicKey.x963Representation
        for _ in 0..<(n / 4) {
            var msg = Data(count: 366)
            _ = msg.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }
            let sig = try k.signature(for: msg)
            print("enclave-cryptokit", "message", hex(pub), hex(msg), hex(sig.derRepresentation))
        }
    } catch {
        FileHandle.standardError.write("cryptokit enclave failed: \(error)\n".data(using: .utf8)!)
    }
}
