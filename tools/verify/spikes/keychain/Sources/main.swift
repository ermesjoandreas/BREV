import Foundation
import Security
import LocalAuthentication

// Windowless probe: can this signed app keep a Secure Enclave key in the data
// protection keychain? Creation, lookup and wrapping never prompt.
func log(_ s: String) { FileHandle.standardOutput.write((s + "\n").data(using: .utf8)!) }
let tag = "no.brev.app.kcprobe.kek".data(using: .utf8)!
let group = (Bundle.main.object(forInfoDictionaryKey: "AppIdentifierPrefix") as? String ?? "") + "no.brev.app"
var err: Unmanaged<CFError>?
guard let acl = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet], &err) else { log("acl failed"); exit(1) }
let ctx = LAContext(); ctx.interactionNotAllowed = true
let attrs: [String: Any] = [
  kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
  kSecAttrKeySizeInBits as String: 256,
  kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
  kSecUseDataProtectionKeychain as String: true,
  kSecUseAuthenticationContext as String: ctx,
  kSecPrivateKeyAttrs as String: [
    kSecAttrIsPermanent as String: true,
    kSecAttrApplicationTag as String: tag,
    kSecAttrAccessControl as String: acl,
  ],
]
guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &err) else {
  let e = err!.takeRetainedValue(); log("CREATE FAILED: \(CFErrorGetDomain(e) as String) \(CFErrorGetCode(e))"); exit(2)
}
log("CREATE OK (permanent Secure Enclave key, biometryCurrentSet)")
let q: [String: Any] = [kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: tag,
  kSecUseDataProtectionKeychain as String: true, kSecReturnRef as String: true,
  kSecUseAuthenticationContext as String: ctx]
var out: CFTypeRef?
let st = SecItemCopyMatching(q as CFDictionary, &out)
log("LOOKUP status=\(st)")
if let pub = SecKeyCopyPublicKey(key),
   let wrapped = SecKeyCreateEncryptedData(pub, .eciesEncryptionCofactorVariableIVX963SHA256AESGCM, Data(count: 32) as CFData, &err) {
  log("WRAP OK (\((wrapped as Data).count) bytes, no prompt)")
} else { log("WRAP FAILED") }
let del = SecItemDelete([kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: tag,
  kSecUseDataProtectionKeychain as String: true] as CFDictionary)
log("DELETE status=\(del)")
exit(0)
