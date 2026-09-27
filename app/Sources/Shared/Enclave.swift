// Enclave.swift — the two Secure Enclave keys and the HPKE-wrapped DEK.
//
// Upholds CLAUDE.md §1.8, §1.9 and §3.3 (docs/DECISIONS.md D-0032, D-0033;
// docs/PHASE2_DESIGN.md §5.1): both keys are CryptoKit SecureEnclave.P256
// keys, ThisDeviceOnly and bound to the current fingerprints
// (.biometryCurrentSet). Their blobs are stored as files by KeyStore, never
// in the keychain. The DEK is wrapped to the KEK with HPKE (RFC 9180,
// P256_SHA256_AES_GCM_256). Creating the keys and wrapping need no prompt;
// opening needs one Touch ID prompt, through the LAContext the caller gives
// the KEK (UnlockService, §5.4). No AppKit: compiled into the app and the
// CLI harness, which runs `wrap` and `open` with a software key.

import CryptoKit
import Foundation
import LocalAuthentication
import Security

enum Enclave {
    static let suite = HPKE.Ciphersuite.P256_SHA256_AES_GCM_256
    static let info = Data("brev/v1/dek-wrap".utf8)
    static let encapsulatedKeyLength = 65
    /// `dek.hpke`: encapsulated key (65) || ciphertext (32) + tag (16).
    static let wrappedLength = encapsulatedKeyLength + 32 + 16

    static func accessControl() throws -> SecAccessControl {
        var err: Unmanaged<CFError>?
        guard let ac = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet], &err)
        else { throw err!.takeRetainedValue() as Error }
        return ac
    }

    /// Creates the identity key and the KEK, without any prompt (a context
    /// that forbids interaction).
    static func makeKeys() throws -> (identity: SecureEnclave.P256.Signing.PrivateKey,
                                      kek: SecureEnclave.P256.KeyAgreement.PrivateKey) {
        let ctx = LAContext()
        ctx.interactionNotAllowed = true
        let ac = try accessControl()
        let identity = try SecureEnclave.P256.Signing.PrivateKey(
            compactRepresentable: false, accessControl: ac, authenticationContext: ctx)
        let kek = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            compactRepresentable: false, accessControl: ac, authenticationContext: ctx)
        return (identity, kek)
    }

    /// Wraps the 32-byte DEK to the KEK's public key. No prompt. The result
    /// is `wrappedLength` bytes and not secret.
    static func wrap(dek: SecretBytes, to kek: P256.KeyAgreement.PublicKey) throws -> Data {
        guard dek.count == 32 else { throw CryptoKitError.incorrectParameterSize }
        var sender = try HPKE.Sender(recipientKey: kek, ciphersuite: suite, info: info)
        let ct = try dek.withBytes { try sender.seal($0) }
        return sender.encapsulatedKey + ct
    }

    /// Opens a wrapped DEK. With a Secure Enclave KEK this is the one Touch
    /// ID prompt. The result is 32 bytes of heap `Data` that the caller hands
    /// to `Brev.unlock` on the same thread and then wipes in place (§5.4).
    /// Generic over the key type, so the harness runs the same code with a
    /// software key (no Secure Enclave, no prompt).
    static func open<K: HPKEDiffieHellmanPrivateKey>(_ wrapped: Data, with key: K) throws -> Data {
        guard wrapped.count == wrappedLength else { throw CryptoKitError.incorrectParameterSize }
        let enc = wrapped.prefix(encapsulatedKeyLength)
        let ct = wrapped.suffix(from: wrapped.startIndex + encapsulatedKeyLength)
        var r = try HPKE.Recipient(privateKey: key, ciphersuite: suite, info: info, encapsulatedKey: Data(enc))
        return try r.open(ct)
    }

    /// The enrolled-fingers hash: a hint only (docs/PHASE2_DESIGN.md §5.5),
    /// compared after an Enclave failure, never a reason to delete anything
    /// by itself. Nil when Touch ID is not available.
    static func biometryStateHash() -> Data? {
        let ctx = LAContext()
        guard ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) else { return nil }
        if #available(macOS 15.0, *) {
            return ctx.domainState.biometry.stateHash
        }
        return ctx.evaluatedPolicyDomainState
    }
}
