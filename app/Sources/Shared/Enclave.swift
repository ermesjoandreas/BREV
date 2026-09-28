// Enclave.swift — the operations on Secure Enclave SecKeys: the KEK's wrap
// and unwrap, and the identity key's signature (`sign(digest:key:)`,
// docs/PHASE3_DESIGN.md §3.1; Swift only signs, Rust verifies).
//
// Upholds CLAUDE.md §1.8, §1.9, §1.10 and §3.3 (docs/DECISIONS.md D-0035):
// both keys are permanent Secure Enclave SecKeys in the data protection
// keychain, ThisDeviceOnly and bound to the current fingerprints
// (.biometryCurrentSet); KeyStore (Keys/) creates and finds them. The DEK is
// wrapped to the KEK's public key with ECIES
// (.eciesEncryptionCofactorVariableIVX963SHA256AESGCM), which needs no
// prompt, and unwrapped with SecKeyCreateDecryptedData, which is the one
// Touch ID prompt, through the LAContext the key was looked up with
// (UnlockService). The unwrapped DEK exists only as the CFData Security
// returns: the caller sees it as a no-copy Data inside a closure, and the
// CFData is zeroed in place when the closure returns, on every path. No
// AppKit and no keychain: compiled into the app and the CLI harness, which
// runs `wrap`, `unwrap` and `sign` with software keys.

import Foundation
import LocalAuthentication
import Security

enum Enclave {
    static let algorithm = SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM
    /// A P-256 public key in X9.63 form: 04 || X || Y.
    static let publicKeyLength = 65
    /// The wrapped DEK: ephemeral public key (65) || ciphertext (32) + tag (16).
    static let wrappedLength = publicKeyLength + 32 + 16

    enum Failure: Error {
        /// A wrapped DEK, an unwrapped DEK or a public key of the wrong length.
        case malformed
        /// Security failed without saying why.
        case unknown
    }

    /// Touch ID only, the current fingers only, this Mac only, and only
    /// while a login password is set (§1.8, §1.9).
    static func accessControl() throws -> SecAccessControl {
        var err: Unmanaged<CFError>?
        guard let ac = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet], &err)
        else { throw err.map { $0.takeRetainedValue() as Error } ?? Failure.unknown }
        return ac
    }

    /// A P-256 public key in X9.63 form (65 bytes). For the identity key
    /// this is what `Brev.create` stores as the user's signing key.
    static func publicKeyBytes(of publicKey: SecKey) throws -> Data {
        var err: Unmanaged<CFError>?
        guard let raw = SecKeyCopyExternalRepresentation(publicKey, &err) as Data?
        else { throw err.map { $0.takeRetainedValue() as Error } ?? Failure.unknown }
        guard raw.count == publicKeyLength else { throw Failure.malformed }
        return raw
    }

    /// Wraps the 32-byte DEK to `publicKey`. No prompt. The result is
    /// `wrappedLength` bytes and not secret. Security reads the DEK through
    /// a no-copy view of its SecretBytes.
    static func wrap(dek: SecretBytes, to publicKey: SecKey) throws -> Data {
        guard dek.count == 32 else { throw Failure.malformed }
        var err: Unmanaged<CFError>?
        // 32 bytes: a no-copy Data of 14 bytes or less would be copied inline.
        let plain = Data(bytesNoCopy: dek.base, count: 32, deallocator: .none)
        let wrapped = withExtendedLifetime(dek) {
            SecKeyCreateEncryptedData(publicKey, algorithm, plain as CFData, &err) as Data?
        }
        guard let wrapped else { throw err.map { $0.takeRetainedValue() as Error } ?? Failure.unknown }
        guard wrapped.count == wrappedLength else { throw Failure.malformed }
        return wrapped
    }

    /// Unwraps `wrapped` with `key` and runs `body` with the DEK: 32 bytes,
    /// a no-copy Data over the CFData Security returned, which must not
    /// escape `body`. The CFData is zeroed in place when this returns, on
    /// every path. With a Secure Enclave KEK this is the one Touch ID prompt.
    /// UnlockService calls `Brev.unlock` in `body`, on the same thread, so
    /// Rust's stack scrub covers the frames this call used (design §2.5).
    /// `decrypt` is always SecKeyCreateDecryptedData; only the harness
    /// passes a wrapper around it, which keeps the CFData so that cases 1
    /// and 3 can check it is the one `body` saw and all zero afterwards.
    static func unwrap<R>(_ wrapped: Data, with key: SecKey,
                          decrypt: (SecKey, SecKeyAlgorithm, CFData, UnsafeMutablePointer<Unmanaged<CFError>?>?)
                              -> CFData? = SecKeyCreateDecryptedData,
                          _ body: (Data) throws -> R) throws -> R {
        guard wrapped.count == wrappedLength else { throw Failure.malformed }
        var err: Unmanaged<CFError>?
        guard let plain = decrypt(key, algorithm, wrapped as CFData, &err)
        else { throw err.map { $0.takeRetainedValue() as Error } ?? Failure.unknown }
        return try withWiped(plain) { dek in
            guard dek.count == 32 else { throw Failure.malformed }
            return try body(dek)
        }
    }

    /// Runs `body` with a no-copy Data over `data`'s bytes, then zeroes those
    /// bytes in place with `memset_s`, on every path. `data` is a CFData that
    /// only this caller holds (Security's decrypt result), so its bytes are
    /// the only copy. The Data must not escape `body`.
    static func withWiped<R>(_ data: CFData, _ body: (Data) throws -> R) rethrows -> R {
        let n = CFDataGetLength(data)
        guard n > 0, let p = CFDataGetBytePtr(data) else { return try body(Data()) }
        let bytes = UnsafeMutableRawPointer(mutating: p)
        defer { _ = memset_s(bytes, n, 0, n) }
        // More than 14 bytes, so Foundation keeps the view out of line: the
        // view is these bytes, not a copy (SecretBytes.capacity).
        let view = Data(bytesNoCopy: bytes, count: n, deallocator: .none)
        return try withExtendedLifetime(data) { try body(view) }
    }

    /// Signs a 32-byte SHA-256 digest with `key` and returns the DER
    /// signature (docs/PHASE3_DESIGN.md §3.1): the signature
    /// `.ecdsaSignatureMessageX962SHA256` gives over the bytes the digest was
    /// made from, which Rust computed and checks. With the Secure Enclave
    /// identity key, looked up with an LAContext (SignService), this is the
    /// one Touch ID prompt of a letter or a registration; the harness passes
    /// a software key. Neither the digest nor the signature is secret.
    static func sign(digest: Data, key: SecKey) throws -> Data {
        guard digest.count == 32 else { throw Failure.malformed }
        var err: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(key, .ecdsaSignatureDigestX962SHA256, digest as CFData, &err) as Data?
        else { throw err.map { $0.takeRetainedValue() as Error } ?? Failure.unknown }
        return signature
    }

    /// Whether `key` says it lives in the Secure Enclave: its own
    /// kSecAttrTokenID (docs/VAULT_SPLIT_PLAN.md §8). A software key has
    /// none. No prompt: reading a key's attributes does not use it.
    static func isInSecureEnclave(_ key: SecKey) -> Bool {
        let attributes = SecKeyCopyAttributes(key) as? [String: Any]
        return attributes?[kSecAttrTokenID as String] as? String == kSecAttrTokenIDSecureEnclave as String
    }

    /// Whether Touch ID is set up and usable. No prompt.
    static func touchIDAvailable() -> Bool {
        LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
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
