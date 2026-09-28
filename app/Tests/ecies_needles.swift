// ecies_needles.swift — an ECIES sender that reveals its secrets.
//
// TEST CODE ONLY; never compiled into Brev. SecKeyCreateEncryptedData picks
// its own ephemeral key and hides the intermediate secrets, but the harness
// needs them as needles: after the unlock closure (Enclave.unwrap, then
// Brev.unlock, then the in-place wipe) no copy of any of them may be left in
// memory (docs/PHASE2_DESIGN.md §11 case 3, with ECIES per
// docs/DECISIONS.md D-0035). So this wraps the DEK the way
// .eciesEncryptionCofactorVariableIVX963SHA256AESGCM does (SecKey.h): ECDH
// on P-256 (cofactor 1), the ANSI X9.63 KDF with SHA-256 and the ephemeral
// public key as shared info, 32 bytes of output split into an AES-128 key
// and a 16-byte GCM IV, no AAD, a 16-byte tag. It is built from CryptoKit's
// own P-256, X9.63 KDF and AES-GCM, and `NeedleFile.make` proves the result
// opens with Security's SecKeyCreateDecryptedData (through Enclave.unwrap).
// The helper also derives the echo peers' DEKs, which `Brev.unlock` derives
// from the DEK, as needles: after the lock no copy of them may be left on
// the unlock thread's stack either. The needles are made in a helper
// process; the measuring process only ever reads their XORed form.

import CryptoKit
import Foundation
import Security

/// The secrets of one ECIES wrap.
struct ECIESWrap {
    let wrapped: Data        // ephemeral public key || ciphertext || tag, the shape of the keychain item
    let sharedSecret: Data   // the ECDH output, 32 bytes
    let key: Data            // the AES-128 key, 16 bytes
    let iv: Data             // the GCM IV, 16 bytes
}

enum X963ECIES {
    /// One wrap of `plaintext` to `pkR` with the ephemeral key `skE`.
    static func wrap(_ plaintext: Data, to pkR: P256.KeyAgreement.PublicKey,
                     ephemeral skE: P256.KeyAgreement.PrivateKey) throws -> ECIESWrap {
        let epk = skE.publicKey.x963Representation
        let shared = try skE.sharedSecretFromKeyAgreement(with: pkR)
        let z = shared.withUnsafeBytes { Data($0) }
        let kdf = shared.x963DerivedSymmetricKey(using: SHA256.self, sharedInfo: epk, outputByteCount: 32)
            .withUnsafeBytes { Data($0) }
        let key = Data(kdf.prefix(16)), iv = Data(kdf.suffix(16))
        let box = try AES.GCM.seal(plaintext, using: SymmetricKey(data: key), nonce: AES.GCM.Nonce(data: iv))
        return ECIESWrap(wrapped: epk + box.ciphertext + box.tag, sharedSecret: z, key: key, iv: iv)
    }
}

/// A software P-256 private key as a SecKey, from its X9.63 form
/// (04 || X || Y || D, 97 bytes): the harness's stand-in for the KEK.
func softwareKEK(_ x963: Data) throws -> SecKey {
    let attrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                                kSecAttrKeyClass as String: kSecAttrKeyClassPrivate]
    var err: Unmanaged<CFError>?
    guard let key = SecKeyCreateWithData(x963 as CFData, attrs as CFDictionary, &err)
    else { throw err.map { $0.takeRetainedValue() as Error } ?? Enclave.Failure.unknown }
    return key
}

/// The echo peers' DEKs as brev-core derives them from the user's DEK
/// (echo.rs `peer_dek`): HKDF-SHA256 with no salt, info
/// "brev/v0/demo-peer/" || index, 32 bytes.
func peerDEK(_ dek: Data, index: UInt8) -> Data {
    HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: dek),
                           info: Data("brev/v0/demo-peer/".utf8) + [index], outputByteCount: 32)
        .withUnsafeBytes { Data($0) }
}

/// The helper run's file: the KEK's private key (97, X9.63) || the wrapped
/// DEK (113), then XOR 0x5A of the DEK (32), the ECDH output (32), the AES
/// key (16), the IV (16) and the two peer DEKs (32 each).
enum NeedleFile {
    static let names = ["dek", "ecdh", "aes_key", "iv", "peer_dek_1", "peer_dek_2"]
    static let lengths = [32, 32, 16, 16, 32, 32]
    /// The needles that brev-core itself holds while unlocked (one copy
    /// each): the DEK and the peer DEKs.
    static let heldWhileUnlocked: Set<Int> = [0, 4, 5]
    static let keyLength = 97
    static let size = keyLength + Enclave.wrappedLength + lengths.reduce(0, +)

    /// The helper: a random DEK wrapped to a new software KEK. Fails unless
    /// Security's decrypt opens the result to the same DEK.
    static func make(at url: URL) throws {
        let kek = P256.KeyAgreement.PrivateKey()
        var dek = Data(count: 32)
        guard dek.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }) == errSecSuccess
        else { throw CryptoKitError.incorrectParameterSize }
        let w = try X963ECIES.wrap(dek, to: kek.publicKey, ephemeral: P256.KeyAgreement.PrivateKey())
        let opened = try Enclave.unwrap(w.wrapped, with: try softwareKEK(kek.x963Representation)) { Data($0) }
        guard opened == dek else { throw CryptoKitError.authenticationFailure }
        var out = kek.x963Representation + w.wrapped
        for secret in [dek, w.sharedSecret, w.key, w.iv, peerDEK(dek, index: 0), peerDEK(dek, index: 1)] {
            out += Data(secret.map { $0 ^ 0x5A })
        }
        precondition(out.count == size)
        try out.write(to: url)
    }
}
