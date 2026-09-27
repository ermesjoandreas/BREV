// hpke_needles.swift — an RFC 9180 sender that reveals its secrets.
//
// TEST CODE ONLY; never compiled into Brev. CryptoKit's HPKE.Sender hides
// the intermediate secrets, but the harness needs them as needles: after the
// unlock closure (Enclave.open, then Brev.unlock, then the wipe) no copy of
// any of them may be left in memory (docs/PHASE2_DESIGN.md §11 case 3). So
// this seals the DEK the way HPKE.Sender would, base mode,
// DHKEM(P-256, HKDF-SHA256) + HKDF-SHA256 + AES-256-GCM, from CryptoKit's
// own P-256, HKDF and AES-GCM, and `makeNeedles` proves the result opens
// with CryptoKit's HPKE.Recipient (through Enclave.open). The needles are
// made in a helper process; the measuring process only ever reads their
// XORed form.

import CryptoKit
import Foundation

/// The secrets of one HPKE seal: the DH output, the KEM shared secret, the
/// AEAD key and the base nonce (RFC 9180 §4.1, §5.1).
struct HPKESeal {
    let wrapped: Data       // enc || ciphertext || tag, the shape of dek.hpke
    let dh: Data            // 32 bytes
    let sharedSecret: Data  // 32 bytes
    let key: Data           // 32 bytes
    let baseNonce: Data     // 12 bytes
}

enum RFC9180 {
    static let kemSuite = Data("KEM".utf8) + Data([0x00, 0x10])   // DHKEM(P-256, HKDF-SHA256)
    static let hpkeSuite = Data("HPKE".utf8) + Data([0x00, 0x10, 0x00, 0x01, 0x00, 0x02])   // + HKDF-SHA256, AES-256-GCM

    static func labeledExtract(salt: Data, label: String, ikm: Data, suite: Data) -> Data {
        let labeled = Data("HPKE-v1".utf8) + suite + Data(label.utf8) + ikm
        return Data(HKDF<SHA256>.extract(inputKeyMaterial: SymmetricKey(data: labeled), salt: salt))
    }

    static func labeledExpand(prk: Data, label: String, info: Data, length: Int, suite: Data) -> Data {
        let labeled = Data([UInt8(length >> 8), UInt8(length & 0xFF)]) + Data("HPKE-v1".utf8) + suite
            + Data(label.utf8) + info
        return HKDF<SHA256>.expand(pseudoRandomKey: prk, info: labeled, outputByteCount: length)
            .withUnsafeBytes { Data($0) }
    }

    /// SetupBaseS + one Seal with empty AAD, with the ephemeral key `skE`.
    static func seal(_ plaintext: Data, to pkR: P256.KeyAgreement.PublicKey, info: Data,
                     ephemeral skE: P256.KeyAgreement.PrivateKey) throws -> HPKESeal {
        let enc = skE.publicKey.x963Representation
        let dh = try skE.sharedSecretFromKeyAgreement(with: pkR).withUnsafeBytes { Data($0) }
        let kemContext = enc + pkR.x963Representation
        let eaePRK = labeledExtract(salt: Data(), label: "eae_prk", ikm: dh, suite: kemSuite)
        let sharedSecret = labeledExpand(prk: eaePRK, label: "shared_secret", info: kemContext, length: 32,
                                         suite: kemSuite)
        let pskIDHash = labeledExtract(salt: Data(), label: "psk_id_hash", ikm: Data(), suite: hpkeSuite)
        let infoHash = labeledExtract(salt: Data(), label: "info_hash", ikm: info, suite: hpkeSuite)
        let context = Data([0x00]) + pskIDHash + infoHash   // mode_base
        let secret = labeledExtract(salt: sharedSecret, label: "secret", ikm: Data(), suite: hpkeSuite)
        let key = labeledExpand(prk: secret, label: "key", info: context, length: 32, suite: hpkeSuite)
        let baseNonce = labeledExpand(prk: secret, label: "base_nonce", info: context, length: 12, suite: hpkeSuite)
        let box = try AES.GCM.seal(plaintext, using: SymmetricKey(data: key), nonce: AES.GCM.Nonce(data: baseNonce))
        return HPKESeal(wrapped: enc + box.ciphertext + box.tag, dh: dh, sharedSecret: sharedSecret,
                        key: key, baseNonce: baseNonce)
    }
}

/// The helper run's file: KEK private key (32) || wrapped DEK (113), then
/// XOR 0x5A of the DEK (32), DH output (32), shared secret (32), AEAD key (32)
/// and base nonce (12).
enum NeedleFile {
    static let names = ["dek", "dh", "shared_secret", "aead_key", "base_nonce"]
    static let lengths = [32, 32, 32, 32, 12]
    static let size = 32 + Enclave.wrappedLength + lengths.reduce(0, +)

    /// The helper: a random DEK sealed to a new software KEK. Fails unless
    /// CryptoKit's recipient opens the result to the same DEK.
    static func make(at url: URL) throws {
        let kek = P256.KeyAgreement.PrivateKey()
        var dek = Data(count: 32)
        guard dek.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }) == errSecSuccess
        else { throw CryptoKitError.incorrectParameterSize }
        let s = try RFC9180.seal(dek, to: kek.publicKey, info: Enclave.info, ephemeral: P256.KeyAgreement.PrivateKey())
        guard try Enclave.open(s.wrapped, with: kek) == dek else { throw CryptoKitError.authenticationFailure }
        var out = kek.rawRepresentation + s.wrapped
        for secret in [dek, s.dh, s.sharedSecret, s.key, s.baseNonce] { out += Data(secret.map { $0 ^ 0x5A }) }
        precondition(out.count == size)
        try out.write(to: url)
    }
}
