// UnlockService.swift — onboarding's key creation and every unlock.
//
// Upholds CLAUDE.md §1.8 (Touch ID only: no password button), §1.10 (the
// DEK is wiped at once) and §3.3 as changed by docs/DECISIONS.md D-0035
// (docs/PHASE2_DESIGN.md §4.3, §5.3, §5.4). Both run on one serial queue,
// `no.brev.unlock`, and results return to main. An unlock is one closure on
// that queue: find the KEK with an LAContext that has no fallback button,
// unwrap the DEK in the Secure Enclave (the one Touch ID prompt), hand it
// to `Brev.unlock` on the same thread without a copy, and zero it in place
// when that returns. Any error locks the session again. Brev never calls
// this on its own: only a human click on the lock screen or onboarding's
// first-unlock page starts it. The store is made and opened with the relay
// URL from Info.plist (`relayURL`).

import Foundation
import LocalAuthentication
import os
import Security

final class UnlockService {
    private static let log = Logger(subsystem: "no.brev.app", category: "keys")

    private let queue = DispatchQueue(label: "no.brev.unlock")
    private let keyStore: KeyStore
    /// Main thread: whether the last unlock unwrapped the DEK with a Secure
    /// Enclave KEK, whose access control needs Touch ID (.biometryCurrentSet).
    /// Set right before that unlock's completion runs, false after a failed
    /// one; LockController keeps it for the unlock's generation, for the
    /// environment report (docs/VAULT_SPLIT_PLAN.md §8).
    private(set) var unlockedWithTouchID = false

    init(keyStore: KeyStore) {
        self.keyStore = keyStore
    }

    /// The relay, from Info.plist `BrevRelayURL` (the build setting
    /// BREV_RELAY_URL, default http://127.0.0.1:8787; docs/PHASE3_DESIGN.md
    /// §5.1). Rust refuses anything but `http://127.0.0.1:<port>`, so a
    /// missing key fails the store's create and open instead of falling back.
    static var relayURL: String {
        Bundle.main.object(forInfoDictionaryKey: "BrevRelayURL") as? String ?? ""
    }

    // MARK: - Onboarding (§5.3 steps 3 to 6)

    /// Deletes the known names, creates both Secure Enclave keys, saves the
    /// fingers hint, makes a fresh DEK, wraps it to the KEK and creates the
    /// store under it. The DEK is wiped before this returns. On
    /// success, main gets the session (locked) and the wrapped DEK, which is
    /// not secret and is stored in the keychain only after the first unlock.
    func create(_ completion: @escaping (Result<(session: Session, wrapped: Data), Error>) -> Void) {
        let keyStore = keyStore
        queue.async {
            let result = Result { try Self.create(in: keyStore) }
            DispatchQueue.main.async { completion(result) }
        }
    }

    private static func create(in keyStore: KeyStore) throws -> (session: Session, wrapped: Data) {
        try keyStore.deleteKnownNames()
        let keys = try keyStore.makeKeys()
        saveFingersHint(keyStore)
        let dek = SecretBytes(capacity: 64)
        defer { dek.wipe() }
        guard SecRandomCopyBytes(kSecRandomDefault, 32, dek.base) == errSecSuccess else { throw BrevError.Rng }
        dek.setCount(32)
        let wrapped = try Enclave.wrap(dek: dek, to: keys.kekPublic)
        let signingKey = try Enclave.publicKeyBytes(of: keys.identityPublic)
        let session = try Session.create(dir: keyStore.dir.path, relay: relayURL, dek: dek, signingKey: signingKey)
        return (session, wrapped)
    }

    // MARK: - Unlock (§5.4)

    /// One Touch ID prompt, then `session` is unlocked, or it is locked and
    /// main gets the failure to show. `install`: during onboarding, the
    /// wrapped DEK from `create`; it is used instead of the keychain item,
    /// and stored as that item once the unlock succeeded (§5.3 step 8).
    func unlock(_ session: Session, install: Data?, _ completion: @escaping (Result<Void, UnlockFailure>) -> Void) {
        let keyStore = keyStore
        queue.async {
            let result: Result<Void, UnlockFailure>
            var touchID = false
            do {
                touchID = try Self.unlock(session, install: install, keyStore: keyStore)
                Self.saveFingersHint(keyStore)
                result = .success(())
            } catch {
                session.brev.lock()
                let changed = !(error is CoreUnlockError) && Self.fingersChanged(keyStore)
                let failure = UnlockFailure.classify(error, fingersChanged: changed)
                let codes = UnlockFailure.chain(error).map { "\($0.domain) \($0.code)" }.joined(separator: ", ")
                Self.log.notice("unlock failed class=\(failure.rawValue, privacy: .public) errors=[\(codes, privacy: .public)]")
                result = .failure(failure)
            }
            DispatchQueue.main.async { [weak self] in
                self?.unlockedWithTouchID = touchID
                completion(result)
            }
        }
    }

    /// The closure of §5.4, on the unlock queue. The KEK lookup does not
    /// prompt; the unwrap does, with `ctx`'s texts and no password button.
    /// Returns whether the KEK is in the Secure Enclave, so the unwrap
    /// needed Touch ID.
    private static func unlock(_ session: Session, install: Data?, keyStore: KeyStore) throws -> Bool {
        let ctx = LAContext()
        ctx.localizedFallbackTitle = ""
        ctx.localizedCancelTitle = L10n.unlockCancel
        ctx.localizedReason = L10n.unlockReason
        let wrapped = try install ?? keyStore.readWrapped()
        let kek = try keyStore.kek(context: ctx)
        try Enclave.unwrap(wrapped, with: kek) { dek in
            do { try session.brev.unlock(dek: dek, idleSecs: LockState.rustIdleSecs) } catch {
                throw CoreUnlockError(underlying: error)
            }
        }
        if let install {
            try keyStore.storeWrapped(install)
            log.notice("installed")
        }
        return Enclave.isInSecureEnclave(kek)
    }

    // MARK: - The fingers hint (biometry.state)

    /// Saves the current enrolled-fingers hash: at onboarding and after
    /// every successful unlock, so a hash change between OS versions is
    /// picked up while the keys still work. A hint only, so a failure is
    /// logged and ignored.
    private static func saveFingersHint(_ keyStore: KeyStore) {
        guard let hash = Enclave.biometryStateHash() else { return }
        do { try keyStore.writeBiometryState(hash) } catch { log.error("biometry.state not written") }
    }

    /// Whether the saved hash exists and differs from the current one.
    private static func fingersChanged(_ keyStore: KeyStore) -> Bool {
        guard let saved = keyStore.readBiometryState(), let now = Enclave.biometryStateHash() else { return false }
        return saved != now
    }
}
