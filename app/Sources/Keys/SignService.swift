// SignService.swift — the identity key's signature: one Touch ID prompt.
//
// Upholds CLAUDE.md §1.8 (Touch ID only: no password button) and §3.3
// (docs/PHASE3_DESIGN.md §3.1, §3.2 step 2, §3.5). Rust hands out the
// SHA-256 digest of what it signs (`signRequest` for a letter,
// `registerRequest` for a registration). This looks the identity key up
// with an LAContext that has no fallback button and the caller's reason,
// which does not prompt, and signs the digest with Enclave.sign, which is
// the one Touch ID prompt. It runs on its own serial queue, `no.brev.sign`,
// and the DER signature or the error returns to main, where the caller
// hands it to Rust, which checks it against the own identity key. Swift
// never verifies. Brev never calls this on its own: only a human's Send (or,
// from WP5, Registrer) starts it. Neither the digest nor the signature is
// secret. The harness and the view host sign with a software key through the
// same Enclave.sign, without this lookup.

import Foundation
import LocalAuthentication

final class SignService {
    private let queue = DispatchQueue(label: "no.brev.sign")
    private let keyStore: KeyStore

    init(keyStore: KeyStore) {
        self.keyStore = keyStore
    }

    /// Signs `digest` (32 bytes) with the identity key. `reason` completes
    /// macOS's sentence «Brev» prøver å … in the Touch ID dialog.
    func sign(digest: Data, reason: String, _ completion: @escaping (Result<Data, Error>) -> Void) {
        let keyStore = keyStore
        queue.async {
            let result = Result { () throws -> Data in
                let ctx = LAContext()
                ctx.localizedFallbackTitle = ""
                ctx.localizedCancelTitle = L10n.unlockCancel
                ctx.localizedReason = reason
                return try Enclave.sign(digest: digest, key: try keyStore.identityKey(context: ctx))
            }
            DispatchQueue.main.async { completion(result) }
        }
    }
}
