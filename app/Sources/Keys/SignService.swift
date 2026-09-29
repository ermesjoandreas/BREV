// SignService.swift — the identity key's signatures: one Touch ID prompt.
//
// Upholds CLAUDE.md §1.8 (Touch ID only: no password button) and §3.3
// (docs/PHASE3_DESIGN.md §3.1, §3.2 step 2, §3.5; docs/AUTHORSHIP.md §3.2,
// D-0109). Rust hands out the SHA-256 digest of what it signs. Each call
// makes one fresh LAContext, with no fallback button and the caller's
// reason, and looks the identity key up with it, which does not prompt; the
// first signature with that key is the one Touch ID prompt. A registration
// (`sign`) has one signature. A letter (`signLetter`) has two under the same
// prompt: the authorship token's digest, then, once Rust has sealed the
// letter with the token (`attachToken`, on main), the envelope's digest,
// signed through the same context without a second prompt.
//
// The context and the key reference exist only inside one run on the serial
// queue `no.brev.sign`. The key is a local of that run and is released when
// it returns; `defer` invalidates the context on every way out: after the
// last signature, on a cancelled prompt, on any error. While a run is in
// flight its context is also in `inFlight`, which `cancel()` (the lock
// sequence) invalidates, so a lock ends a prompt that is up and no
// signature is made after it; `defer` clears it. No authenticated key
// reference or context outlives the send. The result returns to main, where
// the caller hands it to Rust, which checks it against the own identity
// key; Swift never verifies. Brev never calls this on its own: only a
// human's Send or Registrer starts it. Neither the digests nor the
// signatures are secret. The harness, the lock probe and the view host sign
// with a software key through the same Enclave.sign, without this lookup.

import Foundation
import LocalAuthentication

final class SignService {
    private let queue = DispatchQueue(label: "no.brev.sign")
    private let keyStore: KeyStore
    /// The context of the run in flight, for `cancel()`; nil between runs.
    private var inFlight: LAContext?
    private let inFlightLock = NSLock()

    init(keyStore: KeyStore) {
        self.keyStore = keyStore
    }

    /// Signs `digest` (32 bytes) with the identity key: a registration's
    /// one signature. `reason` completes macOS's sentence «Brev» prøver å …
    /// in the Touch ID dialog.
    func sign(digest: Data, reason: String, _ completion: @escaping (Result<Data, Error>) -> Void) {
        run(reason: reason, completion) { key in try Enclave.sign(digest: digest, key: key) }
    }

    /// A letter's two signatures under one prompt (docs/AUTHORSHIP.md
    /// §3.2): `tokenDigest`, which prompts; then `attachToken` on main with
    /// that signature, which gives the envelope's digest; then that digest,
    /// through the same context. `attachToken` throws to stop before the
    /// second signature. The completion gets the envelope's DER signature.
    func signLetter(tokenDigest: Data, reason: String, attachToken: @escaping (Data) throws -> Data,
                    _ completion: @escaping (Result<Data, Error>) -> Void) {
        run(reason: reason, completion) { key in
            let tokenSignature = try Enclave.sign(digest: tokenDigest, key: key)
            let envelopeDigest = try DispatchQueue.main.sync { try attachToken(tokenSignature) }
            return try Enclave.sign(digest: envelopeDigest, key: key)
        }
    }

    /// The lock sequence: the context in flight, if any, is invalidated,
    /// which ends its prompt and fails every signature after it. Main.
    func cancel() {
        inFlightLock.lock()
        let ctx = inFlight
        inFlightLock.unlock()
        ctx?.invalidate()
    }

    /// One run on the sign queue: a fresh context, the key looked up with
    /// it, `body` with the key, the result to main. The key is released
    /// when `signWith` returns, and the context invalidated by `defer`,
    /// whatever happened.
    private func run(reason: String, _ completion: @escaping (Result<Data, Error>) -> Void,
                     _ body: @escaping (SecKey) throws -> Data) {
        let keyStore = keyStore
        queue.async { [self] in
            let ctx = LAContext()
            ctx.localizedFallbackTitle = ""
            ctx.localizedCancelTitle = L10n.unlockCancel
            ctx.localizedReason = reason
            setInFlight(ctx)
            defer {
                setInFlight(nil)
                ctx.invalidate()
            }
            let result = Result { try Self.signWith(ctx, keyStore, body) }
            DispatchQueue.main.async { completion(result) }
        }
    }

    /// The identity key, looked up with `ctx` (no prompt), lives only in
    /// this call.
    private static func signWith(_ ctx: LAContext, _ keyStore: KeyStore,
                                 _ body: (SecKey) throws -> Data) throws -> Data {
        let key = try keyStore.identityKey(context: ctx)
        return try body(key)
    }

    private func setInFlight(_ ctx: LAContext?) {
        inFlightLock.lock()
        inFlight = ctx
        inFlightLock.unlock()
    }
}
