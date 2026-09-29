// Fixture.swift — the relay, a user and fake texts, for the test tools.
//
// Compiled into tools/viewhost and tools/snapshot, never into Brev.app. It
// holds only what both need (docs/UI_REDESIGN.md §5.3, review 6): the relay
// (brev-relay on 127.0.0.1 with a port the OS picks and a database in a
// temporary folder; registration is open, D-0116), `User` (a store under a DEK
// wrapped to a software P-256 key, and a software identity key: no keychain,
// no Touch ID, no Secure Enclave) and `fake(_:)`, which builds a SecretText
// from fixed test strings and the test marker of app/Tests/scan.c (built
// from its XORed bytes, so no String copy of it exists). No window, no
// focus, no activation: scripts/test.sh fails if this file names a call
// that shows a window or takes focus.

import AppKit
import Security

// MARK: - Fake texts

/// "BREV-SECRET-BODY" XOR 0x5A, as in app/Tests/scan.c.
let markerX: [UInt8] = [0x18, 0x08, 0x1f, 0x0c, 0x77, 0x09, 0x1f, 0x19,
                        0x08, 0x1f, 0x0e, 0x77, 0x18, 0x15, 0x1e, 0x03]

/// `parts` joined into one SecretText; `nil` parts are the marker.
func fake(_ parts: [String?]) -> SecretText {
    let t = SecretText(maxUnits: 8192)
    for p in parts {
        if let p {
            let u = Array(p.utf16)
            u.withUnsafeBufferPointer { _ = t.insert($0, at: t.length) }
        } else {
            for i in 0..<16 {
                var unit = UInt16(markerX[i] ^ 0x5A)
                withUnsafePointer(to: &unit) { _ = t.insert(UnsafeBufferPointer(start: $0, count: 1), at: t.length) }
                unit = 0
            }
        }
    }
    return t
}

// MARK: - The relay and the users, as the app makes them, with software keys

/// The relay's --trace lines ("<path> <status>").
final class RelayTrace {
    private let lock = NSLock()
    private var lines: [String] = []
    private var partial = ""

    func append(_ data: Data) {
        lock.lock()
        defer { lock.unlock() }
        partial += String(decoding: data, as: UTF8.self)
        while let nl = partial.firstIndex(of: "\n") {
            lines.append(String(partial[..<nl]))
            partial = String(partial[partial.index(after: nl)...])
        }
    }

    /// How many requests to `path` the relay answered, with `status` if given.
    func count(_ path: String, _ status: Int? = nil) -> Int {
        lock.lock()
        defer { lock.unlock() }
        return lines.filter { line in status.map { line == "\(path) \($0)" } ?? line.hasPrefix(path + " ") }.count
    }
}
let relayBinary = Bundle.main.object(forInfoDictionaryKey: "BrevRelayBinary") as? String

/// This run's relay: the build script's brev-relay (Info.plist
/// BrevRelayBinary) on 127.0.0.1:0 with a database in `dir`; nil if it did
/// not start. With `trace` it traces every request into it.
func startRelay(in dir: URL, trace: RelayTrace? = nil) -> (Process, String)? {
    guard let path = relayBinary else { return nil }
    let port = dir.appendingPathComponent("relay.port")
    let relay = Process()
    relay.executableURL = URL(fileURLWithPath: path)
    relay.arguments = ["serve", "--db", dir.appendingPathComponent("relay.db").path,
                       "--listen", "127.0.0.1:0", "--port-file", port.path] + (trace != nil ? ["--trace"] : [])
    relay.standardError = FileHandle.nullDevice
    if let trace {
        let out = Pipe()
        out.fileHandleForReading.readabilityHandler = { trace.append($0.availableData) }
        relay.standardOutput = out
    }
    do { try relay.run() } catch { return nil }
    for _ in 0..<100 {
        if let text = try? String(contentsOf: port, encoding: .utf8), let n = Int(text.trimmingCharacters(in: .newlines)) {
            return (relay, "http://127.0.0.1:\(n)")
        }
        guard relay.isRunning else { return nil }
        usleep(50_000)
    }
    relay.terminate()
    return nil
}

/// A sample of a Mac with nothing wrong, for the helper users' calls (the
/// shown user's compose sheet samples this Mac, as Brev does).
let cleanSample = Sample(secureInput: true, sharingNone: true, preventsCapture: true, csrConfig: 0,
                         processes: ["launchd", ProcessInfo.processInfo.processName], windows: [])

/// One user, unlocked: a store in its own folder under a DEK wrapped to a
/// software KEK, and a software identity key that signs its digests
/// through Enclave.sign (in Brev, SignService adds the keychain lookup and
/// Touch ID).
final class User {
    let session: Session
    let identity: SecKey

    init(in dir: URL, relay: String) throws {
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        let attrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                                    kSecAttrKeySizeInBits as String: 256]
        guard let kek = SecKeyCreateRandomKey(attrs as CFDictionary, nil), let kekPublic = SecKeyCopyPublicKey(kek),
              let identity = SecKeyCreateRandomKey(attrs as CFDictionary, nil),
              let identityPublic = SecKeyCopyPublicKey(identity)
        else { throw BrevError.Crypto }
        self.identity = identity
        let dek = SecretBytes(capacity: 64)
        guard SecRandomCopyBytes(kSecRandomDefault, 32, dek.base) == errSecSuccess else { throw BrevError.Rng }
        dek.setCount(32)
        let wrapped = try Enclave.wrap(dek: dek, to: kekPublic)
        session = try Session.create(dir: dir.path, relay: relay, dek: dek,
                                     signingKey: try Enclave.publicKeyBytes(of: identityPublic))
        do {
            try Enclave.unwrap(wrapped, with: kek) {
                try session.brev.unlock(dek: $0, idleSecs: LockState.rustIdleSecs)
            }
            try session.brev.confirmActive(sample: cleanSample)
        } catch {
            session.brev.lock()
            throw error
        }
    }

    /// The address `register` registered; nil before.
    private(set) var address: String?

    /// Registers `address` (no invite, D-0116).
    func register(_ address: String) throws {
        let typed = fake([address])
        defer { typed.wipe() }
        let digest = try session.registerRequest(address: typed)
        try session.register(signature: try Enclave.sign(digest: digest, key: identity), digest: digest)
        self.address = address
    }

    /// Registers `newcomer` as `address` and makes it this user's contact
    /// the Phase 4 way: it adds this user (a request), this user's sync
    /// fetches the request and approves it, and its sync learns of the
    /// approval. This user must be registered.
    func befriend(_ newcomer: User, as address: String) throws {
        guard let mine = self.address else { throw BrevError.NotFound }
        try newcomer.register(address)
        let typed = fake([mine])
        defer { typed.wipe() }
        _ = try newcomer.session.addContact(address: typed)
        _ = try session.sync()
        let asks = try session.requests()
        defer { asks.forEach { $0.address.wipe(); $0.code.wipe() } }
        let u = Array(address.utf16)
        guard let ask = asks.first(where: { r in
            r.address.length == u.count && (0..<u.count).allSatisfy { r.address.units[$0] == u[$0] }
        }) else { throw BrevError.NotFound }
        _ = try session.answerRequest(peer: ask.peer, approve: true)
        _ = try newcomer.session.sync()
    }

    /// The local id of the contact with `address`; the names read are wiped.
    func contact(_ address: String) throws -> Data {
        let items = try session.contacts()
        defer { items.forEach { $0.name.wipe() } }
        let u = Array(address.utf16)
        let found = items.first { c in c.name.length == u.count && (0..<u.count).allSatisfy { c.name.units[$0] == u[$0] } }
        guard let found else { throw BrevError.NotFound }
        return found.id
    }

    /// Where the identity key lives: software, which the test archive
    /// (allow-software-keys) allows.
    var keyOrigin: KeyOrigin { EnvironmentProbe.origin(of: identity) }

    /// One letter in the app's steps (docs/AUTHORSHIP.md §3), all on this
    /// thread, with a clean sample; wipes the texts.
    func send(to contact: Data, subject: SecretText, body: SecretText) throws {
        defer { subject.wipe(); body.wipe() }
        // A test user is no admin; an unread fact (nil) fails the
        // requirements, which the test archive keeps but for the key.
        try session.composeStarted(design: EnvironmentProbe.design(), admin: false, keyOrigin: keyOrigin)
        try session.prepareSend(contact: contact, sample: cleanSample)
        let token = try session.signRequest(contact: contact, subject: subject, body: body, sample: cleanSample)
        let envelope = try session.attachTokenSignature(try Enclave.sign(digest: token, key: identity))
        try session.attachSignature(try Enclave.sign(digest: envelope, key: identity))
        _ = try session.submit()
        try session.composeClosed()
    }

    /// Prompts SignService would show: through `sign` and `signLetter`.
    private(set) var signatures = 0

    /// The address page's signer: the software key, answered on main as
    /// SignService answers.
    func sign(_ digest: Data, _ done: @escaping (Result<Data, Error>) -> Void) {
        signatures += 1
        let result = Result { try Enclave.sign(digest: digest, key: identity) }
        DispatchQueue.main.async { done(result) }
    }

    /// The compose sheet's signer: the software key signs the token, Rust
    /// seals the letter, the key signs the envelope; one "prompt", answered
    /// on main as SignService answers.
    func signLetter(_ tokenDigest: Data, _ attachToken: @escaping (Data) throws -> Data,
                    _ done: @escaping (Result<Data, Error>) -> Void) {
        signatures += 1
        let result = Result { () throws -> Data in
            let envelope = try attachToken(try Enclave.sign(digest: tokenDigest, key: identity))
            return try Enclave.sign(digest: envelope, key: identity)
        }
        DispatchQueue.main.async { done(result) }
    }
}
