// Session.swift — the app's side of the Rust session.
//
// Upholds CLAUDE.md §1.10, §3.1 and §6 (docs/PHASE2_DESIGN.md §4.2, §6.2;
// docs/PHASE3_DESIGN.md §3.2, §5.2, §6.4; docs/PHASE4_DESIGN.md §5.4, §7.1):
// Session is the only owner of the Rust `Brev` handle. Every address,
// subject and body comes out as a SecretText that the view holding it
// wipes, and every identity code as a SecretBytes; each
// OpenText is read completely and closed at once, so Rust holds no content
// between calls. Content and typed addresses go to Rust only
// as a no-copy view of a SecretBytes, which is wiped right after the call.
// The calls that go to the relay (`register`, `addContact`, `prepareSend`,
// `submit`, `sync`, and Phase 4's `answerRequest`, `blockContact`) run on
// `Session.net`,
// never on the main thread, and take no content; the calls that take
// content (`signRequest`, `registerRequest`) do no I/O. A registration
// carries the attestor's attestation of its digest (NoAttestor: empty until
// App Attest). Hand (docs/AUTHORSHIP.md §3; D-0110, D-0111): the app hands
// Rust raw samples of the Mac (HandSampler) and the compose events, never a
// count or a class, and a letter's token and envelope are signed under one
// Touch ID. No AppKit: compiled into the app and the CLI harness.

import Foundation

/// A contact, with its name (its address) read out of Rust.
struct ContactItem {
    let id: Data
    let name: SecretText
    /// The relay returned another key: nothing is sent to this contact
    /// until the new key is accepted (docs/PHASE3_DESIGN.md §6.3).
    let keyChanged: Bool
    /// The contact has not approved the user yet: «Venter på svar»
    /// (docs/PHASE4_DESIGN.md §5.2).
    let waiting: Bool
    /// The user blocked the contact (*Blokker*).
    let blocked: Bool
}

/// A thread, with its subject read out of Rust.
struct ThreadItem {
    let id: Data
    let contact: Data
    let createdAt: Int64
    let subject: SecretText
}

/// The user's registration, own address and identity code. The holder
/// wipes the address and the code.
struct MeItem {
    let registered: Bool
    /// Empty until registered.
    let address: SecretText
    /// 35 ASCII bytes.
    let code: SecretBytes
}

/// One contact's address and identity codes. The holder wipes all three.
struct ContactDetails {
    let address: SecretText
    /// The pinned key's code: 35 ASCII bytes.
    let code: SecretBytes
    /// The code of the changed key waiting for acceptance: 35 bytes, or
    /// count 0 when there is none.
    let newCode: SecretBytes
    /// As ContactItem's.
    let waiting: Bool
    let blocked: Bool
}

/// A contact request from an address that is not a contact; it carries no
/// text (docs/PHASE4_DESIGN.md §5.2). The holder wipes the address and the
/// code.
struct RequestItem {
    /// The asker's identity id, 32 bytes: what `answerRequest` takes.
    let peer: Data
    let address: SecretText
    /// The asker's identity code: 35 ASCII bytes.
    let code: SecretBytes
}

final class Session {
    /// The serial queue of every call that goes to the relay
    /// (docs/PHASE3_DESIGN.md §3.2, §5.3). Results go back to main.
    static let net = DispatchQueue(label: "no.brev.net")

    let brev: Brev
    /// Attests a registration's digest (docs/PHASE4_DESIGN.md §7.1).
    private let attestor: Attestor

    init(brev: Brev, attestor: Attestor = NoAttestor()) {
        self.brev = brev
        self.attestor = attestor
    }

    /// Onboarding (§5.3 step 6): creates the store in `dir` under `dek` (32
    /// bytes), which is wiped here on every path, and returns the session
    /// locked. `relay` is `http://127.0.0.1:<port>`; `signingKey` is the
    /// identity key's public key (65 bytes, X9.63).
    static func create(dir: String, relay: String, dek: SecretBytes, signingKey: Data) throws -> Session {
        defer { dek.wipe() }
        // Exactly 32 bytes: a no-copy Data of 14 bytes or less would be
        // copied inline (SecretBytes.capacity).
        guard dek.count == 32 else { throw BrevError.Malformed }   // as Rust's `create`
        let brev = try withExtendedLifetime(dek) {
            try Brev.create(dir: dir, relay: relay, dek: Data(bytesNoCopy: dek.base, count: 32, deallocator: .none),
                            signingKey: signingKey)
        }
        return Session(brev: brev)
    }

    /// Opens the store in `dir`, locked.
    static func open(dir: String, relay: String) throws -> Session {
        Session(brev: try Brev.open(dir: dir, relay: relay))
    }

    // MARK: - Reading

    func contacts() throws -> [ContactItem] {
        let rows = try brev.contacts()
        let names = try Self.readAll(rows.map { $0.name })
        return zip(rows, names).map {
            ContactItem(id: $0.id, name: $1, keyChanged: $0.keyChanged, waiting: $0.waiting,
                        blocked: $0.blocked)
        }
    }

    func threads(contact: Data) throws -> [ThreadItem] {
        let rows = try brev.threads(contact: contact)
        let subjects = try Self.readAll(rows.map { $0.subject })
        return zip(rows, subjects).map {
            ThreadItem(id: $0.id, contact: $0.contact, createdAt: $0.createdAt, subject: $1)
        }
    }

    /// The letters in `thread` (metadata only), oldest first.
    func messages(thread: Data) throws -> [MessageRow] {
        try brev.messages(thread: thread)
    }

    /// One letter's body.
    func body(message: Data) throws -> SecretText {
        try TextReader.read(try brev.openBody(message: message))
    }

    /// The user's registration, address and code.
    func me() throws -> MeItem {
        var info = try brev.me()
        defer { info.code.wipe() }
        let address = try TextReader.read(info.address)
        return MeItem(registered: info.registered, address: address, code: Self.secret(info.code))
    }

    /// One contact's address and codes.
    func contactInfo(contact: Data) throws -> ContactDetails {
        var info = try brev.contactInfo(contact: contact)
        defer {
            info.code.wipe()
            info.newCode.wipe()
        }
        let address = try TextReader.read(info.address)
        return ContactDetails(address: address, code: Self.secret(info.code), newCode: Self.secret(info.newCode),
                              waiting: info.waiting, blocked: info.blocked)
    }

    // MARK: - Registration (no content; the address is typed like content)

    /// Starts registering the typed `address` (registration is open: no
    /// invite; D-0116); returns the digest the identity key signs. No I/O.
    /// The UTF-8 copy is wiped when this returns; the caller wipes
    /// `address`.
    func registerRequest(address: SecretText) throws -> Data {
        try Self.withUTF8(address) { a, al in try brev.registerRequest(address: a, addressLen: al) }
    }

    /// Finishes the registration with the DER signature over `digest` (the
    /// one `registerRequest` returned) and the attestor's attestation of
    /// the same digest (network: `Session.net`).
    func register(signature: Data, digest: Data) throws {
        let attestation = Data(attestor.attestation(for: [UInt8](digest)))
        try brev.register(signature: signature, attestation: attestation)
    }

    /// Adds the contact with the typed `address` and returns its local id
    /// (network: `Session.net`). Rust copies the address before the lookup;
    /// the UTF-8 copy here is wiped when this returns.
    func addContact(address: SecretText) throws -> Data {
        try Self.withUTF8(address) { a, al in try brev.addContact(address: a, addressLen: al) }
    }

    // MARK: - Requests and Blokker (docs/PHASE4_DESIGN.md §5.3)

    /// The contact requests the last `sync` fetched, oldest first. No I/O.
    func requests() throws -> [RequestItem] {
        var rows = try brev.requests()
        defer { for i in rows.indices { rows[i].code.wipe() } }
        let addresses = try Self.readAll(rows.map { $0.address })
        return rows.indices.map {
            RequestItem(peer: rows[$0].peer, address: addresses[$0], code: Self.secret(rows[$0].code))
        }
    }

    /// Answers the request of `peer` (a RequestItem's) with one click, no
    /// Touch ID: `approve` pins the asker and returns its local id; a
    /// decline returns an empty id (network: `Session.net`).
    func answerRequest(peer: Data, approve: Bool) throws -> Data {
        try brev.answerRequest(peer: peer, approve: approve)
    }

    /// *Blokker*: nothing is sent to `contact` and its letters are dropped
    /// from now on; the relay is told to store no more from it (network:
    /// `Session.net`). `Network`: the local block holds, and calling this
    /// again tells the relay.
    func blockContact(contact: Data) throws {
        try brev.blockContact(contact: contact)
    }

    /// Accepts the contact's changed key; `newCode` is the code shown.
    func acceptNewKey(contact: Data, newCode: SecretBytes) throws {
        var code = newCode.withBytes { Data($0) }
        defer { code.wipe() }
        try brev.acceptNewKey(contact: contact, newCode: code)
    }

    // MARK: - Hand (docs/AUTHORSHIP.md §3.1, §4.3)

    /// A sample of the Mac while unlocked (LockController, every 2 s). A
    /// running `sudo` or `su`, or SIP off, locks everything in Rust at once,
    /// and the causes come back; otherwise the list is empty and an open
    /// compose session counts the sample. Flags, SIP bits, process names
    /// and window owners only, no content.
    func observe(_ sample: Sample) throws -> [LockCause] {
        try brev.observe(sample: sample)
    }

    /// The compose sheet opened: Rust starts the letter's fact log with how
    /// Brev is built (`design`), whether the user is an admin (read once;
    /// nil if the read failed) and where the identity key lives.
    func composeStarted(design: Design, admin: Bool?, keyOrigin: KeyOrigin) throws {
        try brev.composeStarted(design: design, admin: admin, keyOrigin: keyOrigin)
    }

    /// The compose sheet closed: Rust drops the fact log.
    func composeClosed() throws {
        try brev.composeClosed()
    }

    /// BrevApplication dropped a synthetic input event: counted in an open
    /// compose session.
    func syntheticDropped() throws {
        try brev.syntheticDropped()
    }

    /// What a received letter's authorship token showed, as Rust stored it
    /// (docs/AUTHORSHIP.md §6); nil for a letter the user sent. No content.
    func letterProof(message: Data) throws -> Proof? {
        try brev.letterProof(message: message)
    }

    // MARK: - A letter (docs/PHASE3_DESIGN.md §3.2; docs/AUTHORSHIP.md §3)

    /// Step 0, without content: with a sample taken on main just before,
    /// checks the compose session's class (an early exit), then the
    /// contact's key at the relay, and takes the send ticket (network:
    /// `Session.net`).
    func prepareSend(contact: Data, sample: Sample) throws {
        try brev.prepareSend(contact: contact, sample: sample)
    }

    /// Step 1, on main: with a sample taken just now, freezes the letter's
    /// facts, and returns the digest of its authorship token, which the
    /// identity key signs. Rust keeps the letter's plaintext until the
    /// token signature comes (`attachTokenSignature`) or the letter is
    /// forgotten. No I/O. The UTF-8 copies live in SecretBytes of 3 bytes
    /// per unit and are wiped when this returns. The caller wipes `subject`
    /// and `body`.
    func signRequest(contact: Data, subject: SecretText, body: SecretText, sample: Sample) throws -> Data {
        try Self.withUTF8(subject) { sd, sl in
            try Self.withUTF8(body) { bd, bl in
                try brev.signRequest(contact: contact, subject: sd, subjectLen: sl, body: bd, bodyLen: bl,
                                     sample: sample)
            }
        }
    }

    /// Step 2: the DER signature over the token digest. Rust seals the
    /// letter with its token, wipes its plaintext, and returns the
    /// envelope's digest, which the same Touch ID signs next.
    func attachTokenSignature(_ signature: Data) throws -> Data {
        try brev.attachTokenSignature(signature: signature)
    }

    /// Step 3: the DER signature over the envelope digest.
    func attachSignature(_ signature: Data) throws {
        try brev.attachSignature(signature: signature)
    }

    /// Step 4: posts the signed letter and stores the own copy; returns the
    /// thread id (network: `Session.net`). `Network` keeps the signed letter
    /// for another `submit`.
    func submit() throws -> Data {
        try brev.submit()
    }

    /// Forgets the ticket and the letter: its plaintext while its token is
    /// signed (wiped), and the sealed letter, signed or not.
    func cancelSend() {
        brev.cancelSend()
    }

    /// Handles the events waiting at the relay (requests and approvals),
    /// then fetches, stores and acknowledges the waiting letters; returns
    /// how many arrived, whether a contact changed and how many requests
    /// wait (network: `Session.net`).
    func sync() throws -> SyncResult {
        try brev.sync()
    }

    // MARK: - Helpers

    /// `text` as UTF-8 in a SecretBytes of 3 bytes per unit, handed to
    /// `body` as the whole buffer and the used length, and wiped when this
    /// returns.
    private static func withUTF8<R>(_ text: SecretText, _ body: (Data, UInt32) throws -> R) rethrows -> R {
        let utf8 = SecretBytes(capacity: 3 * text.length)
        defer { utf8.wipe() }
        Transcode.utf16ToUTF8(text, into: utf8)
        return try utf8.withFFIView(body)
    }

    /// A copy of `data` in a new SecretBytes. The caller wipes `data`.
    private static func secret(_ data: Data) -> SecretBytes {
        let out = SecretBytes(capacity: data.count)
        data.withUnsafeBytes { _ = out.append($0) }
        return out
    }

    /// Reads every text in order. On an error it closes the ones not yet
    /// read and wipes the ones already read, so nothing stays open.
    private static func readAll(_ texts: [OpenText]) throws -> [SecretText] {
        var out: [SecretText] = []
        out.reserveCapacity(texts.count)
        do {
            for t in texts { out.append(try TextReader.read(t)) }
        } catch {
            texts.forEach { $0.close() }
            out.forEach { $0.wipe() }
            throw error
        }
        return out
    }
}
