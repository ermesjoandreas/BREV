// Session.swift — the app's side of the Rust session.
//
// Upholds CLAUDE.md §1.10, §3.1 and §6 (docs/PHASE2_DESIGN.md §4.2, §6.2;
// docs/PHASE3_DESIGN.md §3.2, §5.2, §6.4): Session is the only owner of the
// Rust `Brev` handle. Every address, subject and body comes out as a
// SecretText that the view holding it wipes, and every identity code as a
// SecretBytes; each OpenText is read completely and closed at once, so Rust
// holds no content between calls. Content and typed addresses go to Rust
// only as a no-copy view of a SecretBytes, which is wiped right after the
// call. The calls that go to the relay (`register`, `addContact`,
// `prepareSend`, `submit`, `sync`) run on `Session.net`, never on the main
// thread, and take no content; the calls that take content (`signRequest`,
// `registerRequest`) do no I/O. No AppKit: compiled into the app and the CLI
// harness.

import Foundation

/// A contact, with its name (its address) read out of Rust.
struct ContactItem {
    let id: Data
    let name: SecretText
    /// The relay returned another key: nothing is sent to this contact
    /// until the new key is accepted (docs/PHASE3_DESIGN.md §6.3).
    let keyChanged: Bool
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
}

final class Session {
    /// The serial queue of every call that goes to the relay
    /// (docs/PHASE3_DESIGN.md §3.2, §5.3). Results go back to main.
    static let net = DispatchQueue(label: "no.brev.net")

    let brev: Brev

    init(brev: Brev) {
        self.brev = brev
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
        return zip(rows, names).map { ContactItem(id: $0.id, name: $1, keyChanged: $0.keyChanged) }
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
        return ContactDetails(address: address, code: Self.secret(info.code), newCode: Self.secret(info.newCode))
    }

    // MARK: - Registration (no content; the address is typed like content)

    /// Starts registering the typed `address`; returns the digest the
    /// identity key signs. No I/O. The UTF-8 copy is wiped when this
    /// returns; the caller wipes `address`.
    func registerRequest(address: SecretText) throws -> Data {
        try Self.withUTF8(address) { a, al in try brev.registerRequest(address: a, addressLen: al) }
    }

    /// Finishes the registration with the DER signature over the digest
    /// (network: `Session.net`).
    func register(signature: Data) throws {
        try brev.register(signature: signature)
    }

    /// Adds the contact with the typed `address` and returns its local id
    /// (network: `Session.net`). Rust copies the address before the lookup;
    /// the UTF-8 copy here is wiped when this returns.
    func addContact(address: SecretText) throws -> Data {
        try Self.withUTF8(address) { a, al in try brev.addContact(address: a, addressLen: al) }
    }

    /// Accepts the contact's changed key; `newCode` is the code shown.
    func acceptNewKey(contact: Data, newCode: SecretBytes) throws {
        var code = newCode.withBytes { Data($0) }
        defer { code.wipe() }
        try brev.acceptNewKey(contact: contact, newCode: code)
    }

    // MARK: - A letter (docs/PHASE3_DESIGN.md §3.2)

    /// Step 0, without content: checks the contact's key at the relay and
    /// takes the send ticket (network: `Session.net`).
    func prepareSend(contact: Data) throws {
        try brev.prepareSend(contact: contact)
    }

    /// Step 1, on main: seals a letter that starts a thread with `contact`
    /// and returns the digest the identity key signs. No I/O. The UTF-8
    /// copies live in SecretBytes of 3 bytes per unit and are wiped when
    /// this returns. The caller wipes `subject` and `body`.
    func signRequest(contact: Data, subject: SecretText, body: SecretText) throws -> Data {
        try Self.withUTF8(subject) { sd, sl in
            try Self.withUTF8(body) { bd, bl in
                try brev.signRequest(contact: contact, subject: sd, subjectLen: sl, body: bd, bodyLen: bl)
            }
        }
    }

    /// Step 3: the DER signature over the digest.
    func attachSignature(_ signature: Data) throws {
        try brev.attachSignature(signature: signature)
    }

    /// Step 4: posts the signed letter and stores the own copy; returns the
    /// thread id (network: `Session.net`). `Network` keeps the signed letter
    /// for another `submit`.
    func submit() throws -> Data {
        try brev.submit()
    }

    /// Forgets the ticket and the letter, signed or not.
    func cancelSend() {
        brev.cancelSend()
    }

    /// Fetches, stores and acknowledges the letters waiting at the relay;
    /// returns how many arrived (network: `Session.net`).
    func sync() throws -> UInt32 {
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
