// Session.swift — the app's side of the Rust session.
//
// Upholds CLAUDE.md §1.10, §3.1 and §6 (docs/PHASE2_DESIGN.md §4.2, §6.2):
// Session is the only owner of the Rust `Brev` handle. Every name, subject
// and body comes out as a SecretText that the view holding it wipes; each
// OpenText is read completely and closed at once, so Rust holds no content
// between calls. Content goes to Rust only as a no-copy view of a
// SecretBytes, which is wiped right after the call. No AppKit: compiled into
// the app and the CLI harness.

import Foundation

/// A contact, with its name read out of Rust.
struct ContactItem {
    let id: Data
    let name: SecretText
}

/// A thread, with its subject read out of Rust.
struct ThreadItem {
    let id: Data
    let contact: Data
    let createdAt: Int64
    let subject: SecretText
}

final class Session {
    let brev: Brev

    init(brev: Brev) {
        self.brev = brev
    }

    /// Onboarding (§5.3 step 6): creates the three stores in `dir` under
    /// `dek` (32 bytes), which is wiped here on every path, and returns the
    /// session locked.
    static func create(dir: String, dek: SecretBytes, signingKey: Data) throws -> Session {
        defer { dek.wipe() }
        // Exactly 32 bytes: a no-copy Data of 14 bytes or less would be
        // copied inline (SecretBytes.capacity).
        guard dek.count == 32 else { throw BrevError.Malformed }   // as Rust's `create`
        let brev = try withExtendedLifetime(dek) {
            try Brev.create(dir: dir, dek: Data(bytesNoCopy: dek.base, count: 32, deallocator: .none),
                            signingKey: signingKey)
        }
        return Session(brev: brev)
    }

    /// Opens the three stores in `dir`, locked.
    static func open(dir: String) throws -> Session {
        Session(brev: try Brev.open(dir: dir))
    }

    func contacts() throws -> [ContactItem] {
        let rows = try brev.contacts()
        let names = try Self.readAll(rows.map { $0.name })
        return zip(rows, names).map { ContactItem(id: $0.id, name: $1) }
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

    /// Starts a thread with `contact` and sends its first letter; returns the
    /// thread id. The UTF-8 copies live in SecretBytes of 3 bytes per unit and
    /// are wiped when this returns. The caller wipes `subject` and `body`.
    func send(to contact: Data, subject: SecretText, body: SecretText) throws -> Data {
        let s8 = SecretBytes(capacity: 3 * subject.length)
        defer { s8.wipe() }
        let b8 = SecretBytes(capacity: 3 * body.length)
        defer { b8.wipe() }
        Transcode.utf16ToUTF8(subject, into: s8)
        Transcode.utf16ToUTF8(body, into: b8)
        return try s8.withFFIView { sd, sl in
            try b8.withFFIView { bd, bl in
                try brev.sendNew(contact: contact, subject: sd, subjectLen: sl, body: bd, bodyLen: bl)
            }
        }
    }

    /// Moves the echo peers' letters (§9); returns how many arrived.
    func sync() throws -> UInt32 {
        try brev.sync()
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
