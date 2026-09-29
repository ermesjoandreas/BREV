// padcheck — docs/VERIFY.md V18: every sealed column in Brev's store has a
// padded length (design §2.8; CLAUDE.md §3.1).
//
// A verification tool, never linked into Brev.app. It opens the store
// read-only with the system SQLite and reads only lengths, never a value.
// A sealed column is nonce (24) || XChaCha20-Poly1305 ciphertext of the
// padded plaintext || tag (16), and the padded length is one of 256, 1024,
// 4096 or 16384 bytes, or a larger multiple of 16384 up to 1 MiB
// (brev-proto::padded_len). The sealed columns are identity.keys,
// identity.address, contacts.bundle, contacts.address, contacts.pending,
// contacts.flags, invites.body, threads.subject and messages.body
// (brev-mail/src/store.rs, schema v5;
// docs/PHASE3_DESIGN.md §6.1; messages.env_class is plaintext,
// docs/VAULT_SPLIT_PLAN.md §6). Phase 2's version read three stores; the
// echo peers' stores went with Phase 3.
//
// usage: padcheck [<dir>]
//   <dir> holds brev.db; the default is Brev's folder,
//   ~/Library/Containers/no.brev.app/Data/Library/Application Support/Brev.
//   Prints the store's application_id and user_version (must be BREV and 5)
//   and per column the rows checked and any row whose length is not padded
//   (rowid and length only). Exit 0 when the store passes and has at least
//   one checked column value (the control); 1 otherwise; 3 when it cannot be
//   opened.

import Foundation
import SQLite3

setvbuf(stdout, nil, _IOLBF, 0)
let home = FileManager.default.homeDirectoryForCurrentUser.path
let dir = CommandLine.arguments.dropFirst().first
    ?? "\(home)/Library/Containers/no.brev.app/Data/Library/Application Support/Brev"
let nonce = 24, tag = 16
let columns = [("identity", "keys"), ("identity", "address"), ("contacts", "bundle"), ("contacts", "address"),
               ("contacts", "pending"), ("contacts", "flags"), ("invites", "body"),
               ("threads", "subject"), ("messages", "body")]

func padded(_ n: Int) -> Bool {
    if [256, 1024, 4096, 16384].contains(n) { return true }
    return n > 16384 && n % 16384 == 0 && n <= 1 << 20
}

var failed = false
for store in ["brev.db"] {
    let path = (dir as NSString).appendingPathComponent(store)
    var db: OpaquePointer?
    guard sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK else {
        print("\(store): cannot open (\(String(cString: sqlite3_errmsg(db))))")
        sqlite3_close(db)
        exit(3)
    }
    defer { sqlite3_close(db) }
    func int(_ sql: String) -> Int? {
        var st: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &st, nil) == SQLITE_OK else { return nil }
        defer { sqlite3_finalize(st) }
        return sqlite3_step(st) == SQLITE_ROW ? Int(sqlite3_column_int64(st, 0)) : nil
    }
    let appID = int("PRAGMA application_id"), version = int("PRAGMA user_version")
    let header = appID == 0x4252_4556 && version == 5
    print("\(store): application_id=0x\(String(appID ?? -1, radix: 16)) user_version=\(version ?? -1) \(header ? "ok" : "BAD")")
    if !header { failed = true }
    var checked = 0
    for (table, column) in columns {
        var st: OpaquePointer?
        guard sqlite3_prepare_v2(db, "SELECT rowid, length(\(column)) FROM \(table)", -1, &st, nil) == SQLITE_OK else {
            print("   \(table).\(column): query failed (\(String(cString: sqlite3_errmsg(db))))")
            failed = true
            continue
        }
        var rows = 0, bad: [String] = []
        while sqlite3_step(st) == SQLITE_ROW {
            rows += 1
            let len = Int(sqlite3_column_int64(st, 1))
            if !padded(len - nonce - tag) { bad.append("rowid \(sqlite3_column_int64(st, 0)) length \(len)") }
        }
        sqlite3_finalize(st)
        checked += rows
        print("   \(table).\(column): rows=\(rows) \(bad.isEmpty ? "all padded" : "NOT PADDED: " + bad.joined(separator: ", "))")
        if !bad.isEmpty { failed = true }
    }
    print("   \(store): \(checked) sealed values checked\(checked == 0 ? " (control FAILED: nothing checked)" : "")")
    if checked == 0 { failed = true }
}
print(failed ? "padcheck: FAIL" : "padcheck: pass")
exit(failed ? 1 : 0)
