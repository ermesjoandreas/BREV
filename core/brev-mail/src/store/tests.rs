//! Unit tests of the store: the ones that need the private accessors, the
//! SQL trace or the test-build counters.

use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::sync::Mutex;

use rusqlite::config::DbConfig;
use rusqlite::trace::{TraceEvent, TraceEventCodes};

use super::*;
use crate::test_keys::TestKey;

/// A store path in a fresh folder with mode 0700 of its own: a store locks
/// its folder.
fn temp_path() -> PathBuf {
    let r: [u8; 8] = crypto::random().unwrap();
    let dir = std::env::temp_dir().join(format!("brev-unit-{:016x}", u64::from_le_bytes(r)));
    fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    dir.join("brev.db")
}

/// Removes the folder of a `temp_path()` on drop.
struct Cleanup(PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Some(dir) = self.0.parent() {
            let _ = fs::remove_dir_all(dir);
        }
    }
}

/// A store, confirmed, and the identity key it was made with. Its folder is
/// removed on drop, after the store is closed.
struct Party {
    core: Core,
    key: TestKey,
    path: PathBuf,
    _cleanup: Cleanup,
}

fn party() -> Party {
    let key = TestKey::new();
    let path = temp_path();
    let mut core = Core::create(&path, &mut crypto::random().unwrap(), &key.public).unwrap();
    core.confirm_active().unwrap();
    Party {
        core,
        key,
        _cleanup: Cleanup(path.clone()),
        path,
    }
}

/// Each adds the other under the given address; returns (b at a, a at b).
fn befriend(a: &mut Party, b: &mut Party) -> (ContactId, ContactId) {
    let b_at_a = a
        .core
        .add_contact(&b.core.bundle().unwrap(), b"bob")
        .unwrap();
    let a_at_b = b
        .core
        .add_contact(&a.core.bundle().unwrap(), b"alice")
        .unwrap();
    (b_at_a, a_at_b)
}

/// The whole send path at the core: seal, sign the digest, attach, store
/// the own copy. Returns the signed envelope.
fn send(from: &mut Party, to: ContactId, subject: &[u8], body: &[u8]) -> Envelope {
    let mut letter = from.core.seal_letter(to, subject, body).unwrap();
    let der = from.key.sign_digest(&letter.digest());
    from.core.attach_signature(&mut letter, &der).unwrap();
    from.core.store_sent(&letter).unwrap();
    letter.envelope().clone()
}

/// An envelope from `from` to `to` with a hand-built payload, signed.
fn seal_from(from: &Party, to: &PublicBundle, payload: &[u8]) -> Envelope {
    let me = from.core.me().unwrap();
    let mut env = crypto::seal_message(&me.secret, &to.x25519, me.id, to.id().0, payload).unwrap();
    env.signature = from.key.sign_raw(&env.signed_bytes()).to_vec();
    env
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// `me()` and `lock()` each end with their own stack scrub, on top of
/// the ones inside the crypto calls they make.
#[test]
fn me_and_lock_scrub_the_stack() {
    let mut p = party();
    let before = crypto::scrubs();
    drop(p.core.me().unwrap());
    // One inside open_column (identity_keys), one of me()'s own.
    assert_eq!(crypto::scrubs() - before, 2);
    let before = crypto::scrubs();
    p.core.lock();
    assert_eq!(crypto::scrubs() - before, 1);
}

/// Mandatory lock test, part 2: the DEK buffer itself is zeroed.
#[test]
fn lock_zeroes_the_dek_buffer() {
    let path = temp_path();
    let key = TestKey::new();
    let mut dek: [u8; 32] = crypto::random().unwrap();
    let original = dek;
    let mut core = Core::create(&path, &mut dek, &key.public).unwrap();
    assert_eq!(dek, [0u8; 32], "caller's DEK copy must be wiped");
    assert_eq!(core.dek_for_test(), original, "positive control");
    let addr = core.dek_addr_for_test();
    // A core dropped without lock() wipes the DEK too (compile time).
    crypto::wiped_on_drop(core.v.dek_cell_for_test());

    core.lock();
    assert_eq!(core.dek_for_test(), [0u8; 32]);
    assert_eq!(core.dek_addr_for_test(), addr, "same buffer, not a new one");

    let mut wrong: [u8; 32] = crypto::random().unwrap();
    assert!(matches!(core.unlock(&mut wrong), Err(Error::WrongKey)));
    assert_eq!(wrong, [0u8; 32]);
    assert!(core.is_locked());
    assert_eq!(core.dek_for_test(), [0u8; 32]);

    let mut right = original;
    let built = crypto::secrets_built();
    core.unlock(&mut right).unwrap();
    core.confirm_active().unwrap();
    assert_eq!(right, [0u8; 32]);
    assert_eq!(core.dek_for_test(), original);
    assert_eq!(core.dek_addr_for_test(), addr);
    core.bundle().unwrap();
    core.relay_token().unwrap();
    core.registration(b"anna").unwrap();
    assert_eq!(
        crypto::secrets_built(),
        built,
        "unlock, bundle, the token and a registration never build the X25519 secret"
    );

    // All zeros (a wiped buffer, a failed unwrap) also locks a core that
    // was unlocked.
    assert!(matches!(core.unlock(&mut [0u8; 32]), Err(Error::WrongKey)));
    assert!(core.is_locked());
    assert_eq!(core.dek_for_test(), [0u8; 32]);
    assert!(matches!(core.bundle().map(drop), Err(Error::Locked)));

    // So does a failure that is not about the key: the right DEK with
    // the identity row gone.
    right = original;
    core.unlock(&mut right).unwrap();
    core.db().execute("DELETE FROM identity", []).unwrap();
    right = original;
    assert!(matches!(core.unlock(&mut right), Err(Error::NotFound)));
    assert!(core.is_locked());
    assert_eq!(core.dek_for_test(), [0u8; 32]);
    assert!(matches!(core.bundle().map(drop), Err(Error::Locked)));
    drop(core);
    drop(Cleanup(path));
}

/// A store sealed under the all-zero key (a crafted file: `create`
/// refuses to make one) still does not unlock with zeros, which is what
/// a caller holds after a failed unwrap or a wiped buffer.
#[test]
fn unlock_refuses_all_zero_dek() {
    let path = temp_path();
    let key = TestKey::new();
    drop(Core::init(&path, DekSlot::take(&mut [0u8; 32]), &key.public).unwrap());
    let mut core = Core::open(&path).unwrap();
    let mut zero = [0u8; 32];
    assert!(matches!(core.unlock(&mut zero), Err(Error::WrongKey)));
    assert!(core.is_locked());
    drop(core);
    drop(Cleanup(path));
}

#[test]
fn schema_v3_pragmas() {
    let p = party();
    drop(p.core);
    let core = Core::open(&p.path).unwrap();
    let q = |name: &str| -> String {
        core.db()
            .pragma_query_value(None, name, |r| r.get::<_, rusqlite::types::Value>(0))
            .map(|v| format!("{v:?}"))
            .unwrap()
    };
    assert_eq!(q("journal_mode"), "Text(\"delete\")");
    assert_eq!(q("secure_delete"), "Integer(1)");
    assert_eq!(q("temp_store"), "Integer(2)");
    assert_eq!(q("foreign_keys"), "Integer(1)");
    assert_eq!(q("cell_size_check"), "Integer(1)");
    assert_eq!(q("fullfsync"), "Integer(1)");
    assert_eq!(q("trusted_schema"), "Integer(0)");
    assert_eq!(q("application_id"), format!("Integer({APPLICATION_ID})"));
    assert_eq!(q("user_version"), "Integer(4)");
    assert!(core
        .db()
        .db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE)
        .unwrap());
    // The tables of design §6.1, column by column.
    let columns = |table: &str| -> Vec<String> {
        let mut stmt = core
            .db()
            .prepare(&format!("SELECT name FROM pragma_table_info('{table}')"))
            .unwrap();
        let rows = stmt.query_map([], |r| r.get(0)).unwrap();
        rows.collect::<Result<_, _>>().unwrap()
    };
    assert_eq!(columns("identity"), ["id", "keys", "address"]);
    assert_eq!(
        columns("contacts"),
        ["id", "tag", "bundle", "address", "pending"]
    );
    assert_eq!(
        columns("threads"),
        ["id", "contact_id", "created_at", "subject"]
    );
    assert_eq!(
        columns("messages"),
        [
            "id",
            "thread_id",
            "created_at",
            "outgoing",
            "read",
            "body",
            "env_class"
        ]
    );
}

/// A real Phase 2 store (its schema, application_id and user_version 2)
/// and a v3 store relabelled as version 2 are both refused, unchanged.
#[test]
fn v2_store_is_refused() {
    const V2_SCHEMA: &str = "
CREATE TABLE identity (
    id         BLOB PRIMARY KEY,           -- pt: own identity id
    keys       BLOB NOT NULL               -- ct: X25519 secret || X25519 public || signing public key
) STRICT;
CREATE TABLE contacts (
    id         BLOB PRIMARY KEY,           -- pt: identity id
    bundle     BLOB NOT NULL,              -- ct: public bundle
    name       BLOB NOT NULL               -- ct
) STRICT;
CREATE TABLE threads (
    id         BLOB PRIMARY KEY,           -- pt: 16 random bytes, shared with peer
    contact_id BLOB NOT NULL REFERENCES contacts(id),
    created_at INTEGER NOT NULL,           -- pt: unix seconds
    subject    BLOB NOT NULL               -- ct
) STRICT;
CREATE TABLE messages (
    id         BLOB PRIMARY KEY,           -- pt: 16 random bytes, chosen by sender
    thread_id  BLOB NOT NULL REFERENCES threads(id),
    created_at INTEGER NOT NULL,           -- pt
    outgoing   INTEGER NOT NULL,           -- pt: 1 = sent by me
    read       INTEGER NOT NULL,           -- pt
    body       BLOB NOT NULL               -- ct
) STRICT;
CREATE INDEX messages_by_thread ON messages(thread_id, created_at);
";
    let path = temp_path();
    let raw = Connection::open(&path).unwrap();
    raw.pragma_update(None, "application_id", APPLICATION_ID)
        .unwrap();
    raw.execute_batch(V2_SCHEMA).unwrap();
    raw.pragma_update(None, "user_version", 2).unwrap();
    drop(raw);
    let before = fs::read(&path).unwrap();
    assert!(matches!(Core::open(&path).map(drop), Err(Error::Corrupt)));
    assert_eq!(fs::read(&path).unwrap(), before);
    drop(Cleanup(path));

    // A v4 store relabelled as version 2.
    let p = party();
    drop(p.core);
    let raw = Connection::open(&p.path).unwrap();
    raw.pragma_update(None, "user_version", 2).unwrap();
    assert!(matches!(Core::open(&p.path).map(drop), Err(Error::Corrupt)));
    raw.pragma_update(None, "user_version", 4).unwrap();
    drop(Core::open(&p.path).unwrap());
}

/// A real Phase 3 store before the environment class (schema v3: no
/// `messages.env_class`) and a v4 store relabelled as version 3 are both
/// refused, unchanged: there is no migration (docs/VAULT_SPLIT_PLAN.md Q4).
#[test]
fn v3_store_is_refused() {
    const V3_SCHEMA: &str = "
CREATE TABLE identity (
    id         BLOB PRIMARY KEY,           -- pt: own identity id
    keys       BLOB NOT NULL,              -- ct: X25519 secret || X25519 public || signing key (65) || relay token (32)
    address    BLOB NOT NULL               -- ct: own address; empty until registered
) STRICT;
CREATE TABLE contacts (
    id         BLOB PRIMARY KEY,           -- pt: 16 random bytes, local; kept when the key changes
    tag        BLOB NOT NULL UNIQUE,       -- pt: keyed tag of the pinned identity id (finds the sender)
    bundle     BLOB NOT NULL,              -- ct: pinned bundle
    address    BLOB NOT NULL,              -- ct: the address, also shown as the name
    pending    BLOB NOT NULL               -- ct: empty, or the other bundle the relay returned
) STRICT;
CREATE TABLE threads (
    id         BLOB PRIMARY KEY,           -- pt: 16 random bytes, shared with peer
    contact_id BLOB NOT NULL REFERENCES contacts(id),
    created_at INTEGER NOT NULL,           -- pt: unix seconds
    subject    BLOB NOT NULL               -- ct
) STRICT;
CREATE TABLE messages (
    id         BLOB PRIMARY KEY,           -- pt: 16 random bytes, chosen by sender
    thread_id  BLOB NOT NULL REFERENCES threads(id),
    created_at INTEGER NOT NULL,           -- pt
    outgoing   INTEGER NOT NULL,           -- pt: 1 = sent by me
    read       INTEGER NOT NULL,           -- pt
    body       BLOB NOT NULL               -- ct
) STRICT;
CREATE INDEX messages_by_thread ON messages(thread_id, created_at);
";
    let path = temp_path();
    let raw = Connection::open(&path).unwrap();
    raw.pragma_update(None, "application_id", APPLICATION_ID)
        .unwrap();
    raw.execute_batch(V3_SCHEMA).unwrap();
    raw.pragma_update(None, "user_version", 3).unwrap();
    drop(raw);
    let before = fs::read(&path).unwrap();
    assert!(matches!(Core::open(&path).map(drop), Err(Error::Corrupt)));
    assert_eq!(fs::read(&path).unwrap(), before);
    drop(Cleanup(path));

    // A v4 store relabelled as version 3.
    let p = party();
    drop(p.core);
    let raw = Connection::open(&p.path).unwrap();
    raw.pragma_update(None, "user_version", 3).unwrap();
    assert!(matches!(Core::open(&p.path).map(drop), Err(Error::Corrupt)));
    raw.pragma_update(None, "user_version", 4).unwrap();
    drop(Core::open(&p.path).unwrap());
}

static SQL_LOG: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn record(e: TraceEvent<'_>) {
    if let TraceEvent::Stmt(s, _) = e {
        if let Some(sql) = s.expanded_sql() {
            SQL_LOG.lock().unwrap().push(sql);
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// SQLite is never handed plaintext: every statement, with its bound
/// values expanded, is recorded and searched. This covers the rollback
/// journal, temp storage and freed pages by construction: SQLite can only
/// write what it was given.
#[test]
fn sqlite_never_receives_plaintext() {
    const MARKER: &[u8] = b"BREV-TRACE-MARKER-5d1c";
    const MINE: &[u8] = b"own-trace-marker-7a02";
    const THEIRS: &[u8] = b"contact-trace-marker-19be";
    let (mut a, mut b) = (party(), party());
    for c in [&a, &b] {
        c.core
            .db()
            .trace_v2(TraceEventCodes::SQLITE_TRACE_STMT, Some(record));
    }
    a.core.set_address(MINE).unwrap();
    let b_at_a = a
        .core
        .add_contact(&b.core.bundle().unwrap(), THEIRS)
        .unwrap();
    b.core.add_contact(&a.core.bundle().unwrap(), MINE).unwrap();
    let env = send(&mut a, b_at_a, MARKER, MARKER);
    let m = b.core.receive(&env).unwrap();
    assert_eq!(&b.core.read_body(m).unwrap()[..], MARKER);
    b.core.mark_read(m).unwrap();
    assert!(b.core.contacts().is_ok() && b.core.threads().is_ok());
    assert_eq!(&a.core.address().unwrap()[..], MINE);
    assert_eq!(&a.core.contact_address(b_at_a).unwrap()[..], THEIRS);

    let log = std::mem::take(&mut *SQL_LOG.lock().unwrap());
    assert!(log.len() > 10, "trace recorded the flow");
    for sql in &log {
        let lower = sql.to_ascii_lowercase();
        for m in [MARKER, MINE, THEIRS] {
            let text = String::from_utf8(m.to_vec()).unwrap();
            assert!(!sql.contains(&text) && !lower.contains(&hex(m)), "{sql}");
        }
    }
    // Positive control: a bound marker is visible in the trace.
    a.core
        .db()
        .query_row("SELECT ?1", [MARKER], |_| Ok(()))
        .unwrap();
    let log = std::mem::take(&mut *SQL_LOG.lock().unwrap());
    assert!(log
        .iter()
        .any(|s| s.to_ascii_lowercase().contains(&hex(MARKER))));
}

#[test]
fn receive_rejects_thread_owned_by_another_contact() {
    let (mut a, mut b, mut c) = (party(), party(), party());
    let b_bundle = b.core.bundle().unwrap();
    let (b_at_a, _) = befriend(&mut a, &mut b);
    b.core
        .add_contact(&c.core.bundle().unwrap(), b"carol")
        .unwrap();
    c.core.add_contact(&b_bundle, b"bob").unwrap();
    let env = send(&mut a, b_at_a, b"s", b"x");
    let first = b.core.receive(&env).unwrap();
    let t = b.core.thread_of(first).unwrap();

    // C, a real contact of B, names A's thread id in its payload.
    let payload = encode_payload(&[9; 16], &t.0, b"s", b"hijack").unwrap();
    let from_c = seal_from(&c, &b_bundle, &payload);
    assert!(matches!(b.core.receive(&from_c), Err(Error::Malformed)));
    assert_eq!(b.core.messages(t).unwrap().len(), 1);

    // A letter from A into its own thread is accepted (the owner matches).
    let payload = encode_payload(&[8; 16], &t.0, b"s", b"more").unwrap();
    b.core.receive(&seal_from(&a, &b_bundle, &payload)).unwrap();
    assert_eq!(b.core.messages(t).unwrap().len(), 2);

    // An agent re-points the thread at C in B's file: the owner is
    // authenticated through the subject before C's letter is accepted, and
    // the damaged row is a local failure.
    let c_at_b = b.core.contacts().unwrap()[1].id;
    b.core
        .db()
        .execute(
            "UPDATE threads SET contact_id = ?1 WHERE id = ?2",
            params![&c_at_b.0[..], &t.0[..]],
        )
        .unwrap();
    let e = b.core.receive(&from_c).unwrap_err();
    assert!(matches!(e, Error::Corrupt) && !is_permanent(&e));
    assert_eq!(b.core.messages(t).unwrap().len(), 2);
}

/// The one receive path that writes before it fails: a stored message id
/// under a new thread id. The thread insert is rolled back.
#[test]
fn failed_receive_leaves_no_new_thread() {
    let (mut a, mut b) = (party(), party());
    let b_bundle = b.core.bundle().unwrap();
    let (b_at_a, _) = befriend(&mut a, &mut b);
    let m = b.core.receive(&send(&mut a, b_at_a, b"s", b"x")).unwrap();
    let t = b.core.thread_of(m).unwrap();

    let payload = encode_payload(&m.0, &[0x55; 16], b"new", b"x").unwrap();
    let env = seal_from(&a, &b_bundle, &payload);
    assert!(matches!(b.core.receive(&env), Err(Error::Duplicate)));
    assert_eq!(b.core.threads().unwrap().len(), 1);
    assert_eq!(b.core.messages(t).unwrap().len(), 1);
}

/// A sealed letter holds ciphertext only: nothing decrypted and no X25519
/// secret is alive once `seal_letter` returns, so nothing is while the
/// letter waits for Touch ID and the relay.
#[test]
fn seal_letter_leaves_nothing_decrypted() {
    let (mut a, mut b) = (party(), party());
    let (b_at_a, _) = befriend(&mut a, &mut b);
    // Positive controls: the counters see a decrypted address, an encoded
    // payload and a decrypted identity.
    let contacts = a.core.contacts().unwrap();
    assert_eq!(crypto::live_plaintexts(), 1);
    drop(contacts);
    let payload = encode_payload(&[0; 16], &[1; 16], b"s", b"x").unwrap();
    assert_eq!(crypto::live_plaintexts(), 1);
    drop(payload);
    let me = a.core.me().unwrap();
    assert_eq!(crypto::live_secrets(), 1);
    drop(me);

    let scrubs = crypto::scrubs();
    let letter = a.core.seal_letter(b_at_a, b"s", b"x").unwrap();
    assert_eq!((crypto::live_plaintexts(), crypto::live_secrets()), (0, 0));
    assert!(crypto::scrubs() > scrubs);
    assert!(!letter.is_signed());
    assert!(a.core.threads().unwrap().is_empty(), "nothing stored yet");
}

thread_local! {
    static AT_COMMIT: std::cell::RefCell<Vec<(usize, usize)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Nothing decrypted is alive while `receive` commits (a full fsync):
/// the letter and the X25519 secret are dropped first.
#[test]
fn nothing_decrypted_is_alive_while_receive_commits() {
    fn at_commit(e: TraceEvent<'_>) {
        if let TraceEvent::Stmt(_, "COMMIT") = e {
            let live = (crypto::live_plaintexts(), crypto::live_secrets());
            AT_COMMIT.with(|v| v.borrow_mut().push(live));
        }
    }
    let (mut a, mut b) = (party(), party());
    let b_bundle = b.core.bundle().unwrap();
    let (b_at_a, _) = befriend(&mut a, &mut b);
    let first = send(&mut a, b_at_a, b"s", b"x");
    b.core
        .db()
        .trace_v2(TraceEventCodes::SQLITE_TRACE_STMT, Some(at_commit));
    // The first letter makes a new thread, the second joins it.
    let m = b.core.receive(&first).unwrap();
    let t = b.core.thread_of(m).unwrap();
    let second = seal_from(
        &a,
        &b_bundle,
        &encode_payload(&[7; 16], &t.0, b"s", b"y").unwrap(),
    );
    b.core.receive(&second).unwrap();
    assert_eq!(AT_COMMIT.with(|v| v.take()), [(0, 0), (0, 0)]);
}

#[test]
fn payload_round_trip_and_truncation() {
    let p = encode_payload(&[6; 16], &[7; 16], b"subj", b"body").unwrap();
    let (i, t, s, b) = decode_payload(&p).unwrap();
    assert_eq!((i, t, s, b), ([6; 16], [7; 16], &b"subj"[..], &b"body"[..]));
    assert!(matches!(decode_payload(&p[..35]), Err(Error::Malformed)));
    assert!(matches!(decode_payload(&p[..20]), Err(Error::Malformed)));
}

/// Design §8: subject and body sizes within one bucket give ciphertexts of
/// equal length; each payload size gives its bucket plus the tag; one byte
/// over the maximum is `Malformed`.
#[test]
fn envelope_payload_is_padded() {
    let (mut a, mut b) = (party(), party());
    let (b_at_a, _) = befriend(&mut a, &mut b);
    let len = |subject: usize, body: usize| {
        a.core
            .seal_letter(b_at_a, &vec![b's'; subject], &vec![b'b'; body])
            .unwrap()
            .envelope()
            .ciphertext
            .len()
    };
    // 34 bytes of ids and length, then subject and body: 256 holds up to
    // 218 bytes of content with the 4-byte length prefix.
    assert_eq!(len(0, 0), 256 + 16);
    assert_eq!(len(0, 0), len(10, 200));
    assert_eq!(len(0, 0), len(218, 0));
    assert_eq!(len(219, 0), 1024 + 16, "control: the next bucket");
    assert_eq!(len(100, 800), len(256, 700));
    assert_eq!(len(256, 65_536), 81_920 + 16);

    let me = a.core.me().unwrap();
    let to = b.core.bundle().unwrap();
    for (n, bucket) in [
        (0, 256),
        (252, 256),
        (253, 1024),
        (1020, 1024),
        (1021, 4096),
        (4092, 4096),
        (4093, 16384),
        (16380, 16384),
        (16381, 32768),
        (brev_proto::MAX_PADDED - 4, brev_proto::MAX_PADDED),
    ] {
        let env =
            crypto::seal_message(&me.secret, &to.x25519, me.id, to.id().0, &vec![1; n]).unwrap();
        assert_eq!(env.ciphertext.len(), bucket + 16, "{n}");
    }
    let over = vec![1; brev_proto::MAX_PADDED - 3];
    assert!(matches!(
        crypto::seal_message(&me.secret, &to.x25519, me.id, to.id().0, &over),
        Err(Error::Malformed)
    ));
}

/// The signature is checked with the pinned key before anything is
/// decrypted: a bad one is `Crypto`, the AEAD never runs, nothing is
/// stored.
#[test]
fn receive_verifies_before_decrypting() {
    let (mut a, mut b) = (party(), party());
    let (b_at_a, _) = befriend(&mut a, &mut b);
    let env = send(&mut a, b_at_a, b"s", b"x");
    let mut bad_sig = env.clone();
    bad_sig.signature[5] ^= 1;
    let mut bad_ct = env.clone();
    bad_ct.ciphertext[0] ^= 1;
    let mut other_key = env.clone();
    other_key.signature = TestKey::new().sign_raw(&env.signed_bytes()).to_vec();
    let mut short = env.clone();
    short.signature.pop();
    for (name, e) in [
        ("signature", bad_sig),
        ("ciphertext", bad_ct),
        ("another key", other_key),
        ("63 bytes", short),
    ] {
        let opens = crypto::message_opens();
        let err = b.core.receive(&e).unwrap_err();
        assert!(matches!(err, Error::Crypto) && is_permanent(&err), "{name}");
        assert_eq!(crypto::message_opens(), opens, "{name}: AEAD not called");
    }
    assert!(b.core.threads().unwrap().is_empty(), "nothing stored");
    // Control: the good one opens once and is stored.
    let opens = crypto::message_opens();
    b.core.receive(&env).unwrap();
    assert_eq!(crypto::message_opens(), opens + 1);

    // A valid signature over a tampered ciphertext (made by the sender's
    // own key) passes step 4 and fails the AEAD: `Crypto` too.
    let mut resigned = env.clone();
    resigned.ciphertext[0] ^= 1;
    resigned.signature = a.key.sign_raw(&resigned.signed_bytes()).to_vec();
    let opens = crypto::message_opens();
    assert!(matches!(b.core.receive(&resigned), Err(Error::Crypto)));
    assert_eq!(crypto::message_opens(), opens + 1);
}

/// A damaged or swapped local row is `Corrupt` (class L, not acknowledged),
/// never an error that would drop the letter.
#[test]
fn local_row_failures_are_corrupt() {
    let (mut a, mut b, mut c) = (party(), party(), party());
    let b_bundle = b.core.bundle().unwrap();
    let (b_at_a, a_at_b) = befriend(&mut a, &mut b);
    let c_at_b = b
        .core
        .add_contact(&c.core.bundle().unwrap(), b"carol")
        .unwrap();
    c.core.add_contact(&b_bundle, b"bob").unwrap();
    let env = send(&mut a, b_at_a, b"s", b"x");
    // A second connection, as a filesystem agent would edit the file.
    let db = Connection::open(&b.path).unwrap();
    let get = |column: &str, id: &ContactId| -> Vec<u8> {
        db.query_row(
            &format!("SELECT {column} FROM contacts WHERE id = ?1"),
            [&id.0[..]],
            |r| r.get(0),
        )
        .unwrap()
    };
    let set = |column: &str, id: &ContactId, v: &[u8]| {
        db.execute(
            &format!("UPDATE contacts SET {column} = ?1 WHERE id = ?2"),
            params![v, &id.0[..]],
        )
        .unwrap();
    };
    let corrupt = |core: &mut Core, what: &str| {
        let e = core.receive(&env).unwrap_err();
        assert!(matches!(e, Error::Corrupt), "{what}: {e:?}");
        assert!(!is_permanent(&e), "{what}");
    };

    // Tags swapped between A's and C's rows: A's letter finds C's row,
    // whose bundle does not match the tag.
    let (tag_a, tag_c) = (get("tag", &a_at_b), get("tag", &c_at_b));
    set("tag", &a_at_b, &[0; 32]);
    set("tag", &c_at_b, &tag_a);
    set("tag", &a_at_b, &tag_c);
    corrupt(&mut b.core, "swapped tag");
    set("tag", &c_at_b, &[0; 32]);
    set("tag", &a_at_b, &tag_a);
    set("tag", &c_at_b, &tag_c);

    // Bundles swapped between the rows, and a damaged bundle.
    let (bundle_a, bundle_c) = (get("bundle", &a_at_b), get("bundle", &c_at_b));
    set("bundle", &a_at_b, &bundle_c);
    corrupt(&mut b.core, "swapped bundle");
    let mut damaged = bundle_a.clone();
    damaged[40] ^= 1;
    set("bundle", &a_at_b, &damaged);
    corrupt(&mut b.core, "damaged bundle");
    set("bundle", &a_at_b, &bundle_a);

    // The own identity row damaged after unlock.
    let keys: Vec<u8> = db
        .query_row("SELECT keys FROM identity", [], |r| r.get(0))
        .unwrap();
    let mut bad = keys.clone();
    bad[30] ^= 1;
    db.execute("UPDATE identity SET keys = ?1", [&bad]).unwrap();
    corrupt(&mut b.core, "identity row");
    db.execute("UPDATE identity SET keys = ?1", [&keys])
        .unwrap();

    // Restored: the letter is stored.
    let m = b.core.receive(&env).unwrap();
    let t = b.core.thread_of(m).unwrap();

    // A known thread whose subject no longer opens.
    let subject: Vec<u8> = b
        .core
        .db()
        .query_row(
            "SELECT subject FROM threads WHERE id = ?1",
            [&t.0[..]],
            |r| r.get(0),
        )
        .unwrap();
    let mut bad = subject.clone();
    bad[30] ^= 1;
    b.core
        .db()
        .execute(
            "UPDATE threads SET subject = ?1 WHERE id = ?2",
            params![bad, &t.0[..]],
        )
        .unwrap();
    let payload = encode_payload(&[3; 16], &t.0, b"s", b"y").unwrap();
    let into_t = seal_from(&a, &b_bundle, &payload);
    let e = b.core.receive(&into_t).unwrap_err();
    assert!(matches!(e, Error::Corrupt) && !is_permanent(&e));
}

/// `attach_signature` accepts only a DER signature by the own identity key
/// over the letter's digest; a high S is fine.
#[test]
fn attach_refuses_foreign_signature() {
    let (mut a, mut b) = (party(), party());
    let (b_at_a, _) = befriend(&mut a, &mut b);
    let mut letter = a.core.seal_letter(b_at_a, b"s", b"x").unwrap();
    let digest = letter.digest();
    assert_eq!(digest, letter.envelope().id());
    let other = TestKey::new();
    for (name, der) in [
        ("another key", other.sign_digest(&digest)),
        ("another digest", a.key.sign_digest(&[0; 32])),
        ("not DER", vec![0x30, 0x02, 0x01]),
        ("empty", Vec::new()),
        (
            "raw r || s",
            a.key.sign_raw(&letter.envelope().signed_bytes()).to_vec(),
        ),
    ] {
        assert!(
            matches!(
                a.core.attach_signature(&mut letter, &der),
                Err(Error::Signing)
            ),
            "{name}"
        );
        assert!(!letter.is_signed(), "{name}");
    }
    assert!(matches!(a.core.store_sent(&letter), Err(Error::Malformed)));

    let high = a.key.sign_der_high_s(&letter.envelope().signed_bytes());
    a.core.attach_signature(&mut letter, &high).unwrap();
    assert!(letter.is_signed());
    assert_eq!(
        letter.envelope().signature,
        sig::der_to_raw(&high).unwrap(),
        "S kept as signed"
    );
    a.core.store_sent(&letter).unwrap();
    b.core.receive(letter.envelope()).unwrap();
}

/// Accepting a changed key needs the code the app is showing: the code of
/// the pending bundle at that moment.
#[test]
fn accept_is_bound_to_the_shown_code() {
    let (mut a, mut b) = (party(), party());
    let (b_at_a, _) = befriend(&mut a, &mut b);
    let env = send(&mut a, b_at_a, b"s", b"before");
    b.core.receive(&env).unwrap();
    let pinned = a.core.contact_bundle(b_at_a).unwrap();
    // Nothing pending: every code is refused.
    assert!(matches!(
        a.core.accept_new_key(b_at_a, &pinned.code()),
        Err(Error::KeyChanged)
    ));
    // The pinned key again: fine, nothing pending.
    a.core.check_key(b_at_a, &pinned).unwrap();

    let (b1, b2) = (party(), party());
    let (new1, new2) = (b1.core.bundle().unwrap(), b2.core.bundle().unwrap());
    assert!(matches!(
        a.core.check_key(b_at_a, &new1),
        Err(Error::KeyChanged)
    ));
    assert!(a.core.contacts().unwrap()[0].key_changed);
    assert_eq!(a.core.pending_bundle(b_at_a).unwrap(), Some(new1.clone()));
    assert!(matches!(
        a.core.seal_letter(b_at_a, b"s", b"x").map(drop),
        Err(Error::KeyChanged)
    ));
    // Shown: new1's code. The relay swaps in new2 before the click.
    let shown = new1.code();
    assert!(matches!(
        a.core.check_key(b_at_a, &new2),
        Err(Error::KeyChanged)
    ));
    for code in [&shown[..], &pinned.code()[..], &b""[..], &new2.code()[..34]] {
        assert!(matches!(
            a.core.accept_new_key(b_at_a, code),
            Err(Error::KeyChanged)
        ));
    }
    assert_eq!(a.core.contact_bundle(b_at_a).unwrap(), pinned, "unchanged");
    // The code of what is pending now.
    a.core.accept_new_key(b_at_a, &new2.code()).unwrap();
    assert_eq!(a.core.contact_bundle(b_at_a).unwrap(), new2);
    assert_eq!(a.core.pending_bundle(b_at_a).unwrap(), None);
    assert!(!a.core.contacts().unwrap()[0].key_changed);
    // The old thread stays with the contact and still opens.
    let threads = a.core.threads().unwrap();
    assert_eq!(threads.len(), 1);
    assert_eq!(threads[0].contact, b_at_a);
    let m = a.core.messages(threads[0].id).unwrap()[0].id;
    assert_eq!(&a.core.read_body(m).unwrap()[..], b"before");
    // The pinned key back again clears a new pending one.
    assert!(a.core.check_key(b_at_a, &new1).is_err());
    a.core.check_key(b_at_a, &new2).unwrap();
    assert_eq!(a.core.pending_bundle(b_at_a).unwrap(), None);

    // A new key that is another contact's pinned key: `Duplicate`.
    let c = party();
    let c_bundle = c.core.bundle().unwrap();
    a.core.add_contact(&c_bundle, b"carol").unwrap();
    assert!(a.core.check_key(b_at_a, &c_bundle).is_err());
    assert!(matches!(
        a.core.accept_new_key(b_at_a, &c_bundle.code()),
        Err(Error::Duplicate)
    ));
    // The own identity as a new key: `Malformed`.
    let own = a.core.bundle().unwrap();
    assert!(matches!(
        a.core.check_key(b_at_a, &own),
        Err(Error::Malformed)
    ));
}

/// `brev.db` holds no contact's identity id and no address; the own id
/// (plaintext, the unlock check) is found, so the scan reads the file.
#[test]
fn store_holds_no_contact_id_or_address() {
    const MINE: &[u8] = b"own-address-marker-81c2";
    const THEIRS: &[u8] = b"contact-address-marker-4e0f";
    let (mut a, mut b) = (party(), party());
    a.core.set_address(MINE).unwrap();
    let b_at_a = a
        .core
        .add_contact(&b.core.bundle().unwrap(), THEIRS)
        .unwrap();
    b.core
        .add_contact(&a.core.bundle().unwrap(), b"alice")
        .unwrap();
    b.core.receive(&send(&mut a, b_at_a, b"s", b"x")).unwrap();
    // A key change leaves another identity id in `pending`.
    let b2 = party();
    let b2_id = b2.core.bundle().unwrap().id();
    assert!(a
        .core
        .check_key(b_at_a, &b2.core.bundle().unwrap())
        .is_err());
    let own = a.core.bundle().unwrap().id();
    let b_id = b.core.bundle().unwrap().id();
    let bytes = fs::read(&a.path).unwrap();
    for (name, needle) in [
        ("contact id", &b_id.0[..]),
        ("pending id", &b2_id.0[..]),
        ("own address", MINE),
        ("contact address", THEIRS),
    ] {
        assert!(!contains(&bytes, needle), "{name}");
    }
    assert!(contains(&bytes, &own.0), "control: the own id is there");
    // Control: the contact is found by its keyed tag, which is stored.
    let tag = crypto::contact_tag(a.core.dek().unwrap(), &b_id.0);
    assert!(contains(&bytes, &tag));
}

/// The AD of every contact-bound column holds the 16-byte local id, never
/// the identity id, so accepting a new key re-encrypts nothing.
#[test]
fn column_ad_uses_local_contact_id() {
    let (mut a, mut b) = (party(), party());
    let (b_at_a, _) = befriend(&mut a, &mut b);
    let b_id = b.core.bundle().unwrap().id();
    send(&mut a, b_at_a, b"subject", b"body");
    let t = a.core.threads().unwrap()[0].id;
    let dek = *a.core.dek().unwrap();
    let (created_at, subject): (i64, Vec<u8>) = a
        .core
        .db()
        .query_row(
            "SELECT created_at, subject FROM threads WHERE id = ?1",
            [&t.0[..]],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    let local = subject_ad(&t.0, &b_at_a.0, created_at);
    assert_eq!(
        &crypto::open_column(&dek, &local, &subject).unwrap()[..],
        b"subject"
    );
    let by_identity = column_ad(
        "threads.subject",
        &[&t.0, &b_id.0, &created_at.to_be_bytes()],
    );
    assert!(crypto::open_column(&dek, &by_identity, &subject).is_err());
    for column in ["bundle", "address", "pending"] {
        let sealed: Vec<u8> = a
            .core
            .db()
            .query_row(
                &format!("SELECT {column} FROM contacts WHERE id = ?1"),
                [&b_at_a.0[..]],
                |r| r.get(0),
            )
            .unwrap();
        let label = format!("contacts.{column}");
        assert!(crypto::open_column(&dek, &column_ad(&label, &[&b_at_a.0]), &sealed).is_ok());
        assert!(crypto::open_column(&dek, &column_ad(&label, &[&b_id.0]), &sealed).is_err());
    }
    // After a key change is accepted, the history opens unchanged.
    let before: Vec<u8> = a
        .core
        .db()
        .query_row("SELECT subject FROM threads", [], |r| r.get(0))
        .unwrap();
    let b2 = party();
    let new = b2.core.bundle().unwrap();
    assert!(a.core.check_key(b_at_a, &new).is_err());
    a.core.accept_new_key(b_at_a, &new.code()).unwrap();
    let after: Vec<u8> = a
        .core
        .db()
        .query_row("SELECT subject FROM threads", [], |r| r.get(0))
        .unwrap();
    assert_eq!(before, after, "no re-encryption");
    assert_eq!(&a.core.threads().unwrap()[0].subject[..], b"subject");
}
