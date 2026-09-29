//! Phase 1 invariants through the public `Core` API, with P-256 identity
//! keys, local contact ids and the `MockTransport`: round trip, tamper, no
//! plaintext on disk, lock, plus the store-integrity and hygiene checks.
//! (The DEK-zeroed half of the lock test, the pragma readback and the SQL
//! trace are unit tests in `store/tests.rs`, because their accessors are
//! cfg(test) only.)

mod common;

use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use brev_core::{
    ContactId, Core, Envelope, Error, Letter, MessageId, MockTransport, PublicBundle, Transport,
};
use brev_proto::sig;
use common::{contains, random, unix_now, TempDir, TestKey};

struct Party {
    core: Core,
    dek: [u8; 32],
    net: MockTransport,
    key: TestKey,
}

fn make(dir: &Path, name: &str, net: MockTransport) -> Party {
    let dek = random();
    let key = TestKey::new();
    let mut core = Core::create(&dir.join(name), &mut dek.clone(), &key.public).unwrap();
    core.confirm_active().unwrap();
    Party {
        core,
        dek,
        net,
        key,
    }
}

/// `dir/name`, a new folder with mode 0700.
fn sub(dir: &Path, name: &str) -> PathBuf {
    let p = dir.join(name);
    fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
    p
}

/// A and B, each in its own folder in `dir` (a store locks its folder),
/// each with the other as a contact.
fn pair(dir: &Path) -> (Party, Party, ContactId, ContactId) {
    let (net_a, net_b) = MockTransport::pair();
    let mut a = make(&sub(dir, "a"), "a.db", net_a);
    let mut b = make(&sub(dir, "b"), "b.db", net_b);
    let b_at_a = a
        .core
        .add_contact(&b.core.bundle().unwrap(), b"bob")
        .unwrap();
    let a_at_b = b
        .core
        .add_contact(&a.core.bundle().unwrap(), b"alice")
        .unwrap();
    (a, b, b_at_a, a_at_b)
}

/// A valid bundle nobody holds the keys of.
fn stranger() -> PublicBundle {
    PublicBundle::new(&TestKey::new().public, random()).unwrap()
}

/// Drafts, makes the class-A token and seals, signs (the test key stands in
/// for the Enclave), stores the own copy and hands the envelope to the
/// transport.
fn send(from: &mut Party, to: ContactId, subject: &[u8], body: &[u8]) -> Envelope {
    let draft = from.core.draft(to, subject, body).unwrap();
    let token = from.key.token(draft.letter());
    let mut letter = from.core.seal_letter(&draft, &token).unwrap();
    let der = from.key.sign_digest(&letter.digest());
    from.core.attach_signature(&mut letter, &der).unwrap();
    from.core.store_sent(&letter).unwrap();
    from.net.send(letter.envelope()).unwrap();
    letter.envelope().clone()
}

/// A letter to `to` with no token (its check fails; it is stored anyway).
fn unsigned(from: &Party, to: ContactId, subject: &[u8], body: &[u8]) -> Letter {
    let draft = from.core.draft(to, subject, body).unwrap();
    from.core.seal_letter(&draft, &[]).unwrap()
}

/// Polls, receives the first waiting envelope and acknowledges it.
fn receive_one(p: &mut Party) -> MessageId {
    let inbox = p.net.poll().unwrap();
    let (at, env) = &inbox[0];
    let m = p.core.receive(env, *at).unwrap();
    p.net.ack(&[env.id()]).unwrap();
    m
}

#[test]
fn round_trip_a_encrypts_b_decrypts() {
    let dir = TempDir::new();
    let (mut a, mut b, b_at_a, a_at_b) = pair(&dir.0);
    // Each store generates its own X25519 identity.
    assert_ne!(
        a.core.bundle().unwrap().x25519,
        b.core.bundle().unwrap().x25519
    );
    let body = "Hei Bob, dette er et brev. Blåbær.".as_bytes();
    send(&mut a, b_at_a, b"Hei", body);

    let inbox = b.net.poll().unwrap();
    assert_eq!(inbox.len(), 1);
    let m = b.core.receive(&inbox[0].1, inbox[0].0).unwrap();
    b.net.ack(&[inbox[0].1.id()]).unwrap();
    assert!(b.net.poll().unwrap().is_empty());
    // The token checks out with A's pinned key: class A.
    let proof = b.core.proof(m).unwrap().unwrap();
    assert!(proof.passed(), "{proof:?}");
    assert_eq!(proof.class(), Some(brev_hand::EnvironmentClass::A));

    let threads = b.core.threads().unwrap();
    assert_eq!(threads.len(), 1);
    let t = threads[0].id;
    assert_eq!(threads[0].contact, a_at_b);
    assert_eq!(&threads[0].subject[..], b"Hei");
    let got = b.core.messages(t).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].id, m);
    assert!(!got[0].outgoing && !got[0].read);
    assert_eq!(&b.core.read_body(m).unwrap()[..], body);

    // The sender's own copy has the same thread and message ids and reads
    // back.
    let mine = a.core.threads().unwrap();
    assert_eq!((mine[0].id, mine[0].contact), (t, b_at_a));
    let mine = a.core.messages(t).unwrap();
    assert_eq!(mine[0].id, m);
    assert!(mine[0].outgoing && mine[0].read);
    assert_eq!(&a.core.read_body(m).unwrap()[..], body);

    // A letter the other way starts its own thread.
    send(&mut b, a_at_b, b"Svar", b"Takk!");
    let reply = receive_one(&mut a);
    let threads = a.core.threads().unwrap();
    assert_eq!(threads.len(), 2);
    assert_eq!(a.core.thread_of(reply).unwrap(), threads[1].id);
    assert_eq!(&threads[1].subject[..], b"Svar");
    assert_eq!(&a.core.read_body(reply).unwrap()[..], b"Takk!");

    // mark_read flags that message only, and the flag is not bound to the body.
    send(&mut b, a_at_b, b"Igjen", b"Og en til.");
    let third = receive_one(&mut a);
    a.core.mark_read(reply).unwrap();
    let flags = |id| {
        let t = a.core.thread_of(id).unwrap();
        a.core.messages(t).unwrap()[0].read
    };
    assert!(flags(reply) && !flags(third));
    assert_eq!(&a.core.read_body(reply).unwrap()[..], b"Takk!");
}

#[test]
fn tamper_any_flipped_byte_fails() {
    let dir = TempDir::new();
    let (mut a, mut b, b_at_a, _) = pair(&dir.0);
    let env = send(&mut a, b_at_a, b"s", b"body");
    for i in 0..env.ciphertext.len() {
        let mut bad = env.clone();
        bad.ciphertext[i] ^= 0x01;
        assert!(
            matches!(b.core.receive(&bad, unix_now()), Err(Error::Crypto)),
            "ciphertext byte {i}"
        );
    }
    let mut bad = env.clone();
    bad.nonce[0] ^= 0x01;
    assert!(matches!(
        b.core.receive(&bad, unix_now()),
        Err(Error::Crypto)
    ));
    for i in [0, 31, 32, 63] {
        let mut bad = env.clone();
        bad.signature[i] ^= 0x01;
        assert!(
            matches!(b.core.receive(&bad, unix_now()), Err(Error::Crypto)),
            "signature byte {i}"
        );
    }
    assert!(
        b.core.threads().unwrap().is_empty(),
        "nothing stored from a failed check"
    );
    b.core.receive(&env, unix_now()).unwrap();
}

#[test]
fn no_plaintext_in_any_file() {
    const ADDRESS: &[u8] = b"brev-address-marker-3b8e61";
    const SUBJECT: &[u8] = b"BREV-SUBJECT-MARKER-94d0a7";
    const BODY: &[u8] = b"BREV-BODY-MARKER-c25f18";
    let markers = [ADDRESS, SUBJECT, BODY];
    let dir = TempDir::new();
    let (mut a, mut b, b_at_a, a_at_b) = pair(&dir.0);
    b.core.add_contact(&stranger(), ADDRESS).unwrap();
    let env = send(&mut a, b_at_a, SUBJECT, BODY);
    let wire = env.to_wire().unwrap();
    for m in markers {
        assert!(!contains(&wire, m), "marker in envelope bytes");
    }
    let m = receive_one(&mut b);
    b.core.mark_read(m).unwrap();
    send(&mut b, a_at_b, SUBJECT, BODY);
    receive_one(&mut a);

    // Not vacuous: the content really went in and comes back out.
    assert_eq!(&b.core.read_body(m).unwrap()[..], BODY);
    assert_eq!(&b.core.threads().unwrap()[0].subject[..], SUBJECT);
    assert!(b
        .core
        .contacts()
        .unwrap()
        .iter()
        .any(|c| &c.address[..] == ADDRESS));

    let own = b.core.bundle().unwrap().id();
    let scan = |when: &str| {
        let mut saw_id = false;
        for entry in common::walk(&dir.0) {
            let path = entry.unwrap().path();
            let bytes = fs::read(&path).unwrap();
            for m in markers {
                assert!(!contains(&bytes, m), "{when}: marker in {}", path.display());
            }
            saw_id |= contains(&bytes, &own.0);
        }
        // Positive control: a plaintext id is visible, so the scan reads store data.
        assert!(saw_id, "{when}: control id not found");
    };
    scan("open");
    drop(a);
    drop(b);
    scan("closed");
    assert_eq!(
        TempDir::files(&dir),
        ["a.db", "b.db"],
        "no journal, WAL or SHM left behind"
    );

    // Positive control: a marker that SQLite *is* given shows up in the scan.
    let raw = rusqlite::Connection::open(dir.0.join("b/b.db")).unwrap();
    raw.execute_batch("CREATE TABLE leak (v BLOB)").unwrap();
    raw.execute("INSERT INTO leak VALUES (?1)", [BODY]).unwrap();
    drop(raw);
    assert!(contains(&fs::read(dir.0.join("b/b.db")).unwrap(), BODY));
}

#[test]
fn locked_core_refuses_every_content_call() {
    let dir = TempDir::new();
    let (mut a, mut b, b_at_a, a_at_b) = pair(&dir.0);
    let env = send(&mut a, b_at_a, b"s", b"x");
    let t = a.core.threads().unwrap()[0].id;
    let msg = a.core.messages(t).unwrap()[0].id;
    // An unread letter from B, to show that a locked mark_read writes nothing.
    receive_one(&mut b);
    send(&mut b, a_at_b, b"s", b"y");
    let unread = receive_one(&mut a);
    let draft = a.core.draft(b_at_a, b"s", b"z").unwrap();
    let mut letter = a.core.seal_letter(&draft, &[]).unwrap();
    let der = a.key.sign_digest(&letter.digest());

    a.core.lock();
    assert!(a.core.is_locked());
    let locked = |r: Result<(), Error>| assert!(matches!(r, Err(Error::Locked)));
    locked(a.core.bundle().map(drop));
    locked(a.core.address().map(drop));
    locked(a.core.is_registered().map(drop));
    locked(a.core.set_address(b"anna"));
    locked(a.core.registration(b"anna", &[1; 32], &[2; 32]).map(drop));
    locked(a.core.relay_token().map(drop));
    locked(a.core.verify_own(b"x", &der).map(drop));
    locked(a.core.check_new_address(b"carl"));
    locked(a.core.add_contact(&stranger(), b"carl").map(drop));
    locked(a.core.contacts().map(drop));
    locked(a.core.contact_address(b_at_a).map(drop));
    locked(a.core.contact_bundle(b_at_a).map(drop));
    locked(a.core.pending_bundle(b_at_a).map(drop));
    locked(a.core.check_key(b_at_a, &stranger()));
    locked(a.core.accept_new_key(b_at_a, &[b'A'; 35]));
    locked(a.core.draft(b_at_a, b"s", b"y").map(drop));
    locked(a.core.seal_letter(&draft, &[]).map(drop));
    locked(a.core.attach_signature(&mut letter, &der));
    locked(a.core.store_sent(&letter).map(drop));
    locked(a.core.threads().map(drop));
    locked(a.core.messages(t).map(drop));
    locked(a.core.read_body(msg).map(drop));
    locked(a.core.proof(unread).map(drop));
    locked(a.core.thread_of(msg).map(drop));
    locked(a.core.mark_read(unread));
    locked(a.core.receive(&env, unix_now()).map(drop));

    assert!(matches!(a.core.unlock(&mut random()), Err(Error::WrongKey)));
    assert!(matches!(a.core.unlock(&mut [0; 32]), Err(Error::WrongKey)));
    assert!(a.core.is_locked());

    // Reopen from disk: starts locked, the right DEK opens it again.
    let path = dir.0.join("a/a.db");
    drop(a.core);
    let mut again = Core::open(&path).unwrap();
    assert!(again.is_locked());
    assert!(matches!(again.threads().map(drop), Err(Error::Locked)));
    let mut dek = a.dek;
    again.unlock(&mut dek).unwrap();
    again.confirm_active().unwrap();
    assert_eq!(dek, [0u8; 32]);
    assert_eq!(&again.read_body(msg).unwrap()[..], b"x");
    let ut = again.thread_of(unread).unwrap();
    assert!(
        again
            .messages(ut)
            .unwrap()
            .iter()
            .any(|m| m.id == unread && !m.read),
        "a locked mark_read wrote nothing"
    );
}

/// The envelope carries a P-256 signature by the sender's identity key over
/// its signed bytes; a signature by any other key is refused before
/// anything is stored.
#[test]
fn signature_is_by_the_identity_key_and_signing_can_fail() {
    let dir = TempDir::new();
    let (mut a, _b, b_at_a, _) = pair(&dir.0);
    let env = send(&mut a, b_at_a, b"s", b"x");
    assert_eq!(a.core.bundle().unwrap().signing_key, a.key.public);
    let signature: &[u8; 64] = env.signature.as_slice().try_into().unwrap();
    sig::verify(&a.key.public, &env.signed_bytes(), signature).unwrap();
    let mut bad = env.clone();
    bad.ciphertext[0] ^= 1;
    assert!(sig::verify(&a.key.public, &bad.signed_bytes(), signature).is_err());

    // A signature from another key (a replaced keychain item), over
    // another message, or not DER: `Signing`, and nothing is stored.
    let mut letter = unsigned(&a, b_at_a, b"s", b"y");
    for der in [
        TestKey::new().sign_digest(&letter.digest()),
        a.key.sign_digest(&[1; 32]),
        vec![0x30, 0x00],
    ] {
        assert!(matches!(
            a.core.attach_signature(&mut letter, &der),
            Err(Error::Signing)
        ));
    }
    assert!(matches!(
        a.core.store_sent(&letter).map(drop),
        Err(Error::Malformed)
    ));
    assert_eq!(a.core.threads().unwrap().len(), 1, "nothing stored");
    // The signature over the digest equals one over the signed bytes.
    let der = a.key.sign_der(&letter.envelope().signed_bytes());
    a.core.attach_signature(&mut letter, &der).unwrap();
    assert!(letter.is_signed());
}

#[test]
fn receive_rejects_strangers_misrouted_self_and_replays() {
    let dir = TempDir::new();
    let (mut a, mut b, b_at_a, _) = pair(&dir.0);
    // C knows B's bundle, but B has not added C.
    let mut c = make(&dir.0, "c.db", MockTransport::pair().0);
    let b_at_c = c
        .core
        .add_contact(&b.core.bundle().unwrap(), b"bob")
        .unwrap();
    let from_c = send(&mut c, b_at_c, b"s", b"x");
    let now = unix_now();
    assert!(matches!(b.core.receive(&from_c, now), Err(Error::NotFound)));

    // An envelope for B handed to A.
    let env = send(&mut a, b_at_a, b"s", b"x");
    assert!(matches!(a.core.receive(&env, now), Err(Error::Malformed)));

    // Replay: stored once, also when the relay stamps it again later.
    let m = b.core.receive(&env, now).unwrap();
    assert!(matches!(b.core.receive(&env, now), Err(Error::Duplicate)));
    assert!(matches!(
        b.core.receive(&env, now + 3600),
        Err(Error::Duplicate)
    ));
    let t = b.core.thread_of(m).unwrap();
    assert_eq!(b.core.messages(t).unwrap().len(), 1);

    // Own identity and own address are not contacts; a contact is added
    // once, by identity and by address.
    let me = a.core.bundle().unwrap();
    assert!(matches!(
        a.core.add_contact(&me, b"myself"),
        Err(Error::Malformed)
    ));
    a.core.set_address(b"alice").unwrap();
    assert!(matches!(
        a.core.add_contact(&stranger(), b"alice"),
        Err(Error::Malformed)
    ));
    assert!(matches!(
        a.core.add_contact(&b.core.bundle().unwrap(), b"bob-2"),
        Err(Error::Duplicate)
    ));
    assert!(matches!(
        a.core.add_contact(&stranger(), b"bob"),
        Err(Error::Duplicate)
    ));
    // Addresses follow the rules.
    for bad in [
        &b"ab"[..],
        b"Bob",
        b"1bob",
        b"-bob",
        b"bo_b",
        "blåbær".as_bytes(),
    ] {
        assert!(matches!(
            a.core.add_contact(&stranger(), bad),
            Err(Error::Malformed)
        ));
    }
    // A signing key must be an uncompressed P-256 point.
    let good = TestKey::new().public;
    let mut off_curve = good;
    off_curve[64] ^= 1;
    for key in [&[][..], &[4; 65], &off_curve, &good[..64], &good[1..]] {
        assert!(matches!(
            PublicBundle::new(key, random()),
            Err(Error::Malformed)
        ));
    }
    assert_eq!(a.core.contacts().unwrap().len(), 1);

    // A letter needs a contact; a subject over 65535 bytes is refused and
    // makes nothing; an unknown message cannot be marked read.
    assert!(matches!(
        a.core.draft(ContactId([9; 16]), b"s", b"x").map(drop),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        a.core.draft(b_at_a, &[0; 65536], b"x").map(drop),
        Err(Error::Malformed)
    ));
    assert_eq!(a.core.threads().unwrap().len(), 1);
    assert!(matches!(
        a.core.mark_read(MessageId([0; 16])),
        Err(Error::NotFound)
    ));
}

/// `poll` deletes nothing; `ack` deletes exactly the listed envelopes. Like
/// the relay, the transport stamps each envelope with the time it got it:
/// the system clock, or the time a test set.
#[test]
fn mock_transport_keeps_letters_until_acked() {
    let dir = TempDir::new();
    let (mut a, b, b_at_a, _) = pair(&dir.0);
    let before = unix_now();
    let first = send(&mut a, b_at_a, b"s", b"1");
    a.net.set_time(Some(1_790_000_000));
    let second = send(&mut a, b_at_a, b"s", b"2");
    let polled = b.net.poll().unwrap();
    assert_eq!(polled[1], (1_790_000_000, second.clone()));
    assert_eq!(polled[0].1, first);
    assert!((before..=unix_now()).contains(&polled[0].0));
    assert_eq!(b.net.poll().unwrap().len(), 2, "poll deletes nothing");
    b.net.ack(&[first.id(), [0; 32]]).unwrap();
    assert_eq!(b.net.poll().unwrap(), [(1_790_000_000, second.clone())]);
    b.net.ack(&[second.id()]).unwrap();
    assert!(b.net.poll().unwrap().is_empty());
    assert!(
        a.net.poll().unwrap().is_empty(),
        "each end has its own inbox"
    );
}

/// A filesystem agent that edits plaintext metadata cannot redirect,
/// move or relabel content: each edit makes the affected read fail.
#[test]
fn stored_metadata_is_bound_to_ciphertext() {
    let dir = TempDir::new();
    let (mut a, _b, b_at_a, _) = pair(&dir.0);
    let m = make(&dir.0, "m.db", MockTransport::pair().0);
    let m_at_a = a
        .core
        .add_contact(&m.core.bundle().unwrap(), b"mallory")
        .unwrap();
    send(&mut a, b_at_a, b"s", b"first");
    send(&mut a, b_at_a, b"s2", b"second");
    send(&mut a, m_at_a, b"s3", b"third");
    let threads = a.core.threads().unwrap();
    let (t, t2, other) = (threads[0].id, threads[1].id, threads[2].id);
    drop(threads);
    let ids: Vec<_> = [t, t2]
        .iter()
        .map(|t| a.core.messages(*t).unwrap()[0].id)
        .collect();
    // Each thread lists only its own messages.
    assert!(a.core.messages(other).unwrap()[0].id != ids[0]);
    let raw = rusqlite::Connection::open(dir.0.join("a/a.db")).unwrap();
    let sql = |q: &str, p: &[&[u8]]| {
        raw.execute(q, rusqlite::params_from_iter(p.iter()))
            .unwrap();
    };
    // Swaps one column between two rows; a second call undoes it. A
    // UNIQUE column (the tag) passes through a placeholder.
    let swap = |table: &str, column: &str, x: &[u8], y: &[u8]| {
        let get = |id: &[u8]| -> rusqlite::types::Value {
            let q = format!("SELECT {column} FROM {table} WHERE id = ?1");
            raw.query_row(&q, [id], |r| r.get(0)).unwrap()
        };
        let (vx, vy) = (get(x), get(y));
        let set = format!("UPDATE {table} SET {column} = ?1 WHERE id = ?2");
        if column == "tag" {
            raw.execute(&set, rusqlite::params![&[0u8; 32][..], x])
                .unwrap();
        }
        raw.execute(&set, rusqlite::params![vx, y]).unwrap();
        raw.execute(&set, rusqlite::params![vy, x]).unwrap();
    };

    // Re-point B's thread at Mallory: its subject and body no longer open.
    sql(
        "UPDATE threads SET contact_id = ?1 WHERE id = ?2",
        &[&m_at_a.0, &t.0],
    );
    assert!(matches!(a.core.threads().map(drop), Err(Error::Crypto)));
    assert!(matches!(
        a.core.read_body(ids[0]).map(drop),
        Err(Error::Crypto)
    ));
    sql(
        "UPDATE threads SET contact_id = ?1 WHERE id = ?2",
        &[&b_at_a.0, &t.0],
    );

    // Move a message to another thread: one with another contact, and one
    // with the same contact, which only the thread id in the AD catches.
    let move_to = "UPDATE messages SET thread_id = ?2 WHERE id = ?1";
    for dest in [other, t2] {
        sql(move_to, &[&ids[0].0, &dest.0]);
        assert!(matches!(
            a.core.read_body(ids[0]).map(drop),
            Err(Error::Crypto)
        ));
        sql(move_to, &[&ids[0].0, &t.0]);
        assert_eq!(&a.core.read_body(ids[0]).unwrap()[..], b"first");
    }

    // Flip its direction, change its time.
    for (edit, undo) in [
        (
            "UPDATE messages SET outgoing = 0 WHERE id = ?1",
            "UPDATE messages SET outgoing = 1 WHERE id = ?1",
        ),
        (
            "UPDATE messages SET created_at = created_at + 1 WHERE id = ?1",
            "UPDATE messages SET created_at = created_at - 1 WHERE id = ?1",
        ),
    ] {
        sql(edit, &[&ids[0].0]);
        assert!(
            matches!(a.core.read_body(ids[0]).map(drop), Err(Error::Crypto)),
            "{edit}"
        );
        sql(undo, &[&ids[0].0]);
        assert_eq!(&a.core.read_body(ids[0]).unwrap()[..], b"first");
    }

    // A subject is bound to its thread's time and id: change the time, or
    // give another thread with the same contact this subject and time.
    sql(
        "UPDATE threads SET created_at = created_at + 1 WHERE id = ?1",
        &[&t.0],
    );
    assert!(matches!(a.core.threads().map(drop), Err(Error::Crypto)));
    sql(
        "UPDATE threads SET created_at = created_at - 1 WHERE id = ?1",
        &[&t.0],
    );
    for column in ["subject", "created_at"] {
        swap("threads", column, &t.0, &t2.0);
    }
    assert!(matches!(a.core.threads().map(drop), Err(Error::Crypto)));
    for column in ["subject", "created_at"] {
        swap("threads", column, &t.0, &t2.0);
    }
    assert_eq!(a.core.threads().unwrap().len(), 3);

    // Contact rows are bound to their local id. Bob's and Mallory's
    // bundles swapped: nothing is sealed to Mallory as Bob. Their tags
    // swapped: the bundle no longer matches the tag, and the flags, sealed
    // with the tag, do not open. Their addresses swapped: Mallory is not
    // shown as Bob.
    swap("contacts", "bundle", &b_at_a.0, &m_at_a.0);
    assert!(matches!(
        a.core.draft(b_at_a, b"s", b"secret").map(drop),
        Err(Error::Crypto)
    ));
    swap("contacts", "bundle", &b_at_a.0, &m_at_a.0);
    swap("contacts", "tag", &b_at_a.0, &m_at_a.0);
    assert!(matches!(
        a.core.contact_bundle(b_at_a).map(drop),
        Err(Error::Corrupt)
    ));
    assert!(matches!(
        a.core.draft(b_at_a, b"s", b"secret").map(drop),
        Err(Error::Crypto)
    ));
    swap("contacts", "tag", &b_at_a.0, &m_at_a.0);
    for column in ["address", "pending"] {
        swap("contacts", column, &b_at_a.0, &m_at_a.0);
        assert!(
            matches!(a.core.contacts().map(drop), Err(Error::Crypto)),
            "{column}"
        );
        swap("contacts", column, &b_at_a.0, &m_at_a.0);
    }
    assert_eq!(a.core.contacts().unwrap().len(), 2);

    // Swap ciphertext between rows and between columns.
    sql(
        "UPDATE messages SET body = (SELECT body FROM messages WHERE id = ?2) WHERE id = ?1",
        &[&ids[0].0, &ids[1].0],
    );
    assert!(matches!(
        a.core.read_body(ids[0]).map(drop),
        Err(Error::Crypto)
    ));
    sql(
        "UPDATE contacts SET address = (SELECT subject FROM threads WHERE id = ?2) WHERE id = ?1",
        &[&b_at_a.0, &t.0],
    );
    assert!(matches!(a.core.contacts().map(drop), Err(Error::Crypto)));
    sql(
        "UPDATE identity SET address = (SELECT address FROM contacts WHERE id = ?1)",
        &[&m_at_a.0],
    );
    assert!(matches!(a.core.address().map(drop), Err(Error::Crypto)));

    // The identity row is bound to the own id: with the id edited, the
    // right DEK no longer unlocks, so no envelope carries a forged sender.
    let own: Vec<u8> = raw
        .query_row("SELECT id FROM identity", [], |r| r.get(0))
        .unwrap();
    sql("UPDATE identity SET id = ?1", &[&[7u8; 32]]);
    a.core.lock();
    assert!(matches!(
        a.core.unlock(&mut a.dek.clone()),
        Err(Error::WrongKey)
    ));
    sql("UPDATE identity SET id = ?1", &[&own[..]]);
    a.core.unlock(&mut a.dek.clone()).unwrap();
    a.core.confirm_active().unwrap();
}

#[test]
fn create_and_open_refuse_bad_files() {
    let dir = TempDir::new();
    let key = TestKey::new().public;

    // The caller's DEK is wiped even when create fails before touching disk.
    let mut dek: [u8; 32] = random();
    let r = Core::create(&dir.0.join("no/such/dir.db"), &mut dek, &key);
    assert!(matches!(r, Err(Error::Io(_))));
    assert_eq!(dek, [0u8; 32]);
    // Retrying with the same (now zeroed) buffer must not seal a store under
    // the all-zero key.
    let r = Core::create(&dir.0.join("z.db"), &mut dek, &key);
    assert!(matches!(r, Err(Error::Malformed)));
    assert!(!dir.0.join("z.db").exists());

    // Only absolute paths: SQLite would read `file:` names as URIs.
    let uri = format!("file:{}?mode=ro", dir.0.join("u.db").display());
    // Each early refusal wipes the DEK too.
    for p in ["file:u.db", uri.as_str(), "u.db", ":memory:", ""] {
        dek = random();
        let r = Core::create(Path::new(p), &mut dek, &key);
        assert!(matches!(r, Err(Error::Malformed)), "create {p:?}");
        assert_eq!(dek, [0u8; 32], "create {p:?}");
        assert!(
            matches!(Core::open(Path::new(p)).map(drop), Err(Error::Malformed)),
            "open {p:?}"
        );
    }
    assert!(!Path::new("file:u.db").exists() && !Path::new("u.db").exists());
    // The signing key must be an uncompressed P-256 point.
    let mut off_curve = key;
    off_curve[64] ^= 1;
    for bad in [&[][..], &[1; 32], &[4; 65], &off_curve, &key[..64]] {
        dek = random();
        let r = Core::create(&dir.0.join("x.db"), &mut dek, bad);
        assert!(matches!(r, Err(Error::Malformed)));
        assert_eq!(dek, [0u8; 32]);
        assert!(!dir.0.join("x.db").exists());
    }

    // A failure after the file is made (a directory where the rollback
    // journal goes) removes the file.
    fs::create_dir(dir.0.join("j.db-journal")).unwrap();
    let r = Core::create(&dir.0.join("j.db"), &mut random(), &key);
    assert!(matches!(r, Err(Error::Storage(_))));
    assert!(!dir.0.join("j.db").exists());

    // create refuses an existing store and leaves it untouched.
    let path = dir.0.join("a.db");
    drop(make(&dir.0, "a.db", MockTransport::pair().0));
    let before = fs::read(&path).unwrap();
    match Core::create(&path, &mut random(), &key) {
        Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        _ => panic!("create reused an existing file"),
    }
    assert_eq!(fs::read(&path).unwrap(), before);

    // A URI to a real store is refused too, not opened read-only.
    let uri = format!("file:{}?mode=ro", path.display());
    assert!(matches!(
        Core::open(Path::new(&uri)).map(drop),
        Err(Error::Malformed)
    ));

    // open refuses a foreign SQLite file without writing to it.
    let foreign = dir.0.join("foreign.db");
    rusqlite::Connection::open(&foreign)
        .unwrap()
        .execute_batch("CREATE TABLE t (x BLOB)")
        .unwrap();
    let before = fs::read(&foreign).unwrap();
    assert!(matches!(
        Core::open(&foreign).map(drop),
        Err(Error::Corrupt)
    ));
    assert_eq!(fs::read(&foreign).unwrap(), before);

    // The same for a WAL-mode file (switching it to DELETE mode would
    // rewrite it), a file that is not SQLite at all, a truncated store, and
    // a store whose header names a schema format SQLite does not support.
    let wal = dir.0.join("wal.db");
    let c = rusqlite::Connection::open(&wal).unwrap();
    let mode: String = c
        .query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
    c.execute_batch("CREATE TABLE t (x BLOB)").unwrap();
    drop(c);
    let junk = dir.0.join("junk.db");
    fs::write(&junk, random::<64>().repeat(100)).unwrap();
    let short = dir.0.join("short.db");
    let mut store = fs::read(&path).unwrap();
    fs::write(&short, &store[..store.len() / 2]).unwrap();
    let format = dir.0.join("format.db");
    store[44..48].copy_from_slice(&5u32.to_be_bytes()); // schema format number
    fs::write(&format, &store).unwrap();
    for file in [wal, junk, short, format] {
        let before = fs::read(&file).unwrap();
        assert!(
            matches!(Core::open(&file).map(drop), Err(Error::Corrupt)),
            "{}",
            file.display()
        );
        assert_eq!(fs::read(&file).unwrap(), before, "{}", file.display());
    }

    // open refuses a store whose header names another application or
    // schema version (2 is Phase 2's).
    for (pragma, bad) in [("application_id", 1), ("user_version", 2)] {
        let raw = rusqlite::Connection::open(&path).unwrap();
        let good: i32 = raw.pragma_query_value(None, pragma, |r| r.get(0)).unwrap();
        raw.pragma_update(None, pragma, bad).unwrap();
        assert!(
            matches!(Core::open(&path).map(drop), Err(Error::Corrupt)),
            "{pragma}"
        );
        raw.pragma_update(None, pragma, good).unwrap();
        drop(Core::open(&path).unwrap());
    }

    // open refuses a store with a table redefined under the same name.
    let altered = dir.0.join("altered.db");
    fs::copy(&path, &altered).unwrap();
    rusqlite::Connection::open(&altered)
        .unwrap()
        .execute_batch("ALTER TABLE contacts ADD COLUMN note BLOB")
        .unwrap();
    assert!(matches!(
        Core::open(&altered).map(drop),
        Err(Error::Corrupt)
    ));

    // open refuses a store with a planted trigger.
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute_batch("CREATE TRIGGER t AFTER INSERT ON messages BEGIN DELETE FROM messages; END;")
        .unwrap();
    assert!(matches!(Core::open(&path).map(drop), Err(Error::Corrupt)));

    // open never creates a file.
    let missing = dir.0.join("missing.db");
    assert!(Core::open(&missing).is_err());
    assert!(!missing.exists());
}

/// WAL mode is saved in the file, so an agent can switch a store to it;
/// `open` switches it back, and writes leave no -wal or -shm file.
#[test]
fn open_turns_a_wal_store_back_to_delete_mode() {
    let dir = TempDir::new();
    let a = make(&dir.0, "a.db", MockTransport::pair().0);
    let mut dek = a.dek;
    drop(a);
    let raw = rusqlite::Connection::open(dir.0.join("a.db")).unwrap();
    let mode: String = raw
        .query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
    drop(raw);

    let mut core = Core::open(&dir.0.join("a.db")).unwrap();
    core.unlock(&mut dek).unwrap();
    core.confirm_active().unwrap();
    core.add_contact(&stranger(), b"someone").unwrap();
    assert_eq!(TempDir::files(&dir), ["a.db"]);
}

#[test]
fn core_and_transport_can_move_between_threads() {
    fn send_bound<T: Send>() {}
    fn shared_bound<T: Send + Sync>() {}
    send_bound::<Core>();
    send_bound::<brev_core::Draft>();
    send_bound::<brev_core::Letter>();
    shared_bound::<MockTransport>();
}
