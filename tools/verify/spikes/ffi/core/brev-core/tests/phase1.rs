//! Phase 1 invariants through the public API: round trip, tamper, no
//! plaintext on disk, lock, plus the store-integrity and hygiene checks. (The
//! DEK-zeroed half of the lock test, the pragma readback and the SQL trace
//! are unit tests in `store.rs`, because their accessors are cfg(test) only.)

use std::fs;
use std::path::{Path, PathBuf};

use brev_core::{
    Core, Envelope, Error, IdentityId, MessageId, MockTransport, PublicBundle, Signer, ThreadId,
    Transport,
};
use ed25519_dalek::{Signature, SigningKey};
use rand::rngs::SysRng;
use rand::TryRng;

fn random<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    SysRng.try_fill_bytes(&mut out).unwrap();
    out
}

/// A fresh directory under the system temp dir, removed on drop.
struct TempDir(PathBuf);
impl TempDir {
    fn new() -> TempDir {
        let p =
            std::env::temp_dir().join(format!("brev-test-{:016x}", u64::from_le_bytes(random())));
        fs::create_dir(&p).unwrap();
        TempDir(p)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Ed25519 test key for the signature slot (dev-dependency only).
struct TestSigner(SigningKey);
impl Signer for TestSigner {
    fn sign(&self, signed_bytes: &[u8]) -> Result<Vec<u8>, Error> {
        use ed25519_dalek::Signer as _;
        Ok(self.0.sign(signed_bytes).to_bytes().to_vec())
    }
}

struct Party {
    core: Core,
    dek: [u8; 32],
    net: MockTransport,
    signer: TestSigner,
}

fn make(dir: &Path, name: &str, net: MockTransport) -> Party {
    let dek = random();
    let signer = TestSigner(SigningKey::from_bytes(&random()));
    let vk = signer.0.verifying_key().to_bytes();
    let core = Core::create(&dir.join(name), &mut dek.clone(), &vk).unwrap();
    Party {
        core,
        dek,
        net,
        signer,
    }
}

/// A and B in one directory, each with the other as a contact.
fn pair(dir: &Path) -> (Party, Party, IdentityId, IdentityId) {
    let (net_a, net_b) = MockTransport::pair();
    let mut a = make(dir, "a.db", net_a);
    let mut b = make(dir, "b.db", net_b);
    let b_at_a = a
        .core
        .add_contact(&b.core.bundle().unwrap(), b"Bob")
        .unwrap();
    let a_at_b = b
        .core
        .add_contact(&a.core.bundle().unwrap(), b"Alice")
        .unwrap();
    (a, b, b_at_a, a_at_b)
}

fn stranger() -> PublicBundle {
    PublicBundle {
        signing_key: vec![1; 32],
        x25519: random(),
    }
}

fn send(from: &mut Party, thread: ThreadId, body: &[u8]) -> Envelope {
    let env = from.core.send(thread, body, &from.signer).unwrap();
    from.net.send(env.clone());
    env
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
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
    let t = a.core.new_thread(b_at_a, b"Hei").unwrap();
    send(&mut a, t, body);

    let inbox = b.net.poll();
    assert_eq!(inbox.len(), 1);
    let m = b.core.receive(&inbox[0]).unwrap();

    let threads = b.core.threads().unwrap();
    assert_eq!(threads.len(), 1);
    assert_eq!(threads[0].id, t);
    assert_eq!(threads[0].contact, a_at_b);
    assert_eq!(&threads[0].subject[..], b"Hei");
    let got = b.core.messages(t).unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].id, m);
    assert!(!got[0].outgoing && !got[0].read);
    assert_eq!(&b.core.read_body(m).unwrap()[..], body);

    // The sender's own copy has the same id and reads back.
    let mine = a.core.messages(t).unwrap();
    assert_eq!(mine[0].id, m);
    assert!(mine[0].outgoing && mine[0].read);
    assert_eq!(&a.core.read_body(m).unwrap()[..], body);

    // A reply in the same thread goes the other way.
    send(&mut b, t, b"Takk!");
    a.core.receive(&a.net.poll()[0]).unwrap();
    let mine = a.core.messages(t).unwrap();
    assert_eq!(mine.len(), 2);
    assert!(mine[0].outgoing && !mine[1].outgoing);
    assert_eq!(&a.core.read_body(mine[1].id).unwrap()[..], b"Takk!");

    // mark_read flags that message only, and the flag is not bound to the body.
    send(&mut b, t, b"Og en til.");
    a.core.receive(&a.net.poll()[0]).unwrap();
    let before = a.core.messages(t).unwrap();
    assert!(!before[1].read && !before[2].read);
    a.core.mark_read(before[1].id).unwrap();
    let after = a.core.messages(t).unwrap();
    assert!(after[1].read && !after[1].outgoing && !after[2].read);
    assert_eq!(&a.core.read_body(after[1].id).unwrap()[..], b"Takk!");
}

#[test]
fn tamper_any_flipped_byte_fails() {
    let dir = TempDir::new();
    let (mut a, mut b, b_at_a, _) = pair(&dir.0);
    let t = a.core.new_thread(b_at_a, b"s").unwrap();
    let env = send(&mut a, t, b"body");
    for i in 0..env.ciphertext.len() {
        let mut bad = env.clone();
        bad.ciphertext[i] ^= 0x01;
        assert!(
            matches!(b.core.receive(&bad), Err(Error::Crypto)),
            "ciphertext byte {i}"
        );
    }
    let mut bad = env.clone();
    bad.nonce[0] ^= 0x01;
    assert!(matches!(b.core.receive(&bad), Err(Error::Crypto)));
    assert!(
        b.core.threads().unwrap().is_empty(),
        "nothing stored from a failed decrypt"
    );
    b.core.receive(&env).unwrap();
}

#[test]
fn no_plaintext_in_any_file() {
    const NAME: &[u8] = b"BREV-NAME-MARKER-3b8e61";
    const SUBJECT: &[u8] = b"BREV-SUBJECT-MARKER-94d0a7";
    const BODY: &[u8] = b"BREV-BODY-MARKER-c25f18";
    let markers = [NAME, SUBJECT, BODY];
    let dir = TempDir::new();
    let (mut a, mut b, b_at_a, a_at_b) = pair(&dir.0);
    b.core.add_contact(&stranger(), NAME).unwrap();
    let t = a.core.new_thread(b_at_a, SUBJECT).unwrap();
    let env = send(&mut a, t, BODY);
    let wire = [env.signed_bytes(), env.signature.clone()].concat();
    for m in markers {
        assert!(!contains(&wire, m), "marker in envelope bytes");
    }
    let m = b.core.receive(&b.net.poll()[0]).unwrap();
    b.core.mark_read(m).unwrap();
    send(&mut b, t, BODY);
    a.core.receive(&a.net.poll()[0]).unwrap();

    // Not vacuous: the content really went in and comes back out.
    assert_eq!(&b.core.read_body(m).unwrap()[..], BODY);
    assert_eq!(&b.core.threads().unwrap()[0].subject[..], SUBJECT);
    assert!(b
        .core
        .contacts()
        .unwrap()
        .iter()
        .any(|c| &c.name[..] == NAME));

    let scan = |when: &str| {
        let mut saw_id = false;
        for entry in fs::read_dir(&dir.0).unwrap() {
            let path = entry.unwrap().path();
            let bytes = fs::read(&path).unwrap();
            for m in markers {
                assert!(!contains(&bytes, m), "{when}: marker in {}", path.display());
            }
            saw_id |= contains(&bytes, &a_at_b.0);
        }
        // Positive control: a plaintext id is visible, so the scan reads store data.
        assert!(saw_id, "{when}: control id not found");
    };
    scan("open");
    drop(a);
    drop(b);
    scan("closed");

    let mut names: Vec<_> = fs::read_dir(&dir.0)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(
        names,
        ["a.db", "b.db"],
        "no journal, WAL or SHM left behind"
    );

    // Positive control: a marker that SQLite *is* given shows up in the scan.
    let raw = rusqlite::Connection::open(dir.0.join("b.db")).unwrap();
    raw.execute_batch("CREATE TABLE leak (v BLOB)").unwrap();
    raw.execute("INSERT INTO leak VALUES (?1)", [BODY]).unwrap();
    drop(raw);
    assert!(contains(&fs::read(dir.0.join("b.db")).unwrap(), BODY));
}

#[test]
fn locked_core_refuses_every_content_call() {
    let dir = TempDir::new();
    let (mut a, mut b, b_at_a, _) = pair(&dir.0);
    let t = a.core.new_thread(b_at_a, b"s").unwrap();
    let env = send(&mut a, t, b"x");
    let msg = a.core.messages(t).unwrap()[0].id;
    // An unread letter from B, to show that a locked mark_read writes nothing.
    b.core.receive(&b.net.poll()[0]).unwrap();
    send(&mut b, t, b"y");
    let unread = a.core.receive(&a.net.poll()[0]).unwrap();

    a.core.lock();
    assert!(a.core.is_locked());
    let locked = |r: Result<(), Error>| assert!(matches!(r, Err(Error::Locked)));
    locked(a.core.bundle().map(drop));
    locked(a.core.add_contact(&stranger(), b"n").map(drop));
    locked(a.core.contacts().map(drop));
    locked(a.core.new_thread(b_at_a, b"s").map(drop));
    locked(a.core.threads().map(drop));
    locked(a.core.messages(t).map(drop));
    locked(a.core.read_body(msg).map(drop));
    locked(a.core.mark_read(unread));
    locked(a.core.send(t, b"y", &a.signer).map(drop));
    locked(a.core.receive(&env).map(drop));
    locked(a.core.receive_all(&a.net).map(drop));

    assert!(matches!(a.core.unlock(&mut random()), Err(Error::WrongKey)));
    assert!(matches!(a.core.unlock(&mut [0; 32]), Err(Error::WrongKey)));
    assert!(a.core.is_locked());

    // Reopen from disk: starts locked, the right DEK opens it again.
    let path = dir.0.join("a.db");
    drop(a.core);
    let mut again = Core::open(&path).unwrap();
    assert!(again.is_locked());
    assert!(matches!(again.threads().map(drop), Err(Error::Locked)));
    let mut dek = a.dek;
    again.unlock(&mut dek).unwrap();
    assert_eq!(dek, [0u8; 32]);
    assert_eq!(&again.read_body(msg).unwrap()[..], b"x");
    assert!(
        again
            .messages(t)
            .unwrap()
            .iter()
            .any(|m| m.id == unread && !m.read),
        "a locked mark_read wrote nothing"
    );
}

#[test]
fn signature_slot_holds_a_verifiable_signature_and_signing_can_fail() {
    let dir = TempDir::new();
    let (mut a, _b, b_at_a, _) = pair(&dir.0);
    let t = a.core.new_thread(b_at_a, b"s").unwrap();
    let env = send(&mut a, t, b"x");
    let vk = a.signer.0.verifying_key();
    assert_eq!(a.core.bundle().unwrap().signing_key, vk.to_bytes());
    let sig = Signature::from_slice(&env.signature).unwrap();
    vk.verify_strict(&env.signed_bytes(), &sig).unwrap();
    let mut bad = env.clone();
    bad.ciphertext[0] ^= 1;
    assert!(vk.verify_strict(&bad.signed_bytes(), &sig).is_err());

    struct Refuses;
    impl Signer for Refuses {
        fn sign(&self, _: &[u8]) -> Result<Vec<u8>, Error> {
            Err(Error::Signing)
        }
    }
    assert!(matches!(
        a.core.send(t, b"y", &Refuses),
        Err(Error::Signing)
    ));
    assert_eq!(a.core.messages(t).unwrap().len(), 1, "nothing stored");
}

#[test]
fn receive_rejects_strangers_misrouted_self_and_replays() {
    let dir = TempDir::new();
    let (mut a, mut b, b_at_a, _) = pair(&dir.0);
    // C knows B's bundle, but B has not added C.
    let mut c = make(&dir.0, "c.db", MockTransport::pair().0);
    let b_at_c = c
        .core
        .add_contact(&b.core.bundle().unwrap(), b"Bob")
        .unwrap();
    let tc = c.core.new_thread(b_at_c, b"s").unwrap();
    let from_c = c.core.send(tc, b"x", &c.signer).unwrap();
    assert!(matches!(b.core.receive(&from_c), Err(Error::NotFound)));

    // An envelope for B handed to A.
    let t = a.core.new_thread(b_at_a, b"s").unwrap();
    let env = send(&mut a, t, b"x");
    assert!(matches!(a.core.receive(&env), Err(Error::Malformed)));

    // Replay: stored once.
    b.core.receive(&env).unwrap();
    assert!(matches!(b.core.receive(&env), Err(Error::Duplicate)));
    assert_eq!(b.core.messages(t).unwrap().len(), 1);

    // Own identity is not a contact; a contact is added once; a thread needs a contact.
    let me = a.core.bundle().unwrap();
    assert!(matches!(
        a.core.add_contact(&me, b"me"),
        Err(Error::Malformed)
    ));
    assert!(matches!(
        a.core
            .add_contact(&b.core.bundle().unwrap(), b"Bob")
            .map(drop),
        Err(Error::Duplicate)
    ));
    assert!(matches!(
        a.core.new_thread(IdentityId([9; 32]), b"s").map(drop),
        Err(Error::NotFound)
    ));
    // A signing key must be 1..=255 bytes; a refused bundle adds no contact.
    for signing_key in [vec![], vec![1; 256]] {
        let bad = PublicBundle {
            signing_key,
            x25519: random(),
        };
        assert!(matches!(
            a.core.add_contact(&bad, b"n").map(drop),
            Err(Error::Malformed)
        ));
    }
    assert_eq!(a.core.contacts().unwrap().len(), 1);

    // A subject over 65535 bytes is refused and makes no thread; an
    // unknown message cannot be marked read.
    assert!(matches!(
        a.core.new_thread(b_at_a, &[0; 65536]).map(drop),
        Err(Error::Malformed)
    ));
    assert_eq!(a.core.threads().unwrap().len(), 1);
    assert!(matches!(
        a.core.mark_read(MessageId([0; 16])),
        Err(Error::NotFound)
    ));
}

/// One bad envelope never costs the ones behind it, and a locked core
/// drains nothing.
#[test]
fn receive_all_isolates_bad_envelopes_and_waits_while_locked() {
    let dir = TempDir::new();
    let (mut a, mut b, b_at_a, _) = pair(&dir.0);
    let mut c = make(&dir.0, "c.db", MockTransport::pair().0);
    let b_at_c = c
        .core
        .add_contact(&b.core.bundle().unwrap(), b"Bob")
        .unwrap();
    let tc = c.core.new_thread(b_at_c, b"s").unwrap();
    let t = a.core.new_thread(b_at_a, b"s").unwrap();
    let first = a.core.send(t, b"first", &a.signer).unwrap();
    b.core.receive(&first).unwrap();

    let good = a.core.send(t, b"good", &a.signer).unwrap();
    let mut tampered = good.clone();
    tampered.ciphertext[0] ^= 1;
    // Everything a.net sends lands in B's inbox.
    a.net.send(first); // replay
    a.net.send(c.core.send(tc, b"x", &c.signer).unwrap()); // not B's contact
    a.net.send(tampered);
    a.net.send(good);
    let d = b.core.receive_all(&b.net).unwrap();
    assert_eq!(d.received.len(), 1);
    assert_eq!(&b.core.read_body(d.received[0]).unwrap()[..], b"good");
    assert!(matches!(
        d.rejected[..],
        [Error::Duplicate, Error::NotFound, Error::Crypto]
    ));

    // Locked: nothing is polled, so the letter waits for unlock.
    send(&mut a, t, b"later");
    b.core.lock();
    assert!(matches!(
        b.core.receive_all(&b.net).map(drop),
        Err(Error::Locked)
    ));
    b.core.unlock(&mut b.dek.clone()).unwrap();
    let d = b.core.receive_all(&b.net).unwrap();
    assert_eq!((d.received.len(), d.rejected.len()), (1, 0));
    assert_eq!(b.core.messages(t).unwrap().len(), 3);
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
        .add_contact(&m.core.bundle().unwrap(), b"Mallory")
        .unwrap();
    let t = a.core.new_thread(b_at_a, b"s").unwrap();
    let t2 = a.core.new_thread(b_at_a, b"s2").unwrap();
    let other = a.core.new_thread(m_at_a, b"s3").unwrap();
    send(&mut a, t, b"first");
    send(&mut a, t, b"second");
    send(&mut a, t2, b"third");
    let ids: Vec<_> = a.core.messages(t).unwrap().iter().map(|m| m.id).collect();
    // Each thread lists only its own messages.
    let in_t2 = a.core.messages(t2).unwrap();
    assert_eq!((ids.len(), in_t2.len()), (2, 1));
    assert!(!ids.contains(&in_t2[0].id) && a.core.messages(other).unwrap().is_empty());
    let raw = rusqlite::Connection::open(dir.0.join("a.db")).unwrap();
    let sql = |q: &str, p: &[&[u8]]| {
        raw.execute(q, rusqlite::params_from_iter(p.iter()))
            .unwrap();
    };
    // Swaps one column between two rows; a second call undoes it.
    let swap = |table: &str, column: &str, x: &[u8], y: &[u8]| {
        let get = |id: &[u8]| -> rusqlite::types::Value {
            let q = format!("SELECT {column} FROM {table} WHERE id = ?1");
            raw.query_row(&q, [id], |r| r.get(0)).unwrap()
        };
        let (vx, vy) = (get(x), get(y));
        let set = format!("UPDATE {table} SET {column} = ?1 WHERE id = ?2");
        raw.execute(&set, rusqlite::params![vy, x]).unwrap();
        raw.execute(&set, rusqlite::params![vx, y]).unwrap();
    };

    // Re-point B's thread at Mallory: nothing is encrypted to Mallory.
    sql(
        "UPDATE threads SET contact_id = ?1 WHERE id = ?2",
        &[&m_at_a.0, &t.0],
    );
    assert!(matches!(
        a.core.send(t, b"secret", &a.signer),
        Err(Error::Crypto)
    ));
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

    // Contact rows are bound to their id. Bob's and Mallory's bundles
    // swapped: nothing is encrypted to Mallory in Bob's thread, and no new
    // thread is started. Their names swapped: Mallory is not shown as Bob.
    swap("contacts", "bundle", &b_at_a.0, &m_at_a.0);
    assert!(matches!(
        a.core.send(t, b"secret", &a.signer),
        Err(Error::Crypto)
    ));
    assert!(matches!(
        a.core.new_thread(b_at_a, b"s").map(drop),
        Err(Error::Crypto)
    ));
    swap("contacts", "bundle", &b_at_a.0, &m_at_a.0);
    swap("contacts", "name", &b_at_a.0, &m_at_a.0);
    assert!(matches!(a.core.contacts().map(drop), Err(Error::Crypto)));
    swap("contacts", "name", &b_at_a.0, &m_at_a.0);
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
        "UPDATE contacts SET name = (SELECT subject FROM threads WHERE id = ?2) WHERE id = ?1",
        &[&b_at_a.0, &t.0],
    );
    assert!(matches!(a.core.contacts().map(drop), Err(Error::Crypto)));

    // The identity row is bound to the own id: with the id edited, the
    // right DEK no longer unlocks, so no envelope carries a forged sender.
    let own: Vec<u8> = raw
        .query_row("SELECT id FROM identity", [], |r| r.get(0))
        .unwrap();
    sql("UPDATE identity SET id = ?1", &[&m_at_a.0]);
    a.core.lock();
    assert!(matches!(
        a.core.unlock(&mut a.dek.clone()),
        Err(Error::WrongKey)
    ));
    sql("UPDATE identity SET id = ?1", &[&own[..]]);
    a.core.unlock(&mut a.dek.clone()).unwrap();
}

#[test]
fn create_and_open_refuse_bad_files() {
    let dir = TempDir::new();

    // The caller's DEK is wiped even when create fails before touching disk.
    let mut dek: [u8; 32] = random();
    let r = Core::create(&dir.0.join("no/such/dir.db"), &mut dek, &[1; 32]);
    assert!(matches!(r, Err(Error::Io(_))));
    assert_eq!(dek, [0u8; 32]);
    // Retrying with the same (now zeroed) buffer must not seal a store under
    // the all-zero key.
    let r = Core::create(&dir.0.join("z.db"), &mut dek, &[1; 32]);
    assert!(matches!(r, Err(Error::Malformed)));
    assert!(!dir.0.join("z.db").exists());

    // Only absolute paths: SQLite would read `file:` names as URIs.
    let uri = format!("file:{}?mode=ro", dir.0.join("u.db").display());
    // Each early refusal wipes the DEK too.
    for p in ["file:u.db", uri.as_str(), "u.db", ":memory:", ""] {
        dek = random();
        let r = Core::create(Path::new(p), &mut dek, &[1; 32]);
        assert!(matches!(r, Err(Error::Malformed)), "create {p:?}");
        assert_eq!(dek, [0u8; 32], "create {p:?}");
        assert!(
            matches!(Core::open(Path::new(p)).map(drop), Err(Error::Malformed)),
            "open {p:?}"
        );
    }
    assert!(!Path::new("file:u.db").exists() && !Path::new("u.db").exists());
    dek = random();
    let r = Core::create(&dir.0.join("x.db"), &mut dek, &[]);
    assert!(matches!(r, Err(Error::Malformed)));
    assert_eq!(dek, [0u8; 32]);
    assert!(!dir.0.join("x.db").exists());

    // A failure after the file is made (a directory where the rollback
    // journal goes) removes the file.
    fs::create_dir(dir.0.join("j.db-journal")).unwrap();
    let r = Core::create(&dir.0.join("j.db"), &mut random(), &[1; 32]);
    assert!(matches!(r, Err(Error::Storage(_))));
    assert!(!dir.0.join("j.db").exists());

    // create refuses an existing store and leaves it untouched.
    let path = dir.0.join("a.db");
    drop(make(&dir.0, "a.db", MockTransport::pair().0));
    let before = fs::read(&path).unwrap();
    match Core::create(&path, &mut random(), &[1; 32]) {
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
    // schema version.
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
    core.add_contact(&stranger(), b"n").unwrap();
    let names: Vec<_> = fs::read_dir(&dir.0)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names, ["a.db"]);
}

#[test]
fn core_and_transport_can_move_between_threads() {
    fn send_bound<T: Send>() {}
    fn shared_bound<T: Send + Sync>() {}
    send_bound::<Core>();
    shared_bound::<MockTransport>();
}
