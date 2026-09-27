//! Phase 2 through the public API: the `Brev` session the app holds, its
//! `OpenText` chunks, the echo contacts, the store files and the padded
//! columns. (`lock_closes_every_open_text` and the drop-guard, scrub and
//! echo checks are unit tests in `ffi.rs`, because their counters are
//! cfg(test) only.)

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use brev_core::{
    limits, Brev, BrevError, Core, Error, MessageId, OpenText, Signer, CHUNK, MAX_BODY, MAX_SUBJECT,
};
use rand::rngs::SysRng;
use rand::TryRng;

const FILES: [&str; 3] = ["brev.db", "peer-1.db", "peer-2.db"];

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
    fn arg(&self) -> String {
        self.0.to_str().unwrap().to_owned()
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A new session (locked) and its DEK. The signing key has the length of
/// the Enclave key's x963 representation.
fn new_session(dir: &TempDir) -> (Arc<Brev>, [u8; 32]) {
    let dek = random();
    (Brev::create(dir.arg(), &dek, &[4; 65]).unwrap(), dek)
}

fn unlocked(dir: &TempDir) -> (Arc<Brev>, [u8; 32]) {
    let (b, dek) = new_session(dir);
    b.unlock(&dek).unwrap();
    (b, dek)
}

/// The whole text, reassembled from its chunks the way the app reads it;
/// the text is closed afterwards.
fn read(t: &OpenText) -> Vec<u8> {
    let n = t.byte_len() as usize;
    let mut out = Vec::with_capacity(n);
    for i in 0..n.div_ceil(CHUNK) {
        let c = t.chunk(u32::try_from(i).unwrap()).unwrap();
        assert_eq!(c.len(), CHUNK);
        let take = (n - out.len()).min(CHUNK);
        out.extend_from_slice(&c[..take]);
    }
    t.close();
    out
}

fn contact_ids(b: &Brev) -> Vec<Vec<u8>> {
    b.contacts().unwrap().into_iter().map(|c| c.id).collect()
}

fn files(dir: &Path) -> Vec<String> {
    let mut names: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn len32(n: usize) -> u32 {
    u32::try_from(n).unwrap()
}

#[test]
fn create_returns_locked_session_with_two_contacts() {
    let dir = TempDir::new();
    let (b, dek) = new_session(&dir);
    assert!(b.is_locked());
    assert!(matches!(b.contacts(), Err(BrevError::Locked)));
    assert_eq!(files(&dir.0), FILES);

    b.unlock(&dek).unwrap();
    let contacts = b.contacts().unwrap();
    let names: Vec<_> = contacts.iter().map(|c| read(&c.name)).collect();
    assert_eq!(names, [&b"Ekko"[..], &b"Speil"[..]]);
    assert_ne!(contacts[0].id, contacts[1].id);
    for c in &contacts {
        assert_eq!(c.id.len(), 32);
        assert!(b.threads(c.id.clone()).unwrap().is_empty());
    }

    // Reopened from disk: locked, and the same contacts after unlock.
    drop((contacts, b));
    let b = Brev::open(dir.arg()).unwrap();
    assert!(b.is_locked());
    b.unlock(&dek).unwrap();
    assert_eq!(contact_ids(&b).len(), 2);
}

#[test]
fn chunk_is_exactly_960_zero_padded() {
    let l = limits();
    assert_eq!(
        (l.max_subject, l.max_body, l.chunk),
        (256, 65_536, 960),
        "the limits the app sizes its buffers from"
    );
    let dir = TempDir::new();
    let (b, _) = unlocked(&dir);
    let contact = contact_ids(&b).remove(0);
    // No zero bytes, so a zero in a chunk can only be padding.
    let body: Vec<u8> = (0..2000u32).map(|i| (i % 251) as u8 + 1).collect();
    for len in [0usize, 1, 959, 960, 961, 2000] {
        let t = b
            .send_new(contact.clone(), b"s", 1, &body, len32(len))
            .unwrap();
        let m = b.messages(t).unwrap().remove(0).id;
        let text = b.open_body(m).unwrap();
        assert_eq!(text.byte_len() as usize, len);
        let chunks = len.div_ceil(CHUNK);
        for i in 0..chunks {
            let c = text.chunk(len32(i)).unwrap();
            assert_eq!(c.len(), CHUNK, "{len}: chunk {i}");
            let (start, end) = (i * CHUNK, len.min(i * CHUNK + CHUNK));
            assert_eq!(&c[..end - start], &body[start..end], "{len}: chunk {i}");
            assert!(c[end - start..].iter().all(|&x| x == 0), "{len}: chunk {i}");
        }
        // Out of range, including the only index of an empty text.
        assert!(matches!(
            text.chunk(len32(chunks)),
            Err(BrevError::Malformed)
        ));
        assert!(matches!(text.chunk(u32::MAX), Err(BrevError::Malformed)));
        text.close();
        assert!(matches!(text.chunk(0), Err(BrevError::Locked)));
    }
}

#[test]
fn send_uses_only_the_length_prefix() {
    const MARKER: &[u8] = b"BREV-AFTER-LEN-MARKER-7e21c9";
    let dir = TempDir::new();
    let (b, _) = unlocked(&dir);
    let contact = contact_ids(&b).remove(0);
    let subject = [&b"Emne"[..], MARKER].concat();
    let body = [&b"Hei"[..], MARKER].concat();
    let t = b.send_new(contact.clone(), &subject, 4, &body, 3).unwrap();
    assert_eq!(b.sync().unwrap(), 1);
    let threads = b.threads(contact.clone()).unwrap();
    assert_eq!(read(&threads[0].subject), b"Emne");
    let letters = b.messages(t.clone()).unwrap();
    assert_eq!(letters.len(), 2, "the letter and its echo");
    for m in letters {
        assert_eq!(read(&b.open_body(m.id).unwrap()), b"Hei");
    }

    // A length over the buffer or over the limit is refused and stores
    // nothing; the limits themselves are accepted.
    let long_subject = vec![b'a'; MAX_SUBJECT + 1];
    let long_body = vec![b'b'; MAX_BODY + 1];
    let refused = [
        (&subject[..], len32(subject.len() + 1), &body[..], 3),
        (&subject[..], 4, &body[..], len32(body.len() + 1)),
        (&long_subject[..], len32(MAX_SUBJECT + 1), &body[..], 3),
        (&subject[..], 4, &long_body[..], len32(MAX_BODY + 1)),
    ];
    for (s, sl, bd, bl) in refused {
        assert!(matches!(
            b.send_new(contact.clone(), s, sl, bd, bl),
            Err(BrevError::Malformed)
        ));
    }
    assert!(matches!(
        b.send_new(vec![0; 31], &subject, 4, &body, 3),
        Err(BrevError::Malformed)
    ));
    assert_eq!(b.threads(contact.clone()).unwrap().len(), 1);
    b.send_new(
        contact.clone(),
        &long_subject,
        len32(MAX_SUBJECT),
        &long_body,
        len32(MAX_BODY),
    )
    .unwrap();
    assert_eq!(b.threads(contact).unwrap().len(), 2);

    // The bytes after the length reached no file.
    assert_eq!(b.sync().unwrap(), 1);
    drop((threads, b));
    let mut saw_id = false;
    for name in FILES {
        let bytes = fs::read(dir.0.join(name)).unwrap();
        assert!(!contains(&bytes, MARKER), "marker in {name}");
        saw_id |= contains(&bytes, &t);
    }
    assert!(saw_id, "control: the thread id is stored");
}

#[test]
fn sync_echoes_each_letter_once_into_the_same_thread() {
    let dir = TempDir::new();
    let (b, dek) = unlocked(&dir);
    let mut sent = Vec::new();
    for (i, contact) in contact_ids(&b).into_iter().enumerate() {
        let body = format!("Brev nummer {i}, blåbær").into_bytes();
        let t = b
            .send_new(contact.clone(), b"s", 1, &body, len32(body.len()))
            .unwrap();
        sent.push((contact, t, body));
    }

    // Locked: `Locked`, and nothing is drained, so the letters wait.
    b.lock();
    assert!(matches!(b.sync(), Err(BrevError::Locked)));
    b.unlock(&dek).unwrap();
    assert_eq!(b.sync().unwrap(), 2);
    assert_eq!(b.sync().unwrap(), 0, "each letter is echoed once");

    for (contact, t, body) in sent {
        let threads = b.threads(contact).unwrap();
        assert_eq!(threads.len(), 1, "the echo lands in the same thread");
        assert_eq!(threads[0].id, t);
        let letters = b.messages(t).unwrap();
        assert_eq!(letters.len(), 2);
        assert!(letters[0].outgoing && !letters[1].outgoing);
        assert_ne!(letters[0].id, letters[1].id);
        for m in letters {
            assert_eq!(read(&b.open_body(m.id).unwrap()), body);
        }
    }
}

#[test]
fn create_refuses_existing_files() {
    // Any one of the three names already there: `Io`, and it is untouched.
    for name in FILES {
        let dir = TempDir::new();
        fs::write(dir.0.join(name), b"not a store").unwrap();
        let r = Brev::create(dir.arg(), &random::<32>(), &[4; 65]);
        assert!(matches!(r.map(drop), Err(BrevError::Io)), "{name}");
        assert_eq!(fs::read(dir.0.join(name)).unwrap(), b"not a store");
    }

    // A complete session is not overwritten, and still opens.
    let dir = TempDir::new();
    let (b, dek) = new_session(&dir);
    drop(b);
    let before: Vec<_> = FILES
        .iter()
        .map(|f| fs::read(dir.0.join(f)).unwrap())
        .collect();
    let r = Brev::create(dir.arg(), &random::<32>(), &[4; 65]);
    assert!(matches!(r.map(drop), Err(BrevError::Io)));
    let after: Vec<_> = FILES
        .iter()
        .map(|f| fs::read(dir.0.join(f)).unwrap())
        .collect();
    assert_eq!(before, after);
    Brev::open(dir.arg()).unwrap().unlock(&dek).unwrap();

    // Bad input makes no file.
    let dir = TempDir::new();
    for dek in [&[1u8; 31][..], &[1u8; 33][..], &[0u8; 32][..]] {
        let r = Brev::create(dir.arg(), dek, &[4; 65]);
        assert!(matches!(r.map(drop), Err(BrevError::Malformed)));
    }
    let r = Brev::create(dir.arg(), &random::<32>(), &[]);
    assert!(matches!(r.map(drop), Err(BrevError::Malformed)));
    let r = Brev::create("relative/dir".into(), &random::<32>(), &[4; 65]);
    assert!(matches!(r.map(drop), Err(BrevError::Malformed)));
    assert!(files(&dir.0).is_empty());
}

#[test]
fn store_files_are_0600() {
    let dir = TempDir::new();
    let (b, _) = unlocked(&dir);
    let check = |when: &str| {
        for name in FILES {
            let mode = fs::metadata(dir.0.join(name)).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "{when}: {name}");
        }
    };
    check("created");
    for contact in contact_ids(&b) {
        b.send_new(contact, b"s", 1, b"x", 1).unwrap();
    }
    assert_eq!(b.sync().unwrap(), 2);
    drop(b);
    check("after writes");
}

#[test]
fn no_plaintext_in_any_file() {
    const SUBJECT: &[u8] = b"BREV-P2-SUBJECT-MARKER-0f3a9c";
    const BODY: &[u8] = b"BREV-P2-BODY-MARKER-b71e04";
    // The peers' names are content too. ("Deg", the user's name at the
    // peers, is too short to scan for without false hits.)
    let markers: [&[u8]; 4] = [SUBJECT, BODY, b"Ekko", b"Speil"];
    let dir = TempDir::new();
    let (b, _) = unlocked(&dir);
    let mut threads = Vec::new();
    for contact in contact_ids(&b) {
        let t = b
            .send_new(
                contact.clone(),
                SUBJECT,
                len32(SUBJECT.len()),
                BODY,
                len32(BODY.len()),
            )
            .unwrap();
        threads.push((contact, t));
    }
    assert_eq!(b.sync().unwrap(), 2);

    // Not vacuous: the content went in and comes back out, echoes included.
    for (contact, t) in &threads {
        assert_eq!(
            read(&b.threads(contact.clone()).unwrap()[0].subject),
            SUBJECT
        );
        for m in b.messages(t.clone()).unwrap() {
            assert_eq!(read(&b.open_body(m.id).unwrap()), BODY);
        }
    }

    let scan = |when: &str| {
        for entry in fs::read_dir(&dir.0).unwrap() {
            let path = entry.unwrap().path();
            let bytes = fs::read(&path).unwrap();
            for m in markers {
                assert!(!contains(&bytes, m), "{when}: marker in {}", path.display());
            }
        }
        // Positive control: each thread id (plaintext) is in the user's
        // store and in its peer's store, so the scan reads all three.
        let read_file = |f: &str| fs::read(dir.0.join(f)).unwrap();
        for (i, (_, t)) in threads.iter().enumerate() {
            assert!(contains(&read_file(FILES[0]), t), "{when}: control");
            assert!(contains(&read_file(FILES[i + 1]), t), "{when}: control");
        }
    };
    scan("unlocked");
    b.lock();
    scan("locked");
    drop(b);
    scan("closed");
    assert_eq!(files(&dir.0), FILES, "no journal left behind");
}

/// The sealed content columns of a Phase 2 store.
const SEALED: [(&str, &str); 5] = [
    ("identity", "keys"),
    ("contacts", "bundle"),
    ("contacts", "name"),
    ("threads", "subject"),
    ("messages", "body"),
];

#[test]
fn column_lengths_are_bucketed() {
    let dir = TempDir::new();
    let (b, _) = unlocked(&dir);
    let subject = vec![b's'; MAX_SUBJECT];
    let body = vec![b'b'; MAX_BODY];
    for contact in contact_ids(&b) {
        for len in [0, 300, 1500, 5000, MAX_BODY] {
            b.send_new(
                contact.clone(),
                &subject,
                len32(MAX_SUBJECT),
                &body,
                len32(len),
            )
            .unwrap();
        }
    }
    assert_eq!(b.sync().unwrap(), 10);
    drop(b);

    let is_bucket = |n: usize| matches!(n, 256 | 1024 | 4096) || (n % 16384 == 0 && n > 0);
    for name in FILES {
        let raw = rusqlite::Connection::open_with_flags(
            dir.0.join(name),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let mut lengths = Vec::new();
        for (table, column) in SEALED {
            let q = format!("SELECT length({column}) FROM {table}");
            let mut stmt = raw.prepare(&q).unwrap();
            let rows = stmt.query_map([], |r| r.get::<_, i64>(0)).unwrap();
            for n in rows {
                let n = usize::try_from(n.unwrap()).unwrap();
                // nonce (24) + one bucket + tag (16)
                assert!(
                    n > 40 && is_bucket(n - 40),
                    "{name}: {table}.{column} is {n}"
                );
                lengths.push(n - 40);
            }
        }
        // Every row was checked, and the buckets differ as the sizes do:
        // 256 for names and keys, 1 KiB for the 256-byte subjects, and
        // 256 B, 1 KiB, 4 KiB, 16 KiB, 80 KiB for the bodies.
        lengths.sort_unstable();
        lengths.dedup();
        assert_eq!(lengths, [256, 1024, 4096, 16384, 81920], "{name}");
    }
}

#[test]
fn v1_store_is_refused() {
    let dir = TempDir::new();
    let (b, dek) = new_session(&dir);
    drop(b);
    for name in FILES {
        let raw = rusqlite::Connection::open(dir.0.join(name)).unwrap();
        raw.pragma_update(None, "user_version", 1).unwrap();
        assert!(
            matches!(Brev::open(dir.arg()).map(drop), Err(BrevError::Corrupt)),
            "{name}"
        );
        raw.pragma_update(None, "user_version", 2).unwrap();
    }
    Brev::open(dir.arg()).unwrap().unlock(&dek).unwrap();
}

#[test]
fn thread_of_is_gated_metadata() {
    struct NoSig;
    impl Signer for NoSig {
        fn sign(&self, _: &[u8]) -> Result<Vec<u8>, Error> {
            Ok(Vec::new())
        }
    }
    let dir = TempDir::new();
    let mut a = Core::create(&dir.0.join("a.db"), &mut random(), &[1; 32]).unwrap();
    let b = Core::create(&dir.0.join("b.db"), &mut random(), &[2; 32]).unwrap();
    let b_at_a = a.add_contact(&b.bundle().unwrap(), b"B").unwrap();
    let t = a.new_thread(b_at_a, b"s").unwrap();
    a.send(t, b"x", &NoSig).unwrap();
    let m = a.messages(t).unwrap()[0].id;
    assert_eq!(a.thread_of(m).unwrap(), t);
    assert!(matches!(
        a.thread_of(MessageId([0; 16])),
        Err(Error::NotFound)
    ));
    a.lock();
    assert!(matches!(a.thread_of(m), Err(Error::Locked)));
}
