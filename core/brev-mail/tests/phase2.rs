//! Phase 2 through the public API, moved to Phase 3's surface: the `Brev`
//! session the app holds, its `OpenText` chunks, the one store file and its
//! padded columns. Letters go through the relay (in-process on
//! 127.0.0.1:0). (`lock_closes_every_open_text` and the drop-guard and
//! scrub checks are unit tests in `ffi/tests.rs`, because their counters are
//! cfg(test) only.)

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;

use brev_core::{limits, Brev, BrevError, Core, Error, MessageId, CHUNK, MAX_BODY, MAX_SUBJECT};
use common::{
    contains, len32, pair, random, unlock_active, Relayed, TempDir, TestKey, User, TEST_IDLE,
};

const FILES: [&str; 1] = ["brev.db"];

#[test]
fn create_returns_a_locked_session_without_contacts() {
    let relay = Relayed::new();
    let u = User::locked(&relay.url);
    assert!(u.b.is_locked());
    assert!(matches!(u.b.contacts(), Err(BrevError::Locked)));
    assert_eq!(u.dir.files(), FILES);

    unlock_active(&u.b, &u.dek);
    assert!(u.b.contacts().unwrap().is_empty());
    let me = u.b.me().unwrap();
    assert!(!me.registered);
    assert_eq!(me.address.byte_len(), 0);
    assert_eq!(me.code.len(), 35);

    // Reopened from disk: locked, the same identity after unlock.
    let dir = u.dir.arg();
    let code = me.code;
    drop(u.b);
    let b = Brev::open(dir, relay.url.clone()).unwrap();
    assert!(b.is_locked());
    unlock_active(&b, &u.dek);
    assert_eq!(b.me().unwrap().code, code);
    assert_eq!(relay.requests(), 0, "nothing registered, nothing asked");
}

#[test]
fn chunk_is_exactly_960_zero_padded() {
    let l = limits();
    assert_eq!(
        (l.max_subject, l.max_body, l.chunk, l.max_address),
        (256, 65_536, 960, 32),
        "the limits the app sizes its buffers from"
    );
    let relay = Relayed::new();
    let (a, _b, b_at_a, _) = pair(&relay);
    // No zero bytes, so a zero in a chunk can only be padding.
    let body: Vec<u8> = (0..2000u32).map(|i| (i % 251) as u8 + 1).collect();
    for len in [0usize, 1, 959, 960, 961, 2000] {
        let t = a.send(&b_at_a, b"s", &body[..len]);
        let m = a.b.messages(t).unwrap().remove(0).id;
        let text = a.b.open_body(m).unwrap();
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
    let relay = Relayed::new();
    let (a, b, b_at_a, a_at_b) = pair(&relay);
    let subject = [&b"Emne"[..], MARKER].concat();
    let body = [&b"Hei"[..], MARKER].concat();
    a.b.prepare_send(b_at_a.clone()).unwrap();
    let digest =
        a.b.sign_request(b_at_a.clone(), &subject, 4, &body, 3)
            .unwrap();
    a.b.attach_signature(a.key.sign_digest(&digest)).unwrap();
    a.b.submit().unwrap();
    assert_eq!(b.b.sync().unwrap(), 1);
    assert_eq!(a.letters(&b_at_a), [(b"Emne".to_vec(), b"Hei".to_vec())]);
    assert_eq!(b.letters(&a_at_b), [(b"Emne".to_vec(), b"Hei".to_vec())]);

    // A length over the buffer or over the limit is refused, keeps the
    // ticket and sends nothing; the limits themselves are accepted.
    let long_subject = vec![b'a'; MAX_SUBJECT + 1];
    let long_body = vec![b'b'; MAX_BODY + 1];
    let refused = [
        (&subject[..], len32(subject.len() + 1), &body[..], 3),
        (&subject[..], 4, &body[..], len32(body.len() + 1)),
        (&long_subject[..], len32(MAX_SUBJECT + 1), &body[..], 3),
        (&subject[..], 4, &long_body[..], len32(MAX_BODY + 1)),
    ];
    a.b.prepare_send(b_at_a.clone()).unwrap();
    for (s, sl, bd, bl) in refused {
        assert!(matches!(
            a.b.sign_request(b_at_a.clone(), s, sl, bd, bl),
            Err(BrevError::Malformed)
        ));
    }
    assert!(matches!(
        a.b.sign_request(vec![0; 15], &subject, 4, &body, 3),
        Err(BrevError::Malformed)
    ));
    assert_eq!(a.b.threads(b_at_a.clone()).unwrap().len(), 1);
    let digest =
        a.b.sign_request(
            b_at_a.clone(),
            &long_subject,
            len32(MAX_SUBJECT),
            &long_body,
            len32(MAX_BODY),
        )
        .unwrap();
    a.b.attach_signature(a.key.sign_digest(&digest)).unwrap();
    a.b.submit().unwrap();
    assert_eq!(a.b.threads(b_at_a).unwrap().len(), 2);
    assert_eq!(relay.waiting(), 1);

    // The bytes after the length reached no file, here or at the relay.
    assert!(!relay.files_contain(MARKER));
    assert_eq!(b.b.sync().unwrap(), 1);
    let t = a.b.threads(a.b.contacts().unwrap()[0].id.clone()).unwrap()[0]
        .id
        .clone();
    for u in [&a, &b] {
        let bytes = fs::read(u.dir.0.join("brev.db")).unwrap();
        assert!(!contains(&bytes, MARKER));
        assert!(contains(&bytes, &t), "control: the thread id is stored");
    }
}

#[test]
fn create_refuses_existing_files() {
    const URL: &str = "http://127.0.0.1:9";
    let key = TestKey::new().public;
    // The store already there: `Io`, and it is untouched.
    let dir = TempDir::new();
    fs::write(dir.0.join("brev.db"), b"not a store").unwrap();
    let r = Brev::create(dir.arg(), URL.into(), &random::<32>(), &key);
    assert!(matches!(r.map(drop), Err(BrevError::Io)));
    assert_eq!(fs::read(dir.0.join("brev.db")).unwrap(), b"not a store");

    // A complete session is not overwritten, and still opens.
    let dir = TempDir::new();
    let dek: [u8; 32] = random();
    drop(Brev::create(dir.arg(), URL.into(), &dek, &key).unwrap());
    let before = fs::read(dir.0.join("brev.db")).unwrap();
    let r = Brev::create(dir.arg(), URL.into(), &random::<32>(), &key);
    assert!(matches!(r.map(drop), Err(BrevError::Io)));
    assert_eq!(fs::read(dir.0.join("brev.db")).unwrap(), before);
    Brev::open(dir.arg(), URL.into())
        .unwrap()
        .unlock(&dek, TEST_IDLE)
        .unwrap();

    // Bad input makes no file: the DEK, the key, the directory, the relay.
    let dir = TempDir::new();
    for dek in [&[1u8; 31][..], &[1u8; 33][..], &[0u8; 32][..]] {
        let r = Brev::create(dir.arg(), URL.into(), dek, &key);
        assert!(matches!(r.map(drop), Err(BrevError::Malformed)));
    }
    let mut off_curve = key;
    off_curve[64] ^= 1;
    for bad in [&[][..], &[4; 65], &off_curve] {
        let r = Brev::create(dir.arg(), URL.into(), &random::<32>(), bad);
        assert!(matches!(r.map(drop), Err(BrevError::Malformed)));
    }
    let r = Brev::create("relative/dir".into(), URL.into(), &random::<32>(), &key);
    assert!(matches!(r.map(drop), Err(BrevError::Malformed)));
    for url in [
        "http://localhost:8787",
        "http://[::1]:8787",
        "https://127.0.0.1:8787",
        "http://10.0.0.2:8787",
        "",
    ] {
        let r = Brev::create(dir.arg(), url.into(), &random::<32>(), &key);
        assert!(matches!(r.map(drop), Err(BrevError::Malformed)), "{url}");
    }
    assert!(dir.files().is_empty());
    // `open` checks the relay URL too.
    let dir = TempDir::new();
    drop(Brev::create(dir.arg(), URL.into(), &random::<32>(), &key).unwrap());
    assert!(matches!(
        Brev::open(dir.arg(), "http://localhost:9".into()).map(drop),
        Err(BrevError::Malformed)
    ));
}

#[test]
fn store_files_are_0600() {
    let relay = Relayed::new();
    let (a, b, b_at_a, _) = pair(&relay);
    let check = |u: &User, when: &str| {
        for name in FILES {
            let mode = fs::metadata(u.dir.0.join(name))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{when}: {name}");
        }
    };
    check(&a, "created");
    a.send(&b_at_a, b"s", b"x");
    assert_eq!(b.b.sync().unwrap(), 1);
    for u in [&a, &b] {
        check(u, "after writes");
    }
}

#[test]
fn no_plaintext_in_any_file() {
    const SUBJECT: &[u8] = b"BREV-P2-SUBJECT-MARKER-0f3a9c";
    const BODY: &[u8] = b"BREV-P2-BODY-MARKER-b71e04";
    let relay = Relayed::new();
    let (a, b) = (User::new(&relay.url), User::new(&relay.url));
    a.register("anna-marker-51c0");
    b.register("bert-marker-a93e");
    let b_at_a = a.add("bert-marker-a93e");
    let a_at_b = b.add("anna-marker-51c0");
    let markers: [&[u8]; 4] = [SUBJECT, BODY, b"anna-marker-51c0", b"bert-marker-a93e"];
    let ta = a.send(&b_at_a, SUBJECT, BODY);
    let tb = b.send(&a_at_b, SUBJECT, BODY);
    assert_eq!(a.b.sync().unwrap(), 1);
    assert_eq!(b.b.sync().unwrap(), 1);

    // Not vacuous: the content went in and comes back out, both ways.
    for (u, c) in [(&a, &b_at_a), (&b, &a_at_b)] {
        assert_eq!(
            u.letters(c),
            [
                (SUBJECT.to_vec(), BODY.to_vec()),
                (SUBJECT.to_vec(), BODY.to_vec())
            ]
        );
    }

    let dirs = [a.dir.0.clone(), b.dir.0.clone()];
    let scan = |when: &str| {
        for dir in &dirs {
            for entry in fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                let bytes = fs::read(&path).unwrap();
                for m in markers {
                    assert!(!contains(&bytes, m), "{when}: marker in {}", path.display());
                }
            }
            // Positive control: both thread ids (plaintext) are in each
            // store, so the scan reads it.
            let bytes = fs::read(dir.join("brev.db")).unwrap();
            assert!(contains(&bytes, &ta) && contains(&bytes, &tb), "{when}");
        }
    };
    scan("unlocked");
    a.b.lock();
    b.b.lock();
    scan("locked");
    drop(a.b);
    drop(b.b);
    scan("closed");
    assert_eq!(a.dir.files(), FILES, "no journal left behind");
    assert_eq!(b.dir.files(), FILES, "no journal left behind");
}

/// The sealed content columns of a Phase 3 store.
const SEALED: [(&str, &str); 7] = [
    ("identity", "keys"),
    ("identity", "address"),
    ("contacts", "bundle"),
    ("contacts", "address"),
    ("contacts", "pending"),
    ("threads", "subject"),
    ("messages", "body"),
];

#[test]
fn column_lengths_are_bucketed() {
    let relay = Relayed::new();
    let (a, b, b_at_a, _) = pair(&relay);
    let subject = vec![b's'; MAX_SUBJECT];
    let body = vec![b'b'; MAX_BODY];
    for len in [0, 300, 1500, 5000, MAX_BODY] {
        a.send(&b_at_a, &subject, &body[..len]);
    }
    assert_eq!(b.b.sync().unwrap(), 5);

    let is_bucket = |n: usize| matches!(n, 256 | 1024 | 4096) || (n.is_multiple_of(16384) && n > 0);
    for u in [&a, &b] {
        let raw = rusqlite::Connection::open_with_flags(
            u.dir.0.join("brev.db"),
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
                assert!(n > 40 && is_bucket(n - 40), "{table}.{column} is {n}");
                lengths.push(n - 40);
            }
        }
        // Every row was checked, and the buckets differ as the sizes do:
        // 256 for keys, addresses, bundles and an empty `pending`, 1 KiB
        // for the 256-byte subjects, and 256 B, 1 KiB, 4 KiB, 16 KiB,
        // 80 KiB for the bodies.
        lengths.sort_unstable();
        lengths.dedup();
        assert_eq!(lengths, [256, 1024, 4096, 16384, 81920]);
    }
}

#[test]
fn older_store_is_refused() {
    let dir = TempDir::new();
    let key = TestKey::new().public;
    let dek: [u8; 32] = random();
    drop(Brev::create(dir.arg(), "http://127.0.0.1:9".into(), &dek, &key).unwrap());
    let raw = rusqlite::Connection::open(dir.0.join("brev.db")).unwrap();
    for old in [1, 2] {
        raw.pragma_update(None, "user_version", old).unwrap();
        assert!(matches!(
            Brev::open(dir.arg(), "http://127.0.0.1:9".into()).map(drop),
            Err(BrevError::Corrupt)
        ));
    }
    raw.pragma_update(None, "user_version", 4).unwrap();
    Brev::open(dir.arg(), "http://127.0.0.1:9".into())
        .unwrap()
        .unlock(&dek, TEST_IDLE)
        .unwrap();
}

#[test]
fn thread_of_is_gated_metadata() {
    let (dir, dir_b) = (TempDir::new(), TempDir::new());
    let key = TestKey::new();
    let mut a = Core::create(&dir.0.join("a.db"), &mut random(), &key.public).unwrap();
    let mut b = Core::create(&dir_b.0.join("b.db"), &mut random(), &TestKey::new().public).unwrap();
    a.confirm_active().unwrap();
    b.confirm_active().unwrap();
    let b_at_a = a.add_contact(&b.bundle().unwrap(), b"bob").unwrap();
    let mut letter = a.seal_letter(b_at_a, b"s", b"x").unwrap();
    let der = key.sign_digest(&letter.digest());
    a.attach_signature(&mut letter, &der).unwrap();
    let t = a.store_sent(&letter).unwrap();
    let m = a.messages(t).unwrap()[0].id;
    assert_eq!(a.thread_of(m).unwrap(), t);
    assert!(matches!(
        a.thread_of(MessageId([0; 16])),
        Err(Error::NotFound)
    ));
    a.lock();
    assert!(matches!(a.thread_of(m), Err(Error::Locked)));
}
