//! Phase 3 end to end (docs/PHASE3_DESIGN.md §8), on Phase 4's relay and
//! surface (docs/PHASE4_DESIGN.md §5): two `Brev` sessions in temp dirs, the
//! relay in-process on 127.0.0.1:0, P-256 test keys standing in for the
//! Secure Enclave, and the FFI API exactly as the Swift app uses it.
//! Identities register with no invite (open registration, D-0116) and
//! become contacts by request. Includes both definition-of-done tests of
//! CLAUDE.md §5 Phase 3: `relay_file_holds_no_plaintext` and
//! `changed_key_warns_and_blocks_sending`.

mod common;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use brev_core::{Brev, BrevError};
use brev_relay::{Decision, Endpoint, Policy};
use common::{len32, pair, read, unlock_active, Relayed, TestKey, User};

/// UTF-8 and UTF-16LE forms of a marker.
fn encodings(marker: &str) -> [Vec<u8>; 2] {
    let utf16: Vec<u8> = marker.encode_utf16().flat_map(u16::to_le_bytes).collect();
    [marker.as_bytes().to_vec(), utf16]
}

/// A relay policy for the tests: counts acks, can deny the next ack, and
/// can lock a session when its inbox is asked for (a lock that comes while
/// `sync` is on the network).
#[derive(Default)]
struct Hooks {
    acks: AtomicUsize,
    deny_next_ack: AtomicBool,
    lock_on_inbox: Mutex<Option<Arc<Brev>>>,
}

struct HookPolicy(Arc<Hooks>);

impl Policy for HookPolicy {
    fn register(&self, _: &str) -> Decision {
        Decision::Allow
    }
    fn submit(&self, _: &[u8; 32], _: &[u8; 32], _: usize) -> Decision {
        Decision::Allow
    }
    fn request(&self, _: &[u8; 32], endpoint: Endpoint) -> Decision {
        match endpoint {
            Endpoint::Inbox => {
                if let Some(b) = self.0.lock_on_inbox.lock().unwrap().take() {
                    b.lock();
                }
                Decision::Allow
            }
            Endpoint::Ack => {
                self.0.acks.fetch_add(1, Ordering::SeqCst);
                if self.0.deny_next_ack.swap(false, Ordering::SeqCst) {
                    Decision::Deny
                } else {
                    Decision::Allow
                }
            }
            _ => Decision::Allow,
        }
    }
}

fn hooked() -> (Relayed, Arc<Hooks>) {
    let hooks = Arc::new(Hooks::default());
    (
        Relayed::with(Box::new(HookPolicy(Arc::clone(&hooks)))),
        hooks,
    )
}

/// The one ciphertext envelope waiting at the relay, raw from its file.
fn waiting_wire(relay: &Relayed) -> Vec<u8> {
    let raw = rusqlite::Connection::open_with_flags(
        relay.db(),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    raw.query_row("SELECT wire FROM envelopes", [], |r| r.get(0))
        .unwrap()
}

#[test]
fn two_sessions_exchange_letters_through_the_relay() {
    let relay = Relayed::new();
    let (a, b, b_at_a, a_at_b) = pair(&relay);
    a.send(
        &b_at_a,
        "Hei Bert".as_bytes(),
        "Første brev. Blåbær.".as_bytes(),
    );
    assert_eq!(relay.waiting(), 1);
    assert_eq!(b.b.sync().unwrap().letters, 1);
    assert_eq!(relay.waiting(), 0, "deleted after delivery");
    assert_eq!(b.b.sync().unwrap().letters, 0, "each letter arrives once");
    b.send(&a_at_b, b"Svar", b"Takk for brevet!");
    assert_eq!(a.b.sync().unwrap().letters, 1);

    let first = (
        "Hei Bert".as_bytes().to_vec(),
        "Første brev. Blåbær.".as_bytes().to_vec(),
    );
    let second = (b"Svar".to_vec(), b"Takk for brevet!".to_vec());
    assert_eq!(a.letters(&b_at_a), [first.clone(), second.clone()]);
    assert_eq!(b.letters(&a_at_b), [first, second]);
    // Directions: the first thread was sent by A, the second by B.
    for (u, c, mine) in [(&a, &b_at_a, 0), (&b, &a_at_b, 1)] {
        let threads = u.b.threads(c.clone()).unwrap();
        for (i, t) in threads.iter().enumerate() {
            let m = &u.b.messages(t.id.clone()).unwrap()[0];
            assert_eq!(m.outgoing, i == mine);
        }
    }

    // Names are the addresses; the codes each shows match the other's own.
    let (ma, mb) = (a.b.me().unwrap(), b.b.me().unwrap());
    assert!(ma.registered && mb.registered);
    assert_eq!(read(&ma.address), b"anna");
    assert_eq!(read(&a.b.contacts().unwrap()[0].name), b"bert");
    let info = a.b.contact_info(b_at_a).unwrap();
    assert_eq!(read(&info.address), b"bert");
    assert_eq!(info.code, mb.code);
    assert!(info.new_code.is_empty());
    assert_eq!(b.b.contact_info(a_at_b).unwrap().code, ma.code);
    assert_ne!(ma.code, mb.code);
    assert_eq!(ma.code.len(), 35);
    assert!(ma.code.iter().enumerate().all(|(i, &c)| if i % 6 == 5 {
        c == b' '
    } else {
        matches!(c, b'A'..=b'Z' | b'2'..=b'7')
    }));
}

/// DoD: the relay's file (and any journal) never holds a subject or body,
/// in UTF-8 or UTF-16LE. Controls: both addresses (the directory) are in
/// it, and so is a slice of the waiting ciphertext, which is gone once the
/// letter is acknowledged.
#[test]
fn relay_file_holds_no_plaintext() {
    const SUBJECT: &str = "BREV-P3-SUBJECT-MARKER-6c1f0e";
    const BODY: &str = "BREV-P3-BODY-MARKER-e93a57 blåbærsyltetøy";
    let relay = Relayed::new();
    let (a, b, b_at_a, a_at_b) = pair(&relay);
    let markers: Vec<Vec<u8>> = [SUBJECT, BODY].iter().flat_map(|m| encodings(m)).collect();
    let scan = |when: &str| {
        for m in &markers {
            assert!(
                !relay.files_contain(m),
                "{when}: marker in the relay's files"
            );
        }
        assert!(relay.files_contain(b"anna") && relay.files_contain(b"bert"));
    };

    a.send(&b_at_a, SUBJECT.as_bytes(), BODY.as_bytes());
    let wire = waiting_wire(&relay);
    let slice = &wire[94..94 + 32];
    assert!(relay.files_contain(slice), "control: ciphertext is found");
    scan("waiting");
    assert_eq!(b.b.sync().unwrap().letters, 1);
    assert!(!relay.files_contain(slice), "gone after the ack");
    b.send(&a_at_b, SUBJECT.as_bytes(), BODY.as_bytes());
    scan("second waiting");
    assert_eq!(a.b.sync().unwrap().letters, 1);
    scan("delivered");
    assert_eq!(relay.waiting(), 0);
    // Not vacuous: both letters arrived with the markers.
    let letter = (SUBJECT.as_bytes().to_vec(), BODY.as_bytes().to_vec());
    assert_eq!(a.letters(&b_at_a), [letter.clone(), letter.clone()]);
    assert_eq!(b.letters(&a_at_b), [letter.clone(), letter]);
}

/// DoD: a changed key for a pinned contact triggers the warning and blocks
/// sending until the shown new code is accepted.
#[test]
fn changed_key_warns_and_blocks_sending() {
    let relay = Relayed::new();
    let (a, b, b_at_a, _) = pair(&relay);
    a.send(&b_at_a, b"s", b"to the first bert");
    b.b.sync().unwrap();
    let old_code = b.b.me().unwrap().code;

    // B loses its keys; the operator releases the address and a fresh B'
    // registers it.
    assert!(relay.relay.release("bert").unwrap());
    let b2 = User::new(&relay.url);
    relay.join(&b2, "bert");
    let new_code = b2.b.me().unwrap().code;
    assert_ne!(new_code, old_code);

    // Detected at Send: warning state, both codes, nothing made or sent.
    assert!(matches!(a.prepare(&b_at_a), Err(BrevError::KeyChanged)));
    let rows = a.b.contacts().unwrap();
    assert!(rows[0].key_changed);
    drop(rows);
    let info = a.b.contact_info(b_at_a.clone()).unwrap();
    assert_eq!(info.code, old_code);
    assert_eq!(info.new_code, new_code, "the code B' shows as its own");
    let waiting = relay.waiting();
    assert!(matches!(
        a.sign(&b_at_a, b"s", 1, b"x", 1),
        Err(BrevError::KeyChanged)
    ));
    assert!(matches!(a.b.submit(), Err(BrevError::NotFound)));
    assert_eq!(relay.waiting(), waiting, "no envelope was sent");
    // Still blocked on the next try.
    assert!(matches!(a.prepare(&b_at_a), Err(BrevError::KeyChanged)));

    // Acceptance needs the shown new code.
    for wrong in [old_code.clone(), vec![b'A'; 35], Vec::new()] {
        assert!(matches!(
            a.b.accept_new_key(b_at_a.clone(), wrong),
            Err(BrevError::KeyChanged)
        ));
    }
    assert!(a.b.contacts().unwrap()[0].key_changed);
    a.b.accept_new_key(b_at_a.clone(), info.new_code.clone())
        .unwrap();
    assert!(!a.b.contacts().unwrap()[0].key_changed);
    let after = a.b.contact_info(b_at_a.clone()).unwrap();
    assert_eq!((after.code, after.new_code), (new_code, Vec::new()));
    // The old thread stays with the contact.
    assert_eq!(a.b.threads(b_at_a.clone()).unwrap().len(), 1);

    // After B' adds A (a request, so B' takes A's letters), a letter
    // reaches B'.
    let a_at_b2 = b2.add("anna");
    a.send(&b_at_a, b"s", b"to the new bert");
    assert_eq!(b2.b.sync().unwrap().letters, 1);
    assert_eq!(
        b2.letters(&a_at_b2),
        [(b"s".to_vec(), b"to the new bert".to_vec())]
    );
}

/// Ack after store (design §5.3): a lock between poll and store
/// acknowledges nothing and the letter arrives after unlock; a refused ack
/// means a redelivery that is `Duplicate` and acknowledged then; a damaged
/// contact row keeps the letter at the relay until the row is whole.
#[test]
fn ack_after_store() {
    let (relay, hooks) = hooked();
    let (a, b, b_at_a, a_at_b) = pair(&relay);

    // A lock that comes while `sync` is polling.
    a.send(&b_at_a, b"s", b"one");
    *hooks.lock_on_inbox.lock().unwrap() = Some(Arc::clone(&b.b));
    assert!(matches!(b.b.sync(), Err(BrevError::Locked)));
    assert!(b.b.is_locked());
    assert_eq!(hooks.acks.load(Ordering::SeqCst), 0, "nothing acknowledged");
    assert_eq!(relay.waiting(), 1);
    unlock_active(&b.b, &b.dek);
    assert!(
        b.b.threads(a_at_b.clone()).unwrap().is_empty(),
        "nothing stored"
    );
    assert_eq!(b.b.sync().unwrap().letters, 1);
    assert_eq!(relay.waiting(), 0);

    // The ack is refused: the letter is stored and counted, comes again,
    // is a duplicate, and is acknowledged then.
    a.send(&b_at_a, b"s", b"two");
    hooks.deny_next_ack.store(true, Ordering::SeqCst);
    let acks = hooks.acks.load(Ordering::SeqCst);
    assert_eq!(b.b.sync().unwrap().letters, 1);
    assert_eq!(hooks.acks.load(Ordering::SeqCst), acks + 1);
    assert_eq!(relay.waiting(), 1, "still at the relay");
    assert_eq!(b.b.sync().unwrap().letters, 0, "a duplicate");
    assert_eq!(relay.waiting(), 0);

    // A damaged contact row in B's file: not acknowledged, the letter stays.
    a.send(&b_at_a, b"s", b"three");
    let raw = rusqlite::Connection::open(b.dir.0.join("brev.db")).unwrap();
    let bundle: Vec<u8> = raw
        .query_row(
            "SELECT bundle FROM contacts WHERE id = ?1",
            [&a_at_b],
            |r| r.get(0),
        )
        .unwrap();
    let mut damaged = bundle.clone();
    damaged[50] ^= 1;
    let set = |v: &[u8]| {
        raw.execute(
            "UPDATE contacts SET bundle = ?1 WHERE id = ?2",
            rusqlite::params![v, &a_at_b],
        )
        .unwrap();
    };
    set(&damaged);
    let acks = hooks.acks.load(Ordering::SeqCst);
    for _ in 0..2 {
        assert_eq!(b.b.sync().unwrap().letters, 0);
        assert_eq!(relay.waiting(), 1, "kept at the relay");
    }
    assert_eq!(hooks.acks.load(Ordering::SeqCst), acks, "no ack");
    set(&bundle);
    assert_eq!(b.b.sync().unwrap().letters, 1);
    assert_eq!(relay.waiting(), 0);

    // Exactly one stored copy of each letter.
    let bodies: Vec<Vec<u8>> = b
        .letters(&a_at_b)
        .into_iter()
        .map(|(_, body)| body)
        .collect();
    assert_eq!(
        bodies,
        [b"one".to_vec(), b"two".to_vec(), b"three".to_vec()]
    );
}

/// A signed letter survives a relay that is down: `Network` keeps it, a
/// `sync` does not send it, and `submit` alone sends it once the relay is
/// back, with no second signature.
#[test]
fn submit_retry_is_idempotent() {
    let mut relay = Relayed::new();
    let (a, b, b_at_a, a_at_b) = pair(&relay);
    a.prepare(&b_at_a).unwrap();
    let digest = a.sign(&b_at_a, b"s", 1, b"retry", 5).unwrap();
    a.seal(&digest).unwrap();

    relay.stop();
    for _ in 0..2 {
        assert!(matches!(a.b.submit(), Err(BrevError::Network)));
    }
    assert!(matches!(a.b.sync(), Err(BrevError::Network)));
    assert!(
        a.b.threads(b_at_a.clone()).unwrap().is_empty(),
        "no own copy yet"
    );

    relay.restart();
    assert_eq!(a.b.sync().unwrap().letters, 0);
    assert_eq!(relay.waiting(), 0, "sync does not send the letter");
    let thread = a.b.submit().unwrap();
    assert_eq!(relay.waiting(), 1);
    assert!(
        matches!(a.b.submit(), Err(BrevError::NotFound)),
        "sent once"
    );
    assert_eq!(a.b.threads(b_at_a.clone()).unwrap()[0].id, thread);
    assert_eq!(a.letters(&b_at_a), [(b"s".to_vec(), b"retry".to_vec())]);
    assert_eq!(b.b.sync().unwrap().letters, 1);
    assert_eq!(b.letters(&a_at_b), [(b"s".to_vec(), b"retry".to_vec())]);

    // Registration keeps its body over `Network` the same way.
    let c = User::new(&relay.url);
    let digest = c.b.register_request(b"carl", 4).unwrap();
    let signature = c.key.sign_digest(&digest);
    relay.stop();
    assert!(matches!(
        c.b.register(signature.clone(), Vec::new()),
        Err(BrevError::Network)
    ));
    assert!(!c.b.me().unwrap().registered);
    relay.restart();
    c.b.register(signature, Vec::new()).unwrap();
    assert!(c.b.me().unwrap().registered);
}

/// A locked session makes no request, and a `sync` that was polling when
/// the lock came acknowledges nothing.
#[test]
fn locked_session_makes_no_request() {
    let (relay, hooks) = hooked();
    let (a, b, b_at_a, a_at_b) = pair(&relay);
    b.send(&a_at_b, b"s", b"waiting");
    a.prepare(&b_at_a).unwrap();
    let digest = a.sign(&b_at_a, b"s", 1, b"x", 1).unwrap();
    let signature = a.key.sign_digest(&digest);

    a.b.lock();
    let requests = relay.requests();
    let locked = |r: Result<(), BrevError>| assert!(matches!(r, Err(BrevError::Locked)));
    locked(a.b.sync().map(drop));
    locked(a.b.prepare_send(b_at_a.clone(), common::clean()));
    locked(a.b.add_contact(b"carl", 4).map(drop));
    locked(a.b.register_request(b"carl", 4).map(drop));
    locked(a.b.register(signature.clone(), Vec::new()));
    locked(a.b.attach_token_signature(signature.clone()).map(drop));
    locked(a.b.attach_signature(signature));
    locked(a.b.submit().map(drop));
    locked(a.b.requests().map(drop));
    locked(a.b.answer_request(vec![0; 32], true).map(drop));
    locked(a.b.block_contact(b_at_a.clone()));
    assert_eq!(relay.requests(), requests, "no request while locked");

    // A lock while `sync` polls: no ack follows, the letter waits.
    unlock_active(&a.b, &a.dek);
    *hooks.lock_on_inbox.lock().unwrap() = Some(Arc::clone(&a.b));
    let requests = relay.requests();
    assert!(matches!(a.b.sync(), Err(BrevError::Locked)));
    assert_eq!(
        relay.requests(),
        requests + 2,
        "the events and the poll, and nothing after"
    );
    assert_eq!(hooks.acks.load(Ordering::SeqCst), 0);
    assert_eq!(relay.waiting(), 1);
    unlock_active(&a.b, &a.dek);
    assert_eq!(a.b.sync().unwrap().letters, 1);
    assert_eq!(hooks.acks.load(Ordering::SeqCst), 1);
}

/// Letters from someone the recipient has not added are dropped and
/// acknowledged (owner question Q2), and so are letters from a contact's
/// new key before it is accepted. In Phase 4 the relay stores such a letter
/// only if it lies (or a same-user program edits its file, CLAUDE.md §2):
/// here `links` is set by hand, and the client rule still holds.
#[test]
fn strangers_are_dropped_and_acked() {
    let relay = Relayed::new();
    let (_a, b, _, a_at_b) = pair(&relay);
    let c = User::new(&relay.url);
    relay.join(&c, "carl");
    relay.force_link("bert", "carl");
    let b_at_c = c.add("bert");
    c.send(&b_at_c, b"s", b"from a stranger");
    assert_eq!(relay.waiting(), 1);
    assert_eq!(b.b.sync().unwrap().letters, 0);
    assert_eq!(relay.waiting(), 0, "acknowledged");
    assert_eq!(b.b.contacts().unwrap().len(), 1);
    assert!(b.b.threads(a_at_b.clone()).unwrap().is_empty());

    // A's key changes; A' (the new "anna") writes to B before B accepts.
    assert!(relay.relay.release("anna").unwrap());
    let a2 = User::new(&relay.url);
    relay.join(&a2, "anna");
    relay.force_link("bert", "anna");
    let b_at_a2 = a2.add("bert");
    a2.send(&b_at_a2, b"s", b"from the new key");
    assert_eq!(b.b.sync().unwrap().letters, 0);
    assert_eq!(relay.waiting(), 0, "acknowledged");
    assert!(b.b.threads(a_at_b.clone()).unwrap().is_empty());
    // Control: once B accepts the new key, its letters arrive.
    assert!(matches!(b.prepare(&a_at_b), Err(BrevError::KeyChanged)));
    let new_code = b.b.contact_info(a_at_b.clone()).unwrap().new_code;
    b.b.accept_new_key(a_at_b.clone(), new_code).unwrap();
    a2.send(&b_at_a2, b"s", b"accepted");
    assert_eq!(b.b.sync().unwrap().letters, 1);
    assert_eq!(b.letters(&a_at_b), [(b"s".to_vec(), b"accepted".to_vec())]);
}

/// Addresses (owner question Q3, brev-proto's rules), registered with no
/// invite (open registration, D-0116): typed upper case is
/// folded; the rules, taken addresses (another address goes through), one
/// address per identity; contacts by address; nothing is asked of the
/// relay before the signed registration.
#[test]
fn registration_and_contacts_by_address() {
    let relay = Relayed::new();
    let a = User::new(&relay.url);
    // Before registration: no sync, no lookup, and no request.
    assert!(matches!(a.b.sync(), Err(BrevError::NotFound)));
    assert!(matches!(
        a.b.add_contact(b"bert", 4),
        Err(BrevError::NotFound)
    ));
    assert_eq!(relay.requests(), 0);

    for bad in [
        &b"ab"[..],
        b"1anna",
        b"-anna",
        b"an_na",
        b"an na",
        "blåbær".as_bytes(),
        &[b'a'; 33],
    ] {
        assert!(
            matches!(
                a.b.register_request(bad, len32(bad.len())),
                Err(BrevError::Malformed)
            ),
            "{bad:?}"
        );
    }
    // Only the used length counts, and it must fit the buffer.
    assert!(matches!(
        a.b.register_request(b"anna", 5),
        Err(BrevError::Malformed)
    ));
    // No request, then a signature by another key.
    assert!(matches!(
        a.b.register(vec![0x30], Vec::new()),
        Err(BrevError::NotFound)
    ));
    let digest = a.b.register_request(b"ANNA", 4).unwrap();
    assert!(matches!(
        a.b.register(TestKey::new().sign_digest(&digest), Vec::new()),
        Err(BrevError::Signing)
    ));
    assert!(matches!(
        a.b.register(vec![0x30], Vec::new()),
        Err(BrevError::NotFound)
    ));
    // An attestation over 8 192 bytes.
    let digest = a.b.register_request(b"ANNA", 4).unwrap();
    assert!(matches!(
        a.b.register(a.key.sign_digest(&digest), vec![0; 8193]),
        Err(BrevError::Malformed)
    ));
    assert_eq!(relay.requests(), 0, "nothing asked before a good signature");
    // Registered with no invite: one request.
    a.b.register(a.key.sign_digest(&digest), Vec::new())
        .unwrap();
    assert_eq!(relay.requests(), 1);
    assert_eq!(read(&a.b.me().unwrap().address), b"anna");
    assert!(matches!(
        a.b.register_request(b"anna2", 5),
        Err(BrevError::Duplicate)
    ));

    // Taken, and another address goes through.
    let b = User::new(&relay.url);
    let digest = b.b.register_request(b"anna", 4).unwrap();
    assert!(matches!(
        b.b.register(b.key.sign_digest(&digest), Vec::new()),
        Err(BrevError::AddressTaken)
    ));
    assert!(!b.b.me().unwrap().registered);
    let digest = b.b.register_request(b"bert", 4).unwrap();
    b.b.register(b.key.sign_digest(&digest), Vec::new())
        .unwrap();
    assert!(b.b.me().unwrap().registered);
    // A new identity has no contact: registration approves no one.
    assert!(b.b.contacts().unwrap().is_empty());

    // Contacts by address.
    assert!(matches!(
        a.b.add_contact(b"anna", 4),
        Err(BrevError::Malformed)
    ));
    assert!(matches!(
        a.b.add_contact(b"nobody", 6),
        Err(BrevError::NotFound)
    ));
    assert!(matches!(
        a.b.add_contact(b"b", 1),
        Err(BrevError::Malformed)
    ));
    let b_at_a = a.add("Bert");
    assert_eq!(b_at_a.len(), 16);
    assert!(matches!(
        a.b.add_contact(b"bert", 4),
        Err(BrevError::Duplicate)
    ));
    let rows = a.b.contacts().unwrap();
    assert_eq!(read(&rows[0].name), b"bert");
    assert!(rows[0].waiting && !rows[0].blocked);
    drop(rows);
    // A contact id that is not 16 bytes.
    assert!(matches!(a.prepare(&[0; 32]), Err(BrevError::Malformed)));
    // Until B approves, a letter to B is not made at all (Phase 3 sent it
    // and B dropped it).
    assert!(matches!(a.prepare(&b_at_a), Err(BrevError::NotApproved)));
    assert!(a.b.threads(b_at_a).unwrap().is_empty());
    assert_eq!(relay.waiting(), 0);
}
