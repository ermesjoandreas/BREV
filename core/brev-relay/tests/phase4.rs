//! Phase 4 relay tests (docs/PHASE4_DESIGN.md §8, relay tests 1 to 12, with
//! the three DoD tests 5, 7 and 9; the invite tests went with the invites,
//! D-XXXX (no invites)), open registration, *Blokker* (owner answer 6) and
//! the limit flags. The clock is the relay's manual [`brev_relay::Clock`],
//! moved by the tests.

mod common;

use std::fs;
use std::process::Command;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use brev_proto::body::{EventKind, MAX_ATTESTATION, REGISTRATION_V3_MAX};
use brev_relay::{Clock, Config, Error, Gates, IdentityVerifier, Open, Relay};
use common::*;
use reqwest::StatusCode;
use rusqlite::Connection;

const LONGEST: &str = "abcdefghijklmnopqrstuvwxyz012345";

/// A request event from `who` at `address`, as an events answer shows it.
fn request_from(who: &Identity, address: &str) -> Seen {
    Seen {
        kind: EventKind::Request,
        address: address.into(),
        bundle: who.bundle(),
    }
}

/// Test 1 (open registration, D-XXXX (no invites)): anyone registers an
/// address with no invite, like ordinary e-mail: 201, the same registration
/// again 200, a taken address 409 with nothing written. A new identity has
/// no link and no event, so its letters reach nobody (409) until a contact
/// request is approved. The largest v3 body goes through the router.
#[test]
fn registration_needs_no_invite() {
    let r = Relayed::new();
    let [a, b, c, d] = [1, 2, 3, 4].map(Identity::new);

    assert_eq!(r.register(&a, "anna"), StatusCode::CREATED);
    assert_eq!(r.register(&a, "anna"), StatusCode::OK, "again");
    assert_eq!(r.register(&b, "bob"), StatusCode::CREATED);
    assert_eq!(r.register(&c, "anna"), StatusCode::CONFLICT, "taken");
    assert_eq!(r.rows("identities"), 2);
    assert_eq!((r.rows("links"), r.rows("events")), (0, 0));

    // Registered is not approved: nothing reaches anna from bob yet.
    let w = wire(&envelope(&b, &a.id, 256, 1));
    assert_eq!(r.submit_as(&b, &w), StatusCode::CONFLICT);
    assert_eq!(r.lookup(&b, "anna"), (StatusCode::OK, a.reply(false)));
    assert_eq!(r.waiting(), 0);
    r.approve(&b, &a, "anna");
    assert_eq!(r.submit_as(&b, &w), StatusCode::ACCEPTED);
    assert_eq!(r.inbox(&a), [w]);

    // The largest registration v3 (8 420 bytes) reaches the rules through
    // the real router: not 413.
    let body = d.registration_with(LONGEST.as_bytes(), &d.public, &[0x5A; MAX_ATTESTATION]);
    assert_eq!(body.len(), REGISTRATION_V3_MAX);
    let want = if cfg!(feature = "app-attest") {
        StatusCode::PRECONDITION_REQUIRED // not the dev marker
    } else {
        StatusCode::CREATED // parsed and ignored
    };
    assert_eq!(r.post("/v1/register", body).0, want);
}

/// Test 5 (DoD): an unapproved sender's valid envelope is refused and
/// stored nowhere; after a request and *Godta* it is stored and delivered;
/// a declined sender is refused and its later requests store no event.
#[test]
fn unapproved_sender_cannot_reach_an_inbox() {
    let r = Relayed::new();
    let [a, b, c] = [1, 2, 3].map(Identity::new);
    r.join(&a, "anna");
    r.join(&b, "bob");
    r.join(&c, "carl");

    let w = wire(&envelope(&b, &a.id, 256, 1));
    assert_eq!(r.lookup(&b, "anna"), (StatusCode::OK, a.reply(false)));
    assert_eq!(r.submit_as(&b, &w), StatusCode::CONFLICT);
    assert_eq!(r.waiting(), 0);
    assert!(r.inbox(&a).is_empty());
    assert_eq!(r.count(&b, 1), 0, "a 409 is not counted");

    // Asking is not approval.
    assert_eq!(r.ask(&b, "anna"), StatusCode::ACCEPTED);
    assert_eq!(r.submit_as(&b, &w), StatusCode::CONFLICT);
    assert_eq!(r.waiting(), 0);
    assert_eq!(r.events(&a), [request_from(&b, "bob")]);

    // Godta: stored and delivered on the next poll.
    assert_eq!(r.answer(&a, &b, true), StatusCode::NO_CONTENT);
    assert_eq!(r.lookup(&b, "anna"), (StatusCode::OK, a.reply(true)));
    assert_eq!(r.submit_as(&b, &w), StatusCode::ACCEPTED);
    assert_eq!(r.inbox(&a), std::slice::from_ref(&w));

    // A declined sender.
    assert_eq!(r.ask(&c, "anna"), StatusCode::ACCEPTED);
    assert_eq!(r.answer(&a, &c, false), StatusCode::NO_CONTENT);
    let wc = wire(&envelope(&c, &a.id, 256, 2));
    assert_eq!(r.submit_as(&c, &wc), StatusCode::CONFLICT);
    assert_eq!(r.ask(&c, "anna"), StatusCode::ACCEPTED);
    assert!(r.events(&a).is_empty(), "no new request from carl");
    assert_eq!(r.waiting(), 1);
    assert_eq!(r.inbox(&a), [w]);
}

/// Test 6a: a repeated request stores one event; both are counted.
#[test]
fn requests_once_per_pair() {
    let r = Relayed::new();
    let [a, b] = [1, 2].map(Identity::new);
    r.join(&a, "anna");
    r.join(&b, "bob");
    assert_eq!(r.ask(&b, "anna"), StatusCode::ACCEPTED);
    assert_eq!(r.ask(&b, "anna"), StatusCode::ACCEPTED);
    assert_eq!(r.events(&a), [request_from(&b, "bob")]);
    assert_eq!(
        r.events(&a),
        [request_from(&b, "bob")],
        "reading deletes nothing"
    );
    assert_eq!(r.count(&b, 2), 2);
    // Own address and unknown: 400 and 404, not counted.
    assert_eq!(r.ask(&b, "bob"), StatusCode::BAD_REQUEST);
    assert_eq!(r.ask(&b, "nobody"), StatusCode::NOT_FOUND);
    assert_eq!(r.count(&b, 2), 2);
}

/// Test 6b: answers need an event; yes to a request approves and tells the
/// asker; no declines; approved events are only seen.
#[test]
fn event_answer_rules() {
    let r = Relayed::new();
    let [a, b, c] = [1, 2, 3].map(Identity::new);
    for (who, address) in [(&a, "anna"), (&b, "bob"), (&c, "carl")] {
        r.join(who, address);
    }
    assert_eq!(r.answer(&a, &b, true), StatusCode::NOT_FOUND);
    assert_eq!(r.ask(&b, "anna"), StatusCode::ACCEPTED);
    assert_eq!(r.answer(&a, &b, true), StatusCode::NO_CONTENT);
    assert_eq!(r.answer(&a, &b, true), StatusCode::NOT_FOUND, "answered");
    let approved = Seen {
        kind: EventKind::Approved,
        address: "anna".into(),
        bundle: a.bundle(),
    };
    assert_eq!(r.events(&b), [approved]);
    assert_eq!(r.answer(&b, &a, false), StatusCode::BAD_REQUEST);
    assert_eq!(r.events(&b).len(), 1, "kept");
    assert_eq!(r.answer(&b, &a, true), StatusCode::NO_CONTENT);
    assert!(r.events(&b).is_empty());

    // Decline: the event goes, the asker hears nothing and is refused.
    assert_eq!(r.ask(&c, "anna"), StatusCode::ACCEPTED);
    assert_eq!(r.answer(&a, &c, false), StatusCode::NO_CONTENT);
    assert_eq!(r.answer(&a, &c, false), StatusCode::NOT_FOUND);
    assert!(r.events(&c).is_empty());
    let w = wire(&envelope(&c, &a.id, 256, 1));
    assert_eq!(r.submit_as(&c, &w), StatusCode::CONFLICT);
}

/// Test 6c: two requests that cross approve both ways; the second is 200
/// and not counted, and the first asker is told.
#[test]
fn crossing_requests_approve_each_other() {
    let r = Relayed::new();
    let [a, b] = [1, 2].map(Identity::new);
    r.join(&a, "anna");
    r.join(&b, "bob");
    assert_eq!(r.ask(&a, "bob"), StatusCode::ACCEPTED);
    assert_eq!(r.ask(&b, "anna"), StatusCode::OK);
    assert_eq!(r.count(&b, 2), 0);
    assert!(r.events(&b).is_empty(), "anna's request is answered");
    assert_eq!(r.events(&a)[0].kind, EventKind::Approved);
    assert_eq!(r.events(&a)[0].address, "bob");
    assert_eq!(
        r.submit_as(&a, &wire(&envelope(&a, &b.id, 256, 1))),
        StatusCode::ACCEPTED
    );
    assert_eq!(
        r.submit_as(&b, &wire(&envelope(&b, &a.id, 256, 2))),
        StatusCode::ACCEPTED
    );
}

/// Test 6d (design Q5): new, pending, declined and over the pending cap are
/// all 202; at the request limit all are 429.
#[test]
fn request_answers_do_not_reveal_a_decline() {
    let r = Relayed::with(
        Box::new(Open),
        |c| {
            c.pending_requests = 2;
            c.requests_per_day = 2;
        },
        Gates::default(),
    );
    let [a, c, d, e, g] = [1, 3, 4, 5, 7].map(Identity::new);
    for (who, address) in [
        (&a, "anna"),
        (&c, "carl"),
        (&d, "dora"),
        (&e, "emil"),
        (&g, "gro"),
    ] {
        r.join(who, address);
    }
    assert_eq!(r.ask(&c, "anna"), StatusCode::ACCEPTED, "new");
    assert_eq!(r.ask(&c, "anna"), StatusCode::ACCEPTED, "pending");
    assert_eq!(r.ask(&d, "anna"), StatusCode::ACCEPTED, "new");
    assert_eq!(r.answer(&a, &d, false), StatusCode::NO_CONTENT);
    assert_eq!(r.ask(&d, "anna"), StatusCode::ACCEPTED, "declined");
    assert_eq!(r.ask(&e, "anna"), StatusCode::ACCEPTED, "fills the cap");
    assert_eq!(r.ask(&g, "anna"), StatusCode::ACCEPTED, "over the cap");
    assert_eq!(r.ask(&g, "anna"), StatusCode::ACCEPTED, "over the cap");
    assert_eq!(
        r.events(&a),
        [request_from(&c, "carl"), request_from(&e, "emil")]
    );
    // The third request of the day: 429 for each of them alike.
    for who in [&c, &d, &g] {
        assert_eq!(r.ask(who, "anna"), StatusCode::TOO_MANY_REQUESTS);
    }
    assert_eq!(r.ask(&e, "carl"), StatusCode::ACCEPTED);
    assert_eq!(r.ask(&e, "dora"), StatusCode::TOO_MANY_REQUESTS);
}

/// Test 6e: A declined B; A asking B lifts it (200), and B's letters go.
#[test]
fn re_adding_a_declined_peer_unblocks_them() {
    let r = Relayed::new();
    let [a, b] = [1, 2].map(Identity::new);
    r.join(&a, "anna");
    r.join(&b, "bob");
    assert_eq!(r.ask(&b, "anna"), StatusCode::ACCEPTED);
    assert_eq!(r.answer(&a, &b, false), StatusCode::NO_CONTENT);
    let w = wire(&envelope(&b, &a.id, 256, 1));
    assert_eq!(r.submit_as(&b, &w), StatusCode::CONFLICT);
    assert_eq!(r.ask(&a, "bob"), StatusCode::OK);
    assert_eq!(r.submit_as(&b, &w), StatusCode::ACCEPTED);
    assert_eq!(r.inbox(&a), [w]);
}

/// Test 7 (DoD): the owner's 50 letters per sender per UTC day are stored,
/// the 51st is 429 and stored nowhere; a 200 resubmit and a 409 are not
/// counted; another sender is not affected; the next day it goes.
#[test]
fn letters_are_rate_limited_per_identity_per_day() {
    let r = Relayed::new();
    let limit = Config::default().letters_per_day;
    assert_eq!(limit, 50);
    let [a, b, c, d] = [1, 2, 3, 4].map(Identity::new);
    for (who, address) in [(&a, "anna"), (&b, "bob"), (&c, "carl"), (&d, "dora")] {
        r.join(who, address);
    }
    r.approve(&a, &b, "bob");
    r.approve(&c, &b, "bob");
    let letters: Vec<Vec<u8>> = (0..=limit)
        .map(|n| wire(&envelope(&a, &b.id, 256, n)))
        .collect();
    for (n, w) in letters[..50].iter().enumerate() {
        assert_eq!(r.submit_as(&a, w), StatusCode::ACCEPTED, "{n}");
        if n == 0 {
            assert_eq!(r.submit_as(&a, w), StatusCode::OK, "already waiting");
        }
        if n == 1 {
            let refused = wire(&envelope(&a, &d.id, 256, 1000));
            assert_eq!(r.submit_as(&a, &refused), StatusCode::CONFLICT);
        }
    }
    assert_eq!(r.count(&a, 1), 50);
    assert_eq!(r.submit_as(&a, &letters[50]), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!((r.waiting(), r.count(&a, 1)), (50, 50));
    assert_eq!(
        r.submit_as(&a, &letters[0]),
        StatusCode::OK,
        "a retry of a stored letter is not refused"
    );

    // Another sender, same recipient.
    let other = wire(&envelope(&c, &b.id, 256, 2000));
    assert_eq!(r.submit_as(&c, &other), StatusCode::ACCEPTED);

    // The next UTC day, one second after midnight.
    r.set_time(1, 1);
    assert_eq!(r.submit_as(&a, &letters[50]), StatusCode::ACCEPTED);
    assert_eq!(r.count(&a, 1), 1);
    assert_eq!(r.waiting(), 52);
}

/// Test 8a: 10 requests per requester per day; 429 before any write; the
/// next day they go again. A request to someone who already approved is
/// neither refused nor counted.
#[test]
fn requests_are_rate_limited() {
    let r = Relayed::new();
    let [a, b, c] = [1, 2, 3].map(Identity::new);
    for (who, address) in [(&a, "anna"), (&b, "bob"), (&c, "carl")] {
        r.join(who, address);
    }
    r.approve(&c, &b, "bob");
    for _ in 0..10 {
        assert_eq!(r.ask(&b, "anna"), StatusCode::ACCEPTED);
    }
    assert_eq!(r.ask(&b, "anna"), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(r.count(&b, 2), 10);
    assert_eq!(r.ask(&b, "carl"), StatusCode::OK);
    assert_eq!(r.count(&b, 2), 10);
    r.set_day(1);
    assert_eq!(r.ask(&b, "anna"), StatusCode::ACCEPTED);
    assert_eq!(r.count(&b, 2), 1);
}

/// Test 8c: at most 16 requests wait at one recipient; the 17th asker gets
/// 202 like the others, and nothing waits.
#[test]
fn pending_requests_per_recipient_are_capped() {
    let r = Relayed::new();
    let a = Identity::new(1);
    r.join(&a, "anna");
    let askers: Vec<Identity> = (10..27).map(Identity::new).collect();
    for (n, who) in askers.iter().enumerate() {
        r.join(who, &format!("asker-{n}"));
        assert_eq!(r.ask(who, "anna"), StatusCode::ACCEPTED, "{n}");
    }
    let seen = r.events(&a);
    assert_eq!(seen.len(), 16);
    assert_eq!(seen[15], request_from(&askers[15], "asker-15"));
    assert_eq!(
        r.number("SELECT count(*) FROM events WHERE recipient = ?1", &a.id),
        16
    );
    // Answering one frees a place.
    assert_eq!(r.answer(&a, &askers[0], false), StatusCode::NO_CONTENT);
    let late = Identity::new(40);
    r.join(&late, "late");
    assert_eq!(r.ask(&late, "anna"), StatusCode::ACCEPTED);
    assert_eq!(r.events(&a).last(), Some(&request_from(&late, "late")));
}

/// Test 8d: approved events come before requests, each oldest first, and
/// an answer holds at most 32.
#[test]
fn events_put_approved_before_requests() {
    let r = Relayed::with(
        Box::new(Open),
        |c| c.pending_requests = 40,
        Gates::default(),
    );
    let [a, y] = [1, 3].map(Identity::new);
    r.join(&a, "anna");
    r.join(&y, "yngve");
    assert_eq!(r.ask(&a, "yngve"), StatusCode::ACCEPTED);
    let askers: Vec<Identity> = (10..44).map(Identity::new).collect();
    for (n, who) in askers.iter().enumerate() {
        r.join(who, &format!("asker-{n}"));
        assert_eq!(r.ask(who, "anna"), StatusCode::ACCEPTED);
    }
    assert_eq!(r.answer(&y, &a, true), StatusCode::NO_CONTENT);

    let seen = r.events(&a);
    assert_eq!(seen.len(), 32);
    assert_eq!(
        (seen[0].kind, seen[0].address.as_str()),
        (EventKind::Approved, "yngve")
    );
    for (n, event) in seen[1..].iter().enumerate() {
        assert_eq!(*event, request_from(&askers[n], &format!("asker-{n}")));
    }
}

/// Test 9 (DoD): an approved envelope is handed out on the recipient's
/// next poll, whatever the time of day; nothing is held back.
#[test]
fn approved_envelope_is_delivered_on_the_next_poll() {
    let r = Relayed::new();
    let [a, b] = [1, 2].map(Identity::new);
    r.join(&a, "anna");
    r.join(&b, "bob");
    r.approve(&a, &b, "bob");
    for (n, (day, secs)) in [(0, 8 * 3600), (1, DAY - 60), (2, DAY - 1), (3, 0)]
        .into_iter()
        .enumerate()
    {
        r.set_time(day, secs);
        let w = wire(&envelope(&a, &b.id, 256, u32::try_from(n).unwrap()));
        assert_eq!(r.submit_as(&a, &w), StatusCode::ACCEPTED);
        assert_eq!(r.inbox(&b), std::slice::from_ref(&w), "{day} {secs}");
        assert_eq!(r.ack(&b, &[id(&w)]), StatusCode::NO_CONTENT);
        assert_eq!(r.waiting(), 0);
    }
}

/// Test 10: a submit carries the sender's own token: no prefix is 400,
/// another caller's token 403, a wrong one 401; the recipient cannot
/// replay an acknowledged letter against the sender's count.
#[test]
fn submit_needs_the_senders_token() {
    let r = Relayed::new();
    let [a, b, c] = [1, 2, 3].map(Identity::new);
    for (who, address) in [(&a, "anna"), (&b, "bob"), (&c, "carl")] {
        r.join(who, address);
    }
    r.approve(&a, &b, "bob");
    let w = wire(&envelope(&a, &b.id, 256, 1));
    assert_eq!(
        r.post("/v1/envelopes", w.clone()).0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(r.submit_as(&c, &w), StatusCode::FORBIDDEN);
    assert_eq!(r.submit_as(&b, &w), StatusCode::FORBIDDEN);
    let wrong = [&a.id[..], &c.token, &w].concat();
    assert_eq!(r.post("/v1/envelopes", wrong).0, StatusCode::UNAUTHORIZED);
    assert_eq!(r.waiting(), 0);

    assert_eq!(r.submit_as(&a, &w), StatusCode::ACCEPTED);
    assert_eq!(r.inbox(&b), std::slice::from_ref(&w));
    assert_eq!(r.ack(&b, &[id(&w)]), StatusCode::NO_CONTENT);
    assert_eq!(r.count(&a, 1), 1);
    assert_eq!(r.submit_as(&b, &w), StatusCode::FORBIDDEN, "a replay");
    assert_eq!((r.waiting(), r.count(&a, 1)), (0, 1));
}

/// Test 11a: with `app-attest`, an empty or wrong attestation is 428 before
/// anything is read or written, the dev marker registers; without it, the
/// attestation is ignored.
#[test]
fn attestation_gate() {
    let r = Relayed::new();
    let a = Identity::new(1);
    let register = |attestation: &[u8]| {
        let body = a.registration_with(b"anna", &a.public, attestation);
        r.post("/v1/register", body).0
    };
    #[cfg(feature = "app-attest")]
    {
        let dev = brev_relay::DEV_ATTESTATION;
        assert_eq!(dev, b"BREV-DEV-ATTEST1");
        for bad in [
            &b""[..],
            &b"BREV-DEV-ATTEST2"[..],
            &dev[..15],
            &[&dev[..], b"!"].concat()[..],
        ] {
            assert_eq!(register(bad), StatusCode::PRECONDITION_REQUIRED);
        }
        assert_eq!(r.rows("identities"), 0);
        assert_eq!(register(dev), StatusCode::CREATED);
        assert_eq!(
            register(b""),
            StatusCode::PRECONDITION_REQUIRED,
            "also a retry"
        );
        assert_eq!(register(dev), StatusCode::OK);
    }
    #[cfg(not(feature = "app-attest"))]
    {
        assert_eq!(register(b""), StatusCode::CREATED);
        assert_eq!(register(b"anything"), StatusCode::OK);
    }
}

/// An identity verifier that refuses everyone and counts its calls.
struct Refuse(Arc<AtomicU32>);

impl IdentityVerifier for Refuse {
    fn verify(&self, _: &[u8; 32], evidence: &[u8]) -> bool {
        assert!(evidence.is_empty(), "Phase 4 has no evidence");
        self.0.fetch_add(1, Ordering::SeqCst);
        false
    }
}

/// Test 11b: the identity verifier is asked after the signature check; a
/// refusal is 428 and writes nothing.
#[test]
fn identity_verifier_is_consulted() {
    let calls = Arc::new(AtomicU32::new(0));
    let gates = Gates {
        identity: Box::new(Refuse(Arc::clone(&calls))),
        #[cfg(feature = "app-attest")]
        attest: Box::new(brev_relay::DevAttest),
    };
    let r = Relayed::with(Box::new(Open), |_| {}, gates);
    let a = Identity::new(1);
    assert_eq!(r.register(&a, "anna"), StatusCode::PRECONDITION_REQUIRED);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(r.rows("identities"), 0);
    let mut forged = a.registration(b"anna");
    forged[80] ^= 1; // in the X25519 key
    assert_eq!(r.post("/v1/register", forged).0, StatusCode::UNAUTHORIZED);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "not asked without a valid signature"
    );
}

/// Test 12a: releasing an identity deletes its links, events and counts.
#[test]
fn release_deletes_links_events_counts() {
    let r = Relayed::new();
    let [a, b, c, d] = [1, 2, 3, 4].map(Identity::new);
    for (who, address) in [(&a, "anna"), (&b, "bob"), (&c, "carl"), (&d, "dora")] {
        r.join(who, address);
    }
    r.approve(&a, &b, "bob");
    assert_eq!(r.ask(&c, "anna"), StatusCode::ACCEPTED);
    assert_eq!(r.ask(&a, "dora"), StatusCode::ACCEPTED);
    assert_eq!(
        r.submit_as(&a, &wire(&envelope(&a, &b.id, 256, 1))),
        StatusCode::ACCEPTED
    );
    r.approve(&c, &d, "dora");
    let of_a = |table: &str, columns: &[&str]| {
        let filter = columns
            .iter()
            .map(|c| format!("{c} = ?1"))
            .collect::<Vec<_>>()
            .join(" OR ");
        r.number(
            &format!("SELECT count(*) FROM {table} WHERE {filter}"),
            &a.id,
        )
    };
    let before = [
        of_a("links", &["owner", "peer"]),
        of_a("events", &["recipient", "peer"]),
        of_a("counts", &["identity"]),
    ];
    assert!(before.iter().all(|&n| n > 0), "{before:?}");

    assert!(r.relay.release("anna").unwrap());
    assert_eq!(of_a("links", &["owner", "peer"]), 0);
    assert_eq!(of_a("events", &["recipient", "peer"]), 0);
    assert_eq!(of_a("counts", &["identity"]), 0);
    assert_eq!(of_a("identities", &["id"]), 0);
    // Others' state stays.
    assert_eq!(r.lookup(&c, "dora"), (StatusCode::OK, d.reply(true)));
    assert_eq!(r.count(&c, 2), 2);
}

/// Test 12b: a Phase 3 relay file (version 1) is refused and left as it
/// was, and so are a Phase 4 file (version 2: no `received_at`), one with
/// invites (version 3, D-XXXX (no invites)) and another database.
#[test]
fn v1_relay_file_is_refused() {
    let tmp = TempDir::new();
    let v1 = tmp.0.join("v1.db");
    let v2 = tmp.0.join("v2.db");
    let v3 = tmp.0.join("v3.db");
    let other = tmp.0.join("other.db");
    {
        let db = Connection::open(&v1).unwrap();
        db.execute_batch(
            "CREATE TABLE identities (id BLOB PRIMARY KEY, address TEXT NOT NULL UNIQUE,
                 signing_key BLOB NOT NULL, x25519 BLOB NOT NULL, token_hash BLOB NOT NULL) STRICT;
             CREATE TABLE envelopes (seq INTEGER PRIMARY KEY, id BLOB NOT NULL UNIQUE,
                 recipient BLOB NOT NULL, wire BLOB NOT NULL) STRICT;
             CREATE INDEX inbox ON envelopes(recipient, seq);
             PRAGMA application_id = 1112689753;
             PRAGMA user_version = 1;",
        )
        .unwrap();
        let db = Connection::open(&v2).unwrap();
        db.execute_batch(
            "CREATE TABLE envelopes (seq INTEGER PRIMARY KEY, id BLOB NOT NULL UNIQUE,
                 recipient BLOB NOT NULL, wire BLOB NOT NULL) STRICT;
             PRAGMA application_id = 1112689753;
             PRAGMA user_version = 2;",
        )
        .unwrap();
        let db = Connection::open(&v3).unwrap();
        db.execute_batch(
            "CREATE TABLE invites (hash BLOB PRIMARY KEY, inviter BLOB,
                 day INTEGER NOT NULL, redeemed_by BLOB) STRICT;
             PRAGMA application_id = 1112689753;
             PRAGMA user_version = 3;",
        )
        .unwrap();
        let db = Connection::open(&other).unwrap();
        db.execute_batch("CREATE TABLE t (x); PRAGMA user_version = 3;")
            .unwrap();
    }
    for path in [&v1, &v2, &v3, &other] {
        let bytes = fs::read(path).unwrap();
        let config = Config::default();
        assert!(matches!(
            Relay::open_with(path, Box::new(Open), config, Gates::default()),
            Err(Error::NotRelay)
        ));
        for command in ["release", "serve"] {
            let out = Command::new(BIN)
                .args([command, "--db"])
                .arg(path)
                .args(if command == "serve" {
                    &["--listen", "127.0.0.1:0"][..]
                } else {
                    &["anna"][..]
                })
                .output()
                .unwrap();
            assert_eq!(out.status.code(), Some(1), "{command}");
            assert!(out.stdout.is_empty());
        }
        assert_eq!(fs::read(path).unwrap(), bytes, "left as it was");
    }
}

/// *Blokker* (owner answer 6): B blocks A, so the relay stores no more
/// letters or requests from A. A's requests still get 202, but A sees the
/// lookup status drop to 0 and its letters get 409. What waited at B about
/// A goes; B undoes it by asking A.
#[test]
fn blokker_stops_letters_and_requests() {
    let r = Relayed::new();
    let [a, b, c] = [1, 2, 3].map(Identity::new);
    r.join(&a, "anna");
    r.join(&b, "bob");
    r.join(&c, "carl");
    r.approve(&a, &b, "bob");
    let to_b = |n| wire(&envelope(&a, &b.id, 256, n));
    assert_eq!(r.submit_as(&a, &to_b(1)), StatusCode::ACCEPTED);

    assert_eq!(r.block(&b, &a), StatusCode::NO_CONTENT);
    assert_eq!(r.block(&b, &a), StatusCode::NO_CONTENT, "again");
    assert_eq!(r.lookup(&a, "bob"), (StatusCode::OK, b.reply(false)));
    assert_eq!(r.submit_as(&a, &to_b(2)), StatusCode::CONFLICT);
    // The letter from before still waits, but A's resend of it gets 409
    // too, so A does not learn whether B has fetched it.
    assert_eq!(r.submit_as(&a, &to_b(1)), StatusCode::CONFLICT);
    assert_eq!(r.ask(&a, "bob"), StatusCode::ACCEPTED);
    assert!(r.events(&b).is_empty());
    assert_eq!(r.waiting(), 1, "only the letter from before");
    // A has not blocked B: B's letters still reach A (B's app stops them).
    assert_eq!(
        r.submit_as(&b, &wire(&envelope(&b, &a.id, 256, 3))),
        StatusCode::ACCEPTED
    );

    // What waits at B about the blocked peer goes.
    assert_eq!(r.ask(&c, "bob"), StatusCode::ACCEPTED);
    assert_eq!(r.events(&b), [request_from(&c, "carl")]);
    assert_eq!(r.block(&b, &c), StatusCode::NO_CONTENT);
    assert!(r.events(&b).is_empty());

    // Own id 400, unknown 404, a short body 400.
    assert_eq!(r.block(&b, &b), StatusCode::BAD_REQUEST);
    assert_eq!(r.block(&b, &Identity::new(9)), StatusCode::NOT_FOUND);
    assert_eq!(
        r.post("/v1/block", b.request(&a.id[..31])).0,
        StatusCode::BAD_REQUEST
    );

    // B asks A: B's own decline is lifted.
    assert_eq!(r.ask(&b, "anna"), StatusCode::OK);
    assert_eq!(r.submit_as(&a, &to_b(2)), StatusCode::ACCEPTED);
}

/// *Blokker* also drops the blocker's own request waiting at the blocked
/// peer, whose answer would otherwise put an approved event in the
/// blocker's queue. After the block nothing the peer does reaches that
/// queue: no answer, no request, no letter.
#[test]
fn a_blocked_peer_cannot_reach_the_blockers_queue() {
    let r = Relayed::new();
    let [a, b, c] = [1, 2, 3].map(Identity::new);
    r.join(&a, "anna");
    r.join(&b, "bob");
    r.join(&c, "carl");
    // A asks B, then blocks B before B answers.
    assert_eq!(r.ask(&a, "bob"), StatusCode::ACCEPTED);
    assert_eq!(r.events(&b), [request_from(&a, "anna")]);
    assert_eq!(r.block(&a, &b), StatusCode::NO_CONTENT);
    assert!(r.events(&b).is_empty(), "A's own request is gone");
    assert_eq!(r.answer(&b, &a, true), StatusCode::NOT_FOUND);
    assert_eq!(r.ask(&b, "anna"), StatusCode::ACCEPTED);
    let from_b = wire(&envelope(&b, &a.id, 256, 1));
    assert_eq!(r.submit_as(&b, &from_b), StatusCode::CONFLICT);
    assert!(r.events(&a).is_empty(), "nothing from B waits at A");
    assert_eq!(r.waiting(), 0);

    // Control: an answer to a request that was not blocked puts an
    // approved event in the asker's queue.
    assert_eq!(r.ask(&a, "carl"), StatusCode::ACCEPTED);
    assert_eq!(r.answer(&c, &a, true), StatusCode::NO_CONTENT);
    let seen = r.events(&a);
    assert_eq!(seen.len(), 1);
    assert_eq!(
        (seen[0].kind, seen[0].address.as_str()),
        (EventKind::Approved, "carl")
    );
}

/// The owner's limits are the defaults, and the clock keeps UTC days.
#[test]
fn config_defaults_are_the_owners_values() {
    let c = Config::default();
    assert_eq!(
        (c.letters_per_day, c.requests_per_day, c.pending_requests),
        (50, 10, 16)
    );
    assert!(matches!(c.clock, Clock::System));
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!((now / DAY..=now / DAY + 1).contains(&Clock::System.today()));
    let secs = Arc::new(AtomicU64::new(3 * DAY - 1));
    let manual = Clock::Manual(Arc::clone(&secs));
    assert_eq!(manual.today(), 2);
    secs.store(3 * DAY, Ordering::SeqCst);
    assert_eq!(manual.today(), 3);
}

/// The operator's `invite` command is gone (D-XXXX (no invites)): a usage
/// error (2), and no file is made.
#[test]
fn invite_command_is_gone() {
    let tmp = TempDir::new();
    let db = tmp.0.join("fresh").join("relay.db");
    let out = Command::new(BIN)
        .args(["invite", "--db"])
        .arg(&db)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert!(!db.exists());
}

/// `serve`'s limit flags reach the relay (V78: `--letters-per-day 2`), and
/// bad values are usage errors.
#[test]
fn serve_takes_the_limit_flags() {
    let tmp = TempDir::new();
    let db = tmp.0.join("relay.db");
    let (child, base) = spawn(&tmp, &db, &["--letters-per-day", "2"]);
    let client = client();
    let post = |path: &str, body: Vec<u8>| {
        client
            .post(format!("{base}{path}"))
            .body(body)
            .send()
            .unwrap()
            .status()
    };
    let [a, b] = [1, 2].map(Identity::new);
    for (who, address) in [(&a, "anna"), (&b, "bob")] {
        let body = who.registration(address.as_bytes());
        assert_eq!(post("/v1/register", body), StatusCode::CREATED);
    }
    assert_eq!(
        post("/v1/requests", a.request(b"bob")),
        StatusCode::ACCEPTED
    );
    let yes = [&a.id[..], &[1]].concat();
    assert_eq!(
        post("/v1/events/answer", b.request(&yes)),
        StatusCode::NO_CONTENT
    );
    for (n, want) in [(1, 202), (2, 202), (3, 429)] {
        let w = wire(&envelope(&a, &b.id, 256, n));
        assert_eq!(post("/v1/envelopes", a.request(&w)).as_u16(), want, "{n}");
    }
    drop(child);

    for bad in [
        &["--letters-per-day"][..],
        &["--letters-per-day", "x"],
        &["--letters-per-day", "-1"],
        &["--letters-per-day", "+1"],
        &["--requests-per-day", "4294967296"],
        // The invite limits went with the invites (D-XXXX (no invites)).
        &["--invites-per-day", "3"],
        &["--open-invites", "5"],
        &["--invite-days", "7"],
        // Phase 3's transitional mode is gone (Phase 4 WP4).
        &["--phase3"],
    ] {
        let out = Command::new(BIN)
            .args(["serve", "--db"])
            .arg(tmp.0.join("never").join("relay.db"))
            .args(["--listen", "127.0.0.1:0"])
            .args(bad)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{bad:?}");
    }
    let out = Command::new(BIN)
        .args(["release", "--db"])
        .arg(&db)
        .args(["--requests-per-day", "1", "anna"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(!tmp.0.join("never").exists());
}
