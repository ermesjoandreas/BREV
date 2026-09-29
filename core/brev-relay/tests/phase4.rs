//! Phase 4 relay tests (docs/PHASE4_DESIGN.md §8, relay tests 1 to 12, with
//! the three DoD tests 5, 7 and 9), *Blokker* (owner answer 6), the
//! operator's `invite` command and the limit flags. The clock is the
//! relay's manual [`brev_relay::Clock`], moved by the tests.

mod common;

use std::fs;
use std::process::Command;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use brev_proto::body::{self, EventKind, Peer, MAX_ATTESTATION, REGISTRATION_V2_MAX};
use brev_proto::invite::ROOT_TAG;
use brev_relay::{Clock, Config, Error, Gates, IdentityVerifier, Open, Relay};
use common::*;
use reqwest::StatusCode;
use rusqlite::Connection;

const LONGEST: &str = "abcdefghijklmnopqrstuvwxyz012345";

/// `who`'s `invited_by`: None for a root invite.
fn invited_by(r: &Relayed, who: &Identity) -> Option<Vec<u8>> {
    r.read()
        .query_row(
            "SELECT invited_by FROM identities WHERE id = ?1",
            [who.id],
            |row| row.get(0),
        )
        .unwrap()
}

/// A request event from `who` at `address`, as an events answer shows it.
fn request_from(who: &Identity, address: &str) -> Seen {
    Seen {
        kind: EventKind::Request,
        address: address.into(),
        bundle: who.bundle(),
        tag: [0; 32],
    }
}

/// The invite open answer naming `who` at `address`.
fn opened(who: &Identity, address: &str) -> Vec<u8> {
    let peer = Peer {
        address: address.as_bytes(),
        signing_key: &who.public,
        x25519: &who.x25519,
    };
    body::invite_open_answer(Some(&peer)).unwrap()
}

/// Test 1: none, unknown, used and expired invites are 403; a root invite
/// gives 201 with no inviter; the same registration again is 200 after
/// the invite was used; the largest v2 body goes through the router.
#[test]
fn registration_needs_an_invite() {
    let r = Relayed::new();
    let (a, b, c, d) = (
        Identity::new(1),
        Identity::new(2),
        Identity::new(3),
        Identity::new(4),
    );

    // None (a zero key) and unknown.
    let none = a.registration(b"anna", &[0; 32], &ROOT_TAG);
    assert_eq!(r.post("/v1/register", none).0, StatusCode::FORBIDDEN);
    assert_eq!(
        r.register_by(&a, "anna", &Secret::new(1), None),
        StatusCode::FORBIDDEN
    );

    // Root: 201, invited_by NULL, the invite used. The same registration
    // again: 200.
    let root = r.root();
    assert_eq!(r.register_by(&a, "anna", &root, None), StatusCode::CREATED);
    assert_eq!(invited_by(&r, &a), None);
    assert_eq!(r.register_by(&a, "anna", &root, None), StatusCode::OK);
    assert_eq!(r.open_invite(&root).0, StatusCode::NOT_FOUND);
    // Used: 403 for anyone else.
    assert_eq!(r.register_by(&b, "bob", &root, None), StatusCode::FORBIDDEN);

    // Expired: made on day 0, it works on day 7, not on day 8.
    let (old, older) = (r.root(), r.root());
    r.set_day(7);
    assert_eq!(r.register_by(&b, "bob", &old, None), StatusCode::CREATED);
    r.set_day(8);
    assert_eq!(
        r.register_by(&c, "carl", &older, None),
        StatusCode::FORBIDDEN
    );
    assert_eq!(r.rows("identities"), 2);

    // The largest registration v2 (8 484 bytes) reaches the rules through
    // the real router: not 413.
    let fresh = r.root();
    let body = d.registration_with(
        LONGEST.as_bytes(),
        &d.public,
        &fresh.key(),
        &ROOT_TAG,
        &[0x5A; MAX_ATTESTATION],
    );
    assert_eq!(body.len(), REGISTRATION_V2_MAX);
    let want = if cfg!(feature = "app-attest") {
        StatusCode::PRECONDITION_REQUIRED // not the dev marker
    } else {
        StatusCode::CREATED // parsed and ignored
    };
    assert_eq!(r.post("/v1/register", body).0, want);
}

/// Test 2: without a valid invite a taken and a free address answer alike;
/// with one, a taken address is 409 and the invite is not used.
#[test]
fn registration_does_not_probe_the_directory() {
    let r = Relayed::new();
    let (a, b) = (Identity::new(1), Identity::new(2));
    let used = r.root();
    assert_eq!(r.register_by(&a, "anna", &used, None), StatusCode::CREATED);
    for secret in [Secret::new(7), used] {
        for address in ["anna", "free"] {
            assert_eq!(
                r.register_by(&b, address, &secret, None),
                StatusCode::FORBIDDEN,
                "{address}"
            );
        }
    }
    let root = r.root();
    assert_eq!(r.register_by(&b, "anna", &root, None), StatusCode::CONFLICT);
    assert_eq!(r.open_invite(&root), (StatusCode::OK, vec![0]));
    assert_eq!(r.register_by(&b, "free", &root, None), StatusCode::CREATED);
}

/// Test 3: registering with A's invite records A as the inviter, links both
/// ways and tells A with the tag; a redeem by an existing identity keeps
/// its `invited_by`.
#[test]
fn invite_graph_is_recorded() {
    let r = Relayed::new();
    let (a, b, c, d) = (
        Identity::new(1),
        Identity::new(2),
        Identity::new(3),
        Identity::new(4),
    );
    r.join(&a, "anna");
    let s = Secret::new(1);
    assert_eq!(r.create_invite(&a, &s), StatusCode::CREATED);
    assert_eq!(r.open_invite(&s), (StatusCode::OK, opened(&a, "anna")));
    assert_eq!(r.register_by(&b, "bob", &s, Some(&a)), StatusCode::CREATED);
    assert_eq!(invited_by(&r, &b), Some(a.id.to_vec()));
    assert_eq!(r.lookup(&a, "bob"), (StatusCode::OK, b.reply(true)));
    assert_eq!(r.lookup(&b, "anna"), (StatusCode::OK, a.reply(true)));
    assert_eq!(
        r.events(&a),
        [Seen {
            kind: EventKind::Invited,
            address: "bob".into(),
            bundle: b.bundle(),
            tag: s.tag(&b, &a, "bob"),
        }]
    );
    assert!(r.events(&b).is_empty());

    // A tree: bob invites dora.
    let s2 = Secret::new(2);
    assert_eq!(r.create_invite(&b, &s2), StatusCode::CREATED);
    assert_eq!(
        r.register_by(&d, "dora", &s2, Some(&b)),
        StatusCode::CREATED
    );
    assert_eq!(invited_by(&r, &d), Some(b.id.to_vec()));

    // An existing identity redeems: linked and told, invited_by unchanged.
    r.join(&c, "carl");
    let s3 = Secret::new(3);
    assert_eq!(r.create_invite(&a, &s3), StatusCode::CREATED);
    assert_eq!(r.redeem(&c, "carl", &s3, &a), StatusCode::OK);
    assert_eq!(invited_by(&r, &c), None);
    let redeemed_by: Vec<u8> = r
        .read()
        .query_row(
            "SELECT redeemed_by FROM invites WHERE hash = ?1",
            [s3.hash()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(redeemed_by, c.id);
    assert_eq!(r.lookup(&a, "carl"), (StatusCode::OK, c.reply(true)));
    assert_eq!(r.events(&a).len(), 2);
    assert_eq!(r.events(&a)[1].tag, s3.tag(&c, &a, "carl"));
}

/// Test 4: an invite registers or redeems once; a redeem by the same
/// caller is 200 again, by another 404; root and own invites cannot be
/// redeemed; made on day 0, an invite works through day 7.
#[test]
fn invites_are_one_time_and_expire() {
    let r = Relayed::with(
        Box::new(Open),
        |c| {
            c.invites_per_day = 10;
            c.open_invites = 10;
        },
        Gates::default(),
    );
    let [a, b, c, d, e] = [1, 2, 3, 4, 5].map(Identity::new);
    r.join(&a, "anna");
    let s = Secret::new(1);
    assert_eq!(r.create_invite(&a, &s), StatusCode::CREATED);
    assert_eq!(r.register_by(&b, "bob", &s, Some(&a)), StatusCode::CREATED);
    assert_eq!(
        r.register_by(&c, "carl", &s, Some(&a)),
        StatusCode::FORBIDDEN,
        "a second registration"
    );
    assert_eq!(r.open_invite(&s).0, StatusCode::NOT_FOUND);

    r.join(&c, "carl");
    r.join(&d, "dora");
    assert_eq!(
        r.redeem(&c, "carl", &s, &a),
        StatusCode::NOT_FOUND,
        "used by bob's registration"
    );
    let s2 = Secret::new(2);
    assert_eq!(r.create_invite(&a, &s2), StatusCode::CREATED);
    assert_eq!(r.redeem(&c, "carl", &s2, &a), StatusCode::OK);
    assert_eq!(r.redeem(&c, "carl", &s2, &a), StatusCode::OK, "again");
    assert_eq!(r.redeem(&d, "dora", &s2, &a), StatusCode::NOT_FOUND);
    assert_eq!(r.events(&a).len(), 2, "bob and carl, once each");

    // Root and own: 400, and nothing used.
    let root = r.root();
    let redeem = |who: &Identity, secret: &Secret| {
        let payload = [secret.key(), [0; 32]].concat();
        r.post("/v1/invites/redeem", who.request(&payload)).0
    };
    assert_eq!(redeem(&d, &root), StatusCode::BAD_REQUEST);
    let own = Secret::new(3);
    assert_eq!(r.create_invite(&a, &own), StatusCode::CREATED);
    assert_eq!(redeem(&a, &own), StatusCode::BAD_REQUEST);
    assert_eq!(r.open_invite(&root).0, StatusCode::OK);
    assert_eq!(r.open_invite(&own).0, StatusCode::OK);

    // Life: day 7 yes; day 8 open 404, register 403, redeem 404.
    let (s4, s5, s6) = (Secret::new(4), Secret::new(5), Secret::new(6));
    for secret in [&s4, &s5, &s6] {
        assert_eq!(r.create_invite(&a, secret), StatusCode::CREATED);
    }
    r.set_time(7, DAY - 1);
    assert_eq!(r.open_invite(&s4).0, StatusCode::OK);
    r.set_time(8, 0);
    assert_eq!(r.open_invite(&s4).0, StatusCode::NOT_FOUND);
    assert_eq!(
        r.register_by(&e, "emil", &s5, Some(&a)),
        StatusCode::FORBIDDEN
    );
    assert_eq!(r.redeem(&d, "dora", &s6, &a), StatusCode::NOT_FOUND);
    assert_eq!(
        r.redeem(&c, "carl", &s2, &a),
        StatusCode::NOT_FOUND,
        "a used one expires too"
    );
    // Each invite write deletes the expired ones.
    let start = i64::try_from(START / DAY).unwrap();
    assert_eq!(r.rows("invites"), 10, "3 used roots, 7 made on day 0");
    assert_eq!(r.create_invite(&a, &Secret::new(7)), StatusCode::CREATED);
    let old: i64 = r
        .read()
        .query_row(
            "SELECT count(*) FROM invites WHERE day = ?1",
            [start],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!((old, r.rows("invites")), (0, 1));
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
/// asker; no declines; invited and approved events are only seen.
#[test]
fn event_answer_rules() {
    let r = Relayed::new();
    let [a, b, c, d] = [1, 2, 3, 4].map(Identity::new);
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
        tag: [0; 32],
    };
    assert_eq!(r.events(&b), [approved]);
    assert_eq!(r.answer(&b, &a, false), StatusCode::BAD_REQUEST);
    assert_eq!(r.events(&b).len(), 1, "kept");
    assert_eq!(r.answer(&b, &a, true), StatusCode::NO_CONTENT);
    assert!(r.events(&b).is_empty());

    // Invited: seen with yes, 400 with no.
    let s = Secret::new(1);
    assert_eq!(r.create_invite(&a, &s), StatusCode::CREATED);
    assert_eq!(r.register_by(&d, "dora", &s, Some(&a)), StatusCode::CREATED);
    assert_eq!(r.answer(&a, &d, false), StatusCode::BAD_REQUEST);
    assert_eq!(r.answer(&a, &d, true), StatusCode::NO_CONTENT);
    assert!(r.events(&a).is_empty());

    // Decline: the event goes, the asker hears nothing and is refused.
    assert_eq!(r.ask(&c, "anna"), StatusCode::ACCEPTED);
    assert_eq!(r.answer(&a, &c, false), StatusCode::NO_CONTENT);
    assert_eq!(r.answer(&a, &c, false), StatusCode::NOT_FOUND);
    assert!(r.events(&c).is_empty());
    let w = wire(&envelope(&c, &a.id, 256, 1));
    assert_eq!(r.submit_as(&c, &w), StatusCode::CONFLICT);

    // An approval does not replace an invited event the inviter has not
    // seen: finn redeems emil's invite while emil's request waits at finn,
    // then approves it.
    let [e, f] = [5, 6].map(Identity::new);
    r.join(&e, "emil");
    r.join(&f, "finn");
    assert_eq!(r.ask(&e, "finn"), StatusCode::ACCEPTED);
    let s2 = Secret::new(2);
    assert_eq!(r.create_invite(&e, &s2), StatusCode::CREATED);
    assert_eq!(r.redeem(&f, "finn", &s2, &e), StatusCode::OK);
    assert_eq!(r.answer(&f, &e, true), StatusCode::NO_CONTENT);
    let seen = r.events(&e);
    assert_eq!(seen.len(), 1);
    assert_eq!(
        (seen[0].kind, seen[0].tag),
        (EventKind::Invited, s2.tag(&f, &e, "finn"))
    );
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

/// Test 8b: 3 invites made per day and 5 open; the 4th of a day is 429
/// even after redemptions; the next day works; the same hash again is 200
/// and not counted; root invites count against nothing.
#[test]
fn invites_are_capped() {
    let r = Relayed::new();
    let [a, b, c] = [1, 2, 3].map(Identity::new);
    r.join(&a, "anna");
    let s: Vec<Secret> = (0..8).map(Secret::new).collect();
    for secret in &s[..3] {
        assert_eq!(r.create_invite(&a, secret), StatusCode::CREATED);
    }
    assert_eq!(r.create_invite(&a, &s[3]), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(r.create_invite(&a, &s[0]), StatusCode::OK, "same hash");
    assert_eq!(r.count(&a, 3), 3);

    r.set_day(1);
    assert_eq!(r.create_invite(&a, &s[3]), StatusCode::CREATED);
    assert_eq!(r.create_invite(&a, &s[4]), StatusCode::CREATED);
    assert_eq!(
        r.create_invite(&a, &s[5]),
        StatusCode::TOO_MANY_REQUESTS,
        "5 open"
    );
    assert_eq!(
        r.register_by(&b, "bob", &s[0], Some(&a)),
        StatusCode::CREATED
    );
    assert_eq!(r.create_invite(&a, &s[5]), StatusCode::CREATED, "4 open");
    assert_eq!(
        r.register_by(&c, "carl", &s[1], Some(&a)),
        StatusCode::CREATED
    );
    assert_eq!(
        r.create_invite(&a, &s[6]),
        StatusCode::TOO_MANY_REQUESTS,
        "3 made today, 4 open"
    );
    r.set_day(2);
    assert_eq!(r.create_invite(&a, &s[6]), StatusCode::CREATED);

    // A hash another holds: 409. Root invites: no cap.
    assert_eq!(r.create_invite(&b, &s[6]), StatusCode::CONFLICT);
    for _ in 0..10 {
        r.root();
    }
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

/// Test 8d: invited and approved events come before requests, each oldest
/// first, and an answer holds at most 32.
#[test]
fn events_put_invited_and_approved_before_requests() {
    let r = Relayed::with(
        Box::new(Open),
        |c| c.pending_requests = 40,
        Gates::default(),
    );
    let [a, x, y] = [1, 2, 3].map(Identity::new);
    r.join(&a, "anna");
    r.join(&y, "yngve");
    assert_eq!(r.ask(&a, "yngve"), StatusCode::ACCEPTED);
    let askers: Vec<Identity> = (10..44).map(Identity::new).collect();
    for (n, who) in askers.iter().enumerate() {
        r.join(who, &format!("asker-{n}"));
        assert_eq!(r.ask(who, "anna"), StatusCode::ACCEPTED);
    }
    let s = Secret::new(1);
    assert_eq!(r.create_invite(&a, &s), StatusCode::CREATED);
    assert_eq!(r.register_by(&x, "xena", &s, Some(&a)), StatusCode::CREATED);
    assert_eq!(r.answer(&y, &a, true), StatusCode::NO_CONTENT);

    let seen = r.events(&a);
    assert_eq!(seen.len(), 32);
    assert_eq!(
        (seen[0].kind, seen[0].address.as_str()),
        (EventKind::Invited, "xena")
    );
    assert_eq!(
        (seen[1].kind, seen[1].address.as_str()),
        (EventKind::Approved, "yngve")
    );
    for (n, event) in seen[2..].iter().enumerate() {
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
    let root = r.root();
    let register = |attestation: &[u8]| {
        let body = a.registration_with(b"anna", &a.public, &root.key(), &ROOT_TAG, attestation);
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
        assert_eq!(
            (r.rows("identities"), r.open_invite(&root).0),
            (0, StatusCode::OK)
        );
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

/// Test 11b: the identity verifier is asked after the invite and conflict
/// checks; a refusal is 428 and writes nothing.
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
    let root = r.root();
    assert_eq!(
        r.register_by(&a, "anna", &root, None),
        StatusCode::PRECONDITION_REQUIRED
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(r.rows("identities"), 0);
    assert_eq!(r.open_invite(&root).0, StatusCode::OK, "not used");
    assert_eq!(
        r.register_by(&a, "anna", &Secret::new(5), None),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "not asked without an invite"
    );
}

/// Test 12a: releasing an identity deletes its links, events, invites and
/// counts; its invitees keep `invited_by`.
#[test]
fn release_deletes_links_events_invites_counts() {
    let r = Relayed::new();
    let [a, b, c, d] = [1, 2, 3, 4].map(Identity::new);
    r.join(&a, "anna");
    r.join(&c, "carl");
    r.join(&d, "dora");
    let s = Secret::new(1);
    assert_eq!(r.create_invite(&a, &s), StatusCode::CREATED);
    assert_eq!(r.register_by(&b, "bob", &s, Some(&a)), StatusCode::CREATED);
    assert_eq!(r.create_invite(&a, &Secret::new(2)), StatusCode::CREATED);
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
        of_a("invites", &["inviter"]),
        of_a("counts", &["identity"]),
    ];
    assert!(before.iter().all(|&n| n > 0), "{before:?}");

    assert!(r.relay.release("anna").unwrap());
    assert_eq!(of_a("links", &["owner", "peer"]), 0);
    assert_eq!(of_a("events", &["recipient", "peer"]), 0);
    assert_eq!(of_a("invites", &["inviter"]), 0);
    assert_eq!(of_a("counts", &["identity"]), 0);
    assert_eq!(of_a("identities", &["id"]), 0);
    assert_eq!(invited_by(&r, &b), Some(a.id.to_vec()), "history kept");
    // Others' state stays.
    assert_eq!(r.lookup(&c, "dora"), (StatusCode::OK, d.reply(true)));
    assert_eq!(r.count(&c, 2), 2);
}

/// Test 12b: a Phase 3 relay file (version 1) is refused and left as it
/// was, and so is another database.
#[test]
fn v1_relay_file_is_refused() {
    let tmp = TempDir::new();
    let v1 = tmp.0.join("v1.db");
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
        let db = Connection::open(&other).unwrap();
        db.execute_batch("CREATE TABLE t (x); PRAGMA user_version = 2;")
            .unwrap();
    }
    for path in [&v1, &other] {
        let bytes = fs::read(path).unwrap();
        let config = Config::default();
        assert!(matches!(
            Relay::open_with(path, Box::new(Open), config, Gates::default()),
            Err(Error::NotRelay)
        ));
        for command in ["invite", "serve"] {
            let out = Command::new(BIN)
                .args([command, "--db"])
                .arg(path)
                .args(if command == "serve" {
                    &["--listen", "127.0.0.1:0"][..]
                } else {
                    &[][..]
                })
                .output()
                .unwrap();
            assert_eq!(out.status.code(), Some(1), "{command}");
            assert!(out.stdout.is_empty());
        }
        assert_eq!(fs::read(path).unwrap(), bytes, "left as it was");
    }
}

/// Test 12c: the relay's file never holds an invite's secret, its code or
/// `a`, only SHA-256(`a`); the invitee's tag only until the inviter saw it.
#[test]
fn relay_file_holds_no_invite_secret() {
    let r = Relayed::new();
    let [a, b, c] = [1, 2, 3].map(Identity::new);
    let code = r.relay.root_invite().unwrap();
    let root = Secret::from_code(&code);
    assert_eq!(r.register_by(&a, "anna", &root, None), StatusCode::CREATED);
    r.join(&c, "carl");
    let (used, redeemed, open) = (Secret::new(1), Secret::new(2), Secret::new(3));
    for secret in [&used, &redeemed, &open] {
        assert_eq!(r.create_invite(&a, secret), StatusCode::CREATED);
    }
    assert_eq!(
        r.register_by(&b, "bob", &used, Some(&a)),
        StatusCode::CREATED
    );
    assert_eq!(r.redeem(&c, "carl", &redeemed, &a), StatusCode::OK);
    assert_eq!(r.open_invite(&open).0, StatusCode::OK);

    for secret in [&root, &used, &redeemed, &open] {
        assert!(!r.files_contain(&secret.0), "s");
        assert!(!r.files_contain(&secret.key()), "a");
        assert!(r.files_contain(&secret.hash()), "control: SHA-256(a)");
    }
    assert!(!r.files_contain(&code));
    assert!(!r.files_contain(&code[6..]), "the code's secret part");

    // The tags wait until anna has seen the events, then are gone.
    let tags = [used.tag(&b, &a, "bob"), redeemed.tag(&c, &a, "carl")];
    for tag in &tags {
        assert!(r.files_contain(tag), "control: the tag waits");
    }
    assert_eq!(r.answer(&a, &b, true), StatusCode::NO_CONTENT);
    assert_eq!(r.answer(&a, &c, true), StatusCode::NO_CONTENT);
    for tag in &tags {
        assert!(!r.files_contain(tag), "zeroed once seen");
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
    r.join(&c, "carl");
    let s = Secret::new(1);
    assert_eq!(r.create_invite(&a, &s), StatusCode::CREATED);
    assert_eq!(r.register_by(&b, "bob", &s, Some(&a)), StatusCode::CREATED);
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
        (
            c.letters_per_day,
            c.requests_per_day,
            c.invites_per_day,
            c.open_invites,
            c.pending_requests,
            c.invite_days
        ),
        (50, 10, 3, 5, 16, 7)
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

/// `brev-relay invite` prints a root code that registers, also on a file a
/// relay is serving; it creates a missing file and takes only --db.
#[test]
fn invite_command_prints_a_root_code() {
    let r = Relayed::new();
    let invite = |db: &std::path::Path| {
        Command::new(BIN)
            .args(["invite", "--db"])
            .arg(db)
            .output()
            .unwrap()
    };
    let out = invite(&r.db());
    assert!(out.status.success(), "{out:?}");
    assert!(out.stderr.is_empty());
    let code = out.stdout.strip_suffix(b"\n").unwrap();
    assert_eq!(code.len(), 32);
    let secret = Secret::from_code(code);
    let a = Identity::new(1);
    assert_eq!(
        r.register_by(&a, "anna", &secret, None),
        StatusCode::CREATED
    );
    let again = invite(&r.db());
    assert_ne!(again.stdout, out.stdout);

    // A missing file is made (the first identity needs a code).
    let fresh = r.tmp.0.join("fresh").join("relay.db");
    assert!(invite(&fresh).status.success());
    assert!(fresh.is_file());

    // Only --db: anything else is a usage error (2).
    for extra in [&["x"][..], &["--trace"], &["--letters-per-day", "2"]] {
        let out = Command::new(BIN)
            .args(["invite", "--db"])
            .arg(r.db())
            .args(extra)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{extra:?}");
    }
    // A relative path: refused (1).
    let out = Command::new(BIN)
        .args(["invite", "--db", "relay.db"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
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
        let out = Command::new(BIN)
            .args(["invite", "--db"])
            .arg(&db)
            .output()
            .unwrap();
        let root = Secret::from_code(out.stdout.trim_ascii_end());
        let body = who.registration(address.as_bytes(), &root.key(), &ROOT_TAG);
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
        &["--invite-days", "4294967296"],
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
