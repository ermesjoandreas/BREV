//! Relay tests of Phase 3's properties (docs/PHASE3_DESIGN.md §4.6) on the
//! Phase 4 relay (docs/PHASE4_DESIGN.md §8): open registration rules (no
//! invite, D-0116), token checks on every endpoint, no invite
//! endpoint, envelope checks with the sender's
//! token, inbox and ack, deletion from the file, no plaintext, the policy
//! hook, release, and the binary's listen rule, port file and trace. The
//! relay runs in-process on 127.0.0.1:0
//! and is spoken to over real HTTP with reqwest, as brev-core does;
//! identities sign with p256 test keys (tests only).

mod common;

use std::fs;
use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use brev_proto::body::{self, token_hash, INBOX_MAX, INBOX_MAX_BYTES, SUBMIT_MAX};
use brev_proto::{pad_into, padded_len, Envelope, MAX_PADDED, MAX_WIRE};
use brev_relay::{
    parse_listen, Config, Decision, Endpoint, Error, Gates, Open, Policy, Relay, Server,
};
use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use common::*;
use p256::ecdsa::Signature;
use reqwest::StatusCode;

fn is_high_s(sig: &Signature) -> bool {
    sig.normalize_s() != *sig
}

/// The same signature with s replaced by n − s: also valid.
fn negate_s(sig: &Signature) -> Signature {
    let (r, s) = sig.split_scalars();
    Signature::from_scalars(r, -s).unwrap()
}

#[test]
fn register_rules() {
    let r = Relayed::new();
    let (a, b, c) = (Identity::new(1), Identity::new(2), Identity::new(3));

    // The test's body builder gives brev-proto's body (RFC 6979 signatures
    // are deterministic).
    let unsigned =
        body::registration_body(b"anna", &a.public, &a.x25519, &token_hash(&a.token)).unwrap();
    let sig = a.sign(&body::register_preimage_v3(&unsigned));
    assert_eq!(
        a.registration(b"anna"),
        body::signed_registration_v3(&unsigned, &sig, ATTESTATION).unwrap()
    );

    // New with no invite (open registration), idempotent, taken, one
    // address and one token per identity.
    assert_eq!(r.register(&a, "anna"), StatusCode::CREATED);
    assert_eq!(r.register(&a, "anna"), StatusCode::OK, "idempotent");
    assert_eq!(r.register(&b, "anna"), StatusCode::CONFLICT, "taken");
    assert_eq!(
        r.register(&a, "anna-2"),
        StatusCode::CONFLICT,
        "a second address for one identity"
    );
    let a_again = Identity {
        token: [0x42; 32],
        ..Identity::new(1)
    };
    assert_eq!(a_again.id, a.id);
    assert_eq!(
        r.register(&a_again, "anna"),
        StatusCode::CONFLICT,
        "another token"
    );
    assert_eq!(r.register(&a_again, "other"), StatusCode::CONFLICT);
    // Nothing of that changed the first registration.
    assert_eq!(r.lookup(&a, "anna"), (StatusCode::OK, a.reply(false)));
    assert_eq!(
        r.post("/v1/inbox", a_again.request(&[])).0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(r.lookup(&a, "anna-2").0, StatusCode::NOT_FOUND);
    assert_eq!(r.lookup(&a, "other").0, StatusCode::NOT_FOUND);
    // A new identity has no link and no event: it reaches nobody yet.
    assert_eq!(r.rows("links"), 0);
    assert_eq!(r.rows("events"), 0);

    // Address rules (brev_proto::body::is_valid_address): charset, length,
    // first letter.
    let refused: [&[u8]; 12] = [
        b"Anna",
        b"anNa",
        b"an_a",
        b"an.a",
        b"an a",
        "bl\u{e5}b\u{e6}r".as_bytes(),
        b"ab",
        &[b'a'; 33],
        b"1abc",
        b"-abc",
        b"",
        b"anna\0",
    ];
    for (i, address) in refused.iter().enumerate() {
        let who = Identity::new(10 + u8::try_from(i).unwrap());
        let body = who.registration(address);
        assert_eq!(
            r.post("/v1/register", body).0,
            StatusCode::BAD_REQUEST,
            "{address:?}"
        );
    }
    let accepted = [
        "abc".to_string(),
        "a".repeat(32),
        "a-1".into(),
        "z9--".into(),
    ];
    for (seed, address) in (30..).zip(&accepted) {
        r.join(&Identity::new(seed), address);
    }

    // Signatures: a flipped bit, another key, no signing domain, Phase 3's
    // domain, the invite era's v2 domain.
    let good = c.registration(b"carl");
    let signed = good.len() - 2 - ATTESTATION.len();
    let unsigned = &good[..signed - 64];
    let tail = &good[signed..];
    let mut flipped = good.clone();
    flipped[signed - 1] ^= 1;
    let by_a = a.sign(&body::register_preimage_v3(unsigned));
    let no_domain = c.sign(unsigned);
    let v1_domain = c.sign(&body::register_preimage(unsigned));
    let v2_domain = c.sign(&[&b"brev/v2/register\0"[..], unsigned].concat());
    for bad in [
        flipped,
        [unsigned, &by_a, tail].concat(),
        [unsigned, &no_domain, tail].concat(),
        [unsigned, &v1_domain, tail].concat(),
        [unsigned, &v2_domain, tail].concat(),
    ] {
        assert_eq!(r.post("/v1/register", bad).0, StatusCode::UNAUTHORIZED);
    }

    // Keys: compressed (33 bytes, or an 02 prefix in the 65-byte field),
    // off the curve.
    let compressed = c
        .key
        .verifying_key()
        .to_sec1_point(true)
        .as_bytes()
        .to_vec();
    assert_eq!(compressed.len(), 33);
    let mut prefixed = c.public;
    prefixed[0] = 0x02;
    let mut off_curve = c.public;
    off_curve[64] ^= 1;
    for key in [&compressed[..], &prefixed, &off_curve] {
        let body = c.registration_with(b"carl", key, ATTESTATION);
        assert_eq!(r.post("/v1/register", body).0, StatusCode::BAD_REQUEST);
    }

    // Bodies: empty, one byte short, one byte more, Phase 3's registration,
    // the invite era's v2 layout (an invite key and a tag after the token
    // hash), over the 16 KiB limit.
    let v2_unsigned = [unsigned, &[0xA1; 32], &[0x7A; 32]].concat();
    let v2_sig = c.sign(&[&b"brev/v2/register\0"[..], &v2_unsigned].concat());
    for bad in [
        Vec::new(),
        good[..good.len() - 1].to_vec(),
        [&good[..], &[0]].concat(),
        c.registration_v1(b"carl"),
        [&v2_unsigned[..], &v2_sig, tail].concat(),
    ] {
        assert_eq!(r.post("/v1/register", bad).0, StatusCode::BAD_REQUEST);
    }
    assert_eq!(
        r.post("/v1/register", vec![3; 16 * 1024 + 1]).0,
        StatusCode::PAYLOAD_TOO_LARGE
    );

    // None of the refused bodies registered carl; the good one does.
    assert_eq!(r.lookup(&a, "carl").0, StatusCode::NOT_FOUND);
    assert_eq!(r.post("/v1/register", good).0, StatusCode::CREATED);
    assert_eq!(r.lookup(&a, "carl"), (StatusCode::OK, c.reply(false)));
}

#[test]
fn requests_need_the_token() {
    let r = Relayed::new();
    let (a, b, c) = (Identity::new(1), Identity::new(2), Identity::new(3));
    r.join(&a, "anna");
    r.join(&b, "bob");

    // Every token endpoint but /v1/envelopes (submit_checks), in an order
    // where each valid request is answered by its rules.
    let cases: [(&str, Vec<u8>, StatusCode); 7] = [
        ("/v1/lookup", b"bob".to_vec(), StatusCode::OK),
        ("/v1/inbox", Vec::new(), StatusCode::OK),
        ("/v1/inbox/ack", vec![7; 32], StatusCode::NO_CONTENT),
        ("/v1/requests", b"bob".to_vec(), StatusCode::ACCEPTED),
        ("/v1/events", Vec::new(), StatusCode::OK),
        (
            "/v1/events/answer",
            [&b.id[..], &[1]].concat(),
            StatusCode::NOT_FOUND,
        ),
        ("/v1/block", b.id.to_vec(), StatusCode::NO_CONTENT),
    ];
    for (path, payload, ok) in cases {
        assert_eq!(r.post(path, a.request(&payload)).0, ok, "{path}");
        let unauthorized = [
            c.request(&payload),                                   // unknown id
            [&a.id[..], &[0x5A; 32], &payload].concat(),           // wrong token
            [&a.id[..], &b.token, &payload].concat(),              // another identity's token
            [&b.id[..], &a.token, &payload].concat(),              // and the other way round
            [&a.id[..], &token_hash(&a.token), &payload].concat(), // the stored hash is no token
        ];
        for (i, body) in unauthorized.into_iter().enumerate() {
            assert_eq!(r.post(path, body).0, StatusCode::UNAUTHORIZED, "{path} {i}");
        }
        assert_eq!(
            r.post(path, a.request(&[])[..63].to_vec()).0,
            StatusCode::BAD_REQUEST,
            "{path}: short prefix"
        );
    }

    // With a valid token the payload rules apply; without one, 401 first.
    assert_eq!(r.lookup(&a, "Bob").0, StatusCode::BAD_REQUEST);
    assert_eq!(r.lookup(&c, "Bob").0, StatusCode::UNAUTHORIZED);
    assert_eq!(r.lookup(&a, "nobody").0, StatusCode::NOT_FOUND);
    assert_eq!(r.lookup(&a, "anna"), (StatusCode::OK, a.reply(false)));
    for (path, payload) in [
        ("/v1/inbox", vec![0]),
        ("/v1/events", vec![0]),
        ("/v1/requests", b"Bob".to_vec()),
        ("/v1/events/answer", [&b.id[..], &[2]].concat()),
        ("/v1/events/answer", b.id.to_vec()),
        ("/v1/block", b.id[..31].to_vec()),
    ] {
        assert_eq!(
            r.post(path, a.request(&payload)).0,
            StatusCode::BAD_REQUEST,
            "{path} {}",
            payload.len()
        );
    }
}

/// The invite endpoints are gone (D-0116): each answers 404
/// to any body, with a valid token or none, and writes nothing.
#[test]
fn no_invite_endpoint_answers() {
    let r = Relayed::new();
    let a = Identity::new(1);
    r.join(&a, "anna");
    let before = r.rows("identities");
    for path in ["/v1/invites", "/v1/invites/open", "/v1/invites/redeem"] {
        for body in [
            Vec::new(),
            vec![0; 32],
            a.request(&[0; 32]),
            a.request(&[0; 64]),
        ] {
            assert_eq!(r.post(path, body).0, StatusCode::NOT_FOUND, "{path}");
        }
    }
    assert_eq!(r.rows("identities"), before);
    let tables: i64 = r
        .read()
        .query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name = 'invites'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(tables, 0, "no invites table");
}

#[test]
fn submit_checks() {
    let r = Relayed::new();
    let (a, b, c) = (Identity::new(1), Identity::new(2), Identity::new(3));
    r.join(&a, "anna");
    r.join(&b, "bob");
    r.approve(&a, &b, "bob");
    let submit = |w: &[u8]| r.submit_as(&a, w);

    // Stored once; the same id again is 200, also with the other S.
    let first = envelope(&a, &b.id, 256, 1);
    let w1 = wire(&first);
    assert_eq!(w1.len(), 430);
    assert_eq!(submit(&w1), StatusCode::ACCEPTED);
    assert_eq!(submit(&w1), StatusCode::OK, "already waiting");
    let mut resigned = first.clone();
    resigned.signature = negate_s(&Signature::from_slice(&first.signature).unwrap())
        .to_bytes()
        .to_vec();
    assert_ne!(resigned.signature, first.signature);
    assert_eq!(
        submit(&wire(&resigned)),
        StatusCode::OK,
        "the id excludes the signature"
    );
    assert_eq!(r.waiting(), 1);

    // High-S as the Enclave produces about half the time, and low-S.
    let mut high = envelope(&a, &b.id, 1024, 2);
    let mut low = envelope(&a, &b.id, 4096, 3);
    for (env, want_high) in [(&mut high, true), (&mut low, false)] {
        let sig = Signature::from_slice(&env.signature).unwrap();
        let sig = if is_high_s(&sig) == want_high {
            sig
        } else {
            negate_s(&sig)
        };
        assert_eq!(is_high_s(&sig), want_high);
        env.signature = sig.to_bytes().to_vec();
        assert_eq!(submit(&wire(env)), StatusCode::ACCEPTED);
    }

    // An unregistered sender has no token: 401, also to an unknown
    // recipient, so it cannot probe the directory. A registered sender to
    // an unknown recipient: 404.
    assert_eq!(
        r.submit_as(&c, &wire(&envelope(&c, &b.id, 256, 4))),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        r.submit_as(&c, &wire(&envelope(&c, &[9; 32], 256, 5))),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        submit(&wire(&envelope(&a, &c.id, 256, 6))),
        StatusCode::NOT_FOUND
    );

    // Bad signatures: a ciphertext bit, a signature bit, anna's id signed by
    // bob, r = 0.
    let mut flipped_body = wire(&envelope(&a, &b.id, 256, 7));
    flipped_body[100] ^= 1;
    let mut flipped_sig = wire(&envelope(&a, &b.id, 256, 8));
    *flipped_sig.last_mut().unwrap() ^= 1;
    let mut forged = envelope(&a, &b.id, 256, 9);
    forged.signature = b.sign(&forged.signed_bytes()).to_vec();
    let mut zero_r = envelope(&a, &b.id, 256, 10);
    zero_r.signature[..32].fill(0);
    for bad in [flipped_body, flipped_sig, wire(&forged), wire(&zero_r)] {
        assert_eq!(submit(&bad), StatusCode::FORBIDDEN);
    }

    // Wire rules (Envelope::from_wire): version 0 and version 1 (Phase 3's
    // payload, without the authorship token), magic, a ciphertext that is
    // not bucket + 16, too short, empty.
    let good = wire(&envelope(&a, &b.id, 256, 11));
    let mut version0 = good.clone();
    version0[4..6].copy_from_slice(&[0, 0]);
    let mut version1 = envelope(&a, &b.id, 256, 14);
    let mut signed = version1.signed_bytes();
    signed[4..6].copy_from_slice(&[0, 1]);
    version1.signature = a.sign(&signed).to_vec();
    let version1 = [&signed[..], &version1.signature].concat();
    let mut magic = good.clone();
    magic[0] = b'b';
    let mut unbucketed = envelope(&a, &b.id, 256, 12);
    unbucketed.ciphertext.push(0);
    unbucketed.signature = a.sign(&unbucketed.signed_bytes()).to_vec();
    for bad in [
        version0,
        version1,
        magic,
        wire(&unbucketed),
        good[..429].to_vec(),
        Vec::new(),
    ] {
        assert_eq!(submit(&bad), StatusCode::BAD_REQUEST);
    }

    // The largest envelope is accepted; one byte more is refused before
    // parsing.
    let max = wire(&envelope(&a, &b.id, MAX_PADDED, 13));
    assert_eq!(max.len(), MAX_WIRE);
    assert_eq!(a.request(&max).len(), SUBMIT_MAX);
    assert_eq!(submit(&max), StatusCode::ACCEPTED);
    let mut over = max.clone();
    over.push(0);
    assert_eq!(submit(&over), StatusCode::PAYLOAD_TOO_LARGE);

    // Only the accepted ones wait, byte for byte, in arrival order.
    assert_eq!(r.waiting(), 4);
    assert_eq!(r.inbox(&b), vec![w1, wire(&high), wire(&low), max]);
}

#[test]
fn inbox_and_ack() {
    let r = Relayed::new();
    let (a, b, c) = (Identity::new(1), Identity::new(2), Identity::new(3));
    for (who, address) in [(&a, "anna"), (&b, "bob"), (&c, "carl")] {
        r.join(who, address);
    }
    r.approve(&a, &b, "bob");
    r.approve(&a, &c, "carl");
    r.approve(&c, &b, "bob");
    let e1 = wire(&envelope(&a, &b.id, 256, 1));
    let e2 = wire(&envelope(&a, &b.id, 1024, 2));
    let e3 = wire(&envelope(&a, &c.id, 256, 3));
    let e4 = wire(&envelope(&c, &b.id, 4096, 4));
    for (from, e) in [(&a, &e1), (&a, &e2), (&a, &e3), (&c, &e4)] {
        assert_eq!(r.submit_as(from, e), StatusCode::ACCEPTED);
    }

    // Only one's own envelopes, oldest first; polling deletes nothing.
    assert_eq!(r.inbox(&b), [e1.clone(), e2.clone(), e4.clone()]);
    assert_eq!(r.inbox(&c), std::slice::from_ref(&e3));
    assert_eq!(r.inbox(&b), [e1.clone(), e2.clone(), e4.clone()]);
    assert!(r.inbox(&a).is_empty());

    // An ack of another recipient's envelope, or of an unknown id, deletes
    // nothing.
    assert_eq!(r.ack(&b, &[id(&e3)]), StatusCode::NO_CONTENT);
    assert_eq!(r.ack(&b, &[[0x77; 32]]), StatusCode::NO_CONTENT);
    assert_eq!(r.inbox(&c), std::slice::from_ref(&e3));
    assert_eq!(r.waiting(), 4);

    // Acknowledging the middle one keeps the order of the rest; a later
    // letter comes after them.
    assert_eq!(r.ack(&b, &[id(&e2)]), StatusCode::NO_CONTENT);
    let e5 = wire(&envelope(&a, &b.id, 256, 5));
    assert_eq!(r.submit_as(&a, &e5), StatusCode::ACCEPTED);
    assert_eq!(r.inbox(&b), [e1.clone(), e4.clone(), e5.clone()]);

    // Ack bodies: no id, 257 ids, a cut id.
    for payload in [Vec::new(), vec![0; 32 * 257], vec![0; 33]] {
        assert_eq!(
            r.post("/v1/inbox/ack", b.request(&payload)).0,
            StatusCode::BAD_REQUEST
        );
    }
    // 256 ids in one ack: what is bob's goes.
    let mut ids = vec![[0u8; 32]; 255];
    ids.push(id(&e1));
    assert_eq!(r.ack(&b, &ids), StatusCode::NO_CONTENT);
    assert_eq!(r.inbox(&b), [e4, e5]);

    // At most 16 envelopes per answer.
    let d = Identity::new(4);
    r.join(&d, "dora");
    r.approve(&a, &d, "dora");
    let many: Vec<Vec<u8>> = (0..17)
        .map(|n| wire(&envelope(&a, &d.id, 256, 100 + n)))
        .collect();
    for e in &many {
        assert_eq!(r.submit_as(&a, e), StatusCode::ACCEPTED);
    }
    assert_eq!(r.inbox(&d), many[..INBOX_MAX]);
    let first: Vec<[u8; 32]> = many[..INBOX_MAX].iter().map(|w| id(w)).collect();
    assert_eq!(r.ack(&d, &first), StatusCode::NO_CONTENT);
    assert_eq!(r.inbox(&d), many[INBOX_MAX..]);

    // At most 4 MiB of envelopes per answer: three of MAX_WIRE bytes fit, a
    // fourth would not.
    const _: () = assert!(3 * MAX_WIRE <= INBOX_MAX_BYTES && 4 * MAX_WIRE > INBOX_MAX_BYTES);
    let e = Identity::new(5);
    r.join(&e, "emil");
    r.approve(&a, &e, "emil");
    let big: Vec<Vec<u8>> = (0..5)
        .map(|n| wire(&envelope(&a, &e.id, MAX_PADDED, 200 + n)))
        .collect();
    for w in &big {
        assert_eq!(r.submit_as(&a, w), StatusCode::ACCEPTED);
    }
    assert_eq!(r.inbox(&e), big[..3]);
    let first: Vec<[u8; 32]> = big[..3].iter().map(|w| id(w)).collect();
    assert_eq!(r.ack(&e, &first), StatusCode::NO_CONTENT);
    assert_eq!(r.inbox(&e), big[3..]);
}

/// docs/AUTHORSHIP.md §2.5: the relay stamps an envelope with its own clock
/// (Unix seconds) when it first stores it; a resubmit of the same envelope
/// keeps the first stamp, and the inbox answer hands each envelope over with
/// its stamp. Another envelope gets its own; an acked one takes it along.
#[test]
fn received_at_is_kept_on_resubmit_and_delivered() {
    let r = Relayed::new();
    let (a, b) = (Identity::new(1), Identity::new(2));
    r.join(&a, "anna");
    r.join(&b, "bob");
    r.approve(&a, &b, "bob");
    let first = wire(&envelope(&a, &b.id, 256, 1));
    let second = wire(&envelope(&a, &b.id, 1024, 2));

    r.set_time(0, 1_000);
    assert_eq!(r.submit_as(&a, &first), StatusCode::ACCEPTED);
    let stamped = START / DAY * DAY + 1_000;
    assert_eq!(r.inbox_at(&b), [(stamped, first.clone())]);

    // A resubmit hours later, also with another valid signature over the
    // same bytes: 200, and the first stamp stays.
    r.set_time(0, 30_000);
    assert_eq!(r.submit_as(&a, &first), StatusCode::OK);
    let mut resigned = Envelope::from_wire(&first).unwrap();
    let sig = Signature::from_slice(&resigned.signature).unwrap();
    resigned.signature = negate_s(&sig).to_bytes().to_vec();
    assert_ne!(wire(&resigned), first);
    assert_eq!(r.submit_as(&a, &wire(&resigned)), StatusCode::OK);
    assert_eq!(r.inbox_at(&b), [(stamped, first.clone())]);

    // A new envelope gets the time it arrived.
    assert_eq!(r.submit_as(&a, &second), StatusCode::ACCEPTED);
    let later = START / DAY * DAY + 30_000;
    assert_eq!(
        r.inbox_at(&b),
        [(stamped, first.clone()), (later, second.clone())]
    );
    // What the relay stores: the stamp beside the envelope, and nothing
    // once it is acknowledged.
    assert_eq!(
        r.number(
            "SELECT received_at FROM envelopes WHERE id = ?1",
            &id(&second)
        ),
        i64::try_from(later).unwrap()
    );
    assert_eq!(r.ack(&b, &[id(&first)]), StatusCode::NO_CONTENT);
    assert_eq!(r.inbox_at(&b), [(later, second)]);
    assert_eq!(r.rows("envelopes"), 1);
}

#[test]
fn ack_deletes_bytes_from_the_file() {
    let r = Relayed::new();
    let (a, b) = (Identity::new(1), Identity::new(2));
    r.join(&a, "anna");
    r.join(&b, "bob");
    r.approve(&a, &b, "bob");
    // One small envelope and one of the largest letter brev-core makes
    // (5 × 16 KiB), which spans SQLite overflow pages.
    let small = envelope(&a, &b.id, 256, 1);
    let large = envelope(&a, &b.id, 5 * 16384, 2);
    let slices = [
        &small.ciphertext[100..132],
        &large.ciphertext[70_000..70_032],
    ];
    assert_eq!(r.submit_as(&a, &wire(&small)), StatusCode::ACCEPTED);
    assert_eq!(r.submit_as(&a, &wire(&large)), StatusCode::ACCEPTED);

    // Positive control: the scan reads the relay's file.
    for slice in slices {
        assert!(r.files_contain(slice));
    }
    assert_eq!(r.inbox(&b).len(), 2);
    for slice in slices {
        assert!(r.files_contain(slice), "polling deletes nothing");
    }

    assert_eq!(r.ack(&b, &[small.id(), large.id()]), StatusCode::NO_CONTENT);
    assert_eq!(r.waiting(), 0);
    for slice in slices {
        assert!(!r.files_contain(slice), "acknowledged bytes are zeroed");
    }
    // journal_mode DELETE: only the file itself is left, no -wal or -shm.
    let names: Vec<_> = fs::read_dir(r.folder())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names, ["relay.db"]);

    // No tombstones: the sender can store the same envelope again, and it
    // is delivered again (brev-core drops it as a duplicate).
    assert!(r.inbox(&b).is_empty());
    assert_eq!(r.submit_as(&a, &wire(&small)), StatusCode::ACCEPTED);
    assert_eq!(r.inbox(&b), [wire(&small)]);
}

#[test]
fn relay_file_holds_no_plaintext() {
    const MARKER: &str = "BREV-SECRET-BODY \u{e6}\u{f8}\u{e5}";
    let r = Relayed::new();
    let (a, b) = (Identity::new(1), Identity::new(2));
    r.join(&a, "brev-secret-me");
    r.join(&b, "brev-secret-peer");
    r.approve(&a, &b, "brev-secret-peer");
    assert_eq!(
        r.lookup(&a, "brev-secret-peer"),
        (StatusCode::OK, b.reply(true))
    );

    // A letter sealed as brev-core seals it: the marker in UTF-8 and
    // UTF-16LE, padded, XChaCha20-Poly1305 with the header as associated
    // data.
    let utf16: Vec<u8> = MARKER.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let content = [MARKER.as_bytes(), &utf16].concat();
    let mut sealed = vec![0u8; padded_len(content.len()).unwrap()];
    pad_into(&content, &mut sealed).unwrap();
    assert!(contains(&sealed, MARKER.as_bytes()) && contains(&sealed, &utf16));
    let mut env = Envelope {
        sender: a.id,
        recipient: b.id,
        nonce: [3; 24],
        ciphertext: Vec::new(),
        signature: Vec::new(),
    };
    let header = Envelope::header_bytes(&env.sender, &env.recipient, &env.nonce);
    let tag = XChaCha20Poly1305::new_from_slice(&[9; 32])
        .unwrap()
        .encrypt_inout_detached(
            &XNonce::from(env.nonce),
            &header,
            sealed.as_mut_slice().into(),
        )
        .unwrap();
    sealed.extend_from_slice(&tag);
    env.ciphertext = sealed;
    env.signature = a.sign(&env.signed_bytes()).to_vec();
    assert_eq!(r.submit_as(&a, &wire(&env)), StatusCode::ACCEPTED);

    let check = |delivered: bool| {
        for needle in [MARKER.as_bytes(), &utf16, b"BREV-SECRET-BODY"] {
            assert!(!r.files_contain(needle), "plaintext in the relay's folder");
        }
        // Controls: the directory holds both addresses in clear, each
        // token only as its hash, and the ciphertext until it is delivered.
        for address in ["brev-secret-me", "brev-secret-peer"] {
            assert!(r.files_contain(address.as_bytes()), "{address}");
        }
        for who in [&a, &b] {
            assert!(!r.files_contain(&who.token));
            assert!(r.files_contain(&token_hash(&who.token)));
        }
        assert_eq!(r.files_contain(&env.ciphertext[40..72]), !delivered);
    };
    check(false);
    assert_eq!(r.inbox(&b), [wire(&env)]);
    assert_eq!(r.ack(&b, &[env.id()]), StatusCode::NO_CONTENT);
    check(true);
}

/// Every hook call, in order.
#[derive(Debug, PartialEq)]
enum Call {
    Register(String),
    Submit([u8; 32], [u8; 32], usize),
    Request([u8; 32], Endpoint),
}

#[derive(Default)]
struct Switch {
    deny: AtomicBool,
    calls: Mutex<Vec<Call>>,
}

struct Recording(Arc<Switch>);

impl Recording {
    fn decide(&self, call: Call) -> Decision {
        self.0.calls.lock().unwrap().push(call);
        if self.0.deny.load(Ordering::SeqCst) {
            Decision::Deny
        } else {
            Decision::Allow
        }
    }
}

impl Policy for Recording {
    fn register(&self, address: &str) -> Decision {
        self.decide(Call::Register(address.into()))
    }
    fn submit(&self, sender: &[u8; 32], recipient: &[u8; 32], len: usize) -> Decision {
        self.decide(Call::Submit(*sender, *recipient, len))
    }
    fn request(&self, caller: &[u8; 32], endpoint: Endpoint) -> Decision {
        self.decide(Call::Request(*caller, endpoint))
    }
}

#[test]
fn policy_hook_denies_before_writing() {
    let switch = Arc::new(Switch::default());
    let r = Relayed::with(
        Box::new(Recording(Arc::clone(&switch))),
        |_| {},
        Gates::default(),
    );
    let deny = |on: bool| switch.deny.store(on, Ordering::SeqCst);
    let (a, b) = (Identity::new(1), Identity::new(2));
    r.join(&b, "bob");

    // Registration: 429 and nothing written. It is asked last: a bad
    // signature and a taken address are refused before it.
    deny(true);
    assert_eq!(r.register(&a, "anna"), StatusCode::TOO_MANY_REQUESTS);
    let mut unsigned = a.registration(b"anna");
    unsigned[80] ^= 1; // in the X25519 key
    assert_eq!(r.post("/v1/register", unsigned).0, StatusCode::UNAUTHORIZED);
    assert_eq!(r.register(&a, "bob"), StatusCode::CONFLICT);
    deny(false);
    assert_eq!(r.lookup(&b, "anna").0, StatusCode::NOT_FOUND);
    assert_eq!(
        r.register(&a, "anna"),
        StatusCode::CREATED,
        "not 200: nothing was there"
    );

    // Submit: 429 and nothing stored or counted; it is asked after the
    // approval check, and a bad signature never reaches it.
    let env = envelope(&a, &b.id, 256, 1);
    let w = wire(&env);
    assert_eq!(r.submit_as(&a, &w), StatusCode::CONFLICT, "not approved");
    r.approve(&a, &b, "bob");
    deny(true);
    assert_eq!(r.submit_as(&a, &w), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!((r.waiting(), r.count(&a, 1)), (0, 0));
    let mut forged = w.clone();
    forged[100] ^= 1;
    assert_eq!(r.submit_as(&a, &forged), StatusCode::FORBIDDEN);

    // Token requests: 429 after the token check; a wrong token is 401
    // without asking.
    assert_eq!(r.lookup(&b, "anna").0, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        r.post("/v1/inbox", b.request(&[])).0,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        r.lookup(&Identity::new(3), "anna").0,
        StatusCode::UNAUTHORIZED
    );

    // Ack: 429 and nothing deleted.
    deny(false);
    assert_eq!(r.submit_as(&a, &w), StatusCode::ACCEPTED);
    deny(true);
    assert_eq!(r.ack(&b, &[env.id()]), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(r.waiting(), 1);
    deny(false);
    assert_eq!(r.inbox(&b), std::slice::from_ref(&w));
    assert_eq!(r.ack(&b, &[env.id()]), StatusCode::NO_CONTENT);
    assert_eq!(r.waiting(), 0);

    // The hooks saw exactly the requests that passed every other check,
    // with their arguments.
    let (lookup, inbox, ack) = (Endpoint::Lookup, Endpoint::Inbox, Endpoint::Ack);
    assert_eq!(
        *switch.calls.lock().unwrap(),
        [
            Call::Register("bob".into()),
            Call::Register("anna".into()), // denied
            Call::Request(b.id, lookup),
            Call::Register("anna".into()),
            Call::Request(a.id, Endpoint::Request), // the approval
            Call::Request(b.id, Endpoint::Answer),
            Call::Submit(a.id, b.id, w.len()), // denied
            Call::Request(b.id, lookup),       // denied
            Call::Request(b.id, inbox),        // denied
            Call::Submit(a.id, b.id, w.len()),
            Call::Request(b.id, ack), // denied
            Call::Request(b.id, inbox),
            Call::Request(b.id, ack),
        ]
    );
}

#[test]
fn release_frees_an_address() {
    let r = Relayed::new();
    let (a, b, c) = (Identity::new(1), Identity::new(2), Identity::new(3));
    r.join(&a, "anna");
    r.join(&b, "bob");
    // Asking means taking the answerer's letters: both ways now.
    r.approve(&a, &b, "bob");
    let to_a = [
        wire(&envelope(&b, &a.id, 256, 1)),
        wire(&envelope(&b, &a.id, 1024, 2)),
    ];
    let to_b = wire(&envelope(&a, &b.id, 256, 3));
    for w in &to_a {
        assert_eq!(r.submit_as(&b, w), StatusCode::ACCEPTED);
    }
    assert_eq!(r.submit_as(&a, &to_b), StatusCode::ACCEPTED);

    assert!(r.relay.release("anna").unwrap());
    assert_eq!(r.waiting(), 1, "anna's waiting letters go with her");
    assert_eq!(
        r.inbox(&b),
        std::slice::from_ref(&to_b),
        "letters she sent stay"
    );
    assert_eq!(
        r.post("/v1/inbox", a.request(&[])).0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(r.lookup(&b, "anna").0, StatusCode::NOT_FOUND);
    assert_eq!(r.submit_as(&b, &to_a[0]), StatusCode::NOT_FOUND);
    r.join(&c, "anna");
    assert_eq!(
        r.lookup(&b, "anna"),
        (StatusCode::OK, c.reply(false)),
        "free again, a new identity with no links"
    );
    assert!(!r.relay.release("nobody").unwrap());

    // The operator command, on the file the relay is serving.
    let out = Command::new(BIN)
        .args(["release", "--db"])
        .arg(r.db())
        .arg("bob")
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(r.lookup(&c, "bob").0, StatusCode::NOT_FOUND);
    assert_eq!(r.waiting(), 0);
    // It refuses an invalid address (2), an address nobody has and a
    // missing file (1), and creates nothing.
    let missing = r.tmp.0.join("none").join("relay.db");
    for (db, address, code) in [
        (r.db(), "Bob", 2),
        (r.db(), "bob", 1),
        (missing.clone(), "anna", 1),
    ] {
        let out = Command::new(BIN)
            .args(["release", "--db"])
            .arg(&db)
            .arg(address)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(code), "{address}");
    }
    assert!(!missing.parent().unwrap().exists());
    assert_eq!(r.lookup(&c, "anna"), (StatusCode::OK, c.reply(false)));
}

#[test]
fn listen_refuses_anything_but_127_0_0_1() {
    for ok in ["127.0.0.1:0", "127.0.0.1:8787", "127.0.0.1:65535"] {
        let addr = parse_listen(ok).unwrap();
        assert_eq!(addr.ip(), Ipv4Addr::LOCALHOST);
        assert_eq!(addr.to_string(), ok);
    }
    for bad in [
        "0.0.0.0:8787",
        "[::1]:8787",
        "[::]:8787",
        "[::ffff:127.0.0.1]:8787",
        "localhost:8787",
        "192.168.1.10:8787",
        "10.0.0.2:8787",
        "127.0.0.2:8787",
        "127.1:8787",
        "127.0.0.1",
        "127.0.0.1:",
        "127.0.0.1:+8787",
        "127.0.0.1:65536",
        "127.0.0.1:0x10",
        " 127.0.0.1:8787",
        "127.0.0.1:8787 ",
        "http://127.0.0.1:8787",
    ] {
        assert!(matches!(parse_listen(bad), Err(Error::Listen)), "{bad}");
    }

    // Server::start refuses the others too, before it binds.
    let tmp = TempDir::new();
    let relay = Relay::open_with(
        &tmp.0.join("relay.db"),
        Box::new(Open),
        Config::default(),
        Gates::default(),
    );
    let relay = Arc::new(relay.unwrap());
    for bad in [
        "0.0.0.0:0",
        "[::1]:0",
        "[::ffff:127.0.0.1]:0",
        "192.168.1.10:0",
        "127.0.0.2:0",
    ] {
        let started = Server::start(Arc::clone(&relay), bad.parse().unwrap(), false);
        assert!(matches!(started, Err(Error::Listen)), "{bad}");
    }

    // So does the binary: exit 2, and no database or folder is made.
    for bad in [
        "0.0.0.0:8787",
        "[::1]:8787",
        "localhost:8787",
        "192.168.1.10:8787",
    ] {
        let db = tmp.0.join("never").join("relay.db");
        let out = Command::new(BIN)
            .args(["serve", "--db"])
            .arg(&db)
            .args(["--listen", bad])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{bad}");
        assert!(!db.parent().unwrap().exists(), "{bad}");
    }
}

#[test]
fn serve_writes_the_port_file_and_traces_path_and_status() {
    let tmp = TempDir::new();
    let db = tmp.0.join("brev-relay").join("relay.db");
    let (mut child, base) = spawn(&tmp, &db, &["--trace"]);

    let client = client();
    let health = client.get(format!("{base}/v1/health")).send().unwrap();
    assert_eq!(health.status(), StatusCode::OK);
    assert_eq!(health.text().unwrap(), "brev-relay v1");
    let register = client
        .post(format!("{base}/v1/register"))
        .body(vec![1, 2, 3])
        .send()
        .unwrap();
    assert_eq!(register.status(), StatusCode::BAD_REQUEST);
    let unknown = client.get(format!("{base}/v1/nothing")).send().unwrap();
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);

    // The folder and the file are private to this user.
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(db.parent().unwrap()), 0o700);
    assert_eq!(mode(&db), 0o600);

    // One line per request, path and status only, printed before the answer.
    let mut lines = BufReader::new(child.0.stdout.take().unwrap()).lines();
    for want in ["/v1/health 200", "/v1/register 400", "/v1/nothing 404"] {
        assert_eq!(lines.next().unwrap().unwrap(), want);
    }
}

#[test]
fn stop_closes_the_port_and_a_new_server_reuses_it() {
    let tmp = TempDir::new();
    let relay = Relay::open_with(
        &tmp.0.join("relay.db"),
        Box::new(Open),
        Config::default(),
        Gates::default(),
    );
    let relay = Arc::new(relay.unwrap());
    let server = Server::start(
        Arc::clone(&relay),
        parse_listen("127.0.0.1:0").unwrap(),
        false,
    )
    .unwrap();
    let addr = server.addr();
    assert_eq!(addr.ip(), Ipv4Addr::LOCALHOST);
    assert_ne!(addr.port(), 0);
    let client = client();
    let health = || client.get(format!("http://{addr}/v1/health")).send();
    assert_eq!(health().unwrap().status(), StatusCode::OK);
    assert_eq!(health().unwrap().status(), StatusCode::OK);
    assert_eq!(server.requests(), 2);

    // Stopped: nothing answers, also not on the client's pooled connection.
    server.stop().unwrap();
    assert!(health().is_err());
    assert!(TcpStream::connect(addr).is_err(), "the port is closed");

    // A new server on the same port and file serves again (brev-core's
    // relay-down tests stop and restart the relay this way).
    let server = Server::start(relay, addr, false).unwrap();
    assert_eq!(server.addr(), addr);
    assert_eq!(health().unwrap().status(), StatusCode::OK);
    assert_eq!(server.requests(), 1);
}
