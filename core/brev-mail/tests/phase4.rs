//! Phase 4 end to end (docs/PHASE4_DESIGN.md §8, brev-mail tests 1 to 7):
//! `Brev` sessions in temp dirs, the Phase 4 relay in-process on
//! 127.0.0.1:0, P-256 test keys standing in for the Secure Enclave, and the
//! FFI API exactly as the Swift app uses it. Includes both brev-mail
//! definition-of-done tests of CLAUDE.md §5 Phase 4
//! (`invite_with_wrong_fingerprint_is_rejected`,
//! `a_stranger_cannot_reach_an_inbox`), *Blokker* (owner answer 6), and the
//! deferred WP2 review note: a blocked peer cannot get an event into the
//! blocker's queue.
//!
//! Where a test needs the relay to lie (or a same-user program to edit its
//! file, CLAUDE.md §2), it writes the relay's file through a second
//! connection.

mod common;

use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use brev_core::BrevError;
use brev_proto::invite;
use brev_relay::{Config, Decision, Endpoint, Open, Policy};
use common::{contains, len32, pair, random, read, Relayed, User};

/// Opens `code` at `u`.
fn open(u: &User, code: &[u8]) -> Result<brev_core::InviteInfo, BrevError> {
    u.b.open_invite(code, len32(code.len()))
}

/// The secret of an invite code.
fn secret_of(code: &[u8]) -> [u8; invite::SECRET_LEN] {
    let mut secret = [0u8; invite::SECRET_LEN];
    invite::parse(code, &mut secret).unwrap();
    secret
}

/// Rows of `table` in `u`'s own store.
fn local_rows(u: &User, table: &str) -> i64 {
    let raw = rusqlite::Connection::open_with_flags(
        u.dir.0.join("brev.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    raw.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}

/// Events waiting at the relay for the identity at `address`.
fn events_at(relay: &Relayed, address: &str) -> i64 {
    relay
        .sql()
        .query_row(
            "SELECT count(*) FROM events WHERE recipient = ?1",
            [relay.id_of(address)],
            |r| r.get(0),
        )
        .unwrap()
}

/// The one contact of `u` with `address`: (waiting, verified, blocked).
fn state(u: &User, address: &str) -> (bool, bool, bool) {
    let rows = u.b.contacts().unwrap();
    let row = rows
        .iter()
        .find(|c| read(&c.name) == address.as_bytes())
        .unwrap();
    let info = u.b.contact_info(row.id.clone()).unwrap();
    assert_eq!(
        (info.waiting, info.verified, info.blocked),
        (row.waiting, row.verified, row.blocked),
        "the row and the header agree"
    );
    (row.waiting, row.verified, row.blocked)
}

/// The three steps of a letter after `prepare_send`, when a ticket exists.
fn sign_and_submit(u: &User, contact: &[u8], body: &[u8]) -> Result<Vec<u8>, BrevError> {
    let digest =
        u.b.sign_request(contact.to_vec(), b"s", 1, body, len32(body.len()))?;
    u.b.attach_signature(u.key.sign_digest(&digest))?;
    u.b.submit()
}

/// DoD (design §8 brev-mail 1, V77): a code whose fingerprint, address or
/// form does not match what the relay answers is `InviteMismatch`, and
/// nothing is kept, stored or sent after the open: no registration, no
/// redeem, no contact. Also when the relay lies about the inviter's key.
#[test]
fn invite_with_wrong_fingerprint_is_rejected() {
    let relay = Relayed::new();
    let (a, c) = (User::new(&relay.url), User::new(&relay.url));
    relay.join(&a, "anna");
    relay.join(&c, "carl");
    let code = a.invite();
    let text = String::from_utf8(code.clone()).unwrap();
    let parts: Vec<&str> = text.split('.').collect();
    assert_eq!(parts[..2], ["brev1", "anna"]);
    let (fp, secret) = (parts[2], parts[3]);
    let root = String::from_utf8(relay.root_code()).unwrap();
    let root_secret = root.strip_prefix("brev1.").unwrap();

    // (a) one character of the fingerprint changed, (b) another address,
    // (d) a 4-part code whose secret is a root invite's, answered `00`.
    let mut edited = fp.as_bytes().to_vec();
    edited[7] = if edited[7] == b'a' { b'b' } else { b'a' };
    let edited = String::from_utf8(edited).unwrap();
    let bad = [
        format!("brev1.anna.{edited}.{secret}"),
        format!("brev1.carl.{fp}.{secret}"),
        format!("brev1.anna.{fp}.{root_secret}"),
    ];

    // The invitee on the address page (not registered), and a registered
    // user who would redeem.
    let b = User::new(&relay.url);
    for code in &bad {
        for u in [&b, &c] {
            let requests = relay.requests();
            assert!(
                matches!(open(u, code.as_bytes()), Err(BrevError::InviteMismatch)),
                "{code}"
            );
            assert!(matches!(
                u.b.register_request(b"bert", 4),
                Err(BrevError::InviteInvalid | BrevError::Duplicate)
            ));
            assert!(matches!(
                u.b.redeem_invite(),
                Err(BrevError::InviteInvalid | BrevError::NotFound)
            ));
            assert_eq!(relay.requests(), requests + 1, "{code}: the open only");
        }
    }

    // (c) The relay lies: another bundle (C's) in its row for the inviter.
    let sql = relay.sql();
    let real: (Vec<u8>, Vec<u8>) = sql
        .query_row(
            "SELECT signing_key, x25519 FROM identities WHERE address = 'anna'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    sql.execute(
        "UPDATE identities SET (signing_key, x25519) =
             (SELECT signing_key, x25519 FROM identities WHERE address = 'carl')
         WHERE address = 'anna'",
        [],
    )
    .unwrap();
    for u in [&b, &c] {
        let requests = relay.requests();
        assert!(matches!(open(u, &code), Err(BrevError::InviteMismatch)));
        assert!(matches!(
            u.b.redeem_invite(),
            Err(BrevError::InviteInvalid | BrevError::NotFound)
        ));
        assert_eq!(relay.requests(), requests + 1);
    }
    sql.execute(
        "UPDATE identities SET signing_key = ?1, x25519 = ?2 WHERE address = 'anna'",
        rusqlite::params![real.0, real.1],
    )
    .unwrap();

    // Nothing was stored: no contact, B not registered, the invite unused.
    assert!(!b.b.me().unwrap().registered);
    assert!(b.b.contacts().unwrap().is_empty());
    assert!(c.b.contacts().unwrap().is_empty());
    assert_eq!(relay.rows("identities"), 2);

    // Control: the code as made opens and registers B.
    let info = open(&b, &code).unwrap();
    assert!(!info.root);
    assert_eq!(read(&info.address), b"anna");
    assert_eq!(info.code, a.b.me().unwrap().code);
    let digest = b.b.register_request(b"bert", 4).unwrap();
    b.b.register(b.key.sign_digest(&digest), Vec::new())
        .unwrap();
    assert_eq!(state(&b, "anna"), (false, true, false));
}

/// Design §8 brev-mail 2: root → A; A invites B; B registers with A
/// verified; A's sync pins B verified and deletes its invite row; letters
/// go both ways, and a letter B writes before A's sync arrives in that sync.
#[test]
fn invite_makes_both_approved_and_verified() {
    let relay = Relayed::new();
    let (a, b) = (User::new(&relay.url), User::new(&relay.url));
    relay.join(&a, "anna");
    let code = a.invite();
    assert!(code.len() <= 96 && code.starts_with(b"brev1.anna."));
    assert_eq!(local_rows(&a, "invites"), 1, "A keeps the sealed secret");

    let info = open(&b, &code).unwrap();
    assert!(!info.root);
    assert_eq!(read(&info.address), b"anna");
    assert_eq!(info.code, a.b.me().unwrap().code);
    let digest = b.b.register_request(b"bert", 4).unwrap();
    b.b.register(b.key.sign_digest(&digest), Vec::new())
        .unwrap();
    assert!(b.b.me().unwrap().registered);
    assert_eq!(state(&b, "anna"), (false, true, false));
    // The invite is used up, and B's opened invite with it.
    assert!(matches!(b.b.redeem_invite(), Err(BrevError::InviteInvalid)));
    assert!(matches!(
        open(&User::new(&relay.url), &code),
        Err(BrevError::InviteInvalid)
    ));

    // B writes first; A's sync pins B from the invited event, then takes
    // B's letter in the same sync.
    let a_at_b = b.contact("anna");
    b.send(&a_at_b, b"s", b"first");
    let synced = a.b.sync().unwrap();
    assert!(synced.contacts_changed);
    assert_eq!((synced.letters, synced.requests), (1, 0));
    assert_eq!(state(&a, "bert"), (false, true, false));
    assert_eq!(local_rows(&a, "invites"), 0, "the invite row is gone");
    let b_at_a = a.contact("bert");
    assert_eq!(
        a.b.contact_info(b_at_a.clone()).unwrap().code,
        b.b.me().unwrap().code
    );

    a.send(&b_at_a, b"s", b"reply");
    assert_eq!(b.b.sync().unwrap().letters, 1);
    assert_eq!(a.letters(&b_at_a).len(), 2);
    assert_eq!(b.letters(&a_at_b).len(), 2);
    // Nothing changes on the next sync; no event waits.
    assert!(!a.b.sync().unwrap().contacts_changed);
    assert_eq!(events_at(&relay, "anna"), 0);
    // The relay keeps the invite graph: B came in through A.
    let invited_by: Vec<u8> = relay
        .sql()
        .query_row(
            "SELECT invited_by FROM identities WHERE address = 'bert'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(invited_by, relay.id_of("anna"));
}

/// Design §8 brev-mail 3: invited events the relay forges pin nothing: a
/// random tag, a real tag with another identity's bundle, and a real
/// bundle and tag under another address. A letter from that identity is
/// dropped by the client rule, even with the relay's approval. Control: the
/// real event pins.
#[test]
fn forged_invited_event_is_dropped() {
    let relay = Relayed::new();
    let [a, x, y] = [(); 3].map(|()| User::new(&relay.url));
    relay.join(&a, "anna");
    relay.join(&x, "xena");
    relay.join(&y, "yngve");
    let code = a.invite();
    let s = secret_of(&code);
    let (aid, xid, yid) = (
        relay.id_of("anna"),
        relay.id_of("xena"),
        relay.id_of("yngve"),
    );
    let real = invite::tag(&s, &xid, &aid, b"xena").unwrap();
    let put = |peer: &[u8; 32], tag: &[u8; 32]| {
        relay
            .sql()
            .execute(
                "INSERT INTO events (recipient, peer, kind, tag) VALUES (?1, ?2, 2, ?3)",
                rusqlite::params![aid, peer, tag],
            )
            .unwrap();
    };

    put(&xid, &random());
    put(&yid, &real);
    let synced = a.b.sync().unwrap();
    assert!(!synced.contacts_changed);
    assert!(a.b.contacts().unwrap().is_empty());
    assert_eq!(events_at(&relay, "anna"), 0, "seen and dropped");

    // X's real bundle and tag, but the relay names X "xerxes".
    let rename = |to: &str| {
        relay
            .sql()
            .execute(
                "UPDATE identities SET address = ?1 WHERE id = ?2",
                rusqlite::params![to, xid],
            )
            .unwrap();
    };
    rename("xerxes");
    put(&xid, &real);
    assert!(!a.b.sync().unwrap().contacts_changed);
    assert!(a.b.contacts().unwrap().is_empty());
    rename("xena");
    assert_eq!(local_rows(&a, "invites"), 1, "the invite is not used up");

    // X's letter, stored because the relay says A approved X: dropped.
    relay.force_link("anna", "xena");
    let a_at_x = x.add("anna");
    x.send(&a_at_x, b"s", b"forged");
    assert_eq!(relay.waiting(), 1);
    assert_eq!(a.b.sync().unwrap().letters, 0);
    assert_eq!(relay.waiting(), 0, "acknowledged");
    assert!(a.b.contacts().unwrap().is_empty());

    // Control: the event as the relay makes it on redeem pins X, verified.
    put(&xid, &real);
    assert!(a.b.sync().unwrap().contacts_changed);
    assert_eq!(state(&a, "xena"), (false, true, false));
    assert_eq!(local_rows(&a, "invites"), 0);
}

/// DoD (design §8 brev-mail 4, V76): a stranger C cannot reach A's inbox.
/// C's request waits; `prepare_send` is `NotApproved` with no ticket, so no
/// digest and no prompt; a submit with a faked ticket (test hook) is refused
/// by the relay, `NotApproved`; A's sync gets no letter.
#[test]
fn a_stranger_cannot_reach_an_inbox() {
    let relay = Relayed::new();
    let (a, c) = (User::new(&relay.url), User::new(&relay.url));
    relay.join(&a, "anna");
    relay.join(&c, "carl");
    let a_at_c = c.add("anna");
    assert_eq!(state(&c, "anna"), (true, false, false));

    let requests = relay.requests();
    assert!(matches!(
        c.b.prepare_send(a_at_c.clone()),
        Err(BrevError::NotApproved)
    ));
    assert_eq!(relay.requests(), requests + 1, "the lookup only");
    assert!(matches!(
        c.b.sign_request(a_at_c.clone(), b"s", 1, b"x", 1),
        Err(BrevError::Malformed)
    ));

    c.b.force_ticket_for_test(a_at_c.clone()).unwrap();
    assert!(matches!(
        sign_and_submit(&c, &a_at_c, b"forced"),
        Err(BrevError::NotApproved)
    ));
    assert_eq!(relay.waiting(), 0, "the relay stored nothing");
    assert!(
        matches!(c.b.submit(), Err(BrevError::NotFound)),
        "forgotten"
    );
    assert!(c.b.threads(a_at_c).unwrap().is_empty());

    let synced = a.b.sync().unwrap();
    assert_eq!((synced.letters, synced.requests), (0, 1));
    assert!(a.b.contacts().unwrap().is_empty());
}

/// Design §8 brev-mail 5: a request shows the asker's address and code;
/// approving is one call and makes both contacts; declining tells the
/// asker nothing and stops its requests.
#[test]
fn request_approve_and_decline() {
    let relay = Relayed::new();
    let [a, b, c] = [(); 3].map(|()| User::new(&relay.url));
    relay.join(&a, "anna");
    relay.join(&b, "bert");
    relay.join(&c, "carl");

    let b_at_a = a.add("bert");
    assert_eq!(state(&a, "bert"), (true, false, false));
    let synced = b.b.sync().unwrap();
    assert_eq!((synced.requests, synced.contacts_changed), (1, false));
    let asked = b.b.requests().unwrap();
    assert_eq!(asked.len(), 1);
    assert_eq!(read(&asked[0].address), b"anna");
    assert_eq!(asked[0].code, a.b.me().unwrap().code);
    assert_eq!(asked[0].peer, relay.id_of("anna"));
    assert!(b.b.contacts().unwrap().is_empty(), "not a contact yet");

    // Approve: A (who asked) takes B's letters, so B can write at once.
    let a_at_b = b.b.answer_request(asked[0].peer.clone(), true).unwrap();
    assert_eq!(a_at_b.len(), 16);
    assert_eq!(state(&b, "anna"), (false, false, false));
    assert!(b.b.requests().unwrap().is_empty());
    assert!(matches!(
        b.b.answer_request(asked[0].peer.clone(), true),
        Err(BrevError::NotFound)
    ));
    let synced = a.b.sync().unwrap();
    assert!(synced.contacts_changed, "the approval");
    assert_eq!(state(&a, "bert"), (false, false, false));
    a.send(&b_at_a, b"s", b"a to b");
    assert_eq!(b.b.sync().unwrap().letters, 1);
    b.send(&a_at_b, b"s", b"b to a");
    assert_eq!(a.b.sync().unwrap().letters, 1);

    // Decline: an empty id; C is not told and cannot write.
    let b_at_c = c.add("bert");
    assert_eq!(b.b.sync().unwrap().requests, 1);
    let peer = b.b.requests().unwrap()[0].peer.clone();
    assert!(b.b.answer_request(peer, false).unwrap().is_empty());
    assert!(b.b.requests().unwrap().is_empty());
    assert_eq!(b.b.contacts().unwrap().len(), 1);
    assert!(matches!(
        c.b.prepare_send(b_at_c),
        Err(BrevError::NotApproved)
    ));
    assert_eq!(state(&c, "bert"), (true, false, false));
    assert_eq!(b.b.sync().unwrap().requests, 0, "no new request");
    assert_eq!(events_at(&relay, "bert"), 0);
}

/// Design §8 brev-mail 5: `add_contact` always sends a request, so adding
/// a peer the user declined lifts the decline; and adding a peer whose
/// request waits approves it at once, both ways.
#[test]
fn add_contact_always_requests() {
    let relay = Relayed::new();
    let [a, b, c] = [(); 3].map(|()| User::new(&relay.url));
    relay.join(&a, "anna");
    relay.join(&b, "bert");
    relay.join(&c, "carl");

    // B declines C, then adds C by address.
    let b_at_c = c.add("bert");
    b.b.sync().unwrap();
    let peer = b.b.requests().unwrap()[0].peer.clone();
    b.b.answer_request(peer, false).unwrap();
    let requests = relay.requests();
    let c_at_b = b.add("carl");
    assert_eq!(relay.requests(), requests + 2, "a lookup and a request");
    assert_eq!(state(&b, "carl"), (false, false, false), "C asked B");
    c.send(&b_at_c, b"s", b"unblocked");
    assert_eq!(b.b.sync().unwrap().letters, 1);
    b.send(&c_at_b, b"s", b"reply");
    assert_eq!(c.b.sync().unwrap().letters, 1);

    // A asks B; B adds A while A's request waits in B's session.
    a.add("bert");
    assert_eq!(b.b.sync().unwrap().requests, 1);
    let a_at_b = b.add("anna");
    assert!(b.b.requests().unwrap().is_empty(), "the request is taken");
    assert_eq!(state(&b, "anna"), (false, false, false));
    assert!(a.b.sync().unwrap().contacts_changed, "the approval");
    assert_eq!(state(&a, "bert"), (false, false, false));
    b.send(&a_at_b, b"s", b"crossed");
    assert_eq!(a.b.sync().unwrap().letters, 1);
}

/// Refuses the answers while `deny` is set: answers lost on the way.
struct LoseAnswers(Arc<AtomicBool>);

impl Policy for LoseAnswers {
    fn register(&self, _: &str) -> Decision {
        Decision::Allow
    }
    fn submit(&self, _: &[u8; 32], _: &[u8; 32], _: usize) -> Decision {
        Decision::Allow
    }
    fn request(&self, _: &[u8; 32], endpoint: Endpoint) -> Decision {
        if endpoint == Endpoint::Answer && self.0.load(Ordering::SeqCst) {
            Decision::Deny
        } else {
            Decision::Allow
        }
    }
}

/// Design §8 brev-mail 5: answers that are lost leave their events at the
/// relay; the next sync handles the same events again, finds the same
/// state, and makes no second contact.
#[test]
fn events_are_processed_once() {
    let lose = Arc::new(AtomicBool::new(false));
    let relay = Relayed::with(Box::new(LoseAnswers(Arc::clone(&lose))));
    let [a, b, c, d] = [(); 4].map(|()| User::new(&relay.url));
    relay.join(&a, "anna");
    relay.join(&c, "carl");
    relay.join(&d, "dora");
    // An invited event (B), a request (C) and an approval (D) wait at A.
    b.register_with(&a.invite(), "bert");
    c.add("anna");
    a.add("dora");
    d.b.sync().unwrap();
    let peer = d.b.requests().unwrap()[0].peer.clone();
    d.b.answer_request(peer, true).unwrap();
    assert_eq!(events_at(&relay, "anna"), 3);

    lose.store(true, Ordering::SeqCst);
    let first = a.b.sync().unwrap();
    assert!(first.contacts_changed);
    assert_eq!(first.requests, 1);
    assert_eq!(events_at(&relay, "anna"), 3, "every answer was lost");
    let names = |u: &User| -> Vec<Vec<u8>> {
        u.b.contacts()
            .unwrap()
            .iter()
            .map(|c| read(&c.name))
            .collect()
    };
    assert_eq!(names(&a), [b"dora".to_vec(), b"bert".to_vec()]);
    for _ in 0..2 {
        let again = a.b.sync().unwrap();
        assert!(!again.contacts_changed);
        assert_eq!(again.requests, 1);
        assert_eq!(names(&a), [b"dora".to_vec(), b"bert".to_vec()]);
    }
    assert_eq!(state(&a, "bert"), (false, true, false));
    assert_eq!(state(&a, "dora"), (false, false, false));

    lose.store(false, Ordering::SeqCst);
    assert!(!a.b.sync().unwrap().contacts_changed);
    assert_eq!(events_at(&relay, "anna"), 1, "only C's request waits");
    assert_eq!(names(&a).len(), 2);
    assert_eq!(a.asking(), [b"carl".to_vec()]);
}

/// Design §8 brev-mail 6: B is released and B' (brought in by D) asks A
/// under B's address: A's contact shows the key change, no answer goes
/// out, B' cannot write; once A accepts the new code, the next sync
/// approves B', whose letters then arrive. The accepted key keeps none of
/// the old key's flags.
#[test]
fn key_change_through_a_request() {
    let relay = Relayed::new();
    let (a, _b, b_at_a, _) = pair(&relay);
    assert_eq!(state(&a, "bert"), (false, true, false));
    let d = User::new(&relay.url);
    relay.join(&d, "dora");
    assert!(relay.relay.release("bert").unwrap());
    let b2 = User::new(&relay.url);
    b2.register_with(&d.invite(), "bert");
    let a_at_b2 = b2.add("anna");

    let synced = a.b.sync().unwrap();
    assert!(synced.contacts_changed);
    assert_eq!(synced.requests, 0, "a contact's request, not a stranger's");
    assert!(a.b.contacts().unwrap()[0].key_changed);
    assert_eq!(events_at(&relay, "anna"), 1, "not answered");
    assert!(!a.b.sync().unwrap().contacts_changed, "the same again");
    assert!(matches!(
        b2.b.prepare_send(a_at_b2.clone()),
        Err(BrevError::NotApproved)
    ));

    let new_code = a.b.contact_info(b_at_a.clone()).unwrap().new_code;
    assert_eq!(new_code, b2.b.me().unwrap().code);
    a.b.accept_new_key(b_at_a.clone(), new_code).unwrap();
    assert_eq!(state(&a, "bert"), (true, false, false), "old flags gone");
    assert!(a.b.sync().unwrap().contacts_changed);
    assert_eq!(state(&a, "bert"), (false, false, false));
    assert_eq!(events_at(&relay, "anna"), 0, "answered yes");
    b2.send(&a_at_b2, b"s", b"new key");
    assert_eq!(a.b.sync().unwrap().letters, 1);
}

/// Design §8 brev-mail 6: opening an invite of someone who is already a
/// contact: the same key is fine and redeeming sets «verified» on both
/// sides; another key is `KeyChanged` with the code-verified bundle in
/// `pending`, nothing kept to redeem; after the acceptance the code opens
/// and redeems. A root invite does not redeem.
#[test]
fn open_invite_on_existing_contact() {
    let relay = Relayed::new();
    let (a, b) = (User::new(&relay.url), User::new(&relay.url));
    relay.join(&a, "anna");
    relay.join(&b, "bert");
    a.add("bert");
    b.b.sync().unwrap();
    let peer = b.b.requests().unwrap()[0].peer.clone();
    let a_at_b = b.b.answer_request(peer, true).unwrap();
    a.b.sync().unwrap();
    assert_eq!(state(&b, "anna"), (false, false, false));

    let code = a.invite();
    let info = open(&b, &code).unwrap();
    assert_eq!(info.code, a.b.me().unwrap().code);
    assert_eq!(b.b.redeem_invite().unwrap(), a_at_b, "the same contact");
    assert_eq!(state(&b, "anna"), (false, true, false));
    assert!(matches!(b.b.redeem_invite(), Err(BrevError::InviteInvalid)));
    assert!(a.b.sync().unwrap().contacts_changed);
    assert_eq!(state(&a, "bert"), (false, true, false));
    assert_eq!(b.b.contacts().unwrap().len(), 1);
    assert_eq!(a.b.contacts().unwrap().len(), 1);

    // A root invite opens, but does not redeem.
    assert!(open(&b, &relay.root_code()).unwrap().root);
    assert!(matches!(b.b.redeem_invite(), Err(BrevError::InviteInvalid)));

    // A is released; A' registers "anna" and invites B.
    assert!(relay.relay.release("anna").unwrap());
    let a2 = User::new(&relay.url);
    relay.join(&a2, "anna");
    let code2 = a2.invite();
    assert!(matches!(open(&b, &code2), Err(BrevError::KeyChanged)));
    let info = b.b.contact_info(a_at_b.clone()).unwrap();
    assert_eq!(info.new_code, a2.b.me().unwrap().code);
    assert!(matches!(b.b.redeem_invite(), Err(BrevError::InviteInvalid)));
    b.b.accept_new_key(a_at_b.clone(), info.new_code).unwrap();
    open(&b, &code2).unwrap();
    assert_eq!(b.b.redeem_invite().unwrap(), a_at_b);
    assert_eq!(state(&b, "anna"), (false, true, false));
    assert!(a2.b.sync().unwrap().contacts_changed);
    assert_eq!(state(&a2, "bert"), (false, true, false));
}

/// Design §8 brev-mail 7: the relay's 429 is `RateLimited` for letters (the
/// letter is forgotten and nothing is stored), requests (nothing is added)
/// and invites.
#[test]
fn rate_limited_maps_to_error() {
    let config = Config {
        letters_per_day: 1,
        requests_per_day: 1,
        invites_per_day: 1,
        ..Config::default()
    };
    let relay = Relayed::configured(Box::new(Open), config);
    let (a, _b, b_at_a, _) = pair(&relay);
    assert!(matches!(a.b.create_invite(), Err(BrevError::RateLimited)));
    assert_eq!(local_rows(&a, "invites"), 0, "nothing kept");

    a.send(&b_at_a, b"s", b"one");
    a.b.prepare_send(b_at_a.clone()).unwrap();
    assert!(matches!(
        sign_and_submit(&a, &b_at_a, b"two"),
        Err(BrevError::RateLimited)
    ));
    assert!(
        matches!(a.b.submit(), Err(BrevError::NotFound)),
        "forgotten"
    );
    assert_eq!(relay.waiting(), 1);
    assert_eq!(a.b.threads(b_at_a).unwrap().len(), 1);

    let [c, d] = [(); 2].map(|()| User::new(&relay.url));
    relay.join(&c, "carl");
    relay.join(&d, "dora");
    a.add("carl");
    assert!(matches!(
        a.b.add_contact(b"dora", 4),
        Err(BrevError::RateLimited)
    ));
    assert_eq!(a.b.contacts().unwrap().len(), 2, "dora not added");
}

/// Design §8 brev-mail 7: the flags and the local invites are sealed with
/// their row in the AD, so rows swapped between contacts or invites do not
/// open (`Crypto`); the file holds no invite secret, no code and no
/// derived relay key.
#[test]
fn flags_and_invites_are_sealed() {
    let relay = Relayed::new();
    let (a, _b, _, _) = pair(&relay);
    let c = User::new(&relay.url);
    relay.join(&c, "carl");
    a.add("carl");
    let codes = [a.invite(), a.invite()];
    let path = a.dir.0.join("brev.db");
    let bytes = fs::read(&path).unwrap();
    for code in &codes {
        let s = secret_of(code);
        assert!(!contains(&bytes, &s), "secret");
        assert!(!contains(&bytes, &invite::relay_key(&s)), "relay key");
        assert!(!contains(&bytes, code), "code");
    }
    assert!(contains(&bytes, &relay.id_of("anna")), "control: own id");

    let raw = rusqlite::Connection::open(&path).unwrap();
    let swap = |table: &str, column: &str| {
        let rows: Vec<(Vec<u8>, Vec<u8>)> = {
            let mut stmt = raw
                .prepare(&format!("SELECT id, {column} FROM {table}"))
                .unwrap();
            let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap();
            rows.collect::<Result<_, _>>().unwrap()
        };
        let set = format!("UPDATE {table} SET {column} = ?1 WHERE id = ?2");
        raw.execute(&set, rusqlite::params![rows[1].1, rows[0].0])
            .unwrap();
        raw.execute(&set, rusqlite::params![rows[0].1, rows[1].0])
            .unwrap();
    };
    swap("contacts", "flags");
    assert!(matches!(a.b.contacts(), Err(BrevError::Crypto)));
    swap("contacts", "flags");
    assert_eq!(a.b.contacts().unwrap().len(), 2, "control: swapped back");
    swap("invites", "body");
    assert!(matches!(a.b.sync(), Err(BrevError::Crypto)));
    swap("invites", "body");
    a.b.sync().unwrap();
}

/// Design §8 brev-mail 7: the requests and the opened invite live only in
/// the session: a lock forgets them, and the next sync fetches the
/// requests again.
#[test]
fn session_invite_and_requests_cleared_on_lock() {
    let relay = Relayed::new();
    let [a, b, c] = [(); 3].map(|()| User::new(&relay.url));
    relay.join(&a, "anna");
    relay.join(&c, "carl");
    c.add("anna");
    assert_eq!(a.b.sync().unwrap().requests, 1);
    let peer = a.b.requests().unwrap()[0].peer.clone();
    open(&b, &relay.root_code()).unwrap();

    for u in [&a, &b] {
        u.b.lock();
        common::unlock_active(&u.b, &u.dek);
    }
    assert!(a.b.requests().unwrap().is_empty());
    assert!(matches!(
        a.b.answer_request(peer, true),
        Err(BrevError::NotFound)
    ));
    assert!(matches!(
        b.b.register_request(b"bert", 4),
        Err(BrevError::InviteInvalid)
    ));
    assert_eq!(a.b.sync().unwrap().requests, 1, "fetched again");
    assert_eq!(a.asking(), [b"carl".to_vec()]);
}

/// *Blokker* (owner answer 6): one call sets the sealed flag and tells the
/// relay. Nothing goes to the blocked contact (no request is made), a
/// letter being sent to it is forgotten, its letters are dropped also when
/// the relay would store them, and the relay refuses its new letters.
#[test]
fn blokker_blocks_sending_and_receiving() {
    let relay = Relayed::new();
    let (a, b, b_at_a, a_at_b) = pair(&relay);
    b.send(&a_at_b, b"s", b"before the block");
    a.b.prepare_send(b_at_a.clone()).unwrap();
    let digest = a.b.sign_request(b_at_a.clone(), b"s", 1, b"x", 1).unwrap();
    a.b.attach_signature(a.key.sign_digest(&digest)).unwrap();

    a.b.block_contact(b_at_a.clone()).unwrap();
    a.b.block_contact(b_at_a.clone()).unwrap();
    assert_eq!(state(&a, "bert"), (false, true, true));
    assert!(
        matches!(a.b.submit(), Err(BrevError::NotFound)),
        "forgotten"
    );
    let requests = relay.requests();
    assert!(matches!(
        a.b.prepare_send(b_at_a.clone()),
        Err(BrevError::NotApproved)
    ));
    assert_eq!(
        relay.requests(),
        requests,
        "no request to a blocked contact"
    );
    assert!(a.b.threads(b_at_a.clone()).unwrap().is_empty());

    // The letter from before the block is dropped and acknowledged.
    assert_eq!(relay.waiting(), 1);
    assert_eq!(a.b.sync().unwrap().letters, 0);
    assert_eq!(relay.waiting(), 0);

    // The relay refuses B's new letters, also with a faked ticket.
    assert!(matches!(
        b.b.prepare_send(a_at_b.clone()),
        Err(BrevError::NotApproved)
    ));
    b.b.force_ticket_for_test(a_at_b.clone()).unwrap();
    assert!(matches!(
        sign_and_submit(&b, &a_at_b, b"after"),
        Err(BrevError::NotApproved)
    ));
    assert_eq!(relay.waiting(), 0);

    // A relay that stores them anyway: A's flag drops them.
    relay.force_link("anna", "bert");
    b.send(&a_at_b, b"s", b"through a lying relay");
    assert_eq!(a.b.sync().unwrap().letters, 0);
    assert_eq!(relay.waiting(), 0);
    assert!(a.b.threads(b_at_a).unwrap().is_empty());
}

/// The deferred WP2 review note: A asks B, then blocks B before B answers.
/// B's approval of the request it fetched finds nothing at the relay, and
/// nothing B does puts an event in A's queue. Control: a peer that was not
/// blocked gets its approval to A.
#[test]
fn a_blocked_peer_cannot_reach_the_blockers_queue() {
    let relay = Relayed::new();
    let [a, b, c] = [(); 3].map(|()| User::new(&relay.url));
    relay.join(&a, "anna");
    relay.join(&b, "bert");
    relay.join(&c, "carl");
    let b_at_a = a.add("bert");
    assert_eq!(b.b.sync().unwrap().requests, 1);
    a.b.block_contact(b_at_a).unwrap();

    let peer = b.b.requests().unwrap()[0].peer.clone();
    let a_at_b = b.b.answer_request(peer, true).unwrap();
    assert_eq!(events_at(&relay, "anna"), 0, "no approved event");
    let synced = a.b.sync().unwrap();
    assert!(!synced.contacts_changed);
    assert_eq!(synced.requests, 0);
    assert_eq!(state(&a, "bert"), (true, false, true));
    assert!(matches!(
        b.b.prepare_send(a_at_b),
        Err(BrevError::NotApproved)
    ));
    assert_eq!(events_at(&relay, "anna"), 0);

    // Control.
    a.add("carl");
    c.b.sync().unwrap();
    let peer = c.b.requests().unwrap()[0].peer.clone();
    c.b.answer_request(peer, true).unwrap();
    assert_eq!(events_at(&relay, "anna"), 1);
    assert!(a.b.sync().unwrap().contacts_changed);
    assert_eq!(state(&a, "carl"), (false, false, false));
}
