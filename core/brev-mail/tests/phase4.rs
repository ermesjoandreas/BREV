//! Phase 4 end to end (docs/PHASE4_DESIGN.md §8, brev-mail tests 1 to 7):
//! `Brev` sessions in temp dirs, the Phase 4 relay in-process on
//! 127.0.0.1:0, P-256 test keys standing in for the Secure Enclave, and the
//! FFI API exactly as the Swift app uses it. Includes both brev-mail
//! definition-of-done tests of CLAUDE.md §5 Phase 4
//! (`registration_needs_no_invite`, `a_stranger_cannot_reach_an_inbox`;
//! the invite tests went with the invites, D-XXXX (no invites)), *Blokker*
//! (owner answer 6), and the
//! deferred WP2 review note: a blocked peer cannot get an event into the
//! blocker's queue; and the WP5 review's: a block the relay missed is told
//! by the next sync, also after a lock.
//!
//! Where a test needs the relay to lie (or a same-user program to edit its
//! file, CLAUDE.md §2), it writes the relay's file through a second
//! connection.

mod common;

use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use brev_core::BrevError;
use brev_relay::{Config, Decision, Endpoint, Open, Policy};
use common::{contains, len32, pair, read, Relayed, User};

/// The sealed flags cell of `contact` in `u`'s store; with `put`, that
/// cell is then written in its place, as a program that can write the
/// container could (CLAUDE.md §2).
fn flags_cell(u: &User, contact: &[u8], put: Option<&[u8]>) -> Vec<u8> {
    let raw = rusqlite::Connection::open(u.dir.0.join("brev.db")).unwrap();
    let cell = raw
        .query_row("SELECT flags FROM contacts WHERE id = ?1", [contact], |r| {
            r.get(0)
        })
        .unwrap();
    if let Some(put) = put {
        raw.execute(
            "UPDATE contacts SET flags = ?1 WHERE id = ?2",
            rusqlite::params![put, contact],
        )
        .unwrap();
    }
    cell
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

/// The one contact of `u` with `address`: (waiting, blocked).
fn state(u: &User, address: &str) -> (bool, bool) {
    let rows = u.b.contacts().unwrap();
    let row = rows
        .iter()
        .find(|c| read(&c.name) == address.as_bytes())
        .unwrap();
    let info = u.b.contact_info(row.id.clone()).unwrap();
    assert_eq!(
        (info.waiting, info.blocked),
        (row.waiting, row.blocked),
        "the row and the header agree"
    );
    (row.waiting, row.blocked)
}

/// The steps of a letter after `prepare_send`, when a ticket exists: the
/// sign request, the two signatures of one Touch ID, submit. A ticket made
/// by the test hook comes with no compose session, so one starts here.
fn sign_and_submit(u: &User, contact: &[u8], body: &[u8]) -> Result<Vec<u8>, BrevError> {
    u.compose();
    let digest = u.sign(contact, b"s", 1, body, len32(body.len()))?;
    u.seal(&digest)?;
    u.b.submit()
}

/// DoD (D-XXXX (no invites), replacing design §8 brev-mail 1 to 3): anyone
/// registers an address with no invite, like ordinary e-mail, and
/// registering approves no one. The new identity has no contact; its
/// request waits at A with no text; no letter to A is made until A
/// approves with one click; then letters go both ways.
#[test]
fn registration_needs_no_invite() {
    let relay = Relayed::new();
    let (a, b) = (User::new(&relay.url), User::new(&relay.url));
    relay.join(&a, "anna");

    let requests = relay.requests();
    let digest = b.b.register_request(b"bert", 4).unwrap();
    assert_eq!(relay.requests(), requests, "no I/O before the signature");
    b.b.register(b.key.sign_digest(&digest), Vec::new())
        .unwrap();
    assert_eq!(relay.requests(), requests + 1, "the registration only");
    assert!(b.b.me().unwrap().registered);
    assert_eq!(read(&b.b.me().unwrap().address), b"bert");
    assert!(b.b.contacts().unwrap().is_empty(), "no one approved");
    assert_eq!(relay.rows("links"), 0);
    assert_eq!(events_at(&relay, "anna"), 0);

    // B asks A: nothing reaches A but the request.
    let a_at_b = b.add("anna");
    assert_eq!(state(&b, "anna"), (true, false));
    assert!(matches!(b.prepare(&a_at_b), Err(BrevError::NotApproved)));
    let synced = a.b.sync().unwrap();
    assert_eq!((synced.letters, synced.requests), (0, 1));
    assert!(a.b.contacts().unwrap().is_empty());

    // One click: B can write, and A can answer.
    let peer = a.b.requests().unwrap().remove(0).peer;
    let b_at_a = a.b.answer_request(peer, true).unwrap();
    assert!(b.b.sync().unwrap().contacts_changed);
    assert_eq!(state(&b, "anna"), (false, false));
    b.send(&a_at_b, b"s", b"first");
    assert_eq!(a.b.sync().unwrap().letters, 1);
    a.send(&b_at_a, b"s", b"reply");
    assert_eq!(b.b.sync().unwrap().letters, 1);
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
    assert_eq!(state(&c, "anna"), (true, false));

    let requests = relay.requests();
    assert!(matches!(c.prepare(&a_at_c), Err(BrevError::NotApproved)));
    assert_eq!(relay.requests(), requests + 1, "the lookup only");
    assert!(matches!(
        c.sign(&a_at_c, b"s", 1, b"x", 1),
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
    assert_eq!(state(&a, "bert"), (true, false));
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
    assert_eq!(state(&b, "anna"), (false, false));
    assert!(b.b.requests().unwrap().is_empty());
    assert!(matches!(
        b.b.answer_request(asked[0].peer.clone(), true),
        Err(BrevError::NotFound)
    ));
    let synced = a.b.sync().unwrap();
    assert!(synced.contacts_changed, "the approval");
    assert_eq!(state(&a, "bert"), (false, false));
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
    assert!(matches!(c.prepare(&b_at_c), Err(BrevError::NotApproved)));
    assert_eq!(state(&c, "bert"), (true, false));
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
    assert_eq!(state(&b, "carl"), (false, false), "C asked B");
    c.send(&b_at_c, b"s", b"unblocked");
    assert_eq!(b.b.sync().unwrap().letters, 1);
    b.send(&c_at_b, b"s", b"reply");
    assert_eq!(c.b.sync().unwrap().letters, 1);

    // A asks B; B adds A while A's request waits in B's session.
    a.add("bert");
    assert_eq!(b.b.sync().unwrap().requests, 1);
    let a_at_b = b.add("anna");
    assert!(b.b.requests().unwrap().is_empty(), "the request is taken");
    assert_eq!(state(&b, "anna"), (false, false));
    assert!(a.b.sync().unwrap().contacts_changed, "the approval");
    assert_eq!(state(&a, "bert"), (false, false));
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
    let [a, c, d] = [(); 3].map(|()| User::new(&relay.url));
    relay.join(&a, "anna");
    relay.join(&c, "carl");
    relay.join(&d, "dora");
    // A request (C) and an approval (D) wait at A.
    c.add("anna");
    a.add("dora");
    d.b.sync().unwrap();
    let peer = d.b.requests().unwrap()[0].peer.clone();
    d.b.answer_request(peer, true).unwrap();
    assert_eq!(events_at(&relay, "anna"), 2);

    lose.store(true, Ordering::SeqCst);
    let first = a.b.sync().unwrap();
    assert!(first.contacts_changed);
    assert_eq!(first.requests, 1);
    assert_eq!(events_at(&relay, "anna"), 2, "every answer was lost");
    let names = |u: &User| -> Vec<Vec<u8>> {
        u.b.contacts()
            .unwrap()
            .iter()
            .map(|c| read(&c.name))
            .collect()
    };
    assert_eq!(names(&a), [b"dora".to_vec()]);
    for _ in 0..2 {
        let again = a.b.sync().unwrap();
        assert!(!again.contacts_changed);
        assert_eq!(again.requests, 1);
        assert_eq!(names(&a), [b"dora".to_vec()]);
    }
    assert_eq!(state(&a, "dora"), (false, false));

    lose.store(false, Ordering::SeqCst);
    assert!(!a.b.sync().unwrap().contacts_changed);
    assert_eq!(events_at(&relay, "anna"), 1, "only C's request waits");
    assert_eq!(names(&a).len(), 1);
    assert_eq!(a.asking(), [b"carl".to_vec()]);
}

/// Design §8 brev-mail 6: B is released and B' asks A
/// under B's address: A's contact shows the key change, no answer goes
/// out, B' cannot write; once A accepts the new code, the next sync
/// approves B', whose letters then arrive. The accepted key keeps none of
/// the old key's flags, also when the old flags cell is written back: it
/// does not open under the new key.
#[test]
fn key_change_through_a_request() {
    let relay = Relayed::new();
    let (a, _b, b_at_a, _) = pair(&relay);
    assert_eq!(state(&a, "bert"), (false, false));
    assert!(relay.relay.release("bert").unwrap());
    let b2 = User::new(&relay.url);
    relay.join(&b2, "bert");
    let a_at_b2 = b2.add("anna");

    let synced = a.b.sync().unwrap();
    assert!(synced.contacts_changed);
    assert_eq!(synced.requests, 0, "a contact's request, not a stranger's");
    assert!(a.b.contacts().unwrap()[0].key_changed);
    assert_eq!(events_at(&relay, "anna"), 1, "not answered");
    assert!(!a.b.sync().unwrap().contacts_changed, "the same again");
    assert!(matches!(b2.prepare(&a_at_b2), Err(BrevError::NotApproved)));

    let new_code = a.b.contact_info(b_at_a.clone()).unwrap().new_code;
    assert_eq!(new_code, b2.b.me().unwrap().code);
    let old = flags_cell(&a, &b_at_a, None);
    a.b.accept_new_key(b_at_a.clone(), new_code).unwrap();
    assert_eq!(state(&a, "bert"), (true, false), "old flags gone");
    let new = flags_cell(&a, &b_at_a, Some(&old));
    assert!(matches!(
        a.b.contact_info(b_at_a.clone()),
        Err(BrevError::Crypto)
    ));
    flags_cell(&a, &b_at_a, Some(&new));
    assert!(a.b.sync().unwrap().contacts_changed);
    assert_eq!(state(&a, "bert"), (false, false));
    assert_eq!(events_at(&relay, "anna"), 0, "answered yes");
    b2.send(&a_at_b2, b"s", b"new key");
    assert_eq!(a.b.sync().unwrap().letters, 1);
}

/// Design §8 brev-mail 7: the relay's 429 is `RateLimited` for letters (the
/// letter is forgotten and nothing is stored) and requests (nothing is
/// added).
#[test]
fn rate_limited_maps_to_error() {
    let config = Config {
        letters_per_day: 1,
        requests_per_day: 1,
        ..Config::default()
    };
    let relay = Relayed::configured(Box::new(Open), config);
    let (a, _b, b_at_a, _) = pair(&relay);

    a.send(&b_at_a, b"s", b"one");
    a.prepare(&b_at_a).unwrap();
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

/// Design §8 brev-mail 7: the flags are sealed with their row in the AD,
/// so flags swapped between contacts do not open (`Crypto`).
#[test]
fn flags_are_sealed() {
    let relay = Relayed::new();
    let (a, _b, _, _) = pair(&relay);
    let c = User::new(&relay.url);
    relay.join(&c, "carl");
    a.add("carl");
    let path = a.dir.0.join("brev.db");
    let bytes = fs::read(&path).unwrap();
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
    a.b.sync().unwrap();
}

/// Design §8 brev-mail 7: the requests live only in the session: a lock
/// forgets them, and the next sync fetches them again.
#[test]
fn session_requests_cleared_on_lock() {
    let relay = Relayed::new();
    let [a, c] = [(); 2].map(|()| User::new(&relay.url));
    relay.join(&a, "anna");
    relay.join(&c, "carl");
    c.add("anna");
    assert_eq!(a.b.sync().unwrap().requests, 1);
    let peer = a.b.requests().unwrap()[0].peer.clone();

    a.b.lock();
    common::unlock_active(&a.b, &a.dek);
    assert!(a.b.requests().unwrap().is_empty());
    assert!(matches!(
        a.b.answer_request(peer, true),
        Err(BrevError::NotFound)
    ));
    assert_eq!(a.b.sync().unwrap().requests, 1, "fetched again");
    assert_eq!(a.asking(), [b"carl".to_vec()]);
}

/// *Blokker* (owner answer 6): one call sets the sealed flag and tells the
/// relay. Nothing goes to the blocked contact (no request is made), a
/// letter or ticket for it is forgotten, a ticket the block did not see is
/// refused at the seal, its letters are dropped also when the relay would
/// store them, and the relay refuses its new letters.
#[test]
fn blokker_blocks_sending_and_receiving() {
    let relay = Relayed::new();
    let (a, b, b_at_a, a_at_b) = pair(&relay);
    b.send(&a_at_b, b"s", b"before the block");
    a.prepare(&b_at_a).unwrap();
    let digest = a.sign(&b_at_a, b"s", 1, b"x", 1).unwrap();
    a.seal(&digest).unwrap();
    // And a ticket for the next letter.
    a.prepare(&b_at_a).unwrap();

    a.b.block_contact(b_at_a.clone()).unwrap();
    a.b.block_contact(b_at_a.clone()).unwrap();
    assert_eq!(state(&a, "bert"), (false, true));
    assert!(
        matches!(a.b.submit(), Err(BrevError::NotFound)),
        "forgotten"
    );
    assert!(
        matches!(a.sign(&b_at_a, b"s", 1, b"x", 1), Err(BrevError::Malformed)),
        "the ticket too"
    );
    // A ticket set after the block (a lookup that was in flight).
    a.b.force_ticket_for_test(b_at_a.clone()).unwrap();
    assert!(matches!(
        sign_and_submit(&a, &b_at_a, b"late"),
        Err(BrevError::NotApproved)
    ));
    let requests = relay.requests();
    assert!(matches!(a.prepare(&b_at_a), Err(BrevError::NotApproved)));
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
    assert!(matches!(b.prepare(&a_at_b), Err(BrevError::NotApproved)));
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

/// *Blokker* through a key change: A blocks B; B is released and B' asks A
/// under B's address. The relay's block was for
/// B, so only A's flag stands: accepting the new key keeps it, the next
/// sync answers no (the relay declines B', no event is left), and B''s
/// letters are refused.
#[test]
fn blokker_holds_through_a_key_change() {
    let relay = Relayed::new();
    let (a, _b, b_at_a, _) = pair(&relay);
    a.b.block_contact(b_at_a.clone()).unwrap();
    assert!(relay.relay.release("bert").unwrap());
    let b2 = User::new(&relay.url);
    relay.join(&b2, "bert");
    let a_at_b2 = b2.add("anna");

    assert!(a.b.sync().unwrap().contacts_changed);
    let new_code = a.b.contact_info(b_at_a.clone()).unwrap().new_code;
    assert_eq!(new_code, b2.b.me().unwrap().code);
    a.b.accept_new_key(b_at_a.clone(), new_code).unwrap();
    assert_eq!(state(&a, "bert"), (true, true), "the block stays");

    a.b.sync().unwrap();
    assert_eq!(state(&a, "bert"), (true, true));
    assert_eq!(events_at(&relay, "anna"), 0, "answered");
    let link: i64 = relay
        .sql()
        .query_row(
            "SELECT state FROM links WHERE owner = ?1 AND peer = ?2",
            [relay.id_of("anna"), relay.id_of("bert")],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(link, 2, "declined");
    assert!(matches!(b2.prepare(&a_at_b2), Err(BrevError::NotApproved)));
    b2.b.force_ticket_for_test(a_at_b2.clone()).unwrap();
    assert!(matches!(
        sign_and_submit(&b2, &a_at_b2, b"blocked"),
        Err(BrevError::NotApproved)
    ));
    assert_eq!(relay.waiting(), 0);
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
    assert_eq!(state(&a, "bert"), (true, true));
    assert!(matches!(b.prepare(&a_at_b), Err(BrevError::NotApproved)));
    assert_eq!(events_at(&relay, "anna"), 0);

    // Control.
    a.add("carl");
    c.b.sync().unwrap();
    let peer = c.b.requests().unwrap()[0].peer.clone();
    c.b.answer_request(peer, true).unwrap();
    assert_eq!(events_at(&relay, "anna"), 1);
    assert!(a.b.sync().unwrap().contacts_changed);
    assert_eq!(state(&a, "carl"), (false, false));
}

/// The WP5 review: a block the relay did not hear of (it was down) is not
/// lost at a lock. The sealed flag holds at once, and the next sync that
/// reaches the relay tells it, after the lock too, and only once. Until
/// then the relay still stores B's letters and A's flag drops them; after
/// it, B's letters are refused.
#[test]
fn a_block_the_relay_missed_is_told_by_the_next_sync() {
    let mut relay = Relayed::new();
    let (a, b, b_at_a, a_at_b) = pair(&relay);
    relay.stop();
    assert!(matches!(
        a.b.block_contact(b_at_a.clone()),
        Err(BrevError::Network)
    ));
    assert!(matches!(a.b.sync(), Err(BrevError::Network)));
    relay.restart();
    assert_eq!(state(&a, "bert"), (false, true), "the flag holds");
    b.send(&a_at_b, b"s", b"the relay was not told");
    assert_eq!(relay.waiting(), 1, "not told: the relay stores it");

    a.b.lock();
    common::unlock_active(&a.b, &a.dek);
    assert_eq!(a.b.sync().unwrap().letters, 0, "the flag drops it");
    assert_eq!(relay.waiting(), 0);
    let link: i64 = relay
        .sql()
        .query_row(
            "SELECT state FROM links WHERE owner = ?1 AND peer = ?2",
            [relay.id_of("anna"), relay.id_of("bert")],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(link, 2, "declined: the sync told the relay");
    assert!(matches!(b.prepare(&a_at_b), Err(BrevError::NotApproved)));
    b.b.force_ticket_for_test(a_at_b.clone()).unwrap();
    assert!(matches!(
        sign_and_submit(&b, &a_at_b, b"after"),
        Err(BrevError::NotApproved)
    ));
    assert_eq!(relay.waiting(), 0);

    // Told once: a later sync asks only for the events and the inbox.
    let before = relay.requests();
    a.b.sync().unwrap();
    assert_eq!(relay.requests() - before, 2);
}
