//! Unit tests of the session: the ones that need the test-build counters,
//! the test panic hook or the session's private state. The Phase 4 relay
//! runs in-process on 127.0.0.1:0 with a policy that counts its calls and
//! checks at each one that the session mutex is free (every endpoint but
//! the unauthenticated invite open).

use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Weak;
use std::thread;
use std::time::Instant;

use brev_proto::sig;
use brev_relay::{parse_listen, Config, Decision, Endpoint, Gates, Policy, Relay, Server};

use super::*;
use crate::test_keys::TestKey;
use crate::{Envelope, MockTransport};

/// A fresh directory with mode 0700 under the system temp dir, removed on
/// drop.
struct Tmp(PathBuf);
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn tmp() -> Tmp {
    let r: [u8; 8] = crypto::random().unwrap();
    let p = std::env::temp_dir().join(format!("brev-ffi-{:016x}", u64::from_le_bytes(r)));
    std::fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
    Tmp(p)
}

/// The idle time of the test sessions: long enough that no timer fires.
const TEST_IDLE: u32 = 3600;

/// A sample of a Mac with nothing wrong: secure input, capture excluded,
/// SIP on, no `sudo`, no agent, no other window.
fn clean() -> Sample {
    Sample {
        secure_input: true,
        sharing_none: true,
        prevents_capture: true,
        csr_config: Some(0),
        processes: Some(names(&["launchd", "Brev", "zsh"])),
        windows: Some(Vec::new()),
    }
}

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|&n| n.to_owned()).collect()
}

/// This process, whose windows are Brev's own.
fn own_pid() -> i32 {
    i32::try_from(std::process::id()).unwrap()
}

/// How Brev is built: every defence by design.
const DESIGN: Design = Design {
    ax_opaque: true,
    pasteboard_off: true,
    input_filter: true,
};

/// Unlocks `b` and confirms it with a clean sample, as the app does once it
/// shows the mail.
fn unlock_active(b: &Brev, dek: &[u8]) {
    b.unlock(dek, TEST_IDLE).unwrap();
    b.confirm_active(clean()).unwrap();
}

/// Opens a compose session with the Secure Enclave key (the test key
/// stands in for it) and an admin user.
fn compose(u: &User) {
    u.b.compose_started(DESIGN, Some(true), KeyOrigin::SecureEnclave)
        .unwrap();
}

/// A compose session, then `prepare_send` with a clean sample.
fn prepare(u: &User, contact: &[u8]) -> Result<(), BrevError> {
    compose(u);
    u.b.prepare_send(contact.to_vec(), clean())
}

/// The one Touch ID of a letter: the test key signs the token digest, then
/// the envelope digest that answers it.
fn seal(u: &User, token_digest: &[u8]) -> Result<(), BrevError> {
    let digest =
        u.b.attach_token_signature(u.key.sign_digest(token_digest))?;
    u.b.attach_signature(u.key.sign_digest(&digest))
}

fn len32(n: usize) -> u32 {
    u32::try_from(n).unwrap()
}

/// At every policy call (every authenticated relay request), counts the
/// call and tries each watched session's mutex from the relay's thread: a
/// session that held it during its own request would be counted in `held`.
#[derive(Default)]
struct Probe {
    watched: Mutex<Vec<Weak<Brev>>>,
    calls: AtomicUsize,
    held: AtomicUsize,
}

impl Probe {
    fn watch(&self, b: &Arc<Brev>) {
        guard(&self.watched).push(Arc::downgrade(b));
    }

    fn check(&self) -> Decision {
        self.calls.fetch_add(1, Ordering::SeqCst);
        for w in guard(&self.watched).iter() {
            if let Some(b) = w.upgrade() {
                if b.s.try_lock().is_err() {
                    self.held.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
        Decision::Allow
    }
}

struct ProbePolicy(Arc<Probe>);

impl Policy for ProbePolicy {
    fn register(&self, _: &str) -> Decision {
        self.0.check()
    }
    fn submit(&self, _: &[u8; 32], _: &[u8; 32], _: usize) -> Decision {
        self.0.check()
    }
    fn request(&self, _: &[u8; 32], _: Endpoint) -> Decision {
        self.0.check()
    }
}

/// The relay in-process on 127.0.0.1:0. Fields drop in order: the server
/// stops before its directory goes.
struct Net {
    server: Server,
    relay: Arc<Relay>,
    probe: Arc<Probe>,
    url: String,
    _tmp: Tmp,
}

fn net() -> Net {
    let tmp = tmp();
    let probe = Arc::new(Probe::default());
    let policy = Box::new(ProbePolicy(Arc::clone(&probe)));
    let path = tmp.0.join("relay.db");
    let relay =
        Arc::new(Relay::open_with(&path, policy, Config::default(), Gates::default()).unwrap());
    let server = Server::start(
        Arc::clone(&relay),
        parse_listen("127.0.0.1:0").unwrap(),
        false,
    )
    .unwrap();
    let url = format!("http://{}", server.addr());
    Net {
        server,
        relay,
        probe,
        url,
        _tmp: tmp,
    }
}

/// A port nobody listens on: for sessions that never reach the relay.
const NO_RELAY: &str = "http://127.0.0.1:9";

struct User {
    b: Arc<Brev>,
    dek: [u8; 32],
    key: TestKey,
    _dir: Tmp,
}

/// A new session for `url`, locked.
fn locked_user(url: &str) -> User {
    let dir = tmp();
    let key = TestKey::new();
    let dek: [u8; 32] = crypto::random().unwrap();
    let b = Brev::create(
        dir.0.to_str().unwrap().into(),
        url.into(),
        &dek,
        &key.public,
    )
    .unwrap();
    User {
        b,
        dek,
        key,
        _dir: dir,
    }
}

/// A new, unlocked session at `net`, watched by its probe.
fn user(net: &Net) -> User {
    let u = locked_user(&net.url);
    unlock_active(&u.b, &u.dek);
    net.probe.watch(&u.b);
    u
}

/// Registers `u` at `address` with the invite `code`: open, request,
/// Touch ID (the test key), register.
fn register_with(u: &User, code: &[u8], address: &str) {
    u.b.open_invite(code, len32(code.len())).unwrap();
    let digest =
        u.b.register_request(address.as_bytes(), len32(address.len()))
            .unwrap();
    u.b.register(u.key.sign_digest(&digest), Vec::new())
        .unwrap();
}

/// Registers `u` at `address` with a fresh root invite.
fn join(net: &Net, u: &User, address: &str) {
    register_with(u, &net.relay.root_invite().unwrap(), address);
}

/// The local id of `u`'s contact at `address`.
fn contact(u: &User, address: &str) -> Vec<u8> {
    let rows = u.b.contacts().unwrap();
    rows.iter()
        .find(|c| {
            let n = c.name.byte_len() as usize;
            c.name.chunk(0).is_ok_and(|b| &b[..n] == address.as_bytes())
        })
        .map(|c| c.id.clone())
        .unwrap()
}

/// A new user registered at `address` with `inviter`'s invite, and the
/// inviter's sync that pins it: (the user, its id at the inviter, the
/// inviter's id at it).
fn invitee(net: &Net, inviter: &User, at: &str, address: &str) -> (User, Vec<u8>, Vec<u8>) {
    let u = user(net);
    register_with(&u, &inviter.b.create_invite().unwrap(), address);
    inviter.b.sync().unwrap();
    let (theirs, mine) = (contact(inviter, address), contact(&u, at));
    (u, theirs, mine)
}

fn add(u: &User, address: &str) -> Vec<u8> {
    u.b.add_contact(address.as_bytes(), len32(address.len()))
        .unwrap()
}

/// The steps of a letter, as the app makes them: compose, prepare, the
/// sign request, the two signatures of one Touch ID, submit.
fn send(u: &User, contact: &[u8], subject: &[u8], body: &[u8]) -> Vec<u8> {
    prepare(u, contact).unwrap();
    let digest =
        u.b.sign_request(
            contact.to_vec(),
            subject,
            len32(subject.len()),
            body,
            len32(body.len()),
            clean(),
        )
        .unwrap();
    seal(u, &digest).unwrap();
    u.b.submit().unwrap()
}

/// A ("anna", by a root invite) and B ("bert", by A's invite), each
/// other's contact: (a, b, b at a, a at b).
fn pair(net: &Net) -> (User, User, Vec<u8>, Vec<u8>) {
    let a = user(net);
    join(net, &a, "anna");
    let (b, b_at_a, a_at_b) = invitee(net, &a, "anna", "bert");
    (a, b, b_at_a, a_at_b)
}

fn sign_request(u: &User, contact: &[u8]) -> Result<Vec<u8>, BrevError> {
    u.b.sign_request(contact.to_vec(), b"s", 1, b"body", 4, clean())
}

#[test]
fn locked_session_refuses_every_export() {
    let net = net();
    let (a, _b, b_at_a, _) = pair(&net);
    let thread = send(&a, &b_at_a, b"s", b"b");
    let msg = a.b.messages(thread.clone()).unwrap()[0].id.clone();
    prepare(&a, &b_at_a).unwrap();
    let code = net.relay.root_invite().unwrap();
    let requests = net.server.requests();
    a.b.lock();
    assert!(a.b.is_locked());
    let locked = |r: Result<(), BrevError>| assert!(matches!(r, Err(BrevError::Locked)));
    locked(a.b.contacts().map(drop));
    locked(a.b.threads(b_at_a.clone()).map(drop));
    locked(a.b.messages(thread).map(drop));
    locked(a.b.open_body(msg.clone()).map(drop));
    locked(a.b.me().map(drop));
    locked(a.b.contact_info(b_at_a.clone()).map(drop));
    locked(a.b.accept_new_key(b_at_a.clone(), vec![b'A'; 35]));
    locked(a.b.register_request(b"carl", 4).map(drop));
    locked(a.b.register(vec![0x30], Vec::new()));
    locked(a.b.add_contact(b"carl", 4).map(drop));
    locked(a.b.observe(clean()).map(drop));
    locked(a.b.compose_started(DESIGN, Some(true), KeyOrigin::SecureEnclave));
    locked(a.b.compose_closed());
    locked(a.b.synthetic_dropped());
    locked(a.b.paste_accepted());
    locked(a.b.prepare_send(b_at_a.clone(), clean()));
    locked(sign_request(&a, &b_at_a).map(drop));
    locked(a.b.attach_token_signature(vec![0x30]).map(drop));
    locked(a.b.attach_signature(vec![0x30]));
    locked(a.b.letter_proof(msg).map(drop));
    locked(a.b.submit().map(drop));
    locked(a.b.sync().map(drop));
    locked(a.b.create_invite().map(drop));
    locked(a.b.open_invite(&code, len32(code.len())).map(drop));
    locked(a.b.redeem_invite().map(drop));
    locked(a.b.requests().map(drop));
    locked(a.b.answer_request(vec![0; 32], true).map(drop));
    locked(a.b.block_contact(b_at_a.clone()));
    a.b.cancel_send();
    assert!(a.b.is_locked());
    assert_eq!(net.server.requests(), requests, "no request while locked");
}

#[test]
fn panic_in_unlock_locks_all_scrubs_and_poison_returns_locked() {
    let u = locked_user(NO_RELAY);
    let b = &u.b;
    let dek = u.dek;
    let is_locked = || guard(&b.s).me.is_locked();
    // Panics after the core unlocked: the drop guard locks and scrubs
    // while unwinding, and the mutex is poisoned.
    let panic_in_unlock = || {
        let deep = crypto::deep_scrubs();
        PANIC_IN_UNLOCK.with(|p| p.set(true));
        let r = catch_unwind(AssertUnwindSafe(|| b.unlock(&dek, TEST_IDLE)));
        PANIC_IN_UNLOCK.with(|p| p.set(false));
        assert!(r.is_err(), "the test panic must propagate");
        assert_eq!(crypto::deep_scrubs(), deep + 1, "scrubbed while unwinding");
        assert!(b.s.is_poisoned());
        assert!(is_locked());
    };

    // A content call on the poisoned session: `Locked`, poison cleared.
    panic_in_unlock();
    assert!(matches!(b.contacts(), Err(BrevError::Locked)));
    assert!(!b.s.is_poisoned());
    assert!(is_locked());

    // `unlock` on the poisoned session: `Locked`, and it still scrubs.
    panic_in_unlock();
    let deep = crypto::deep_scrubs();
    assert!(matches!(b.unlock(&dek, TEST_IDLE), Err(BrevError::Locked)));
    assert_eq!(crypto::deep_scrubs(), deep + 1);
    assert!(!b.s.is_poisoned());
    assert!(is_locked());

    // `is_locked` on the poisoned session: true, poison cleared.
    panic_in_unlock();
    assert!(b.is_locked());
    assert!(!b.s.is_poisoned());
    assert!(is_locked());

    // `lock` on the poisoned session never fails and clears the poison,
    // so the unlock right after it (the app's retry) succeeds.
    panic_in_unlock();
    b.lock();
    assert!(!b.s.is_poisoned());
    assert!(is_locked());
    unlock_active(b, &dek);
    assert!(!b.is_locked());
    assert!(b.contacts().unwrap().is_empty());
}

#[test]
fn poison_while_unlocked_locks_all_on_next_call() {
    let net = net();
    let (a, _b, _, _) = pair(&net);
    let name = Arc::clone(&a.b.contacts().unwrap()[0].name);
    prepare(&a, &a.b.contacts().unwrap()[0].id).unwrap();
    // A panic in a content method while unlocked: the DEK is loaded and no
    // drop guard has locked anything.
    let r = catch_unwind(AssertUnwindSafe(|| {
        let _s = a.b.s.lock().unwrap();
        panic!("test panic while unlocked");
    }));
    assert!(r.is_err());
    assert!(a.b.s.is_poisoned());
    // Positive control.
    assert!(!guard(&a.b.s).me.is_locked());
    assert!(name.byte_len() > 0);

    assert!(matches!(a.b.contacts(), Err(BrevError::Locked)));
    assert!(!a.b.s.is_poisoned());
    let s = guard(&a.b.s);
    assert!(s.me.is_locked() && s.ticket.is_none() && s.compose.is_none());
    drop(s);
    assert_eq!(name.byte_len(), 0);
    assert_eq!(crypto::live_plaintexts(), 0);
}

#[test]
fn drop_closes_every_open_text() {
    let net = net();
    let u = user(&net);
    join(&net, &u, "anna");
    let address = u.b.me().unwrap().address;
    assert!(address.byte_len() > 0, "positive control");
    drop(u);
    assert_eq!(address.byte_len(), 0);
    assert!(matches!(address.chunk(0), Err(BrevError::Locked)));
    assert_eq!(crypto::live_plaintexts(), 0);
}

#[test]
fn unlock_scrubs_deep_on_every_path() {
    let u = locked_user(NO_RELAY);
    let b = &u.b;
    for bad in [
        &[0u8; 31][..],
        &[0u8; 33][..],
        &[0u8; 32][..],
        &[7u8; 32][..],
    ] {
        let n = crypto::deep_scrubs();
        assert!(matches!(b.unlock(bad, TEST_IDLE), Err(BrevError::WrongKey)));
        assert_eq!(crypto::deep_scrubs(), n + 1);
        assert!(b.is_locked());
    }
    let n = crypto::deep_scrubs();
    unlock_active(b, &u.dek);
    assert_eq!(crypto::deep_scrubs(), n + 1);
    assert!(!b.is_locked());
    let n = crypto::deep_scrubs();
    assert!(matches!(
        b.unlock(&[7u8; 32], TEST_IDLE),
        Err(BrevError::WrongKey)
    ));
    assert_eq!(crypto::deep_scrubs(), n + 1);
    assert!(b.is_locked(), "a wrong DEK on an unlocked session locks it");
}

/// `create` ends with one stack scrub after `create_in` returns
/// (`create_in`'s own count is the same for the same inputs), so deleting
/// it fails here.
#[test]
fn create_scrubs_the_stack_after_create_in() {
    fn scrubs_in(f: impl FnOnce()) -> usize {
        let before = crypto::scrubs();
        f();
        crypto::scrubs() - before
    }
    let (t1, t2) = (tmp(), tmp());
    let key = TestKey::new();
    let dek: [u8; 32] = crypto::random().unwrap();
    let inner = scrubs_in(|| drop(Brev::create_in(&t1.0, NO_RELAY, &dek, &key.public).unwrap()));
    let outer = scrubs_in(|| {
        drop(
            Brev::create(
                t2.0.to_str().unwrap().into(),
                NO_RELAY.into(),
                &dek,
                &key.public,
            )
            .unwrap(),
        )
    });
    assert!(inner > 0, "positive control: create_in scrubs");
    assert_eq!(outer, inner + 1);
}

/// Item 7 of Phase 2's test list, with Phase 3's texts: contact names
/// (addresses), the own address, a subject and a body.
#[test]
fn lock_closes_every_open_text() {
    let net = net();
    let (a, _b, b_at_a, _) = pair(&net);
    let thread = send(&a, &b_at_a, b"subject", b"body");
    let contacts = a.b.contacts().unwrap();
    let threads = a.b.threads(b_at_a.clone()).unwrap();
    assert_eq!(threads[0].id, thread);
    let msg = a.b.messages(thread).unwrap()[0].id.clone();
    let body = a.b.open_body(msg).unwrap();
    let me = a.b.me().unwrap();
    let info = a.b.contact_info(b_at_a).unwrap();
    let mut kept: Vec<Arc<OpenText>> = contacts.iter().map(|c| Arc::clone(&c.name)).collect();
    kept.push(Arc::clone(&threads[0].subject));
    kept.push(body);
    kept.push(me.address);
    kept.push(info.address);
    drop((contacts, threads));
    // Positive control: the kept handles hold live plaintext.
    assert_eq!(crypto::live_plaintexts(), 5);
    assert!(kept.iter().all(|t| t.byte_len() > 0 && t.chunk(0).is_ok()));

    a.b.lock();
    assert_eq!(crypto::live_plaintexts(), 0);
    for t in &kept {
        assert_eq!(t.byte_len(), 0);
        assert!(matches!(t.chunk(0), Err(BrevError::Locked)));
        t.close(); // idempotent
    }
    assert!(guard(&a.b.s).me.open_texts_for_test().is_empty());
}

/// `sign_request` needs the ticket of a `prepare_send` for that contact,
/// made since the last one was used, cancelled or locked away.
#[test]
fn sign_request_needs_a_fresh_prepare() {
    let net = net();
    let (a, _b, b_at_a, _) = pair(&net);
    let (_c, c_at_a, _) = invitee(&net, &a, "anna", "carl");
    let malformed = |r: Result<Vec<u8>, BrevError>| assert!(matches!(r, Err(BrevError::Malformed)));

    // None yet.
    malformed(sign_request(&a, &b_at_a));
    // For another contact: refused, and the ticket is used up.
    prepare(&a, &c_at_a).unwrap();
    malformed(sign_request(&a, &b_at_a));
    malformed(sign_request(&a, &c_at_a));
    // Used once.
    prepare(&a, &b_at_a).unwrap();
    sign_request(&a, &b_at_a).unwrap();
    malformed(sign_request(&a, &b_at_a));
    // A bad length does not use it; a good call then does.
    prepare(&a, &b_at_a).unwrap();
    assert!(matches!(
        a.b.sign_request(b_at_a.clone(), b"s", 2, b"b", 1, clean()),
        Err(BrevError::Malformed)
    ));
    sign_request(&a, &b_at_a).unwrap();
    // `lock` and `cancel_send` clear it.
    prepare(&a, &b_at_a).unwrap();
    a.b.lock();
    unlock_active(&a.b, &a.dek);
    compose(&a);
    malformed(sign_request(&a, &b_at_a));
    prepare(&a, &b_at_a).unwrap();
    a.b.cancel_send();
    malformed(sign_request(&a, &b_at_a));
    // A failed prepare clears the one before it.
    prepare(&a, &b_at_a).unwrap();
    assert!(matches!(
        a.b.prepare_send(vec![7; 16], clean()),
        Err(BrevError::NotFound)
    ));
    malformed(sign_request(&a, &b_at_a));
    assert!(a.b.threads(b_at_a).unwrap().is_empty(), "nothing stored");
    assert_eq!(net.relay.waiting().unwrap(), 0, "nothing sent");
}

/// The calls that take content (`sign_request`) or a typed address for
/// signing (`register_request`) make no request; neither do the other
/// local calls.
#[test]
fn sign_request_and_register_request_make_no_request() {
    let net = net();
    let (a, _b, b_at_a, _) = pair(&net);
    let fresh = user(&net);
    let code = net.relay.root_invite().unwrap();
    fresh.b.open_invite(&code, len32(code.len())).unwrap();
    prepare(&a, &b_at_a).unwrap();
    let before = net.server.requests();
    let digest = sign_request(&a, &b_at_a).unwrap();
    seal(&a, &digest).unwrap();
    a.b.cancel_send();
    let digest = fresh.b.register_request(b"Carl", 4).unwrap();
    assert_eq!(digest.len(), 32);
    drop((
        a.b.me().unwrap(),
        a.b.contacts().unwrap(),
        a.b.contact_info(b_at_a.clone()).unwrap(),
        a.b.threads(b_at_a.clone()).unwrap(),
        a.b.requests().unwrap(),
    ));
    assert!(a.b.accept_new_key(b_at_a, vec![b'A'; 35]).is_err());
    assert_eq!(net.server.requests(), before);
    // Control: the relay counts a request.
    fresh
        .b
        .register(fresh.key.sign_digest(&digest), Vec::new())
        .unwrap();
    assert_eq!(net.server.requests(), before + 1);
    // The typed address was folded to lower case.
    let me = fresh.b.me().unwrap();
    assert!(me.registered);
    assert_eq!(&me.address.chunk(0).unwrap()[..5], b"carl\0");
}

/// `lock` and `cancel_send` forget the letter at every step: its plaintext
/// while its token is signed (wiped: the live counter drops to 0), and the
/// sealed letter, signed or not. Nothing is attached, submitted or stored
/// afterwards.
#[test]
fn lock_and_cancel_clear_the_pending_letter() {
    let net = net();
    let (a, _b, b_at_a, _) = pair(&net);
    let not_found = |r: Result<(), BrevError>| assert!(matches!(r, Err(BrevError::NotFound)));
    let token_digest = |a: &User| {
        prepare(a, &b_at_a).unwrap();
        sign_request(a, &b_at_a).unwrap()
    };
    let cancel_or_lock = |a: &User, lock: bool| {
        if lock {
            a.b.lock();
            unlock_active(&a.b, &a.dek);
        } else {
            a.b.cancel_send();
        }
    };

    // Nothing to attach or submit yet.
    not_found(a.b.attach_token_signature(vec![0x30]).map(drop));
    not_found(a.b.attach_signature(vec![0x30]));
    not_found(a.b.submit().map(drop));
    // A letter waiting for its token signature: no envelope to sign or
    // submit yet.
    let d = token_digest(&a);
    not_found(a.b.attach_signature(a.key.sign_digest(&d)));
    not_found(a.b.submit().map(drop));
    a.b.cancel_send();
    // Waiting for its token signature (the plaintext), then cancelled or
    // locked: wiped.
    for lock in [false, true] {
        let d = token_digest(&a);
        assert!(guard(&a.b.s).pending.is_some());
        assert_eq!(crypto::live_plaintexts(), 1, "the letter's plaintext");
        cancel_or_lock(&a, lock);
        assert_eq!(crypto::live_plaintexts(), 0, "lock {lock}");
        assert!(guard(&a.b.s).pending.is_none());
        not_found(a.b.attach_token_signature(a.key.sign_digest(&d)).map(drop));
    }
    // The token signed (sealed, the plaintext wiped), before the envelope
    // signature; and signed, before the submit. Then cancelled or locked.
    for (signed, lock) in [(false, false), (false, true), (true, false), (true, true)] {
        let d = token_digest(&a);
        let e = a.b.attach_token_signature(a.key.sign_digest(&d)).unwrap();
        assert_eq!(crypto::live_plaintexts(), 0, "sealed: ciphertext only");
        if signed {
            a.b.attach_signature(a.key.sign_digest(&e)).unwrap();
            assert!(guard(&a.b.s).letter.as_ref().unwrap().is_signed());
        }
        cancel_or_lock(&a, lock);
        assert!(guard(&a.b.s).letter.is_none());
        not_found(a.b.attach_signature(a.key.sign_digest(&e)));
        not_found(a.b.submit().map(drop));
    }
    // A foreign envelope signature clears it too.
    let d = token_digest(&a);
    a.b.attach_token_signature(a.key.sign_digest(&d)).unwrap();
    assert!(matches!(
        a.b.attach_signature(TestKey::new().sign_digest(&[0; 32])),
        Err(BrevError::Signing)
    ));
    not_found(a.b.submit().map(drop));
    assert!(a.b.threads(b_at_a.clone()).unwrap().is_empty());
    assert_eq!(net.relay.waiting().unwrap(), 0);
    // Control: the same steps without a lock send the letter.
    let d = token_digest(&a);
    seal(&a, &d).unwrap();
    a.b.submit().unwrap();
    assert_eq!(net.relay.waiting().unwrap(), 1);
    assert_eq!(a.b.threads(b_at_a).unwrap().len(), 1);
}

/// No decrypted value and no X25519 secret is alive in the core at any
/// request: counted on this thread right before each one is sent, and
/// matched with the relay's own request count.
#[test]
fn nothing_decrypted_is_alive_on_the_network() {
    let net = net();
    let before = net.server.requests();
    crate::relay::live_at_requests();
    let (a, b, b_at_a, _) = pair(&net);
    send(&a, &b_at_a, b"subject", b"body");
    assert_eq!(b.b.sync().unwrap().letters, 1);
    assert_eq!(b.b.sync().unwrap().letters, 0);
    // A registration that is refused, a lookup of nobody.
    let digest = b.b.register_request(b"anna", 4);
    assert!(matches!(digest, Err(BrevError::Duplicate)));
    assert!(matches!(
        a.b.add_contact(b"nobody", 6),
        Err(BrevError::NotFound)
    ));
    let at = crate::relay::live_at_requests();
    // The pair: open and register ×2, the invite, A's events, its answer
    // and poll (5 + 3); the letter: lookup and submit (2); B's two syncs:
    // events, poll, ack, then events and poll (5); the failed lookup (1).
    assert_eq!(at.len(), 16);
    assert_eq!(net.server.requests() - before, 16);
    assert!(at.iter().all(|&live| live == (0, 0)), "{at:?}");
    // Control: the counter sees a text the app holds open.
    let kept = a.b.contacts().unwrap();
    assert!(matches!(a.b.sync(), Ok(r) if r.letters == 0));
    assert_eq!(crate::relay::live_at_requests(), [(1, 0), (1, 0)]);
    drop(kept);
}

/// Design §8 brev-mail 7: the Phase 4 calls, none of which carries
/// content, make their requests with nothing decrypted alive: an invite
/// made, opened and redeemed, a contact request and its answer, the events
/// and their answers, and *Blokker*.
#[test]
fn invite_calls_carry_no_content() {
    let net = net();
    let (a, _b, _, _) = pair(&net);
    let c = user(&net);
    join(&net, &c, "carl");
    crate::relay::live_at_requests();
    let before = net.server.requests();
    // A request, the events that carry it, and its approval.
    add(&c, "anna");
    a.b.sync().unwrap();
    let peer = a.b.requests().unwrap()[0].peer.clone();
    a.b.answer_request(peer, true).unwrap();
    // C's invite, opened and redeemed by A (already C's contact).
    let code = c.b.create_invite().unwrap();
    a.b.open_invite(&code, len32(code.len())).unwrap();
    a.b.redeem_invite().unwrap();
    // C's sync: the approved and invited events, seen.
    c.b.sync().unwrap();
    a.b.block_contact(contact(&a, "carl")).unwrap();
    let at = crate::relay::live_at_requests();
    // add: lookup, request (2); A's sync: events, poll (2); the answer (1);
    // the invite: create, open, redeem (3); C's sync: events, one answer
    // (the invited event supersedes the approval), poll (3); block (1).
    assert_eq!(at.len(), 12);
    assert_eq!(net.server.requests() - before, 12);
    assert!(at.iter().all(|&live| live == (0, 0)), "{at:?}");
}

/// Every request is made with the session mutex released (design §5.2):
/// the relay's policy tries each session's mutex during each request that
/// it is asked about (all but the unauthenticated invite open).
#[test]
fn no_network_under_the_session_mutex() {
    let net = net();
    let (a, b, b_at_a, _) = pair(&net);
    send(&a, &b_at_a, b"s", b"x");
    b.b.sync().unwrap();
    // The Phase 4 calls: a request and its answer, an invite redeemed, a
    // block.
    let c = user(&net);
    join(&net, &c, "carl");
    add(&c, "anna");
    a.b.sync().unwrap();
    let peer = a.b.requests().unwrap()[0].peer.clone();
    a.b.answer_request(peer, true).unwrap();
    let code = c.b.create_invite().unwrap();
    a.b.open_invite(&code, len32(code.len())).unwrap();
    a.b.redeem_invite().unwrap();
    a.b.block_contact(contact(&a, "carl")).unwrap();
    let calls = net.probe.calls.load(Ordering::SeqCst);
    // The pair: register ×2, invite create, A's events, answer, inbox (6);
    // the letter: lookup, submit (2); B's sync: events, inbox, ack (3);
    // C: register, lookup, request (3); A's sync: events, inbox (2); the
    // answer (1); C's invite create, A's redeem (2); the block (1).
    assert_eq!(calls, 20);
    assert_eq!(net.probe.held.load(Ordering::SeqCst), 0);
    // Control: a request made while the mutex is held is seen.
    let (caller, token) = guard(&a.b.s).credentials().unwrap();
    let held = guard(&a.b.s);
    a.b.net.lookup(&caller, &token, b"bert").unwrap();
    drop(held);
    assert_eq!(net.probe.held.load(Ordering::SeqCst), 1);
}

/// A sync whose poll or ack cannot be answered: `Network` from the poll;
/// letters that arrived are counted even if their ack fails, and come
/// again as duplicates that are acknowledged then.
#[test]
fn sync_counts_arrivals_when_the_ack_fails() {
    struct AckFails(MockTransport);
    impl Transport for AckFails {
        fn send(&self, e: &Envelope) -> Result<(), NetError> {
            self.0.send(e)
        }
        fn poll(&self) -> Result<Vec<(u64, Envelope)>, NetError> {
            self.0.poll()
        }
        fn ack(&self, _: &[[u8; 32]]) -> Result<(), NetError> {
            Err(NetError::Network)
        }
    }
    let net = net();
    let (a, b, b_at_a, _) = pair(&net);
    send(&a, &b_at_a, b"s", b"x");
    let (caller, token) = guard(&b.b.s).credentials().unwrap();
    let envelopes = b.b.net.inbox(&caller, &token).unwrap();
    let (to_b, at_b) = MockTransport::pair();
    for (_, e) in &envelopes {
        to_b.send(e).unwrap();
    }
    let epoch = guard(&b.b.s).epoch;
    let failing = AckFails(at_b);
    assert_eq!(b.b.sync_via(&failing, epoch).unwrap(), 1);
    // Again: a duplicate, nothing arrived, so the failed ack is reported.
    assert!(matches!(
        b.b.sync_via(&failing, epoch),
        Err(BrevError::Network)
    ));
    let AckFails(at_b) = failing;
    assert_eq!(b.b.sync_via(&at_b, epoch).unwrap(), 0);
    assert!(at_b.poll().unwrap().is_empty(), "the duplicate is acked");
    // A stale epoch (a lock and unlock in between) stores nothing.
    to_b.send(&envelopes[0].1).unwrap();
    assert!(matches!(
        b.b.sync_via(&at_b, epoch.wrapping_sub(1)),
        Err(BrevError::Locked)
    ));
    assert_eq!(at_b.poll().unwrap().len(), 1, "not acked");
}

/// Waits up to 5 s for `t` to be closed (`Locked`; an open empty text is
/// `Malformed`), without touching the session. The time it took.
fn wait_closed(t: &OpenText) -> Duration {
    let start = Instant::now();
    while !matches!(t.chunk(0), Err(BrevError::Locked)) && start.elapsed() < Duration::from_secs(5)
    {
        thread::sleep(Duration::from_millis(20));
    }
    start.elapsed()
}

/// `unlock` arms: nothing opens until `confirm_active`. The idle time must
/// be 1 to 3600 s.
#[test]
fn unlock_is_armed_until_confirmed() {
    let u = locked_user(NO_RELAY);
    let b = &u.b;
    assert!(
        matches!(b.confirm_active(clean()), Err(BrevError::Locked)),
        "nothing to confirm"
    );
    b.unlock(&u.dek, TEST_IDLE).unwrap();
    assert!(b.is_locked());
    assert!(matches!(b.contacts(), Err(BrevError::Locked)));
    assert!(matches!(b.me().map(drop), Err(BrevError::Locked)));
    b.confirm_active(clean()).unwrap();
    assert!(!b.is_locked());
    assert!(b.contacts().unwrap().is_empty());
    b.confirm_active(clean()).unwrap();
    assert!(!b.is_locked(), "idempotent while open");
    for idle in [0, MAX_IDLE_SECS + 1, u32::MAX] {
        assert!(matches!(b.unlock(&u.dek, idle), Err(BrevError::Malformed)));
        assert!(b.is_locked());
    }
    b.note_activity();
    assert!(b.is_locked(), "activity opens nothing");
}

/// No confirm within 2 s: the timer wipes everything (texts, the ticket,
/// the epoch), and a confirm after that is `Locked`.
#[test]
fn an_unconfirmed_unlock_is_wiped_after_2_s() {
    let net = net();
    let (a, _b, b_at_a, _) = pair(&net);
    let kept = Arc::clone(&a.b.contacts().unwrap()[0].name);
    prepare(&a, &b_at_a).unwrap();
    // Unlocking an open session arms it again, texts and all.
    a.b.unlock(&a.dek, TEST_IDLE).unwrap();
    let epoch = guard(&a.b.s).epoch;
    assert!(kept.byte_len() > 0, "control: the text is open");
    let took = wait_closed(&kept);
    assert!(
        took >= Duration::from_millis(1500),
        "not before the window: {took:?}"
    );
    assert_eq!(kept.byte_len(), 0, "the timer closed the text");
    {
        let s = guard(&a.b.s);
        assert!(s.me.is_locked() && s.ticket.is_none() && s.epoch != epoch);
        assert!(s.compose.is_none(), "the compose session is gone too");
    }
    assert!(matches!(
        a.b.confirm_active(clean()),
        Err(BrevError::Locked)
    ));
    assert!(a.b.is_locked());
}

/// Idle for `idle_secs`: the timer wipes. `note_activity` moves the
/// deadline.
#[test]
fn idle_wipes_and_activity_postpones_it() {
    let u = locked_user(NO_RELAY);
    let b = &u.b;
    b.unlock(&u.dek, 2).unwrap();
    b.confirm_active(clean()).unwrap();
    // The empty own address: `Malformed` while open, `Locked` once closed.
    let kept = b.me().unwrap().address;
    assert!(matches!(kept.chunk(0), Err(BrevError::Malformed)));
    thread::sleep(Duration::from_millis(1200));
    b.note_activity();
    let noted = Instant::now();
    thread::sleep(Duration::from_millis(1200));
    assert!(!guard(&b.s).me.is_locked(), "open 2.4 s after the confirm");
    wait_closed(&kept);
    let idle = noted.elapsed();
    assert!(
        idle >= Duration::from_millis(1900) && idle < Duration::from_millis(4000),
        "{idle:?}"
    );
    assert!(matches!(kept.chunk(0), Err(BrevError::Locked)));
    assert!(guard(&b.s).me.is_locked());
    assert!(b.is_locked());
}

/// A deadline that passes while the session mutex is held (critic 8a):
/// whoever takes the mutex next, an `unlock` or the timer, wipes first, so
/// the epoch moves and a `sync` that was on the network stores nothing.
#[test]
fn a_passed_deadline_moves_the_epoch_before_anything_runs() {
    let net = net();
    let (a, b, b_at_a, a_at_b) = pair(&net);
    send(&a, &b_at_a, b"s", b"x");
    let (caller, token) = guard(&b.b.s).credentials().unwrap();
    let envelopes = b.b.net.inbox(&caller, &token).unwrap();
    let (to_b, at_b) = MockTransport::pair();
    for (_, e) in &envelopes {
        to_b.send(e).unwrap();
    }
    b.b.unlock(&b.dek, 1).unwrap();
    b.b.confirm_active(clean()).unwrap();
    // The epoch of a `sync` whose poll is under way.
    let epoch = guard(&b.b.s).epoch;
    let held = guard(&b.b.s);
    thread::sleep(Duration::from_millis(1300));
    drop(held);
    unlock_active(&b.b, &b.dek);
    assert_ne!(guard(&b.b.s).epoch, epoch);
    assert!(matches!(b.b.sync_via(&at_b, epoch), Err(BrevError::Locked)));
    assert!(b.b.threads(a_at_b).unwrap().is_empty(), "nothing stored");
    assert_eq!(at_b.poll().unwrap().len(), 1, "nothing acknowledged");
}

/// One open session per folder: a second open is `Busy`; a dropped session
/// frees the folder at once (its timer is joined), every time.
#[test]
fn one_session_per_folder_and_drop_frees_it() {
    let u = locked_user(NO_RELAY);
    let dir = u._dir.0.to_str().unwrap().to_owned();
    let dek = u.dek;
    assert!(matches!(
        Brev::open(dir.clone(), NO_RELAY.into()).map(drop),
        Err(BrevError::Busy)
    ));
    let key = TestKey::new();
    assert!(matches!(
        Brev::create(dir.clone(), NO_RELAY.into(), &dek, &key.public).map(drop),
        Err(BrevError::Busy)
    ));
    drop(u.b);
    for i in 0..100 {
        let b = Brev::open(dir.clone(), NO_RELAY.into()).unwrap();
        if i % 2 == 0 {
            unlock_active(&b, &dek);
        } else {
            b.unlock(&dek, TEST_IDLE).unwrap();
        }
        drop(b);
    }
}

/// The folder must be 0700 and `brev.db` 0600: `Unsafe` otherwise, and
/// `create` makes no file.
#[test]
fn folder_and_file_modes_are_checked() {
    let dir = tmp();
    let arg = dir.0.to_str().unwrap().to_owned();
    let path = MAIL.path_in(&dir.0);
    let key = TestKey::new();
    let dek: [u8; 32] = crypto::random().unwrap();
    let chmod = |p: &Path, mode: u32| {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap()
    };
    chmod(&dir.0, 0o755);
    assert!(matches!(
        Brev::create(arg.clone(), NO_RELAY.into(), &dek, &key.public).map(drop),
        Err(BrevError::Unsafe)
    ));
    assert!(!path.exists());
    chmod(&dir.0, 0o700);
    drop(Brev::create(arg.clone(), NO_RELAY.into(), &dek, &key.public).unwrap());
    chmod(&dir.0, 0o755);
    assert!(matches!(
        Brev::open(arg.clone(), NO_RELAY.into()).map(drop),
        Err(BrevError::Unsafe)
    ));
    chmod(&dir.0, 0o700);
    chmod(&path, 0o644);
    assert!(matches!(
        Brev::open(arg.clone(), NO_RELAY.into()).map(drop),
        Err(BrevError::Unsafe)
    ));
    chmod(&path, 0o600);
    unlock_active(&Brev::open(arg, NO_RELAY.into()).unwrap(), &dek);
}

/// A letter needs every requirement (docs/AUTHORSHIP.md §3.3, §4.1): facts
/// that miss one, a software or unknown key (a release build refuses it),
/// or no compose session give `Environment` with the requirements not met,
/// before any request, and leave no ticket. Facts that meet them all send.
#[cfg(not(feature = "allow-software-keys"))]
#[test]
fn prepare_send_needs_every_requirement() {
    assert_eq!(KEY_RULE, brev_hand::Rule::All);
    let net = net();
    let (a, _b, b_at_a, _) = pair(&net);
    let missing = Sample {
        secure_input: false,
        prevents_capture: false,
        ..clean()
    };
    let before = net.server.requests();
    for (key, sample, want) in [
        (
            Some(KeyOrigin::SecureEnclave),
            missing.clone(),
            vec!["capture-off", "secure-input"],
        ),
        (Some(KeyOrigin::Software), clean(), vec!["key"]),
        (Some(KeyOrigin::Unknown), clean(), vec!["key"]),
        (
            Some(KeyOrigin::Software),
            missing,
            vec!["key", "capture-off", "secure-input"],
        ),
        (None, clean(), vec![]),
    ] {
        // A lock forgets the compose session; the unlock makes none.
        a.b.lock();
        unlock_active(&a.b, &a.dek);
        if let Some(key) = key {
            a.b.compose_started(DESIGN, Some(true), key).unwrap();
        }
        match a.b.prepare_send(b_at_a.clone(), sample.clone()) {
            Err(BrevError::Environment { failed }) => assert_eq!(failed, want, "{key:?}"),
            other => panic!("{key:?}: {other:?}"),
        }
        assert!(guard(&a.b.s).ticket.is_none());
        assert!(matches!(
            sign_request(&a, &b_at_a),
            Err(BrevError::Malformed)
        ));
    }
    assert_eq!(net.server.requests(), before, "the relay saw no request");
    // Control: every requirement met sends.
    send(&a, &b_at_a, b"s", b"x");
    assert_eq!(net.server.requests(), before + 2, "lookup and submit");
}

/// The compose calls go through the gate, and a lock forgets the session;
/// `compose_closed` drops it, and the events count only in an open one.
#[test]
fn compose_needs_the_gate_and_a_lock_forgets_it() {
    let u = locked_user(NO_RELAY);
    let b = &u.b;
    let start = || b.compose_started(DESIGN, None, KeyOrigin::SecureEnclave);
    assert!(matches!(start(), Err(BrevError::Locked)));
    b.unlock(&u.dek, TEST_IDLE).unwrap();
    assert!(matches!(start(), Err(BrevError::Locked)), "armed");
    b.confirm_active(clean()).unwrap();
    // Without a compose session the events count nowhere.
    b.synthetic_dropped().unwrap();
    b.paste_accepted().unwrap();
    start().unwrap();
    b.synthetic_dropped().unwrap();
    b.synthetic_dropped().unwrap();
    b.paste_accepted().unwrap();
    let env = guard(&b.s).facts(&clean().into()).unwrap().1;
    assert_eq!((env.blocked_input, env.pastes, env.admin), (2, 1, None));
    // A second start starts again.
    start().unwrap();
    assert_eq!(
        guard(&b.s).facts(&clean().into()).unwrap().1.blocked_input,
        0
    );
    b.compose_closed().unwrap();
    assert!(guard(&b.s).compose.is_none());
    start().unwrap();
    b.lock();
    assert!(guard(&b.s).compose.is_none());
}

/// Design §8 brev-mail 7: each sync deletes the local invites past their
/// life (made before day today − 7, as the relay counts), and keeps the
/// others. The invite `create_invite` keeps is dated today.
#[test]
fn expired_local_invites_are_deleted() {
    let net = net();
    let u = user(&net);
    join(&net, &u, "anna");
    let today = crate::store::today();
    {
        let mut s = guard(&u.b.s);
        for (i, day) in [today - 8, today - 7, today - 1].into_iter().enumerate() {
            s.me.store_invite(&[u8::try_from(i).unwrap(); 16], day)
                .unwrap();
        }
    }
    u.b.create_invite().unwrap();
    let days = |u: &User| -> Vec<u64> {
        let mut days: Vec<u64> = guard(&u.b.s)
            .me
            .local_invites()
            .unwrap()
            .iter()
            .map(|i| i.day)
            .collect();
        days.sort_unstable();
        days
    };
    assert_eq!(days(&u), [today - 8, today - 7, today - 1, today]);
    u.b.sync().unwrap();
    assert_eq!(days(&u), [today - 7, today - 1, today]);
    // Kept rows still open to their secrets.
    let secrets: Vec<[u8; 16]> = guard(&u.b.s)
        .me
        .local_invites()
        .unwrap()
        .iter()
        .filter(|i| i.day < today)
        .map(|i| *i.secret)
        .collect();
    assert!(secrets.contains(&[1; 16]) && secrets.contains(&[2; 16]));
}

/// B's one letter from A: its message id.
fn received(b: &User, a_at_b: &[u8]) -> Vec<u8> {
    let threads = b.b.threads(a_at_b.to_vec()).unwrap();
    let thread = threads.last().unwrap().id.clone();
    b.b.messages(thread).unwrap().remove(0).id
}

/// A's signed letter to `contact`, sealed and signed but not submitted: its
/// envelope, for a transport of the test's own.
fn signed_envelope(a: &User, contact: &[u8]) -> Envelope {
    prepare(a, contact).unwrap();
    let digest = sign_request(a, contact).unwrap();
    seal(a, &digest).unwrap();
    let s = guard(&a.b.s);
    s.letter.as_ref().unwrap().envelope().clone()
}

/// Delivers `envelopes` to `b` through a `MockTransport` stamped at
/// `received_at` (the system clock when `None`): how many arrived.
fn deliver(b: &User, envelopes: &[&Envelope], received_at: Option<u64>) -> u32 {
    let (to_b, at_b) = MockTransport::pair();
    to_b.set_time(received_at);
    for e in envelopes {
        to_b.send(e).unwrap();
    }
    let epoch = guard(&b.b.s).epoch;
    let arrived = b.b.sync_via(&at_b, epoch).unwrap();
    assert!(at_b.poll().unwrap().is_empty(), "all acknowledged");
    arrived
}

/// docs/AUTHORSHIP.md §8: a letter A → B that meets every requirement,
/// through a `MockTransport`. The facts come from raw samples and events, counted in
/// Rust; the Secure Enclave key (a test key) signs the token and the
/// envelope; B's core checks the token with A's pinned key and the
/// transport's `received_at`, and stores the result: verified, with the
/// counts A's app saw. A's own copy has no proof.
#[test]
fn a_letter_round_trips_with_a_verified_token() {
    let net = net();
    let (a, b, b_at_a, a_at_b) = pair(&net);
    compose(&a);
    let seen = Sample {
        processes: Some(names(&["launchd", "claude", "Brev"])),
        windows: Some(vec![
            Window {
                owner_pid: 7,
                layer: 0,
            },
            Window {
                owner_pid: 8,
                layer: 0,
            },
            Window {
                owner_pid: own_pid(),
                layer: 0,
            },
            Window {
                owner_pid: 9,
                layer: 25,
            },
        ]),
        ..clean()
    };
    assert!(a.b.observe(seen).unwrap().is_empty());
    for _ in 0..3 {
        a.b.synthetic_dropped().unwrap();
    }
    a.b.prepare_send(b_at_a.clone(), clean()).unwrap();
    let digest = sign_request(&a, &b_at_a).unwrap();
    let envelope_digest =
        a.b.attach_token_signature(a.key.sign_digest(&digest))
            .unwrap();
    assert_ne!(digest, envelope_digest, "two signatures, two digests");
    a.b.attach_signature(a.key.sign_digest(&envelope_digest))
        .unwrap();
    let envelope = guard(&a.b.s).letter.as_ref().unwrap().envelope().clone();
    assert_eq!(envelope.id().to_vec(), envelope_digest);
    let sent = a.b.submit().unwrap();

    assert_eq!(deliver(&b, &[&envelope], None), 1);
    let proof = b.b.letter_proof(received(&b, &a_at_b)).unwrap().unwrap();
    assert!(proof.seconds.is_some_and(|s| s <= 5), "{proof:?}");
    assert_eq!(
        proof,
        Proof {
            verified: true,
            failed: Vec::new(),
            attested: false,
            admin: Some(true),
            agents: Some(1),
            windows: Some(2),
            blocked_input: Some(3),
            seconds: proof.seconds,
            sip: Some(true),
            sudo: Some(0),
        }
    );
    // The letter itself arrived as it was written.
    let m = received(&b, &a_at_b);
    let body = b.b.open_body(m).unwrap();
    assert_eq!(&body.chunk(0).unwrap()[..4], b"body");
    // The sender's own copy: no proof shown back.
    let own = a.b.messages(sent).unwrap().remove(0).id;
    assert_eq!(a.b.letter_proof(own).unwrap(), None);
    assert!(matches!(
        b.b.letter_proof(vec![0; 16]),
        Err(BrevError::NotFound)
    ));
}

/// docs/AUTHORSHIP.md §6: a token tampered with inside a payload that the
/// sender's key sealed and signed again. The letter is stored anyway, with
/// the failed check: a signature one bit off fails `"signature"`; a good
/// token moved to another letter fails `"content"`. Neither shows the
/// sender's counts. So does a letter the relay stamped a day late:
/// `"iat"`.
#[test]
fn a_tampered_token_is_stored_as_not_verified() {
    let net = net();
    let (a, b, b_at_a, a_at_b) = pair(&net);
    // A letter and its claims, as `sign_request` keeps them, and the
    // signature the Enclave gives.
    let pending = |a: &User| {
        prepare(a, &b_at_a).unwrap();
        let digest = sign_request(a, &b_at_a).unwrap();
        let raw = sig::der_to_raw(&a.key.sign_digest(&digest)).unwrap();
        (guard(&a.b.s).pending.take().unwrap(), raw)
    };
    let sealed = |draft: &Draft, token: &[u8]| {
        let s = guard(&a.b.s);
        let mut letter = s.me.seal_letter(draft, token).unwrap();
        let der = a.key.sign_digest(&letter.digest());
        s.me.attach_signature(&mut letter, &der).unwrap();
        letter.envelope().clone()
    };
    let (first, raw1) = pending(&a);
    let mut bad = raw1;
    bad[40] ^= 1;
    let flipped = sealed(&first.draft, &token::assemble(&first.payload, &bad));
    let (second, _) = pending(&a);
    let moved = sealed(&second.draft, &token::assemble(&first.payload, &raw1));
    let (third, raw3) = pending(&a);
    let late = sealed(&third.draft, &token::assemble(&third.payload, &raw3));
    let (fourth, raw4) = pending(&a);
    let good = sealed(&fourth.draft, &token::assemble(&fourth.payload, &raw4));

    let day_later = unix_now() + brev_hand::verify::PAST + 60;
    for (env, at, want) in [
        (&flipped, None, "signature"),
        (&moved, None, "content"),
        (&late, Some(day_later), "iat"),
    ] {
        assert_eq!(deliver(&b, &[env], at), 1, "{want}: stored anyway");
        let proof = b.b.letter_proof(received(&b, &a_at_b)).unwrap().unwrap();
        assert_eq!(
            proof,
            Proof {
                verified: false,
                failed: vec![want.to_owned()],
                attested: false,
                admin: None,
                agents: None,
                windows: None,
                blocked_input: None,
                seconds: None,
                sip: None,
                sudo: None,
            },
            "{want}"
        );
    }
    // Control: a letter built the same way with its own token verifies.
    assert_eq!(deliver(&b, &[&good], None), 1);
    let proof = b.b.letter_proof(received(&b, &a_at_b)).unwrap().unwrap();
    assert!(proof.verified && proof.failed.is_empty(), "{proof:?}");
}

/// docs/AUTHORSHIP.md §6 step 5: a replayed envelope, the same message id
/// and token, is refused as `Duplicate` in the transaction that would store
/// it, acknowledged, and not counted; the stored letter and its result stay.
#[test]
fn a_replayed_envelope_is_duplicate() {
    let net = net();
    let (a, b, b_at_a, a_at_b) = pair(&net);
    let envelope = signed_envelope(&a, &b_at_a);
    assert_eq!(deliver(&b, &[&envelope], None), 1);
    let m = received(&b, &a_at_b);
    // Again, also stamped later and twice in one poll.
    assert_eq!(deliver(&b, &[&envelope], None), 0);
    assert_eq!(
        deliver(&b, &[&envelope, &envelope], Some(unix_now() + 60)),
        0
    );
    assert!(matches!(
        guard(&b.b.s).me.receive(&envelope, unix_now()),
        Err(Error::Duplicate)
    ));
    let threads = b.b.threads(a_at_b.clone()).unwrap();
    assert_eq!(threads.len(), 1);
    assert_eq!(b.b.messages(threads[0].id.clone()).unwrap().len(), 1);
    assert!(b.b.letter_proof(m).unwrap().unwrap().verified);
    // The same through the relay: submitted, fetched as a duplicate,
    // acknowledged.
    a.b.submit().unwrap();
    assert_eq!(net.relay.waiting().unwrap(), 1);
    assert_eq!(b.b.sync().unwrap().letters, 0);
    assert_eq!(net.relay.waiting().unwrap(), 0);
}

/// docs/AUTHORSHIP.md §4.3 (D-0109): a sample with a running `sudo` locks
/// everything at once: every open text, the letter's plaintext waiting for
/// its token signature, the compose session, the ticket; the plaintext
/// counter is 0. The reasons come back. A failed read does not lock; SIP
/// off does, and both reasons are named.
#[test]
fn a_sudo_sample_locks_everything() {
    let net = net();
    let (a, _b, b_at_a, _) = pair(&net);
    let kept = a.b.contacts().unwrap();
    prepare(&a, &b_at_a).unwrap();
    sign_request(&a, &b_at_a).unwrap();
    assert!(
        crypto::live_plaintexts() >= 2,
        "control: texts and the letter"
    );
    let sudo = Sample {
        processes: Some(names(&["launchd", "sudo", "Brev"])),
        ..clean()
    };
    assert_eq!(a.b.observe(sudo.clone()).unwrap(), [LockCause::Sudo]);
    assert!(a.b.is_locked());
    assert_eq!(crypto::live_plaintexts(), 0);
    assert_eq!(kept[0].name.byte_len(), 0);
    {
        let s = guard(&a.b.s);
        assert!(s.pending.is_none() && s.compose.is_none() && s.ticket.is_none());
    }
    assert!(matches!(a.b.observe(sudo), Err(BrevError::Locked)));
    assert!(matches!(
        a.b.attach_token_signature(vec![0x30]),
        Err(BrevError::Locked)
    ));

    // A read that failed is no reason to lock (it fails the requirements).
    unlock_active(&a.b, &a.dek);
    let unread = Sample {
        processes: None,
        csr_config: None,
        windows: None,
        ..clean()
    };
    assert!(a.b.observe(unread).unwrap().is_empty());
    assert!(!a.b.is_locked());
    // SIP off locks too; with sudo, both are named.
    let both = Sample {
        processes: Some(names(&["su"])),
        csr_config: Some(0x04),
        ..clean()
    };
    assert_eq!(
        a.b.observe(both).unwrap(),
        [LockCause::Sudo, LockCause::SipOff]
    );
    assert!(a.b.is_locked());
    // The samples of the send calls follow the same rule.
    unlock_active(&a.b, &a.dek);
    compose(&a);
    let sip_off = Sample {
        csr_config: Some(0x02),
        ..clean()
    };
    match a.b.prepare_send(b_at_a.clone(), sip_off) {
        Err(BrevError::Environment { failed }) => assert_eq!(failed, ["sip"]),
        other => panic!("{other:?}"),
    }
    assert!(a.b.is_locked());
    assert_eq!(net.relay.waiting().unwrap(), 0);
}

/// docs/AUTHORSHIP.md §4.3: the second unlock step takes a sample, and one
/// with SIP off (or a `sudo`) refuses it, names the fact, and leaves
/// everything locked; the unlock it answered is gone.
#[test]
fn confirm_active_with_sip_off_refuses_and_stays_locked() {
    let u = locked_user(NO_RELAY);
    let b = &u.b;
    for (sample, fact) in [
        (
            Sample {
                csr_config: Some(0x02),
                ..clean()
            },
            "sip",
        ),
        (
            Sample {
                processes: Some(names(&["sudo"])),
                ..clean()
            },
            "sudo",
        ),
    ] {
        b.unlock(&u.dek, TEST_IDLE).unwrap();
        match b.confirm_active(sample) {
            Err(BrevError::Environment { failed }) => assert_eq!(failed, [fact]),
            other => panic!("{fact}: {other:?}"),
        }
        assert!(b.is_locked());
        assert!(matches!(b.contacts(), Err(BrevError::Locked)));
        assert!(
            matches!(b.confirm_active(clean()), Err(BrevError::Locked)),
            "{fact}: the armed unlock is gone"
        );
        assert!(b.is_locked());
    }
    // Control: a clean sample opens.
    unlock_active(b, &u.dek);
    assert!(!b.is_locked());
}

/// docs/AUTHORSHIP.md §2.2, §4.1: a gap of more than 5 s in the measuring
/// (here the compose session's clock moved 6 s on since the last sample)
/// misses a requirement, so `sign_request` refuses after a `prepare_send` that
/// passed, with `"max-gap"`. The letter from before (sealed, unsent) and
/// the ticket are gone, and nothing decrypted is left.
#[test]
fn a_sample_gap_over_5_s_refuses_the_sign_request() {
    let net = net();
    let (a, _b, b_at_a, _) = pair(&net);
    prepare(&a, &b_at_a).unwrap();
    let d = sign_request(&a, &b_at_a).unwrap();
    a.b.attach_token_signature(a.key.sign_digest(&d)).unwrap();
    a.b.prepare_send(b_at_a.clone(), clean()).unwrap();
    {
        let mut s = guard(&a.b.s);
        assert!(s.letter.is_some() && s.ticket.is_some());
        let c = s.compose.as_mut().unwrap();
        c.started = c.started.checked_sub(Duration::from_secs(6)).unwrap();
    }
    match sign_request(&a, &b_at_a) {
        Err(BrevError::Environment { failed }) => assert_eq!(failed, ["max-gap"]),
        other => panic!("{other:?}"),
    }
    {
        let s = guard(&a.b.s);
        assert!(s.pending.is_none() && s.letter.is_none() && s.ticket.is_none());
    }
    assert_eq!(crypto::live_plaintexts(), 0);
    assert!(matches!(a.b.submit(), Err(BrevError::NotFound)));
    // The gap stays in this compose session's facts: prepare refuses too.
    assert!(matches!(
        a.b.prepare_send(b_at_a.clone(), clean()),
        Err(BrevError::Environment { .. })
    ));
    // Samples every 2 s leave no such gap: control, a fresh session sends.
    compose(&a);
    assert!(a.b.observe(clean()).unwrap().is_empty());
    send(&a, &b_at_a, b"s", b"x");
    assert_eq!(net.relay.waiting().unwrap(), 1);
}

/// docs/AUTHORSHIP.md §3.2: the token signature must be the own key's over
/// the digest `sign_request` gave. Anything else (another key, another
/// digest, the envelope-style signature over the claims, not DER) is
/// `Signing`, and the letter, its plaintext and the ticket are forgotten.
#[test]
fn a_wrong_token_signature_is_signing_and_forgets_the_letter() {
    let net = net();
    let (a, _b, b_at_a, _) = pair(&net);
    // A wrong DER signature, from the user, the token digest and the claims.
    type Wrong = fn(&User, &[u8], &[u8]) -> Vec<u8>;
    let wrong: [Wrong; 4] = [
        |_, d, _| TestKey::new().sign_digest(d),
        |a, _, _| a.key.sign_digest(&[0; 32]),
        |a, _, payload| a.key.sign_der_high_s(payload),
        |_, _, _| vec![0x30, 0x02, 0x01],
    ];
    for (i, der) in wrong.into_iter().enumerate() {
        prepare(&a, &b_at_a).unwrap();
        let d = sign_request(&a, &b_at_a).unwrap();
        let payload = guard(&a.b.s).pending.as_ref().unwrap().payload.clone();
        assert!(
            matches!(
                a.b.attach_token_signature(der(&a, &d, &payload)),
                Err(BrevError::Signing)
            ),
            "{i}"
        );
        {
            let s = guard(&a.b.s);
            assert!(s.pending.is_none() && s.letter.is_none() && s.ticket.is_none());
        }
        assert_eq!(crypto::live_plaintexts(), 0, "{i}");
        assert!(matches!(
            a.b.attach_token_signature(a.key.sign_digest(&d)),
            Err(BrevError::NotFound)
        ));
    }
    assert_eq!(net.relay.waiting().unwrap(), 0);
    assert!(a.b.threads(b_at_a).unwrap().is_empty());
}
