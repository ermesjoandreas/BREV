//! Unit tests of the session: the ones that need the test-build counters,
//! the test panic hook or the session's private state. The relay runs
//! in-process on 127.0.0.1:0 with a policy that counts its calls and checks
//! at each one that the session mutex is free.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};

use brev_relay::{parse_listen, Decision, Endpoint, Policy, Relay, Server};

use super::*;
use crate::test_keys::TestKey;
use crate::{Envelope, MockTransport};

/// A fresh directory under the system temp dir, removed on drop.
struct Tmp(PathBuf);
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn tmp() -> Tmp {
    let r: [u8; 8] = crypto::random().unwrap();
    let p = std::env::temp_dir().join(format!("brev-ffi-{:016x}", u64::from_le_bytes(r)));
    std::fs::create_dir(&p).unwrap();
    Tmp(p)
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
    let relay = Arc::new(Relay::open(&tmp.0.join("relay.db"), policy).unwrap());
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
    u.b.unlock(&u.dek).unwrap();
    net.probe.watch(&u.b);
    u
}

fn register(u: &User, address: &str) {
    let digest =
        u.b.register_request(address.as_bytes(), len32(address.len()))
            .unwrap();
    u.b.register(u.key.sign_digest(&digest)).unwrap();
}

fn add(u: &User, address: &str) -> Vec<u8> {
    u.b.add_contact(address.as_bytes(), len32(address.len()))
        .unwrap()
}

/// The three steps of a letter, as the app makes them.
fn send(u: &User, contact: &[u8], subject: &[u8], body: &[u8]) -> Vec<u8> {
    u.b.prepare_send(contact.to_vec()).unwrap();
    let digest =
        u.b.sign_request(
            contact.to_vec(),
            subject,
            len32(subject.len()),
            body,
            len32(body.len()),
        )
        .unwrap();
    u.b.attach_signature(u.key.sign_digest(&digest)).unwrap();
    u.b.submit().unwrap()
}

/// A ("anna") and B ("bert"), registered and each other's contact:
/// (a, b, b at a, a at b).
fn pair(net: &Net) -> (User, User, Vec<u8>, Vec<u8>) {
    let (a, b) = (user(net), user(net));
    register(&a, "anna");
    register(&b, "bert");
    let b_at_a = add(&a, "bert");
    let a_at_b = add(&b, "anna");
    (a, b, b_at_a, a_at_b)
}

fn sign_request(u: &User, contact: &[u8]) -> Result<Vec<u8>, BrevError> {
    u.b.sign_request(contact.to_vec(), b"s", 1, b"body", 4)
}

#[test]
fn locked_session_refuses_every_export() {
    let net = net();
    let (a, _b, b_at_a, _) = pair(&net);
    let thread = send(&a, &b_at_a, b"s", b"b");
    let msg = a.b.messages(thread.clone()).unwrap()[0].id.clone();
    a.b.prepare_send(b_at_a.clone()).unwrap();
    let requests = net.server.requests();
    a.b.lock();
    assert!(a.b.is_locked());
    let locked = |r: Result<(), BrevError>| assert!(matches!(r, Err(BrevError::Locked)));
    locked(a.b.contacts().map(drop));
    locked(a.b.threads(b_at_a.clone()).map(drop));
    locked(a.b.messages(thread).map(drop));
    locked(a.b.open_body(msg).map(drop));
    locked(a.b.me().map(drop));
    locked(a.b.contact_info(b_at_a.clone()).map(drop));
    locked(a.b.accept_new_key(b_at_a.clone(), vec![b'A'; 35]));
    locked(a.b.register_request(b"carl", 4).map(drop));
    locked(a.b.register(vec![0x30]));
    locked(a.b.add_contact(b"carl", 4).map(drop));
    locked(a.b.prepare_send(b_at_a.clone()));
    locked(sign_request(&a, &b_at_a).map(drop));
    locked(a.b.attach_signature(vec![0x30]));
    locked(a.b.submit().map(drop));
    locked(a.b.sync().map(drop));
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
        let r = catch_unwind(AssertUnwindSafe(|| b.unlock(&dek)));
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
    assert!(matches!(b.unlock(&dek), Err(BrevError::Locked)));
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
    b.unlock(&dek).unwrap();
    assert!(!b.is_locked());
    assert!(b.contacts().unwrap().is_empty());
}

#[test]
fn poison_while_unlocked_locks_all_on_next_call() {
    let net = net();
    let (a, _b, _, _) = pair(&net);
    let name = Arc::clone(&a.b.contacts().unwrap()[0].name);
    a.b.prepare_send(a.b.contacts().unwrap()[0].id.clone())
        .unwrap();
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
    assert!(s.me.is_locked() && s.ticket.is_none());
    drop(s);
    assert_eq!(name.byte_len(), 0);
    assert_eq!(crypto::live_plaintexts(), 0);
}

#[test]
fn drop_closes_every_open_text() {
    let net = net();
    let u = user(&net);
    register(&u, "anna");
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
        assert!(matches!(b.unlock(bad), Err(BrevError::WrongKey)));
        assert_eq!(crypto::deep_scrubs(), n + 1);
        assert!(b.is_locked());
    }
    let n = crypto::deep_scrubs();
    b.unlock(&u.dek).unwrap();
    assert_eq!(crypto::deep_scrubs(), n + 1);
    assert!(!b.is_locked());
    let n = crypto::deep_scrubs();
    assert!(matches!(b.unlock(&[7u8; 32]), Err(BrevError::WrongKey)));
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
    assert!(guard(&a.b.s).open.is_empty());
}

/// `sign_request` needs the ticket of a `prepare_send` for that contact,
/// made since the last one was used, cancelled or locked away.
#[test]
fn sign_request_needs_a_fresh_prepare() {
    let net = net();
    let (a, _b, b_at_a, _) = pair(&net);
    let c = user(&net);
    register(&c, "carl");
    let c_at_a = add(&a, "carl");
    let malformed = |r: Result<Vec<u8>, BrevError>| assert!(matches!(r, Err(BrevError::Malformed)));

    // None yet.
    malformed(sign_request(&a, &b_at_a));
    // For another contact: refused, and the ticket is used up.
    a.b.prepare_send(c_at_a.clone()).unwrap();
    malformed(sign_request(&a, &b_at_a));
    malformed(sign_request(&a, &c_at_a));
    // Used once.
    a.b.prepare_send(b_at_a.clone()).unwrap();
    sign_request(&a, &b_at_a).unwrap();
    malformed(sign_request(&a, &b_at_a));
    // A bad length does not use it; a good call then does.
    a.b.prepare_send(b_at_a.clone()).unwrap();
    assert!(matches!(
        a.b.sign_request(b_at_a.clone(), b"s", 2, b"b", 1),
        Err(BrevError::Malformed)
    ));
    sign_request(&a, &b_at_a).unwrap();
    // `lock` and `cancel_send` clear it.
    a.b.prepare_send(b_at_a.clone()).unwrap();
    a.b.lock();
    a.b.unlock(&a.dek).unwrap();
    malformed(sign_request(&a, &b_at_a));
    a.b.prepare_send(b_at_a.clone()).unwrap();
    a.b.cancel_send();
    malformed(sign_request(&a, &b_at_a));
    // A failed prepare clears the one before it.
    a.b.prepare_send(b_at_a.clone()).unwrap();
    assert!(matches!(
        a.b.prepare_send(vec![7; 16]),
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
    a.b.prepare_send(b_at_a.clone()).unwrap();
    let before = net.server.requests();
    let digest = sign_request(&a, &b_at_a).unwrap();
    a.b.attach_signature(a.key.sign_digest(&digest)).unwrap();
    a.b.cancel_send();
    let digest = fresh.b.register_request(b"Carl", 4).unwrap();
    assert_eq!(digest.len(), 32);
    drop((
        a.b.me().unwrap(),
        a.b.contacts().unwrap(),
        a.b.contact_info(b_at_a.clone()).unwrap(),
        a.b.threads(b_at_a.clone()).unwrap(),
    ));
    assert!(a.b.accept_new_key(b_at_a, vec![b'A'; 35]).is_err());
    assert_eq!(net.server.requests(), before);
    // Control: the relay counts a request.
    fresh.b.register(fresh.key.sign_digest(&digest)).unwrap();
    assert_eq!(net.server.requests(), before + 1);
    // The typed address was folded to lower case.
    let me = fresh.b.me().unwrap();
    assert!(me.registered);
    assert_eq!(&me.address.chunk(0).unwrap()[..5], b"carl\0");
}

/// `lock` and `cancel_send` forget the letter, signed or not: nothing is
/// attached, submitted or stored afterwards.
#[test]
fn lock_and_cancel_clear_the_pending_letter() {
    let net = net();
    let (a, _b, b_at_a, _) = pair(&net);
    let not_found = |r: Result<(), BrevError>| assert!(matches!(r, Err(BrevError::NotFound)));
    let digest = |a: &User| {
        a.b.prepare_send(b_at_a.clone()).unwrap();
        sign_request(a, &b_at_a).unwrap()
    };

    // Nothing to attach or submit yet.
    not_found(a.b.attach_signature(vec![0x30]));
    not_found(a.b.submit().map(drop));
    // An unsigned letter can not be submitted.
    let d = digest(&a);
    not_found(a.b.submit().map(drop));
    // Unsigned, then cancelled or locked.
    a.b.cancel_send();
    not_found(a.b.attach_signature(a.key.sign_digest(&d)));
    let d = digest(&a);
    a.b.lock();
    a.b.unlock(&a.dek).unwrap();
    not_found(a.b.attach_signature(a.key.sign_digest(&d)));
    // Signed, then cancelled or locked.
    for lock in [false, true] {
        let d = digest(&a);
        a.b.attach_signature(a.key.sign_digest(&d)).unwrap();
        assert!(guard(&a.b.s).letter.as_ref().unwrap().is_signed());
        if lock {
            a.b.lock();
            a.b.unlock(&a.dek).unwrap();
        } else {
            a.b.cancel_send();
        }
        assert!(guard(&a.b.s).letter.is_none());
        not_found(a.b.submit().map(drop));
    }
    // A foreign signature clears it too.
    digest(&a);
    assert!(matches!(
        a.b.attach_signature(TestKey::new().sign_digest(&[0; 32])),
        Err(BrevError::Signing)
    ));
    not_found(a.b.submit().map(drop));
    assert!(a.b.threads(b_at_a.clone()).unwrap().is_empty());
    assert_eq!(net.relay.waiting().unwrap(), 0);
    // Control: the same steps without a lock send the letter.
    let d = digest(&a);
    a.b.attach_signature(a.key.sign_digest(&d)).unwrap();
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
    assert_eq!(b.b.sync().unwrap(), 1);
    assert_eq!(b.b.sync().unwrap(), 0);
    // A registration that is refused, a lookup of nobody.
    let digest = b.b.register_request(b"anna", 4);
    assert!(matches!(digest, Err(BrevError::Duplicate)));
    assert!(matches!(
        a.b.add_contact(b"nobody", 6),
        Err(BrevError::NotFound)
    ));
    let at = crate::relay::live_at_requests();
    // register ×2, add ×2 (lookups), prepare, submit, poll, ack, poll, and
    // the failed lookup: 10.
    assert_eq!(at.len(), 10);
    assert_eq!(net.server.requests() - before, 10);
    assert!(at.iter().all(|&live| live == (0, 0)), "{at:?}");
    // Control: the counter sees a text the app holds open.
    let kept = a.b.contacts().unwrap();
    assert!(matches!(a.b.sync(), Ok(0)));
    assert_eq!(crate::relay::live_at_requests(), [(1, 0)]);
    drop(kept);
}

/// Every request is made with the session mutex released (design §5.2):
/// the relay's policy tries each session's mutex during each request.
#[test]
fn no_network_under_the_session_mutex() {
    let net = net();
    let (a, b, b_at_a, _) = pair(&net);
    send(&a, &b_at_a, b"s", b"x");
    b.b.sync().unwrap();
    let calls = net.probe.calls.load(Ordering::SeqCst);
    // register ×2, lookup ×3, submit, inbox, ack.
    assert_eq!(calls, 8);
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
        fn poll(&self) -> Result<Vec<Envelope>, NetError> {
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
    for e in &envelopes {
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
    to_b.send(&envelopes[0]).unwrap();
    assert!(matches!(
        b.b.sync_via(&at_b, epoch.wrapping_sub(1)),
        Err(BrevError::Locked)
    ));
    assert_eq!(at_b.poll().unwrap().len(), 1, "not acked");
}
