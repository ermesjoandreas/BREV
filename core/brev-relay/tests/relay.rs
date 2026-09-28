//! Relay tests (docs/PHASE3_DESIGN.md §4.6). The relay runs in-process on
//! 127.0.0.1:0 and is spoken to over real HTTP with reqwest, as brev-core
//! will; identities sign with p256 test keys (tests only). The binary is run
//! for `serve`'s port file, trace and listen rule, and for `release`.

use std::fs;
use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use brev_proto::body::{self, token_hash, INBOX_ANSWER_MAX, INBOX_MAX, INBOX_MAX_BYTES};
use brev_proto::{identity_id, pad_into, padded_len, Envelope, MAX_PADDED, MAX_WIRE};
use brev_relay::{parse_listen, Decision, Endpoint, Error, Open, Policy, Relay, Server};
use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use reqwest::blocking::Client;
use reqwest::StatusCode;

const BIN: &str = env!("CARGO_BIN_EXE_brev-relay");

/// A fresh directory under the system temp dir, removed on drop.
struct TempDir(PathBuf);
impl TempDir {
    fn new() -> TempDir {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("brev-relay-test-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir(&p).unwrap();
        TempDir(p)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Deterministic bytes, different for every seed (xorshift32).
fn noise(seed: u32, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// A test identity: a P-256 key from `seed`, an X25519 public key and a
/// relay token.
struct Identity {
    key: SigningKey,
    public: [u8; 65],
    x25519: [u8; 32],
    token: [u8; 32],
    id: [u8; 32],
}

impl Identity {
    fn new(seed: u8) -> Identity {
        let key = SigningKey::from_slice(&[seed; 32]).unwrap();
        let public: [u8; 65] = key
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .try_into()
            .unwrap();
        let x25519: [u8; 32] = noise(1000 + u32::from(seed), 32).try_into().unwrap();
        Identity {
            id: identity_id(&public, &x25519),
            key,
            public,
            x25519,
            token: noise(2000 + u32::from(seed), 32).try_into().unwrap(),
        }
    }

    /// Raw r ‖ s over `msg`.
    fn sign(&self, msg: &[u8]) -> [u8; 64] {
        let sig: Signature = self.key.sign(msg);
        sig.to_bytes().into()
    }

    /// A registration body with any address bytes and signing-key field,
    /// signed by this identity's key (design §2.4).
    fn registration_with(&self, address: &[u8], key_field: &[u8]) -> Vec<u8> {
        let mut unsigned = vec![u8::try_from(address.len()).unwrap()];
        unsigned.extend_from_slice(address);
        unsigned.extend_from_slice(key_field);
        unsigned.extend_from_slice(&self.x25519);
        unsigned.extend_from_slice(&token_hash(&self.token));
        let sig = self.sign(&body::register_preimage(&unsigned));
        [&unsigned[..], &sig].concat()
    }

    fn registration(&self, address: &[u8]) -> Vec<u8> {
        self.registration_with(address, &self.public)
    }

    /// A lookup, inbox or ack body: id ‖ token ‖ payload.
    fn request(&self, payload: &[u8]) -> Vec<u8> {
        [&self.id[..], &self.token, payload].concat()
    }

    /// The lookup answer the relay gives for this identity.
    fn bundle(&self) -> Vec<u8> {
        body::lookup_answer(&self.public, &self.x25519).to_vec()
    }
}

/// An envelope from `from` to `to` with a ciphertext of `padded` + 16 noise
/// bytes (different for every `n`), signed by `from`.
fn envelope(from: &Identity, to: &[u8; 32], padded: usize, n: u32) -> Envelope {
    let mut nonce = [0u8; 24];
    nonce[..4].copy_from_slice(&n.to_be_bytes());
    let mut env = Envelope {
        sender: from.id,
        recipient: *to,
        nonce,
        ciphertext: noise(n, padded + 16),
        signature: Vec::new(),
    };
    env.signature = from.sign(&env.signed_bytes()).to_vec();
    env
}

fn wire(env: &Envelope) -> Vec<u8> {
    env.to_wire().unwrap()
}

fn id(wire: &[u8]) -> [u8; 32] {
    Envelope::from_wire(wire).unwrap().id()
}

fn is_high_s(sig: &Signature) -> bool {
    sig.normalize_s() != *sig
}

/// The same signature with s replaced by n − s: also valid.
fn negate_s(sig: &Signature) -> Signature {
    let (r, s) = sig.split_scalars();
    Signature::from_scalars(r, -s).unwrap()
}

fn client() -> Client {
    Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(60))
        .build()
        .unwrap()
}

/// The relay in-process on 127.0.0.1:0 with its file in a temp dir. Fields
/// drop in order: the server stops before the directory is removed.
struct Relayed {
    _server: Server,
    relay: Arc<Relay>,
    client: Client,
    base: String,
    tmp: TempDir,
}

impl Relayed {
    fn new() -> Relayed {
        Relayed::with(Box::new(Open))
    }

    fn with(policy: Box<dyn Policy>) -> Relayed {
        let tmp = TempDir::new();
        let relay = Arc::new(Relay::open(&tmp.0.join("relay").join("relay.db"), policy).unwrap());
        let listen = parse_listen("127.0.0.1:0").unwrap();
        let server = Server::start(Arc::clone(&relay), listen, false).unwrap();
        let base = format!("http://{}", server.addr());
        Relayed {
            _server: server,
            relay,
            client: client(),
            base,
            tmp,
        }
    }

    fn folder(&self) -> PathBuf {
        self.tmp.0.join("relay")
    }

    fn db(&self) -> PathBuf {
        self.folder().join("relay.db")
    }

    fn post(&self, path: &str, body: Vec<u8>) -> (StatusCode, Vec<u8>) {
        let response = self
            .client
            .post(format!("{}{path}", self.base))
            .body(body)
            .send()
            .unwrap();
        let status = response.status();
        (status, response.bytes().unwrap().to_vec())
    }

    fn register(&self, who: &Identity, address: &str) -> StatusCode {
        self.post("/v1/register", who.registration(address.as_bytes()))
            .0
    }

    fn lookup(&self, who: &Identity, address: &str) -> (StatusCode, Vec<u8>) {
        self.post("/v1/lookup", who.request(address.as_bytes()))
    }

    fn submit(&self, wire: &[u8]) -> StatusCode {
        self.post("/v1/envelopes", wire.to_vec()).0
    }

    /// `who`'s inbox answer, parsed.
    fn inbox(&self, who: &Identity) -> Vec<Vec<u8>> {
        let (status, answer) = self.post("/v1/inbox", who.request(&[]));
        assert_eq!(status, StatusCode::OK);
        assert!(answer.len() <= INBOX_ANSWER_MAX);
        body::parse_inbox_answer(&answer)
            .unwrap()
            .into_iter()
            .map(<[u8]>::to_vec)
            .collect()
    }

    fn ack(&self, who: &Identity, ids: &[[u8; 32]]) -> StatusCode {
        self.post("/v1/inbox/ack", who.request(&ids.concat())).0
    }

    fn waiting(&self) -> u64 {
        self.relay.waiting().unwrap()
    }

    /// Whether any file in the relay's folder (the file and any `-journal`)
    /// holds `needle`.
    fn files_contain(&self, needle: &[u8]) -> bool {
        fs::read_dir(self.folder())
            .unwrap()
            .filter_map(|e| fs::read(e.unwrap().path()).ok())
            .any(|bytes| contains(&bytes, needle))
    }
}

#[test]
fn register_rules() {
    let r = Relayed::new();
    let (a, b, c) = (Identity::new(1), Identity::new(2), Identity::new(3));

    // The test's body builder gives brev-proto's body (RFC 6979 signatures
    // are deterministic).
    let unsigned =
        body::registration_body(b"anna", &a.public, &a.x25519, &token_hash(&a.token)).unwrap();
    let sig = a.sign(&body::register_preimage(&unsigned));
    assert_eq!(a.registration(b"anna"), [&unsigned[..], &sig].concat());

    // New, idempotent, taken, one address and one token per identity.
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
    assert_eq!(r.lookup(&a, "anna"), (StatusCode::OK, a.bundle()));
    assert_eq!(
        r.post("/v1/inbox", a_again.request(&[])).0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(r.lookup(&a, "anna-2").0, StatusCode::NOT_FOUND);
    assert_eq!(r.lookup(&a, "other").0, StatusCode::NOT_FOUND);

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
        assert_eq!(
            r.post("/v1/register", who.registration(address)).0,
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
        assert_eq!(
            r.register(&Identity::new(seed), address),
            StatusCode::CREATED,
            "{address}"
        );
    }

    // Signatures: a flipped bit, another key, no signing domain.
    let good = c.registration(b"carl");
    let unsigned = &good[..good.len() - 64];
    let mut flipped = good.clone();
    *flipped.last_mut().unwrap() ^= 1;
    let by_a = a.sign(&body::register_preimage(unsigned));
    let no_domain = c.sign(unsigned);
    for bad in [
        flipped,
        [unsigned, &by_a].concat(),
        [unsigned, &no_domain].concat(),
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
        assert_eq!(
            r.post("/v1/register", c.registration_with(b"carl", key)).0,
            StatusCode::BAD_REQUEST
        );
    }

    // Bodies: empty, one byte short, one byte more, over the 16 KiB limit.
    for bad in [
        Vec::new(),
        good[..good.len() - 1].to_vec(),
        [&good[..], &[0]].concat(),
    ] {
        assert_eq!(r.post("/v1/register", bad).0, StatusCode::BAD_REQUEST);
    }
    assert_eq!(
        r.post("/v1/register", vec![3; 16 * 1024 + 1]).0,
        StatusCode::PAYLOAD_TOO_LARGE
    );

    // None of the refused bodies registered carl; the good one does.
    assert_eq!(r.lookup(&a, "carl").0, StatusCode::NOT_FOUND);
    assert_eq!(r.register(&c, "carl"), StatusCode::CREATED);
    assert_eq!(r.lookup(&a, "carl"), (StatusCode::OK, c.bundle()));
}

#[test]
fn requests_need_the_token() {
    let r = Relayed::new();
    let (a, b, c) = (Identity::new(1), Identity::new(2), Identity::new(3));
    assert_eq!(r.register(&a, "anna"), StatusCode::CREATED);
    assert_eq!(r.register(&b, "bob"), StatusCode::CREATED);

    let cases: [(&str, Vec<u8>, StatusCode); 3] = [
        ("/v1/lookup", b"bob".to_vec(), StatusCode::OK),
        ("/v1/inbox", Vec::new(), StatusCode::OK),
        ("/v1/inbox/ack", vec![7; 32], StatusCode::NO_CONTENT),
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
    assert_eq!(r.lookup(&a, "anna"), (StatusCode::OK, a.bundle()));
    assert_eq!(
        r.post("/v1/inbox", a.request(&[0])).0,
        StatusCode::BAD_REQUEST
    );
}

#[test]
fn submit_checks() {
    let r = Relayed::new();
    let (a, b, c) = (Identity::new(1), Identity::new(2), Identity::new(3));
    assert_eq!(r.register(&a, "anna"), StatusCode::CREATED);
    assert_eq!(r.register(&b, "bob"), StatusCode::CREATED);

    // Stored once; the same id again is 200, also with the other S.
    let first = envelope(&a, &b.id, 256, 1);
    let w1 = wire(&first);
    assert_eq!(w1.len(), 430);
    assert_eq!(r.submit(&w1), StatusCode::ACCEPTED);
    assert_eq!(r.submit(&w1), StatusCode::OK, "already waiting");
    let mut resigned = first.clone();
    resigned.signature = negate_s(&Signature::from_slice(&first.signature).unwrap())
        .to_bytes()
        .to_vec();
    assert_ne!(resigned.signature, first.signature);
    assert_eq!(
        r.submit(&wire(&resigned)),
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
        assert_eq!(r.submit(&wire(env)), StatusCode::ACCEPTED);
    }

    // Unknown sender: 403, also to an unknown recipient, so an unsigned
    // request cannot probe the directory. Unknown recipient: 404.
    assert_eq!(
        r.submit(&wire(&envelope(&c, &b.id, 256, 4))),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        r.submit(&wire(&envelope(&c, &[9; 32], 256, 5))),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        r.submit(&wire(&envelope(&a, &c.id, 256, 6))),
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
        assert_eq!(r.submit(&bad), StatusCode::FORBIDDEN);
    }

    // Wire rules (Envelope::from_wire): version 0, magic, a ciphertext that
    // is not bucket + 16, too short, empty.
    let good = wire(&envelope(&a, &b.id, 256, 11));
    let mut version0 = good.clone();
    version0[4..6].copy_from_slice(&[0, 0]);
    let mut magic = good.clone();
    magic[0] = b'b';
    let mut unbucketed = envelope(&a, &b.id, 256, 12);
    unbucketed.ciphertext.push(0);
    unbucketed.signature = a.sign(&unbucketed.signed_bytes()).to_vec();
    for bad in [
        version0,
        magic,
        wire(&unbucketed),
        good[..429].to_vec(),
        Vec::new(),
    ] {
        assert_eq!(r.submit(&bad), StatusCode::BAD_REQUEST);
    }

    // The largest envelope is accepted; one byte more is refused before
    // parsing.
    let max = wire(&envelope(&a, &b.id, MAX_PADDED, 13));
    assert_eq!(max.len(), MAX_WIRE);
    assert_eq!(r.submit(&max), StatusCode::ACCEPTED);
    let mut over = max.clone();
    over.push(0);
    assert_eq!(r.submit(&over), StatusCode::PAYLOAD_TOO_LARGE);

    // Only the accepted ones wait, byte for byte, in arrival order.
    assert_eq!(r.waiting(), 4);
    assert_eq!(r.inbox(&b), vec![w1, wire(&high), wire(&low), max]);
}

#[test]
fn inbox_and_ack() {
    let r = Relayed::new();
    let (a, b, c) = (Identity::new(1), Identity::new(2), Identity::new(3));
    for (who, address) in [(&a, "anna"), (&b, "bob"), (&c, "carl")] {
        assert_eq!(r.register(who, address), StatusCode::CREATED);
    }
    let e1 = wire(&envelope(&a, &b.id, 256, 1));
    let e2 = wire(&envelope(&a, &b.id, 1024, 2));
    let e3 = wire(&envelope(&a, &c.id, 256, 3));
    let e4 = wire(&envelope(&c, &b.id, 4096, 4));
    for e in [&e1, &e2, &e3, &e4] {
        assert_eq!(r.submit(e), StatusCode::ACCEPTED);
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
    assert_eq!(r.submit(&e5), StatusCode::ACCEPTED);
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
    assert_eq!(r.register(&d, "dora"), StatusCode::CREATED);
    let many: Vec<Vec<u8>> = (0..17)
        .map(|n| wire(&envelope(&a, &d.id, 256, 100 + n)))
        .collect();
    for e in &many {
        assert_eq!(r.submit(e), StatusCode::ACCEPTED);
    }
    assert_eq!(r.inbox(&d), many[..INBOX_MAX]);
    let first: Vec<[u8; 32]> = many[..INBOX_MAX].iter().map(|w| id(w)).collect();
    assert_eq!(r.ack(&d, &first), StatusCode::NO_CONTENT);
    assert_eq!(r.inbox(&d), many[INBOX_MAX..]);

    // At most 4 MiB of envelopes per answer: three of MAX_WIRE bytes fit, a
    // fourth would not.
    const _: () = assert!(3 * MAX_WIRE <= INBOX_MAX_BYTES && 4 * MAX_WIRE > INBOX_MAX_BYTES);
    let e = Identity::new(5);
    assert_eq!(r.register(&e, "emil"), StatusCode::CREATED);
    let big: Vec<Vec<u8>> = (0..5)
        .map(|n| wire(&envelope(&a, &e.id, MAX_PADDED, 200 + n)))
        .collect();
    for w in &big {
        assert_eq!(r.submit(w), StatusCode::ACCEPTED);
    }
    assert_eq!(r.inbox(&e), big[..3]);
    let first: Vec<[u8; 32]> = big[..3].iter().map(|w| id(w)).collect();
    assert_eq!(r.ack(&e, &first), StatusCode::NO_CONTENT);
    assert_eq!(r.inbox(&e), big[3..]);
}

#[test]
fn ack_deletes_bytes_from_the_file() {
    let r = Relayed::new();
    let (a, b) = (Identity::new(1), Identity::new(2));
    assert_eq!(r.register(&a, "anna"), StatusCode::CREATED);
    assert_eq!(r.register(&b, "bob"), StatusCode::CREATED);
    // One small envelope and one of the largest letter brev-core makes
    // (5 × 16 KiB), which spans SQLite overflow pages.
    let small = envelope(&a, &b.id, 256, 1);
    let large = envelope(&a, &b.id, 5 * 16384, 2);
    let slices = [
        &small.ciphertext[100..132],
        &large.ciphertext[70_000..70_032],
    ];
    assert_eq!(r.submit(&wire(&small)), StatusCode::ACCEPTED);
    assert_eq!(r.submit(&wire(&large)), StatusCode::ACCEPTED);

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

    // No tombstones: the same envelope again is stored and delivered again
    // (brev-core drops it as a duplicate).
    assert!(r.inbox(&b).is_empty());
    assert_eq!(r.submit(&wire(&small)), StatusCode::ACCEPTED);
    assert_eq!(r.inbox(&b), [wire(&small)]);
}

#[test]
fn relay_file_holds_no_plaintext() {
    const MARKER: &str = "BREV-SECRET-BODY \u{e6}\u{f8}\u{e5}";
    let r = Relayed::new();
    let (a, b) = (Identity::new(1), Identity::new(2));
    assert_eq!(r.register(&a, "brev-secret-me"), StatusCode::CREATED);
    assert_eq!(r.register(&b, "brev-secret-peer"), StatusCode::CREATED);
    assert_eq!(
        r.lookup(&a, "brev-secret-peer"),
        (StatusCode::OK, b.bundle())
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
    assert_eq!(r.submit(&wire(&env)), StatusCode::ACCEPTED);

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
    let r = Relayed::with(Box::new(Recording(Arc::clone(&switch))));
    let deny = |on: bool| switch.deny.store(on, Ordering::SeqCst);
    let (a, b) = (Identity::new(1), Identity::new(2));
    assert_eq!(r.register(&b, "bob"), StatusCode::CREATED);

    // Registration: 429 and nothing written. A bad signature is refused
    // before the policy is asked.
    deny(true);
    assert_eq!(r.register(&a, "anna"), StatusCode::TOO_MANY_REQUESTS);
    let mut unsigned = a.registration(b"anna");
    *unsigned.last_mut().unwrap() ^= 1;
    assert_eq!(r.post("/v1/register", unsigned).0, StatusCode::UNAUTHORIZED);
    deny(false);
    assert_eq!(r.lookup(&b, "anna").0, StatusCode::NOT_FOUND);
    assert_eq!(
        r.register(&a, "anna"),
        StatusCode::CREATED,
        "not 200: nothing was there"
    );

    // Submit: 429 and nothing stored; a bad signature never reaches the
    // policy.
    let env = envelope(&a, &b.id, 256, 1);
    let w = wire(&env);
    deny(true);
    assert_eq!(r.submit(&w), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(r.waiting(), 0);
    let mut forged = w.clone();
    forged[100] ^= 1;
    assert_eq!(r.submit(&forged), StatusCode::FORBIDDEN);

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
    assert_eq!(r.submit(&w), StatusCode::ACCEPTED);
    deny(true);
    assert_eq!(r.ack(&b, &[env.id()]), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(r.waiting(), 1);
    deny(false);
    assert_eq!(r.inbox(&b), std::slice::from_ref(&w));
    assert_eq!(r.ack(&b, &[env.id()]), StatusCode::NO_CONTENT);
    assert_eq!(r.waiting(), 0);

    // The hooks saw exactly the authenticated, valid requests, with their
    // arguments.
    let (lookup, inbox, ack) = (Endpoint::Lookup, Endpoint::Inbox, Endpoint::Ack);
    assert_eq!(
        *switch.calls.lock().unwrap(),
        [
            Call::Register("bob".into()),
            Call::Register("anna".into()), // denied
            Call::Request(b.id, lookup),
            Call::Register("anna".into()),
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
    assert_eq!(r.register(&a, "anna"), StatusCode::CREATED);
    assert_eq!(r.register(&b, "bob"), StatusCode::CREATED);
    let to_a = [
        wire(&envelope(&b, &a.id, 256, 1)),
        wire(&envelope(&b, &a.id, 1024, 2)),
    ];
    let to_b = wire(&envelope(&a, &b.id, 256, 3));
    for w in to_a.iter().chain([&to_b]) {
        assert_eq!(r.submit(w), StatusCode::ACCEPTED);
    }

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
    assert_eq!(r.submit(&to_a[0]), StatusCode::NOT_FOUND);
    assert_eq!(r.register(&c, "anna"), StatusCode::CREATED, "free again");
    assert_eq!(r.lookup(&b, "anna"), (StatusCode::OK, c.bundle()));
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
    assert_eq!(r.lookup(&c, "anna"), (StatusCode::OK, c.bundle()));
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
    let relay = Arc::new(Relay::open(&tmp.0.join("relay.db"), Box::new(Open)).unwrap());
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

/// Kills the child on drop.
struct Running(Child);
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn serve_writes_the_port_file_and_traces_path_and_status() {
    let tmp = TempDir::new();
    let db = tmp.0.join("brev-relay").join("relay.db");
    let port_file = tmp.0.join("port");
    let mut child = Running(
        Command::new(BIN)
            .args(["serve", "--db"])
            .arg(&db)
            .args(["--listen", "127.0.0.1:0", "--port-file"])
            .arg(&port_file)
            .arg("--trace")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    let port = loop {
        if let Ok(text) = fs::read_to_string(&port_file) {
            break text;
        }
        assert!(Instant::now() < deadline, "no port file");
        std::thread::sleep(Duration::from_millis(20));
    };
    let port: u16 = port.strip_suffix('\n').unwrap().parse().unwrap();
    assert_ne!(port, 0);
    assert!(!tmp.0.join("port.tmp").exists());

    let client = client();
    let base = format!("http://127.0.0.1:{port}");
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
    let relay = Arc::new(Relay::open(&tmp.0.join("relay.db"), Box::new(Open)).unwrap());
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
