//! Helpers shared by the relay's tests: temp dirs, P-256 test identities
//! (tests only), envelopes, and the relay in-process on 127.0.0.1:0 with a
//! clock the test moves, spoken to over real HTTP with reqwest as brev-core
//! speaks to it.

// Each test file uses its own part of this module.
#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use brev_proto::body::{self, token_hash, EventKind, INBOX_ANSWER_MAX};
use brev_proto::{identity_id, invite, Envelope};
use brev_relay::{parse_listen, Clock, Config, Gates, Open, Policy, Relay, Server};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use reqwest::blocking::Client;
use reqwest::StatusCode;
use rusqlite::{Connection, OpenFlags};

pub const BIN: &str = env!("CARGO_BIN_EXE_brev-relay");

/// The attestation a Phase 4 app build sends: the dev marker with the
/// feature `app-attest`, nothing without it (the app's `NoAttestor`).
#[cfg(feature = "app-attest")]
pub const ATTESTATION: &[u8] = brev_relay::DEV_ATTESTATION;
#[cfg(not(feature = "app-attest"))]
pub const ATTESTATION: &[u8] = b"";

/// Seconds in a day.
pub const DAY: u64 = 86_400;
/// The tests' first day (2024-10-04), at noon UTC.
pub const START: u64 = 20_000 * DAY + DAY / 2;

/// A fresh directory under the system temp dir, removed on drop.
pub struct TempDir(pub PathBuf);
impl TempDir {
    pub fn new() -> TempDir {
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
pub fn noise(seed: u32, len: usize) -> Vec<u8> {
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

pub fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// A test identity: a P-256 key from `seed`, an X25519 public key and a
/// relay token.
pub struct Identity {
    pub key: SigningKey,
    pub public: [u8; 65],
    pub x25519: [u8; 32],
    pub token: [u8; 32],
    pub id: [u8; 32],
}

impl Identity {
    pub fn new(seed: u8) -> Identity {
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
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        let sig: Signature = self.key.sign(msg);
        sig.to_bytes().into()
    }

    /// A registration v2 body with any address bytes and signing-key field,
    /// signed by this identity's key (design §3.2).
    pub fn registration_with(
        &self,
        address: &[u8],
        key_field: &[u8],
        invite: &[u8; 32],
        tag: &[u8; 32],
        attestation: &[u8],
    ) -> Vec<u8> {
        let mut unsigned = vec![u8::try_from(address.len()).unwrap()];
        unsigned.extend_from_slice(address);
        unsigned.extend_from_slice(key_field);
        unsigned.extend_from_slice(&self.x25519);
        unsigned.extend_from_slice(&token_hash(&self.token));
        unsigned.extend_from_slice(invite);
        unsigned.extend_from_slice(tag);
        let sig = self.sign(&body::register_preimage_v2(&unsigned));
        let len = u16::try_from(attestation.len()).unwrap().to_be_bytes();
        [&unsigned[..], &sig, &len, attestation].concat()
    }

    /// A registration v2 of `address` with the invite key `a` and `tag`,
    /// with [`ATTESTATION`].
    pub fn registration(&self, address: &[u8], invite: &[u8; 32], tag: &[u8; 32]) -> Vec<u8> {
        self.registration_with(address, &self.public, invite, tag, ATTESTATION)
    }

    /// A Phase 3 registration body, which the relay refuses.
    pub fn registration_v1(&self, address: &[u8]) -> Vec<u8> {
        let unsigned = body::registration_body(
            address,
            &self.public,
            &self.x25519,
            &token_hash(&self.token),
        )
        .unwrap();
        let sig = self.sign(&body::register_preimage(&unsigned));
        [&unsigned[..], &sig].concat()
    }

    /// A token-authenticated body: id ‖ token ‖ payload.
    pub fn request(&self, payload: &[u8]) -> Vec<u8> {
        [&self.id[..], &self.token, payload].concat()
    }

    /// The 97-byte bundle: signing key ‖ X25519 key.
    pub fn bundle(&self) -> Vec<u8> {
        body::lookup_answer(&self.public, &self.x25519).to_vec()
    }

    /// The Phase 4 lookup answer for this identity: bundle ‖ status.
    pub fn reply(&self, approved: bool) -> Vec<u8> {
        body::lookup_reply(&self.public, &self.x25519, approved).to_vec()
    }
}

/// An invite secret: the code's `s`, and the values derived from it.
#[derive(Clone, Copy)]
pub struct Secret(pub [u8; invite::SECRET_LEN]);

impl Secret {
    pub fn new(seed: u32) -> Secret {
        Secret(noise(5000 + seed, invite::SECRET_LEN).try_into().unwrap())
    }

    /// Parses a code the relay's `invite` command printed.
    pub fn from_code(code: &[u8]) -> Secret {
        let mut secret = [0u8; invite::SECRET_LEN];
        assert!(
            invite::parse(code, &mut secret).unwrap().is_none(),
            "a root code"
        );
        Secret(secret)
    }

    /// `a`, what the relay sees.
    pub fn key(&self) -> [u8; 32] {
        invite::relay_key(&self.0)
    }

    /// SHA-256(`a`), what the relay stores.
    pub fn hash(&self) -> [u8; 32] {
        invite::stored_hash(&self.key())
    }

    /// The invitee's tag for the inviter.
    pub fn tag(&self, invitee: &Identity, inviter: &Identity, address: &str) -> [u8; 32] {
        invite::tag(&self.0, &invitee.id, &inviter.id, address.as_bytes()).unwrap()
    }
}

/// An envelope from `from` to `to` with a ciphertext of `padded` + 16 noise
/// bytes (different for every `n`), signed by `from`.
pub fn envelope(from: &Identity, to: &[u8; 32], padded: usize, n: u32) -> Envelope {
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

pub fn wire(env: &Envelope) -> Vec<u8> {
    env.to_wire().unwrap()
}

pub fn id(wire: &[u8]) -> [u8; 32] {
    Envelope::from_wire(wire).unwrap().id()
}

pub fn client() -> Client {
    Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(60))
        .build()
        .unwrap()
}

/// One event of an events answer, owned.
#[derive(Debug, PartialEq)]
pub struct Seen {
    pub kind: EventKind,
    pub address: String,
    pub bundle: Vec<u8>,
    pub tag: [u8; 32],
}

/// The relay in-process on 127.0.0.1:0 with its file in a temp dir and a
/// manual clock at [`START`]. Fields drop in order: the server stops before
/// the directory is removed.
pub struct Relayed {
    pub server: Server,
    pub relay: Arc<Relay>,
    pub client: Client,
    pub base: String,
    pub secs: Arc<AtomicU64>,
    pub tmp: TempDir,
}

impl Relayed {
    /// A Phase 4 relay with the owner's limits.
    pub fn new() -> Relayed {
        Relayed::with(Box::new(Open), |_| {}, Gates::default())
    }

    /// A Phase 4 relay with `policy`, the default config changed by `edit`,
    /// and `gates`.
    pub fn with(policy: Box<dyn Policy>, edit: impl FnOnce(&mut Config), gates: Gates) -> Relayed {
        let tmp = TempDir::new();
        let secs = Arc::new(AtomicU64::new(START));
        let mut config = Config {
            clock: Clock::Manual(Arc::clone(&secs)),
            ..Config::default()
        };
        edit(&mut config);
        let relay = Relay::open_with(&tmp.0.join("relay").join("relay.db"), policy, config, gates);
        Relayed::serve(Arc::new(relay.unwrap()), secs, tmp)
    }

    fn serve(relay: Arc<Relay>, secs: Arc<AtomicU64>, tmp: TempDir) -> Relayed {
        let listen = parse_listen("127.0.0.1:0").unwrap();
        let server = Server::start(Arc::clone(&relay), listen, false).unwrap();
        let base = format!("http://{}", server.addr());
        Relayed {
            server,
            relay,
            client: client(),
            base,
            secs,
            tmp,
        }
    }

    pub fn folder(&self) -> PathBuf {
        self.tmp.0.join("relay")
    }

    pub fn db(&self) -> PathBuf {
        self.folder().join("relay.db")
    }

    /// Moves the clock to `secs` after the start of day `START / DAY + day`.
    pub fn set_time(&self, day: u64, secs: u64) {
        self.secs
            .store((START / DAY + day) * DAY + secs, Ordering::SeqCst);
    }

    /// Moves the clock to noon of day `START / DAY + day`.
    pub fn set_day(&self, day: u64) {
        self.set_time(day, DAY / 2);
    }

    pub fn post(&self, path: &str, body: Vec<u8>) -> (StatusCode, Vec<u8>) {
        let response = self
            .client
            .post(format!("{}{path}", self.base))
            .body(body)
            .send()
            .unwrap();
        let status = response.status();
        (status, response.bytes().unwrap().to_vec())
    }

    /// A root invite from the operator.
    pub fn root(&self) -> Secret {
        Secret::from_code(&self.relay.root_invite().unwrap())
    }

    /// Registers `who` at `address` with the invite `secret` made by
    /// `inviter` (None: a root invite, zero tag).
    pub fn register_by(
        &self,
        who: &Identity,
        address: &str,
        secret: &Secret,
        inviter: Option<&Identity>,
    ) -> StatusCode {
        let tag = inviter.map_or(invite::ROOT_TAG, |inviter| {
            secret.tag(who, inviter, address)
        });
        self.post(
            "/v1/register",
            who.registration(address.as_bytes(), &secret.key(), &tag),
        )
        .0
    }

    /// Registers `who` at `address` with a fresh root invite: 201.
    pub fn join(&self, who: &Identity, address: &str) {
        let root = self.root();
        assert_eq!(
            self.register_by(who, address, &root, None),
            StatusCode::CREATED,
            "{address}"
        );
    }

    /// `who` creates the invite `secret` (`POST /v1/invites`).
    pub fn create_invite(&self, who: &Identity, secret: &Secret) -> StatusCode {
        self.post("/v1/invites", who.request(&secret.hash())).0
    }

    /// Opens `secret` (`POST /v1/invites/open`, no token).
    pub fn open_invite(&self, secret: &Secret) -> (StatusCode, Vec<u8>) {
        self.post("/v1/invites/open", secret.key().to_vec())
    }

    /// `who` redeems `secret` of `inviter` with its tag.
    pub fn redeem(
        &self,
        who: &Identity,
        address: &str,
        secret: &Secret,
        inviter: &Identity,
    ) -> StatusCode {
        let payload = [secret.key(), secret.tag(who, inviter, address)].concat();
        self.post("/v1/invites/redeem", who.request(&payload)).0
    }

    pub fn lookup(&self, who: &Identity, address: &str) -> (StatusCode, Vec<u8>) {
        self.post("/v1/lookup", who.request(address.as_bytes()))
    }

    /// `caller` submits `wire` with its token (prefix ‖ wire).
    pub fn submit_as(&self, caller: &Identity, wire: &[u8]) -> StatusCode {
        self.post("/v1/envelopes", caller.request(wire)).0
    }

    /// `who` asks `address` for contact.
    pub fn ask(&self, who: &Identity, address: &str) -> StatusCode {
        self.post("/v1/requests", who.request(address.as_bytes())).0
    }

    /// `who`'s events, parsed and owned.
    pub fn events(&self, who: &Identity) -> Vec<Seen> {
        let (status, answer) = self.post("/v1/events", who.request(&[]));
        assert_eq!(status, StatusCode::OK);
        body::parse_events_answer(&answer)
            .unwrap()
            .into_iter()
            .map(|e| Seen {
                kind: e.kind,
                address: String::from_utf8(e.peer.address.to_vec()).unwrap(),
                bundle: body::lookup_answer(e.peer.signing_key, e.peer.x25519).to_vec(),
                tag: *e.tag,
            })
            .collect()
    }

    /// `who` answers the event about `peer`.
    pub fn answer(&self, who: &Identity, peer: &Identity, yes: bool) -> StatusCode {
        let payload = [&peer.id[..], &[u8::from(yes)]].concat();
        self.post("/v1/events/answer", who.request(&payload)).0
    }

    /// *Blokker*: `who` blocks `peer`.
    pub fn block(&self, who: &Identity, peer: &Identity) -> StatusCode {
        self.post("/v1/block", who.request(&peer.id)).0
    }

    /// `asker` asks `approver` at `address`, who approves: 202 and 204.
    pub fn approve(&self, asker: &Identity, approver: &Identity, address: &str) {
        assert_eq!(self.ask(asker, address), StatusCode::ACCEPTED);
        assert_eq!(self.answer(approver, asker, true), StatusCode::NO_CONTENT);
    }

    /// `who`'s inbox answer, parsed.
    pub fn inbox(&self, who: &Identity) -> Vec<Vec<u8>> {
        let (status, answer) = self.post("/v1/inbox", who.request(&[]));
        assert_eq!(status, StatusCode::OK);
        assert!(answer.len() <= INBOX_ANSWER_MAX);
        body::parse_inbox_answer(&answer)
            .unwrap()
            .into_iter()
            .map(<[u8]>::to_vec)
            .collect()
    }

    pub fn ack(&self, who: &Identity, ids: &[[u8; 32]]) -> StatusCode {
        self.post("/v1/inbox/ack", who.request(&ids.concat())).0
    }

    pub fn waiting(&self) -> u64 {
        self.relay.waiting().unwrap()
    }

    /// A read-only connection to the relay's file, for the tests' checks
    /// of what it holds.
    pub fn read(&self) -> Connection {
        Connection::open_with_flags(self.db(), OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap()
    }

    /// One integer from `sql` with the blob `param`.
    pub fn number(&self, sql: &str, param: &[u8]) -> i64 {
        self.read().query_row(sql, [param], |r| r.get(0)).unwrap()
    }

    /// Rows in `table`.
    pub fn rows(&self, table: &str) -> i64 {
        self.read()
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }

    /// `who`'s count of `kind` (1 letters, 2 requests, 3 invites) today, 0
    /// if its row is of another day or missing.
    pub fn count(&self, who: &Identity, kind: i64) -> i64 {
        let today = i64::try_from(self.secs.load(Ordering::SeqCst) / DAY).unwrap();
        self.read()
            .query_row(
                "SELECT coalesce(sum(n), 0) FROM counts
                 WHERE identity = ?1 AND kind = ?2 AND day = ?3",
                rusqlite::params![who.id, kind, today],
                |r| r.get(0),
            )
            .unwrap()
    }

    /// Whether any file in the relay's folder (the file and any `-journal`)
    /// holds `needle`.
    pub fn files_contain(&self, needle: &[u8]) -> bool {
        fs::read_dir(self.folder())
            .unwrap()
            .filter_map(|e| fs::read(e.unwrap().path()).ok())
            .any(|bytes| contains(&bytes, needle))
    }
}

/// Kills the child on drop.
pub struct Running(pub Child);
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Starts `brev-relay serve` with `args` and waits for its port file.
pub fn spawn(tmp: &TempDir, db: &Path, args: &[&str]) -> (Running, String) {
    let port_file = tmp.0.join("port");
    let child = Running(
        Command::new(BIN)
            .args(["serve", "--db"])
            .arg(db)
            .args(["--listen", "127.0.0.1:0", "--port-file"])
            .arg(&port_file)
            .args(args)
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
    (child, format!("http://127.0.0.1:{port}"))
}
