//! Helpers shared by the integration tests: temp dirs, P-256 test signers,
//! the Phase 4 relay in-process on 127.0.0.1:0 (docs/PHASE4_DESIGN.md §4),
//! and sessions driven through the FFI API as the Swift app drives it:
//! registration with an invite code, contacts by invite or by request.

// Each test file uses its own part of this module.
#![allow(dead_code)]

use std::fs;
use std::net::SocketAddr;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use brev_core::{Brev, EnvironmentReport, KeyOrigin, OpenText, CHUNK};
use brev_relay::{parse_listen, Config, Gates, Open, Policy, Relay, Server};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{DerSignature, Signature, SigningKey};
use rand::rngs::SysRng;
use rand::TryRng;
use rusqlite::{Connection, OpenFlags};

pub fn random<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    SysRng.try_fill_bytes(&mut out).unwrap();
    out
}

pub fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

pub fn len32(n: usize) -> u32 {
    u32::try_from(n).unwrap()
}

/// The idle time of the test sessions: long enough that no timer fires.
pub const TEST_IDLE: u32 = 3600;

/// The report of an app with every defence in place: class A.
pub fn class_a() -> EnvironmentReport {
    EnvironmentReport {
        key_origin: KeyOrigin::SecureEnclave,
        biometric_used: true,
        capture_excluded: true,
        secure_input_active: true,
        synthetic_input_rejected: true,
        accessibility_opaque: true,
        pasteboard_disabled: true,
    }
}

/// Unlocks `b` and confirms it, as the app does once it shows the mail,
/// and reports class A, as the app does before a letter.
pub fn unlock_active(b: &Brev, dek: &[u8]) {
    b.unlock(dek, TEST_IDLE).unwrap();
    b.confirm_active().unwrap();
    b.report_environment(class_a()).unwrap();
}

/// A fresh directory with mode 0700 under the system temp dir (a store
/// needs a private folder of its own), removed on drop.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new() -> TempDir {
        let p =
            std::env::temp_dir().join(format!("brev-test-{:016x}", u64::from_le_bytes(random())));
        fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
        TempDir(p)
    }

    pub fn arg(&self) -> String {
        self.0.to_str().unwrap().to_owned()
    }

    /// The names of the files in the directory and in its subdirectories,
    /// sorted.
    pub fn files(&self) -> Vec<String> {
        let mut names: Vec<_> = walk(&self.0)
            .into_iter()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }
}

/// The entries of every file below `dir`: its subdirectories are walked,
/// not listed.
pub fn walk(dir: &Path) -> Vec<std::io::Result<fs::DirEntry>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).unwrap() {
        match entry {
            Ok(e) if e.file_type().unwrap().is_dir() => out.extend(walk(&e.path())),
            other => out.push(other),
        }
    }
    out
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A random P-256 identity key, standing in for the Secure Enclave key.
pub struct TestKey {
    key: SigningKey,
    pub public: [u8; 65],
}

impl TestKey {
    pub fn new() -> TestKey {
        loop {
            if let Ok(key) = SigningKey::from_slice(&random::<32>()) {
                let public = key
                    .verifying_key()
                    .to_sec1_point(false)
                    .as_bytes()
                    .try_into()
                    .unwrap();
                return TestKey { key, public };
            }
        }
    }

    /// DER over a 32-byte digest: what `SecKeyCreateSignature` with
    /// `.ecdsaSignatureDigestX962SHA256` returns.
    pub fn sign_digest(&self, digest: &[u8]) -> Vec<u8> {
        let sig: DerSignature = self.key.sign_prehash(digest).unwrap();
        sig.as_bytes().to_vec()
    }

    /// DER over `msg`, hashed with SHA-256.
    pub fn sign_der(&self, msg: &[u8]) -> Vec<u8> {
        let sig: Signature = self.key.sign(msg);
        sig.to_der().as_bytes().to_vec()
    }
}

/// The Phase 4 relay in-process on 127.0.0.1:0, its file in a temp dir,
/// with the system clock. It can be stopped and started again on the same
/// port.
pub struct Relayed {
    server: Option<Server>,
    pub relay: Arc<Relay>,
    pub url: String,
    addr: SocketAddr,
    pub dir: TempDir,
}

impl Relayed {
    /// The owner's limits (design §4.4).
    pub fn new() -> Relayed {
        Relayed::with(Box::new(Open))
    }

    pub fn with(policy: Box<dyn Policy>) -> Relayed {
        Relayed::configured(policy, Config::default())
    }

    /// `config`'s limits, and `policy`.
    pub fn configured(policy: Box<dyn Policy>, config: Config) -> Relayed {
        let dir = TempDir::new();
        let path = dir.0.join("relay").join("relay.db");
        let relay = Arc::new(Relay::open_with(&path, policy, config, Gates::default()).unwrap());
        let listen = parse_listen("127.0.0.1:0").unwrap();
        let server = Server::start(Arc::clone(&relay), listen, false).unwrap();
        let addr = server.addr();
        Relayed {
            server: Some(server),
            relay,
            url: format!("http://{addr}"),
            addr,
            dir,
        }
    }

    /// HTTP requests the running server has received.
    pub fn requests(&self) -> u64 {
        self.server.as_ref().map_or(0, Server::requests)
    }

    pub fn stop(&mut self) {
        self.server.take().unwrap().stop().unwrap();
    }

    pub fn restart(&mut self) {
        assert!(self.server.is_none());
        self.server = Some(Server::start(Arc::clone(&self.relay), self.addr, false).unwrap());
    }

    /// Envelopes waiting, for everyone.
    pub fn waiting(&self) -> u64 {
        self.relay.waiting().unwrap()
    }

    pub fn db(&self) -> PathBuf {
        self.dir.0.join("relay").join("relay.db")
    }

    /// Whether any file in the relay's folder (the file and any
    /// `-journal`) holds `needle`.
    pub fn files_contain(&self, needle: &[u8]) -> bool {
        fs::read_dir(self.dir.0.join("relay"))
            .unwrap()
            .filter_map(|e| fs::read(e.unwrap().path()).ok())
            .any(|bytes| contains(&bytes, needle))
    }

    /// A root invite code from the operator (`brev-relay invite`).
    pub fn root_code(&self) -> Vec<u8> {
        self.relay.root_invite().unwrap()
    }

    /// Registers `u` at `address` with a fresh root invite.
    pub fn join(&self, u: &User, address: &str) {
        u.register_with(&self.root_code(), address);
    }

    /// A second connection to the relay's file, as a relay that lies (or a
    /// same-user program, CLAUDE.md §2) would edit it.
    pub fn sql(&self) -> Connection {
        Connection::open_with_flags(self.db(), OpenFlags::SQLITE_OPEN_READ_WRITE).unwrap()
    }

    /// The identity id the relay holds for `address`.
    pub fn id_of(&self, address: &str) -> [u8; 32] {
        self.sql()
            .query_row(
                "SELECT id FROM identities WHERE address = ?1",
                [address],
                |r| r.get(0),
            )
            .unwrap()
    }

    /// Sets `links(owner, peer)` to approved in the relay's file: the
    /// owner takes the peer's letters, whatever the owner's app knows.
    pub fn force_link(&self, owner: &str, peer: &str) {
        let (owner, peer) = (self.id_of(owner), self.id_of(peer));
        self.sql()
            .execute(
                "INSERT INTO links (owner, peer, state) VALUES (?1, ?2, 1)
                 ON CONFLICT(owner, peer) DO UPDATE SET state = 1",
                rusqlite::params![owner, peer],
            )
            .unwrap();
    }

    /// Rows in the relay's `table`.
    pub fn rows(&self, table: &str) -> i64 {
        self.sql()
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }
}

impl Drop for Relayed {
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            let _ = server.stop();
        }
    }
}

/// One user: a session in its own directory and its identity key.
pub struct User {
    pub b: Arc<Brev>,
    pub dek: [u8; 32],
    pub key: TestKey,
    pub dir: TempDir,
}

impl User {
    /// A new session for the relay at `url`, locked.
    pub fn locked(url: &str) -> User {
        let dir = TempDir::new();
        let key = TestKey::new();
        let dek = random();
        let b = Brev::create(dir.arg(), url.into(), &dek, &key.public).unwrap();
        User { b, dek, key, dir }
    }

    /// A new session for the relay at `url`, unlocked.
    pub fn new(url: &str) -> User {
        let u = User::locked(url);
        unlock_active(&u.b, &u.dek);
        u
    }

    /// Registers `address` with the invite `code`, as the address page
    /// does: open the code, request, Touch ID (the test key), register
    /// (no attestation: the app's `NoAttestor`).
    pub fn register_with(&self, code: &[u8], address: &str) {
        self.b.open_invite(code, len32(code.len())).unwrap();
        let digest = self
            .b
            .register_request(address.as_bytes(), len32(address.len()))
            .unwrap();
        self.b
            .register(self.key.sign_digest(&digest), Vec::new())
            .unwrap();
    }

    /// A new invite code of this user.
    pub fn invite(&self) -> Vec<u8> {
        self.b.create_invite().unwrap()
    }

    /// Adds the contact with `address` (a contact request); its local id.
    pub fn add(&self, address: &str) -> Vec<u8> {
        self.b
            .add_contact(address.as_bytes(), len32(address.len()))
            .unwrap()
    }

    /// The local id of the contact with `address`.
    pub fn contact(&self, address: &str) -> Vec<u8> {
        self.b
            .contacts()
            .unwrap()
            .into_iter()
            .find(|c| read(&c.name) == address.as_bytes())
            .map(|c| c.id)
            .unwrap_or_else(|| panic!("no contact {address}"))
    }

    /// The addresses of the waiting contact requests.
    pub fn asking(&self) -> Vec<Vec<u8>> {
        self.b
            .requests()
            .unwrap()
            .iter()
            .map(|r| read(&r.address))
            .collect()
    }

    /// The letter flow of the compose sheet: prepare, sign request, Touch
    /// ID (the test key), attach, submit. The new thread's id.
    pub fn send(&self, contact: &[u8], subject: &[u8], body: &[u8]) -> Vec<u8> {
        self.b.prepare_send(contact.to_vec()).unwrap();
        let digest = self
            .b
            .sign_request(
                contact.to_vec(),
                subject,
                len32(subject.len()),
                body,
                len32(body.len()),
            )
            .unwrap();
        self.b
            .attach_signature(self.key.sign_digest(&digest))
            .unwrap();
        self.b.submit().unwrap()
    }

    /// The one thread with `contact`: its subject and its letters' bodies,
    /// oldest first.
    pub fn letters(&self, contact: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut out = Vec::new();
        for t in self.b.threads(contact.to_vec()).unwrap() {
            let subject = read(&t.subject);
            for m in self.b.messages(t.id.clone()).unwrap() {
                out.push((subject.clone(), read(&self.b.open_body(m.id).unwrap())));
            }
        }
        out
    }
}

/// The whole text, reassembled from its chunks the way the app reads it;
/// the text is closed afterwards.
pub fn read(t: &OpenText) -> Vec<u8> {
    let n = t.byte_len() as usize;
    let mut out = Vec::with_capacity(n);
    for i in 0..n.div_ceil(CHUNK) {
        let c = t.chunk(u32::try_from(i).unwrap()).unwrap();
        assert_eq!(c.len(), CHUNK);
        let take = (n - out.len()).min(CHUNK);
        out.extend_from_slice(&c[..take]);
    }
    t.close();
    out
}

/// A ("anna") and B ("bert") at `relay`, each other's contact the Phase 4
/// way: A registers with a root invite, B with A's invite code, and A's
/// sync pins B from the relay's invited event. (a, b, b at a, a at b).
pub fn pair(relay: &Relayed) -> (User, User, Vec<u8>, Vec<u8>) {
    pair_as(relay, "anna", "bert")
}

/// [`pair`] with other addresses.
pub fn pair_as(relay: &Relayed, first: &str, second: &str) -> (User, User, Vec<u8>, Vec<u8>) {
    let (a, b) = (User::new(&relay.url), User::new(&relay.url));
    relay.join(&a, first);
    b.register_with(&a.invite(), second);
    let synced = a.b.sync().unwrap();
    assert!(synced.contacts_changed && synced.letters == 0);
    let (b_at_a, a_at_b) = (a.contact(second), b.contact(first));
    (a, b, b_at_a, a_at_b)
}
