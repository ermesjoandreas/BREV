//! Helpers shared by the integration tests: temp dirs, P-256 test signers,
//! the relay in-process on 127.0.0.1:0, and sessions driven through the FFI
//! API as the Swift app drives it.

// Each test file uses its own part of this module.
#![allow(dead_code)]

use std::fs;
use std::net::SocketAddr;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use brev_core::{Brev, EnvironmentReport, KeyOrigin, OpenText, CHUNK};
use brev_relay::{parse_listen, Open, Policy, Relay, Server};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{DerSignature, Signature, SigningKey};
use rand::rngs::SysRng;
use rand::TryRng;

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

/// The relay in-process on 127.0.0.1:0, its file in a temp dir. It can be
/// stopped and started again on the same port.
pub struct Relayed {
    server: Option<Server>,
    pub relay: Arc<Relay>,
    pub url: String,
    addr: SocketAddr,
    pub dir: TempDir,
}

impl Relayed {
    pub fn new() -> Relayed {
        Relayed::with(Box::new(Open))
    }

    pub fn with(policy: Box<dyn Policy>) -> Relayed {
        let dir = TempDir::new();
        let relay = Arc::new(Relay::open(&dir.0.join("relay").join("relay.db"), policy).unwrap());
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

    /// Registers `address`: request, Touch ID (the test key), register.
    pub fn register(&self, address: &str) {
        let digest = self
            .b
            .register_request(address.as_bytes(), len32(address.len()))
            .unwrap();
        self.b.register(self.key.sign_digest(&digest)).unwrap();
    }

    /// Adds the contact with `address`; its local id.
    pub fn add(&self, address: &str) -> Vec<u8> {
        self.b
            .add_contact(address.as_bytes(), len32(address.len()))
            .unwrap()
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

/// A ("anna") and B ("bert") at `relay`, registered and each other's
/// contact: (a, b, b at a, a at b).
pub fn pair(relay: &Relayed) -> (User, User, Vec<u8>, Vec<u8>) {
    let (a, b) = (User::new(&relay.url), User::new(&relay.url));
    a.register("anna");
    b.register("bert");
    let b_at_a = a.add("bert");
    let a_at_b = b.add("anna");
    (a, b, b_at_a, a_at_b)
}
