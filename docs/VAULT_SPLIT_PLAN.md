# Plan: brev-core → brev-vault + brev-mail, then Rust checks (step 2) and the environment class (step 3)

Revised after the critic. Base: `claude/phase3` at ab2f14d (WP5 is in; it touched only Swift and docs). Clone: `scratchpad/split/revise`. /Users/andypandy/BREV was not touched.

Order: step 1 (split), review, step 2 (five checks), review, step 3 (class), review. One commit per step. Items are named, not line-numbered, except where a test line is quoted.

## 0. Critic points: verdicts

| # | Verdict | What changed in this plan |
|---|---|---|
| 1 dir lock vs phase1 | **Confirmed.** `no_plaintext_in_any_file` scans `read_dir(dir)` and asserts `["a.db","b.db"]`. A flock on the db file breaks SQLite: I re-ran the critic's test and got `DatabaseBusy` on both connections. | `make()` stays in `dir`. `pair()` uses `dir/a` and `dir/b`. 5 test-body lines change (§7). **Owner question Q1.** |
| 2 bare `Core` timing | **Confirmed.** `Core::create` returns unlocked today. There are 12 `core.unlock` calls, 7 of them inside `assert!`. | `Vault` owns the clock. `Core::unlock(&mut dek)` keeps its signature, and the idle time is a `Core` field. create and unlock both leave the store Armed. The helpers confirm, and phase1 lines 282, 611 and 776 each get one `confirm_active()` line (§5, §7). |
| 3 sleep | **Confirmed.** Rust std `sys/pal/unix/time.rs:265`: on Apple, `Instant` is `CLOCK_UPTIME_RAW`, which stops while the Mac sleeps. | The deadline is kept on two clocks, Instant and wall. The timer waits at most 1 s at a time (§5d). |
| 4 padcheck | **Confirmed.** `padcheck.swift:57` has `version == 3`, and V18 says "schema v3". | Step 3 changes both to 4. |
| 5 release scrub test | **Confirmed.** test.sh:94 runs `-p brev-core --lib scrub_stack`, and both matching tests move to the vault. | `-p brev-vault`, and the output must say `2 passed`. |
| 6 release guard | **Confirmed.** There is no build phase today, and `ENABLE_USER_SCRIPT_SANDBOXING=YES`. | An XcodeGen pre-build script checks the archive the app links (inputFiles declared), plus a check in gen-bindings.sh (§6). |
| 7 bindings cmp | **Confirmed.** Line 1 of the app bindings is the patch marker. | patch-bindings.py runs on the temporary copy before `cmp`. |
| 8 timer gaps | **Confirmed**, all three: `resume()` checks only `is_locked()` and the epoch; the timer sleeps with no timeout while Locked; the timer can hold a strong reference. | Whoever takes the session mutex first after the deadline wipes. unlock and confirm notify the timer. **Different fix for the flock:** `Timer::drop` joins the thread, instead of releasing the DirLock by hand. The timer never holds a `Brev`, so the drop never runs on the timer thread, and after the join the session and its flock are gone before `drop(Brev)` returns. |
| 9 mode-check order | **Accepted.** | The order is `verify_store`, then the 0600 check, then `set_journal_mode`. |
| 10 ffi `tmp()` | **Confirmed** (`ffi/tests.rs:22-25`, `create_dir`, 0755). | It becomes a 0700 DirBuilder. |
| 11 spawn failure | **Accepted.** | On a spawn error the file is removed while the Core (and its flock) is still alive, then the Core is dropped. |

My own new findings:
- **N1. `Brev.s` must stay an `Arc<Mutex<Session>>`.** ffi/tests.rs asserts `b.s.is_poisoned()` and calls `guard(&b.s)`. The draft's `Guarded<S>` wrapper would change those lines. The timer is a separate field instead (§5).
- **N2. Name clash.** `fn identity_row` already exists (store.rs, it builds the key row). The ungated key check gets the name `open_identity(db, dek)`.
- **N3. `used()` and `dek32()` stay in `ffi`.** They return `BrevError` and parse FFI arguments. Moving them (as the draft did) changes their error type for no gain.
- **N4. The lock probe runs without MallocScribble** (test.sh:471), and so does the view host. Both link the test archive. TouchIDProbe (V51) refuses to run without `MallocScribble=1` (touchid-probe/main.swift:134), so it keeps the app archive with the guard, and V51's conditions do not change.
- **N5. Step 3 must edit three test lines** that hard-code v3: store/tests.rs:189 `"Integer(3)"` (an assertion), store/tests.rs:265 and phase2.rs:344 (the restore to 3). This follows from the approved schema bump. Listed in §7.
- **N6. The FFI `unlock(dek, idle_secs)` is the owner's API.** 4 error assertions gain `, TEST_IDLE` (ffi/tests 229, 246, 320, 329); their conditions stay the same.

## 1. Crate layout and file moves (step 1)

```
core/brev-vault/  NEW  package brev-vault, lib brev_vault, rlib only, no UniFFI, forbid(unsafe_code)
  src/lib.rs      #[global_allocator] (feature), re-exports
  src/error.rs    Error
  src/crypto.rs   column AEAD, Plaintext, scrubs, rng, test hooks
  src/padding.rs  from brev-proto
  src/store.rs    Vault, VaultConfig, DekSlot, hardening, lock state
  src/text.rs     Text (chunked reads), CHUNK
  step 2: src/clock.rs (Clock, Timer, Holder), src/dirlock.rs, src/launch.rs
  step 3: src/platform.rs
core/brev-mail/   = git mv core/brev-core; package brev-mail, [lib] name = "brev_core"
```

| Item | From | To |
|---|---|---|
| `fill`, `random`, `is_zero`, `encrypt`→`aead_seal`, `decrypt`→`aead_open`, `pad`, `seal_column`, `open_column`, `column_ad`, `COLUMN_LABEL`, `NONCE_LEN`, `TAG_LEN`, `Plaintext` (+`pub fn new`), `scrub_stack`, `scrub_stack_deep`, counters `LIVE_PLAINTEXTS`, `SCRUBS`, `DEEP_SCRUBS`, `wiped_on_drop` | crypto.rs (**mixed**) | vault crypto.rs |
| `contact_tag`, `Secret`, `static_secret`, `public_key`, `seal_message`, `open_message`, `message_key`, labels, `SECRETS_BUILT`, `LIVE_SECRETS`, `MESSAGE_OPENS` | crypto.rs | stay |
| tests `column_round_trip_and_ad_binding`, `scrub_stack_wipes_its_buffer`, `scrub_stack_deep_wipes_its_buffer`, `column_padding_is_enforced`, `plaintext_wipes_on_drop`, 3 Plaintext doctests (`brev_vault::Plaintext`) | crypto.rs | vault |
| `every_key_operation_scrubs_the_stack`, `every_seal_uses_a_fresh_nonce`, message/tag tests | crypto.rs | stay |
| `Core{db,dek,unlocked}` part → `Vault`; `create` (file part), `open`, `unlock` (copy, zero test, lock-on-failure), `lock`, `is_locked`, `dek()`, `connect`, `check_path`, `verify_store`, `not_a_store`, `schema_of`, `SchemaRow`, `set_journal_mode`, `dek_for_test`, `dek_addr_for_test` | store.rs (**mixed**) | vault store.rs |
| `APPLICATION_ID`, `SCHEMA_VERSION`, `SCHEMA` → `const MAIL: VaultConfig`; identity/contact/thread/message code, `init`'s identity part, `identity_row`, `is_permanent`, `local`, ADs, payload codec, `now` | store.rs | stay |
| `#[global_allocator]` | lib.rs (**mixed**) | vault, feature `zeroing-allocator` |
| `Error` variants Locked, WrongKey, Crypto, NotFound, Malformed, Corrupt, Rng, Io, Storage + `From<rusqlite::Error>` | lib.rs | copied into the vault `Error`; mail's `Error` keeps **all** variants |
| `OpenText` internals (`Mutex<Option<Plaintext>>`, `byte_len`/`chunk`/`close` logic), `CHUNK`, the `Session.open` registry | ffi.rs (**mixed**) | vault text.rs + `Vault::open_text` |
| `OpenText` UniFFI shell (`struct OpenText { text: Arc<Text> }`, same methods, same doc comments), `MAX_BODY`, `MAX_SUBJECT`, `Limits`, `Brev`, records, `BrevError`, `Finish`, `unlock_all`, `used`, `dek32`, `typed_address`, `id`, `guard` | ffi.rs | stay in `ffi` (N3) |
| `MAX_PADDED`, `LEN_PREFIX`, `BUCKETS` (now pub), `STEP`, `PadError` (same derives/impls), `padded_len`, `is_padded_len`, `pad_into`, `unpad` + tests `padded_lengths_only`, `padding_boundaries`, `padding_is_strict` | brev-proto lib.rs | vault padding.rs; proto: `pub use brev_vault::padding::{MAX_PADDED, PadError, padded_len, is_padded_len, pad_into, unpad};`, `MIN_WIRE` uses `brev_vault::padding::BUCKETS[0]` |
| `MockTransport` | transport.rs | same file, `#[cfg(any(test, feature = "test-hooks"))]` (Q5) |
| `test_keys.rs` | brev-core | brev-mail (uses `brev_vault::random`) |

**UniFFI rule** (from the draft's experiment: checksums include `module_path`). No `#[uniffi::export]` item and no `uniffi::{Record,Object,Error,Enum}` type moves. Their doc comments stay word for word. `ffi::CHUNK` stays a `pub const` in `ffi` (`= brev_vault::CHUNK`).

Dependencies:
- **vault:** rusqlite, chacha20poly1305, poly1305 (zeroize), rand, zeroize, thiserror, zeroizing-alloc (optional). No sha2, since nothing in the vault hashes. No serde.
- **brev-mail:** drops its direct rand, chacha20poly1305, poly1305 and zeroizing-alloc, and adds brev-vault.
- **brev-proto:** adds `brev-vault = { path, default-features = false }` (R6).
- **rust-version:** vault uses the workspace's 1.85 in step 1. Step 2 raises the vault and the workspace to 1.89, because it needs `File::try_lock`; the toolchain here is 1.91.1.

## 2. Naming (confirmed)

The package name is `brev-mail` and the directory is `core/brev-mail`. `[lib] name = "brev_core"` is kept.

Evidence from the draft's experiment: with `[crate-roots] brev_core = "brev-mail"` and `-p brev-mail`, `BrevCore.swift` was byte-identical (cmp). So these stay unchanged:
- the `uniffi_brev_core_*` and `ffi_brev_core_*` symbols;
- `libbrev_core.a` and `.dylib`;
- the patch-bindings targets (`ffi_brev_core_rustbuffer_free`);
- project.yml's `core/target/release/libbrev_core.a`;
- touchid-probe's `BREV_CORE_ARCHIVE`;
- `uniffi.toml` (BrevCore/BrevCoreFFI).

Edits are needed only in:
- core/Cargo.toml (members) and uniffi-global.toml;
- gen-bindings.sh (`-p`, the error-text path);
- test.sh (`-p` ×4, the test_keys path, the scrub test → `-p brev-vault`);
- tools/verify/build.sh (`CRYPTO=core/brev-vault/src/crypto.rs`, the sed target path in the copy, `-p brev-mail`);
- relay Cargo.toml comments.

`ping()` keeps `CORE_NAME = "brev-core"`, because its test asserts that prefix and AppDelegate logs it.

**Step 1 behaviour check:** the generated `BrevCore.swift`, `BrevCoreFFI.h` and `.modulemap` are byte-identical before and after.

## 3. brev-vault API (step 1)

```rust
pub struct VaultConfig { pub file_name: &'static str, pub application_id: i32,
                         pub schema: &'static str, pub schema_version: i32 }
impl VaultConfig { pub fn path_in(&self, dir: &Path) -> PathBuf }
pub struct DekSlot(Box<Zeroizing<[u8; 32]>>);
impl DekSlot { pub fn take(dek: &mut [u8; 32]) -> DekSlot /* copy, then zero source */; pub fn is_zero(&self) -> bool }
pub struct Vault { db: Connection, dek: Box<Zeroizing<[u8; 32]>>, unlocked: bool,
                   texts: Vec<Weak<Text>>, cfg: &'static VaultConfig }   // step 2: + clock, idle, _dir: DirLock
impl Vault {
  /// file 0600 create_new, connect, journal mode, `seal(dek)` before BEGIN (as today),
  /// one tx: application_id, schema, `insert(tx, sealed)`, user_version. Error → file removed.
  pub fn create<T, E: From<Error>>(path: &Path, dek: DekSlot, cfg: &'static VaultConfig,
      seal: impl FnOnce(&[u8; 32]) -> Result<T, E>,
      insert: impl FnOnce(&rusqlite::Transaction<'_>, T) -> Result<(), E>) -> Result<Vault, E>;
  pub fn open(path: &Path, cfg: &'static VaultConfig) -> Result<Vault, Error>;       // locked
  pub fn unlock<E: From<Error>>(&mut self, dek: &mut [u8; 32],
      check: impl FnOnce(&Connection, &[u8; 32]) -> Result<(), E>) -> Result<(), E>;
  pub fn lock(&mut self);     // close texts, zero DEK, unlocked=false, scrub_stack
  pub fn is_locked(&self) -> bool;
  pub fn dek(&self) -> Result<&[u8; 32], Error>;     // the single gate
  pub fn db(&self) -> &Connection;  pub fn db_mut(&mut self) -> &mut Connection;
  pub fn open_text(&mut self, p: Plaintext) -> Arc<Text>;
  #[cfg(any(test, feature = "test-hooks"))] pub fn dek_for_test(&self) -> [u8; 32];
  #[cfg(any(test, feature = "test-hooks"))] pub fn dek_addr_for_test(&self) -> usize;
  #[cfg(any(test, feature = "test-hooks"))] pub fn dek_cell_for_test(&self) -> &Zeroizing<[u8; 32]>;
}
pub fn check_path(path: &Path) -> Result<(), Error>;
pub struct Plaintext(Zeroizing<Vec<u8>>); impl Plaintext { pub fn new(b: Zeroizing<Vec<u8>>) -> Self }  // Deref<[u8]> only
pub fn seal_column(dek: &[u8; 32], ad: &[u8], pt: &[u8]) -> Result<Vec<u8>, Error>;
pub fn open_column(dek: &[u8; 32], ad: &[u8], stored: &[u8]) -> Result<Plaintext, Error>;
pub fn column_ad(label: &str, fields: &[&[u8]]) -> Vec<u8>;
pub fn aead_seal(key: &[u8; 32], nonce: &[u8; NONCE_LEN], ad: &[u8], prefix: &[u8], pt: &[u8]) -> Result<Vec<u8>, Error>;
pub fn aead_open(key: &[u8; 32], nonce: &[u8; NONCE_LEN], ad: &[u8], ct_tag: &[u8]) -> Result<Plaintext, Error>;
pub fn pad(content: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error>;
pub fn fill(out: &mut [u8]) -> Result<(), Error>; pub fn random<const N: usize>() -> Result<[u8; N], Error>;
pub fn is_zero(k: &[u8; 32]) -> bool; pub fn scrub_stack() -> usize; pub fn scrub_stack_deep() -> usize;
pub const CHUNK: usize = 960;
pub struct Text { plain: Mutex<Option<Plaintext>> }
impl Text { pub fn byte_len(&self) -> u32; pub fn chunk(&self, i: u32) -> Result<Vec<u8>, Error>; pub fn close(&self) }
pub mod padding { /* as brev-proto today, BUCKETS pub */ }
#[derive(Debug, thiserror::Error)] pub enum Error { Locked, WrongKey, Crypto, NotFound, Malformed,
    Corrupt, Rng, Io(std::io::Error), Storage(rusqlite::Error) }      // step 2 appends Busy, Unsafe
#[cfg(any(test, feature = "test-hooks"))] pub mod test_hooks { live_plaintexts, scrubs, deep_scrubs, wiped_on_drop }
```

**Composition.** `pub struct Core { v: Vault }` with private `db()`, `db_mut()` and `dek()` that delegate.
- `Core::create(path, dek, key)`: `DekSlot::take`, `check_path`, the zero check, `sig::check_key`. All fail with `Malformed` in today's order, and the DEK is always zeroed first. Then `Vault::create(path, slot, &MAIL, seal, insert)`:
  - `seal` makes the X25519 secret and the token, and seals `identity.keys` and `identity.address` (the secret lives only in the closure);
  - `insert` adds the identity row.
- `Core::open(path)` = `Vault::open(path, &MAIL)`.
- `Core::unlock(dek)` = `v.unlock(dek, |db, k| open_identity(db, k).map(drop).map_err(crypto_to_wrong_key))`. `open_identity` is the ungated half of `identity_keys` (N2), and `identity_keys` = `dek()?` + `open_identity`.
- The FFI path is `MAIL.path_in(dir)` (`"brev.db"`). The Rust `Core` API keeps taking a full path. A directory-only API would rewrite about 20 lines of `create_and_open_refuse_bad_files`, which uses a dozen file names in one folder.
- `Session::register(p)` = `Arc::new(OpenText { text: self.me.v.open_text(p) })`. `lock_all` keeps its order; the texts are closed inside `me.lock()`. All of this runs under the session mutex.

**Errors.** Mail's `Error` gets `From<brev_vault::Error>`, 1:1. `From<Error> for BrevError` is untouched, so the Swift variants and their order are the same. `OpenText::chunk` = `self.text.chunk(i).map_err(|e| Error::from(e).into())`, which gives the same variants (Locked, Malformed).

**Test hooks across crates.** Mail's crypto.rs has `#[cfg(test)] pub(crate) use brev_vault::test_hooks::{…}`, so the test bodies keep calling `crypto::scrubs()` and the other hooks unchanged.

## 4. Features, builds, dependency whitelist

```toml
# brev-vault
[features] default = ["zeroing-allocator"]            # step 2: + "launch-guard"
zeroing-allocator = ["dep:zeroizing-alloc"]; launch-guard = []; test-hooks = []
# brev-mail
brev-vault = { path = "../brev-vault", default-features = false, features = ["zeroing-allocator"] }
[features] default = []                                # step 2: ["launch-guard"]
launch-guard = ["brev-vault/launch-guard"]; test-hooks = ["brev-vault/test-hooks"]; allow-software-keys = []  # step 3
[dev-dependencies] brev-mail = { path = ".", default-features = false, features = ["test-hooks"] }
# brev-proto
brev-vault = { path = "../brev-vault", default-features = false }   # relay: no allocator, no guard
```

- **App archive:** gen-bindings.sh runs `cargo build --release -p brev-mail` with the default features. That means launch-guard from step 2 on, and never test-hooks or allow-software-keys. Right after the build, gen-bindings.sh checks that the marker is absent (§6) and that `cargo tree -p brev-mail -e features` shows neither feature.
- **Rust tests (step 2+):** `cargo test --workspace --no-default-features`, which turns the launch guard off; the allocator stays on through mail's dependency line. Plus `cargo test -p brev-vault --features launch-guard --lib launch`.
- **Release scrub test:** `cargo test --release -p brev-vault --lib scrub_stack`. The output must contain `2 passed` (critic 5).
- **WIPER check:** unchanged, on brev-mail's release test binary. The allocator comes from the vault, but it is linked into that binary.
- **Test archive (step 2+)**, for the harness, the lock probe and the view host (N4): `cargo build --release -p brev-mail --no-default-features [--features allow-software-keys] --target-dir core/target/test-archive`. It needs its own target dir, or it would overwrite the app's archive. test.sh and viewhost/build.sh link `core/target/test-archive/release/libbrev_core.a`.
- **Bindings check:** test.sh runs bindgen on the test cdylib into a temp dir, then `patch-bindings.py` on that copy (critic 7), then `cmp` with `app/Generated/BrevCore.swift`. Features must not change the FFI.
- **clippy:** default features plus `--all-features`, both with `-D warnings`.
- **Whitelist**, `scripts/check-vault-deps.sh`, called from test.sh:
  1. `cargo tree -p brev-vault --all-features -e normal --depth 1 --prefix none -f '{p}'`. Every direct dependency must be in {chacha20poly1305, poly1305, rand, rusqlite, thiserror, zeroize, zeroizing-alloc}.
  2. The full `-e normal` tree must not contain reqwest, hyper, tokio, axum, p256, x25519-dalek, curve25519-dalek, hkdf, serde, uniffi or brev-proto.
  3. Control: the same function run on brev-mail must fail (it finds reqwest).

## 5. Step 2: five checks in brev-vault

New errors, appended after `Refused` so existing indices stay: `Busy`, `Unsafe` (in the vault's `Error`, mail's `Error` and `BrevError`).

**Open order:**
1. `check_path`;
2. launch check (c);
3. dir open, dir mode (b), flock (a);
4. connect;
5. `verify_store` (Corrupt);
6. file mode 0600 (b);
7. `set_journal_mode`.

Foreign test files (0644) still give `Corrupt`, and nothing is written to a file before its mode is checked (critic 9).

**Create order:** mail's `Malformed` checks, then 2, then 3, then `create_new` 0600, then as today.

**(a) Single instance.** `struct DirLock(File)` is a field of `Vault`, so it lives exactly as long as the store.
- `File::open(parent)`, `Io` if that fails. So `no/such/dir.db` still gives `Io`.
- `try_lock()`: `WouldBlock` → `Busy`, anything else → `Io`.
- The directory itself is locked, not a file in it. A flock on the db file breaks SQLite (critic 1, re-run), and a lock file adds a name that tests and Swift's reset list would see.
- Tests: a second `Core::open` or `Brev::open` on the same dir → `Busy`; ok after `drop`; a second `create` in the dir → `Busy`; `drop(Brev); Brev::open(dir)` 100× in a row, never `Busy` (critic 8c).

**(b) Permissions.** `fstat` on the locked fd: a directory with `mode & 0o7777 == 0o700`, otherwise `Unsafe`. The file on open: `mode & 0o7777 == 0o600`, otherwise `Unsafe`. Tests: a 0755 dir → Unsafe (create and open); a 0644 brev.db → Unsafe; 0700 with 0600 → Ok.

**(c) Launch guard** (`launch-guard`: on by default, off in tests).
- `pub fn launch_check(vars: impl IntoIterator<Item=(OsString,OsString)>) -> Result<(), Error>` gives `Unsafe` if a name starts with `DYLD_`, or if `MallocScribble != "1"` ("1" is what LaunchGuard and V2 require).
- create, open and unlock call it with `env::vars_os()` under the feature. `unlock` first copies and zeroes the caller's DEK, then checks, and stays locked.
- Tests: the pure function with injected lists. Plus one `#[cfg(feature = "launch-guard")]` test: the real cargo-test environment (cargo sets `DYLD_FALLBACK_LIBRARY_PATH`) is refused.

**(d)+(e) Clock, arming, timer** (vault `clock.rs`).
- `Deadline { mono: Instant, wall: SystemTime, set_wall: SystemTime }`. It has passed if `now.mono >= mono`, or if `now.wall >= wall` while `now.wall >= set_wall`. If the wall clock went backwards, only Instant counts (critic 3).
- `Clock { m: Mutex<Timing{phase, shutdown}>, cv: Condvar }`, where `phase` is `Locked | Armed{until} | Active{until, idle}`.
- `Vault` owns `Arc<Clock>` and `idle: Duration`. The default is 300 s; `Core::set_idle(d)` and `Vault::set_idle(d)` change it (critic 2).
- The gate: `dek()` = `unlocked && clock.is_active(now)`. So Armed or a passed deadline gives `Locked` at once, even before the timer runs. `is_locked()` is the negation of the gate.
- `unlock` succeeds → `Armed{now + CONFIRM_WINDOW}`, with `CONFIRM_WINDOW = 2 s`, then `notify_all`. `Core::create` also leaves the store Armed.
- `confirm_active()`: while Armed and in time → `Active{now + idle}` + `notify_all`. Otherwise `lock()` and `Err(Locked)`. It is idempotent while Active.
- `Clock::note_activity()`: while Active, `until = now + idle`. Otherwise a no-op. It takes only the clock mutex. No notify is needed, because the deadline only moves later.
- `lock()` sets the phase to `Locked`.
- `pub trait Holder: Send + 'static { fn lock_all(&mut self); }`.
- `pub struct Timer { clock: Arc<Clock>, thread: Option<JoinHandle<()>> }`:
  - `Timer::spawn<S: Holder>(s: Weak<Mutex<S>>, clock) -> io::Result<Timer>` (thread `brev-vault-timer`);
  - `Drop`: set `shutdown`, `notify_all`, `join`.
- Timer loop:
  1. Hold the clock guard. Return on shutdown. While Locked, wait with no timeout; otherwise `cv.wait_timeout(min(until − now, 1 s))`. The 1 s cap catches a wall-clock deadline that passed during sleep.
  2. If not expired, loop.
  3. **Drop the clock guard.** Upgrade the Weak (return if that fails). Lock the session mutex, recovering from poison. `if clock.take_expired(now) { s.lock_all() }`. Drop the Arc.
- **Lock order** is always session → clock. Mail code takes the clock briefly under the session mutex. The timer never holds the clock while it takes the session mutex, and `note_activity` takes only the clock. So there is no cycle. `dek()` takes and releases the clock on each call, so nested gate calls are fine.
- **Epoch window (critic 8a).** `Brev::session()` runs `if clock.take_expired(now) { s.lock_all() }` before it returns the guard. The first thread to take the mutex after a deadline does the wipe and bumps the epoch, so an `unlock` cannot slip in first.
- **FFI.** `Brev { s: Arc<Mutex<Session>>, timer: Timer, net }` (N1).
  - `unlock(dek: &[u8], idle_secs: u32)`: idle must be in 1..=3600, else `Malformed`. It calls `me.set_idle`, then `unlock_all` as today.
  - `confirm_active()`: under the session mutex. If it is late, `lock_all()` and `Locked`.
  - `note_activity()`: `timer.clock().note_activity()`; it never fails and never takes the session mutex.
  - `Drop`: `guard(&self.s).lock_all()`, then the Timer drop joins. After that no other Arc exists, so the Session, its connection and its flock are dropped before `drop(Brev)` returns.
  - `create_in`: `Core::create`, `me.lock()`, `Timer::spawn`. On a spawn error: `fs::remove_file(path)` while `me` is alive, then drop, then `Io` (critic 11).
- **The wipe** is `Session::lock_all` on the timer thread: texts, ticket, letter, registration, epoch, DEK zeroed, scrub. An in-flight network call finds a new epoch and stores nothing.
- **Tests** (vault tests use ms durations through a `cfg(test)` window/idle override and an injected clock; FFI tests use real time):
  - Armed → Locked for content;
  - no confirm → Locked after 2 s, texts closed, `dek_for_test` all zero;
  - confirm → content works;
  - the idle deadline passes → Locked plus the wipe;
  - `note_activity` pushes the deadline out;
  - `note_activity` while Armed does nothing;
  - wall-clock skew (injected clock: `mono` stands still, `wall` jumps) → Locked;
  - the timer vs a held session mutex (`recv_timeout` detects a deadlock);
  - epoch window: the deadline passes, then `unlock`+`confirm` before the timer runs; an in-flight `sync` stores nothing;
  - drop joins the thread;
  - `TEST_IDLE = 3600`, so the timer never fires in the other tests, and the relay probe's mutex check in ffi/tests is not disturbed.

**Swift call sites.**
- `confirmActive()`: in `LockController.endUnlock`, after `state.endUnlock(...)` returned true. If it throws, run the lock sequence with a new `LockReason.unlockExpired` and return false.
- `noteActivity()`: `BrevApplication` gets `static var noteActivity: (() -> Void)?` and `lastNoted`. It is called only where `lastHumanInput` is stamped today, which is after `InputFilter.isSynthetic(event)` returned false and `isInput` is true: in `sendEvent` and in the `nextEvent` branch that returns the event. It is throttled to at most once per second (CLOCK_MONOTONIC ns). Injected events are dropped before this point, so they cannot keep the vault unlocked. `AppDelegate.adopt` sets `{ [weak opened] in opened?.brev.noteActivity() }`, and `reset()` clears it.
- `idleSecs = LockState.rustIdleSecs` (Q3).
- `LockController`'s idle timer also calls `lock(.idle)` when `session?.brev.isLocked() == true` while `state.unlocked`.

## 6. Step 3: environment class

**Vault `platform.rs`:**
```rust
pub enum KeyOrigin { SecureEnclave, Tpm, Software, Unknown }
pub struct EnvironmentReport { pub key_origin: KeyOrigin, pub biometric_used: bool, pub capture_excluded: bool,
  pub secure_input_active: bool, pub synthetic_input_rejected: bool, pub accessibility_opaque: bool, pub pasteboard_disabled: bool }
pub enum EnvironmentClass { A, B, C }
impl EnvironmentClass { pub fn rank(self) -> u8 /* A=2,B=1,C=0 */; pub fn code(self) -> i64 /* A=1,B=2,C=3 */ }
pub trait Platform { fn environment_report(&self) -> EnvironmentReport; }
pub fn classify(r: &EnvironmentReport) -> EnvironmentClass  // hw=SE|Tpm; A: hw&&bio&&all 5; B: hw&&bio; C: else
#[cfg(test)] struct MockPlatform(EnvironmentReport);
```
All types derive `Clone, Copy, Debug, PartialEq, Eq`. Tests: all flags → A; each of the 5 flags off alone → B (5 cases); Tpm behaves like SecureEnclave; Software, Unknown or no biometric → C.

**brev-mail (in `ffi`):**
- UniFFI mirrors: `#[derive(uniffi::Enum)] KeyOrigin` and `#[derive(uniffi::Record)] EnvironmentReport`, each with a `From` into the vault type.
- `struct Reported(..); impl Platform for Reported`.
- `report_environment(&self, report) -> Result<(), BrevError>`: under the gate, stored in `Session.report` and cleared by `lock_all`.
- `const SEND_THRESHOLD: EnvironmentClass` = `A`, or `C` under `allow-software-keys`. `fn may_send(c, threshold)` compares ranks, and plain tests cover both thresholds.
- `prepare_send`: after `s.ticket = None` and before any network I/O, `classify(report, or C if there is none)` must reach the threshold, otherwise `BrevError::Environment` (appended).
  - The ticket becomes `Some((contact, class))`.
  - `sign_request` sets `letter.class = Some(class)`. `seal_letter`'s signature does not change, so the phase1 calls stay as they are.
  - `store_sent` writes `letter.class.map(code)`. Core-level sends in tests store NULL.
- **Schema v4:** `messages.env_class INTEGER` (nullable, plaintext), `SCHEMA_VERSION = 4`.
  - Not in `body_ad`, so the body format is unchanged (R5).
  - There is no migration: a v3 store gives `Corrupt` (Q4).
  - `padcheck.swift` and VERIFY V18 change to 4 (critic 4); `env_class` is not a sealed column.
- **Release guard (critic 6):**
  - Under the feature: `#[used] static SOFTWARE_KEYS_MARKER: [u8; 26] = *b"BREV-ALLOW-SOFTWARE-KEYS-1"`.
  - gen-bindings.sh: after the build, `grep -aq BREV-ALLOW-SOFTWARE-KEYS core/target/release/libbrev_core.a` → fail.
  - app/project.yml: a target `preBuildScripts` entry, "Rust archive has no test features", in every config (the app never links the test archive). `inputFiles: [$(SRCROOT)/../core/target/release/libbrev_core.a]`, `outputFiles: [$(DERIVED_FILE_DIR)/rust-archive-checked]`; it fails the build if the marker is present. This covers Release and Archive from the IDE, and the Verify build from tools/verify/build.sh.
  - test.sh control: the test archive must contain the marker, and the app archive must not.
  - There is no CI yet (Phase 5); the Xcode phase is the build-time check.
- **Docs:** CLAUDE.md §2 "Accepted residual risk" and docs/THREAT_MODEL.md (verbatim) get this bullet:

  > *"Sending needs environment class A, but the class comes from Swift's own report (key origin, Touch ID, capture exclusion, secure input, synthetic-input rejection, AX opacity, no pasteboard). Until attestation lands, the class-A rule catches Swift bugs, not attackers. Test builds lower the threshold with the cargo feature `allow-software-keys`; a build-time check fails any app build whose Rust archive has it."*

- **Tests:**
  - B, C or no report → `Environment`, and the relay sees 0 requests;
  - A → the send works, the sent row has `env_class = 1` and the received row NULL (read through `core.db()`);
  - a v3 file → `Corrupt`;
  - lock clears the report.

## 7. Test-helper and test-body changes

- **Step 1:**
  - store/tests.rs: `core.db` → `core.db()` (about 16 lines, some inside `assert!`, with the same condition);
  - `crypto::wiped_on_drop(&*core.dek)` → `(core.v.dek_cell_for_test())`.
- **Step 2, helpers:**
  - `common::TempDir::new`: `DirBuilder::new().mode(0o700)`.
  - `TempDir::files()`: now lists every file below the dir, by name, sorted. Subdirs are walked, not listed. So `["a.db","b.db"]` and `FILES` stay as they are.
  - phase1 `make()`: unchanged dir, plus `core.confirm_active()`.
  - phase1 `pair()`: A in `dir/a/`, B in `dir/b/` (0700).
  - `User::new`: `unlock_active` (= `unlock(&dek, TEST_IDLE)` + `confirm_active()`).
  - store/tests.rs `temp_path()`: its own 0700 dir; `Party::drop` removes the dir. Today they share `$TMPDIR`, which the flock would turn into `Busy`. `party()` confirms.
  - ffi/tests.rs `tmp()`: a 0700 DirBuilder (critic 10).
  - Relay tests are untouched.
- **Step 2, body lines (Q1):**
  - phase1:200 `fs::read_dir(&dir.0)` → `common::walk(&dir.0)`;
  - 222 and 226 `dir.0.join("b.db")` → `dir.0.join("b/b.db")` (226 is inside `assert!`, and only the path changes);
  - 276 and 463 `dir.0.join("a.db")` → `dir.0.join("a/a.db")`;
  - phase1 282, 611 and 776 get a `.confirm_active().unwrap()` line;
  - the FFI `.unlock(&dek).unwrap()` sites become `unlock_active(..)` (phase2 26, 39; ffi 139, 263, 325, 428, 499, 508; phase3 255, 392, 403); phase2 167 and 347 get `, TEST_IDLE`;
  - N6: 4 error assertions get `, TEST_IDLE`.
- **Step 3:**
  - `class_a()`; `unlock_active` and `User::new` also call `report_environment(class_a())`;
  - N5: store/tests.rs:189 `"Integer(3)"` → `"Integer(4)"`; store/tests.rs:265 and phase2.rs:344 restore 4.

## 8. Swift changes per step

- **Step 1: none.** The bindings are byte-identical.
- **Step 2:**
  - `UnlockService`: `unlock(dek:idleSecs:)`.
  - `LockController`: confirm, the `isLocked()` poll, `.unlockExpired`.
  - `LockState.rustIdleSecs`.
  - `BrevApplication.noteActivity` with the throttle.
  - `AppDelegate`: adopt/reset wiring. In the `route()` catch: `.Unsafe` → `NoticeViewController(L10n.launchErrorUnsafe)` (an existing string); `.Busy` → the existing second-instance path; anything else → damaged, as today.
  - `LaunchGuard.unsafePrefixes += "DYLD_"` (Q2).
  - app/Tests/main.swift, Tests/Lock/main.swift, tools/viewhost/main.swift and touchid-probe/main.swift: 0700 dirs (`attributes: [.posixPermissions: 0o700]`), `idleSecs`, and `confirmActive()` wherever `!isLocked()` is expected after an unlock.
  - test.sh and viewhost/build.sh link the test archive.
- **Step 3:**
  - `App/EnvironmentProbe.swift` fills `EnvironmentReport` from what happened:
    - key origin: `kSecAttrTokenID == kSecAttrTokenIDSecureEnclave` on the identity key → `.secureEnclave`, otherwise `.software`;
    - `biometricUsed`: set by UnlockService for this unlock generation;
    - `captureExcluded`: `sharingType == .none` plus the layers' `preventsCapture`;
    - `secureInputActive`: `IsSecureEventInputEnabled()`;
    - `syntheticInputRejected`: `NSApp is BrevApplication`;
    - `accessibilityOpaque`: the content views expose no AX value;
    - `pasteboardDisabled`: no Copy/Cut/Paste reaches content.
  - `ComposeSheet.send()` calls `reportEnvironment` on main right before `prepareSend`.
  - `.Environment` → the existing `compose.error` text.
  - The harness, lock probe and view host report `.software` honestly and link the allow-software-keys test archive.

## 9. Done-checks (repo root; `B=$SCRATCH/split-base`)

**Baseline (ab2f14d, before step 1):**
```
scripts/gen-bindings.sh && mkdir -p $B && cp app/Generated/BrevCore{.swift,FFI.h,FFI.modulemap} $B/
cargo test --manifest-path core/Cargo.toml --workspace -- --list 2>/dev/null | grep ': test$' | sed -E 's/: test$//; s/.*:://' | sort > $B/tests.txt
cargo test --manifest-path core/Cargo.toml --workspace 2>&1 | grep -E '^test result' > $B/results.txt
scripts/build.sh && nm -gU "$APP/Contents/MacOS/Brev" | grep -E '(uniffi|ffi)_brev_core' | sort > $B/syms.txt
codesign -d --entitlements - --xml "$APP" > $B/ent.xml; plutil -convert xml1 -o $B/info.xml "$APP/Contents/Info.plist"
```

**Step 1:**
1. `scripts/gen-bindings.sh && for f in BrevCore.swift BrevCoreFFI.h BrevCoreFFI.modulemap; do cmp app/Generated/$f $B/$f; done` prints nothing.
2. The same `--list` pipeline `diff`s clean against `$B/tests.txt`, and the passed totals are the same (the 3 doctests are now in brev_vault).
3. `scripts/test.sh` passes, including check-vault-deps.sh, its control, and `2 passed` for the release scrub test.
4. `scripts/build.sh`: syms, ent and info are identical to `$B`, and `nm Brev | grep -q zeroizing_alloc5WIPER` finds it.
5. `cargo tree -p brev-relay -e features | grep -c 'zeroing-allocator'` gives 0.
6. `wc -l` of `core/brev-vault/src/**/*.rs` < `core/brev-mail/src/**/*.rs`, reported with and without tests.
7. `grep -rn uniffi core/brev-vault` finds nothing.
8. `tools/verify/build.sh --check` passes.

**Step 2:**
1. `cargo test --manifest-path core/Cargo.toml --workspace --no-default-features` passes, with the (a) to (e) tests.
2. `cargo test --manifest-path core/Cargo.toml -p brev-vault --features launch-guard --lib launch` passes.
3. `scripts/test.sh` passes: the harness 5×N, the lock probe, and the test-cdylib bindings (patched) `cmp` the app ones.
4. `diff $B/step1-BrevCore.swift app/Generated/BrevCore.swift` shows only `unlock(dek:idleSecs:)`, `confirmActive`, `noteActivity`, `Busy`, `Unsafe`.
5. `scripts/build.sh` and `tools/verify/build.sh --check` pass.

**Step 3:**
1. The same test commands pass.
2. The classify tests cover A, the five single-flag B cases, and C.
3. `! grep -aq BREV-ALLOW-SOFTWARE-KEYS core/target/release/libbrev_core.a && grep -aq BREV-ALLOW-SOFTWARE-KEYS core/target/test-archive/release/libbrev_core.a`.
4. The Xcode phase is proven by a one-off: copy the test archive over the app path, run `xcodebuild -configuration Release`, and it must fail. Then rerun gen-bindings.sh.
5. V18's padcheck says `ok` on a v4 store (VERIFY row, run by the owner).

**DoD:**
- all of the above;
- the machine VERIFY rows (`grep -nE '\| A \|' docs/VERIFY.md`, 26 rows) are run, and the H+A rows (V51 among them) are listed for the owner;
- a DECISIONS entry (the next free D-number): the split and the naming evidence, the module-path rule, the dir flock, the check order, the timer design (two clocks, join, epoch), the features, schema v4, the release guard;
- ARCHITECTURE-REUSE.md: §1/§2 "is in brev-vault / brev-mail"; §3 rows show what Rust now enforces; §4 blockers reworded;
- the CLAUDE.md §2 and THREAT_MODEL.md bullet.

## 10. Risks (raised, not worked around)

- **R1. Module path in checksums.** No exported item leaves `brev_core::ffi` (or the crate root, for `ping`).
- **R2. One store per directory** (step 2a). The app has one folder with one `brev.db`, so this is fine there. The tests need §7's changes (Q1).
- **R3. Rust cannot blank the screen.** If Rust locks first, content stays on screen until Swift's 15 s poll sees `isLocked()` (Q3).
- **R4. The 2 s confirm window** runs from Rust's `unlock` return to main's `endUnlock`. In between on onboarding: `storeWrapped` and `saveFingersHint` (keychain writes), plus a busy main thread. If it goes over 2 s, the user needs a second Touch ID. The lock probe logs the latency. If it gets close, reordering is a Swift change for the owner.
- **R5. `env_class` is not bound into the AD.** A process that can write the file can change it. It is informational, like `read`.
- **R6. brev-proto's graph grows:** rusqlite, chacha20poly1305, poly1305, rand, zeroize and thiserror through the vault (for padding). The relay already has rusqlite and thiserror. The MSRV for the whole workspace becomes 1.89 in step 2.
- **R7. Two archives.** The harness, lock probe and view host link the test archive (launch guard off; step 3 adds allow-software-keys). The only cfg differences are these two features. test.sh counts the `cfg(feature = "launch-guard")` and `cfg(feature = "allow-software-keys")` sites, so a new one is noticed.
- **R8. The vault still carries Brev's meaning:** `COLUMN_LABEL = "brev/v0/column/"` is in every stored AD, and `CHUNK = 960`. Changing either is a format change. ARCHITECTURE-REUSE.md will say so.
- **R9. `Busy` after reset** while an old `Brev` is still alive (a `sync` in flight for up to 15 s). Onboarding's `create` then gets `Busy`, which Swift shows as retry. The timer does not keep the flock, because of the join.
- **R10. flock on a directory inside the App Sandbox container** was tested only outside the sandbox. The first real-app run (an H row) confirms it. If it fails, the app shows `Io`/damaged, which must be caught before step 2 is merged.

## Questions for the owner

- **Q1. Test bodies (critic 1, N6).** A directory lock means one store per folder. phase1 needs 5 path lines changed (200, 222, 226, 276, 463; 226 is inside an `assert!`, and only its path changes) plus 3 added `confirm_active()` lines. The FFI `unlock(dek, idle_secs)` you specified adds `, TEST_IDLE` to 4 error assertions. Step 3's schema bump changes store/tests.rs:189 (`Integer(3)` → `Integer(4)`) and two restore lines. No assertion changes its condition. OK?
- **Q2. Add `DYLD_` to Swift's LaunchGuard?** Debug runs from Xcode set DYLD_* variables. Rust would then refuse to unlock, unless Swift strips them and re-executes.
- **Q3. Rust idle time.** 320 s (Swift's 300 s + its 15 s poll + 5 s), with Swift also polling `isLocked()`? Or exactly 300 s, where the screen can show content for up to about 15 s after Rust's wipe?
- **Q4. Existing v3 stores.** After schema v4 they open as `Corrupt` and must be reset, as for v3 (D-0045). Or do you want a migration?
- **Q5. MockTransport.** Plain `cfg(test)` cannot reach phase1.rs, which is an integration test. Pick one: a `test-hooks` feature (no test changes; the release checks prove it is off in the app), or include the file from tests/common via `include!` (literal `cfg(test)`, and phase1's import line changes).
- **Q6. New errors and UI.** Are the names `Busy`, `Unsafe` (for both b and c) and `Environment` OK? And may they reuse the existing strings (second instance, `launchErrorUnsafe`, `compose.error`)?

## Owner answers (2026-09-28)

Yes to all six recommendations above:
- Q1: the listed test-body changes are accepted (no assertion changes its condition).
- Q2: Swift's LaunchGuard strips `DYLD_*` and re-executes once. **Addition:** in Debug builds it logs clearly when it strips `DYLD_*` and restarts, so odd Debug behaviour is traceable.
- Q3: Rust idle time 320 s; Swift keeps locking at 300 s and also polls `isLocked()` to blank the screen if Rust locked first.
- Q4: v3 stores open as `Corrupt` and must be reset; no migration.
- Q5: a `test-hooks` feature carries `MockTransport`; release checks prove it is off in the app.
- Q6: error names `Busy`, `Unsafe`, `Environment`. **Addition:** `Environment` carries which report field(s) failed, and the Swift screen text names them (for example «opptaksvern av»), not a generic compose error.

Earlier owner additions that still apply: a build-time check fails if `allow-software-keys` is on in a release build; CLAUDE.md §2 (and its copy docs/THREAT_MODEL.md) notes that the class-A rule catches Swift bugs, not attackers, until attestation lands; `note_activity()` is called only for input that already passed the synthetic-event filter.
