# Brev Phase 2: "The locked UI" (final design)

Superseded in part (2026-09-28): the key files and HPKE (§5, and every mention of `identity.se`, `kek.se`, `dek.hpke`, the rogue-Brev test R and the anchor A) by keychain keys and ECIES (D-0035), and drawing in `draw(_:)` or into a bitmap by the protected content layer (D-0034); planned decision numbers shift by three. See the notes at the top of §13, and docs/VERIFY.md "Changes from the design".

Status: final after review, 2026-09-27. Based on branch `claude/laughing-knuth-yhp8ji` at `d1c800d`. Inputs: CLAUDE.md as of `d1c800d`, docs/DECISIONS.md D-0001 to D-0032, `core/`, `app/`, `scripts/`, the enclave and ffi spikes (the skeptics' corrections override the original claims), the lead's rulings R1 to R6, and 34 review findings (dispositions are returned separately).

The owner accepted A1 to A7 in **D-0032**. CLAUDE.md §1.9, §2, §3.1 to §3.3, §4 and §5 already say so. This design treats them as settled: key files plus HPKE, key files not bound to Brev, `.biometryCurrentSet`, `zeroizing-alloc`, patched bindings, framework copies as residual risk, and padded storage (schema v2). Still open: the GUI facts U1 to U4 and the owner questions at the end.

Scratch roots: `S = …/scratchpad/p2/design` (first pass) and `R = S/revise` (this pass), under the session scratchpad
`/private/tmp/claude-503/-Users-andypandy/01f11233-b284-49b2-9c90-391fa2f358ef/scratchpad/p2/`. That directory is volatile;
a copy of its sources (no build output) is in `~/BREV-phase2-scratch.tgz` (unpack: `tar -xzf ~/BREV-phase2-scratch.tgz -C <dir>`).
Starting-point code referenced below is copied into the repo by the work package that uses it.

## 0. What was verified (CLI only: no window, no prompt, no posted event, repo untouched)

| Proof | Result |
|---|---|
| Revised Rust surface `R/core` (§2): padding in `seal_column`/`open_column`, `SCHEMA_VERSION = 2`, drop-guard `unlock`, poison handling, smaller surface | `cargo test --workspace`: 43 pass (brev-core 25 unit + 11 integration + 3 doc, brev-proto 4). Two Phase 1 tests change on purpose (a column is now 256 B long; `user_version` is 2); one `create_and_open_refuse_bad_files` case now uses version 1 as the bad version. Clippy `-D warnings` is clean (the sketch allows `missing_docs`) |
| New tests in `R/core/brev-core/src/ffi.rs` | `locked_session_refuses_every_export`, `panic_in_unlock_locks_all_scrubs_and_poison_returns_locked`, `unlock_scrubs_deep_on_every_path`, `echo_pump_holds_no_plaintext_after_sync`: all pass |
| Bindings from `R/core`, uniffi 0.32.2, then `S/patch-bindings.py` | each patch applies exactly once; a second run exits 1 ("already patched") |
| FFI surface grep (§11) on the generated Swift | `^(public \|open )(static )?func .*String` finds exactly `create(dir: String…)`, `open(dir: String)` and `ping() -> String`. There are 0 `public var x: String` record fields (the two `errorDescription: String?` are excluded) |
| Glyph residue (finding confirmed) | The first pass's harness never looked for glyph ids. With a glyph needle (`R/swift/Harness/main.swift`), per-line drawing plus a flush by length (first the recorded lengths, then every length 1…448, typesetter and line) leaves **29 to 57 glyph hits after lock** at 4 KiB and 64 KiB bodies in every run (10 of 10 per build). In isolation (`R/ct/main.swift`) the same flush clears them in some runs and leaves 21 in others |
| What clears it | `MallocScribble=1` (documented in `malloc(3)`: freed blocks are filled with 0x55) removes all glyph residue after lock (`R/ct`: 0 in every run, also with a `codesign -o runtime` copy). The full harness uses CTLine-only line breaking (§6.4), a 1…448 filler sweep (4 ms) and `MallocScribble=1`: **0 UTF-8 / 0 UTF-16 / 0 glyph hits after lock in 8 of 8 runs** at 64, 200, 4 096 and 65 000 units. The same was true with `CTTypesetter` breaking in that build. One earlier build that used `CTTypesetter` left 2 live UTF-16 hits at 64 units in 10 of 10 runs, and scribbling does not remove live memory. That is why this design drops the typesetter (§6.4) |
| Typing path (`R/ct/typed.swift`) | `CTTypesetter` over growing text keeps a live UTF-16 copy of recent text (7 hits at 300 units); a later typesetter over filler replaces it. `CTLine` alone keeps none |
| Norwegian keys, headless (`R/keytr.swift`: `TISCreateInputSourceList` + `UCKeyTranslate`) | dead keys are 24 (´, ⇧ `) and 30 (¨, ⇧ ^, ⌥ ~). Results: ´+e → é, ¨+u → ü, ⇧´+e → è, ⌥¨ then n → ñ, ´ then space → ´. æ/ø/å are keys 39/41/33 (⇧ gives Æ Ø Å). @ is key 42 with no modifier, $ is ⇧4, \| is ⌥7, \\ is ⇧⌥7, [ ] are ⌥8/⌥9, { } are ⇧⌥8/⇧⌥9. **⌥2 gives ™, not @** (the first draft was wrong) |
| CGEvent fields, in memory only (`S/critic-macos/pidfield`) | A CGEvent made in-process gets the **creating process's PID** in `.eventSourceUnixProcessID`. That field, and `.eventSourceStateID`, can be set to any value (0, another PID, the HID state 1). Whether the window server rewrites them when an event is posted is unknown (U2) |
| `xcrun swiftc -typecheck -target arm64-apple-macos14.0 R/AppRevise.swift` | passes. Covers `BrevApplication.sendEvent` + `nextEvent` filter, `HumanButton.sendAction` gating plus the cell override, common-mode timers, launch hygiene, `O_EXLOCK` instance lock, `isExcludedFromBackup`, `cancelTracking` |

Limits: CLI processes only; a software HPKE key, not the Enclave; 16-byte markers and one 16-glyph needle; the sandboxed hardened app itself has not been run (the Verify build in §10 V39 covers that).

## 1. Scope

### 1.1 CLAUDE.md §5 Phase 2, line by line

| §5 line | Built by | § / WP |
|---|---|---|
| Onboarding explains "no backup, Touch ID only" (and fingerprint changes, §1.9) in Norwegian; creates Enclave keys; wraps a fresh DEK | `OnboardingViewController`, `Enclave`, `KeyStore`, `Brev::create` | §5, WP5 |
| Unlock screen → Touch ID → `core.unlock(dek)` | `UnlockViewController`, `UnlockService`, `Brev::unlock(&[u8])` | §5, WP5 |
| Three-pane AppKit window; content panes use `SecureTextView` | `MailViewController`, `SecureListView`, `LetterStackView`, `SecureTextView` | §7, WP7 |
| Compose sheet with `SecureComposeView` (secure input, synthetic rejection, no pasteboard, no autocorrect, `writingToolsBehavior = .none`) | `ComposeSheet`, `SecureComposeView`, `EditModel`, `KeyTranslator`, `SecureInput`, `BrevApplication` | §7, §8, WP6, WP8 |
| Window capture exclusion, auto-lock, blank-on-lock | `Hardening`, `LockController`, `RootViewController` | §8, WP3, WP10, WP11 |
| Two contacts hard-coded through `MockTransport` | `echo.rs`, `Brev::sync` | §9, WP1 |
| Stored content padded to the envelope buckets with `brev-proto`'s function (schema v2), before any real store exists | `brev-proto::pad_into/unpad`, `seal_column`/`open_column` | §2.8, WP1 |
| `docs/VERIFY.md` written and run | §10 | WP0, WP12 |
| DoD: checklist passes; build is sandboxed and hardened | V1 to V3 plus all rows | WP12 |

### 1.2 Items Phase 1 deferred to Phase 2

| Deferred item | Resolution |
|---|---|
| FFI copies: `RustBuffer` freed without zeroing; `read_body`/`unlock` must not be exported as they are | content comes out only through `OpenText` 960-byte chunks and goes in only as `&[u8]`; zeroing allocator; binding patches (§2, §3) |
| `lock()` cannot wipe a `Plaintext` the caller holds | `OpenText` registry; `lock()` closes every open text (§2.4) |
| `create` is not crash-atomic | `dek.hpke` is written last, after the first successful unlock; known-name cleanup before every onboarding attempt (§5.2, §5.3) |
| D-0007/§6: second capture defence if ScreenCaptureKit behaves differently | U1 plan (§8.2) |
| D-0013: System Events could read the title and menus | `OpaqueView`, app-wide event filter, `HumanButton` (§7, §8) |
| D-0013: Debug builds have no Hardened Runtime | VERIFY runs on Release (and on the Verify config for V39) only |
| D-0028 item 2: test.sh links a stale archive | test.sh runs `gen-bindings.sh` and `xcodegen generate` first (§11) |
| Signature slot | stays empty in Phase 2 (`Unsigned`); Enclave signing is Phase 3 |

### 1.3 Explicitly out of Phase 2

Relay, network entitlement, Enclave signing, notifications (R5: when they come, the text is exactly "Ny melding"; D-0027), settings (idle time is a constant), adding contacts, identity codes, search, deletion, attachments, **replies** (every letter starts a thread; the echo still lands in that thread), **read/unread state**, drafts that survive a lock, text selection or copy of anything, VoiceOver for content, input methods (CJK), rich text, multiple windows, a universal build, notarization, an XCTest target, Phase 5 keychain storage.

## 2. Rust changes

### 2.1 Files

- `core/brev-core/src/ffi.rs` (new): exported objects, records and errors. Start from `R/core/brev-core/src/ffi.rs`.
- `core/brev-core/src/echo.rs` (new, removed in Phase 3): `Peer`, `peer_dek`, the peers' names and file names, `pump`.
- `core/brev-core/src/lib.rs`: `mod ffi; mod echo;`, re-exports, `#[global_allocator]`.
- `core/brev-core/src/crypto.rs`: `scrub_stack_deep()` (64 KiB, counted in test builds); `pad()` plus padding inside `seal_column`/`open_column`.
- `core/brev-core/src/store.rs`: `Core::thread_of(MessageId) -> Result<ThreadId, Error>` (gated, metadata only); `create` opens its new file with `OpenOptionsExt::mode(0o600)` (safe code; SQLite gives journals the database file's mode); `SCHEMA_VERSION = 2`.
- `core/brev-proto/src/lib.rs`: `MAX_PADDED`, `padded_len`, `pad_into`, `unpad`, `PadError`.
- `core/Cargo.toml`, `brev-core/Cargo.toml`: `zeroizing-alloc = "0.1.1"` (approved in §4).
- `core/brev-core/tests/phase2.rs` (new); the `phase1.rs` expectations named in §0.

### 2.2 The UniFFI surface (exact)

```rust
pub const CHUNK: usize = 960;          // bytes per OpenText::chunk, always exactly this
pub const MAX_SUBJECT: usize = 256;    // UTF-8 bytes
pub const MAX_BODY: usize = 65_536;    // UTF-8 bytes

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum BrevError { Locked, WrongKey, Crypto, NotFound, Duplicate, Malformed, Corrupt, Signing, Rng, Io, Storage }
impl From<crate::Error> for BrevError { /* 1:1; Io(_) and Storage(_) drop their inner error */ }

#[derive(uniffi::Record)] pub struct Limits { pub max_subject: u32, pub max_body: u32, pub chunk: u32 }
#[derive(uniffi::Record)] pub struct ContactRow { pub id: Vec<u8>, pub name: Arc<OpenText> }
#[derive(uniffi::Record)] pub struct ThreadRow { pub id: Vec<u8>, pub contact: Vec<u8>, pub created_at: i64,
                                                 pub subject: Arc<OpenText> }
#[derive(uniffi::Record)] pub struct MessageRow { pub id: Vec<u8>, pub created_at: i64, pub outgoing: bool }

#[uniffi::export] pub fn ping() -> String;          // unchanged, content-free
#[uniffi::export] pub fn limits() -> Limits;

#[derive(uniffi::Object)] pub struct OpenText { plain: Mutex<Option<Plaintext>> }
#[uniffi::export] impl OpenText {
    pub fn byte_len(&self) -> u32;                                   // 0 once closed
    pub fn chunk(&self, index: u32) -> Result<Vec<u8>, BrevError>;   // exactly CHUNK bytes, zero-padded
    pub fn close(&self);                                             // wipes now; idempotent
}

#[derive(uniffi::Object)] pub struct Brev { s: Mutex<Session> }
#[uniffi::export] impl Brev {
    #[uniffi::constructor] pub fn create(dir: String, dek: &[u8], signing_key: &[u8]) -> Result<Arc<Brev>, BrevError>;
    #[uniffi::constructor] pub fn open(dir: String) -> Result<Arc<Brev>, BrevError>;
    pub fn unlock(&self, dek: &[u8]) -> Result<(), BrevError>;
    pub fn lock(&self);
    pub fn is_locked(&self) -> bool;
    pub fn contacts(&self) -> Result<Vec<ContactRow>, BrevError>;
    pub fn threads(&self, contact: Vec<u8>) -> Result<Vec<ThreadRow>, BrevError>;
    pub fn messages(&self, thread: Vec<u8>) -> Result<Vec<MessageRow>, BrevError>;
    pub fn open_body(&self, message: Vec<u8>) -> Result<Arc<OpenText>, BrevError>;
    pub fn send_new(&self, contact: Vec<u8>, subject: &[u8], subject_len: u32,
                    body: &[u8], body_len: u32) -> Result<Vec<u8>, BrevError>;   // returns the thread id
    pub fn sync(&self) -> Result<u32, BrevError>;                              // letters that arrived
}
```

In Swift these become `Brev.create(dir:dek:signingKey:)`, `Brev.open(dir:)`, `unlock(dek:)`, `openBody(message:)`, `sendNew(contact:subject:subjectLen:body:bodyLen:)`, `OpenText.chunk(index:)` and `BrevError.Locked`.

Rules the surface encodes:
- **No `String` carries content** in either direction. The only `String`s are `ping()` and `dir` (test.sh enforces this, §11).
- **Content in** is `&[u8]` only (zero-copy `ForeignBytes`), passed as *(whole buffer, used length)*. Swift hands over its fixed `SecretBytes` allocation, which is at least 64 bytes, so Foundation never stores it as inline `Data`. Rust uses `&buf[..len]` and returns `Malformed` if `len > buf.len()` or the length is over the limit. The DEK is exactly 32 bytes of heap `Data`.
- **Content out** only through `OpenText.chunk`, always exactly 960 bytes. Every buffer on both sides stays at or under 1 KiB. This is defence in depth on top of the allocator and the patches.
- **Errors are unit variants**: only a variant index crosses.
- Records carry ids and metadata only; every name, subject and body is an `OpenText` handle.

### 2.3 Semantics

- `create`: `dir` is absolute (`…/Application Support/Brev`). Each `Core::create` refuses a file that already exists (`create_new`), so `create` fails rather than overwrite. It creates `brev.db` and both peer stores (§9), adds each peer as a contact of the user and the user ("Deg") to each peer, **locks everything** and returns the session locked. The DEK is copied into `Zeroizing<[u8;32]>`, and `Core::create` zeroes its argument. `signing_key` is the Enclave identity key's `x963Representation` (65 bytes; Phase 1 accepts 1 to 255). On error, `Core::create` removes the file it was making, and Swift's known-name cleanup (§5.2) removes anything an earlier step left.
- `open`: opens all three stores locked. A foreign or v1 store gives `Corrupt`.
- `unlock`: a DEK that is not 32 bytes gives `WrongKey`. It derives both peer keys, unlocks the user core, then the peers. A `Finish` drop guard runs on **every** exit, including a panic unwind: it calls `lock_all()` unless the unlock succeeded, then `scrub_stack_deep()`.
- Poisoned mutex: `Brev::session()` recovers the guard, runs `lock_all()`, clears the poison and returns `Locked`. `lock()` and `Drop` recover and lock; they never fail. Swift calls `brev.lock()` after **any** error thrown by `unlock` (a Rust panic arrives as a thrown internal error).
- `lock`: closes every registered `OpenText`, then locks the three cores (DEKs zeroed, 16 KiB scrub each).
- `threads(contact)` is Phase 1 `threads()` filtered by contact. `open_body` is Phase 1 `read_body` wrapped in a registered `OpenText`. `send_new` is `new_thread` + `send` with the `Unsigned` signer (an empty signature; nothing verifies before Phase 3, D-0019), and the envelope goes to the peer whose bundle id equals `env.recipient`. `sync` is described in §9.

### 2.4 `OpenText` and the lock registry

`Session { me: Core, peers: Vec<Peer>, open: Vec<Weak<OpenText>> }`. Every `OpenText` is made by `Session::register(Plaintext)`, which prunes dead `Weak`s. `lock_all()` upgrades each one and calls `close()`. After that `chunk()` returns `Locked` and `byte_len()` returns 0, even for a handle Swift still holds. Swift reads a text completely and closes it at once (§6.3 rule 6), so the registry is a safety net; Rust holds no content between calls on the normal path.

### 2.5 `unlock(&[u8])` and the 64 KiB scrub (R2)

`scrub_stack_deep()` is `scrub_stack()` with a 64 KiB buffer (same `black_box` + `zeroize`). It is called only from `Finish::drop`. Test builds count calls, and a release test proves the wipe survives the optimiser. Swift calls `Enclave.unwrap` and `brev.unlock` back to back in one closure on the unlock queue (§5.4), so Rust's frames reuse the stack the Enclave call used. The depth is still unproven for **this** path: the spike's 16 to 64 KiB residue came from `SecKeyCopyKeyExchangeResult` (rows copied by hand), and Rust's scrub starts below the closure, binding and scaffolding frames. The Touch ID probe (§14.2 K) measures the exact §5.4 closure. If residue remains, the probe is repeated at 128 KiB, and the depth change goes to the owner, because §2's text says 64 KiB.

### 2.6 Zeroing allocator

`lib.rs`: `#[global_allocator] static ALLOC: zeroizing_alloc::ZeroAlloc<std::alloc::System> = zeroizing_alloc::ZeroAlloc(std::alloc::System);`. This is safe code, and `#![forbid(unsafe_code)]` stays. It zeroes every Rust free, including the `RustBuffer`s Swift frees through `rustbuffer_free`. test.sh checks that `cargo tree -p brev-core` contains `zeroizing-alloc`. All Phase 1 tests pass with it (§0).

### 2.7 Echo peers

See §9. `echo.rs` holds `Peer { core: Core, mine: MockTransport, theirs: MockTransport }`, `peer_dek(dek, index)` (HKDF-SHA256 from the approved `hkdf`, info `"brev/v0/demo-peer/" ‖ index`, `scrub_stack` after) and `pump`. There is no new crypto helper in `crypto.rs`.

### 2.8 Padding of stored columns

`brev-proto` (no new dependency; the caller owns and wipes the buffer; proven in `R/core/brev-proto`):

```rust
pub const MAX_PADDED: usize = 1 << 20;
pub fn padded_len(n: usize) -> Option<usize>;   // 4+n → 256, 1024, 4096, 16384, then ×16384; None above MAX_PADDED
pub fn pad_into(content: &[u8], out: &mut [u8]) -> Result<(), PadError>;   // u32 BE len ‖ content ‖ zeros
pub fn unpad(padded: &[u8]) -> Result<&[u8], PadError>;  // refuses anything pad_into could not have written
pub enum PadError { Size, Malformed }
```

`seal_column` pads into a `Zeroizing<Vec<u8>>` of exact length before encrypting. `open_column` unpads into a new `Plaintext` of exact length (a bad pad is `Crypto`), and the padded `Plaintext` is dropped and wiped. **All** sealed columns are padded (names, subjects, bodies, identity keys, bundles): one code path, and key rows leak no lengths. A 64 KiB body pads to 80 KiB. Phase 3's envelope reuses the same functions.

### 2.9 Schema and versions

The `SCHEMA` text is unchanged (D-0023's text comparison is untouched). `SCHEMA_VERSION = 2` because the column format changed; v1 stores open as `Corrupt`. No v1 store exists outside tests, because padding lands in WP1, before any app code creates a store. `PROTOCOL_VERSION` stays 0.

### 2.10 Crash-atomic creation

Nothing counts as installed until `dek.hpke` exists. It is written last, after the new store has been unlocked once with Touch ID (§5.3). A crash anywhere before that leaves no `dek.hpke`, and the next attempt deletes the known leftover files first (§5.2).

### 2.11 Rust tests to add

In `ffi.rs` unit tests (they need `cfg(test)` hooks); the first four exist in `R/core`:
1. `locked_session_refuses_every_export`: after `lock()`, every method except `create`, `open`, `unlock`, `lock` and `is_locked` returns `Locked`, and all three cores are locked.
2. `panic_in_unlock_locks_all_scrubs_and_poison_returns_locked` (a `cfg(test)` flag panics after the user core unlocked).
3. `unlock_scrubs_deep_on_every_path` (31, 33, zero and wrong DEKs, then success; a wrong DEK on an unlocked session ends with everything locked).
4. `echo_pump_holds_no_plaintext_after_sync`. Also, in `cfg(test)`, `pump` records `live_plaintexts()` at every `theirs.send`, and the test asserts it was 0 each time.
5. `scrub_stack_deep_wipes_its_buffer` (also `--release`).

In `tests/phase2.rs` (public API):
6. `create_returns_locked_session_with_two_contacts` (after unlock: "Ekko" and "Speil").
7. `lock_closes_every_open_text` (a kept handle gives `Locked` and `byte_len` 0; live `Plaintext` is 0).
8. `chunk_is_exactly_960_zero_padded` (reassembles; out of range gives `Malformed`; an empty text has no chunk).
9. `send_uses_only_the_length_prefix` (a marker after `len` is stored nowhere; `len > buf.len()` and over-limit give `Malformed`).
10. `sync_echoes_each_letter_once_into_the_same_thread` (both peers; locked `sync` returns `Locked` and drains nothing).
11. `create_refuses_existing_files`; `store_files_are_0600`; `no_plaintext_in_any_file` over all three stores.
12. Padding: proto boundaries (0, 252, 253, 1020, 1021, 16380, 16381, MAX−4, MAX−3); `column_lengths_are_bucketed` (every sealed column is nonce + bucket + tag); `v1_store_is_refused`.

## 3. Bindings: the patch step

`scripts/patch-bindings.py <BrevCore.swift>` (start from `S/patch-bindings.py`) is called by `gen-bindings.sh` right after bindgen. It rewrites the file in place (temp file + rename).

| Patch | Stock code | Patched |
|---|---|---|
| A | `RustBuffer.deallocate()` frees without wiping | `memset_s` over `capacity`, then `rustbuffer_free` |
| B | `FfiConverterRustBuffer.lift` frees only on success | `defer { buf.deallocate() }`, so throw paths wipe and free too |
| C | `lower` leaves the writer `[UInt8]` unwiped | wipe the writer after `RustBuffer(bytes:)` |
| D | `FfiConverterData.read` is `Data(readBytes(...))` (a temporary array) | one copy straight into the returned `Data` |

Drift protection; each of these fails the build:
1. Every pattern must match exactly once.
2. Post-check: each inserted line appears exactly once, and `Data(try readBytes(` is gone.
3. A first-line marker is added; running on a patched file is refused (verified, exit 1).
4. `gen-bindings.sh` reads the `uniffi` version from `core/Cargo.lock` and refuses anything but `PATCHED_FOR_UNIFFI=0.32.2`, with the message "uniffi changed: re-check scripts/patch-bindings.py and the heap-scan harness, then update PATCHED_FOR_UNIFFI".
5. test.sh greps `app/Generated/BrevCore.swift` for the marker.

`gen-bindings.sh` checks `command -v python3` and names the fix if it is missing.

## 4. Swift architecture

### 4.1 Files under `app/Sources` (AppKit only; no SwiftUI)

`Shared/` is compiled into the app **and** into the CLI harness (`app/Tests`), so it must not import AppKit.

| File | Purpose |
|---|---|
| `main.swift` | `LaunchGuard.run()` first (§8.6); then `BrevApplication.shared`, the delegate and the menu; run |
| `AppDelegate.swift` | owns the object graph; instance lock; launch routing (§5.2); terminate → lock |
| `App/BrevApplication.swift` | `@objc(BrevApplication)` subclass: filters synthetic input in `sendEvent` **and** `nextEvent`; `inHumanDispatch` flag; human-input clock |
| `App/MainMenu.swift` | menus "Brev" and "Arkiv" (§8.5) |
| `App/Hardening.swift` | `apply(_ window:)` for every window; `NSWindow.allowsAutomaticWindowTabbing = false` |
| `App/MainWindow.swift` | existing class, now through `Hardening`, without `.miniaturizable`; holds one `RootViewController` for its whole life |
| `App/RootViewController.swift` | swaps child controllers (onboarding / unlock / mail) inside a fixed-size root, so the window never resizes |
| `App/LockController.swift` | AppKit side of locking: notifications, common-mode timers, the lock sequence; state in `LockState` |
| `App/L10n.swift` | typed accessors for `Localizable.strings` keys |
| `Keys/KeyStore.swift` | container paths, 0700 dir, `O_EXCL` 0600 writes with `F_FULLFSYNC`, install marker, known-name cleanup, reset, `.lock` instance lock, backup exclusion |
| `Keys/UnlockService.swift` | serial queue `no.brev.unlock`: unwrap → `brev.unlock` → wipe; error classification |
| `Shared/Enclave.swift` | SE key creation, HPKE wrap/unwrap, biometry hash |
| `Shared/Session.swift` | owns `Brev`; turns rows into items holding `SecretText`; send helper; `sync` |
| `Shared/SecretBytes.swift`, `Shared/SecretText.swift` | `SecretBytes`, `Data.wipe()`; UTF-16 text in a fixed buffer |
| `Shared/Transcode.swift` | UTF-8 ↔ UTF-16 without `String`; `TextReader` (`OpenText` → `SecretText`) |
| `Shared/TextLayout.swift` | CTLine-only layout and drawing in windows of at most 448 units; `GlyphFlush` |
| `Shared/EditModel.swift` | caret and edit operations over a `SecretText` (insert, delete by composed character, move by character/line/document) |
| `Shared/KeyTranslator.swift` | `UCKeyTranslate` with its own dead-key state; the layout source can be injected (current TIS layout, or a named one in tests) |
| `Shared/InputFilter.swift` | the source-PID rule over a `CGEvent?` (§8.5) |
| `Shared/LockState.swift` | `generation`, `authInFlight`, lock reasons; plain state, no AppKit |
| `Shared/LaunchGuard.swift` | argv, argument domain, environment and debug-default checks; the `MallocScribble` check |
| `UI/OpaqueView.swift` | base class: AX-opaque, no menu, no Services, no Quick Look, flipped |
| `UI/HumanButton.swift` | `NSButton` + `HumanButtonCell`: actions run only inside human dispatch (§7.1) |
| `UI/ConfirmSheet.swift` | the reset confirmation: an own hardened sheet with two `HumanButton`s (no `NSAlert`) |
| `UI/SecureTextView.swift`, `UI/SecureListView.swift`, `UI/LetterStackView.swift` | draw a letter; draw list rows; stack a thread's letters in an `NSScrollView` |
| `UI/MailViewController.swift` | split view with the three panes and the button bar |
| `UI/ComposeSheet.swift` | the sheet window: recipient (drawn), subject, body, Send/Avbryt |
| `UI/SecureComposeView.swift`, `UI/SecureInput.swift` | the editor view; balanced `Enable/DisableSecureEventInput` |
| `UI/OnboardingViewController.swift`, `UI/UnlockViewController.swift` | onboarding pages; lock screen |
| `Verify/SelfScan.swift` | **Verify configuration only**: after every lock, scans its own task (linking `app/Tests/scan.c`) and logs hit counts |
| `nb.lproj/Localizable.strings` | every user-facing string (§5.6) |

`project.yml`: `NSPrincipalClass: BrevApplication`; `LSEnvironment: {MallocScribble: "1"}` (§6.4); a third configuration `Verify` (Release settings plus `SWIFT_ACTIVE_COMPILATION_CONDITIONS = BREV_SELFSCAN`, its own bridging header that also imports `scan.h`); `EXCLUDED_SOURCE_FILE_NAMES = SelfScan.swift scan.c` in Debug and Release. `build.sh` never builds Verify; `tools/verify/build.sh` does. Carbon (HIToolbox), Core Text and Core Graphics are the system frameworks §3.2 already names.

### 4.2 Object graph

```
main.swift ── LaunchGuard ── BrevApplication.shared ── AppDelegate (strong top-level let)
AppDelegate
 ├─ instanceLock: Int32 (fd with O_EXLOCK, held for the process lifetime)
 ├─ keyStore: KeyStore            (paths and files; no secrets)
 ├─ session: Session?             (the ONLY owner of the Rust `Brev` handle)
 ├─ unlock: UnlockService         (serial queue)
 ├─ lock: LockController          (LockState; weak refs to window and session; timers)
 └─ window: MainWindow ── root: RootViewController ── child ∈
       OnboardingViewController | UnlockViewController | MailViewController
            MailViewController ── contacts: SecureListView, threads: SecureListView,
                                  letters: LetterStackView ── [SecureTextView]
            └─ presents ComposeSheet (own hardened NSWindow) ── recipient OpaqueView, SecureComposeView ×2
```

Views own their `SecretText`s and wipe them; they never hold `Brev` or `OpenText`. The Enclave key objects exist only inside `Enclave`/`UnlockService` calls; blobs are read from files on each use.

### 4.3 Threading

- Main thread: all UI, all `Brev` calls except the two below, `SecureInput`, the lock sequence, `GlyphFlush`.
- `UnlockService` queue: onboarding key creation + `Brev.create`, and every unlock (`Enclave.unwrap`, which blocks during Touch ID, then `brev.unlock`, then the wipe) in **one closure**, so R2's same-thread rule holds. Results return to main with `DispatchQueue.main.async`.
- Rust serialises everything with the session mutex. A `lock()` on main is never blocked by the Touch ID prompt, because the prompt happens before `brev.unlock` takes the mutex.
- `LockState.generation` increments on every lock. An unlock that finishes under an older generation calls `brev.lock()` instead of showing mail.

## 5. Keys, onboarding and unlock (R1; D-0032 items 1 to 3)

### 5.1 Files in `~/Library/Containers/no.brev.app/Data/Library/Application Support/Brev/` (directory 0700, excluded from backup)

| File | Content | Size | Written |
|---|---|---|---|
| `.lock` | nothing; held with `O_EXLOCK` | 0 | every launch |
| `identity.se` | `SecureEnclave.P256.Signing.PrivateKey.dataRepresentation` | 569 B | onboarding step 5 |
| `kek.se` | `SecureEnclave.P256.KeyAgreement.PrivateKey.dataRepresentation` | 569 B | step 5 |
| `biometry.state` | enrolled-fingers hash (a hint only) | 32 B | step 5, then after **every** successful unlock (atomic) |
| `brev.db`, `peer-1.db`, `peer-2.db` | stores (ciphertext only) | – | step 6 (Rust) |
| `dek.hpke` | HPKE `encapsulatedKey (65) ‖ ciphertext+tag (48)` | 113 B | **last**, step 8 |

Both keys use `SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet])` and are created with an `LAContext` whose `interactionNotAllowed = true` (no prompt). HPKE uses `P256_SHA256_AES_GCM_256`, base mode, `info = "brev/v1/dek-wrap"`. Every new file: `open(O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0600)`, write, `fcntl(F_FULLFSYNC)`, close. `dek.hpke` and `biometry.state` go to `name.tmp`, then `rename`, then an `fsync` of the directory. No keychain item is created (an ad-hoc app gets -34018). At creation, `URLResourceValues.isExcludedFromBackup = true` is set on the folder (open question 3). A local APFS snapshot can still hold older files.

### 5.2 Launch routing

0. `LaunchGuard` has run (§8.6); an unsafe launch stops here with `launch.error.unsafe`. Take `.lock` with `O_CREAT|O_RDWR|O_EXLOCK|O_NONBLOCK|O_CLOEXEC`. On `EWOULDBLOCK`, log `second instance`, activate the running Brev through `NSRunningApplication`, and terminate.
1. `dek.hpke` exists → `Brev.open(dir)` → unlock screen. If `open` fails (`Corrupt`), show the "damaged" state (§5.5).
2. Otherwise → onboarding. **Before every onboarding attempt** (first run, *Prøv igjen*, after a reset), delete the known names: `identity.se`, `kek.se`, `biometry.state`, the three `.db` files and their `-journal` files, `dek.hpke.tmp`, `biometry.state.tmp`. Nothing else is ever deleted.

### 5.3 Onboarding (step by step)

1. **Velkommen** page, button *Fortsett*.
2. **Dette må du vite** page with the texts `touchid`, `nobackup`, `fingers` and `prompt` (§5.6). A checkbox *Jeg forstår …*; *Opprett nøkler* is enabled only when it is ticked. If `canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)` is false, show `onboarding.error.notouchid` instead and stop.
3. A filtered human click → the known-name cleanup (§5.2) → the unlock queue.
4. `Enclave.makeKeys()`.
5. Write `identity.se` and `kek.se`, and `biometry.state` if a hash is available.
6. DEK: `SecretBytes(capacity: 64)` filled by `SecRandomCopyBytes` (32 bytes). `wrapped = Enclave.wrap(dek:to: kek.publicKey)` (kept in memory; not secret). `Brev.create(dir:, dek: Data(bytesNoCopy: dek.base, count: 32, deallocator: .none), signingKey: identity.publicKey.x963Representation)` → a locked session. `dek.wipe()` in a `defer`. Any failure → `onboarding.error.failed` with *Prøv igjen* (back to step 3).
7. **Lås opp for første gang** page: *Lås opp med Touch ID* runs §5.4 with `wrapped` from memory.
8. On success: write `dek.hpke` atomically → mail window. On cancel: stay on the page. On any other failure: the error text and *Slett alt og start på nytt*. A crash or quit before this step leaves no `dek.hpke`, and §5.2 cleans up.

### 5.4 Unlock (one Touch ID prompt)

1. `UnlockViewController` shows *Brev er låst* and *Lås opp med Touch ID*. **Brev never prompts on its own** (not on launch, not on activation); only a human click or Return does.
2. On a human click: `authInFlight = true`, capture `generation`, read `kek.se` and `dek.hpke` (during onboarding, `wrapped` comes from memory). Then, on the unlock queue:
   ```swift
   let ctx = LAContext(); ctx.localizedFallbackTitle = ""; ctx.localizedCancelTitle = L10n.unlockCancel
   ctx.localizedReason = L10n.unlockReason
   let kek = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: kekBlob, authenticationContext: ctx)
   var dek = try Enclave.open(wrapped, with: kek)   // HPKE.Recipient: SE key agreement + Touch ID
   defer { dek.wipe() }
   do { try session.brev.unlock(dek: dek) } catch { session.brev.lock(); throw error }   // same thread, zero-copy
   ```
   Errors can come from `init(dataRepresentation:)` and from the HPKE step; both are caught.
3. Back on main: `authInFlight = false`. If `generation` changed → `brev.lock()`. If `NSApp.isActive` → mail window, and rewrite `biometry.state`. Otherwise → `brev.lock()` (the simple rule). WP10 adds a short wait for `didBecomeActive` only if the U4 spike shows the Touch ID panel takes activation and gives it back after the unwrap returns. Resign-active while `authInFlight` never locks (otherwise the panel itself could lock Brev during every unlock).

### 5.5 Error mapping (strings in §5.6)

| Caught | State shown |
|---|---|
| `LAError` `.userCancel/.systemCancel/.appCancel`; `TKError.canceledByUser` (-4) | back to the lock screen, no text |
| `LAError.biometryLockout` | `unlock.error.lockout` |
| `LAError.biometryNotAvailable/.biometryNotEnrolled` | `unlock.error.unavailable` |
| `BrevError.WrongKey/.Corrupt`, missing or short `kek.se`/`dek.hpke` | `unlock.error.damaged` + reset button |
| the error the spike records for an invalidated key (§14.2 U4.3) **and** `biometry.state` ≠ current hash | `unlock.error.fingers` + reset button |
| anything else | `unlock.error.retry` |

Only the reset button followed by *Slett alt* in `ConfirmSheet` deletes anything. Reset deletes the known names (§5.2) and returns to onboarding. With backup exclusion on, deleting the blobs destroys the Enclave keys unless a local snapshot still holds a copy.

### 5.6 User-facing strings (`nb.lproj/Localizable.strings`, bokmål)

| Key | Text |
|---|---|
| `onboarding.welcome.title` / `.next` | Velkommen til Brev / Fortsett |
| `onboarding.welcome.body` | Brev er for private brev mellom mennesker. Brevene kan bare leses i dette vinduet, og bare etter at du har låst opp med fingeren. |
| `onboarding.rules.title` / `.create` / `onboarding.working` | Dette må du vite / Opprett nøkler / Oppretter nøkler … |
| `onboarding.rules.touchid` | Brev låses bare opp med Touch ID. Det finnes ikke noe passord. |
| `onboarding.rules.nobackup` | Det finnes ingen sikkerhetskopi. Nøklene finnes bare på denne Macen. Mister du Macen, eller blir den nullstilt, er brevene borte for alltid. |
| `onboarding.rules.fingers` | Legger du til eller fjerner et fingeravtrykk i Touch ID, kan brevene aldri åpnes igjen. Da er både brevene og identiteten din borte. |
| `onboarding.rules.prompt` | Lås bare opp når du selv har trykket «Lås opp» i Brev. Ber et annet program om Touch ID for Brev, trykk Avbryt. |
| `onboarding.rules.confirm` | Jeg forstår at brevene ikke kan gjenopprettes |
| `onboarding.first.title` / `.body` | Lås opp for første gang / Bekreft med Touch ID at nøklene virker. Først da er Brev klar til bruk. |
| `onboarding.error.notouchid` | Brev krever Touch ID. Sett opp Touch ID i Systeminnstillinger, og åpne Brev på nytt. |
| `onboarding.error.failed` / `.retry` | Nøklene kunne ikke lages. / Prøv igjen |
| `launch.error.unsafe` | Brev ble startet på en måte som ikke er trygg, og kan ikke låses opp nå. Avslutt Brev og åpne det på nytt fra Programmer-mappen. |
| `unlock.title` / `.button` / `.cancel` | Brev er låst / Lås opp med Touch ID / Avbryt |
| `unlock.reason` | låse opp brevene dine |
| `unlock.error.retry` | Brev ble ikke låst opp. Prøv igjen. |
| `unlock.error.lockout` | Touch ID er sperret etter for mange forsøk. Lås Macen, logg inn med passordet, og prøv igjen. |
| `unlock.error.unavailable` | Touch ID er ikke tilgjengelig. Brev kan bare låses opp med Touch ID. |
| `unlock.error.fingers` | Fingeravtrykkene på denne Macen ser ut til å være endret. Da kan brevene ikke åpnes igjen. |
| `unlock.error.damaged` | Filene til Brev er skadet. Brevene kan ikke åpnes. |
| `reset.button` | Slett alt og start på nytt |
| `reset.confirm.title` / `.ok` / `.cancel` | Slette alle brev? / Slett alt / Avbryt |
| `reset.confirm.body` | Alle brev og nøkler på denne Macen blir slettet. Dette kan ikke angres. |
| `mail.new` / `mail.lock` / `mail.nothreads` | Nytt brev / Lås / Ingen brev ennå |
| `mail.sent` / `mail.received` | Sendt %@ / Mottatt %@ (a date from `DateFormatter` nb; metadata) |
| `compose.to` / `compose.subject` | Til: / Emne: |
| `compose.send` / `compose.cancel` / `compose.error` | Send / Avbryt / Brevet ble ikke sendt. Prøv igjen. |
| `menu.app.lock` / `menu.app.quit` | Lås Brev / Avslutt Brev |
| `menu.file.title` / `menu.file.new` | Arkiv / Nytt brev |
| `window.main.title` | Brev |

Only if open question 1 ends in its fallback: `onboarding.rules.gone` = «Er brevene dine plutselig borte etter at du har låst opp, så ikke skriv nye brev. Da kan et annet program ha byttet ut filene til Brev.» If the anchor works instead: `unlock.error.tampered` = «Filene til Brev er byttet ut av et annet program. Brev låses ikke opp.» macOS shows the reason as «Brev» prøver å låse opp brevene dine. "Ekko", "Speil" and "Deg" are content stored encrypted by Rust, not strings in the app.

## 6. Secret memory in Swift

### 6.1 Types (Shared; proofs in `R/swift/Shared`)

```swift
final class SecretBytes {                    // fixed allocation, never grows; a class, so no copy-on-write
    let capacity: Int                        // max(requested, 64): a Data view of it is never inline
    private(set) var count: Int; let base: UnsafeMutableRawPointer   // zero-filled, align 16
    init(capacity: Int); deinit              // deinit = wipe() + deallocate()
    func wipe()                              // memset_s(base, capacity); count = 0
    @discardableResult func append(_ src: UnsafeRawBufferPointer) -> Bool   // false if it would not fit
    func setCount(_ n: Int); func withBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R
    func withFFIView<R>(_ body: (Data, UInt32) throws -> R) rethrows -> R   // Data(bytesNoCopy: base, count: capacity,
                                             //   deallocator: .none) plus count; the Data must not escape
}
extension Data { mutating func wipe() }      // memset_s in place; only for a uniquely referenced Data
final class SecretText {                     // UTF-16 in a SecretBytes(capacity: 2 * maxUnits)
    let maxUnits: Int; var length: Int; var units: UnsafeMutablePointer<UInt16>
    @discardableResult func insert(_ u: UnsafeBufferPointer<UInt16>, at: Int) -> Bool  // memmove in place
    func delete(_ r: Range<Int>)             // memmove, then memset_s of the freed tail
    func composedRange(at i: Int, window: Int = 64) -> Range<Int>   // CF sees at most `window` units around i
    func copy() -> SecretText                // a second fixed buffer (the compose sheet's recipient)
    func wipe()
}
enum Transcode { static func utf8ToUTF16(_:into:); static func utf16ToUTF8(_:into:) }  // stdlib transcode(), U+FFFD on error
enum TextReader { static func read(_ t: OpenText) throws -> SecretText }   // chunks → wipe each → UTF-16 → close
```

### 6.2 Where every secret lives, and when it is wiped

| Secret | Lives in | Wiped |
|---|---|---|
| New DEK (onboarding) | `SecretBytes(64)` | `defer` right after `Brev.create` |
| Unwrapped DEK | the `Data` HPKE `open` returns (32 B, heap, unique) | `defer` right after `brev.unlock`, same thread |
| Received chunk | the `Data` (960 B) from `chunk(index:)` | in place, right after copying it into the UTF-8 staging buffer |
| UTF-8 staging | `SecretBytes(byte_len)` in `TextReader` | `defer` after transcoding |
| Names, subjects, bodies | `SecretText` owned by list rows and letter views | on selection change, reload, pane teardown, lock |
| Recipient name in the compose sheet | `SecretText.copy()` owned by the sheet, drawn by an `OpaqueView` | on send, cancel, lock |
| Compose subject/body | `SecretText` in `SecureComposeView` (fixed 256 / 65 536 units) | on send, cancel, lock |
| Outgoing UTF-8 | `SecretBytes(3 × units)` | `defer` after `sendNew` |
| One keystroke | 4-unit stack buffer in `keyDown` | `memset_s` before `keyDown` returns |
| One line being drawn | CF/CT objects over a no-copy window of at most 448 units | released in an `autoreleasepool` per line; freed blocks scribbled; `GlyphFlush` on lock |

### 6.3 Rules (review checklist; the grep in §11 enforces the checkable ones)

1. Content is never a `String`, `NSString`, `Substring`, `Character`, `[UInt8]` or `NSAttributedString`. No `description`, `print`, `Logger` or `fatalError` with content.
2. The only `Data` that ever holds content: FFI chunk results and the HPKE output. Each is used by one `var`, never assigned to a second variable, never appended to, and wiped in place.
3. Content arguments go out only through `SecretBytes.withFFIView`.
4. No growth: every buffer is sized once (limits from `limits()`); inserts past capacity are refused.
5. CF bridging only as `CFStringCreateWithCharactersNoCopy(nil, ptr, n, kCFAllocatorNull)` with `n ≤ 448` (this includes `composedRange`), inside an `autoreleasepool`, never bridged to `String`/`NSString`, never stored.
6. `TextReader.read` closes the `OpenText` in a `defer`; nobody keeps an `OpenText`.
7. Logs: ids, counts, error variant names and lock reasons only.
8. No `CTTypesetter`, `CTFramesetter`, `NSLayoutManager`, `NSTextView`, `NSTextField` or `NSStringDrawing` on content.

### 6.4 Per-line Core Text path

`TextLayout` (proof `R/swift/Shared/TextLayout.swift`):
- **Layout**: split at U+000A. For each paragraph, take a window of at most 448 units (not ending on a lead surrogate). Build a no-copy `CFString` → `CFAttributedString` → `CTLine`, and take `CTLineGetStringIndexForPosition(line, (width, 0))`. Back off to after the last U+0020 in the window if there is one, and never split a surrogate pair. That is one line. Only `LineRef(start, length)` integers are stored. There is **no `CTTypesetter`**, because it keeps a live copy of recent text (§0).
- **Draw**: recreate one `CTLine` per visible `LineRef` and draw it (`kCTForegroundColorFromContextAttributeName`, text matrix flipped for flipped views).
- **Malloc scribbling**: Info.plist `LSEnvironment` sets `MallocScribble=1`, so libmalloc fills every freed block with 0x55. This is what removes the glyph ids and text copies Core Text leaves in freed run storage, which libmalloc's own free handling does not clear (§0: 29 to 57 glyph hits after lock without scribbling, 0 with it). `LaunchGuard` checks the variable (§8.6).
- **`GlyphFlush.flush()`**: lays out and draws filler lines of **every** length 1…448 into a 1×1 context (4 ms measured). This replaces any live per-length buffer. It runs once in the lock sequence and when a letter view is torn down. `GlyphFlush.attrs` is the one app-wide content font.

## 7. Content views and the compose view

### 7.1 `OpaqueView` and `HumanButton` (U3)

`OpaqueView`: `isAccessibilityElement() → false`, `accessibilityChildren() → []`, `accessibilityRole/Value/Label/Title/Help/SelectedText → nil`, `accessibilityNumberOfCharacters() → 0`, `accessibilityString(for:)/accessibilityAttributedString(for:) → nil`, `accessibilityHitTest → nil`; `menu(for:) → nil`; `validRequestor(forSendType:returnType:) → nil`; `quickLook(with:)` does nothing; no drag source or destination; `isFlipped = true`. Fallback if the spike shows a leak through `NSScrollView`/`NSClipView`: make the whole content container one `OpaqueView` with no children and call `setAccessibilityElement(false)` on the scroll views.

`HumanButton` does not rely on AX internals. For a single-cell control the AX element may be the cell, so there are three layers:
1. `override func sendAction(_:to:) -> Bool` runs the action only if `BrevApplication.inHumanDispatch` is true **and** `NSApp.currentEvent` is `.leftMouseUp`, `.keyDown` or `.keyUp` and passes `InputFilter`. An AX press arrives from the AX run-loop source, outside `sendEvent`, so it is refused.
2. `HumanButtonCell.accessibilityPerformPress() → false`.
3. `HumanButton.accessibilityPerformPress() → false`.

`BrevApplication.nextEvent(matching:…)` also filters synthetic events, so a button's mouse-tracking loop only ever sees human events. There is no `NSAlert` anywhere: the reset confirmation is `ConfirmSheet` with `HumanButton`s.

### 7.2 `SecureTextView`, `SecureListView`, `LetterStackView`, `MailViewController`

- `SecureTextView`: holds `SecretText?` and a `TextLayout`; lays out again when the width changes; draws only lines that intersect `dirtyRect`. **No selection, no caret, no mouse handling.** `clear()` wipes the text and calls `needsDisplay = true`.
- `SecureListView`: fixed-height rows; each row draws the first line (at most 448 units, clipped) of its `SecretText` through `TextLayout`, plus metadata (a date from `DateFormatter` nb). Selection is of rows, never of text: click or ↑/↓. A delegate callback gets the row index.
- `LetterStackView`: the flipped document view of an `NSScrollView`. Each letter has a metadata header (*Sendt …*/*Mottatt …*, drawn by an `OpaqueView`) and a `SecureTextView`. Frames are laid out from each layout's height. Scrolling is the stock scroll view.
- `MailViewController`: `NSSplitView` (about 200 | 280 | rest) and a bar of `HumanButton`s (*Nytt brev*, *Lås*). After unlock: `contacts()` → select the first contact → its threads → the newest thread → its letters. A 3-second `sync()` timer runs in `.common` mode while unlocked. When letters arrive, the two right-hand panes reload (old texts wiped) and keep the selection by id.

### 7.3 `SecureComposeView`: primary (U2), direct key handling, no `NSTextInputClient`

- Model: an `EditModel` over one `SecretText` (subject 256 units, single line; body 65 536 units, multi-line). The UTF-8 length is recomputed after each edit; an insert that would pass the byte limit is refused with `NSSound.beep()`.
- `keyDown`: first `InputFilter` (belt and braces). ⌃ combinations are ignored. Command combinations are never text: ⌘↩ = Send; ⌘←/⌘→/⌘↑/⌘↓ = line or document start/end; every other ⌘ key (⌘C, ⌘V, ⌘X, ⌘A, ⌘Z …) does nothing, and `performKeyEquivalent` returns false. Named keys go by `keyCode`: Return 36/76 (a newline, or the next field in the subject), Delete 51 (back one composed character), Forward Delete 117, arrows 123 to 126, Tab 48 (the other field), Escape 53 (cancel). Every other key goes to `KeyTranslator.translate`, which calls `UCKeyTranslate(layout, keyCode, kUCKeyActionDown, carbon modifiers (shift, option, caps lock), LMGetKbdType(), 0, &deadKeyState, 4, &len, stackBuf)` with `TISCopyCurrentKeyboardLayoutInputSource()`. The `len` units are inserted at the caret, and the stack buffer is wiped. A dead key gives 0 units and keeps `deadKeyState`; losing focus resets it. `NSEvent.characters` is never read.
- Caret: a 1 pt bar placed with `CTLineGetOffsetForStringIndex`; no blinking; a click sets it with `CTLineGetStringIndexForPosition`. **No selection**, so nothing can be copied even in principle. The body sits in an `NSScrollView`, with `scrollToVisible(caretRect)`.
- Traits: conforms to `NSTextInputTraits` with every trait `.no` and `writingToolsBehavior = .none` (15+); `writingToolsCoordinator = nil` (15.2+); `makeTouchBar() → nil`.
- System features: dictation, the emoji and character pickers, press-and-hold, inline predictions and autocorrect all deliver text through `NSTextInputClient`. This view is not one, so they have no target. Writing Tools needs an `NSTextView` or a coordinator, and Services needs a requestor; neither exists. There is no Edit menu, which is where macOS injects Dictation, Emoji and Writing Tools items. Paste has no path.
- Secure event input: `SecureInput.enable()` when the view becomes first responder **and** its window is key **and** the app is active. `disable()` on resign first responder, window resign key, app resign active, sheet close and lock. `SecureInput` keeps its own Bool so the counted Carbon calls always balance. Main thread only.

### 7.4 `SecureComposeView`: fallback (only if U2 fails, and only after the owner accepts its cost)

Adopt `NSTextInputClient`. `keyDown` sets `inKeyDown = true` and calls `interpretKeyEvents`. `insertText`/`setMarkedText` are accepted **only while `inKeyDown`**; the argument is copied at once with `CFStringGetCharacters` into the `SecretText`. `validAttributesForMarkedText = []`, and `ApplePressAndHoldEnabled = false` is registered in memory. The cost: one `NSString` per keystroke that Brev cannot wipe, which scribbling only covers after it is freed. That is outside §2's accepted list, so it needs the owner first.

## 8. Window and app hardening

### 8.1 Windows

`Hardening.apply` runs on **every** window Brev creates (main window, compose sheet, `ConfirmSheet`): `sharingType = .none`, `isExcludedFromWindowsMenu = true`, `isRestorable = false`, `tabbingMode = .disallowed`. Sheets need it explicitly, because the capture spike saw a sheet on a `.none` window report `sharingType=1`. The main window loses `.miniaturizable`. `allowsAutomaticWindowTabbing = false`; the title stays "Brev"; `applicationDockMenu` returns nil; there is no Dock badge. A debug-build assertion after each sheet checks `NSApp.windows.allSatisfy { $0.sharingType == .none }`. `RootViewController` keeps the window size across lock and unlock (setting `contentViewController` would resize the window, NSWindow.h:649).

### 8.2 Capture exclusion (U1)

Primary: `sharingType = .none` on every window (`screencapture` verified in D-0013; NSWindow.h: "cannot be captured"). The spike (§14.2 U1) tests ScreenCaptureKit including `captureImage(in:)` (15.2) and `captureScreenshot(contentFilter:/rect:configuration:)` (26), SCStream with `includeChildWindows`, legacy `CGWindowListCreateImage`/`CGDisplayCreateImage` from a binary built with the 14.0 SDK, Screen Sharing/VNC, ARD observe, and AirPlay/Sidecar mirroring.

Second defence, if any path shows a `.none` window: content views draw into an `AVSampleBufferDisplayLayer` with `preventsCapture = true` (macOS 10.15+). `TextLayout` draws into an IOSurface-backed `CVPixelBuffer`, wrapped as a `CMSampleBuffer` and enqueued, and the pixel buffers are wiped on lock. That needs AVFoundation, CoreMedia and CoreVideo, which are not in §4, so the owner must approve it, and it needs its own spike. If it fails too: stop and ask (§1 conflict). No public API tells an app that it is being captured.

### 8.3 Auto-lock triggers (U4) and idle

`LockController` locks on: `NSApplication.didResignActiveNotification` (except while `authInFlight`); the distributed `com.apple.screenIsLocked`; `NSWorkspace.willSleepNotification`, `.screensDidSleepNotification` and `.sessionDidResignActiveNotification`; ⌘L / *Lås*; app terminate. Idle: `BrevApplication` stamps `lastHumanInput = clock_gettime_nsec_np(CLOCK_MONOTONIC)` for every accepted input event, in both `sendEvent` and `nextEvent`. A 15 s timer locks after **300 s** without input. Every lock-related timer, and the sync timer, is created with `Timer(timeInterval:repeats:block:)` plus `RunLoop.main.add(t, forMode: .common)`, so it also fires during menu tracking. Fallbacks after the spike: `CGEventSource.secondsSinceLastEventType(.combinedSessionState, ~0)` for idle, and polling `CGSessionCopyCurrentDictionary()["CGSSessionScreenIsLocked"]` in the same timer if the distributed notification does not reach the sandbox.

### 8.4 Lock sequence (blank-on-lock): idempotent, main thread

1. `generation += 1`; stop the sync and idle timers; `SecureInput.disable()`; `NSApp.mainMenu?.cancelTracking()`.
2. Compose sheet: wipe its three `SecretText`s (recipient, subject, body), then `endSheet` (the draft is discarded).
3. `MailViewController.wipeAll()`: every row and letter `SecretText`.
4. `GlyphFlush.flush()` (after steps 2 and 3, so it covers compose, rows and letters).
5. `session.brev.lock()` (Rust closes open texts, zeroes three DEKs, scrubs stacks).
6. `root.show(UnlockViewController())`; the mail controller is released.
7. `window.display()`, so the window server's backing store holds the blank frame at once.
8. Log `lock reason=<resignActive|screenLocked|sleep|sessionResign|idle|manual|terminate>`.
9. Verify build only: `SelfScan.run()` logs `selfscan u8=<n> u16=<n>`.

### 8.5 Menus, plist, scripting, synthetic input

- Menus are built in code: **Brev** (*Lås Brev* ⌘L, a separator, *Avslutt Brev* ⌘Q) and **Arkiv** (*Nytt brev* ⌘N, enabled only when unlocked with a contact selected). There is no Edit, View, Window, Help, Services or Share menu, and `NSApp.servicesMenu` is never set. Accessibility can press these items; all three actions are harmless (open an empty sheet, lock, quit), and V13 confirms it.
- `Info.plist`: `NSPrincipalClass = BrevApplication`, `LSEnvironment = {MallocScribble = 1}`; D-0009's forbidden keys stay absent.
- Scripting: no `NSAppleScriptEnabled`, so no dictionary. The core Apple Events (open, reopen, quit, activate) still work and return no content.
- **Synthetic input, spec rule (CLAUDE.md §3.2)**: `InputFilter.isSynthetic` is true for any input event (key, flags, all mouse buttons, moved, dragged, scroll, gestures, tablet) whose `cgEvent` is nil, or whose `.eventSourceUnixProcessID` is **not 0**. Brev's own PID is not an exception. A CGEvent created in-process defaults to its creator's PID (§0), so the spike logs whether AppKit ever routes such an event through `sendEvent`. Widening the rule needs that evidence and a D-entry. Dropped events are logged as `dropped synthetic <type> pid=<n>`.

### 8.6 Launch hygiene (`LaunchGuard`, first lines of `main.swift`)

1. Release and Verify: any argument besides `argv[0]` (and a `-psn_…` argument, if the spike shows LaunchServices still passes one) → log `launch refused: arguments` and `exit(64)`. Debug keeps Xcode's arguments.
2. `UserDefaults.standard.removeVolatileDomain(forName: UserDefaults.argumentDomain)`.
3. Unsafe launch: an environment variable starting with `NSZombie`, `CFZombie`, `NSDebug`, `NSTrace`, `NSDeallocateZombies`, `NSObjCMessageLogging`, `OBJC_`, `MallocStackLogging`, `CFLOG` or `OS_ACTIVITY_DT_MODE`; any of `NSTraceEvents`, `NSZombieEnabled`, `NSDebugEnabled` or `NSDeallocateZombies` true in `UserDefaults.standard` (global domain included); or `MallocScribble` ≠ `1`. Then Brev re-executes itself once with a cleaned environment plus `MallocScribble=1` (if the spike shows `execve` of its own binary works in the sandbox). If the launch is still unsafe, the window shows only `launch.error.unsafe`: no onboarding and no unlock button, so nothing is ever decrypted in that process.

The spike (§14.2 L) confirms that `NSTraceEvents` really logs key characters on 26.2 and completes the key list from the AppKit, Foundation, CoreFoundation and HIToolbox binaries.

## 9. The two hard-coded contacts (R4)

Phase 1 refuses a core's own identity as a contact, so "send a message to yourself" cannot be a self-contact. The simplest reading that keeps the rule: the user's store gets two hard-coded contacts, **Ekko** and **Speil**. Each is a real in-process `Core` with its own store file (`peer-1.db`, `peer-2.db`, DEK = HKDF-SHA256(user DEK, `"brev/v0/demo-peer/" ‖ index`), so the three files can never be swapped for one another under one key), connected to the user's core by its own `MockTransport::pair()`. Each peer echoes every letter it receives back into the same thread. A letter you write therefore travels the whole path twice (seal, envelope, transport, open, store, and back) and arrives in your own thread a few seconds later: a message to yourself that you see arrive. Rejected alternatives: a second user identity in the app (needs an identity switcher and a second key set); peers kept only in memory (their identities would change every launch and leave stale contacts); a self-contact (forbidden by Phase 1, and it would weaken the misrouting check).

Wiring: `Brev::create` makes both peers (random 32-byte placeholder signing keys; nothing is verified before Phase 3), adds them as contacts and locks. `open`, `unlock` and `lock` treat the three stores as one. `send_new` puts the envelope on the right pair. `sync()` (every 3 s): for each peer, `receive_all` → for each new id, `thread_of` + `read_body` → `send` the same body into the same thread, dropping the plaintext before the envelope is queued → the user's core runs `receive_all` on that pair. Envelopes in flight are lost on quit (in-memory queues). Phase 3 deletes `echo.rs` and the peer files.

## 10. `docs/VERIFY.md` (R6)

Preamble: run on a **Release** build from `scripts/build.sh`; V39 uses the Verify build from `tools/verify/build.sh`. Type the marker `BREV-SECRET-BODY æøå` into every new letter. A = can run from a CLI (a human may need to grant a permission once); H = needs a human at the Mac. Every A row that reads through a permission has a **positive control** in the same run. Tools live in `tools/verify/` (WP4).

| # | Check | How (tool) | A/H |
|---|---|---|---|
| V1 | Sandboxed + hardened | `codesign -dv`: `runtime`; entitlements only `app-sandbox`; no `get-task-allow` | A |
| V2 | Plist | `plutil -p`: none of D-0009's keys; `NSPrincipalClass = BrevApplication`; `LSEnvironment.MallocScribble = 1` | A |
| V3 | No AppleScript | `sdef` fails; `osascript -e 'tell application "Brev" to get name of every window'` must fail with an error from Brev itself (expected -1708, errAEEventNotHandled; record the code); -1743 (not permitted) or -600 (not running) means the event never reached Brev and fails the row (grant Automation first) | A |
| V4 | ⇧⌘4 (window and area), ⇧⌘5 recording | content absent or black | H |
| V5 | `screencapture` | `-x` and `-V 3` show no letter; `-l <id>` fails; control window visible | A |
| V6 | ScreenCaptureKit | `tools/verify/capture-probe`: display filter, window filter (`includeChildWindows`), `captureImage(in:)`, `captureScreenshot(…)` (26); a control window must be visible | H grants, A runs |
| V7 | Legacy CG capture | `capture-probe --legacy` (built for 14.0): `CGWindowListCreateImage`, `CGDisplayCreateImage` | A |
| V8 | Screen Sharing / ARD / AirPlay | a second Mac views, observes, mirrors: no letter visible | H |
| V9 | Every window excluded | `tools/verify/windows`: `kCGWindowSharingState == 0` for all Brev windows with the compose sheet and `ConfirmSheet` open | A (H opens) |
| V10 | Accessibility Inspector | lists, letter, compose fields and the recipient show no text | H |
| V11 | AX dump | `tools/verify/axdump Brev`: all attributes and parameterized attributes; marker absent; **control: title "Brev" present** | A (H grants AX) |
| V12 | GUI scripting | System Events `entire contents of window 1`: marker absent; control: the button titles are listed | A |
| V13 | AX press refused | `axdump --press` on *Send*, *Lås opp med Touch ID*, *Slett alt og start på nytt* and `ConfirmSheet`'s *Slett alt*: nothing happens (log shows no send/unlock/reset); menu items: only harmless actions | A |
| V14 | ⌘C, ⌘X, ⌘A, ⌘V | in letter and compose views: nothing; `pbpaste` unchanged | H + A |
| V15 | Menus | only Brev and Arkiv; right-click in content shows no menu | H |
| V16 | Drag | dragging in a letter moves nothing out | H |
| V17 | No plaintext on disk | `strings -a` and a UTF-16LE grep over every container file: marker absent | A |
| V18 | Padding | `tools/verify/padcheck`: every sealed column length is nonce + bucket + tag in all three stores | A |
| V19 | No plaintext in logs | `log show --info --debug --predicate 'process == "Brev"' --last 30m`: marker absent (UTF-8 and UTF-16LE); control: `lock reason=` lines present | A |
| V20 | Crash report | `kill -SEGV` an unlocked Brev with a marker letter open; scan the new `~/Library/Logs/DiagnosticReports/Brev*.ips`: marker absent | A |
| V21 | Spotlight | `mdfind BREV-SECRET-BODY`: nothing | A |
| V22 | Switching app locks | ⌘-Tab away: the lock screen; log `lock reason=resignActive` | H + A |
| V23 | Screen lock locks | ⌃⌘Q: `lock reason=screenLocked` | H + A |
| V24 | Sleep locks | sleep and wake: locked | H |
| V25 | Idle locks | 5 min without input, also with the Brev menu left open: locked | H |
| V26 | No prompt without a human | `open -a Brev`; `osascript -e 'activate application "Brev"'`: no Touch ID dialog | H |
| V27 | Touch ID | exactly one prompt; no password button; *Avbryt* returns to the lock screen | H |
| V28 | Launch hygiene | `open -a Brev --args -NSTraceEvents YES` exits; `defaults write -g NSTraceEvents -bool YES` then launch → `launch.error.unsafe`, no unlock button; `open --env NSZombieEnabled=YES -a Brev` → same; delete the default afterwards | A + H looks |
| V29 | Second instance | during onboarding, `open -n -a Brev`: the second instance exits; files unchanged | A |
| V30 | Secure input flag | `ioreg -l -w 0 \| grep kCGSSessionSecureInputPID` = Brev's PID only while a compose field has focus | A (H focuses) |
| V31 | Keyloggers see nothing | `tools/verify/keylisten` (listen-only CGEventTap + IOHIDManager, Input Monitoring granted) while typing the marker in compose: no key values; control: it sees keys typed in TextEdit | H + A |
| V32 | Synthetic keys | `tools/verify/poster key` (CGEventPost at HID and session taps, `CGEventPostToPid`, each with field 41 untouched, set to 0, and set to Brev's PID; `AXUIElementPostKeyboardEvent`; `IOHIDPostEvent`); System Events `keystroke`: nothing typed; log `dropped synthetic`; control: the same posts type into TextEdit | A |
| V33 | Synthetic clicks | `poster click` on *Send* / *Lås opp* with the same variants: no effect; control as V32 | A |
| V34 | Text services | dictation, emoji picker, press-and-hold, Writing Tools, Look Up (⌃⌘D, force click), text replacement, Services shortcuts: none reach compose | H |
| V35 | Norwegian input | æ ø å Æ Ø Å; ´+e → é; ¨+u → ü; ⇧´+e → è; ⌥¨ then n → ñ; @ (the key left of Return); ⇧4 $; ⌥7 \|; ⇧⌥7 \\; ⌥8/⌥9 [ ]; ⇧⌥8/⇧⌥9 { }; Caps Lock; key repeat | H |
| V36 | Onboarding | the four rules texts appear in bokmål; *Opprett nøkler* stays disabled until *Jeg forstår* is ticked | H |
| V37 | Crash during onboarding | `kill -9` after *Opprett nøkler*, before the first unlock: relaunch shows onboarding; only fresh files exist after the next attempt | A + H |
| V38 | Damaged and reset | rename `kek.se`: `unlock.error.damaged`; files unchanged after *Avbryt* in `ConfirmSheet`; gone only after *Slett alt*; onboarding starts | H + A |
| V39 | Heap residue in the real app | Verify build: send and read a marker letter to Ekko, lock; log `selfscan u8=0 u16=0`; control: a scan while the letter is open shows > 0 | H + A |
| V40 | Key files | `identity.se`, `kek.se` 569 B; `dek.hpke` 113 B; all files 0600, the directory 0700; `security find-generic-password -s no.brev.app` finds nothing; `xattr`/`tmutil isexcluded` shows the folder excluded | A |
| V41 | Nothing else written | no `Saved Application State`; only §5.1's files in Application Support | A |
| V42 | Echo | a letter to Ekko and one to Speil show as sent; each echo arrives within 3 s in the same thread | H |
| V43 | Dock / title | no minimise button; title "Brev"; the Dock window list shows only "Brev" | H |
| V44 | Quit while unlocked | relaunch starts on the lock screen | H |
| V45 | Automated suite | `scripts/test.sh` exits 0 on this Mac (including the Swift harness and the forbidden-API grep) | A |

## 11. Test plan

**Rust** (`cargo test`, plus release runs in test.sh): §2.11. test.sh also checks that `cargo tree -p brev-core` contains `zeroizing-alloc` plus every existing zeroize feature, and runs both scrub tests in `--release`.

**Swift harness** (no XCTest: a hosted bundle would put a window on screen, and an unhosted one would duplicate this). `app/Tests/{main.swift, hpke_needles.swift, scan.c, scan.h, bridging.h}` (based on `R/swift/Harness`), built by test.sh on macOS with `xcrun swiftc -O -target <arch>-apple-macos14.0 -import-objc-header app/Tests/bridging.h` from `app/Sources/Shared/*`, `app/Generated/BrevCore.swift`, `core/target/release/libbrev_core.a` and `scan.c`. Every case runs **five times per body size under `MallocScribble=1`** (as the app runs), with `TMPDIR` under `core/target/harness`.
1. Units: `SecretBytes` (capacity ≥ 64, `append` bounds, the FFI view's base is `base`, so no copy); `Data.wipe` keeps the address; `SecretText` insert/delete/`composedRange` (e + U+0301, emoji, windowed at the ends); transcoding round trip, invalid UTF-8 → U+FFFD; `TextLayout` covers every unit, lines ≤ 448, no split surrogate, breaks at spaces.
2. `EditModel` (caret moves and composed deletes), `KeyTranslator` on the named Norwegian layout (the V35 table, including dead keys; skipped with a message when TIS is unavailable), `InputFilter` on in-memory CGEvents (PID 0 kept; own PID, another PID and nil dropped), `LockState` (a stale generation discards an unlock; resign-active during auth does not lock), and `LaunchGuard` on injected environments and defaults.
3. R2 DEK hand-off (software HPKE key): same address, all zero after the wipe; the DEK exists only in Rust's box while unlocked (2 hits); 0 after create and after lock. **HPKE needles**: `hpke_needles.swift` seals the DEK with its own RFC 9180 sender (a known ephemeral key, CryptoKit HKDF and AES-GCM; test code only, checked by opening the result with CryptoKit's `HPKE.Recipient`). It writes the DH output, the KEM shared secret, the AEAD key and the base nonce, XORed, for the scanner. Needles are made in a helper run, never in the measuring process. All must give 0 hits after the unlock closure returns.
4. Content path at 64, 200, 4 096 and 65 000 units, including 200 `composedRange` calls and 300 typed keystrokes with layout and draw after each: live hits > 0 while open (positive control); **0 UTF-8, 0 UTF-16 and 0 glyph hits after wipe + `GlyphFlush` + lock**.
5. A kept `OpenText` throws after `lock()`.
6. Negative control: a live `String` of a 64 KiB letter gives hits > 0 (the scanner sees Swift heap). One extra run **without** scribbling must show glyph hits > 0 after lock, which proves the needle works and that scribbling is what removes them.

**test.sh order on macOS**: `gen-bindings.sh` (fresh archive, patched bindings, uniffi pin) → `xcodegen generate` (skipped with the existing message style if xcodegen is missing; the xcodebuild step is then skipped too) → fmt → clippy → tests → release scrub tests → zeroize/allocator check → FFI surface check → patch-marker check → forbidden-API grep → cargo audit → Swift harness → xcodebuild Debug compile. Linux is unchanged; the macOS-only steps print their skip messages.

- **FFI surface check** (verified on the generated file, §0): `grep -nE '^(public |open )(static )?func .*String'` must list only `ping() -> String`, `create(dir: String, …)` and `open(dir: String)`, and `grep -cE '^\s+public (var|let) [a-zA-Z]+: String([^?]|$)'` must be 0.
- **Forbidden-API grep** over `app/Sources` (allow-list file `scripts/allowed-apis.txt` with line reasons): `NSPasteboard`, `NSTextView`, `NSTextField`, `NSTextInputClient`, `.characters`, `String(decoding`, `NSString(`, `NSAttributedString(`, `CTTypesetter`, `CTFramesetter`, `NSAlert`, `print(`, `servicesMenu`.

## 12. Work packages (in order)

Nothing in WP0 to WP4 waits for an owner answer or a GUI fact. WP4 ends with the human GUI-spike session; the packages after it use its results.

| WP | Content | Files | Needs | Waits for | Done when |
|---|---|---|---|---|---|
| 0 | `docs/VERIFY.md` (§10) with tool paths; rows that depend on the spike are marked "per D-0057" | `docs/VERIFY.md` | – | – | reviewed; every §5 check and every new mechanism has a row |
| 1 | Rust: `ffi.rs`, `echo.rs`, `thread_of`, 0600, `scrub_stack_deep`, **padding + schema v2**, **zeroing allocator**, tests §2.11 | `core/**` | – | – | `cargo test`, clippy, release scrub tests, `cargo tree` check; `nm -gU` lists the new symbols |
| 2 | Binding patch step + uniffi pin; `Shared/{SecretBytes,SecretText,Transcode,TextLayout,Enclave,Session}`; CLI harness incl. HPKE and glyph needles; test.sh steps (xcodegen, surface check, marker, grep, harness) | `scripts/*`, `app/Sources/Shared/*`, `app/Tests/*` | 1 | – | test.sh green; harness cases 1, 3, 4, 5, 6 pass 5 of 5 per size; a mutated binding input fails the build |
| 3 | App shell: `LaunchGuard`, `LockState`, `InputFilter` (spec rule), `BrevApplication`, `MainMenu`, `Hardening`, `MainWindow`, `RootViewController`, `L10n`, strings, `AppDelegate` routing and instance lock, `LockController` with ⌘L and blank-on-lock, `project.yml` (principal class, `LSEnvironment`, Verify config) | `app/Sources/App/*`, `Shared/{LaunchGuard,LockState,InputFilter}`, `main.swift`, `AppDelegate.swift`, `project.yml`, `Localizable.strings` | 2 | – | builds; harness case 2 (those three) green; V1, V2, V3 pass; the hardened empty window opens |
| 4 | Verification tools and the GUI spike apps (§14.2): `capture-probe`, `windows`, `axdump`, `poster`, `keylisten`, `padcheck`, `InputLab.app`, `rogue-brev.app`, `touchid-probe`, `anchor-probe`; copy `p2/capture`, `p2/enclave`, `p2/ffi` harness sources into `tools/verify/spikes/`; never linked into Brev.app | `tools/verify/**` | 3 | – | `tools/verify/build.sh` builds all; **the human session runs §14.2**; results are recorded in D-0057 |
| 5 | Keys, onboarding, unlock, errors, reset, `ConfirmSheet`, backup exclusion, `biometry.state` rewrite | `Keys/*`, `UI/Onboarding…`, `UI/Unlock…`, `UI/ConfirmSheet`, `UI/HumanButton` | 3 | K (unlock depth), U4.3 (error codes) for the final mapping | V26, V27, V29, V36, V37, V38, V40 |
| 6 | Headless compose core: `EditModel`, `KeyTranslator`; `InputFilter` adjusted only if D-0057 requires it | `Shared/{EditModel,KeyTranslator,InputFilter}` | 2 | – (U2 results plug in later) | harness case 2 (all parts) green |
| 7 | Content views and mail window, sync timer | `UI/OpaqueView`, `SecureTextView`, `SecureListView`, `LetterStackView`, `MailViewController` | 5 | U3 | harness green; V10 on lists and letter; V42 once WP8 exists |
| 8 | Compose view and sheet, `SecureInput`, recipient drawing | `UI/*Compose*`, `UI/SecureInput` | 6, 7 | U2 (fallback §7.4 needs the owner) | V9, V14, V30 to V35 |
| 9 | Anchor against file substitution (only if the spike's anchor probe passes and the owner chooses it) | `Keys/Anchor.swift`, `UnlockService` | 5 | owner question 1, spike A | a swapped `kek.se` + `dek.hpke` gives `unlock.error.tampered` |
| 10 | Lock triggers finalised from the spike (activation wait if needed, fallbacks) | `LockController`, `LockState` | 3, 5 | U4 | V22 to V25 |
| 11 | Capture second defence (only if U1 shows a leak) | `UI/ProtectedLayerView` | 7 | U1 + owner approval of AVFoundation/CoreMedia/CoreVideo | V4 to V8 |
| 12 | Run VERIFY on Release (V39 on Verify); decision entries; README; phase summary | `docs/*`, `README.md` | all | – | all rows pass or have an owner-accepted entry |

Starting points (copy them now; `/private/tmp` is volatile): WP1 `R/core/brev-core/src/{ffi,crypto,store,lib}.rs`, `R/core/brev-proto/src/lib.rs`; WP2 `S/patch-bindings.py`, `R/swift/Shared/*`, `R/swift/Harness/*`, `R/ct/*`; WP3/WP8 `S/swift/App/AppProof.swift`, `R/AppRevise.swift`; WP6 `R/keytr.swift`; WP4 `p2/capture`, `p2/enclave`, `p2/ffi`, `S/critic-macos/{pidfield,selfscan}*`.

## 13. Decision-log entries to add (D-0033 onward)

> Keys note (2026-09-28, D-0035): §5's key files + HPKE are replaced by permanent Secure Enclave `SecKey`s in the data protection keychain (access group `AV26DNQ5SC.no.brev.app`), the wrapped DEK as a generic-password item in the same group, `SecKeyCreateDecryptedData` (ECIES) for unwrap, and team signing with automatic provisioning. Anything below about `kek.se`, `identity.se`, `dek.hpke`, HPKE, the rogue-Brev test (R) or the login-keychain anchor (A, WP9) is superseded.
> Numbering note (2026-09-28): D-0033, D-0034 and D-0035 were used for owner decisions (answers to this design's questions; the capture defence; keychain keys). Every number below shifts by three (D-0033 → D-0036 … D-0058 → D-0061). The topics of D-0055 and D-0056 are already recorded in D-0033. WP11 is no longer conditional: it is part of Phase 2's definition of done (D-0034).

- D-0033: Phase 2 UniFFI surface: `Brev` + `OpenText`, unit-variant `BrevError`, content in only as `&[u8]` + length, out only as 960-byte chunks, no content `String`; no replies or read state in Phase 2.
- D-0034: `OpenText` registry; `lock()` closes every open text; Swift reads a text completely and closes it.
- D-0035: `unlock` drop guard (lock on any failure or panic, 64 KiB scrub on every exit); poisoned mutex → lock all, `Locked`.
- D-0036: Install atomicity: `dek.hpke` last, after the first Touch ID unlock; known-name cleanup before every attempt (closes Phase 1's `create` finding).
- D-0037: Container layout, 0600/0700, `.lock` single instance, backup exclusion.
- D-0038: `biometry.state` is a hint, rewritten after each unlock; the fingers message only with the invalidated-key error.
- D-0039: Padding of every sealed column with `brev-proto`; schema v2 (implements D-0032 item 7).
- D-0040: Bindings patch step pinned to uniffi 0.32.2 (implements D-0032 item 5).
- D-0041: Echo peers Ekko and Speil over `MockTransport`, HKDF-derived peer DEKs (R4); removed in Phase 3.
- D-0042: AppKit only; Carbon (HIToolbox), Core Text and Core Graphics as §3.2 names them; `RootViewController`.
- D-0043: Swift secret-memory rules: `SecretBytes`/`SecretText`, no content `String`, `Data` only for chunks and the HPKE output.
- D-0044: Rendering: CTLine-only layout in windows of at most 448 units, no `CTTypesetter`; `MallocScribble=1` through `LSEnvironment`; 1…448 glyph sweep on lock (the measured glyph residue and why).
- D-0045: Launch hygiene: no arguments, no argument domain, debug-key and environment checks, re-exec, never unlock when unsafe.
- D-0046: Compose input by `keyDown` + `UCKeyTranslate`, no `NSTextInputClient`; fallback recorded (U2).
- D-0047: Synthetic input: spec rule PID ≠ 0 (no own-PID exception), nil `cgEvent` dropped, filter in `sendEvent` and `nextEvent`; `HumanButton` gating by human dispatch.
- D-0048: Every window through `Hardening.apply`; no `NSAlert`; no minimise, no tabbing; capture second-defence plan (U1).
- D-0049: Lock triggers, common-mode timers, own idle clock (300 s), simple post-unlock rule, lock sequence (U4).
- D-0050: Menus: Brev and Arkiv only.
- D-0051: Phase 2 limits: subject ≤ 256 B, body ≤ 64 KiB UTF-8.
- D-0052: Test strategy: Swift CLI harness under scribbling in test.sh, glyph and HPKE needles, no XCTest; test.sh runs gen-bindings and xcodegen first (closes D-0028 #2); forbidden-API grep.
- D-0053: Verify build configuration with in-process self-scan (never built by `build.sh`).
- D-0054: `tools/verify/` (verification and spike tools; never linked into Brev.app).
- D-0055: File substitution risk and the chosen answer (owner question 1).
- D-0056: New §2 residual risks as the owner accepts them (owner question 2).
- D-0057: GUI-spike results for U1 to U4, L, M, K, R, A, S (facts only).
- D-0058: Phase 2 VERIFY results and the phase summary.

R5 ("Ny melding") is already D-0027 and is not repeated.

## 14. Residual risks, limits, and the GUI-spike checklist

### 14.1 Residual risks and limits

- **File substitution (new; not covered by §2's key-file risk).** A process that can **write** the container (Full Disk Access, or the user approving "access data from other apps") can seal a DEK it knows to a new biometric SE key of its own, build the three stores with `brev-core`, and replace `kek.se`, `dek.hpke` and the stores. The user then unlocks at **Brev's own** prompt, and every letter written afterwards is readable by that process. This is a disclosure, not only a loss. The only sign is that the history is gone. Mitigation: open question 1 (anchor, or warning text); Phase 3 pinning shows the new identity to contacts.
- **Key files not bound to Brev** (accepted in §2): stands, subject to the rogue-"Brev" test (§14.2 R).
- **Copies Brev cannot wipe** (accepted in §2): Core Text / Core Graphics while a line is drawn; CryptoKit / Security during unwrap. Freed copies are scribbled (`MallocScribble`). Live framework caches are replaced by the 1…448 sweep, and no residue was measured after it in CLI processes; the real app is checked by V39.
- **Keystrokes** exist in `NSEvent`/`CGEvent` objects (one character each; `NSApp.currentEvent` keeps the last one until the next event) and in the window server. Secure input stops event taps only. This is not in §2's list (open question 2).
- **Pixels** of unlocked letters live in layer backing stores and window-server surfaces until blank-on-lock (open question 2).
- **Documented behaviour relied on**: `sharingType` (U1), `MallocScribble` (a malloc debugging variable, honoured by the hardened CLI here). **Undocumented behaviour relied on**: the PID of hardware events and whether posted events can forge it (U2), and the SE residue depth (K).
- **Accessibility cost**: VoiceOver cannot read letters. Accessibility Keyboard, Voice Control and Switch Control post synthetic events and are expected to be rejected (measured in U2.3, not assumed). There are no input methods.
- **Drafts** are discarded on every lock. **Echo peers** keep a copy of every letter in two more files under the same key root (open question 2). **Envelopes are unsigned**; Phase 1's freshness and delivery limits stand. **Metadata on disk**: bucketed sizes, counts, times.
- **Backups**: with exclusion on, Time Machine does not copy the folder; a local APFS snapshot can still bring back reset files on this Mac.
- **Rust panic messages** reach Swift (and crash reports); Phase 1's content-free message rule covers them. The generated `lock()` uses `try!`, so a panic there ends the process, which leaves nothing unlocked.

### 14.2 GUI-spike checklist (a human at the Mac; built in WP4; results go to D-0057)

Record the macOS build for every item. **Stop and ask the owner** wherever a row says so; never reword a failure as residual risk on our own.

**U1: capture.** Use `InputLab`/`SpikeCapture` with an excluded window, an excluded window with a `.none` sheet, one with the sheet left at the default, and a control window. With Screen Recording granted to `capture-probe`: `SCShareableContent` (is the excluded window listed?); `SCScreenshotManager` with a display filter, a `desktopIndependentWindow` filter and `display excludingApplications`; `captureImage(in:)` (15.2); `captureScreenshot(contentFilter:)` and `(rect:)` (26); one `SCStream` frame each with a display filter and with a window filter with `includeChildWindows = true`; `CGWindowListCreateImage`/`CGDisplayCreateImage` from a 14.0-SDK build; ⇧⌘4, ⇧⌘5, `screencapture -x/-V/-l`; Screen Sharing from a second Mac (or a VNC client), ARD observe, AirPlay/Sidecar. Classify pixels (magenta = leak). Any leak → repeat with `AVSampleBufferDisplayLayer` (`preventsCapture = true`), then ask the owner (WP11).

**U2: input** (`InputLab.app`, sandboxed and hardened; view a = `keyDown` + `UCKeyTranslate`, view b = minimal `NSTextInputClient` with the keyDown-only rule; Norwegian layout).
1. With secure input on and off: the V35 table and key repeat. Log key codes and unit counts only. Confirm `TISCopyCurrentKeyboardLayoutInputSource` still returns the Norwegian layout under secure input.
2. Log `eventSourceUnixProcessID`, `eventSourceStateID` and `eventSourceUserData`, and whether `cgEvent` is nil, for: the built-in keyboard, trackpad click/drag/scroll, an external mouse, every event AppKit itself generates (mouse entered/exited, key equivalents), `CGEventPost` (HID and session taps) and `CGEventPostToPid`, **each with field 41 untouched, set to 0, and set to InputLab's PID**, `AXUIElementPostKeyboardEvent`, `IOHIDPostEvent`, System Events `keystroke`/`click`, Accessibility Keyboard, Screen Sharing/ARD keys and clicks, and Universal Control. **If any posted or remote event arrives with PID 0 (or any value the rule accepts)**, no documented field proves where an event came from: stop and ask the owner (§1/§2 conflict). If a hardware event has a non-zero PID, record which and whether it is stable (D-0047).
3. Which features reach each view: dictation, emoji picker, Character Viewer, press-and-hold, autocorrect, inline predictions, Writing Tools (shortcut and menu), Services shortcuts, Look Up, text replacement, Touch Bar suggestions.
4. `ioreg … kCGSSessionSecureInputPID` on focus, blur, app switch, sheet close. `keylisten` (event tap + IOHIDManager with Input Monitoring) while typing in view a with secure input on. **If IOHIDManager sees key values**, stop and ask (secure input would not meet §2's keylogger defence).
5. Keystroke accumulation (S): InputLab scans its own memory (self-scan works under Hardened Runtime, `S/critic-macos/selfscan`) for a typed 16-character marker (UTF-8 and UTF-16) after typing, after lock, and after one more event, for views a and b, with and without `MallocScribble`.

**U3: accessibility.** Accessibility Inspector on an `OpaqueView` text view, a list and the compose view, each inside an `NSScrollView`: the hierarchy, every attribute, hit-testing on text. `axdump`: all attributes and parameterized attributes (`AXStringForRange`, `AXAttributedStringForRange`) of every element; grep the marker. `AXPress` on a `HumanButton`, on the `ConfirmSheet` button and on the menu items: does any action run? VoiceOver cursor over the content views; System Events `entire contents`.

**U4: lock triggers.** In InputLab, log with monotonic times `didResignActive`, `didBecomeActive`, window `didResignKey`/`didBecomeKey`, `com.apple.screenIsLocked`/`…Unlocked`, `willSleep`, `didWake`, `screensDidSleep` and `sessionDidResignActive`, for: ⌃⌘Q, lid close, display sleep, a Hot Corner lock, fast user switching, ⌘-Tab, ⌘H.
1. During a biometric HPKE unwrap: does the Touch ID panel make the app resign active or the window resign key, and in what order do the unwrap's completion and `didBecomeActive` arrive? Is a password button shown with `localizedFallbackTitle = ""`?
2. `CGEventSource.secondsSinceLastEventType` and `CGSessionCopyCurrentDictionary` in the sandbox.
3. The error domain and code CryptoKit throws for: cancel, three failed fingers, lockout, and an invalidated key (a test key only: add then remove a fingerprint).

**L: launch hygiene.** In InputLab: `defaults write -g NSTraceEvents -bool YES`, `open -a InputLab --args -NSTraceEvents YES`, and `open --stderr <file> --env NSTraceEvents=YES -a InputLab`. Type a marker, then grep `log show --predicate 'process == "InputLab"'` and the stderr file. Is any `-psn_` argument passed from Finder or the Dock? Do `removeVolatileDomain` and the checks prevent the effect? Extract candidate debug keys with `strings` over AppKit, Foundation, CoreFoundation and HIToolbox.

**M: malloc scribbling in the real process.** Is `LSEnvironment`'s `MallocScribble=1` visible in the sandboxed hardened app when launched from Finder, the Dock and `open`? Does `execve` of its own binary work in the sandbox? Do all flows work with scribbling (no crash)? V39 then runs on the Verify build.

**K: unlock residue** (`touchid-probe`). Run the exact §5.4 closure (LAContext → `init(dataRepresentation:)` → `Enclave.open` → `brev.unlock` → wipe) on one GCD queue thread, with needles for the DEK, the P-256 DH output, the HPKE KEM shared secret, the AEAD key and the base nonce. The wrapped DEK comes from the RFC 9180 test sender (§11 case 3), using the probe key's public key. Scan all RW regions (all thread stacks) with `scrub_stack_deep` at 64 KiB, at 128 KiB, and disabled. Only then does D-0035 say which depth is enough.

**R: a rogue named Brev** (`rogue-brev.app`: `CFBundleName` and executable "Brev", Brev's icon, `localizedReason` = `unlock.reason`, using a copied `kek.se`). Run it alone, and again right after Brev's own prompt. Record exactly what the dialog shows (name, icon, path, signing info). **If the two cannot be told apart**, §2's "the system dialog names the requesting program" is not a mitigation: stop and ask the owner to accept A2 again on the corrected facts, and reword `onboarding.rules.prompt`. Also run the enclave skeptic's ACL-tamper check (rewrite `okd(cbio…)` in a copied biometric blob; with `interactionNotAllowed` the use must fail).

**A: anchor against file substitution** (`anchor-probe`, sandboxed and ad-hoc signed like Brev). Is a generic-password item in the **file-based login keychain** (no `kSecUseDataProtectionKeychain`) holding SHA-256 of the KEK public key (1) created without any prompt, (2) read back in a later launch of the same build without a prompt, (3) readable without a prompt after a rebuild (new cdhash), and (4) impossible for another unsandboxed same-user process to modify, delete or replace without a user-visible prompt? Only if 1, 2 and 4 hold (and 3, or the owner accepts a one-time prompt per build), WP9 adds the anchor: Brev refuses to unlock when the anchor is missing or does not match while `dek.hpke` exists.

## Open questions for the owner (not covered by A1 to A7)

1. File substitution (§14.1, first bullet): accept it as residual risk with the mitigation the spike allows (a login-keychain anchor if probe A passes, otherwise the `onboarding.rules.gone` warning), or hold Phase 2 until Phase 5 keychain storage?
2. Add to §2's accepted risks: keystroke characters in `NSEvent`/`CGEvent` objects and the window server; letter pixels in backing stores until lock; echo peers' copies of every letter (Phase 2 only); reliance on the documented `MallocScribble` variable for framework residue.
3. Exclude Brev's container folder from Time Machine (`isExcludedFromBackup`), which matches the "no backup" promise and makes a reset final except for local snapshots, or allow backups, which can restore reset letters on this Mac?
