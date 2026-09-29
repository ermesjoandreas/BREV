# The core as an SDK — design

## Kort fortalt

Rust-kjernen blir en SDK som andre apper kan bygge på, og Brev blir
utstillingsvinduet. Vi lager én ny crate, brev-sdk, med et lite API: en
forseglet lagring og et bevis for hvordan en tekst ble skrevet. Den sikre
Swift-koden fra Brev blir en egen pakke, HandKit, som andre Mac-apper kan
bruke. Eksamens-editoren blir første kunde, og sensor ser et merke med
klasse A, B eller C når beviset er sjekket. På Mac kan vi ikke bevise at
det var editoren som skrev, så en student som lager sitt eget program, kan
jukse. Brev virker som før, og ingen regel i CLAUDE.md §1 blir svakere.
Kotlin, C#, iOS, Windows og Linux kommer senere, og flere av dem trenger
nye verktøy som du må godkjenne. Seks spørsmål til deg står nederst.

Status: design only, for the owner to read before any code. Nothing here is
built. Base: branch `claude/laughing-knuth-yhp8ji` at 444934b (Hand done on
Mac, D-0112). Paths are relative to the repo root.

The owner's picture: apps (Brev post as the showcase, an exam editor as the
likely first customer, other apps later) sit on an SDK in Swift, Kotlin and
C#. Under the SDK, a platform adapter per OS observes and reports facts. The
Rust core decides. Hand (the proof, docs/AUTHORSHIP.md) sits over Vault (the
safe). A verification API lets a recipient, for example an examiner, check
the proof and show a badge.

## 1. The goal

The SDK lets any app prove how a piece of text was written: with a hardware
key and one biometric check, inside protected views, while the core measured
the device. It keeps that text sealed on the device until the app sends it.
Anyone who holds the author's public key can check the proof with a small
verifier, without the app.

**What "generic" means here.** The SDK knows nothing about mail: no
contacts, threads, letters, relay, envelopes or invites. The host app
decides what its records are, what the text is, how it travels and how the
author's key is registered. The SDK does not become generic by getting
weaker. The lock rule, the class rule, the sealing, the wiping and the
facts-not-flags adapter stay exactly as strict as in Brev. What changes is
only who names the content and who carries it.

## 2. What exists

| Part | Where | Reusable as is | Mail-specific | Swift-only |
|---|---|---|---|---|
| Encrypted store, DEK, lock state, two-step unlock, idle timer, column AEAD, padding, `Plaintext`/`Text`, stack scrubs, zeroing allocator, launch guard | `core/brev-vault` | yes, through `VaultConfig` (docs/ARCHITECTURE-REUSE.md §4) | no; but the column label `brev/v0/column/`, `CHUNK` = 960 and the buckets carry Brev's format (§5 item 3 there) | no |
| Environment class of a report (`KeyOrigin`, `EnvironmentClass`, `classify`) | `core/brev-vault/src/platform.rs` | yes | no | no |
| Facts from raw samples (`FactLog`, `Sample`, `Design`), lock rule (sudo, SIP), class rule, token (COSE_Sign1, fixed CBOR), `verify` | `core/brev-hand` | mostly: the rules and the token are generic | the profile string, the content-hash domain `brev/v1/hand/content\0`, and `"platform"` fixed to 1 (macOS; decode refuses anything else) | no |
| P-256 verification (`sig::verify`, `der_to_raw`) | `core/brev-proto/src/sig.rs` | yes | the rest of brev-proto is Brev's wire format | no |
| Identity, contacts, threads, letters, schema v6, X25519 + HKDF message crypto, relay client, the whole UniFFI surface (`Brev`, `OpenText`, `BrevError`, `Proof`) | `core/brev-mail` (lib `brev_core`) | the FFI *glue pattern* (session mutex, `Finish` guard, `used`/`dek32`, `OpenText`, epoch) is reusable by copying | yes | no |
| Relay server | `core/brev-relay` | no | yes | no |
| Bindings build: `gen-bindings.sh`, `patch-bindings.py` (wipes byte buffers), `ffi-surface.txt`, release markers | `scripts/` | by copying and renaming (written for `brev_core`, uniffi 0.32.2) | names only | no |
| Protected capture layer (`ContentView`/`OpaqueView`, `preventsCapture`), `SecureTextView`, `SecureListView`, `TextLayout` | `app/Sources/UI`, `Shared` | yes | no | **yes** |
| Compose: `SecureComposeView`, `SecureInput`, `EditModel`, `KeyTranslator`, `ComposeKey` | `app/Sources/UI`, `Shared` | yes | no | **yes** |
| `InputFilter`, `BrevApplication` (drops synthetic events), `HumanButton` | `Shared`, `App`, `UI` | yes, after renaming | no | **yes** |
| `Hardening`/`HardenedWindow`, `MainMenu` (no Copy/Paste/Services) | `App` | yes | menu items are Brev's | **yes** |
| `LockController`, `LockState` (lock triggers, wipe order, 2 s sampler) | `App`, `Shared` | the pattern; the code names Brev's views | partly | **yes** |
| `LaunchGuard` (arguments, defaults, `DYLD_*`, `MallocScribble` re-exec) | `Shared` | yes | no | **yes** |
| `SecretBytes`, `SecretText`, `Transcode` | `Shared` | yes | no | **yes** |
| `HandSampler`, `EnvironmentProbe` | `Shared`, `App` | yes | the probe names Brev's windows | **yes** |
| `Enclave`, `KeyStore`, `UnlockService`, `SignService`, `Attestor` | `Shared`, `Keys` | yes, with the host's access group and labels | key labels, Brev's two-signature letter flow | **yes** |
| Mail UI (`MailViewController`, `ContactSheet`, `ComposeSheet`, `ProofSheet`, …) | `app/Sources/UI` | no | yes | yes |

In short: Rust is ready to be reused, but has no FFI outside mail. The
security kit is complete but lives inside the app as loose files.

## 3. Layers and crates

```
 host app (exam editor, …)
   ├─ HandKit (Swift, source only): UI kit + macOS adapter; names no generated type
   └─ HandCore (Swift): generated bindings + glue from HandKit's values
        └─ HandCore.xcframework  ← brev-sdk, feature `ffi` (UniFFI, staticlib)
             ├─ brev-hand   (facts, class, lock rule, token, verify)
             │    └─ brev-proto::sig (P-256 verify)
             └─ brev-vault  (store, DEK, lock state, sealing, wiping)
 Brev post (from §11 step 11): HandKit only; libbrev_core.a = brev-mail over brev-sdk, `ffi` off
 examiner / institution
   └─ hand-verify (CLI) or brev-sdk's `verify` export, both over brev-hand::verify
```

**The crate plan (smallest thing that works):**

1. **`brev-vault`**: no change.
2. **`brev-hand`**: a `HandProfile` value carries today's constants: the
   `eat_profile` string, the content-hash domain and the allowed platform
   codes. `BREV_V1` gives today's bytes exactly, so every Brev token and
   test vector stays the same. The SDK gets its own profile (§4.2, Q1).
   This changes signatures, not only constants: `content_hash`,
   `Claims::new` and `verify` take the profile, and under the SDK profile
   also the purpose and context (§4.2). `Claims::new` sets `platform` from
   `cfg!(target_os)` (§5). Brev's call sites change in the same step:
   `Claims::new` in `core/brev-mail/src/ffi.rs` (send) and
   `src/test_keys.rs`, `brev_hand::verify` in `src/store.rs` (receive),
   and the test tokens in `tests/common/mod.rs`.
3. **`brev-sdk`**, a new crate beside `brev-mail`. It is the UniFFI crate
   of the SDK (`crate-type = ["lib", "staticlib", "cdylib"]`, its own lib
   name, its own `uniffi.toml`). Its scaffolding and every
   `#[uniffi::export]` sit behind a feature `ffi`, with `uniffi` an
   optional dependency: HandCore's archive turns it on, brev-mail never
   does (item 5). It holds the SDK's one fixed store schema (§4.1), the FFI
   objects, the error enum, the release markers and a dependency whitelist
   like `check-vault-deps.sh`: no network, no brev-mail, no x25519-dalek
   unless Q4 says so, no reqwest.
4. **`hand-verify`**, a new bin-only crate: the command-line verifier over
   `brev-hand::verify`, JSON out (`serde_json`, and `anyhow` for bins;
   both approved). The library *is* brev-hand. No separate verify crate is
   needed.
5. **`brev-mail`**: no change now beyond item 2's call sites. **Later, yes,
   it should sit on brev-sdk's Rust API, with `ffi` off**, for two reasons.
   First, the showcase then really runs on the SDK. Second, a binary can
   link only one Rust archive (ARCHITECTURE-REUSE §5 item 2), so Brev could
   never use an SDK feature beside `libbrev_core.a` otherwise. With `ffi`
   on, brev-sdk's exports and records would land in `libbrev_core.a`, and
   `uniffi-bindgen --library` would emit a second Swift module beside
   `BrevCore.swift`, with a second `Sample`, `Design`, `KeyOrigin` and
   `LockCause`. Cargo unifies features in a workspace build, so a symbol
   check runs on the archive itself. But not before the exam editor
   works. Brev is owner-tested (D-0112), and the move changes its session
   code. It is the last Mac step (§11 step 11).

No crate is renamed. `brev-` stays as a prefix inside the repo. The name
the SDK ships under is part of Q1.

## 4. The SDK API surface (sketch)

UniFFI proc-macro style, like brev-mail. Content crosses the FFI only as
bytes the caller wipes on the way in, and as `OpenText` 960-byte chunks on
the way out, never as `String`. Errors are one enum, `SdkError`: the
vault's variants in its order (`Locked`, `WrongKey`, `Crypto`, `NotFound`,
`Malformed`, `Corrupt`, `Rng`, `Io`, `Storage`, `Busy`, `Unsafe`), then
`Duplicate`, `Environment { facts: Vec<String> }` and `Signing`.

### 4.1 Vault: a sealed store the host fills

One fixed schema that every host shares. The host picks record kinds
(numbers that name a type of record, never an item; kind 0 is the SDK's
own) and ids. An id is exactly 16 bytes; any other length is `Malformed`.
The SDK seals every value, padded, with the row's kind and id in the AD.
There is no host-supplied SQL, and no plaintext column except kind and id.
Those two leak nothing only if the host makes ids random or opaque (§6).

```sql
meta(k INTEGER PRIMARY KEY, v BLOB)                  -- author key, sealed key check
records(kind INTEGER, id BLOB, value BLOB,           -- id: 16 bytes; value: sealed, padded
        PRIMARY KEY (kind, id))
```

```rust
#[derive(uniffi::Object)]
pub struct Vault { /* timer, Arc<Mutex<Session>> as in brev-mail */ }

#[uniffi::export]
impl Vault {
    /// New store in `dir` (absolute, 0700, one store per folder). `dek`: 32
    /// bytes from the adapter, copied and wiped. `author_key`: the P-256
    /// public key (65 bytes) of the adapter's hardware key; stored, and used
    /// to check every signature the adapter hands back. Returns it locked.
    #[uniffi::constructor]
    pub fn create(dir: String, dek: &[u8], author_key: &[u8]) -> Result<Arc<Vault>, SdkError>;
    #[uniffi::constructor]
    pub fn open(dir: String) -> Result<Arc<Vault>, SdkError>;

    /// Two-step unlock, as Brev: armed until `confirm_active` within 2 s.
    pub fn unlock(&self, dek: &[u8], idle_secs: u32) -> Result<(), SdkError>;
    pub fn confirm_active(&self, sample: Sample) -> Result<(), SdkError>;
    /// Every 2 s while unlocked. Sudo or SIP off locks at once (D-0109).
    pub fn observe(&self, sample: Sample) -> Result<Vec<LockCause>, SdkError>;
    pub fn note_activity(&self);
    pub fn lock(&self);
    pub fn is_locked(&self) -> bool;

    /// Sealed records owned by the host. `id`: 16 bytes. `value_len` of
    /// `value` is used (the rest is slack the caller wipes), at most 1 MiB
    /// padded.
    pub fn put(&self, kind: u32, id: Vec<u8>, value: &[u8], value_len: u32) -> Result<(), SdkError>;
    pub fn open_record(&self, kind: u32, id: Vec<u8>) -> Result<Arc<OpenText>, SdkError>;
    pub fn ids(&self, kind: u32) -> Result<Vec<Vec<u8>>, SdkError>;
    pub fn delete(&self, kind: u32, id: Vec<u8>) -> Result<(), SdkError>;
}
```

The key check at unlock is the sealed `meta` row, as brev-mail's identity
row is today.

### 4.2 Hand: a session bound to one record

One Hand session at a time per vault, like Brev's compose session. It is
bound to one record from its start. Samples reach it through `observe`, so
there is one sampling loop, not two. The token covers the bound record as
sealed, so the text does not cross the FFI a second time.

```rust
#[uniffi::export]
impl Vault {
    /// Starts the fact log for the record (`kind`, `id`), which must not
    /// exist yet (`Duplicate`); the host writes it with `put` while the
    /// session runs. `purpose`: a fixed label compiled into the host (for
    /// example "no.example.exam.answer/v1"). `context`: the bytes the token
    /// must be bound to (the exam's submission id, §8). `design`, `admin`
    /// and `key` as Brev's `compose_started`.
    pub fn hand_start(&self, kind: u32, id: Vec<u8>, purpose: String, context: Vec<u8>,
                      design: Design, admin: Option<bool>, key: KeyOrigin) -> Result<(), SdkError>;
    /// Only if Q2 part 2 is (b): continues the log sealed beside the record
    /// after a lock. Each design fact keeps its worse value.
    pub fn hand_resume(&self, kind: u32, id: Vec<u8>, design: Design,
                       admin: Option<bool>, key: KeyOrigin) -> Result<(), SdkError>;
    pub fn hand_synthetic_dropped(&self) -> Result<(), SdkError>;
    pub fn hand_paste_accepted(&self) -> Result<(), SdkError>;
    /// Freezes the facts with `sample` and computes the class, refusing
    /// (`Environment`) only below what Q2 part 1 allows. Hashes the bound
    /// record's plaintext inside Rust, and returns the digest the adapter
    /// signs.
    pub fn hand_finish(&self, sample: Sample) -> Result<Vec<u8>, SdkError>;
    /// The adapter's DER signature over that digest, checked against
    /// `author_key`. Returns the token (not secret). `Signing` forgets it.
    pub fn hand_attach(&self, signature: Vec<u8>) -> Result<Vec<u8>, SdkError>;
    pub fn hand_cancel(&self);
}
```

**The binding.** A lock or `hand_cancel` ends the session and wipes its
log; the sealed record stays. A new `hand_start` over that record is
`Duplicate`, so no session finishes over text it did not see written. A
`put` into the record outside its session is allowed, but the record can
then never be finished. Under Q2 part 2 (b), every `put` into the bound
record also seals the log (counts only, no content) in the same
transaction, as a kind-0 row with the same id, and `hand_resume` continues
it. A `put` into that record while no session runs, or a `delete`, removes
that sealed log for good. Inside a session the SDK cannot tell typed bytes
from imported ones; that is the host's word (§10).

The SDK profile's content hash is:

```
content = SHA-256( "hand/v1/content\0" || u16 len || purpose || u16 len || context || record )
```

Brev's profile keeps its own domain and its own `letter` bytes (§3 item 2).
A token made under one profile fails under the other (`eat_profile`
differs), and a token for one purpose or context fails for another (the
hash differs).

### 4.3 Keys: the platform signs, the core checks

The core never holds a signing key, on any platform that has an adapter
(Linux has none yet: §5, Q5). The adapter creates the author key, the KEK
and the DEK, wraps and unwraps the DEK, and signs the digests the core
returns: registration (`registration_digest`, §4.4) and token. The core
checks every signature against `author_key` before it uses one. Swift never
verifies (CLAUDE.md §3.3) and hashes nothing: every digest comes from the
core. On Mac this is Brev's `Enclave`,
`KeyStore`, `UnlockService` and `SignService`, with the host's access
group. One fresh `LAContext` per signature run, dropped on every way out
(AUTHORSHIP §3.2).

### 4.4 Verification (any side, no vault needed)

```rust
#[uniffi::export]
pub fn verify(purpose: String, context: Vec<u8>, content: &[u8], token: &[u8],
              author_key: &[u8], received_at: u64) -> Verification;   // record of brev-hand's checks
/// SHA-256("hand/v1/register\0" || challenge); `challenge`: 32 bytes from the host's server.
#[uniffi::export]
pub fn registration_digest(challenge: &[u8]) -> Result<Vec<u8>, SdkError>;
#[uniffi::export]
pub fn verify_key_proof(challenge: &[u8], author_key: &[u8], signature: &[u8]) -> bool;
```

`verify` checks the token only. Checks that belong to one use, such as an
exam's time rules (§8), are the caller's.

## 5. The platform adapter contract: facts, not flags

The adapter hands over what it read. The core counts, applies the lists
and decides the class. The adapter has no setter for a count, a fact or a
class (AUTHORSHIP §3.1), nor for the platform (below). A read that fails is `None`, and
`None` gives B (D-0107 item 3).

**What every adapter must provide:**

1. A hardware key that asks for user presence on every signature. The
   adapter signs digests with it, and gives its public key and its origin,
   read from the key's own attributes.
2. A KEK that wraps a 32-byte DEK, with one presence check per unlock.
3. Raw samples: every 2 s while unlocked, one at `confirm_active`, and one
   at `hand_finish`.
4. The design facts, read at `hand_start` from what the app does: no AX
   text, no Copy/Cut/Paste, the input filter in place.
5. Events: each synthetic input dropped, each paste accepted.
6. Lock triggers: resign active, screen lock, sleep, user switch. Each one
   calls `lock()` and blanks the views. The adapter also blanks when
   `is_locked()` turns true on its own.

**Per platform.** The class is never configured per platform. It follows
from which facts the platform can read and which key it has. Columns other
than macOS are candidates and need a spike each.

| Fact / need | macOS (built) | iOS/iPadOS | Windows | Linux |
|---|---|---|---|---|
| Key | Secure Enclave + Touch ID | Secure Enclave + Face/Touch ID | TPM (NCrypt platform provider) + Windows Hello | none chosen: no standard presence-gated hardware key, and a software key needs a signer (Q5) |
| Presence is biometric only | yes (`.biometryCurrentSet`) | yes | **no**: Hello allows a PIN | no |
| `secure-input` | `IsSecureEventInputEnabled()` | not applicable (no global taps) | no equivalent: `None` | X11: none; Wayland: compositor-dependent |
| `capture-off` | `sharingType` + `preventsCapture` layer | `isCaptured`, secure text layers | `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` | none |
| `sip` | `csr_get_active_config` | not applicable | no equivalent: `None` | none |
| `sudo` | `sysctl KERN_PROC_ALL` names | not readable | process snapshot (elevated or `sudo.exe`) | `/proc` |
| `agents`, `windows` | process names, window owners | not readable | process snapshot, `EnumWindows` | `/proc`, X11/Wayland |
| `input-filter` | `eventSourceUnixProcessID != 0` | not applicable | `LLKHF_INJECTED` (candidate) | none reliable |
| App attestation | none (D-0108) | **App Attest** | none for apps | none |
| **Class under today's rule** | **A** (D-0112) | **B** (unreadable facts) | **B** | **no adapter** until Q5 |

Two changes to the rule are needed before other platforms, and each is a
token profile change. Both are decided at their platform's step, not now:

- **"Not applicable" is not "unreadable".** On iOS, other apps cannot tap
  keys or list processes, so those facts are guaranteed by the OS, not
  missing. The owner's picture puts iOS in class A. That needs a table *in
  the core* of the facts each platform guarantees, and two rules so the
  table is not a flag under another name. (1) The core sets the token's
  `platform` from `cfg!(target_os)`; no adapter call sets it. That stops a
  bug in the Mac adapter from claiming iOS. (2) A verifier applies the
  table only when the token carries an `app-attest` claim that verified.
  Without it, the iOS facts that cannot be read stay `None` and give B.
  That stops any other signer, since `platform` is only the signer's word.
- **Presence method.** brev-hand's `classify` sets `biometric_used = true`
  because Brev's key demands Touch ID. Windows Hello can fall back to a PIN
  (compare CLAUDE.md §1.8), so a presence fact read from the key, and a
  new platform code, must come first.

## 6. The secure UI kit

**What a host app must use** to keep the promise for its content views:

- the protected layer (`ContentView`): content only as pixels, drawn into
  `preventsCapture` buffers, zeroed on lock; `draw(_:)` draws nothing;
- `OpaqueView` as the base of every view that can show content: no AX
  element or value, no context menu, no Services, no drag;
- `SecureComposeView`: secure event input on focus, no pasteboard, no
  autocorrect, no spell check, no Writing Tools, no input context;
- the application class that applies `InputFilter` to every event, and
  `HumanButton` for every action that unlocks, signs or submits;
- `HardenedWindow`: `sharingType = .none`, not in the Windows menu, applied
  to sheets and child windows;
- `LaunchGuard`, `SecretBytes`/`SecretText` for every Swift buffer of
  content, and the lock controller pattern with its wipe order.

**How it ships.** As one Swift package with two library targets.
`HandKit` is source only: the kit's AppKit sources and the macOS adapter.
It names no generated type; the files that name one today (`HandSampler`,
`EnvironmentProbe`, `LockController`) return or take the kit's own Swift
values. `HandCore` holds the XCFramework as a binary target (§9), the
generated bindings (patched by `patch-bindings.py`) and a small glue file
that maps the kit's values to brev_sdk's records. A new host takes both.
Brev takes only `HandKit` and keeps its own glue to `BrevCore`, so it still
links one Rust archive. The package is our own, so it adds no third-party
code. It is source, so a customer can review what runs in their app. In
the first steps `HandKit` is a copy of Brev's files, generalised (names,
access group, labels). A check script pairs each kit file with its Brev
file until Brev adopts the package (step 11), so a fix in one cannot
silently miss the other.

**What the host must set up** that the kit cannot: `NSPrincipalClass` set
to the kit's application class; `LSEnvironment` `MallocScribble=1`;
Hardened Runtime, App Sandbox, no `get-task-allow`, library validation;
no AppleScript dictionary, Services, URL types or document types; its own
keychain access group.

**CLAUDE.md §1: who enforces what.** §1 is Brev's promise and stays in
full for Brev. A host on the SDK makes its own promise. The table says
which parts the SDK can hold for it.

| §1 | SDK enforces itself | Host must uphold (kit helps) |
|---|---|---|
| 1 no plaintext on disk | its store: ciphertext only, no logs, 0600/0700 | everything the host writes itself: caches, autosave, crash logs; record ids random or opaque, never a title, a name or a candidate number |
| 2 no AX text | Hand's `ax-opaque` fact lowers the class if broken | the views (`OpaqueView`) |
| 3 no pasteboard | Hand counts pastes; any paste gives B | the views and menus |
| 4 no programmatic content interface | the SDK has no IPC, no export, and content only as `OpenText` chunks to its own process | every interface the host adds; the host's own submit path (§8) is its one allowed exit |
| 5 no content in notifications, titles, Spotlight | — | the host |
| 6 no autocorrect, dictation, Writing Tools | — | `SecureComposeView` |
| 7 no own crypto, audited crates only | yes | yes (no crypto in Swift beyond Security) |
| 8 biometric only, no password | the class rule assumes it on Mac | the adapter's key flags |
| 9 keys this-device-only, no backup | — | the adapter's key flags; backup exclusion |
| 10 wipe plaintext early | allocator, `Plaintext`, scrubs, lock wipes, launch guard | `SecretBytes`, the wipe order on lock |

The SDK cannot see most of the host's column. The class catches honest
bugs there, not a host that lies (§10).

## 7. Verification

**Verifier.** Everything is one Rust function, `brev-hand::verify`, with the
profile added. It ships three ways:

1. **Native CLI, now:** `hand-verify --purpose … --context <hex>
   --content <file> --token <file> --key <hex> --received-at <unix>`. It
   prints each check and the facts as JSON. The exit code is 0 only if
   every token check passes. That means "the token is valid", not "the
   answer met the exam's rules". It is reproducible, and its hash is
   published, so an institution can rebuild it.
2. **The `verify` export in the SDK**, for the institution's server and
   for tools in Swift or Kotlin.
3. **Later, WASM or a service.** WASM needs brev-hand's verify path free of
   brev-vault and brev-proto, because rusqlite's bundled C does not build
   for `wasm32-unknown-unknown`. The split: move `platform.rs`'s class types
   into brev-hand, keep `Claims::new`/`FactLog` behind a `sender` feature,
   and verify P-256 there. It also needs `wasm-bindgen` (a new crate). Not
   now.

**Key trust: how a verifier learns the author's key.** The token proves
only "the holder of this key signed these statements about this content".
So the whole value rests on binding the key to a person. For the exam
editor:

1. At first start the editor creates the keys (§4.3).
2. The student logs in to the institution (its own login, for example
   Feide, outside the SDK). The institution's server returns a random
   32-byte challenge.
3. The editor gets `registration_digest(challenge)` from the core and signs
   it with one Touch ID. The server checks it with `verify_key_proof` and
   stores (student, key, registered_at) in its registry. A new key (a new
   Mac, or changed fingerprints under `.biometryCurrentSet`) means a new
   registration, and the registry keeps the history. While one of the
   student's exams is open, the server refuses a new registration (Q3).
4. When the server issues a submission id (§8), it records the student's
   key that is active at that moment. A verifier checks the token against
   that one key: never another key from the registry, and never a key from
   the submission.

A key registered before the exam on someone else's Mac is still the
student's own act; the registry cannot tell (§10). Q3 asks whether the
registry is enough, or whether the institution should sign a key
certificate that verifiers check offline.

**What a badge may claim.** Only what the checks proved, in the words of
AUTHORSHIP §6. For an exam answer, only the institution's server shows the
badge, after `verify` and its policy checks (§8); an examiner's view shows
the server's result.

- «Skrevet i ‹app› · klasse A» (or B or C) when every check passes;
  otherwise «Ikke verifisert»;
- in the detail: each check, the facts as numbers, «Nøkkelen er registrert
  på ‹kandidat› ‹dato›» from the registry, and on Mac always «Appen er ikke
  bekreftet av Apple (støttes ikke på Mac)».

A badge must never say «menneske», «uten KI», «uten hjelp» or «skrevet av
kandidaten» (D-0107 item 4, §10).

## 8. The first customer end to end: the exam editor

```
 institution server                 exam editor (Mac)                    examiner
 ─────────────────                  ─────────────────                    ────────
 registry: student → key   ◄──(0) register key, one Touch ID
 exam opens: issue
   submission_id (16 B random),
   store (student, exam, key,
          issued_at)       ──(1)──► hand_start(kind, id, purpose, context = submission_id)
                                            student writes in SecureComposeView;
                                            observe every 2 s; put(answer) sealed often
                                    (2) Levér: hand_finish → one Touch ID → hand_attach
 received_at := own clock   ◄──(3)── answer + token (the host's submit path, Q4)
 verify + policy, stores once ─────────────────────────────────────────►  badge
```

**Binding and replay.** The content hash covers `purpose || submission_id ||
answer`, and the verifier uses the key the server recorded with that
submission id. So a token cannot move to another answer, another exam or
another student, and a key registered during the exam cannot sign for the
student. The server takes the submission id only from a student it issued
it to. It stores each (submission id, token) once, and the same token again
is a duplicate. Re-delivery before the deadline is a new token over the new
answer. The server keeps the last one it received.

**The time window.** The submission id is random and issued when the exam
opens, so no token for it can exist before `issued_at`. The server stamps
`received_at` with its own clock and refuses anything after the exam's end
plus grace. `verify` checks brev-hand's window (`received_at − 24 h ≤ iat ≤
received_at + 5 min`). The server's policy adds `issued_at ≤ iat` and
`seconds ≤ received_at − issued_at` + 5 min; `hand-verify` and the `verify`
export do not run these. `iat` is the student's clock (AUTHORSHIP §7), so
`issued_at ≤ iat` adds little beyond the random submission id.

**A lock during the exam.** A sudo or SIP-off sample, or the idle deadline,
locks the vault (D-0109). The answer is never lost: the editor seals it
with `put` every few seconds, and a sealed record survives every lock. What
a lock loses is the fact log in memory, and with it the answer's chance of
a token (§4.2). For a three-hour exam that is too harsh, so Q2 proposes:
the log is sealed beside the answer and resumed with `hand_resume` after
the next unlock (part 2 (b)). The time locked is a gap over 5 s, so the
answer is class B, and the examiner sees «målingen hadde et hull». That
answer gets a token only if part 1 allows B: (a), or (b) with a threshold
of B. Under (c) a lock ends the student's chance to deliver with a proof.
The exam editor uses part 1 (a) and part 2 (b).

**What the examiner learns, and what the student must be told:** the
platform, whether the user is an admin, whether SIP was on, the counts, how
long the writing took, and whether the measuring had a hole. The editor's
onboarding must say so (AUTHORSHIP §7, last paragraph).

## 9. Languages, distribution, build

| Language | How | New crate or tool (owner's yes needed) |
|---|---|---|
| Swift (macOS first, iOS later) | `cargo build --release -p brev-sdk --features ffi` per target; `uniffi-bindgen` Swift; `xcodebuild -create-xcframework` (approved tools); the `HandCore` target with the XCFramework as a binary target (with checksum) | none for macOS arm64. A universal (x86_64) slice and iOS targets are only new rustup targets. |
| Kotlin (Android later, JVM verifier) | `uniffi-bindgen` generates Kotlin (built in) | **JNA**, the Java library UniFFI's Kotlin code loads through; the **Android NDK** and possibly **cargo-ndk** for the Android build |
| C# (Windows) | no generator in UniFFI | **uniffi-bindgen-cs** (third party, NordSecurity), pinned to a uniffi release that may lag 0.32. Q5. |
| Linux signing | no hardware key (§5) | **P-256 signing**: `p256` signing in the core (§4 approves it for verification only), or a crypto library in the host's language. Q5. |
| WASM verifier | §7 item 3 | **wasm-bindgen** |
| iOS App Attest check | reserved `"app-attest"` claim, AUTHORSHIP §5 | **p384** (Apple's root is P-384, D-0108). Q6. |

**Build and reproducibility.** Everything Brev does for its archive applies
to the SDK's archive:

- uniffi pinned to 0.32.2, `patch-bindings.py` on the generated Swift (the
  build fails if a patch no longer applies), and a surface pin file
  `scripts/sdk-ffi-surface.txt` compared on every test run;
- the default features: launch guard and zeroing allocator on, and never
  `test-hooks` or `allow-software-keys`. The marker check runs on the
  XCFramework's archive and in `HandCore`'s build;
- `Cargo.lock` committed, `cargo-deny` and `cargo-audit`, and
  `scripts/repro-build.sh` extended to rebuild the XCFramework and
  `hand-verify` and compare hashes (docs/REPRODUCIBLE_BUILD.md);
- one Rust archive per binary: a host links `HandCore` and no other Rust
  archive.

## 10. What the SDK does not promise

Everything in AUTHORSHIP §7 holds for every app on the SDK, with "Brev"
read as "the app". Stated for the exam case:

- **That the editor was used at all, on Mac.** There is no App Attest for
  Mac apps (D-0108). The registry cannot tell the editor from a script
  that made its own P-256 key, even a Secure Enclave key. Such a script
  can register, then sign class A tokens over AI-written text. **In an
  exam the author is the adversary**, unlike in Brev. So on student-owned
  Macs, Hand catches bugs and deters casual cheating. It does not stop a
  student who writes a program. Q6.
- **Who typed**, and **where the words came from.** Copy-typing from a
  phone or paper, dictation into another device, and hardware or virtual
  keyboards that type prepared text all pass (AUTHORSHIP §7).
- **Anything under root or kernel compromise**, and a cached sudo login.
- **Whose finger**: an enrolled finger, not a willing or particular one.
- **The student's clock**: `iat` is theirs, and `received_at` is the
  server's.
- **The host app's own column in §6.** The design facts and the key origin
  are the host's word.
- **Anything after the content leaves**: what the examiner or the
  institution does with the answer.

## 11. Work order

Mac and Swift first. Each step is one commit with its tests. Brev's
`scripts/test.sh` must stay green at every step.

1. **brev-hand `HandProfile`.** `content_hash`, `Claims::new` and `verify`
   take the profile; brev-mail's call sites follow (§3 item 2). Test:
   `BREV_V1`'s content hash equals today's
   `SHA-256("brev/v1/hand/content\0" || letter)`; a token saved before the
   change (a new fixed test vector) still verifies and re-encodes byte for
   byte under `BREV_V1`; brev-hand's and brev-mail's tests pass with only
   the call sites changed; a token under one profile fails under the other;
   the SDK content hash differs for another purpose or context.
2. **brev-sdk skeleton.** UniFFI behind `ffi`, `ping`, the surface pin, the
   dependency whitelist script with a control, the release marker. Test:
   the bindings generate and are patched; the surface matches; the
   whitelist fails on brev-mail; built without `ffi`, the archive has no
   `uniffi_brev_sdk_*` symbol.
3. **SDK Vault.** Test: no-plaintext scan of the store with a marker; lock
   zeroes the DEK and closes every `OpenText`; `Busy`, `Unsafe`, `Corrupt`;
   two records swapped between rows fail to open (AD binding); an id of 15
   or 17 bytes is `Malformed`; a sudo sample locks.
4. **SDK Hand.** Test: round trip with a test signer → `verify` passes in
   class A; each B case names its fact; a lock mid-session wipes the pending
   hash; `hand_start` over an existing record is `Duplicate`; a `put`
   outside the session leaves a record that cannot be finished; a
   registration preimage never starts like a token's Sig_structure (as
   brev-hand's `token_and_envelope_signatures_do_not_cross`), and a
   registration signature is not valid as a token signature, and the
   reverse; the record's plaintext is dropped at `hand_attach`.
5. **`hand-verify` CLI and the `verify` export.** Test: step 4's vectors
   pass; tampered content, token, key and time fail with the right check;
   the JSON is stable (golden file).
6. **HandKit package.** The kit's files, generalised, plus the pairing check
   against Brev's files. Test: the package builds; the `HandKit` target
   builds without the binary; the kit's unit parts (InputFilter,
   HandSampler) pass in the CLI harness.
7. **Demo host.** A minimal Mac app on HandKit: one protected editor, `put`,
   finish, token to a file. Test: lock-probe checks (capture, AX,
   pasteboard, blank on lock), then an owner run on the real Mac (new
   VERIFY rows: one Touch ID per finish, sudo locks).
8. **Exam flow against an in-process mock server** (no server crate):
   register, issue, submit, verify with policy. Test: replay, a moved
   token, the wrong student's key, a registration while the exam is open
   (refused), a token by the student's other registered key (fails), a
   late submission, and a lock giving B (if Q2 says so).
9. **Exam editor pilot build** for the customer, on the answers to Q1–Q6.
10. **Next platform.** iOS (App Attest) or Windows, as Q6 decides: a facts
    spike first, then the profile change of §5, then its adapter and, for
    Windows, C# (Q5).
11. **Brev on the SDK.** brev-mail uses brev-sdk's Rust API with `ffi` off,
    and the app uses the `HandKit` target only. Test: Brev's full
    `scripts/test.sh`, the brev_core surface pin unchanged, no
    `uniffi_brev_sdk_*` symbol in `libbrev_core.a`, and V82–V84 rerun by
    the owner.
12. **WASM verifier**, if an institution needs it in a browser.

## 12. Spørsmål til eier

**Q1. Navn og tokenprofil.**
(a) Én profil for hele SDK-en (`tag:‹domene›,2026:hand-sdk-v1`). Appens
formål ligger i innholds-hashen.
(b) Én profil per app.
(c) Bruk Brevs `hand-v1` som den er.
*Anbefaling: (a).* Da har alle verifikatorer én regel, og formålet holder
appene fra hverandre. (b) gir ingenting ekstra på Mac. (c) er låst til
macOS og Brevs brevformat. Velg også domenet i taggen (`brev.no` er bare en
plassholder) og navnet SDK-en skal hete.

**Q2. Terskel og lås under eksamen.** To valg som henger sammen.
Del 1: når får en tekst bevis?
(a) Alltid. Beviset sier klassen, og merket viser A, B eller C.
(b) Hver profil har en fast terskel. Den er bygget inn i koden og er aldri
en innstilling.
(c) Bare i klasse A, som i Brev. Da stopper en lås studenten fra å levere
med bevis.
Del 2: hva skjer etter en lås? Teksten er alltid trygg, for den ligger
forseglet. Det som går tapt, er målingen.
(a) Som i Brev: målingen er borte, og svaret kan aldri få bevis.
(b) Målingen lagres forseglet ved siden av svaret. Etter opplåsing
fortsetter editoren den med vilje. Hullet gir klasse B.
*Anbefaling: del 1 (a) og del 2 (b). Det er dette eksamens-editoren
bruker.* Ingen student mister beviset på grunn av en lås, og hullet vises
ærlig som B. Låsen er lik i alle apper og blir aldri en innstilling. Brev
beholder sin egen terskel A.

**Q3. Hvordan sensor vet hvilken nøkkel som er studentens.**
(a) Institusjonens register, fylt når studenten logger inn (§7). Serveren
husker hvilken nøkkel studenten hadde da eksamen åpnet, og sjekker bare mot
den.
(b) Som (a), og i tillegg signerer institusjonen et lite nøkkelsertifikat
som kan sjekkes uten nett. Det bruker samme CBOR-kode og trenger ingen ny
crate.
(c) Plattformen bekrefter nøkkelen (Managed Device Attestation, TPM).
Og: skal en ny nøkkel mens en eksamen er åpen avvises, eller bare vises i
merkets detaljer?
*Anbefaling: (a) nå, og (b) når noen utenfor institusjonen skal sjekke.
Avvis nye nøkler mens en eksamen er åpen.* (c) viser at nøkkelen er i
maskinvare, ikke at editoren brukte den.

**Q4. Hvordan svaret kommer fram til institusjonen.**
(a) Appen sender det over TLS fra sitt eget minne.
(b) SDK-en krypterer svaret i Rust til institusjonens X25519-nøkkel, slik
brev-mail gjør. Det bruker x25519-dalek, hkdf og chacha20poly1305, som
alle er godkjent. Teksten forlater da Rust bare kryptert.
*Anbefaling: (b).* Regelen «innhold bare som chiffertekst» holder helt til
siste steg, uten nye crates.

**Q5. Nye verktøy for Windows og Linux.**
Del 1, C#: UniFFI har ingen C#-generator.
(a) `uniffi-bindgen-cs` (tredjepart, NordSecurity), låst til én versjon og
bare brukt når vi bygger.
(b) Et håndskrevet C-grensesnitt. Det trenger `unsafe`, som CLAUDE.md §6
forbyr.
(c) Ingen C# før vi har testet Windows.
Del 2, Linux: Linux har ingen vanlig maskinvarenøkkel med fingeravtrykk.
Da må noen signere med en nøkkel i programvare.
(a) Kjernen signerer med `p256`. I dag er `p256` bare godkjent for å sjekke
signaturer.
(b) Appen signerer med et kryptobibliotek i sitt eget språk. Det er ikke
godkjent.
(c) Ingen Linux-adapter ennå.
*Anbefaling: C# (c), så (a) hvis verktøyet støtter vår uniffi-versjon da.
Linux (c).* Ingen trenger C# før Windows, og et bevis fra Linux ville bare
bli klasse C.

**Q6. Hvilke maskiner eksamenspiloten bruker.** På Mac kan beviset ikke
vise at det var editoren som skrev (§10).
(a) Studentenes egne Mac-er, bare til øving og tilbakemelding. Grensen står
i merkets detaljer.
(b) iPad, der App Attest beviser appen. Det trenger `p384` (ny crate), et
UI-sett for iOS og regelen i §5: fakta som iOS garanterer, teller bare når
beviset har en verifisert `app-attest`.
(c) Mac-er som institusjonen eier og styrer, der editoren installeres og
registreres under tilsyn.
*Anbefaling: (a) for piloten nå, og (b) som neste plattform før Windows
hvis kunden vil ha eksamener som teller.* Windows kan i dag ikke bevise mer
enn en Mac (klasse B, og Windows Hello tillater PIN).
