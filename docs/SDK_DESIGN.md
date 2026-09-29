# The core as an SDK — design

## Kort fortalt

Rust-kjernen blir en SDK som andre apper kan bygge på, og Brev blir
utstillingsvinduet. SDK-en gir en forseglet lagring og et bevis for hvordan
en tekst ble skrevet. Det finnes ingen klasser lenger: enten holder alle
kravene, og appen får et bevis, eller så får den ikke noe bevis. Merket
sier bare «Skrevet i ‹app›» eller «Ikke verifisert», og detaljene viser
tallene. Teksten forlater Rust bare kryptert til mottakeren, og mottakeren
sjekker nøkkelen mot sitt eget register. I dag kan bare Mac lage bevis;
Windows og Linux kan ikke før de kan lese alle kravene. Ett åpent spørsmål
og én ja/nei-sjekk til deg står nederst.

Status: design only, for the owner to read before any code. Nothing here is
built. Base: branch `claude/laughing-knuth-yhp8ji`, code as at 444934b
(Hand done on Mac, D-0112). Revised 2026-09-29 with the owner's answers:
no classes, a generic host app and verifier, a key registry, sealing in
Rust, no C# or Linux yet. Paths are relative to the repo root.

The owner's picture: apps (Brev post as the showcase, other apps later) sit
on an SDK in Swift, Kotlin and C#. Under the SDK, a platform adapter per OS
observes and reports facts. The Rust core decides. Hand (the proof,
docs/AUTHORSHIP.md) sits over Vault (the safe). A verification API lets a
recipient check the proof and show a badge.

Two words used throughout. The **host app** is any app built on the SDK.
The **verifier** is whoever receives the text and checks its proof,
usually an organisation with its own server.

## 1. The goal

The SDK lets any app prove how a piece of text was written: with a hardware
key and one biometric check, inside protected views, while the core measured
the device and found every requirement met (§5). It keeps that text sealed
on the device, and hands it out only as ciphertext to the verifier. Anyone
who holds the author's public key can check the proof with a small
verifier, without the host app.

**What "generic" means here.** The SDK knows nothing about mail: no
contacts, threads, letters, relay, envelopes or invites. The host app
decides what its records are, what the text is, where it is sent and how
the author's key is registered. The SDK does not become generic by getting
weaker. The lock rule, the requirements, the sealing, the wiping and the
facts-not-flags adapter stay exactly as strict as in Brev. What changes is
only who names the content and who receives it.

## 2. What exists

| Part | Where | Reusable as is | Mail-specific | Swift-only |
|---|---|---|---|---|
| Encrypted store, DEK, lock state, two-step unlock, idle timer, column AEAD, padding, `Plaintext`/`Text`, stack scrubs, zeroing allocator, launch guard | `core/brev-vault` | yes, through `VaultConfig` (docs/ARCHITECTURE-REUSE.md §4) | no; but the column label `brev/v0/column/`, `CHUNK` = 960 and the buckets carry Brev's format (§5 item 3 there) | no |
| Key origin and the class of a report (`KeyOrigin`, `EnvironmentClass`, `classify`: A, B, C) | `core/brev-vault/src/platform.rs` | `KeyOrigin` yes; the classes go (§12 step 1) | no | no |
| Facts from raw samples (`FactLog`, `Sample`, `Design`), lock rule (sudo, SIP), class rule, token (COSE_Sign1, fixed CBOR, with a `class` claim), `verify` | `core/brev-hand` | mostly: the facts, the lock rule and the token are generic; the class rule becomes the requirement check (§5) | the profile string, the content-hash domain `brev/v1/hand/content\0`, and `"platform"` fixed to 1 (macOS; decode refuses anything else) | no |
| P-256 verification (`sig::verify`, `der_to_raw`) | `core/brev-proto/src/sig.rs` | yes | the rest of brev-proto is Brev's wire format | no |
| Identity, contacts, threads, letters, schema v6 (a sent letter's `env_class`), X25519 + HKDF message crypto, relay client, the whole UniFFI surface (`Brev`, `OpenText`, `BrevError`, `Proof` with its `class`) | `core/brev-mail` (lib `brev_core`) | the FFI *glue pattern* (session mutex, `Finish` guard, `used`/`dek32`, `OpenText`, epoch) by copying; the sealing construction | yes | no |
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

In short: Rust is ready to be reused, but has no FFI outside mail, and it
still has classes. The security kit is complete but lives inside the app as
loose files.

## 3. Layers and crates

```
 host app
   ├─ HandKit (Swift, source only): UI kit + macOS adapter; names no generated type
   └─ HandCore (Swift): generated bindings + glue from HandKit's values
        └─ HandCore.xcframework  ← brev-sdk, feature `ffi` (UniFFI, staticlib)
             ├─ brev-hand   (facts, requirements, lock rule, token, verify)
             │    └─ brev-proto::sig (P-256 verify)
             └─ brev-vault  (store, DEK, lock state, sealing, wiping)
 Brev post (from §12 step 11): HandKit only; libbrev_core.a = brev-mail over brev-sdk, `ffi` off
 verifier
   └─ hand-verify (CLI) or brev-sdk's `verify` and `open_sealed`, over brev-hand::verify
```

**The crate plan (smallest thing that works):**

1. **`brev-vault`**: `EnvironmentClass` and `classify` go; `KeyOrigin`
   stays. That is part of removing the classes (§12 step 1), not of the
   SDK itself.
2. **`brev-hand`**: after step 1, a `HandProfile` value carries the
   constants: the `eat_profile` string, the content-hash domain and the
   allowed platform codes. `BREV` gives Brev's bytes exactly as step 1
   left them. The SDK gets its own profile (§4.2, Q1). This changes
   signatures, not only constants: `content_hash`, `Claims::new` and
   `verify` take the profile, and under the SDK profile also the purpose
   and context (§4.2). `Claims::new` sets `platform` from
   `cfg!(target_os)` (§5). Brev's call sites change in the same step:
   `Claims::new` in `core/brev-mail/src/ffi.rs` (send) and
   `src/test_keys.rs`, `brev_hand::verify` in `src/store.rs` (receive),
   and the test tokens in `tests/common/mod.rs`.
3. **`brev-sdk`**, a new crate beside `brev-mail`. It is the UniFFI crate
   of the SDK (`crate-type = ["lib", "staticlib", "cdylib"]`, its own lib
   name, its own `uniffi.toml`). Its scaffolding and every
   `#[uniffi::export]` sit behind a feature `ffi`, with `uniffi` an
   optional dependency: HandCore's archive turns it on, brev-mail never
   does (item 5). It holds the SDK's one fixed store schema (§4.1), the
   sealing to the verifier (§4.3), the FFI objects, the error enum, the
   release markers and a dependency whitelist like `check-vault-deps.sh`:
   `x25519-dalek`, `hkdf` and `chacha20poly1305` for the sealing (all
   approved), and no network, no brev-mail, no reqwest.
4. **`hand-verify`**, a new bin-only crate: the command-line verifier over
   `brev-hand::verify`, JSON out (`serde_json`, and `anyhow` for bins;
   both approved). The library *is* brev-hand. No separate verify crate is
   needed.
5. **`brev-mail`**: no change now beyond step 1 and item 2's call sites.
   **Later, yes, it should sit on brev-sdk's Rust API, with `ffi` off**,
   for two reasons. First, the showcase then really runs on the SDK.
   Second, a binary can link only one Rust archive (ARCHITECTURE-REUSE §5
   item 2), so Brev could never use an SDK feature beside
   `libbrev_core.a` otherwise. With `ffi` on, brev-sdk's exports and
   records would land in `libbrev_core.a`, and `uniffi-bindgen --library`
   would emit a second Swift module beside `BrevCore.swift`, with a second
   `Sample`, `Design`, `KeyOrigin` and `LockCause`. Cargo unifies features
   in a workspace build, so a symbol check runs on the archive itself. But
   not before a demo host works. Brev is owner-tested (D-0112), and the
   move changes its session code. It is the last Mac step (§12 step 11).

No crate is renamed. `brev-` stays as a prefix inside the repo. The name
the SDK ships under is part of Q1.

## 4. The SDK API surface (sketch)

UniFFI proc-macro style, like brev-mail. Content crosses the FFI only as
bytes the caller wipes on the way in, as `OpenText` 960-byte chunks for the
host's own protected views, and as ciphertext to the verifier. Never as
`String`. Errors are one enum, `SdkError`: the vault's variants in its
order (`Locked`, `WrongKey`, `Crypto`, `NotFound`, `Malformed`, `Corrupt`,
`Rng`, `Io`, `Storage`, `Busy`, `Unsafe`), then `Duplicate`,
`Environment { facts: Vec<String> }` and `Signing`.

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
    /// example "com.example.notes.entry/v1"). `context`: the bytes the token
    /// must be bound to, normally an id the verifier issued (§8). `design`,
    /// `admin` and `key` as Brev's `compose_started`.
    pub fn hand_start(&self, kind: u32, id: Vec<u8>, purpose: String, context: Vec<u8>,
                      design: Design, admin: Option<bool>, key: KeyOrigin) -> Result<(), SdkError>;
    pub fn hand_synthetic_dropped(&self) -> Result<(), SdkError>;
    pub fn hand_paste_accepted(&self) -> Result<(), SdkError>;
    /// Freezes the facts with `sample` and checks the requirements (§5).
    /// Refuses with `Environment`, naming every failed fact, unless all
    /// hold. Hashes the bound record's plaintext inside Rust, and returns
    /// the digest the adapter signs.
    pub fn hand_finish(&self, sample: Sample) -> Result<Vec<u8>, SdkError>;
    /// The adapter's DER signature over that digest, checked against
    /// `author_key`. Seals the record and the token to `recipient` (§4.3)
    /// and returns only that ciphertext. `Signing` forgets the session.
    pub fn hand_attach(&self, signature: Vec<u8>, recipient: Vec<u8>) -> Result<Vec<u8>, SdkError>;
    pub fn hand_cancel(&self);
}
```

**The binding.** A lock or `hand_cancel` ends the session and wipes its
log; the sealed record stays. A new `hand_start` over that record is
`Duplicate`, so no session finishes over text it did not see written. A
`put` into the record outside its session is allowed, but the record can
then never be finished. There is no resume: a lock leaves a hole in the
measuring, and a hole fails the requirements anyway (§5). So a lock while
writing means that record never gets a proof; the text itself is never
lost. Inside a session the SDK cannot tell typed bytes from imported ones;
that is the host's word (§11).

The SDK profile's content hash is:

```
content = SHA-256( "hand/v1/content\0" || u16 len || purpose || u16 len || context || record )
```

Brev's profile keeps its own domain and its own `letter` bytes (§3 item 2).
A token made under one profile fails under the other (`eat_profile`
differs), and a token for one purpose or context fails for another (the
hash differs).

### 4.3 Sealing to the verifier

The record leaves Rust only as ciphertext. `hand_attach` builds the token,
then seals `record || token` to the verifier's X25519 public key (32
bytes), as brev-mail seals a letter: a fresh X25519 key made in Rust,
HKDF-SHA256, XChaCha20-Poly1305, the plaintext padded to the buckets, and
the profile, purpose and context in the AD. The fresh secret and the
plaintext are wiped when it returns. Only approved crates are used, and no
primitive is our own (CLAUDE.md §1.7).

The verifier opens it with `open_sealed(secret, purpose, context, sealed)`,
in brev-sdk's Rust API and its exports, and then runs `verify`. How the
verifier keeps its X25519 secret is its own matter. The host gets the
verifier's public key over a channel it trusts, or compiled in; the SDK
cannot check where it came from (§11).

### 4.4 Keys: the platform signs, the core checks

The core never holds a signing key, on any platform. The adapter creates
the author key, the KEK and the DEK, wraps and unwraps the DEK, and signs
the digests the core returns: registration (`registration_digest`, §4.5)
and token. The core checks every signature against `author_key` before it
uses one. Swift never verifies (CLAUDE.md §3.3) and hashes nothing: every
digest comes from the core. On Mac this is Brev's `Enclave`, `KeyStore`,
`UnlockService` and `SignService`, with the host's access group. One fresh
`LAContext` per signature run, dropped on every way out (AUTHORSHIP §3.2).

### 4.5 Verification (any side, no vault needed)

```rust
#[uniffi::export]
pub fn open_sealed(secret: &[u8], purpose: String, context: Vec<u8>, sealed: &[u8])
                   -> Result<Opened, SdkError>;                     // content + token
#[uniffi::export]
pub fn verify(purpose: String, context: Vec<u8>, content: &[u8], token: &[u8],
              author_key: &[u8], received_at: u64) -> Verification;   // record of brev-hand's checks
/// SHA-256("hand/v1/register\0" || challenge); `challenge`: 32 bytes from the verifier's server.
#[uniffi::export]
pub fn registration_digest(challenge: &[u8]) -> Result<Vec<u8>, SdkError>;
#[uniffi::export]
pub fn verify_key_proof(challenge: &[u8], author_key: &[u8], signature: &[u8]) -> bool;
```

`verify` checks the token only, including the requirements against its
facts. Checks that belong to one use, such as a deadline, are the
verifier's own (§8).

## 5. One rule: every requirement holds, or no proof

There are no classes. There is one pass/fail rule, one function in
brev-hand, used by the sender and by the verifier.

**The requirements.** All of these must hold:

- **Hardware key**: the author key is in hardware and asks for biometric
  presence on every signature (`"key"` is a hardware origin; on Mac the
  Secure Enclave with Touch ID).
- **Every protection fact on**: `secure-input`, `capture-off`, `ax-opaque`,
  `pasteboard-off` and `input-filter` are true.
- **No pastes**: `pastes` is 0.
- **SIP on**: `sip` is true.
- **No sudo**: `sudo` is 0.
- **No measuring gap**: `max-gap` is at most 5 seconds.
- **Every fact readable**: no fact is `null`, including the ones shown only
  as numbers.

**The sender.** `hand_finish` refuses with `Environment` and names every
failed fact, in token order. No token is made. Brev already refuses to send
below this bar, and keeps doing so.

**The token.** It carries no class claim. It carries the facts, and a
token exists only if they met the requirements when it was made.

**The verifier.** `verify` checks the facts in the token against the same
requirements. A token whose facts miss one fails that check, which names
the facts.

**Shown, never required.** `windows`, `agents`, `admin`, `blocked-input` and
`seconds` are shown as numbers. Their values never fail the rule; only an
unreadable one does (AUTHORSHIP §4.2).

**Brev's code today.** brev-vault, brev-hand and brev-mail still have
classes A, B and C: `classify`, the `class` claim, `SEND_THRESHOLD`, the
stored `env_class`, `Proof.class` and the badge «klasse A». Brev behaves as
this rule already, because it sends only in class A. Removing the classes
is its own step, first in the work order (§12 step 1).

### 5.1 The platform adapter contract: facts, not flags

The adapter hands over what it read. The core counts, applies the lists
and checks the requirements. The adapter has no setter for a count, a fact
or a result (AUTHORSHIP §3.1), nor for the platform. A read that fails is
`None`, and `None` fails the rule.

**What every adapter must provide:**

1. A hardware key that asks for biometric presence on every signature. The
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

### 5.2 Per platform

The rule is the same everywhere and is never configured per platform. **A
platform that cannot read a required fact cannot produce proofs until it
can.** There are no lower tiers. Columns other than macOS are candidates
and need a spike each.

| Fact / need | macOS (built) | iOS/iPadOS | Windows | Linux |
|---|---|---|---|---|
| Key | Secure Enclave + Touch ID | Secure Enclave + Face/Touch ID | TPM (NCrypt platform provider) + Windows Hello | none: no standard presence-gated hardware key |
| Presence is biometric only | yes (`.biometryCurrentSet`) | yes | **no**: Hello allows a PIN | no |
| `secure-input` | `IsSecureEventInputEnabled()` | no global taps, but not readable | no equivalent: `None` | X11: none; Wayland: compositor-dependent |
| `capture-off` | `sharingType` + `preventsCapture` layer | `isCaptured`, secure text layers | `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` | none |
| `sip` | `csr_get_active_config` | not readable | no equivalent: `None` | none |
| `sudo` | `sysctl KERN_PROC_ALL` names | not readable | process snapshot (elevated or `sudo.exe`) | `/proc` |
| `agents`, `windows` | process names, window owners | not readable | process snapshot, `EnumWindows` | `/proc`, X11/Wayland |
| `input-filter` | `eventSourceUnixProcessID != 0` | not readable | `LLKHF_INJECTED` (candidate) | none reliable |
| App attestation | none (D-0108) | **App Attest** | none for apps | none |
| **Can produce proofs** | **yes** (D-0112) | **no**, until the facts are readable (below) | **no** | **no** |

Said plainly:

- **Windows cannot produce proofs.** Windows Hello allows a PIN, so the key
  does not prove biometric presence (compare CLAUDE.md §1.8), and SIP and
  secure input have no equivalent. That holds until Windows has a
  biometric-only key that the adapter can read as such, and a read for
  each required fact.
- **Linux cannot produce proofs.** It has no hardware key with presence.
  There is no Linux adapter (Q5 answer).
- **iOS cannot produce proofs today.** Other apps there cannot tap keys or
  list processes, but the facts still cannot be read, so they are `None`.
  Whether a guarantee of the OS, proven by a verified App Attest, may stand
  in for a read is for the owner to decide at the iOS step. It would be a
  table in the core, not a lower tier, and the core would set the token's
  `platform` from `cfg!(target_os)`, never from an adapter call.

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
values. `HandCore` holds the XCFramework as a binary target (§10), the
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
| 1 no plaintext on disk | its store: ciphertext only, no logs, 0600/0700 | everything the host writes itself: caches, autosave, crash logs; record ids random or opaque, never a title or a name |
| 2 no AX text | a broken `ax-opaque` fact means no proof | the views (`OpaqueView`) |
| 3 no pasteboard | Hand counts pastes; any paste means no proof | the views and menus |
| 4 no programmatic content interface | the SDK has no IPC and no export; content leaves only as ciphertext to the verifier (§4.3), or as `OpenText` chunks to the host's own views | every interface the host adds |
| 5 no content in notifications, titles, Spotlight | — | the host |
| 6 no autocorrect, dictation, Writing Tools | — | `SecureComposeView` |
| 7 no own crypto, audited crates only | yes | yes (no crypto in Swift beyond Security) |
| 8 biometric only, no password | the key requirement assumes it on Mac | the adapter's key flags |
| 9 keys this-device-only, no backup | — | the adapter's key flags; backup exclusion |
| 10 wipe plaintext early | allocator, `Plaintext`, scrubs, lock wipes, launch guard | `SecretBytes`, the wipe order on lock |

The SDK cannot see most of the host's column. The requirements catch
honest bugs there, not a host that lies (§11).

## 7. Verification

**Verifier.** Everything is one Rust function, `brev-hand::verify`, with the
profile added. It ships three ways:

1. **Native CLI, now:** `hand-verify --purpose … --context <hex>
   --content <file> --token <file> --key <hex> --received-at <unix>` (or
   `--sealed <file> --secret <file>` in place of content and token). It
   prints each check and the facts as JSON. The exit code is 0 only if
   every token check passes. That means "the token is valid", not "the
   text met the verifier's own rules". It is reproducible, and its hash is
   published, so a verifier can rebuild it.
2. **The `verify` and `open_sealed` exports in the SDK**, for the
   verifier's server and for tools in Swift or Kotlin.
3. **Later, WASM or a service.** WASM needs brev-hand's verify path free of
   brev-vault and brev-proto, because rusqlite's bundled C does not build
   for `wasm32-unknown-unknown`. The split: move `KeyOrigin` and the
   requirement check into brev-hand, keep `Claims::new`/`FactLog` behind a
   `sender` feature, and verify P-256 there. It also needs `wasm-bindgen`
   (a new crate). Not now.

**Key trust: the verifier's registry.** The token proves only "the holder
of this key signed these statements about this content". So the whole
value rests on binding the key to a person. The verifier's organisation
keeps a registry of its authors' keys:

1. At first start the host app creates the keys (§4.4).
2. The author logs in to the verifier with a login it trusts (outside the
   SDK). The verifier's server returns a random 32-byte challenge.
3. The host gets `registration_digest(challenge)` from the core and signs
   it with one biometric check. The server checks it with
   `verify_key_proof` and stores (author, key, registered_at). A new key (a
   new device, or changed fingerprints under `.biometryCurrentSet`) means
   a new registration, and the registry keeps the history.
4. When the server issues a session or submission id (§8), it records the
   author's key that is active at that moment. That key is the one
   checked: never another key from the registry, and never a key sent
   with the text.
5. While one of the author's sessions is open, the server refuses a new
   key.

A key registered on someone else's device is still the author's own act;
the registry cannot tell (§11).

**What a badge may claim.** Only what the checks proved, in the words of
AUTHORSHIP §6. There is no class in it.

- «Skrevet i Brev», or the host app's own name («Skrevet i ‹app›»), when
  every check passes; otherwise «Ikke verifisert».
- In the detail: each check, then the numbers: windows, AI programs,
  admin, blocked input, writing time. Then «Nøkkelen er registrert på
  ‹navn› ‹dato›» from the registry, and on Mac always «Appen er ikke
  bekreftet av Apple (støttes ikke på Mac)».

A badge must never say «menneske», «uten KI» or «uten hjelp» (D-0107 item
4, §11).

## 8. A host and a verifier, end to end

```
 verifier's server                   host app                          verifier's view
 ─────────────────                   ────────                          ───────────────
 registry: author → key    ◄──(0) register key, one biometric check
 issue id (16 B random),
 store (author, key,
        issued_at)         ──(1)──► hand_start(kind, id, purpose, context = issued id)
                                            author writes in SecureComposeView;
                                            observe every 2 s; put(text) sealed often
                                    (2) hand_finish → one biometric check → hand_attach
 received_at := own clock  ◄──(3)── sealed (text + token), ciphertext only
 open_sealed + verify + own rules, stores once ─────────────────────►  badge
```

**Binding and replay.** The content hash covers `purpose || issued id ||
text`, and the verifier uses the key the server recorded with that id. So
a token cannot move to another text, another use or another author, and a
key registered during a session cannot sign for the author. The server
takes an id only from the author it issued it to. It stores each (id,
token) once, and the same token again is a duplicate. A new delivery is a
new token over the new text; the server decides which one counts.

**Time.** The id is random and issued at the start, so no token for it can
exist before `issued_at`. The server stamps `received_at` with its own
clock. `verify` checks brev-hand's window (`received_at − 24 h ≤ iat ≤
received_at + 5 min`). Anything else, such as a deadline, is the
verifier's own rule. `iat` is the author's clock (AUTHORSHIP §7).

**A lock.** A sudo or SIP-off sample, or the idle deadline, locks the vault
(D-0109). The text is never lost: the host seals it with `put` every few
seconds. But the session ends, and that record never gets a proof (§4.2).
A host where this matters should say so to the author before they start.

**What the verifier learns, and what the author must be told:** the
platform, whether the user is an admin, the counts and how long the writing
took. The host's onboarding must say so (AUTHORSHIP §7, last paragraph).

## 9. Example: an exam editor

One possible host, from the owner's diagram. An institution runs the
verifier's server and registers each student's key at its own login. When
an exam opens it issues a submission id; the editor starts a session bound
to it. «Levér» finishes, signs with one Touch ID and sends the sealed answer.
The server refuses late answers by its own clock, and an examiner sees «Skrevet
i ‹editor›» or «Ikke verifisert», with the numbers. Two limits matter here.
A lock during the exam leaves that answer without a proof. And on a Mac the
author is the adversary: a student who writes their own signing program
can pass (§11).

## 10. Languages, distribution, build

| Language | How | New crate or tool (owner's yes needed) |
|---|---|---|
| Swift (macOS first, iOS later) | `cargo build --release -p brev-sdk --features ffi` per target; `uniffi-bindgen` Swift; `xcodebuild -create-xcframework` (approved tools); the `HandCore` target with the XCFramework as a binary target (with checksum) | none for macOS arm64. A universal (x86_64) slice and iOS targets are only new rustup targets. |
| Kotlin (Android later, JVM verifier) | `uniffi-bindgen` generates Kotlin (built in) | **JNA**, the Java library UniFFI's Kotlin code loads through; the **Android NDK** and possibly **cargo-ndk** for the Android build |
| C# (Windows) | none until Windows is tested (Q5 answer) | then maybe **uniffi-bindgen-cs** (third party, NordSecurity); it still needs the owner's approval then |
| Linux | no adapter (Q5 answer) | — |
| WASM verifier | §7 item 3 | **wasm-bindgen** |
| iOS App Attest check | reserved `"app-attest"` claim, AUTHORSHIP §5 | **p384** (Apple's root is P-384, D-0108) |

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

## 11. What the SDK does not promise

Everything in AUTHORSHIP §7 holds for every app on the SDK, with "Brev"
read as "the app":

- **That the host app was used at all, on Mac.** There is no App Attest
  for Mac apps (D-0108). The registry cannot tell the host from a script
  that made its own P-256 key, even a Secure Enclave key. Such a script can
  register, then sign tokens that meet every requirement over AI-written
  text. Where the author is the adversary, Hand catches bugs and deters
  casual cheating on the author's own Mac. It does not stop an author who
  writes a program.
- **Who typed**, and **where the words came from.** Copy-typing from a
  phone or paper, dictation into another device, and hardware or virtual
  keyboards that type prepared text all pass (AUTHORSHIP §7).
- **Text the host imports into a record** during a session: the SDK cannot
  tell it from typed text.
- **Anything under root or kernel compromise**, and a cached sudo login.
- **Whose finger**: an enrolled finger, not a willing or particular one.
- **The author's clock**: `iat` is theirs, and `received_at` is the
  server's.
- **The verifier's public key**: the host must get it over a channel it
  trusts.
- **The host app's own column in §6.** The design facts and the key origin
  are the host's word.
- **Anything after the content leaves**: what the verifier does with it.

## 12. Work order

Mac and Swift first. Each step is one commit with its tests. Brev's
`scripts/test.sh` must stay green at every step.

1. **Remove the classes (Brev).** A token profile change, since the `class`
   claim goes away. brev-vault's `EnvironmentClass`/`classify` become the
   requirement check of §5, returning the failed facts; brev-hand's class
   check becomes a requirements check; brev-mail drops `SEND_THRESHOLD`,
   `may_send`, the stored `env_class` and `Proof.class`; the app's badge
   says «Skrevet i Brev» or «Ikke verifisert»; `allow-software-keys` skips
   the requirement check in test archives instead of lowering the class,
   and its release check stays. Brev's letters are test letters only, so
   Brev starts blank. AUTHORSHIP.md and a DECISIONS entry follow. Test:
   each failed requirement is refused and named; a token whose facts miss
   one fails verification with that fact; a token with a `class` claim
   fails form; an old-profile token fails; V82–V84 rerun by the owner.
2. **brev-hand `HandProfile`.** `content_hash`, `Claims::new` and `verify`
   take the profile; brev-mail's call sites follow (§3 item 2). Test:
   `BREV`'s content hash equals `SHA-256("brev/v1/hand/content\0" ||
   letter)`; a token saved after step 1 (a fixed test vector) still
   verifies and re-encodes byte for byte; brev-hand's and brev-mail's tests
   pass with only the call sites changed; a token under one profile fails
   under the other; the SDK content hash differs for another purpose or
   context.
3. **brev-sdk skeleton.** UniFFI behind `ffi`, `ping`, the surface pin, the
   dependency whitelist script with a control, the release marker. Test:
   the bindings generate and are patched; the surface matches; the
   whitelist fails on brev-mail; built without `ffi`, the archive has no
   `uniffi_brev_sdk_*` symbol.
4. **SDK Vault.** Test: no-plaintext scan of the store with a marker; lock
   zeroes the DEK and closes every `OpenText`; `Busy`, `Unsafe`, `Corrupt`;
   two records swapped between rows fail to open (AD binding); an id of 15
   or 17 bytes is `Malformed`; a sudo sample locks.
5. **SDK Hand and sealing.** Test: round trip with a test signer →
   `open_sealed` → `verify` passes; each failed requirement is refused and
   named; a lock mid-session wipes the pending hash; `hand_start` over an
   existing record is `Duplicate`; a `put` outside the session leaves a
   record that cannot be finished; the sealed bytes hold no marker from the
   text, and fail to open under another purpose, context or key; a
   registration preimage never starts like a token's Sig_structure (as
   brev-hand's `token_and_envelope_signatures_do_not_cross`), and a
   registration signature is not valid as a token signature, and the
   reverse; the record's plaintext is dropped at `hand_attach`.
6. **`hand-verify` CLI and the exports.** Test: step 5's vectors pass;
   tampered content, token, key, sealing and time fail with the right
   check; the JSON is stable (golden file).
7. **HandKit package.** The kit's files, generalised, plus the pairing check
   against Brev's files. Test: the package builds; the `HandKit` target
   builds without the binary; the kit's unit parts (InputFilter,
   HandSampler) pass in the CLI harness.
8. **Demo host.** A minimal Mac app on HandKit: one protected editor, `put`,
   finish, sealed text to a file. Test: lock-probe checks (capture, AX,
   pasteboard, blank on lock), then an owner run on the real Mac (new
   VERIFY rows: one Touch ID per finish, sudo locks).
9. **Host and verifier against an in-process mock server** (no server
   crate): register, issue, submit, open, verify. Test: replay, a moved
   token, the wrong author's key, a new key while a session is open
   (refused), a token by the author's other registered key (fails).
10. **Next platform**, only once it can read every required fact: a facts
    spike first, then its adapter. For Windows, C# after Windows is tested,
    maybe with uniffi-bindgen-cs if the owner approves it then. No Linux
    adapter before Windows is tested, and Linux cannot produce proofs
    without a hardware key (§5.2).
11. **Brev on the SDK.** brev-mail uses brev-sdk's Rust API with `ffi` off,
    and the app uses the `HandKit` target only. Test: Brev's full
    `scripts/test.sh`, the brev_core surface pin unchanged, no
    `uniffi_brev_sdk_*` symbol in `libbrev_core.a`, and V82–V84 rerun by
    the owner.
12. **WASM verifier**, if a verifier needs it in a browser.

## 13. Spørsmål til eier

**Q1. Navn og tokenprofil.** (Det eneste åpne spørsmålet.)
(a) Én profil for hele SDK-en (`tag:‹domene›,2026:hand-sdk-v1`). Appens
formål ligger i innholds-hashen.
(b) Én profil per app.
*Anbefaling: (a).* Da har alle verifikatorer én regel, og formålet holder
appene fra hverandre. (b) gir ingenting ekstra. Velg også domenet i taggen
(`brev.no` er bare en plassholder) og navnet SDK-en skal hete.

**Sjekk: har jeg forstått «ingen klasser» riktig?** Svar ja eller nei.
- Et bevis lages bare når alle kravene i §5 holder. Ellers får teksten
  ikke noe bevis, og appen sier hvilke krav som feilet.
- Merket sier bare «Skrevet i ‹app›» eller «Ikke verifisert». Tallene står
  i detaljene.
- En lås mens noen skriver, betyr at den teksten aldri får bevis. Teksten
  er trygg, men målingen fortsetter ikke etter låsen.
- Windows, Linux og iOS kan ikke lage bevis før de kan lese alle kravene.
- Testarkiv hopper over kravene, slik de i dag senker klassen. Appens
  arkiv kan aldri gjøre det.
- Å fjerne klassene fra Brevs kode er første steg. Brev starter da blankt,
  siden brevene bare er testbrev.
