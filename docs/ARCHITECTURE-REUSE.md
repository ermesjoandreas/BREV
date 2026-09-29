# brev-vault and brev-mail: what a second app reuses, what Swift decides

Snapshot: branch `claude/phase3` at 60d4e1b, after the vault split
(`docs/VAULT_SPLIT_PLAN.md` steps 1 to 3; docs/DECISIONS.md D-0066 to
D-0068). Paths are relative to `core/` unless they start with `app/`. The
earlier version of this file (a04ca0f) was the map for the split; this one
describes the result.

## 1. In brev-vault (generic)

An rlib with no UniFFI and no network. `scripts/check-vault-deps.sh` (run by
`scripts/test.sh`) allows only chacha20poly1305, poly1305, rand, rusqlite,
thiserror, zeroize and zeroizing-alloc as direct dependencies.

| Item | Where |
|---|---|
| `Vault`: `create` (file 0600, one transaction through the caller's `seal` and `insert`), `open` (locked), `unlock` (with the caller's key check), `confirm_active`, `set_idle`, `lock`, `is_locked`, the gate `dek()`, `db()`, `db_mut()`, `open_text`, `clock()` | `brev-vault/src/store.rs` |
| `VaultConfig` (file name, `application_id`, schema, schema version), `DekSlot` (copies the DEK, zeroes the source), `check_path` | `brev-vault/src/store.rs` |
| Store hardening: absolute path only, connection pragmas, exact schema check, `Corrupt` for files SQLite cannot parse, rollback journal | `brev-vault/src/store.rs` |
| One store per directory: a flock on the folder while the store is open (`Busy`); folder 0700 and file 0600 (`Unsafe`) | `brev-vault/src/dirlock.rs`, `store.rs` |
| Launch guard (feature `launch-guard`): `Unsafe` with a `DYLD_*` variable or without `MallocScribble=1` | `brev-vault/src/launch.rs` |
| The lock in time: `Armed` until `confirm_active` (`CONFIRM_WINDOW`, 2 s), then `Active` until idle (`DEFAULT_IDLE` 300 s, or `set_idle`); `Clock::note_activity`; deadlines on the monotonic and the wall clock; `Timer` (thread `brev-vault-timer`) and the `Holder` trait it locks through | `brev-vault/src/clock.rs` |
| Column AEAD: `seal_column`, `open_column`, `column_ad`, `aead_seal`, `aead_open`, `pad`, `fill`, `random`, `is_zero`, `NONCE_LEN`, `TAG_LEN` | `brev-vault/src/crypto.rs` |
| `Plaintext` (read-only, wiped on drop, no Debug, Clone or DerefMut) and `Text` (read in `CHUNK` = 960-byte chunks; the vault's lock closes every open one) | `brev-vault/src/crypto.rs`, `text.rs` |
| Stack scrubs `scrub_stack` (16 KiB) and `scrub_stack_deep` (64 KiB) | `brev-vault/src/crypto.rs` |
| Padding: `padded_len`, `is_padded_len`, `pad_into`, `unpad`, `MAX_PADDED`, `BUCKETS`, `PadError` (brev-proto re-exports them) | `brev-vault/src/padding.rs` |
| Environment report: `KeyOrigin`, `EnvironmentReport`, `failed_fields`, `ReportField` (the classes went in D-0115) | `brev-vault/src/platform.rs` |
| Zeroing global allocator (feature `zeroing-allocator`, on by default) | `brev-vault/src/lib.rs` |
| Errors: `Locked`, `WrongKey`, `Crypto`, `NotFound`, `Malformed`, `Corrupt`, `Rng`, `Io`, `Storage`, `Busy`, `Unsafe` | `brev-vault/src/error.rs` |
| Test counters and accessors (feature `test-hooks`, never in the app's archive) | `brev-vault/src/lib.rs` (`test_hooks`), `store.rs` |

## 2. In brev-mail (mail; library name `brev_core`)

- **Store:** `Core` wraps a `Vault` with the `MAIL` config (`brev.db`,
  "BREV", schema v4); `IdentityId`, `ContactId`, `ThreadId`, `MessageId`,
  `PublicBundle`, `Contact`, `Thread`, `Message`, `Letter`; the identity row
  and the key check `open_identity`; contacts, threads, letters, the sealed
  addresses and `pending` (`store.rs`; `env_class` went in D-0115).
- **Crypto:** `seal_message`, `open_message`, `message_key` (HKDF),
  `contact_tag`, `static_secret`, `public_key`, `Secret` (`crypto.rs`).
- **Transport:** `Transport`, `NetError`, `RelayTransport` (`relay.rs`,
  `http://127.0.0.1:<port>` only); `MockTransport` behind `test-hooks`
  (`transport.rs`).
- **FFI (`ffi.rs`):** `Brev` (session mutex, timer, relay client),
  `OpenText` (a shell over the vault's `Text`), the records, `BrevError`,
  `Limits`, `MAX_SUBJECT`, `MAX_BODY`, the `unlock` drop guard `Finish`,
  `used`, `dek32`, `report_environment`, the class-A send rule
  (`SEND_THRESHOLD`, lowered to C only by the test feature
  `allow-software-keys`).
- **Build:** `crate-type = ["lib", "staticlib", "cdylib"]`; `uniffi.toml`
  (`BrevCore`, `BrevCoreFFI`); `scripts/gen-bindings.sh` and
  `scripts/patch-bindings.py` (pinned to uniffi 0.32.2); the release checks
  for `test-hooks` symbols and the `allow-software-keys` marker.
- **brev-proto:** `Envelope` and the wire format, `identity_id` and
  `identity_code`, `sig` (p256), the relay bodies. It takes only the padding
  from the vault, without the allocator.
- **Dependencies only mail needs:** uniffi, reqwest (with hyper and tokio),
  p256 (through brev-proto), x25519-dalek, hkdf, sha2.

## 3. Security decisions made in Swift, and what Rust enforces now

| Decision | Swift | What Rust knows or enforces |
|---|---|---|
| Touch ID before unlock (ECIES unwrap) | `Shared/Enclave.swift`, `Keys/UnlockService.swift` | that the DEK opens the store. Sending: `biometric_used` in the report, Swift's own word (D-0068) |
| Identity key in the Secure Enclave | `Keys/KeyStore.swift` | that `create` got a valid P-256 point. Sending: `key_origin` in the report, Swift's own word |
| Touch ID for each signature | `Keys/SignService.swift` | that the signature matches the identity key from `create` |
| Access control flags, keychain group, no password button | `Shared/Enclave.swift`, `Keys/*` | nothing |
| Human-only buttons, AX press refused | `UI/HumanButton.swift` | nothing |
| Capture exclusion (sharingType, the protected layer, sheets and child windows, buffers zeroed) | `App/Hardening.swift`, `UI/OpaqueView.swift` | Sending: `capture_excluded` in the report |
| Secure input | `UI/SecureInput.swift`, `UI/SecureComposeView.swift` | Sending: `secure_input_active` in the report |
| Synthetic-event rejection (PID rule) | `Shared/InputFilter.swift`, `App/BrevApplication.swift` | Sending: `synthetic_input_rejected` in the report. Rust's idle clock moves only on `note_activity`, which Swift calls only for input that passed the filter |
| AX opacity; no pasteboard, Services, Writing Tools, autocorrect, input context | `UI/OpaqueView.swift`, `UI/SecureComposeView.swift`, `App/MainMenu.swift` | Sending: `accessibility_opaque` and `pasteboard_disabled` in the report |
| Swift secret memory, Core Text per line, glyph flush | `Shared/SecretBytes.swift`, `SecretText.swift`, `TextLayout.swift` | nothing |
| Lock triggers (resign active, screen lock, sleep, user switch, ⌘L, quit) and the wipe order | `App/LockController.swift`, `Shared/LockState.swift` | told by `lock()` |
| Idle lock | `App/LockController.swift` (300 s, polls `isLocked()` every 15 s) | enforced: its own deadline (320 s from Swift, `idle_secs`), wiped by its timer thread; it cannot blank the screen |
| Post-unlock rule (show mail only if still active) | `Shared/LockState.swift`, `App/LockController.swift` | enforced: an unlock is `Armed`, and content stays `Locked` unless `confirm_active` comes within 2 s |
| Launch guard (arguments, debug defaults and environment, `MallocScribble` re-exec, `DYLD_*` stripped) | `Shared/LaunchGuard.swift` | enforced in part: `create`, `open` and `unlock` refuse a `DYLD_*` variable or `MallocScribble` other than `1`. Arguments and defaults stay Swift's |
| Single instance, folder 0700, backup exclusion | `Keys/KeyStore.swift` | enforced: one open store per folder (`Busy`), folder 0700 and file 0600 (`Unsafe`). Backup exclusion stays Swift's |
| Environment report (the seven fields) | `App/EnvironmentProbe.swift`, `UI/ComposeSheet.swift` | enforced: no letter unless every requirement holds (D-0115). The report itself is not attested |

Rust enforces on its own: DEK correctness, a non-zero DEK, signatures (its
own against the identity key, received ones against the contact's pinned
key), the `Locked` gate after `lock()`, the 127.0.0.1-only
relay URL, heap zeroing and stack scrubs, and since the split the five
checks of D-0067 and the send rule of D-0068.

## 4. What a second app reuses from brev-vault as it is

A Rust crate that adds `brev-vault` as a path dependency gets, without
changes:

1. Its own store: a `VaultConfig` with its own file name, `application_id`,
   schema and version; `Vault::create` with its own `seal` and `insert`
   closures for its first rows; `Vault::unlock` with its own key check (for
   example, opening a sealed row). Nothing in the vault names Brev's tables.
2. The hardening that comes with every store: absolute paths, the
   pragmas, the exact schema check, the rollback journal, file 0600, a
   private 0700 folder held with a flock.
3. The lock state: one DEK buffer, the gate, `lock()` that closes every
   open `Text` and scrubs, the two-step unlock and the idle deadline. The
   caller keeps its session in an `Arc<Mutex<S>>`, implements `Holder` for
   `S`, and starts `Timer::spawn(Arc::downgrade(&s), vault.clock())`.
4. Column encryption bound to each row's fields, the padding, `Plaintext`,
   the chunked `Text`, the stack scrubs and the OS RNG.
5. The launch guard (feature `launch-guard`) and the zeroing allocator
   (feature `zeroing-allocator`), each on or off by feature.
6. The environment report: its platform layer fills an
   `EnvironmentReport`, and `failed_fields` says what the report is short
   of.
7. The dependency whitelist, which already holds for the vault itself.

## 5. What still blocks, or must be copied

1. **No FFI in the vault.** A second app writes its own UniFFI crate: the
   session mutex, the `unlock` drop guard, argument parsing (`used`,
   `dek32`), an `OpenText`-style handle and its own error enum, as
   `brev-mail/src/ffi.rs` does. `gen-bindings.sh`, `patch-bindings.py` and
   the surface pin (`scripts/ffi-surface.txt`) are written for `brev_core`
   and uniffi 0.32.2, so they are copied and renamed.
2. **One Rust archive per binary.** An app's staticlib bundles the Rust
   runtime, the global allocator and every `sqlite3_*` symbol (rusqlite
   `bundled`). A second app is its own binary with its own archive; it
   cannot link Brev's `libbrev_core.a` beside its own.
3. **Format constants that carry Brev's meaning:** the AD label
   `brev/v0/column/` in every sealed column, `CHUNK` = 960, the padding
   buckets and the 1 MiB maximum (shared with brev-proto's envelope),
   `CONFIRM_WINDOW` = 2 s, and the thread name. Changing the label, the
   chunk or the buckets is a format change for Brev too (plan R8).
4. **No migrations.** The schema check is exact: any schema change is a new
   version, and older stores open as `Corrupt` (Brev reset at v2, v3 and
   v4).
5. **One store per folder**, 0700 folder and 0600 file: each store needs its
   own private folder.
6. **The launch guard's rule is macOS's:** a second app sets
   `MallocScribble=1` (Brev uses `LSEnvironment`) and strips `DYLD_*` before
   Rust runs, or leaves the feature off.
7. **The environment report is self-reported.** Until attestation, the
   class catches bugs in the platform layer, not attackers (CLAUDE.md §2).
8. **Swift is not a package.** Everything in §3's Swift column (the
   protected layer, `SecureComposeView`, `HumanButton`, `InputFilter`,
   `LaunchGuard`, `LockController`, `EnvironmentProbe`, the keychain code,
   `SecretBytes`/`SecretText`/`TextLayout`) lives in `app/Sources`. A
   second app copies the files; its keychain names and access group follow
   its own bundle id.
9. **brev-proto** keeps the "BREV" magic and protocol version; only a
   separate protocol would need its own.

Carries Brev's meaning but works: the limits and FFI names in brev-mail,
uniffi pinned to 0.32.2, `MACOSX_DEPLOYMENT_TARGET` 14.0, `rust-version`
1.89 (the vault's `File::try_lock`).
