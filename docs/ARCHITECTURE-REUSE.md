# brev-core: what is generic, what is mail, what Swift decides

Snapshot: branch `claude/phase3` at 239de4a (Phase 3 WP4). Paths are relative
to `core/` unless they start with `app/`. This file is the map for splitting
`brev-core` into a generic `brev-vault` and a mail layer `brev-mail`.

## 1. Generic (would move to brev-vault)

| Item | Where |
|---|---|
| Column AEAD: `seal_column`, `open_column`, `column_ad`, `encrypt`, `decrypt`, `fill`, `random`, `is_zero` | `brev-core/src/crypto.rs` |
| `Plaintext` (read-only, wiped on drop, no Debug/Clone/DerefMut) | `brev-core/src/crypto.rs` |
| Stack scrubs `scrub_stack` (16 KiB), `scrub_stack_deep` (64 KiB) and their test counters | `brev-core/src/crypto.rs` |
| Zeroing global allocator (`zeroizing-alloc`) | `brev-core/src/lib.rs` |
| Lock state: `Core { db, dek: Box<Zeroizing<[u8;32]>>, unlocked }`, `unlock`, `lock`, `is_locked`, the `dek()` gate | `brev-core/src/store.rs` |
| Store hardening: `connect` pragmas, `check_path`, `verify_store`, `schema_of`, `not_a_store`, `set_journal_mode`, 0600 file mode on create | `brev-core/src/store.rs` |
| Padding: `padded_len`, `pad_into`, `unpad`, `MAX_PADDED`, `PadError` | `brev-proto/src/lib.rs` (next to p256 code) |
| `OpenText` (chunked reads, registry closed on lock), `CHUNK`, `MAX_BODY`, `used`, `dek32`, the unlock drop guard | `brev-core/src/ffi.rs` |
| Generic errors: `Locked`, `WrongKey`, `Crypto`, `NotFound`, `Malformed`, `Corrupt`, `Rng`, `Io`, `Storage` | `brev-core/src/lib.rs` |

## 2. Mail-specific (would stay in brev-mail)

- **Types:** `IdentityId`, `ContactId`, `ThreadId`, `MessageId`, `PublicBundle`, `Contact`, `Thread`, `Message`, `Letter`, `Me` (`store.rs`); `Secret` (`crypto.rs`); `RelayTransport`, `Mailbox` (`relay.rs`); `Transport`, `NetError`, `MockTransport` (`transport.rs`, public in release today); FFI records `ContactRow`, `ContactInfo`, `MeInfo`, `ThreadRow`, `MessageRow`; `Limits.max_subject/max_address`, `MAX_SUBJECT` (`ffi.rs`).
- **Core methods:** `bundle`, `address`, `is_registered`, `set_address`, `registration`, `relay_token`, `verify_own`, `check_new_address`, `add_contact`, `contacts`, `contact_address`, `contact_bundle`, `pending_bundle`, `check_key`, `accept_new_key`, `seal_letter`, `attach_signature`, `store_sent`, `threads`, `messages`, `read_body`, `thread_of`, `mark_read`, `receive`, plus helpers `my_id`, `identity_keys`, `me`, `set_pending`, `is_permanent`, `local`, `subject_ad`, `body_ad`, `identity_row`, `encode_payload`, `decode_payload`, `KEY_*` constants. `Core::create` requires a P-256 signing key and `init` creates the identity.
- **Crypto:** `seal_message`, `open_message`, `message_key` (HKDF), `contact_tag`, `static_secret`, `public_key`, `MESSAGE_KEY_LABEL`, `CONTACT_TAG_LABEL`.
- **Schema v3:** tables `identity`, `contacts`, `threads`, `messages`, index `messages_by_thread`; AD labels `identity.keys`, `identity.address`, `contacts.address/bundle/pending`, `threads.subject`, `messages.body`.
- **FFI (`Brev`):** `create`/`open` (with a relay URL), `me`, `register_request`, `register`, `add_contact`, `contacts`, `contact_info`, `accept_new_key`, `threads`, `messages`, `open_body`, `prepare_send`, `sign_request`, `attach_signature`, `submit`, `cancel_send`, `sync`, the network epoch.
- **Errors:** `Signing`, `KeyChanged`, `AddressTaken`, `Network`, `Refused`; `Duplicate` and `Malformed` are partly mail.
- **brev-proto:** `Envelope` and the wire format, `identity_id`/`identity_code`, `sig` (p256), `body` (addresses, registration, lookup, inbox, ack).
- **Dependencies only mail needs:** reqwest (pulls hyper and tokio into the normal build), p256 (through brev-proto), x25519-dalek, hkdf. reqwest is why `brev-core` needs rust-version 1.88.

## 3. Security decisions made in Swift, and what Rust knows

| Decision | Swift | Rust knows |
|---|---|---|
| Touch ID before unlock (ECIES unwrap) | `Shared/Enclave.swift`, `Keys/UnlockService.swift` | only that the DEK is right |
| Identity key is in the Secure Enclave | `Keys/KeyStore.swift` | only that `create` got a valid P-256 point |
| Touch ID for each signature | `Keys/SignService.swift` | only that the signature matches the key from `create` |
| Access control flags, keychain group, no password button | `Shared/Enclave.swift`, `Keys/*` | nothing |
| Human-only buttons, AX press refused | `UI/HumanButton.swift` | nothing |
| Capture exclusion (sharingType, preventsCapture layer, sheets/child windows, pixel buffers zeroed) | `App/Hardening.swift`, `UI/OpaqueView.swift` | nothing |
| Secure input | `UI/SecureInput.swift`, `UI/SecureComposeView.swift` | nothing |
| Synthetic-event rejection (PID rule) | `Shared/InputFilter.swift`, `App/BrevApplication.swift` | nothing |
| AX opacity; no pasteboard, Services, Writing Tools, autocorrect, input context | `UI/OpaqueView.swift`, `UI/SecureComposeView.swift`, `App/MainMenu.swift` | nothing |
| Swift secret memory, Core Text per line, glyph flush | `Shared/SecretBytes.swift`, `SecretText.swift`, `TextLayout.swift` | nothing |
| Lock triggers (resign active, screen lock, sleep, user switch, idle 300 s, ⌘L, quit) and the wipe order | `App/LockController.swift`, `Shared/LockState.swift` | told by `lock()`; cannot tell when it is missing |
| Post-unlock rule (show mail only if still active) | `Shared/LockState.swift` | none: Rust is unlocked when `unlock` returns |
| Launch guard (arguments, debug defaults and environment, MallocScribble re-exec) | `Shared/LaunchGuard.swift` | nothing: Rust would open and unlock in an unsafe process |
| Single instance, folder 0700, backup exclusion | `Keys/KeyStore.swift` | nothing (Rust sets 0600 on `brev.db` itself) |

Rust enforces itself: DEK correctness, a non-zero DEK, signatures against the stored key, the `Locked` gate after `lock()`, the 127.0.0.1-only relay URL, heap zeroing and stack scrubs.

## 4. What a second app cannot reuse without changes

Blockers:
1. `#[global_allocator]` inside the library (`brev-core/src/lib.rs`).
2. The staticlib bundles its own Rust runtime and exports every `sqlite3_*` symbol (rusqlite `bundled`).
3. UniFFI scaffolding in the crate; module names `BrevCore`/`BrevCoreFFI` in `uniffi.toml`; `gen-bindings.sh`/`patch-bindings.py` tied to `brev_core`.
4. Fixed store identity: file `brev.db`, `application_id` "BREV", `SCHEMA_VERSION` 3, and an exact schema check (no extra table, no migration).
5. `create` requires a P-256 signing key.
6. `Brev` owns a `RelayTransport`; `create`/`open` require a 127.0.0.1 relay URL.
7. brev-proto's "BREV" magic and protocol version (only for a separate protocol).

Carries Brev's meaning but works: the `brev/v0/...` domain labels, the limits, the FFI names, uniffi pinned to 0.32.2, `MACOSX_DEPLOYMENT_TARGET` 14.0, `rust-version` 1.88, the public `MockTransport`.

Fine: all test hooks are `cfg(test)`; no global state besides the allocator.
