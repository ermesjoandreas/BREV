# BREV — a locked, human-only mail app for macOS

You are building Brev (Norwegian for "letter"): a native macOS app for private correspondence between verified people. It should feel like mail did before spam and AI agents: slow, personal, and completely sealed.

Read this whole file before writing any code. Work through the phases in order. Do not start a phase before the previous phase's "Definition of done" is met.

## 1. Mission and non-negotiable invariants

The app has ONE core promise:

> Nothing on this Mac — no other app, no AI agent, no OS feature, no browser extension, no automation — can read the content of messages or the message history. There is no setting, API, export or integration that can change this. Content is only ever visible inside the app window, to a human who has physically authenticated with Touch ID.

The following invariants are absolute. If a task in any phase conflicts with one of them, STOP and ask instead of implementing a workaround.

NEVER:

1. Store plaintext message content on disk, in any cache, log, crash report, temp file, or database. Only ciphertext is ever written.
2. Expose message text through the macOS Accessibility tree (no `NSAccessibility` text/value for content views).
3. Put message content on the pasteboard (`NSPasteboard`). No copy, no cut, no drag-and-drop of content. Copying is disabled by design.
4. Add a Share menu, Services, Quick Look, printing, PDF export, AppleScript dictionary, Shortcuts/App Intents, URL scheme, plugin system, MCP server, or any programmatic interface that returns content.
5. Show message content in notifications, the Dock, Spotlight, Handoff, or window titles. Notifications say only "Ny melding": no sender name, no content. Contact names stay encrypted.
6. Enable autocorrect, spell-check, predictive text, dictation, or Apple Writing Tools in any view that holds content.
7. Implement your own cryptographic primitives. Use audited crates only (see §4). Ask before adding any dependency not listed here.
8. Allow a password fallback for unlocking. Touch ID only (`.deviceOwnerAuthenticationWithBiometrics`, `.biometryCurrentSet`).
9. Sync keys to iCloud Keychain. Keys are `ThisDeviceOnly` and non-synchronizable. Losing the Mac means losing the history — this is intentional and must be explained to the user at setup. The same happens when fingerprints are added or removed (`.biometryCurrentSet`), and setup says that too. Brev's container is excluded from Time Machine (`isExcludedFromBackup`); local APFS snapshots can still hold old copies.
10. Keep plaintext in memory longer than needed. Zeroize buffers when a message is closed or the app locks.

ALWAYS:

* Write tests for the Rust core. Security-relevant code needs tests that prove the invariant (e.g. "store contains no plaintext bytes after save").
* Record every architectural decision in `docs/DECISIONS.md` with the date and reasoning.
* Prefer the simplest thing that works and can be extended. This is a phase-0 product, not a finished one.

## 2. Threat model (what we defend against, and what we don't)

In scope — must be defended against:

* AI coding agents and tools with filesystem access (Claude Code, Cursor, MCP file servers) → they see only ciphertext.
* Computer-use / screen-reading agents using the Accessibility API → they see an opaque view, no text.
* Screenshot and screen-recording tools → window excluded from capture.
* Keyloggers and event taps → secure event input while composing.
* Synthetic input (AppleScript, CGEvent injection, agents "clicking") → rejected in the app.
* macOS system AI features (notification summaries, Writing Tools, Spotlight, Siri suggestions) → nothing exposed to them.
* The relay server (our own backend) → zero-access; sees only ciphertext and minimal routing metadata. It also serves the address directory, so a malicious relay could hand out a false key on first contact; key pinning, key-change warnings, invite codes that carry a key fingerprint, and optional safety-code comparison make that detectable (Phase 3–4).
* Spam / mass messaging / AI-generated noise → identity, contact approval, invite codes, rate limits (Phase 4).

Out of scope — explicitly NOT defended against:

* Kernel/root compromise of macOS, or hardware attacks.
* A camera pointed at the screen, or the user retyping content elsewhere.
* The recipient choosing to leak what they received.

Accepted residual risk — known, reviewed, and not fixed:

* Transient stack copies of key material inside audited crates that no `zeroize` feature reaches: (1) ChaCha20 intermediates when XChaCha derives its subkey (HChaCha20 state), (2) the HKDF intermediate key (PRK) inside `hkdf`, (3) by-value copies of the X25519 secret inside `x25519-dalek`. They cannot be wiped without `unsafe`, and even `unsafe` could not guarantee it. Mitigation: `scrub_stack()` overwrites 16 KiB of stack after each crypto operation, and a release-mode test proves the wipe is not optimised away. Out of the threat model: reading another process's memory already needs root or a kernel compromise (Hardened Runtime blocks debuggers, and macOS encrypts swap).
* Internal copies inside Apple frameworks that Brev cannot wipe: Core Text / CoreGraphics while a line is drawn, and CryptoKit / Security while the Secure Enclave unwraps the DEK. Mitigation: content is drawn one line at a time from a wipeable buffer, never laid out as a whole body, and `unlock` overwrites 64 KiB of stack. Out of the threat model for the same reason as above.
* File substitution of the stores: a process that can write Brev's container can delete or replace `brev.db` and the echo stores. It cannot make stores that open under Brev's DEK, because the DEK and the keys live in the keychain, bound to Brev (§3.2). Replaced stores fail to unlock; deleted stores lose the history. Onboarding says not to write new letters if the history is suddenly gone.
* On a Mac that holds Brev's team signing key (a developer's Mac), any same-user process can sign its own program with Brev's App ID and keychain group without a prompt, and so replace Brev's keychain items or ask for Touch ID on Brev's keys. Verified 2026-09-28: an agent session did it with `xcodebuild -allowProvisioningUpdates`. Real letters belong on a Mac without that key, or with the key behind a password prompt (owner decision pending).
* Keystrokes exist briefly in macOS event objects (one character per event) and in the window server; secure event input stops event taps, not those.
* Pixels of an open letter live in the window's backing stores, and in the protected layer's pixel buffers, until blank-on-lock (the buffers are zeroed in place on lock).
* Phase 2 only: the two built-in echo contacts keep copies of every letter in two more stores under the same key.
* Freed memory inside Apple frameworks is overwritten by the documented malloc debugging variable `MallocScribble=1`, set in Info.plist (`LSEnvironment`); Brev refuses to unlock if it is not in effect.

## 3. Architecture

Two languages, strict separation:

```
brev/
├── core/                 # Rust workspace — all logic, storage, crypto
│   ├── brev-core/        # library crate, exposed to Swift via UniFFI
│   ├── brev-proto/       # wire format + envelope (shared with relay)
│   └── brev-relay/       # minimal relay server (axum), Phase 3
├── app/                  # Swift + AppKit macOS app (Xcode project via XcodeGen)
│   ├── project.yml
│   ├── Sources/
│   └── Generated/        # UniFFI-generated Swift bindings (gitignored)
├── scripts/              # build.sh, gen-bindings.sh, test.sh
└── docs/
    ├── DECISIONS.md
    └── THREAT_MODEL.md   # copy of §1–§2, kept in sync
```

### 3.1 Rust core (`brev-core`) — owns everything that touches content

* Data model: `Contact`, `Message`, `Thread`, `Envelope`.
* Encrypted store: SQLite via `rusqlite` (bundled). Every content column is a ciphertext BLOB, padded before encryption to the same buckets as envelopes (§5 Phase 3), so stored lengths show only the bucket. Metadata that must be queryable (contact id, timestamp, read flag) may be plaintext, but never subject lines or bodies.
* Crypto (see §4): identity keys, message encryption/decryption, envelope signing/verification.
* Session state: an `Unlocked` / `Locked` state machine. When locked, the data-encryption key and all plaintext are zeroized and every content call returns `Err(Locked)`.
* Transport trait: `trait Transport { send(&Envelope) -> Result<(), NetError>; poll() -> Result<Vec<Envelope>, NetError>; ack(&[[u8; 32]]) -> Result<(), NetError> }`. `poll` deletes nothing; the receiver acknowledges each envelope after it is stored (or refused for good), and the relay deletes it then. `MockTransport` (in-process, Phase 1 tests) and `RelayTransport` (blocking HTTP to `http://127.0.0.1:<port>` only, never under the session mutex; Phase 3).
* Exposed to Swift with UniFFI (`uniffi` crate, proc-macro style). The Swift side never sees raw keys; it passes opaque handles. `brev-core` uses a zeroing global allocator (`zeroizing-alloc`), so every freed Rust buffer, including UniFFI's, is wiped. `scripts/gen-bindings.sh` patches the generated Swift so byte buffers are wiped before they are freed; the build fails if a patch no longer applies.

### 3.2 Swift app (`app/`) — owns only what must be Mac-native

* AppKit, not SwiftUI, for every view that can contain content (we need low-level control over rendering, events and accessibility). SwiftUI is allowed for settings/onboarding screens that never show content.
* `SecureTextView: NSView` — renders text with Core Text directly into `draw(_:)`. No `NSTextView`, no `NSTextField` for content. Overrides `accessibilityRole`/`accessibilityValue` to expose nothing.
* `SecureComposeView: NSView` — same rendering, custom key handling, calls `EnableSecureEventInput()` on focus and `DisableSecureEventInput()` on blur. Rejects events where `CGEventGetIntegerValueField(event, .eventSourceUnixProcessID) != 0` (synthetic input from another process).
* Main window: `sharingType = .none`, `isExcludedFromWindowsMenu = true`, `titlebarAppearsTransparent`, no content in title. `sharingType = .none` alone is not enough on macOS 26: `CGDisplayStream` and `AVCaptureScreenInput` still capture such a window. So every view that can show content draws into pixel buffers shown through an `AVSampleBufferDisplayLayer` with `preventsCapture = true`; `sharingType = .none` stays as the first defence. Sheets and child windows get the same settings as their parent.
* Auto-lock: on `NSApplication.didResignActiveNotification`, on screen lock, and after N minutes idle → call `core.lock()`, blank all views.
* Touch ID gate: `LAContext` with `.deviceOwnerAuthenticationWithBiometrics` and `localizedFallbackTitle = ""` (no password button). Both Enclave keys are permanent Secure Enclave `SecKey`s created with `SecKeyCreateRandomKey` (`kSecAttrTokenIDSecureEnclave`, `kSecUseDataProtectionKeychain`, access group `AV26DNQ5SC.no.brev.app`) and `SecAccessControlCreateWithFlags(kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet])`. The wrapped DEK is a generic-password item in the same access group. The keychain binds all three to Brev's signing identity, so no other program can use, read or replace them, on a Mac that does not hold Brev's signing key (see §2). The app is signed by team `AV26DNQ5SC` with a provisioning profile; ad-hoc builds cannot reach these items.
* Notifications via `UserNotifications`, text exactly "Ny melding" (no sender name, no content).
* Bundle: Hardened Runtime ON, App Sandbox ON, `get-task-allow` OFF, library validation ON, no `NSAppleScriptEnabled`, no `NSServices`, no document types, no URL types.
* UI language: Norwegian (bokmål). Keep strings in `Localizable.strings`.

### 3.3 Key design (how Touch ID and Rust fit together)

The Secure Enclave can only hold P-256 keys, so:

* Identity signing key: P-256 in Secure Enclave, Touch ID-gated. Signs every outgoing envelope. Public key = the user's identity.
* Key-encryption key (KEK): a second P-256 Enclave key used with `SecKeyCreateDecryptedData` (ECIES, `.eciesEncryptionCofactorVariableIVX963SHA256AESGCM`) to unwrap a 32-byte data-encryption key (DEK) that lives only in Rust memory while unlocked. One Touch ID prompt per unlock.
* DEK encrypts the SQLite content columns (XChaCha20-Poly1305).
* X25519 message keys (for encrypting to contacts) are generated in Rust and stored in the DB, encrypted under the DEK.
* Unlock flow: Swift → Touch ID → Enclave unwraps DEK (ECIES) → `core.unlock(dek: &[u8])` (no copy across the FFI) → Rust copies it into its own buffer → Swift wipes its buffer and the `CFData` in place immediately after the call.
* Lock flow: `core.lock()` → zeroize DEK + all cached plaintext.

## 4. Approved dependencies

Rust: `uniffi`, `rusqlite` (features `bundled`), `chacha20poly1305` (XChaCha), `x25519-dalek`, `ed25519-dalek` (relay-side only), `p256` (feature `ecdsa`; verifies Secure Enclave P-256 signatures in `brev-core` and `brev-relay`; Swift only signs), `poly1305` (feature `zeroize` only, to wipe the one-time MAC key), `zeroizing-alloc` (1Password; `brev-core`'s global allocator, zeroes every freed block), `hkdf`, `sha2`, `rand` (with `getrandom`), `zeroize`, `serde` + `serde_json`, `thiserror`, `anyhow` (bin crates only), `tokio` + `axum` + `reqwest` (relay/transport only), `tracing` (never log content).

Swift: Foundation, AppKit, Security, LocalAuthentication, CryptoKit (only if an Enclave operation needs it), AVFoundation + CoreMedia + CoreVideo (only for the capture-protected content layer), UserNotifications, DeviceCheck (Phase 4). No third-party Swift packages without asking.

Tooling: `cargo`, `uniffi-bindgen`, `xcodegen`, `xcodebuild`, `swiftlint` (optional), `cargo-audit`, `cargo-deny`.

## 5. Phases

Each phase ends with a short summary in `docs/DECISIONS.md` and passing `scripts/test.sh`. Ask before moving on if anything is unclear.

### Phase 0 — Scaffold

* Create the directory layout in §3, `Cargo.toml` workspace, `project.yml` for XcodeGen, `.gitignore`, `scripts/build.sh` (cargo build → uniffi bindings → xcodebuild), `scripts/test.sh`.
* `brev-core` exposes one UniFFI function `ping() -> String`.
* The Swift app launches, shows an empty window titled "Brev", calls `ping()` and logs the result.
* Copy §1–§2 into `docs/THREAT_MODEL.md`. Create `docs/DECISIONS.md`.
* Definition of done: `scripts/build.sh` produces a runnable `.app` from a clean checkout; `cargo test` passes; the window opens.

### Phase 1 — Encrypted core, no UI

* Implement data model, encrypted SQLite store, DEK-based column encryption, `Locked`/`Unlocked` state machine, zeroization.
* Implement crypto: X25519 key agreement + HKDF + XChaCha20-Poly1305 for message bodies; envelope struct with sender id, recipient id, ciphertext, nonce, and a signature slot (signature filled by Swift/Enclave later — for now accept an Ed25519 test key).
* `MockTransport`: two `Core` instances in one process can exchange envelopes.
* Tests that must exist:
   * Round-trip: A encrypts → B decrypts → equal.
   * Tamper: flip one ciphertext byte → decrypt fails.
   * No-plaintext: write a message with a known marker string, then scan the raw DB file bytes and assert the marker is absent.
   * Lock: after `lock()`, reading returns `Err(Locked)` and the DEK memory is zeroed (test via a debug-only accessor).
* Definition of done: all tests pass; `cargo audit` clean; no `unsafe` outside the UniFFI boundary.

### Phase 2 — The locked UI

* Onboarding: explain the "no backup, Touch ID only" tradeoff in Norwegian; create Enclave keys; wrap a fresh DEK.
* Unlock screen → Touch ID → `core.unlock(dek)`.
* Three-pane AppKit window: contacts list, thread list, message view. Content panes use `SecureTextView`.
* Compose sheet with `SecureComposeView` (secure event input, synthetic event rejection, no pasteboard, no autocorrect, `writingToolsBehavior = .none`).
* Window capture exclusion, including the protected content layer (§3.2), auto-lock, blank-on-lock. The capture defence is part of the definition of done.
* Two contacts hard-coded through `MockTransport` so you can send a message to yourself and see it arrive.
* Stored content (contact names, subjects, bodies) padded to the envelope buckets with the padding function from `brev-proto` (schema v2), before any real store exists.
* Manual verification checklist (write it to `docs/VERIFY.md` and run it):
   * Screenshot (⇧⌘4) of the window shows black/empty content.
   * Accessibility Inspector shows no text for content views.
   * ⌘C does nothing in content views; Edit menu has no Copy/Paste for them.
   * `strings` on the SQLite file finds no message text.
   * AppleScript `tell application "Brev" to ...` fails (no dictionary).
   * Switching to another app locks Brev.
* Definition of done: checklist passes; build is sandboxed + hardened.

### Phase 3 — Real transport

* `brev-relay`: minimal axum server. Endpoints: register public identity with a chosen address, look up an address, submit envelope, poll envelopes for a recipient. Stores only ciphertext + routing metadata. Deletes envelopes after delivery. No accounts yet beyond a public key and its address.
* `RelayTransport` in `brev-core` (HTTP, polling every N seconds; no websockets yet).
* Envelope signatures now come from the Secure Enclave via Swift: `core.sign_request(bytes) -> Swift signs with Touch ID → core.attach_signature()`. Relay verifies the P-256 signature against the registered identity; `brev-core` verifies it on receive (`p256`, §4). Swift never verifies.
* Padding: the plaintext payload is padded before encryption, as part of the envelope format in `brev-proto`, to fixed buckets of 256 B / 1 KiB / 4 KiB / 16 KiB, and above that to the next multiple of 16 KiB. The padding is unambiguous so the recipient can strip it (a length prefix; PKCS#7 cannot express more than 255 bytes of padding). Hard maximum: 1 MiB padded payload, defined in `brev-proto` and enforced by both the app and the relay. Tests: payloads within one bucket give ciphertexts of equal length; boundary sizes (exact bucket, bucket + 1, maximum, maximum + 1).
* Contact exchange by address, like email (docs/DECISIONS.md D-0031): a user registers a short, unique address; adding a contact means typing their address, and the relay returns their public keys. The app pins a contact's identity key the first time it sees it (trust on first use). If that key later changes, the app shows a clear warning and sends nothing until the user accepts the new key. Each contact's identity code (base32 of the public-key hash) is shown in the app so people who want to can compare it; comparing is optional. No QR codes, no links.
* Definition of done: two Macs (or two app instances with separate data dirs) exchange messages through a local relay; relay DB contains no plaintext (test it); a changed key for a pinned contact triggers the warning and blocks sending (test it).

### Phase 4 — Human-only guarantees (anti-noise)

* Contact approval: messages only from approved contacts; one short contact request otherwise, which the recipient approves or declines with one click.
* Invite codes: one-time text codes that carry the inviter's address and identity-key fingerprint. Redeeming one makes inviter and invitee approved contacts of each other, with the inviter's key already verified against the fingerprint. A new identity needs one to register; the relay tracks the invite graph. Codes are text to paste, never links (§1.4 forbids URL schemes). Addresses and invite codes are not message content, so copy and paste of them is allowed on the contact screen only, never in content views.
* Rate limits: max N messages/day per identity (relay-enforced).
* Delivery: like ordinary email, the relay hands an envelope to the recipient on their next poll after it passes the checks above. No delayed or batched delivery (docs/DECISIONS.md D-0030).
* App Attest (`DCAppAttestService`): relay accepts registrations only from attested app builds. Stub behind a feature flag if unavailable on the dev machine.
* BankID/ID-porten: stub only — a `IdentityVerifier` trait with a `DevVerifier` that always passes. Document the real integration as a future task.
* Definition of done: an unapproved sender cannot reach an inbox; an invite code whose fingerprint does not match the key the relay returns is rejected; rate limits and immediate delivery of approved envelopes are covered by relay tests.

### Phase 5 — Hardening and trust

* Reproducible build script; document how a user can verify the binary.
* `cargo-deny` config, `cargo-audit` in CI, Swift build warnings as errors.
* Memory review: search for every place plaintext exists in Swift; ensure it is a `[UInt8]` buffer that is zeroed, never a `String` that lingers.
* Notarization steps documented (not required to run).
* Developer ID distribution: sign Release builds with the Developer ID certificate and a Developer ID provisioning profile carrying the same keychain access group, and document notarization. (Keychain storage itself arrived in Phase 2, D-0035.)
* Write `docs/SECURITY.md` for external reviewers.

## 6. Working conventions

* Commit after each meaningful step with a clear message.
* Keep functions small; keep the UniFFI surface minimal and opaque.
* Rust: `#![forbid(unsafe_code)]` in `brev-core` except the generated bindings module. `clippy::all` clean.
* Swift: no `String` for message content in views — use `[UInt8]` / `Data` and convert only at draw time, then wipe.
* Never log content, even at debug level. Log message ids, not bodies.
* When unsure whether something violates §1, it probably does — ask.
* If a macOS API behaves differently on the installed OS version than documented (e.g. `sharingType` vs ScreenCaptureKit), note it in `docs/DECISIONS.md` and add a second defense rather than relying on one.

Start with: "Read CLAUDE.md, confirm the plan for Phase 0 in a few sentences, then begin."
