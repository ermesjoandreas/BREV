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
5. Show message content in notifications, the Dock, Spotlight, Handoff, or window titles. Notifications say only "Ny melding fra <navn>".
6. Enable autocorrect, spell-check, predictive text, dictation, or Apple Writing Tools in any view that holds content.
7. Implement your own cryptographic primitives. Use audited crates only (see §4). Ask before adding any dependency not listed here.
8. Allow a password fallback for unlocking. Touch ID only (`.deviceOwnerAuthenticationWithBiometrics`, `.biometryCurrentSet`).
9. Sync keys to iCloud Keychain. Keys are `ThisDeviceOnly` and non-synchronizable. Losing the Mac means losing the history — this is intentional and must be explained to the user at setup.
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
* The relay server (our own backend) → zero-access; sees only ciphertext and minimal routing metadata.
* Spam / mass messaging / AI-generated noise → identity, contact approval, invite codes, rate limits (Phase 4).

Out of scope — explicitly NOT defended against:

* Kernel/root compromise of macOS, or hardware attacks.
* A camera pointed at the screen, or the user retyping content elsewhere.
* The recipient choosing to leak what they received.

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
* Encrypted store: SQLite via `rusqlite` (bundled). Every content column is a ciphertext BLOB. Metadata that must be queryable (contact id, timestamp, read flag) may be plaintext, but never subject lines or bodies.
* Crypto (see §4): identity keys, message encryption/decryption, envelope signing/verification.
* Session state: an `Unlocked` / `Locked` state machine. When locked, the data-encryption key and all plaintext are zeroized and every content call returns `Err(Locked)`.
* Transport trait: `trait Transport { send(Envelope); poll() -> Vec<Envelope> }` with a `MockTransport` (in-process, Phase 2) and `RelayTransport` (HTTP, Phase 3).
* Exposed to Swift with UniFFI (`uniffi` crate, proc-macro style). The Swift side never sees raw keys; it passes opaque handles.

### 3.2 Swift app (`app/`) — owns only what must be Mac-native

* AppKit, not SwiftUI, for every view that can contain content (we need low-level control over rendering, events and accessibility). SwiftUI is allowed for settings/onboarding screens that never show content.
* `SecureTextView: NSView` — renders text with Core Text directly into `draw(_:)`. No `NSTextView`, no `NSTextField` for content. Overrides `accessibilityRole`/`accessibilityValue` to expose nothing.
* `SecureComposeView: NSView` — same rendering, custom key handling, calls `EnableSecureEventInput()` on focus and `DisableSecureEventInput()` on blur. Rejects events where `CGEventGetIntegerValueField(event, .eventSourceUnixProcessID) != 0` (synthetic input from another process).
* Main window: `sharingType = .none`, `isExcludedFromWindowsMenu = true`, `titlebarAppearsTransparent`, no content in title.
* Auto-lock: on `NSApplication.didResignActiveNotification`, on screen lock, and after N minutes idle → call `core.lock()`, blank all views.
* Touch ID gate: `LAContext` with `.deviceOwnerAuthenticationWithBiometrics`. Secure Enclave key created with `SecAccessControlCreateWithFlags(... [.privateKeyUsage, .biometryCurrentSet])` and `kSecAttrTokenIDSecureEnclave`, `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`.
* Notifications via `UserNotifications`, sender name only.
* Bundle: Hardened Runtime ON, App Sandbox ON, `get-task-allow` OFF, library validation ON, no `NSAppleScriptEnabled`, no `NSServices`, no document types, no URL types.
* UI language: Norwegian (bokmål). Keep strings in `Localizable.strings`.

### 3.3 Key design (how Touch ID and Rust fit together)

The Secure Enclave can only hold P-256 keys, so:

* Identity signing key: P-256 in Secure Enclave, Touch ID-gated. Signs every outgoing envelope. Public key = the user's identity.
* Key-encryption key (KEK): a second P-256 Enclave key used with `SecKeyCreateDecryptedData` (ECIES) to unwrap a 32-byte data-encryption key (DEK) that lives only in Rust memory while unlocked.
* DEK encrypts the SQLite content columns (XChaCha20-Poly1305).
* X25519 message keys (for encrypting to contacts) are generated in Rust and stored in the DB, encrypted under the DEK.
* Unlock flow: Swift → Touch ID → Enclave unwraps DEK → `core.unlock(dek)` → Rust zeroizes the Swift-side buffer reference immediately after copy.
* Lock flow: `core.lock()` → zeroize DEK + all cached plaintext.

## 4. Approved dependencies

Rust: `uniffi`, `rusqlite` (features `bundled`), `chacha20poly1305` (XChaCha), `x25519-dalek`, `ed25519-dalek` (relay-side only), `hkdf`, `sha2`, `rand` (with `getrandom`), `zeroize`, `serde` + `serde_json`, `thiserror`, `anyhow` (bin crates only), `tokio` + `axum` + `reqwest` (relay/transport only), `tracing` (never log content).

Swift: Foundation, AppKit, Security, LocalAuthentication, CryptoKit (only for Enclave interop), UserNotifications, DeviceCheck (Phase 4). No third-party Swift packages without asking.

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
* Window capture exclusion, auto-lock, blank-on-lock.
* Two contacts hard-coded through `MockTransport` so you can send a message to yourself and see it arrive.
* Manual verification checklist (write it to `docs/VERIFY.md` and run it):
   * Screenshot (⇧⌘4) of the window shows black/empty content.
   * Accessibility Inspector shows no text for content views.
   * ⌘C does nothing in content views; Edit menu has no Copy/Paste for them.
   * `strings` on the SQLite file finds no message text.
   * AppleScript `tell application "Brev" to ...` fails (no dictionary).
   * Switching to another app locks Brev.
* Definition of done: checklist passes; build is sandboxed + hardened.

### Phase 3 — Real transport

* `brev-relay`: minimal axum server. Endpoints: register public identity, submit envelope, poll envelopes for a recipient. Stores only ciphertext + routing metadata. Deletes envelopes after delivery. No accounts yet beyond a public key.
* `RelayTransport` in `brev-core` (HTTP, polling every N seconds; no websockets yet).
* Envelope signatures now come from the Secure Enclave via Swift: `core.sign_request(bytes) -> Swift signs with Touch ID → core.attach_signature()`. Relay verifies the P-256 signature against the registered identity.
* Contact exchange: out-of-band by sharing a short identity code (base32 of public key hash) which the app renders; no QR codes yet.
* Definition of done: two Macs (or two app instances with separate data dirs) exchange messages through a local relay; relay DB contains no plaintext (test it).

### Phase 4 — Human-only guarantees (anti-noise)

* Contact approval: messages only from approved contacts; one short contact request otherwise.
* Invite codes: new identities need an invite from an existing one; relay tracks the invite graph.
* Rate limits: max N messages/day per identity (relay-enforced).
* Delivery: like ordinary email, the relay hands an envelope to the recipient on their next poll after it passes the checks above. No delayed or batched delivery (docs/DECISIONS.md D-0013).
* App Attest (`DCAppAttestService`): relay accepts registrations only from attested app builds. Stub behind a feature flag if unavailable on the dev machine.
* BankID/ID-porten: stub only — a `IdentityVerifier` trait with a `DevVerifier` that always passes. Document the real integration as a future task.
* Definition of done: an unapproved sender cannot reach an inbox; rate limits and immediate delivery of approved envelopes are covered by relay tests.

### Phase 5 — Hardening and trust

* Reproducible build script; document how a user can verify the binary.
* `cargo-deny` config, `cargo-audit` in CI, Swift build warnings as errors.
* Memory review: search for every place plaintext exists in Swift; ensure it is a `[UInt8]` buffer that is zeroed, never a `String` that lingers.
* Notarization steps documented (not required to run).
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
