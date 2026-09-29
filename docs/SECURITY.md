# Brev — security overview for reviewers

This file is for people who review Brev from the outside. It says what Brev
promises, what it defends against, where each defence lives, how the keys
work, what the relay sees, how to check the claims, and what is still open.
It points to the detailed documents instead of copying them.

Status (2026-09-29, branch `claude/phase4`): Phases 0 to 4 are code-complete,
and the Phase 5 items that need no human are done (§7 item 5). The checks
that need a human at the Mac (Touch ID) have not all been run yet (see
"Known gaps"). Brev holds **test letters only**. It is not released.

Where to read more:

| Document | What it holds |
|---|---|
| `CLAUDE.md` | the specification: invariants (§1), threat model (§2), architecture (§3), approved dependencies (§4), phases (§5) |
| `docs/THREAT_MODEL.md` | §1 and §2 on their own, kept in sync with `CLAUDE.md` |
| `docs/DECISIONS.md` | every architectural decision, dated, with reasoning and what verified it (D-0001 onward) |
| `docs/ARCHITECTURE-REUSE.md` | what lives in which crate, and which security decisions Swift makes and Rust enforces |
| `docs/PHASE2_DESIGN.md`, `docs/PHASE3_DESIGN.md`, `docs/PHASE4_DESIGN.md` | the designs of the locked UI, the transport and the anti-noise rules |
| `docs/VERIFY.md`, `docs/VERIFY-RESULTS.md` | the verification checklist (rows V1 to V81) and the machine-run results |
| `docs/DISTRIBUTION.md` | Developer ID signing, notarization, and how a user checks a downloaded build |
| `docs/REPRODUCIBLE_BUILD.md` | how to rebuild Brev from source and compare it byte for byte (`scripts/repro-build.sh`) |
| `docs/SWIFT_MEMORY_REVIEW.md` | every place Swift holds content or key material, its type, wipe point and check |

## 1. What Brev promises

The one core promise (`CLAUDE.md` §1):

> Nothing on this Mac — no other app, no AI agent, no OS feature, no browser
> extension, no automation — can read the content of messages or the message
> history. There is no setting, API, export or integration that can change
> this. Content is only ever visible inside the app window, to a human who
> has physically authenticated with Touch ID.

Ten invariants back it up. In short: no plaintext on disk; no text in the
Accessibility tree; no content on the pasteboard; no Share menu, Services,
printing, AppleScript, Shortcuts, URL scheme, plugins or any other interface
that returns content; no content in notifications ("Ny melding" only), the
Dock, Spotlight, Handoff or window titles; no autocorrect, spell-check,
dictation or Writing Tools where content is; no home-made cryptography;
Touch ID only, no password fallback; keys never leave this Mac (no iCloud
Keychain, no backup); plaintext is wiped from memory when a letter closes or
the app locks. The exact text is in `docs/THREAT_MODEL.md` §1.

A consequence users must accept: **there is no backup.** Losing the Mac, or
adding or removing a fingerprint, loses the history. Setup says so.

## 2. Threat model

The full threat model, including every accepted residual risk with its
mitigation, is `docs/THREAT_MODEL.md` §2. In one line each:

- **In scope:** AI agents with file access (they see ciphertext only),
  screen-reading and computer-use agents (an opaque view), screenshots and
  screen recording (the window is excluded), keyloggers and event taps
  (secure input while composing), synthetic input (rejected), macOS system
  AI features (nothing exposed), the relay itself (zero-access, key changes
  detectable), and spam (approval, invites, rate limits).
- **Out of scope:** a kernel or root compromise, hardware attacks, a camera
  pointed at the screen, a recipient who leaks what they got.
- **Accepted residual risks** (reviewed, not fixed; each is explained in
  `docs/THREAT_MODEL.md`): transient key copies inside audited crates and
  inside Apple frameworks; file substitution of `brev.db`; the developer
  Mac that holds Brev's signing key; the local relay (Phases 3 and 4);
  keystrokes in macOS event objects; pixels in backing stores until lock;
  freed memory in Apple frameworks (handled by `MallocScribble=1`); and the
  self-reported environment class.

## 3. Architecture and where each defence lives

Two languages with a hard line between them. **Rust owns everything that
touches content**: storage, cryptography, the lock state, the relay client.
**Swift owns only what must be Mac-native**: the window, drawing, input, the
keychain and Touch ID.

```
            ┌──────────────────────── Brev.app (sandboxed, hardened) ─────────────────────────┐
            │  Swift / AppKit (app/Sources)                                                    │
            │   window hardening, protected layer, HumanButton, input filter, secure input,    │
  Touch ID ─┼─► Secure Enclave keys (identity, KEK) + wrapped DEK in the keychain              │
            │        │ DEK (32 bytes, wiped after the call)            ▲ opaque handles only  │
            │  ──────▼─────────────────────── UniFFI (BrevCore) ───────┴────────────────────   │
            │  Rust: brev-mail (library brev_core) ── brev-proto ── brev-vault                 │
            │   mail rows, message crypto,            wire format,    store, DEK, lock state,  │
            │   relay client, FFI surface             signatures      column AEAD, padding,    │
            │                                                          zeroing allocator       │
            └────────────────────────────────────┬─────────────────────────────────────────────┘
                                                 │ HTTP, http://127.0.0.1:<port> only
                                         brev-relay (axum, separate process, relay.db)
```

### 3.1 The components

| Component | Language | Role |
|---|---|---|
| `core/brev-vault` | Rust (rlib, no UniFFI, no network) | The SQLite store and its hardening (absolute path, 0700 folder held with a flock, 0600 file, exact schema check), the DEK in one buffer with the `Locked`/`Unlocked` gate, the two-step unlock and the idle deadline, column encryption, padding, `Plaintext` and chunked `Text`, stack scrubs, the OS RNG, the zeroing global allocator, the launch guard, and the environment class. `scripts/check-vault-deps.sh` fails on any dependency outside its whitelist. |
| `core/brev-mail` | Rust (library `brev_core`) | Mail on top of the vault: the schema (`brev.db`, v5), identity, contacts and their sealed flags, invites, threads, letters; message crypto; the relay client; the whole UniFFI surface (`ffi.rs`). The send rule (environment class A) lives here. |
| `core/brev-proto` | Rust | The wire format shared by app and relay: envelope, bodies, identity id and code, invite codes, P-256 signature verification (`sig`). Re-exports the vault's padding so both sides use one implementation. |
| `core/brev-relay` | Rust (axum binary) | The relay: registration, lookup, envelopes, inbox and ack, requests, events, invites, *Blokker*, rate limits. Listens on `127.0.0.1` only. Stores ciphertext and routing metadata. |
| `app/` | Swift + AppKit | Onboarding, unlock, the three-pane window, the compose sheet, the contact screen. Draws content only into capture-protected pixel buffers. Holds the keychain and Touch ID code. |

A detailed map of files and items is in `docs/ARCHITECTURE-REUSE.md` §1–§2.

### 3.2 What Rust enforces, and what it trusts Swift for

This is the most important table for a reviewer. It is condensed from
`docs/ARCHITECTURE-REUSE.md` §3.

**Rust enforces on its own**, whatever Swift does:

- The DEK is correct (the store's key check) and non-zero.
- Every content call returns `Locked` after `lock()`, and `lock()` wipes the
  DEK and closes every open `Text`.
- An unlock stays `Armed` (content still locked) unless Swift confirms the
  app is active within 2 s; an idle deadline (320 s) wipes the DEK from a
  Rust timer thread even if Swift never calls `lock()`.
- One open store per folder; folder 0700, file 0600; no plaintext columns
  for content.
- The launch guard (in part): `create`, `open` and `unlock` refuse a
  `DYLD_*` variable or a `MallocScribble` other than `1`.
- Signatures: Rust checks its own signature (from the Secure Enclave)
  against the identity key before sending, and every received envelope
  against the contact's pinned key before decrypting.
- Key pinning: a changed key for a contact blocks sending until the user
  accepts it; invite fingerprints must match what the relay returns.
- The relay URL must be exactly `http://127.0.0.1:<port>`.
- Heap zeroing (the global allocator) and stack scrubs after crypto.

**Rust enforces, but on Swift's word** (the environment report, see §7):

- A letter goes out only in environment class A. The class comes from
  seven fields Swift reports: key origin (Secure Enclave), Touch ID used,
  capture exclusion, secure input, synthetic-input rejection, AX opacity,
  no pasteboard. Rust cannot check these facts. Until attestation, this rule
  catches Swift bugs, not attackers.

**Swift only** (Rust knows nothing):

| Defence | Where |
|---|---|
| Touch ID gate, no password button, access-control flags, keychain group | `Shared/Enclave.swift`, `Keys/KeyStore.swift`, `Keys/UnlockService.swift`, `Keys/SignService.swift` |
| Capture exclusion: `sharingType = .none` plus an `AVSampleBufferDisplayLayer` with `preventsCapture` (macOS 26 needs both) | `App/Hardening.swift`, `UI/OpaqueView.swift` |
| Secure event input while composing | `UI/SecureInput.swift`, `UI/SecureComposeView.swift` |
| Synthetic input refused (the source-PID rule), AX presses refused on buttons | `Shared/InputFilter.swift`, `App/BrevApplication.swift`, `UI/HumanButton.swift` |
| No text in the Accessibility tree; no pasteboard, Services, Writing Tools, autocorrect or input context in content views | `UI/OpaqueView.swift`, `UI/SecureComposeView.swift`, `App/MainMenu.swift` |
| Pasteboard for addresses and invite codes only, on the contact screen only | `UI/ContactPasteboard.swift` (a test.sh grep keeps it the only file) |
| Secret memory as wipeable byte buffers; Core Text one line at a time | `Shared/SecretBytes.swift`, `SecretText.swift`, `TextLayout.swift` |
| Lock triggers (resign active, screen lock, sleep, user switch, ⌘L, quit) and blank-on-lock | `App/LockController.swift`, `Shared/LockState.swift` |
| Launch hygiene (arguments, debug defaults, re-exec with `MallocScribble`), backup exclusion | `Shared/LaunchGuard.swift`, `Keys/KeyStore.swift` |

**The bundle** (`app/project.yml`): App Sandbox on, Hardened Runtime on,
library validation on, no `get-task-allow` in Release, only the entitlements
`app-sandbox`, `network.client` and one keychain access group. No AppleScript
dictionary, Services, document types or URL types in `Info.plist`.

## 4. Key management and cryptography

Brev implements no cryptographic primitive itself. Rust uses the audited
RustCrypto and dalek crates listed in `CLAUDE.md` §4; Swift uses Apple's
Security framework.

### 4.1 The keys

| Key | Kind | Where it lives | Protected by |
|---|---|---|---|
| Identity key | P-256, Secure Enclave `SecKey` | keychain, tag `no.brev.app.identity` | Touch ID per use (`.biometryCurrentSet`, `.privateKeyUsage`) |
| Key-encryption key (KEK) | P-256, Secure Enclave `SecKey` | keychain, tag `no.brev.app.kek` | Touch ID per use |
| Wrapped DEK | 32 bytes, ECIES-wrapped under the KEK | keychain generic-password item (service `no.brev.app`, account `wrapped-dek`) | only the KEK can unwrap it |
| DEK | 32 random bytes | Rust memory only, while unlocked | wiped on lock and by the idle timer |
| X25519 message key | static secret, generated in Rust | `identity.keys` column in `brev.db`, sealed under the DEK | the DEK |
| Relay token | 32 random bytes | same sealed column; the relay keeps only its SHA-256 | the DEK |

All three keychain items are in the data protection keychain, access group
`AV26DNQ5SC.no.brev.app`, `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`,
never synchronizable. The keychain binds them to Brev's signing identity,
so no other program can use, read or replace them — **on a Mac that does
not hold Brev's team signing key** (see §7). Details: `docs/DECISIONS.md`
D-0035, D-0036, D-0037.

### 4.2 Unlock

1. Swift asks for Touch ID (`.deviceOwnerAuthenticationWithBiometrics`,
   empty fallback title, so no password button).
2. The Secure Enclave unwraps the DEK with `SecKeyCreateDecryptedData`,
   algorithm `.eciesEncryptionCofactorVariableIVX963SHA256AESGCM`.
3. Swift calls `unlock(dek)`. Rust copies the 32 bytes into its own buffer
   and checks them against the store. Swift then wipes its buffer and the
   `CFData` in place. Rust overwrites 64 KiB of stack.
4. The unlock stays `Armed` until Swift confirms the app is still active
   (within 2 s); only then can content be read.

One Touch ID prompt per unlock. Lock (`lock()`) wipes the DEK and every open
plaintext buffer.

### 4.3 Stored content

Every content column (contact names and addresses, subjects, bodies, keys,
flags, invite secrets) is `nonce[24] ‖ ciphertext ‖ tag[16]`:
XChaCha20-Poly1305 under the DEK, a fresh random nonce per write, and the
row's fixed fields in the associated data (label `brev/v0/column/`). Moving
a ciphertext to another row, or editing a bound field, makes the next read
fail. Content is padded before encryption to the envelope buckets, so a
stored length shows only the bucket. Contacts are found by a keyed tag
(HKDF-SHA256 of the identity id under the DEK), not by a plaintext id.
D-0021, D-0041, `docs/PHASE3_DESIGN.md` §6.1.

### 4.4 Letters

- **Identity id:** SHA-256(`"brev/v0/identity"` ‖ length ‖ P-256 signing key
  ‖ X25519 public key). It commits to both keys (D-0016). The identity code
  shown to users is base32 of its first 150 bits.
- **Encryption:** static-static X25519 between sender and recipient; key =
  HKDF-SHA256(salt = the 24-byte nonce, info = `"brev/v0/message-key"` ‖
  sender id ‖ recipient id); cipher XChaCha20-Poly1305 with the envelope
  header as associated data (D-0017).
- **Padding:** the payload is padded (length prefix) to 256 B, 1 KiB,
  4 KiB, 16 KiB, then multiples of 16 KiB, at most 1 MiB, before
  encryption. The relay sees only the bucket (`docs/PHASE3_DESIGN.md` §2.2).
- **Signature:** Rust computes SHA-256 of the envelope's signed bytes
  (header ‖ ciphertext). Swift signs that digest with the Secure Enclave
  identity key (`.ecdsaSignatureDigestX962SHA256`, one Touch ID prompt per
  letter). Rust converts and verifies the signature against its own
  identity key before the letter leaves. The relay verifies it against the
  registered key; the recipient's Rust core verifies it against the pinned
  key before it decrypts. Swift never verifies. Verification uses the `p256`
  crate through one function, `brev_proto::sig::verify`.
- **Order of checks on receive** (`docs/PHASE3_DESIGN.md` §3.3): addressed
  to me, a known contact, the contact row intact, signature, AEAD, payload
  shape, thread owner, then store. Unapproved or blocked senders are refused.

Known properties of this design, accepted for now (D-0017): **no forward
secrecy**; whoever holds one party's X25519 secret can read that party's
recorded traffic and forge letters *to* that party; the sender can decrypt
its own envelopes. The X25519 secret sits under the DEK, so these need the
DEK first.

### 4.5 Memory hygiene

Rust: a zeroing global allocator wipes every freed heap block (including
UniFFI's buffers); `Plaintext` is wiped on drop and cannot be cloned or
printed; `scrub_stack` overwrites 16 KiB of stack after each crypto
operation, and a release-mode test proves it is not optimised away.
`scripts/gen-bindings.sh` patches the generated Swift so byte buffers are
wiped before they are freed; the build fails if a patch stops applying.
Swift: content is `[UInt8]` in wipeable buffers, drawn one line at a time,
never a lingering `String`. Freed memory inside Apple frameworks is
overwritten because `MallocScribble=1` is set in `Info.plist`, and Brev
refuses to unlock without it. D-0039, D-0040, D-0044, D-0045. The Swift
side is inventoried in `docs/SWIFT_MEMORY_REVIEW.md` (no code gap found).

## 5. What the relay sees

The relay is Brev's own backend, and it is inside the threat model: it must
learn no content. It speaks binary `POST` bodies over HTTP on
`127.0.0.1` only (no TLS yet, because it is local; see §7).

| The relay sees and keeps | How long |
|---|---|
| Each identity's address, P-256 signing key, X25519 public key, SHA-256 of its relay token | until the operator releases the address |
| Envelopes: sender id, recipient id, nonce, ciphertext (bucketed size), signature | until the recipient acknowledges them; then deleted with `secure_delete` |
| Who looks up whom; when each user polls (every 5 s, only while unlocked) | not stored; visible while it happens |
| The invite graph: who brought each identity in | for the identity's life |
| The approval graph: who takes letters from whom, who declined or blocked whom | persistent |
| Pending contact requests (who asks whom) | until answered |
| Invites: SHA-256 of a value derived from the secret, the inviter, the day | 7 days |
| Letters, requests and invites per identity today | until the next day's write |

The relay **never** sees: letter content, subjects, contact names, the
invite secret, which channel carried an invite code, or any key that
decrypts anything. It stores no timestamps (days only), no IP addresses and
no request log.

What a malicious relay could still do, and what stops it:

- **Hand out a false key at first contact** (trust on first use). Invite
  codes carry the inviter's fingerprint and are checked both ways, so an
  invite-based contact is verified. A contact added by address is pinned on
  first sight; a later key change shows a warning and blocks sending. Users
  can compare identity codes.
- **Drop, delay or reorder letters.** Not detected: there are no sequence
  numbers.
- **Widen who can write to you.** It cannot: the app keeps its own sealed
  approval flags, and refuses letters from anyone who is not an approved
  contact, whatever the relay stores.

Details: `docs/PHASE3_DESIGN.md` §4 and §11, `docs/PHASE4_DESIGN.md` §2–§4
and §11.

## 6. How to verify the claims

### 6.1 Automated: `scripts/test.sh`

One command, no Touch ID, no window on screen. On macOS it runs, in order:
the patched bindings and the Xcode project; `cargo fmt` and `clippy`; the
Rust tests (including the invariant tests: no marker bytes in the store
file, tamper fails, lock zeroes the DEK, stack scrubs survive release
optimisation, key change blocks sending, an unapproved sender cannot reach
an inbox, invite fingerprint mismatch is refused, rate limits); the zeroize,
allocator and crate-feature checks; brev-vault's dependency whitelist; a
check that no production code creates a P-256 signing key; the pinned FFI
surface and the binding patch markers; the forbidden-API grep over
`app/Sources` (no `NSTextView` or `NSTextField`, no Services menu, no
logging calls, no `String` built from content bytes, no `URLSession`, and
more; each allowed exception is listed with a reason in
`scripts/allowed-apis.txt`); the pasteboard greps; `cargo audit` and
`cargo deny check` against `core/deny.toml` (each skipped with a loud
warning if the tool is not installed); a local relay with a fresh database;
the Swift heap-scan harness and the lock probe; type-checks of the
verification tools; and an Xcode build. Swift and C warnings are errors in
the app (`app/project.yml`) and in every build `scripts/test.sh` runs. It
stops at the first failure. On Linux it runs the Rust part only.
`.github/workflows/ci.yml` runs the Rust part (fmt, clippy, tests,
`cargo audit`, `cargo deny`) on Linux.

### 6.2 Manual: `docs/VERIFY.md`

81 rows (V1 to V81) that check the running app from outside: screenshots
and every capture path (ScreenCaptureKit, CoreGraphics, `CGDisplayStream`,
`AVCaptureScreenInput`, `screencapture`), the Accessibility tree, the
pasteboard, AppleScript, synthetic keys and clicks, event taps, the files on
disk, a memory scan of the running process at each lock (the Verify build),
the relay's database, key changes, approvals, invites and rate limits. Each
row says whether a machine can run it (A) or a human is needed (H), and each
permission-based check has a positive control. `docs/VERIFY-RESULTS.md`
records the machine-run results.

### 6.3 The tools: `tools/verify`, `tools/viewhost`

`tools/verify/build.sh` builds the probes the rows use: `capture-probe`
(judges each capture path against a visible control window), `windows`,
`axdump`, `poster` (synthetic input), `keylisten` (event tap), `padcheck`
(sealed column lengths), a Touch ID probe with a negative control, and the
Verify build of Brev. `tools/viewhost` runs Brev's windows with fake
letters and a software key, for checks that need no keychain. The table in
`docs/VERIFY.md` ("Tools") says which row uses which tool.

### 6.4 A downloaded build

How a user checks the signature, notarization and entitlements of a
downloaded Brev is in `docs/DISTRIBUTION.md` §6. How to check that it was
built from the published source is in `docs/REPRODUCIBLE_BUILD.md`.

## 7. Known gaps

These are open today. None is hidden in the residual-risk list; each is
named here so a reviewer does not have to find it.

1. **Human verification pending.** The `docs/VERIFY.md` rows that need a
   human with Touch ID have not been run for Phase 2, Phase 3 (the
   two-instance run, WP6) or Phase 4 (its definition-of-done run). The
   machine-run rows are in `docs/VERIFY-RESULTS.md`. Until the human run
   passes, the Touch ID paths, the real Secure Enclave signing prompt and
   parts of the capture defence are tested only by machine and by design.
2. **The developer Mac's signing key.** On a Mac that holds Brev's team
   signing key, any same-user program can sign itself into Brev's App ID
   and keychain group without a prompt, and then replace Brev's keychain
   items or ask for Touch ID on Brev's keys. This was shown on 2026-09-28.
   The owner accepted it while Brev holds only test letters (D-0062,
   D-0065). **Real letters go only on a Mac that does not hold the team's
   signing keys.** Developer ID signing (`docs/DISTRIBUTION.md`) does not
   change this on the developer's Mac.
3. **The local relay.** In Phases 3 and 4 the relay runs as the same user
   on `127.0.0.1`, so any same-user program can act as the relay: edit its
   database, take its port, hand out a false key at first contact, change
   approvals, invites and rate-limit counts. The relay-side checks are
   built and tested but protect only once the relay runs elsewhere, with
   TLS. The inviter-side invite check and the app's own approval flags hold
   even against the relay.
4. **Self-reported environment class.** Sending needs class A, but the
   class comes from Swift's own report. Until App Attest (per-letter
   assertions) lands, the rule catches Swift bugs, not attackers. App
   Attest and the BankID/ID-porten `IdentityVerifier` are stubs: any build
   can register, and one person can hold several identities, limited by
   invites.
5. **Phase 5.** Done: `cargo audit` and `cargo-deny` (`core/deny.toml`)
   in `scripts/test.sh` and in CI (`.github/workflows/ci.yml`, not pushed
   yet); Swift and C warnings as errors; the Swift memory review
   (`docs/SWIFT_MEMORY_REVIEW.md`); a reproducible build
   (`scripts/repro-build.sh`, `docs/REPRODUCIBLE_BUILD.md`; shown on one
   Mac, not yet on a second one or a Developer ID-signed build). Not done:
   a universal (arm64 and x86_64) build; Brev is built for arm64 only.
6. **Design limits** listed in the phase designs: no forward secrecy; the
   relay can drop or reorder letters undetected; an invite code is a
   bearer secret while it sits on the pasteboard (at most 60 s) or in
   transit; a program that can write Brev's container can roll back a
   store or a sealed flag cell to an older copy (no version counter); local
   APFS snapshots can keep old encrypted stores; no notifications while
   locked. `docs/PHASE3_DESIGN.md` §11 and `docs/PHASE4_DESIGN.md` §11.

## 8. Reporting a security issue

*Placeholder: a contact address and a disclosure policy will be added
before the first public release.* Until then, contact the project owner
directly and do not open a public issue. Please include the commit, the
macOS version, and the steps to reproduce. Never include real letter
content.
