# Brev — threat model

Copy of CLAUDE.md §1–§2; keep in sync.

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
