# Swift memory review (Phase 5)

CLAUDE.md §5 Phase 5: "search for every place plaintext exists in Swift;
ensure it is a `[UInt8]` buffer that is zeroed, never a `String` that
lingers." This file is the inventory of that search over `app/Sources` at
the head of `claude/phase4` (2026-09-29), with the checks that prove each
row. The rules it checks against are docs/PHASE2_DESIGN.md §6.2 and §6.3
(D-0044).

## Method

- Read every file in `app/Sources` (Shared, Keys, App, UI, Verify,
  AppDelegate) and the patched bindings (`app/Generated/BrevCore.swift`,
  patches A–D of `scripts/patch-bindings.py`).
- Grepped every `String`, `Data`, `[UInt8]`, `SecretBytes`, `SecretText`,
  `wipe`, CF string constructor and log call, and followed every value that
  leaves Rust (`OpenText`, record fields of type `Data`) or goes into it.
- For each secret: the type that holds it, who owns it, where it is wiped,
  and which automated check proves it. "Harness" is the heap-scan harness
  (`app/Tests/main.swift`, run five times per case by `scripts/test.sh`,
  under `MallocScribble=1`); "lock probe" is `app/Tests/Lock/main.swift`
  (the AppKit side, run once by `scripts/test.sh`); "view host" is
  `tools/viewhost` (compiled by `scripts/test.sh`, run by hand).

Two facts carry the whole table:

1. `SecretBytes` wipes on `wipe()` and on `deinit` (`memset_s` over its whole
   capacity), and never grows. `SecretText` is a `SecretBytes`. So a holder
   that is dropped without an explicit wipe still leaves nothing; the
   explicit wipes only make the wipe happen at the right moment (close, new
   selection, lock), not later.
2. Every freed heap block is overwritten (`MallocScribble=1`, enforced by
   the launch guard, D-0047). So a `Data` or array that held a secret and is
   freed leaves nothing either. What must not happen is a secret in memory
   that stays *allocated* after it is needed. That is what this review looks
   for.

## Inventory

Verdict: **ok** (right type, wiped at the right time, checked), **ok,
bounded** (right type, lives slightly longer for a stated reason),
**accepted** (outside Swift's reach, CLAUDE.md §2).

### Key material

| Secret | Location | Type | Wipe point | Coverage | Verdict |
|---|---|---|---|---|---|
| New DEK (onboarding) | `Keys/UnlockService.swift` `create(in:)` | `SecretBytes(64)`, filled by `SecRandomCopyBytes` in place | `defer` in `create(in:)` and in `Session.create` | Harness case 3: one copy (its buffer) before and **after `Enclave.wrap`** (added in this review), none after `Session.create` | ok |
| DEK read by Security to wrap it | `Shared/Enclave.swift` `wrap(dek:to:)` | no-copy `Data` view of the `SecretBytes`, bridged to `CFData` | not held; the view dies with the call | Harness case 3 (added) | ok |
| DEK passed to `Brev.create` | `Shared/Session.swift` `create` | no-copy `Data` view (32 B, out of line) | `defer { dek.wipe() }` | Harness case 3 | ok |
| Unwrapped DEK | `Shared/Enclave.swift` `unwrap` / `withWiped` | the `CFData` Security returns, seen through a no-copy `Data` | `memset_s` in place when `withWiped` returns, every path, same thread as `Brev.unlock` | Harness case 1 (`withWiped` and `unwrap` zero on throw) and case 3 (same address, all zero; DEK only in Rust while unlocked, nowhere after lock; no ECDH, AES key or IV left) | ok |
| Serialised DEK on its way into Rust | bindings `FfiConverterRustBuffer.lower` | `[UInt8]` writer, then `RustBuffer` | patch C wipes the writer; Rust's zeroing allocator frees the buffer | Harness case 3 | ok |
| KEK and identity private keys | Secure Enclave `SecKey` | never in process memory | — | — | ok |
| Wrapped DEK, public keys, digests, signatures | `KeyStore`, `AppDelegate.pendingWrapped`, `SignService`, `Session.register` | `Data` | not secret | — | ok |

### Content leaving Rust (names, subjects, bodies)

| Secret | Location | Type | Wipe point | Coverage | Verdict |
|---|---|---|---|---|---|
| A 960-byte chunk of an `OpenText` | `Shared/Transcode.swift` `TextReader.read` | `Data` from the FFI (patch D: one copy, straight from the `RustBuffer`, which patch A wipes) | `c.wipe()` right after it is copied | Harness cases 4, 8, 9 | ok |
| UTF-8 staging of one text | `TextReader.read` | `SecretBytes(byte_len)` | `defer` | Harness cases 4, 8, 9 | ok |
| Body shown | `UI/SecureTextView.swift` | `SecretText` owned by the view | `clear()` on new selection, reload, sync, lock (`LetterStackView.clear`, then `GlyphFlush`) | Harness cases 4, 8, 9 (the same `TextReader` → `TextLayout` path); lock probe (lists and letters wiped, pixels zero) | ok |
| Subjects, contact names, request addresses in lists | `UI/SecureListView.swift`, shared with `MailViewController.threads/contacts/requests` | `SecretText` owned by the list | `setRows`/`clear()` wipes the old rows; `wipeAll()` at lock | Harness cases 4, 8, 9 (subjects: marker); **case 9 needle 2** (names, added); lock probe | ok |
| A text read when a later read fails | `Session.readAll`, `MailViewController.showLetters` | `SecretText` | wiped on the error path; unread `OpenText`s closed | code review | ok |
| A kept `OpenText` | nowhere: `TextReader.read` closes in `defer`, nobody stores one | — | Rust empties it at lock | Harness case 5 | ok |

### Content going into Rust (compose, keystrokes)

| Secret | Location | Type | Wipe point | Coverage | Verdict |
|---|---|---|---|---|---|
| Subject and body being written | `UI/SecureComposeView.swift` → `Shared/EditModel.swift` | `SecretText` of fixed size (limits from Rust), edited in place; `delete` zeroes the freed tail | `wipe()` on send, cancel, close and lock (`ComposeSheet.wipeAll`) | Harness case 2 compose (typed marker in the model, none after `wipe`); **lock probe: a draft in both fields is zeroed by the lock** (added) | ok |
| One keystroke | `Shared/KeyTranslator.swift` `translate` | 4-unit stack tuple | `memset_s` in `defer`, before `translate` returns | Harness case 2 compose (typing through `KeyTranslator`) | ok |
| Folded address/contact units, pasted units | `EditModel.insert`, `insertPasted` | `withUnsafeTemporaryAllocation` | `memset_s` in `defer` | Harness case 2 (units) | ok |
| Dead-key state | `KeyTranslator.deadKeyState` | `UInt32` (which accent waits, not text) | `reset()` on focus loss, on `wipe()`, and on any named key | code review | ok |
| Recipient name in the compose sheet | `UI/ComposeSheet.swift` `RecipientView` | `SecretText.copy()` owned by the view | `clear()` in `wipeAll` (every close, and the lock) | **Lock probe** (added) | ok |
| Outgoing UTF-8 | `Session.withUTF8` (letters, typed addresses) | `SecretBytes(3 × units)`, handed over as `withFFIView` | `defer` | Harness cases 4 (up to 65 000 units), 8, 9 | ok |
| Serialised argument | bindings `lower` | `[UInt8]` writer | patch C | Harness cases 4, 8, 9 | ok |

### Contact data (addresses, identity codes, invite codes)

| Secret | Location | Type | Wipe point | Coverage | Verdict |
|---|---|---|---|---|---|
| Own address, a contact's address, an inviter's or asker's address | `Session.me/contactInfo/openInvite/requests` → `ContactHeaderView`, `ContactSheet`, `AddressViewController` (`ContactTextView` rows) | `SecretText` owned by the view | `set(i, nil)` / `clear()` on new selection and in each `wipeAll` | **Harness case 9, needle 2** (B's address as UTF-16, seen while held, gone after wipe and lock; added); lock probe (header, address page) | ok |
| Identity codes (35 ASCII bytes) | `Session.me/contactInfo/requests/openInvite` | FFI `Data` copied into `SecretBytes` by `Session.secret`, the `Data` wiped in `defer`; drawn as a `SecretText` copy | the header wipes the bytes after copying them; the text copy with its row; `newCode` kept for `acceptNewKey`, wiped by `clearContact` | **Harness case 9, needle 3** (added); lock probe (header) | ok |
| Code sent back in `acceptNewKey` | `Session.acceptNewKey` | 35-byte `Data` copy | `defer { code.wipe() }` | code review (same pattern as the needle-3 rows) | ok |
| Typed address or invite code | `ContactField` / address field (`EditModel`) | `SecretText` | `wipe()` on success and in `wipeAll` | Lock probe (address page, both steps) | ok |
| UTF-8 copy of a typed address or code while its relay call runs | `ContactSheet.add`, `AddressViewController.next` | `SecretBytes`, or a `SecretText.copy()` | wiped when the call on `Session.net` returns | Harness case 9 (codes: needle 0 after lock) | **ok, bounded**: a lock during the call does not wait for it; the copy lives until the call returns (at most 15 s, `relay.rs` `TIMEOUT`). Rust holds its own copy for the same call. |
| Invite code made here | `Session.createInvite` → `ContactSheet.code` | `SecretBytes` (FFI `Data` wiped in `defer`) | next code, close, lock; a result after a close is wiped at once | Harness case 9 (needles 0 and 1: its secret as text in Swift and as bytes in Rust) | ok |

### Pasteboard (contact screen only)

| Secret | Location | Type | Wipe point | Coverage | Verdict |
|---|---|---|---|---|---|
| Bytes written (own address, invite code) | `UI/ContactPasteboard.swift` `write` | no-copy `Data` view of a `SecretBytes`; the pasteboard copies | the caller's `SecretBytes` (`copyAddress`: `defer`; the code: with the sheet) | View host (the text read back equals what was written, markers first) | ok |
| Bytes read by ⌘V | `ContactPasteboard.read` | AppKit's `Data` inside an `autoreleasepool`, copied into a `SecretBytes(256)` | AppKit's copy freed at the end of the pool; the `SecretBytes` wiped in `ContactField.pasteText`'s `defer` | View host; lock probe (`insertPasted`) | ok |
| The pasteboard's own copy | the pasteboard server | — | self-clear after 60 s and at quit, if still Brev's | View host | accepted by design (PHASE4 §6.2; SECURITY.md design limits) |

### Drawing (Core Text, pixels)

| Secret | Location | Type | Wipe point | Coverage | Verdict |
|---|---|---|---|---|---|
| One line being laid out or drawn | `Shared/TextLayout.swift`, `SecretText.composedRange` | `CFStringCreateWithCharactersNoCopy` over ≤ 448 units, `CFAttributedString`, `CTLine`, in an `autoreleasepool` | freed per line (scribbled); `GlyphFlush` after a letter view is torn down, after a sheet closes and in the lock | Harness case 4 (glyph needle; control without scribbling), 8, 9; SelfScan (Verify build, V39) | accepted (framework copies, CLAUDE.md §2) |
| Pixels | `UI/OpaqueView.swift` pixel buffers | `CVPixelBuffer` | `memset_s` in place on `blank()` and in the lock | Lock probe (every buffer zero after lock) | accepted until blank-on-lock (CLAUDE.md §2) |
| Dates and labels | `drawMeta`, `InterfaceText`, `L10n` | `String` | — | — | not content |

### Everything that is a `String`

Every `String` in `app/Sources` is one of: an L10n string or a date
(`InterfaceText`, `LetterStackView.Letter.header`, `SecureListView.Row.meta`,
`L10n.*`), an error variant name for a log, a store path or relay URL
(`Session.create/open`), a keychain attribute key, a layout id, or a launch
argument or environment variable name. None holds content, an address or a
code. The forbidden-API grep in `scripts/test.sh` keeps the ways to make a
`String` from bytes out of `app/Sources`. Logs carry counts, flags and error
variant names only (every `Logger` interpolation was checked).

## Findings

**No code gap.** Every place that holds content, contact data or key
material holds it in a `SecretBytes`/`SecretText` (or, for one call, a
no-copy view of one, a `CFData` wiped in place, or an FFI `Data` wiped in
place), and each is wiped where docs/PHASE2_DESIGN.md §6.2 says. No `String`,
`[UInt8]` or `NSString` holds any of it.

**Coverage gaps, closed in this review** (each new check has a positive
control and fails if the wipe is left out):

1. Onboarding's `Enclave.wrap` was not heap-scanned: case 3 wrapped in a
   helper process. Case 3 now wraps the DEK in-process and checks that the
   DEK is still only in its own buffer.
2. Addresses and identity codes were never scanned (the harness holds its
   test addresses as `String`s, so a UTF-8 needle would find those). Case 9
   now scans for B's address as UTF-16 (the form only a `SecretText` has)
   and for B's identity code while B's own and A's reads of them are held,
   and finds neither after the wipe and the locks. Leaving `infoB`
   unwiped makes the check fail (`needles=[0,0,1,1,…]`; run by hand).
3. The lock probe checked that a lock ends the compose sheet, not that it
   wipes the draft. It now types a draft into both fields and checks that
   the lock zeroes both buffers and the recipient's name copy.

## Not covered by a heap scan, and why

- The AppKit holders (`SecureComposeView`, `ContactTextView`,
  `RecipientView`, `ContactSheet`, `ContactPasteboard`) cannot run in the
  harness, which is built from `Shared/` only. They hold the same
  `SecretText`/`SecretBytes` types the harness scans, and the lock probe
  checks that each is zeroed or dropped by the lock.
- Single keystrokes and single pasted characters: the scanner looks for
  16-unit sequences, so one unit of stack residue cannot be seen. The
  keystroke buffer is wiped by code (`memset_s` in `defer`), and a typed
  16-unit marker leaves no copy (case 2).
- Swift's own stack frames are not scrubbed (Rust scrubs its own). What a
  frame can hold is at most the transcoder's few bytes of state in
  `Transcode` or one keystroke; out of the threat model for the same reason
  as CLAUDE.md §2's stack copies.

## Left for the owner

- A decision entry for this review (no `DECISIONS.md` entry was written
  here, by instruction).
- `docs/SECURITY.md` §7 item 5 now lists this review as done (2026-09-29).
- The bounded case above (a typed address or code lives up to the relay
  timeout if a lock comes during its call) could only be shortened by a
  Rust API that copies the argument before its I/O and returns at once;
  not worth it while Rust holds the same copy for the same time.
