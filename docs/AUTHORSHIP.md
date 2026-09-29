# Authorship attestation ("Hand"), v1 — design

Status: the owner's design (D-0107 to D-0109). §9 steps 1 to 4 are built
(D-0110, D-0111), and the owner test (step 5, docs/VERIFY.md V82 to V84)
passed (D-0112). Since D-0113 and D-0115 there are no classes: one set of
requirements (§4), profile `hand-v2`, store schema v7; V82 to V84 need a
rerun by the owner.

## 1. What a letter proves today, and what Hand adds

Today a letter proves one thing: its envelope was signed by the sender's
identity key (a Secure Enclave P-256 key, Touch ID-gated), and the relay and
the recipient check that signature.

Hand adds a signed **authorship token** inside every letter. It states how
the letter was written: the key, the protections that were on, what the app
measured on the Mac while the letter was open, and a hash of the exact
content. The recipient's Rust core checks the token and stores the result,
and the inbox shows it as a badge.

On Mac there is one hard limit (D-0108). Apple's App Attest is switched off
for native Mac apps on macOS 26.2, and the relay's registration check is a
stub that accepts any P-256 key. So nothing proves to the recipient that
the token came from Brev at all. On Mac the token proves only that **the
holder of the sender's identity key signed these statements about this
content**. Everything else in it is the sender's own word. The detail view
says so in plain words: «Appen er ikke bekreftet av Apple (støttes ikke på
Mac)».

## 2. The token

The token is a COSE_Sign1 structure (RFC 9052), the usual envelope for an
EAT (RFC 9711), encoded with `ciborium`. There is one signer (the identity
key) and one algorithm (ES256: ECDSA P-256 with SHA-256).

```
Token = [                       ; COSE_Sign1, untagged, CBOR array of 4
  protected:   bstr .cbor { 1: -7 },   ; alg = ES256, nothing else
  unprotected: {},                     ; always empty
  payload:     bstr .cbor Claims,
  signature:   bstr (64)               ; raw r ‖ s, low-s not required
]
```

### 2.1 Claims

Integer keys are registered EAT/CWT claims; text keys are Brev's own claims.

| Key | Name | Type | Meaning |
|---|---|---|---|
| 6 | `iat` | uint | Sender's clock at signing, Unix seconds. |
| 10 | `eat_nonce` | bstr (16) | Random per token, from the OS RNG in Rust. |
| 265 | `eat_profile` | tstr | `"tag:ermesjoandreas.github.io,2026:hand-v2"`. v1 had a `"class"` claim; a v1 token fails the form (D-0115). |
| `"platform"` | | uint | 1 = macOS. Reported by the app. |
| `"key"` | | uint | Where the identity key lives: 1 Secure Enclave, 2 TPM, 3 software, 4 unknown. |
| `"content"` | | bstr (32) | Content hash, §2.3. |
| `"env"` | | map | The measured facts, §2.2. |
| `"app-attest"` | | bstr | Apple's assertion (§5). **Absent on Mac.** |

### 2.2 The facts (`"env"`)

A fact the app could not read is CBOR `null`. D-0107 item 3 applies: any
`null` fails the requirements (§4).

| Key | Type | Source | How it is measured |
|---|---|---|---|
| `"secure-input"` | bool / null | sampled | `IsSecureEventInputEnabled()` was true in every sample while the compose view had focus. |
| `"capture-off"` | bool / null | sampled | The compose window had `sharingType = .none` and its protected layer `preventsCapture = true` in every sample. |
| `"ax-opaque"` | bool | by design | Content views expose no text to Accessibility. |
| `"pasteboard-off"` | bool | by design | No copy, cut, paste or drag of content. |
| `"input-filter"` | bool | by design | Events from another process (`eventSourceUnixProcessID != 0`) are dropped. |
| `"pastes"` | uint | counted | Pastes that reached the content. Always 0 in Brev, because paste is blocked; the field exists for other apps on the SDK. |
| `"blocked-input"` | uint | counted | Synthetic events the filter dropped. |
| `"sip"` | bool / null | sampled | System Integrity Protection on: `csr_get_active_config` returns 0 (checked against `csrutil status`). |
| `"sudo"` | uint / null | sampled | Live `sudo` or `su` processes (`sysctl KERN_PROC_ALL`). |
| `"agents"` | uint / null | sampled | Running processes whose name is on the agent list (§4.3). |
| `"windows"` | uint / null | sampled | Highest number of other apps' normal windows (layer 0) on screen in any sample. |
| `"admin"` | bool / null | once | The user is in the admin group (`mbr_check_membership`). |
| `"seconds"` | uint | Rust clock | From opening compose to the send request. |
| `"max-gap"` | uint | Rust clock | Longest gap in seconds in the chain *compose opened → every sample → the sample taken at send*, on a monotonic clock. |

Rust takes one sample synchronously at `sign_request` (Swift hands it
over with the request). A sampled fact with no sample behind it is `null`.
So a letter with no measuring has gaps or `null` facts and fails the
requirements.

"By design" facts are true because of how Brev is built; the app cannot
measure them at run time. They are listed so the requirements can name
them, and so an SDK app that lacks one of them cannot make a proof.

### 2.3 Content hash

```
content = SHA-256( "brev/v1/hand/content\0" || letter )
letter  = message id (16) || thread id (16) || subject length (u16 BE) || subject || body
```

`letter` is today's payload (store.rs `encode_payload`), unchanged and not
padded. The spec said "the padded plaintext"; hashing before padding gives
the same protection (the padding is strictly checked on unpad) and keeps
the hash independent of Brev's transport, so another SDK app can use it.

### 2.4 The exact bytes that are signed

The Secure Enclave signs the SHA-256 digest of COSE's `Sig_structure`:

```
digest = SHA-256( CBOR([ "Signature1", protected, h'', payload ]) )
```

`protected` and `payload` are the exact byte strings in the token.
`external_aad` is empty. Every other preimage Brev signs starts with
`"BREV"` (envelope) or `"brev/v2/register\0"` (registration); this one
starts with CBOR `0x84 0x6A "Signature1"`, so no signature is valid for two
purposes.

**Encoding.** `ciborium` has no deterministic mode: it writes map entries
in the order it is given them. It also keeps duplicate keys and tags when
it decodes. So `brev-hand` has its own small encoder, with shortest forms,
definite lengths and a fixed key order. That order is bytewise order of the
encoded keys (RFC 8949 §4.2.1).

- **Claims:** `6, 10, 265, "env", "key", "content", "platform", "app-attest"`.
- **`env`:** `"sip", "sudo", "admin", "agents", "pastes", "max-gap", "seconds", "windows", "ax-opaque", "capture-off", "input-filter", "secure-input", "blocked-input", "pasteboard-off"`.

The verifier does four things, in order:

1. It decodes with `ciborium`.
2. It requires exactly these key lists, in this order, with no extra keys,
   no duplicates and no tags.
3. It builds the typed claims.
4. It re-encodes them and requires the result to equal the payload bytes.

`protected` must be exactly `A1 01 26`. The claims therefore have one valid
encoding. The signature has two, s and n − s. That is harmless, because
nothing is keyed on the token's bytes. The token is at most 2 KiB.

### 2.5 Where the token travels

Inside the encrypted payload, after the letter:

```
payload = letter length (u32 BE) || letter || token length (u16 BE) || token
```

The envelope protocol version goes from 1 to 2, and the relay and the app
refuse version 1. All existing letters are test letters. The relay sees
nothing new except one field it adds itself: `received_at` (u64 BE, Unix
seconds) next to each envelope in the inbox answer, outside the signed
bytes. A short letter now fills the 1 KiB bucket instead of 256 B.

## 3. Producing it (sender)

### 3.1 Who does what

| Step | Swift adapter | Rust (`brev-hand`, `brev-mail`) |
|---|---|---|
| Compose opens | `compose_started()` | Starts the clock and an empty fact log. |
| Every 2 s | Samples and hands over **raw observations**: secure-input state, own window settings, `csr_get_active_config` value, process names, on-screen windows (owner pid, layer) | Counts, keeps maxima, applies the agent list and the window filter, records gaps. |
| On each event | `synthetic_dropped()`, `paste_accepted()` | Counts. |
| Send | `sign_request(...)` as today | Checks the requirements, builds letter, content hash, nonce, `iat`, claims; returns the token digest. |
| Touch ID | New `LAContext`, one prompt, signs the token digest | Checks the signature with the own key, seals payload with the token, returns the envelope digest. |
| Same context | Signs the envelope digest (no second prompt), then invalidates the context | Checks it; `submit` as today. |

Swift never assembles the token, never decides whether the requirements
hold and never passes a count: it passes what it saw (process names, window list, raw SIP bits) and
Rust decides. So Swift cannot claim "0 agents" without also hiding the
process names it read, and the adapter's surface has no setter for a fact.

Nothing the adapter sends contains content. Process names and window owners
are kept in memory only for counting and are wiped with the compose session.

### 3.2 One Touch ID, two signatures

The token must be signed before the letter is sealed (it is inside the
ciphertext), and the envelope after. Both signatures use one fresh
`LAContext`, so the user sees one prompt per letter, as today. Unlock never
counts: the context is created for this letter only.

**Invalidating the context.** It is invalidated, and the `SecKey` looked up
with it is dropped, on every way out:

- after the second signature;
- when Rust refuses the token signature;
- on a lock;
- on `cancel_send`;
- on any error.

No authenticated key reference is kept, because a kept one would sign later
digests without a prompt.

**Plaintext during the prompt.** Between the two steps, Rust holds the
letter's plaintext during the prompt, which today's `seal_letter` avoids.
It is a vault `Plaintext`, and a lock or `cancel_send` wipes it (§1.10).

### 3.3 Send rule

`sign_request` freezes the fact log (with its sample taken at send) and
refuses unless every requirement of §4.1 holds; `Environment` names the
ones that do not. A token exists only for facts that met them.
`prepare_send` keeps the same check only as an early exit before the
network lookup. `allow-software-keys` skips only the hardware-key
requirement, on the sender's and the recipient's side, in test archives
only, with the existing release check.

## 4. Requirements

There are no classes (D-0113, D-0115). A letter either meets every
requirement below, or it is not sent; the recipient checks the facts in
the token against the same list.

### 4.1 The rule (one function in `brev-hand`, used by sender and recipient)

`requirements::unmet` returns the names of the requirements a letter does
not meet, in token order (`"key"` first); empty means it meets them all.
Each of these must hold:

- the key is in hardware (`"key"` is 1 or 2);
- no fact is `null` (unreadable);
- `secure-input`, `capture-off`, `ax-opaque`, `pasteboard-off` and `input-filter` are true;
- `pastes` is 0;
- `sip` is true;
- `sudo` is 0;
- `max-gap` ≤ 5 (the measuring had no hole).

A test archive (`allow-software-keys`) skips the first line only.

### 4.2 Shown, but not required

`windows`, `agents`, `admin`, `blocked-input` and `seconds` are shown to the
recipient as numbers, and their values never fail the rule. If one of them
could not be read, the rule fails (D-0107 item 3). The spike read all of
them in the sandbox. They are weak signals: the agent list is a name list,
window titles are not readable, most Mac users are admins, and a blocked
input never reached the letter. Requiring them would make the badge claim
things nobody can prove (D-0107 item 4).

### 4.3 Locking: sudo and SIP (owner, D-0109)

While Brev is unlocked, the adapter hands Rust a sample every 2 s. It does
this all the time, not only during compose. If a sample shows a running
`sudo` or `su`, or SIP off, Rust locks the vault at once: the DEK and every
open letter are wiped, and an unsent draft is lost. Unlock is refused with
`Environment` while either holds, because the sample taken at unlock must
be clean.

A fact that cannot be read does not lock Brev. It fails the requirements
(D-0107 item 3), so letters can still be read but not sent. The token keeps
`"sip"` and `"sudo"`, and the rule in §4.1 still fails them, although
genuine Brev never gets that far.

### 4.4 The agent list

A short, documented list of process names (for example `claude`, `codex`,
`cursor`, `ollama`), kept in `brev-hand` and versioned with the profile. A
renamed program is not seen; the doc and the detail view say so.

## 5. App Attest (not on Mac)

App Attest is not available to native Mac apps on macOS 26.2 (D-0108). The
`"app-attest"` claim is reserved: when a platform supports it, it holds
Apple's assertion over the deterministic CBOR of the claims map without
the `"app-attest"` key, and the Secure Enclave signature covers it as well.
Apple's App Attestation Root CA is pinned by the SHA-256 of its DER,
`1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932`
(`tools/verify/spikes/hand/vectors/`).

Until a verifier exists, a token that carries `"app-attest"` fails
verification: the recipient never shows a check it did not make. Later, a
sender that has once sent an attested token must keep doing so, like key
pinning, so a missing attestation cannot be passed off as "not supported".

## 6. Verifying it (recipient)

`verify(letter, token, sender_key, received_at) -> Verification`, in
`brev-hand`, runs every check and reports each one as pass or fail with the
failing field names:

1. **Form**: the token parses as §2, is at most 2 KiB, re-encodes to the
   same bytes, `alg` is ES256, the profile is `hand-v2`, and every claim and
   fact is present with the right type (so a `"class"` claim fails).
2. **Signature**: ES256 over §2.4, with the sender's pinned identity key
   (the key that already verified the envelope).
3. **App Attest**: absent → pass, and noted as "not attested". Present →
   fail until a verifier exists (§5).
4. **Content**: `"content"` equals the hash of the received letter bytes.
5. **Replay**: the message id was not stored before. The content hash
   binds the message id, so a token cannot be moved to another letter.
   The store already refuses a stored message id for good (`Duplicate`),
   in the same transaction that stores the letter. That replaces the
   spec's separate nonce cache, which would have to live as long and be
   written in the same transaction anyway. `eat_nonce` stays in the token,
   so no two tokens are alike.
6. **Time**: `received_at − 24 h ≤ iat ≤ received_at + 5 min`.
   `received_at` is set by the relay at the first submit and kept on
   redelivery.
7. **Requirements**: the facts in the token meet §4.1. A failure names the
   facts that miss one.

The result (every check, the numbers from §4.2) is stored sealed with the
letter (store schema v7).

**Badge**

| Result | Reading header | Message list |
|---|---|---|
| All checks pass | «Skrevet i Brev» | a small seal |
| Any check fails | «Ikke verifisert» | the chip «Ikke verifisert» |

**Detail on click.** The detail view lists each check in plain Norwegian,
for example «Innholdet er endret etter signering». It then lists what the
sender's app reported: «Nøkkel i maskinvare med Touch ID: ja (oppgitt av
avsenderens app)», «Andre vinduer synlige: 2», «Kjente AI-programmer i
gang: 0», «Skrivetid: 4 min». A failed requirements check reads «Kravene
er ikke oppfylt: …» with the facts. The last line is always «Appen er ikke
bekreftet av Apple (støttes ikke på Mac)». The view shows no content and no
keystroke data, only counts.

## 7. What this does not prove

- **That Brev was used at all (on Mac today).** The relay accepts any
  P-256 key, and App Attest is off. Any program with any P-256 key and an
  invite, for example a script with a software key, can send tokens with
  any facts. That includes `"key": 1` and facts that meet every
  requirement. The key and every fact are the sender's own statement. The signature proves only which identity
  sent the token.
- **That the app was unmodified on a Mac holding Brev's team signing key**
  (CLAUDE.md §2). A modified Brev there can use the real keys.
- **Who typed.** Some input looks like a human at the keyboard and has a
  source pid of 0, so the input filter lets it through:
  - a USB HID emulator or a hardware keyboard injector;
  - a software virtual keyboard (a DriverKit driver such as
    Karabiner-Elements).

  Karabiner's rules live in a file the user can write, and they reload by
  themselves. So a program running as the user can make one keypress type
  prepared text, and the letter still meets the requirements.
- **Where the words came from.** Copy-typing from another screen, a phone
  or paper; text an AI wrote and a human retyped.
- **Anything a camera records.**
- **Anything under kernel or root compromise.** `"sudo": 0` means only
  "no `sudo` or `su` process was running at the samples". None of these is
  seen:
  - a cached sudo login;
  - root processes started earlier (`sudo -b`, launchd daemons, "with
    administrator privileges").
- **Whose finger.** Touch ID proves an enrolled finger, not a willing one
  (a coerced finger), and not which enrolled person.
- **When the finger was placed.** The Enclave proves the key was used with
  Touch ID; that the prompt was fresh for this letter is the app's promise.
- **That no agent ran.** The agent list is a list of names.
- **What other windows showed.** Only their number is known.
- **The sender's clock.** `iat` is the sender's clock and `received_at` is
  the relay's. A malicious relay can set `received_at` so that any genuine
  letter shows «Ikke verifisert».

**What the recipient learns about the sender's Mac:** the platform, whether
the user is an admin, whether SIP is on, the counts in §2.2 and how long the
letter took to write. Onboarding must say this. The relay learns nothing
new, because the token is inside the ciphertext.

## 8. Tests

**Rust (`brev-hand`, `brev-mail`)**

- Round trip A → B meeting every requirement, verified, with the result stored.
- A tampered content hash fails (step 4).
- A replayed letter (same message id and token) fails (step 5), also after
  a crash between receiving and storing.
- Facts that miss a requirement fail step 7, which names them; a token
  with a `"class"` claim, or of profile v1, fails the form.
- A missing App Attest passes on Mac and is noted; a present one fails
  (step 3).
- A `null` fact fails the requirements.
- A sample gap over 5 s fails `max-gap`. This includes the gap from
  opening compose to the first sample, and from the last sample to send.
  No samples at all fails too.
- Facts that stop meeting the requirements between `prepare_send` and
  `sign_request` stop the send.
- Keys out of order, a duplicate key, a tag, an extra key, or a
  `protected` other than `A1 01 26` fail (step 1).
- A software key fails `"key"`, and a release build refuses to send it;
  a test archive skips only that requirement.
- A non-deterministic encoding fails (step 1).
- A signature made over the envelope digest does not verify as a token
  signature, and the reverse.
- `iat` just outside the window on either side fails (step 6).
- The adapter API has no way to set a count or a result: the fact log built
  from raw observations gives the expected counts, and a UniFFI surface pin
  test covers it.

**Swift**: one prompt per letter; the context is invalidated after the
second signature. **Owner test**: two instances, a letter each way, badge
and detail as in §6.

## 9. Work order (after the owner's go)

1. `brev-hand`: claims, CBOR, the requirements, verify, and the tests above.
2. Wire: envelope v2, payload with token, `received_at` in the inbox
   answer, store schema v6, v7 since D-0115 (sealed result; replay stays
   the message-id rule).
3. Swift adapter: the samplers and events of §3.1, one-context signing.
4. Recipient: verification on receive, stored result, badge and detail.
5. Owner test on the real Mac.
