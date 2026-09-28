# Brev Phase 4: "Human-only guarantees (anti-noise)" (design, revised)

Status: revised after review, 2026-09-28. Read at branch `claude/laughing-knuth-yhp8ji`, head **`63fc44f`** (= `cc7dbd6` + a `USER_SESSION.md` commit + "Phase 3 WP6 prep: `scripts/build.sh --instance b` builds Brev B"). Inputs: CLAUDE.md §1 to §6 (§5 Phase 4 as amended by D-0030 and D-0031), docs/DECISIONS.md up to **D-0068**, docs/PHASE3_DESIGN.md, docs/ARCHITECTURE-REUSE.md, `core/brev-{proto,relay,mail}`, the Swift contact UI. The repo was not modified. Scratch: `S = /private/tmp/claude-503/-Users-andypandy/01f11233-b284-49b2-9c90-391fa2f358ef/scratchpad/p4` (reviser clone in `S/reviser`, spikes in `S/spike`).

Principle: the simplest thing that meets §5 Phase 4. The relay stays on 127.0.0.1. The envelope format does not change. No new crate, no new Swift framework, no new Enclave key, no new Touch ID prompt. Approvals are relay state that only the recipient can change. Invites are one-time text codes checked against a fingerprint **in both directions** (the inviter checks the invitee with the same secret, §3.4). Rate limits are daily counters in the relay's file.

## 0. What was verified (CLI only: no window, no prompt, no network off 127.0.0.1, repo untouched)

| Proof | Result |
|---|---|
| Baseline | `cargo test -p brev-relay -p brev-proto --no-default-features`: green (20 tests). |
| Phase 3 is not closed | `scripts/build.sh --instance b` now exists (commit `63fc44f`, bundle id `no.brev.app.b`, name "Brev B"), but the WP6 DoD run with Touch ID has not happened, and Phase 3's own entries (its D-0037 to D-0053, 17 topics) are unwritten; DECISIONS.md reserves "numbers after D-0068" for them. CLAUDE.md §5: do not start a phase before the previous one's DoD. Owner question Q1. |
| Relay code facts used below | `server.rs:33` `SMALL_BODY = 16 * 1024` applies to `/v1/register`. `/v1/envelopes` takes a bare wire with no token (`submit`), and `store` is `INSERT … ON CONFLICT(id) DO NOTHING`, so an envelope acked (deleted) can be stored again. The server header promises that "an unsigned request cannot probe the directory". |
| brev-mail facts used below | `Core::receive` (`store.rs` ~802) accepts any envelope whose sender tag matches a `contacts` row. `SCHEMA_VERSION = 4`. `BrevError::KeyChanged` exists. `hkdf` and `sha2` are already brev-mail dependencies (§4 approved). |
| Pasteboard bytes without `String` (`S/spike/pb.swift`, named pasteboard only) | `setData(bytes, forType: .string)` → `data(forType: .string)` returns the same bytes. Another app's `setString` comes back as UTF-8 through `data(forType:)`. `org.nspasteboard.ConcealedType` / `TransientType` can sit beside `.string`. |
| macOS 26 pasteboard privacy (SDK `NSPasteboard.h` 52–70) | Programmatic reads of the **general** pasteboard may prompt; "user originated and paste related" access does not. Whether ⌘V in `keyDown` counts, or only a `paste:` action, needs a GUI: spike P1 (WP5). |
| App Attest in the dev setup | `DCAppAttestService.shared.isSupported` is false without the entitlement, and `attestKey` talks to Apple (off loopback, not allowed now). So: stub (§7). |
| Envelope untouched | Requests, approvals and invites are relay bodies. `PROTOCOL_VERSION` stays 1; `signed_bytes`, padding and `MAX_WIRE` do not change. |

## 1. Scope

### 1.1 CLAUDE.md §5 Phase 4, line by line

| §5 line | Built by | § / WP |
|---|---|---|
| Messages only from approved contacts | The relay stores an envelope only if the recipient approved the sender (`links`, else 409). brev-mail still drops letters from non-contacts, and now a contact row exists only for peers the user approved or verified (§5.3), so the client rule is a real second check | §4.3, WP2, WP3 |
| One short request otherwise, approved or declined with one click | `POST /v1/requests`, one per pair, no text (Q2). Shown with address and safety code in the protected layer; *Godta* / *Avslå* are one `HumanButton` click, no Touch ID | §4.3, §6.1 |
| Invite codes: one-time text codes with the inviter's address and fingerprint | `brev1.<address>.<fingerprint>.<secret>` (§3.1). The relay only ever sees a value derived from the secret | §3.1, §3.4 |
| Redeeming makes both approved contacts, inviter's key verified | The invitee checks the relay's answer against the code (`InviteMismatch`). The inviter checks the invitee's key with a tag only a holder of the secret can make (§3.4). Both sides pin with `VERIFIED` | §3.4, §5.3 |
| A new identity needs an invite to register | Registration v2 carries the invite (403 without). The operator mints root invites (`brev-relay invite`) | §3.2, §4.3, §4.6 |
| The relay tracks the invite graph | `identities.invited_by` (NULL = root) | §4.2 |
| Codes are text, never links | Plain ASCII; no URL type, no link detection | §3.1 |
| Copy/paste of addresses and codes only on the contact screen | `ContactPasteboard.swift` is the only `NSPasteboard` user outside OpaqueView's existing clear, called only from the contact field (address page, `ContactSheet`). Content views unchanged (V14) | §6.2 |
| Max N messages/day per identity, relay-enforced | `counts` per identity and UTC day (letters, requests, invites created); token-authenticated submit so nobody else can spend a sender's quota | §4.4 |
| Immediate delivery (D-0030) | Unchanged from Phase 3: all checks at submit, nothing held. Tested | §4.3, §8 |
| App Attest stub behind a feature flag | brev-relay feature `app-attest` + `AttestVerifier` (`DevAttest`); Swift `Attestor`/`NoAttestor`; registration carries an attestation field | §7 |
| `IdentityVerifier` + `DevVerifier`; real integration documented | brev-relay `gates.rs`, called at registration; future task in §7.3 | §7 |
| DoD: an unapproved sender cannot reach an inbox | relay `unapproved_sender_cannot_reach_an_inbox`, brev-mail `a_stranger_cannot_reach_an_inbox`, V76 | §8 |
| DoD: wrong fingerprint rejected | brev-mail `invite_with_wrong_fingerprint_is_rejected`, V77 | §8 |
| DoD: rate limits and immediate delivery in relay tests | relay tests 7, 8, 9 | §8 |

### 1.2 What Phase 3's answers and plans change

| Phase 3 item | Phase 4 |
|---|---|
| Q2: letters from people not added are dropped and acked | Replaced by requests. A stranger's envelope never reaches the relay's store (409). The client rule and `strangers_are_dropped_and_acked` stay |
| Q3: addresses are permanent; only the operator's `release` frees one | Unchanged. A re-registered B′ is a new identity with no links; it needs an invite (to register) and a request or invite to reach A, and at A that goes through Phase 3's key-change path (§5.3) |
| `add_contact` pins the relay's key (TOFU) | Still pins, and now **always** sends a request (§4.3); shows «Venter på svar» until approved |
| `Policy` hooks | Kept as a test deny hook. Phase 4 rules live in `Relay`, in the same transaction as their writes |
| Phase 3 D-0042 there: "signed requests come back with TLS and a remote relay (Phase 4)" | Not in §5 Phase 4. The relay stays local and token-authenticated. §2's "Phase 3 only" local-relay line becomes "Phases 3 and 4" (Q4) |
| `/v1/envelopes` without a token | Now `prefix ‖ wire`, caller must equal the envelope's sender (§3.2), so a recipient cannot replay old letters against the sender's quota |
| Stores and relay file | Mail schema v5, relay schema v2. v4 stores and v1 relay files are refused. Reset (test letters only; no migration) |

### 1.3 Out of Phase 4

Remote relay, TLS, off-Mac traffic. Text in requests (Q2). Listing or revoking one's own open invites (they expire). Real App Attest and the real BankID/ID-porten verifier (§7). Replies in a thread, notifications, several devices per identity. Everything in Phase 5. *Blokker* (removing an approved contact) is out unless the owner picks Q6 (b).

## 2. The model in one paragraph

The relay holds a directed **link** per pair: `links(owner, peer)` is *approved* (owner takes letters from peer) or *declined*. An **event** is something the relay tells an identity about a peer: *request*, *invited* (peer redeemed my invite, with a proof tag), *approved* (peer approved my request). An **invite** is a one-time secret `s`; the relay knows only `a = H("brev/invite/relay" ‖ s)` and stores `SHA-256(a)`. A letter S→R is stored only if `links(R, S)` is approved. A request S→R sets `links(S, R)` approved (asking means accepting replies; it also lifts S's own earlier decline of R) and, unless R already approved S, an event at R. R's *Godta* sets `links(R, S)` approved; *Avslå* sets it declined. Redeeming an invite sets both directions. Locally, brev-mail's contacts are exactly the peers the user added, approved, or verified by invite, so "letters only from contacts" is a local approval check that the relay cannot widen.

## 3. Wire (`brev-proto`)

### 3.1 Invite code text (`brev_proto::invite`)

`brev1.<address>.<fingerprint>.<secret>`, lower-case ASCII, at most **96 bytes** (6 + 32 + 1 + 30 + 1 + 26).
- `address`: the inviter's address (Phase 3 rules; `.` is not an address character, so the split is unambiguous).
- `fingerprint`: the inviter's identity code without spaces, lower case: base32 of the first 150 bits of the identity id (30 chars). The id hashes both public keys (D-0016), so it covers the signing and X25519 keys.
- `secret`: `s`, 16 bytes from the OS RNG, base32, 26 chars; the 2 padding bits must be zero.
- Root invite (operator, no inviter): `brev1.<secret>`.

`parse` trims ASCII whitespace, folds A–Z to a–z, and requires the prefix, 2 or 4 parts, a valid address and canonical base32. `format` is the inverse. The base32 decoder is a table lookup like `identity_code`, with known-answer tests. The relay never parses a code.

Derived values (brev-proto, `sha2` + `hkdf`):
- `a = SHA-256("brev/invite/relay\0" ‖ s)` (32 bytes): what the relay sees for open, register and redeem. It stores `SHA-256(a)`.
- `tag = HKDF-SHA256(ikm = s, salt = none, info = "brev/invite/peer\0" ‖ invitee id ‖ inviter id)`, 32 bytes: the invitee's proof to the inviter (§3.4). For a root invite the tag is 32 zero bytes and the relay ignores it.

### 3.2 Bodies (binary `POST`; paths stay `/v1`; health still answers `brev-relay v1`)

"Prefix" is Phase 3's 64 bytes: caller id ‖ relay token.

| Body | Layout |
|---|---|
| Registration **v2** (`/v1/register`) | `L ‖ address ‖ signing key 65 ‖ X25519 32 ‖ SHA-256(token) 32 ‖ a 32 ‖ tag 32 ‖ signature 64 ‖ attestation length u16 BE ‖ attestation (0 to **8 192** bytes)`. Signature over `"brev/v2/register\0" ‖ bytes [0, 194 + L)`. The attestation is made over the signed digest (§7.1), so it is not itself signed. Largest body 8 452 + L < `SMALL_BODY` |
| Lookup answer (changed) | `bundle 97 ‖ status 1`; 1 = target takes letters from caller, else 0 (pending and declined both read 0) |
| Envelope submit (**changed**, `/v1/envelopes`) | `prefix ‖ wire`; the route limit becomes `MAX_WIRE + 64` |
| Request (`/v1/requests`) | prefix ‖ target address |
| Events (`/v1/events`) | prefix. Answer: `count u8 (≤ 32) ‖ count × (kind u8 ‖ L u8 ‖ address ‖ bundle 97 ‖ tag 32)`. Kinds 2 and 3 first, then requests, each oldest first. Tag is zero except for kind 2 |
| Event answer (`/v1/events/answer`) | prefix ‖ peer id 32 ‖ verdict u8 (1 yes/seen, 0 decline) |
| Invite create (`/v1/invites`) | prefix ‖ SHA-256(a) 32 |
| Invite open (`/v1/invites/open`, no prefix) | a 32. Answer: `L ‖ address ‖ bundle 97`, or the single byte `00` for a root invite |
| Invite redeem (`/v1/invites/redeem`) | prefix ‖ a 32 ‖ tag 32 |

### 3.3 Authentication, signatures, replay

- **Identity signature (Touch ID):** registration only. Domain `brev/v2/register\0`, so a v1 body never verifies. The invitee's signature covers `a` and `tag`: the graph edge carries it.
- **Token:** submit, request, events, event answer, invite create, invite redeem. Phase 3's reasoning holds on loopback. Approvals are one click; `HumanButton` refuses synthetic clicks. Touch ID for invite creation is Q7.
- **Unauthenticated:** invite open, so an unregistered identity can check a code. `a` is 256 bits and derived from a 128-bit secret; it cannot be guessed.
- **Replay** needs no nonce or clock. Every write is idempotent or one-time: Same registration → 200; same invite hash → 200; redeem by the same caller → 200, by another → 404; repeat request → the uniform 202 (§4.3); repeat event answer → 404 (client reads "done"); envelope → token-bound to its sender, then Phase 3's dedupe (`Duplicate`). A replayed *invited* event is dropped because the inviter deleted its local invite row (§5.3).

### 3.4 Integrity of a code, both directions

- **Invitee checks inviter:** the relay's answer to `a` must match the code's form (2-part code → only `00`; 4-part → only a bundle), address and fingerprint. A lying relay cannot fit a 150-bit fingerprint to its own key. Otherwise `InviteMismatch`, and nothing is stored or sent.
- **Inviter checks invitee:** the inviter keeps `s` sealed in its store (§5.1). The *invited* event carries the invitee's bundle and `tag`. The inviter recomputes `HKDF(s, … ‖ bundle.id() ‖ my id)` for each of its open invites; a match pins the invitee with `VERIFIED` and deletes that invite row. No match → the event is marked seen and dropped. The relay knows only `a`, not `s`, so it can neither forge an *invited* event nor swap the invitee's key. This meets D-0031's "invite codes avoid [a false key] entirely" for both people.

## 4. Relay (`brev-relay`)

### 4.1 Endpoints (new or changed)

| Path | Auth | Answers |
|---|---|---|
| `POST /v1/register` | identity signature | 201 new; 200 Same; **403** invite unknown, used or expired; 409 taken or conflict; 400; 401; **428** attestation or identity verification failed; 429 policy |
| `POST /v1/lookup` | token | 200 `bundle ‖ status`; 404 |
| `POST /v1/envelopes` | token, caller = sender, + envelope signature | Phase 3's answers; 401 bad token; 403 caller ≠ sender; **409** not approved; **429** over the letter limit. 409 and 429 store nothing |
| `POST /v1/requests` | token | **202** for new, pending, declined and over the pending cap alike; 200 when the target already approved the caller; 400 own address; 404 unknown address; 429 over the request limit |
| `POST /v1/events` | token | 200 events (never deletes) |
| `POST /v1/events/answer` | token | 204; 404 no such event; 400 a decline of a non-request |
| `POST /v1/invites` | token | 201; 200 same hash again; 429 at the open cap or the daily cap |
| `POST /v1/invites/open` | none | 200; 404 unknown, used or expired |
| `POST /v1/invites/redeem` | token | 200 (also again by the same caller); 404 unknown, used by another, expired; 400 root or own |

### 4.2 Schema v2 (`application_id` "BRLY", `user_version` 2; v1 refused as `NotRelay`)

```sql
CREATE TABLE identities (id BLOB PRIMARY KEY, address TEXT NOT NULL UNIQUE, signing_key BLOB NOT NULL,
    x25519 BLOB NOT NULL, token_hash BLOB NOT NULL,
    invited_by BLOB                        -- the invite graph; NULL = root invite
) STRICT;
CREATE TABLE envelopes (...)               -- unchanged
CREATE TABLE links (owner BLOB NOT NULL, peer BLOB NOT NULL,
    state INTEGER NOT NULL,                -- 1 approved (owner takes letters from peer), 2 declined
    PRIMARY KEY (owner, peer)) STRICT, WITHOUT ROWID;
CREATE TABLE events (seq INTEGER PRIMARY KEY, recipient BLOB NOT NULL, peer BLOB NOT NULL,
    kind INTEGER NOT NULL,                 -- 1 request, 2 invited, 3 approved
    tag BLOB NOT NULL,                     -- 32 bytes; the invitee's proof for kind 2, else zeros
    UNIQUE (recipient, peer)) STRICT;      -- a newer event for a pair replaces the older
CREATE TABLE invites (hash BLOB PRIMARY KEY,  -- SHA-256(a)
    inviter BLOB,                          -- NULL = root
    day INTEGER NOT NULL,                  -- UTC day of creation (no timestamps)
    redeemed_by BLOB) STRICT;
CREATE TABLE counts (identity BLOB NOT NULL, kind INTEGER NOT NULL,  -- 1 letters, 2 requests, 3 invites made
    day INTEGER NOT NULL, n INTEGER NOT NULL, PRIMARY KEY (identity, kind)) STRICT, WITHOUT ROWID;
```

Pragmas, modes, `secure_delete` and the single `Mutex<Connection>` are Phase 3's. Days only, never times. Each invite write deletes expired invites; a count row of an older day is reset on write.

### 4.3 The rules, in order (each in one transaction with its writes)

- **Register:** parse (400); signature (401); attestation (feature `app-attest`, 428); **Same → 200** (a retry after the invite was used still works; only the key holder can hit it); **invite** by `SHA-256(a)`: exists, not redeemed, within its life (403); **then** address or id conflict (409); `IdentityVerifier` (428); `Policy::register` (429). Insert with `invited_by = inviter`, set `redeemed_by`. Unless root: `links` approved both ways and event (inviter, new, *invited*, tag). The invite check comes before the conflict check, so nobody without a valid invite learns which addresses are taken (Phase 3's no-directory-probe promise). A 409 does not consume the invite.
- **Submit:** parse; token (401); caller = `envelope.sender` (403); Phase 3's signature and recipient checks; `links(recipient, sender)` approved (409); letter count < limit (429); `Policy::submit`; insert; **only if inserted** (202) the count goes up. A 200 (already waiting) does not count.
- **Request S→R:** R exists (404); R ≠ S (400). If `links(R, S)` approved: set `links(S, R)` approved; if an event (S, R, *request*) is pending (R asked S), delete it and add event (R, S, *approved*); 200, no count. Otherwise: request count < limit (429); count it; set `links(S, R)` approved (overriding S's own earlier decline of R); then, only if `links(R, S)` is not declined, no event (R, S) exists, and R has fewer than **16** pending requests, add event (R, S, *request*); 202 in every case. So the requester cannot tell new, pending, declined or capped apart (Q5), and at the limit all get 429 alike.
- **Event answer by R about P:** event must exist (404). *Request* + yes → `links(R, P)` approved, delete, add event (P, R, *approved*). *Request* + no → `links(R, P)` declined, delete. *Invited*/*approved* + yes → delete (seen). No on those → 400.
- **Invite create:** open invites (not redeemed, in life) < cap and invites made today < daily cap, else 429; insert (201, and count it) or same hash (200, no count).
- **Invite open:** by `SHA-256(a)`. Unknown, redeemed, too old → 404. Root → `00`. Else the inviter's address and bundle.
- **Invite redeem by a registered B:** unknown or too old → 404. Redeemed by B → 200; by another → 404. Root or B's own → 400. Else `redeemed_by = B`, `links` approved both ways (an explicit invite overrides an earlier decline), event (inviter, B, *invited*, tag); 200. `invited_by` does not change.
- **`release`** (operator) also deletes the identity's links, events (as recipient or peer), invites it made, and counts. Its invitees keep `invited_by` (a dangling id; history kept).

### 4.4 Rate limits and the clock

The relay gains a clock: `today = unix_secs / 86 400` (UTC days), given through `Config` so tests can move it. `Config { letters_per_day, requests_per_day, invites_per_day, open_invites, pending_requests, invite_days, today }` goes to `Relay::open` beside `Policy`. Defaults (Q3): **50 letters, 10 requests, 3 invites made per identity per day; 5 open invites; 16 pending requests per recipient; 7-day invite life.** `serve` takes a flag for each. Lookups are not limited (§11).

What this bounds, honestly: the daily invite cap turns "unlimited puppets per minute" into at most a 3-way tree per day per identity; that still grows over days. The per-recipient pending cap means a victim never sees more than 16 open requests, and the event order means requests can never hide *invited*/*approved* events. Declining is one click and stops that identity for good. The invite graph lets the operator find and `release` a puppet subtree. A real stop needs App Attest and BankID, which are stubs (§7).

### 4.5 What the relay learns (new in Phase 4)

| Learns | Kept |
|---|---|
| Invite graph: who brought each identity in | identity's life (`invited_by`) |
| Invites made per identity and day; `a` at open, register, redeem; the opaque `tag` | 7 days, `SHA-256(a)` only; `tag` until the event is seen |
| **Approval graph**: who takes letters from whom, who declined whom | persistent (Q4) |
| Pending requests: who asks whom | until answered |
| Letters, requests and invites per identity today | until the next day's write |
| Never: content, contact names, `s`, which channel carried a code | – |

This goes beyond Phase 3, where who-writes-to-whom lived only until delivery. It is the price of the relay-side approval check D-0030 names. Content protection is unchanged.

### 4.6 CLI

`brev-relay invite --db <path>` prints a root invite code on stdout, stores `SHA-256(a)`, exits. It is the only way to bring in the first identity. `serve` gains the limit flags; `release` gains the deletions of §4.3. `scripts/relay.sh` passes the flags through.

## 5. brev-mail

### 5.1 Schema v5 (`SCHEMA_VERSION = 5`; v4 opens as `Corrupt`; reset)

- `contacts` gains `flags BLOB NOT NULL`, sealed under the DEK with AD `contacts.flags` ‖ local id: one byte, `APPROVED_ME = 1` (they take my letters), `VERIFIED = 2` (key checked through an invite).
- New `invites (id BLOB PRIMARY KEY, body BLOB NOT NULL)`: `id` is 16 random local bytes; `body` sealed with AD `invites.body` ‖ id holds `s ‖ UTC day u64`. Rows older than 7 days are deleted at each sync. The file shows only how many invites are open.
- Incoming requests and an opened invite live only in the session (cleared on lock) and are fetched again at each sync.

### 5.2 Contact states as the user sees them

| Local | Relay | Shown |
|---|---|---|
| no row, request in session | event *request* at me | under «Forespørsler» with *Godta* / *Avslå* |
| row, no `APPROVED_ME` | `links(me, them)` only | «Venter på svar»; *Send* gives `NotApproved` before Touch ID |
| row, `APPROVED_ME` | both links | ordinary contact |
| row, `VERIFIED` | both links | also «Bekreftet med invitasjon» |

### 5.3 Flows (Phase 3's pattern: gate and read under the mutex, network without it, `resume(epoch)` to store)

- **Add by address** (`add_contact`): Phase 3's checks; lookup (status); **always** `/v1/requests` (429 → `RateLimited`, nothing added); pin with `flags = status ? APPROVED_ME : 0`; remove the peer from `session.requests` if there. A lost answer is safe: a retry looks up and requests again.
- **Send:** `prepare_send`: class-A check (unchanged), then lookup. Status 0 → `NotApproved`: no ticket, no digest, no prompt. Status 1 sets `APPROVED_ME`. `submit` sends `prefix ‖ wire`: 409 → `NotApproved`, 429 → `RateLimited`; both clear the slot like Phase 3's `Refused`.
- **Sync:** poll, store, ack (unchanged); then `/v1/events`, and per event (one mutex hold each):
  - *request* from an unknown address → `session.requests`. From an existing contact → `check_key`: same key → answer yes; changed key → `pending` (Phase 3 warning), no answer, so it returns after `accept_new_key`.
  - *invited* → verify the tag against the stored invites (§3.4). Match → delete that invite row; a new contact is pinned with `APPROVED_ME | VERIFIED`; for an existing contact the same key gains the flags, a changed key goes to `pending`. No match → seen and dropped, nothing pinned.
  - *approved* → an existing contact gets `APPROVED_ME`, seen. Unknown (a store was reset) → seen and dropped.
  Answers go out after the loop without the mutex. `sync` returns `SyncResult { letters, contacts_changed, requests }`.
- **Answer a request** (`answer_request(peer, approve)`): peer in `session.requests` (`NotFound`); `/v1/events/answer`; yes → pin with `APPROVED_ME`, return the contact id; no → remove, return an empty id.
- **Create an invite** (`create_invite`): registered (`NotFound`); `s` from the RNG; `/v1/invites` with `SHA-256(a)`; on 201/200 store the sealed row; return the code as bytes; wipe `s` in memory. 429 → `RateLimited`.
- **Open an invite** (`open_invite(code)`): `parse` (`InviteInvalid`); `/v1/invites/open` with `a` (404 → `InviteInvalid`); form, address and fingerprint must match (§3.4), else `InviteMismatch` and nothing stored or sent. Own identity → `Malformed`. **Existing contact:** same key → fine (redeem will set `VERIFIED`); different key → the code-verified bundle goes into that contact's `pending` and `KeyChanged` is returned (Phase 3's warning; after `accept_new_key` the user opens the code again). The verified inviter and `s` are kept in `session.invite`.
- **Register:** `register_request(address)` needs `session.invite` (`InviteInvalid`), computes `a` and the tag (own id, inviter id; zeros for root), builds body v2. `register(signature, attestation)` → 201/200: set the address, pin the inviter with `APPROVED_ME | VERIFIED` (the bundle checked at open), clear the invite. 403 → `InviteInvalid`; 428 → `Refused`.
- **Redeem while registered** (`redeem_invite`): needs a non-root `session.invite`; `/v1/invites/redeem` with `a` and tag → pin (or flag) the inviter with `APPROVED_ME | VERIFIED`.

### 5.4 UniFFI surface (additions; the rest is Phase 3's)

```rust
// BrevError: appended after Environment, so no index moves (D-0067 practice)
NotApproved, RateLimited, InviteInvalid, InviteMismatch,
pub struct Limits { /* + */ pub max_invite: u32 /* 96 */ }
pub struct ContactRow  { /* + */ pub waiting: bool, pub verified: bool }
pub struct ContactInfo { /* + */ pub waiting: bool, pub verified: bool }
pub struct RequestRow  { pub peer: Vec<u8> /* 32 */, pub address: Arc<OpenText>, pub code: Vec<u8> /* 35 */ }
pub struct InviteInfo  { pub root: bool, pub address: Arc<OpenText> /* empty for root */, pub code: Vec<u8> /* 35 or empty */ }
pub struct SyncResult  { pub letters: u32, pub contacts_changed: bool, pub requests: u32 }
impl Brev {
    pub fn create_invite(&self) -> Result<Vec<u8>, BrevError>;                              // network; ≤ 96 ASCII
    pub fn open_invite(&self, code: &[u8], code_len: u32) -> Result<InviteInfo, BrevError>; // network, no token
    pub fn redeem_invite(&self) -> Result<Vec<u8>, BrevError>;                              // network; contact id
    pub fn requests(&self) -> Result<Vec<RequestRow>, BrevError>;                           // no I/O
    pub fn answer_request(&self, peer: Vec<u8>, approve: bool) -> Result<Vec<u8>, BrevError>; // network
    pub fn register(&self, signature: Vec<u8>, attestation: Vec<u8>) -> Result<(), BrevError>; // changed
    pub fn sync(&self) -> Result<SyncResult, BrevError>;                                    // changed
}
```

`open_invite` copies the code out of the borrowed buffer before its request, like `add_contact`. Codes cross as bytes, addresses as `OpenText`. `scripts/ffi-surface.txt` is updated in WP3.

### 5.5 The class-A rule

1. Only letters need class A (`prepare_send`, unchanged). Requests, answers and invites carry no content: gated by the unlock only. `env_class` and the report are unchanged.
2. `pasteboard_disabled` keeps its meaning: at *Send*, no responder in the key window takes copy, cut or paste. `ContactSheet` is a sheet on the main window, so it cannot be open with `ComposeSheet`. If P1 needs a `paste:` action in `ContactField`, the view host proves the probe reports false while `ContactSheet` is key (positive control) and true after it closes.
3. The class stays Swift's own word (§2). The App Attest stub does not change that (§7.2).

## 6. Swift (AppKit only; all contact data drawn in the protected layer)

### 6.1 Screens

- **`UI/ContactSheet.swift`** replaces `AddContactSheet` (hardened like it; the button becomes *Kontakter*). Rows: (1) «Din adresse:» + own address (protected) + *Kopier adressen min*; (2) *Lag invitasjon*, the code (protected, two lines), *Kopier koden*, `invite.note`; (3) «Adresse eller invitasjonskode:» + `ContactField` + *Legg til*: input starting `brev1.` goes to `open_invite`, then shows the inviter (protected) and *Godta invitasjonen* (`redeem_invite`); anything else goes to `add_contact` and shows `request.sent` (or joins the list at once if already approved); (4) the fixed error line.
- **Address page** (unregistered): step 1 the invite code in a `ContactField` (⌘V) + *Fortsett* (`open_invite`), then «Invitert av» with address and code (protected) or `invite.root`; step 2 Phase 3's address field + *Registrer* (Touch ID, unchanged).
- **Requests** (`MailViewController`, `SecureListView`): a section «Forespørsler» above the contacts, rows in the protected layer. Selecting one makes `ContactHeaderView` show address and code (protected), `request.body`, *Godta* and *Avslå* (`HumanButton`s): one click, no Touch ID, no confirm.
- **Contact header:** `contact.waiting` or `contact.verified` beside the code.
- **ComposeSheet:** `NotApproved` → `compose.notapproved`, `RateLimited` → `compose.ratelimited`; the draft stays.
- The 5 s sync reloads the contact pane only when `contacts_changed` or `requests` changed.

### 6.2 Pasteboard (`UI/ContactPasteboard.swift`, the only new `NSPasteboard` file)

- `write(_ bytes: SecretBytes)`: `clearContents`; `declareTypes([.string, ConcealedType, TransientType])`; `setData`; remember `changeCount`. Only two callers: *Kopier adressen min* (bytes of `me().address`) and *Kopier koden* (bytes from `create_invite`). No generic entry point.
- **Self-clear:** after 60 s, or when Brev locks, whichever is first, if `changeCount` is still Brev's own, `clearContents`. Not on sheet close: the user may close the sheet before pasting elsewhere.
- `read() -> [UInt8]?`: `data(forType: .string)`, at most 256 bytes. Called only from `ContactField`. Bytes go through the `.contact` charset filter (a–z, 0–9, `-`, `.`; A–Z folded) into the field's `EditModel`, then are wiped; never a `String`, drawn only in the protected layer.
- `ContactField` is a `SecureComposeView` configuration (one line, 96 units, secure input while focused, synthetic events refused) with ⌘V. **Spike P1** (WP5, human, macOS 26.2): (a) ⌘V handled in `keyDown`, reading directly; (b) a «Rediger» menu with only «Lim inn» (`paste:`), enabled only in `ContactField`. Take (a) if it raises no alert (V15 unchanged, no responder answers `paste:`); else (b), rewrite V15, rely on §5.5.2. If both alert, one alert is accepted and recorded.
- test.sh: `allowed-apis.txt` gains `ContactPasteboard.swift`'s lines only; a grep fails if `ContactPasteboard` appears outside `ContactField.swift`, `ContactSheet.swift`, `AddressViewController.swift` (and the lock hook that clears it); no `copy:`, `cut:`, `selectAll:` anywhere; `paste:` only in `ContactField.swift` (variant b).

### 6.3 Strings (`nb.lproj`; none takes an address, code or name)

| Key | Text |
|---|---|
| `contacts.title` / `.me` / `.copyme` | Kontakter / Din adresse: / Kopier adressen min |
| `invite.make` / `.copy` / `.note` | Lag invitasjon / Kopier koden / Koden kan brukes én gang og gjelder i 7 dager. Send den til én person. |
| `contacts.field` / `.add` | Adresse eller invitasjonskode: / Legg til |
| `invite.from` / `.accept` / `.root` | Invitert av: / Godta invitasjonen / Invitasjon fra Brev-tjenesten. |
| `invite.error.invalid` / `.mismatch` | Invitasjonskoden er ukjent, brukt eller utløpt. / Invitasjonskoden stemmer ikke med nøkkelen tjenesten ga. Ingenting ble lagret. |
| `invite.error.limit` | Du kan ikke lage flere invitasjoner nå. Prøv igjen i morgen. |
| `address.invite.title` / `.body` / `.next` | Lim inn invitasjonen / Du trenger en invitasjonskode fra en som bruker Brev. Lim den inn med ⌘V. / Fortsett |
| `request.sent` | Forespørsel sendt. Du kan skrive når den er godtatt. |
| `requests.title` / `request.body` | Forespørsler / Vil skrive til deg. Godtar du, kan dere skrive til hverandre. |
| `request.accept` / `.decline` | Godta / Avslå |
| `contact.waiting` / `contact.verified` | Venter på svar / Bekreftet med invitasjon |
| `compose.notapproved` / `compose.ratelimited` | Mottakeren har ikke godtatt deg ennå. Brevet ble ikke sendt. / Du har sendt for mange brev i dag. Brevet ble ikke sendt. |
| `request.error.limit` | Du har sendt for mange forespørsler i dag. |

`KeyChanged` from `open_invite` reuses Phase 3's key-change string.

## 7. App Attest stub and IdentityVerifier

### 7.1 App Attest (feature `app-attest` on brev-relay; off by default)

- **Relay:** `gates.rs`: `trait AttestVerifier { fn verify(&self, attestation: &[u8], client_data_hash: &[u8; 32]) -> bool }`. `client_data_hash` is the registration digest, so an attestation binds to this key, address, token and invite. With the feature on, empty or failing → 428 before any write. Phase 4 has only `DevAttest`, which accepts exactly the 16-byte marker `BREV-DEV-ATTEST1`. Feature off: parsed (≤ 8 192 bytes) and ignored.
- **Swift:** `Keys/Attestor.swift`: `protocol Attestor { func attestation(for digest: [UInt8]) -> [UInt8] }` and `NoAttestor` (empty). No `DCAppAttestService` call and no entitlement in Phase 4.
- **Later** (future task, owner then): `AppAttestor` with `DCAppAttestService` (DeviceCheck, approved in §4): `generateKey` once, `attestKey(keyId, clientDataHash: digest)` (contacts Apple). A real `AppleAttestVerifier` must parse CBOR and check an X.509 chain to Apple's App Attest root; those crates are not in §4, so an owner question then. It must accept both App IDs, `AV26DNQ5SC.no.brev.app` and `AV26DNQ5SC.no.brev.app.b` (Brev B), or Brev B must be dropped for real builds. Real attestation objects are about 5–6 KB, under the 8 KiB cap. Open then: which App Attest environment a Developer ID build gets on macOS.

### 7.2 Relation to the environment class

Attestation at registration proves the app was genuine once. The next step would be `generateAssertion` per letter over (envelope digest ‖ SHA-256 of the report), checked by the relay against the attested key: then only genuine Brev code could claim class A. It still would not prove the defences were on, and proves nothing on a Mac that holds the team signing key (§2, D-0062). So §2's class-A line ("until attestation lands …") stays unchanged in Phase 4.

### 7.3 IdentityVerifier (BankID / ID-porten)

`gates.rs`: `trait IdentityVerifier { fn verify(&self, identity: &[u8; 32], evidence: &[u8]) -> bool }` and `DevVerifier` (always true). Called at registration with empty `evidence`; a refusal gives 428. **Future task** (documented, not built): the operator runs an ID-porten/BankID web login outside Brev that hands out a one-time text code; the app pastes it like an invite (no URL scheme, §1.4). Registration v3 carries it; the relay stores only SHA-256(pairwise `sub` ‖ relay salt): one person, one identity. Trade-off for then: the relay would link each identity to a real person.

## 8. Test plan

**brev-proto:** `invite_code_round_trip_and_known_answers` (all-zero id and secret, a real id, root form, 96 bytes at the longest address); `invite_parse_refuses` (no prefix, 3 parts, bad address, non-base32, wrong length, non-zero padding bits, 97 bytes); `base32_decode_inverts_identity_code`; `invite_derivations_known_answers` (`a`, `tag`; the tag changes with either id); `registration_v2_layout` (offsets; v1 domain fails; attestation 0 and 8 192, 8 193 refused); `lookup_reply_status`; `events_answer_parse` (count 33 refused, trailing byte, address rules); `submit_body_prefix`.

**brev-relay** (`tests/relay.rs` updated, new `tests/phase4.rs`; clock via `Config`):
1. `registration_needs_an_invite` (none, unknown, used, expired → 403; root → 201, `invited_by` NULL; Same retry after use → 200; the largest v2 body (address 32, attestation 8 192) goes through the real router, not 413).
2. `registration_does_not_probe_the_directory` (no invite: taken and free addresses both 403; with a valid invite, taken → 409 and the invite still opens).
3. `invite_graph_is_recorded` (A's invite → B's `invited_by` = A; a redeem by an existing C leaves C's).
4. `invites_are_one_time_and_expire` (second registration 403; redeem same caller 200, another 404; day + 8 → 404).
5. **`unapproved_sender_cannot_reach_an_inbox`** (DoD): unapproved sender's valid envelope → 409, `waiting()` unchanged, inbox empty; after request and *Godta* → 202 and delivered; a declined sender → 409, its later requests store no event.
6. `requests_once_per_pair`, `event_answer_rules`, `crossing_requests_approve_each_other`, `request_answers_do_not_reveal_a_decline` (new, pending, declined, over the pending cap: all 202; at the limit all 429), `re_adding_a_declined_peer_unblocks_them` (A declines B, A requests B → 200, a letter B→A → 202).
7. **`letters_are_rate_limited_per_identity_per_day`** (DoD): N → 202, N+1 → 429 and nothing stored; a 200 resubmit and a 409 do not count; another sender unaffected; day + 1 → 202.
8. `requests_are_rate_limited`; `invites_are_capped` (5 open → 6th 429; 3 made today → 4th 429 even after redemptions; next day → 201); `pending_requests_per_recipient_are_capped` (17th → 202, no event); `events_put_invited_and_approved_before_requests` (16 requests pending, an *invited* event still returned first).
9. **`approved_envelope_is_delivered_on_the_next_poll`** (DoD): clock frozen, submit, one `/v1/inbox` returns it; the same at "08:00" and "23:59"; ack deletes.
10. `submit_needs_the_senders_token` (no prefix 400; another caller's token 403; the recipient replaying an acked wire with its own token → 403, the sender's count unchanged).
11. `attestation_gate` (`--features app-attest`: empty 428, marker 201, wrong 428; feature off: empty → 201); `identity_verifier_is_consulted` (refusing verifier → 428, nothing written).
12. `release_deletes_links_events_invites_counts`; `v1_relay_file_is_refused`; `relay_file_holds_no_invite_secret` (byte scan: `s` and `a` absent, `SHA-256(a)` present; Phase 3's plaintext test re-run).

**brev-mail** (`tests/phase4.rs`, two or three sessions, the relay in-process, p256 test signers):
1. **`invite_with_wrong_fingerprint_is_rejected`** (DoD): (a) fingerprint changed in one character, (b) address changed, (c) the relay lies (another bundle in its row for the inviter), (d) a 4-part code answered with `00`. Each → `InviteMismatch`; the request log has no `/v1/register` or `/v1/invites/redeem`; no contact stored.
2. `invite_makes_both_approved_and_verified` (root → A; A invites B; B registers with A `verified`; A's sync pins B `verified`; letters both ways; the A invite row is gone).
3. **`forged_invited_event_is_dropped`**: the relay handle inserts a kind-2 event with a random tag, and one with a real tag but another bundle → A pins nothing; a letter from that identity is dropped by the client rule.
4. **`a_stranger_cannot_reach_an_inbox`** (DoD): C cannot `prepare_send` to A (`NotApproved`, no digest); a forced submit (test hook) → `NotApproved`; A's sync gets nothing.
5. `request_approve_and_decline`; `add_contact_always_requests` (decline then re-add unblocks); `events_are_processed_once` (lost answers → same events next sync, no duplicate contact).
6. `key_change_through_a_request` (release B, B′ with an invite from D requests A → `pending`, no answer; after `accept_new_key` the next sync answers yes); `open_invite_on_existing_contact` (same key → redeem sets `VERIFIED`; different key → `KeyChanged` and `pending` holds the code-verified bundle).
7. `rate_limited_maps_to_error`; `schema_v5` and `v4_store_is_refused`; `flags_and_invites_are_sealed` (swapped rows → `Crypto`; no `s` in the file bytes); `expired_local_invites_are_deleted`; `session_invite_and_requests_cleared_on_lock`; `invite_calls_carry_no_content` (live-plaintext counter 0 at each request).

**Swift harness:** case 9 `invite_round_trip`: test.sh mints a root invite; A registers and invites; B opens (also an edited code → `InviteMismatch`), registers, syncs; marker letter both ways; after lock, 0 heap hits. **View host** `--contacts`: `ContactSheet` hardened; *Kopier*, *Lag invitasjon*, *Godta*, *Avslå* refuse AX presses and synthetic clicks; code, addresses and requests only in the protected layer; pasteboard reads only in `ContactField`; the self-clear after a shortened timer; the `pasteboardDisabled` control (§5.5). **test.sh:** FFI surface; the pasteboard greps; relay started with defaults and a root invite.

**VERIFY rows** (after V70). Rewritten: **V14** (⌘V still inserts nothing in letter and compose views), **V15** (only if P1 takes variant b), **V66** (pasteboard lines of `allowed-apis.txt`: OpaqueView's plus `ContactPasteboard.swift`'s), **V69** (the view host's contacts mode). New:

| # | Check | How | A/H |
|---|---|---|---|
| V71 | Invite onboarding | `brev-relay invite` → Brev registers (1 Touch ID); *Lag invitasjon* → *Kopier koden*; Brev B: ⌘V on the address page shows «Invitert av» (protected), registers; both lists show each other with «Bekreftet med invitasjon» | H |
| V72 | P1: paste without an alert | ⌘V in `ContactField` shows no pasteboard alert; record the variant | H |
| V73 | Pasteboard only on the contact screen | after *Kopier koden*: `.string` + Concealed + Transient; after 60 s the pasteboard is empty; ⌘V in compose and letter pane inserts nothing; `pasteboardDisabled` true at *Send* | H + A |
| V74 | Request and approval | Brev adds Brev B by address → «Venter på svar»; B sees the request (protected), *Godta* one click, no Touch ID; A's next sync clears it; letters flow | H |
| V75 | Decline | *Avslå*; A's *Send* shows `compose.notapproved`, relay count unchanged; A's new request does not appear at B | H + A |
| V76 | Unapproved sender (DoD) | relay test 5 and brev-mail test 4 in test.sh; with `--trace`, a stranger's `/v1/envelopes` → 409 and `sqlite3 relay.db 'select count(*) from envelopes'` unchanged | A |
| V77 | Wrong fingerprint (DoD) | one character of a copied code changed → `invite.error.mismatch`; trace shows `/v1/invites/open` only | H + A |
| V78 | Rate limit | relay with `--letters-per-day 2`: third letter → `compose.ratelimited`, draft kept, count unchanged | H + A |
| V79 | New UI hardened, no contact data in AX or capture | V67 and V68 for `ContactSheet`, the invite step, the requests section and its buttons | A |
| V80 | Relay file | the harness's byte scan over `relay.db*` (`xxd -p` joined, then `grep` the hex): `s`, `a` and the letter marker absent; control: hex of `SHA-256(a)` found | A |

## 9. Work packages (in order; independent first)

| WP | Content | Files | Needs | Done when | Human |
|---|---|---|---|---|---|
| 0 | This design as `docs/PHASE4_DESIGN.md`; VERIFY rows V71–V80 and the rewrites | `docs/PHASE4_DESIGN.md`, `docs/VERIFY.md` | – | reviewed | – |
| 1 | brev-proto: `invite` (format, parse, base32 decode, `a`, `tag`), registration v2, the new bodies, submit prefix, `lookup_reply`, events answer | `brev-proto/src/{lib,body,invite}.rs`, `Cargo.toml` (`hkdf` from the workspace) | – | `cargo test -p brev-proto`; clippy `-D warnings` | – |
| 2 | brev-relay: schema v2, `Config` + clock, §4.3 rules, endpoints, token on submit, `gates.rs` (feature `app-attest`, `DevAttest`, `IdentityVerifier`, `DevVerifier`), CLI `invite`, limit flags, `release`; `scripts/relay.sh` | `brev-relay/**`, `scripts/relay.sh` | 1 | `cargo test -p brev-relay` and `--features app-attest`: tests 1–12 incl. the three DoD tests | – |
| 3 | brev-mail: schema v5 (`flags`, `invites`), §5.3 flows, relay client calls (submit prefix), §5.4 surface and errors, `SyncResult`; `ffi-surface.txt` | `brev-mail/src/**`, `tests/phase{3,4}.rs`, `scripts/ffi-surface.txt` | 1, 2 | `cargo test -p brev-mail` incl. DoD tests; clippy both feature sets. test.sh red until WP4 | – |
| 4 | Swift callers on the new surface: bindings; `Session` (`register` + `NoAttestor`, `SyncResult`, new calls, errors); `ComposeSheet` errors; harness case 9; view host fakes; test.sh | `app/Sources/{Shared,Keys}/*`, `UI/{ComposeSheet,MailViewController}.swift`, `app/Tests/*`, `tools/viewhost/**`, `scripts/{test,gen-bindings}.sh`, `scripts/allowed-apis.txt` | 3 | `scripts/test.sh` green; case 9 passes 5 of 5 | – |
| 5 | UI: `ContactSheet`, `ContactField`, `ContactPasteboard` (with self-clear), address-page invite step, requests section and header buttons, strings; **P1** and the variant; view host contacts mode | `UI/{ContactSheet,ContactField,ContactPasteboard,AddressViewController,ContactHeaderView,MailViewController,SecureListView}.swift`, `App/{L10n,MainMenu}.swift`, `Localizable.strings` | 4 | V72, V73, V79; view host PASS | **yes**: P1 (a paste, maybe a system alert), one registration (Touch ID) |
| 6 | DoD run with Brev and Brev B (`build.sh --instance b` exists): V71, V74–V78, V80, rewritten rows; decision entries; summary; README (root invite) | `docs/*`, `README.md` | 5, Phase 3 WP6 run, Q1–Q7 | every row passes or has an owner-accepted entry | **yes**: 2 onboardings, an unlock per switch, one prompt per letter; about 12 Touch ID |

If the owner picks Q6 (b), *Blokker* is added to WP2 (endpoint), WP3 (flag, call) and WP5 (button), with one relay and one brev-mail test.

## 10. Decision entries to add

Numbered after D-0068. **Collision:** DECISIONS.md reserves the numbers after D-0068 for Phase 3's own WP6 entries (17 topics). If those land first, every number below moves up by 17 (D-0069 → D-0086), in this order. Until then a number here names the topic.

- **D-0069** Owner answers Q1–Q7 and the §2 edits they cause (local-relay line for Phase 4; the approval graph as relay metadata).
- **D-0070** Invite codes: text format, fingerprint = identity code (150 bits), 128-bit `s`, the relay sees only `a` and stores `SHA-256(a)`, the HKDF tag for the inviter's check, one use, 7-day life, root invites, the form/address/fingerprint check before anything is stored.
- **D-0071** Registration v2: `a` and tag in the signed body, domain `brev/v2/register\0`, the unsigned 8 KiB attestation field, the check order (Same → invite → conflict), no directory probe.
- **D-0072** Approval at the relay: `links`, `events` (kinds 2/3 first), requests without text, requests always sent and lifting one's own decline, the 409 at submit, uniform 202 answers, one-click answers without Touch ID, the lookup status byte.
- **D-0073** Relay schema v2, the UTC-day clock, counts, caps, sweeps, `release`; what the relay learns (§4.5).
- **D-0074** Rate limits: values, what counts (202 only), per identity per UTC day, 429 before any write, the sender's token on submit, and what the caps do not stop (§4.4).
- **D-0075** brev-mail schema v5: sealed `flags`, sealed local `invites`; requests and opened invites only in the session; `SyncResult`; event processing, forged-event drop, key-change interplay.
- **D-0076** Phase 4 FFI additions and the four error variants.
- **D-0077** Pasteboard on the contact screen only: one file, two write buttons, Concealed/Transient, self-clear after 60 s or at lock, read on ⌘V only, bytes never `String`; P1 result and variant; `pasteboardDisabled` meaning.
- **D-0078** App Attest stub, why it is a stub, both App IDs later, and its future link to the environment class.
- **D-0079** `IdentityVerifier`/`DevVerifier` and the BankID/ID-porten future task.
- **D-0080** Phase 4 review record (the eleven review findings and what changed, §12) and VERIFY results.

## 11. Residual risks and limits

- **Local relay (Q4):** any same-user program can act as the relay and edit approvals, invites and counts. The guarantees are built and tested, but enforced only once the relay runs elsewhere. The inviter-side tag check (§3.4) holds even against the relay.
- **An invite code is a bearer secret.** Whoever redeems it first becomes a verified, approved contact of the inviter, including an app that reads the general pasteboard in the ≤ 60 s it is there, and anyone on the channel it travels through. Limits: one use, 7 days, 5 open, 3 a day; the inviter sees who redeemed it. Undo only if Q6 (b).
- **Sock puppets:** without real App Attest or BankID, each identity can bring in 3 more a day, so a patient spammer's tree grows. Per-recipient pending cap (16), one-click decline and the operator's view of the graph bound the harm; they do not stop it.
- **Relay metadata (§4.5):** invite graph, approval graph and pending requests are persistent; counts show daily activity.
- **First contact by address is still TOFU** (D-0031); the safety code catches it for people who compare. Invites are verified both ways.
- **Pasteboard alert (P1):** macOS 26 may show a one-time alert on the first paste.
- **Stubs:** any build registers; one person can hold several identities, limited by invites.
- **The relay's clock** decides the day; on a local relay the user can move it.
- **Lookups are not rate-limited:** a registered identity can probe addresses (as in Phase 3). Registration no longer leaks it to outsiders.
- **Unverified here:** P1; the Swift UI with Touch ID; `CFBundleDisplayName` for Brev B.

## 12. Review record (critic findings and what changed)

| # | Finding | Verdict | Change |
|---|---|---|---|
| 1 | Invite cap frees on redeem → unlimited puppets and requests | Confirmed | Daily invites-made cap (kind 3, 3/day) beside the open cap; 16 pending requests per recipient; §4.4 now says what it does not stop |
| 2 | Relay can forge *invited* events / swap the invitee's key | Confirmed (`receive` trusts any contact row; `create_invite` kept nothing) | Relay sees `a`, not `s`; HKDF tag in register/redeem; inviter keeps `s` sealed and pins only on a tag match (§3.4); test brev-mail 3 |
| 3 | Re-adding a declined peer leaves them blocked | Confirmed | `add_contact` always requests; a request lifts the requester's own decline; test relay 6 |
| 4 | Repeat or limited requests reveal a decline | Confirmed | Uniform 202; limit check first for all but "already approved" |
| 5 | Events starve behind 16 old requests | Confirmed | Kinds 2/3 first; answer up to 32; pending cap 16 |
| 6 | Anyone with a signed wire can burn the sender's quota | Confirmed (no token on submit; acked envelopes re-insert) | Submit body `prefix ‖ wire`, caller = sender; test relay 10 |
| 7 | Registration reveals taken addresses | Confirmed (breaks `server.rs` header promise) | Order Same → invite → conflict; test relay 2 |
| 8 | `open_invite` gives up on existing contacts; form not checked | Confirmed | Same key → `VERIFIED` via redeem; different key → `pending` + `KeyChanged`; form must match |
| 9 | 16 KiB attestation exceeds `SMALL_BODY` | Confirmed (16 596 + L) | Attestation capped at 8 KiB; largest body tested through the router |
| 10 | V80 `strings` cannot find binary hashes | Confirmed | Hex byte scan with positive control |
| 11 | Stale HEAD; Brev B App ID; pasteboard exposure | Confirmed | §0 updated to `63fc44f`; §7.1 names both App IDs; self-clear after 60 s or lock; Q6 now recommends (b). Rejected part: clearing on sheet close (breaks paste into another app) |

## 13. Owner questions (product decisions)

1. **Phase order.** Phase 3's DoD run (its WP6, Touch ID with Brev and Brev B; the `--instance b` build now exists) is still open, and §5 says not to start a phase before the previous one is done. (a) Finish Phase 3 WP6 first, then all of Phase 4. (b) Do Phase 4 WP0–WP2 (docs, brev-proto, relay; nothing the Phase 3 run uses) on their own branch now, WP3 onward after Phase 3 is signed off. **Recommended: (b).**
2. **What a contact request carries.** (A) No text: address and safety code only; no new content path, and a spammer's only channel is a 32-character address. (B) A short encrypted note (~200 bytes) drawn like a letter, as Signal's message requests; about one more WP. **Recommended: (A)**, (B) possible later.
3. **Limits.** **Recommended:** per identity per UTC day 50 letters, 10 requests, 3 invites made; 5 open invites; 16 pending requests per recipient; 7-day invite life. Alternatives: stricter (20 / 5 / 1; 3 open) or looser (200 / 20 / 10; 10 open). All are relay flags.
4. **Metadata and the local relay (§2 edits).** (a) Accept a persistent approval graph at the relay (who takes letters from whom, who declined whom) and change §2's "Phase 3 only: the local relay …" to "Phases 3 and 4"; the relay-side guarantees then protect only once the relay runs elsewhere. (b) Enforce approval only in the app: no graph, but the relay stores spam and D-0030's relay-side contact-approval check is not met. **Recommended: (a).**
5. **Does a requester learn a decline?** **Recommended: no** (built as uniform 202; letters show «ikke godtatt ennå»). Alternative: tell the requester.
6. **Removing or blocking an approved contact.** Not in §5; without it an approval, or a stolen invite code, cannot be undone in Phase 4. (a) Defer to Phase 5. (b) Add *Blokker* now: one relay call sets `links(me, them)` declined, a sealed local flag blocks sending and receiving; one endpoint, one flag, one button, two tests. **Recommended: (b)**, because the invite code is a bearer secret on the general pasteboard and same-user agents are in scope (§2).
7. **Touch ID to create an invite?** (a) No: one `HumanButton` click; the invitee's registration is signed and the inviter checks the invitee's tag. (b) Yes: one prompt per invite, and the relay keeps the inviter's signature on the graph edge. **Recommended: (a).**
