# Brev Phase 3: "Real transport" (design)

Status: revised after review, 2026-09-28. Based on branch `claude/laughing-knuth-yhp8ji` at `1873eed` (Phase 2 WP4 review). Inputs: CLAUDE.md (§1 to §6), docs/DECISIONS.md up to **D-0035**, docs/PHASE2_DESIGN.md, `core/`, `app/`, `scripts/`, `tools/`, and 29 review findings (dispositions in §12). The repo was not modified. Scratch root: `P = /private/tmp/claude-503/-Users-andypandy/01f11233-b284-49b2-9c90-391fa2f358ef/scratchpad/p3` (volatile; WP1 copies the spike sources into `tools/verify/spikes/p3/`).

Principle: the simplest thing that meets §5 Phase 3. One relay, loopback only, one IP literal, binary bodies, blocking HTTP, one Touch ID per letter, no third key, no foreign callback, no new crate outside §4.

## 0. What was verified (CLI only: no window, no prompt, nothing bound off 127.0.0.1, repo untouched)

| Proof | Result |
|---|---|
| **p256 verifies Security.framework signatures** (`P/sigspike/main.swift` signs; `P/revise/derchk` verifies) | 550 of 550 verify with `p256` 0.14.0 **as produced**: 400 from a software `SecKey`, **150 from real Secure Enclave keys** (a non-permanent `SecKey` with `kSecAttrTokenIDSecureEnclave`, and a CryptoKit `SecureEnclave.P256` key; `[.privateKeyUsage]` only, `LAContext.interactionNotAllowed`, so no prompt could occur). 300 signed with `.ecdsaSignatureMessageX962SHA256` over the bytes, 250 with `.ecdsaSignatureDigestX962SHA256` over their SHA-256; both verify with `VerifyingKey::verify(bytes)`. A flipped message bit fails all 550 |
| **DER parsing needs no code of ours** | p256 0.14 always enables ecdsa's `der` feature (its `Cargo.toml`: `ecdsa-core … features = ["der"]`), so `Signature::from_der` exists with exactly `default-features = false, features = ["ecdsa"]`. All 550 parse (DER of 69 to 72 bytes) and re-encode byte for byte; 6 of 6 malformed inputs are refused (empty, trailing byte, negative r, non-minimal r, long-form length, r = 0). The draft's hand-written parser is dropped |
| High-S | 267 of 550 (48.5 %) are high-S (Security.framework does not normalise). p256 verifies them unchanged (`NORMALIZE_S = false`); raw r ‖ s round trip (`to_bytes` → `from_slice`) verifies 550 of 550 |
| Enclave signing cost | mean **4.7 ms** per Secure Enclave signature, 1.3 ms software |
| **axum relay + reqwest round trip on 127.0.0.1** (`P/ws/core/brev-relay`, `P/ws/core/brev-core/tests/p3spike.rs`) | Two real `Core`s. register 201, again 200, another identity on the address 409; submit 202, again 200, one flipped ciphertext bit 403, `MAX_WIRE + 1` bytes 413; B polls, verifies, receives, reads the marker; ack 204; next poll empty. Wire 430 bytes for a 256-byte padded payload. (The spike authenticated polls with signatures; §4.2 replaces that with a token. The HTTP path is the same) |
| **Relay file holds no plaintext** | relay SQLite file (plus `-journal`) holds a 32-byte ciphertext slice (positive control) and not the marker; **after the ack the slice is gone from the file** (`secure_delete = ON`) |
| **Sandbox needs `network.client` for loopback** (`P/sandbox/`) | a reqwest probe in a sandboxed, hardened, ad-hoc-signed bundle: without `com.apple.security.network.client` `connect` fails; with it the request reaches the relay |
| **`localhost` is not 127.0.0.1** (`P/critic-security/gai.rs`) | `("localhost", 8787).to_socket_addrs()` gives `[[::1]:8787, 127.0.0.1:8787]` (/etc/hosts lines 7 and 9); hyper-util tries the first family first. So only the literal `127.0.0.1` is allowed (§5.1) |
| **Crate set** (`P/revise/ws/core`: the repo's `core/` plus p256, reqwest, axum, tokio, minus ed25519-dalek) | `Cargo.lock` 123 → **209 packages** (+88 new, −2: ed25519-dalek and ed25519). Normal graphs: brev-core 73 → **150** (the app binary), brev-proto 1 → 33, brev-relay 2 → 75. `cargo tree -d -e normal` per crate: only syn 2/3 twice in brev-core (build-only); brev-proto and brev-relay none. `cargo audit --no-fetch --deny warnings`: **exit 0, 209 crates**, 1271 advisories. `nm -u libbrev_core.a` names no CF/SC/Security symbol (reqwest without `system-proxy`) |
| **rust-version** | reqwest → url → idna → idna_adapter 1.2.2 (declares 1.86) → ICU4X 2.3 crates (declare **1.88**) enter brev-core's graph. brev-proto and brev-relay stay at ≤ 1.85 |
| UniFFI foreign callbacks | `uniffi_core-0.32.2/src/ffi_converter_impls.rs:631-633` panics when a foreign trait throws a non-`BrevError` and no `From<UnexpectedUniFFICallbackError>` exists (critic probe `P/critic/ftpanic`). Phase 3 has **no foreign trait**, so this cannot arise |
| Receive cost | 16 commits of 80 KiB with `fullfsync`: 176 ms in total, at most 12 ms each; p256 verify 0.08 to 0.40 ms (`P/critic/timing`). Hence one mutex hold per envelope (§5.3) |

Limits: CLI processes only. The Touch ID path of the real identity key is not exercised (the spike's Enclave keys have no biometry flag; the signature format is the same). Whether the Touch ID panel makes Brev resign active (Phase 2's U4) is unmeasured; WP5 measures it (§3.2). Side effect: `~/Library/Containers/no.brev.p3spike.{net,nonet}` (28 KB each, empty) were left by the sandbox probe; delete them in Finder.

## 1. Scope

### 1.1 CLAUDE.md §5 Phase 3, line by line

| §5 line | Built by | § / WP |
|---|---|---|
| `brev-relay`: minimal axum server; register identity with an address, look up an address, submit envelope, poll | `brev-relay` lib + bin, §4.1 | §4, WP2 |
| Stores only ciphertext + routing metadata; deletes envelopes after delivery | schema §4.3; the recipient's ack deletes the row | §4.3, WP2 |
| No accounts beyond a public key and its address | `identities`: id, address, two public keys, token hash | §4.3 |
| `RelayTransport` in brev-core (HTTP, polling every N s, no websockets) | `relay.rs` (reqwest blocking); N = 5 s while unlocked | §5, WP3, WP5 |
| Signatures from the Enclave: `sign_request` → Swift signs with Touch ID → `attach_signature` | FFI §5.6; `SignService` in Swift | §3.2, WP3, WP4 |
| Relay verifies P-256 against the registered identity; brev-core verifies on receive (`p256`); Swift never verifies | `brev_proto::sig::verify`, used by both | §3.3 |
| Padding 256 B / 1 KiB / 4 KiB / 16 KiB, then ×16 KiB, length prefix, hard max 1 MiB in app and relay; tests for equal length and boundaries | Phase 2's `pad_into`/`unpad` inside `seal_message`/`open_message`; relay length check | §2.2, WP1, WP3 |
| Contacts by address (D-0031); relay returns keys; TOFU pinning; warning + no sending on a changed key | schema v3 §6.1; `add_contact`, `prepare_send`, `accept_new_key` | §6, WP3, WP5 |
| Identity code (base32 of the public-key hash) shown per contact; comparing optional; no QR, no links | `identity_code` §3.4; contact header | §3.4, §6.5 |
| DoD: two app instances exchange letters through a local relay | bundle-id variant "Brev B" §7 | §7, WP6 |
| DoD: relay DB contains no plaintext (test it) | `relay_file_holds_no_plaintext` (Rust), V58 | §8 |
| DoD: a changed key triggers the warning and blocks sending (test it) | `changed_key_warns_and_blocks_sending` (Rust), V60 | §8 |

### 1.2 Phase 2 items this replaces or closes

| Item | Resolution |
|---|---|
| Echo peers Ekko and Speil (`echo.rs`, `peer-1.db`, `peer-2.db`, `Unsigned`, `send_new`, the echo `sync`) | deleted in WP3; `sync()` talks to the relay; `KeyStore.knownFiles` loses the peer names |
| CLAUDE.md §2: line 61 ("Phase 2 only: the two built-in echo contacts …") and "and the echo stores" in line 57 | owner edit, applied when WP3 lands; `docs/THREAT_MODEL.md` re-synced |
| Tools and rows that assume echo peers or the Phase 2 FFI: `tools/viewhost` (`Session.create` with 65 × `0x04`, `send`, Ekko/Speil), `tools/verify/padcheck.swift` (three stores), `capture-probe.swift` (pane text "Ekko"/"Speil"), `touchid-probe` (`Session.create`), `app/Tests/main.swift` (fake signing key); VERIFY V1, V17, V18, V39, V40, V41, V42 | moved in WP4 (tools) and WP0 (rows), §8 |
| Envelopes unsigned (PHASE2 §1.2) | signed by the identity key, verified by relay and recipient |
| D-0019 `Signer` trait inside `send`, and its only user `ed25519-dalek` (dev-dependency) | replaced by the two-step flow; ed25519-dalek removed from both manifests |
| D-0016 "signing key opaque, 1..=255 bytes" | must be a valid uncompressed P-256 point |
| D-0026 at-most-once (`poll` drains) | ack after store (§5.3) |
| D-0017 key-compromise impersonation (forging letters *to* a party whose X25519 secret leaked) | the recipient now also requires the sender's identity signature |
| Phase 1 "a contact's bundle is trusted as given" | TOFU pin + identity code |

### 1.3 Out of Phase 3

Contact requests and approval, invite codes, rate limits (only the hooks), App Attest, BankID (Phase 4). Letters from people the recipient has not added (dropped, owner Q2). Local nicknames: a contact's name is its address. Copy and paste of addresses (it comes with Phase 4's invite codes on a real contact screen; Phase 3 types addresses). Background key checks (a key is checked at each Send, §6.3). Replies inside a thread, read state, deleting contacts or letters. Notifications: nothing polls while locked. TLS, a remote relay, two Macs over a LAN, websockets. Self-service release of an address. Relay retention sweeps. Sender timestamps and sequence numbers. More than one device per identity. Migration of Phase 2 stores (v2 is refused; reset). Everything in Phase 5.

## 2. Wire format (`brev-proto`)

### 2.1 Envelope on the wire (`POST /v1/envelopes`, `application/octet-stream`)

| Offset | Bytes | Field |
|---|---|---|
| 0 | 4 | `"BREV"` (42 52 45 56) |
| 4 | 2 | `PROTOCOL_VERSION` u16 BE = **1** |
| 6 | 32 | sender identity id |
| 38 | 32 | recipient identity id |
| 70 | 24 | nonce |
| 94 | C | ciphertext = padded payload (P bytes) ‖ 16-byte tag; **P ∈ {256, 1024, 4096, 16384, k·16384 ≤ 1 048 576}** |
| 94 + C | 64 | signature: r ‖ s, 32 bytes each, big-endian, as the signer produced it |

`signed_bytes` = bytes `[0, 94 + C)`: D-0018's layout, unchanged; only the version value moves 0 → 1 (§2.3). Header and signature have fixed lengths, so the parse is unambiguous without a length field. Envelope id (relay dedupe and ack) = SHA-256(`signed_bytes`); it does not cover the signature, so signature malleability changes no key. Sizes: minimum 94 + 272 + 64 = **430** bytes; `MAX_WIRE` = 94 + 1 048 592 + 64 = **1 048 750**.

`from_wire` refuses: length < 430 or > `MAX_WIRE`, wrong magic, version ≠ 1, `C − 16` not a padded length. `to_wire` refuses a signature that is not 64 bytes.

### 2.2 Payload padding

The payload (D-0020: message id 16 ‖ thread id 16 ‖ subject length u16 ‖ subject ‖ body) is padded with Phase 2's functions before encryption: `seal_message` pads with `pad_into` (u32 BE length ‖ content ‖ zeros, exact bucket); `open_message` calls `unpad` on the decrypted buffer. New API, nothing else:

```rust
pub const PROTOCOL_VERSION: u16 = 1;
pub const SIG_LEN: usize = 64;
pub const MAX_CIPHERTEXT: usize = MAX_PADDED + 16;          // 1 048 592
pub const MAX_WIRE: usize = HEADER_LEN + MAX_CIPHERTEXT + SIG_LEN;
pub fn is_padded_len(n: usize) -> bool;                      // n >= 4 && padded_len(n - 4) == Some(n)
```

In practice `MAX_SUBJECT` 256 + `MAX_BODY` 65 536 + 34 gives at most 81 920 padded bytes (5 × 16 KiB). The 1 MiB maximum is enforced in the app by `padded_len` returning `None` (`Malformed`) and in the relay by `from_wire` and axum's `DefaultBodyLimit::max(MAX_WIRE)` (413 before parsing).

### 2.3 Version bump

0 → 1 because the plaintext inside the AEAD changed (padding): a v0 reader would misparse a v1 payload. The version is in the AEAD associated data and in the signed bytes, so a v0 envelope fails everywhere. D-0018 kept 0 while "nothing has been released"; Phase 3 makes the first real wire.

### 2.4 The other bodies (binary, `POST`)

Registration (`/v1/register`), `194 + L` bytes, signed by the **identity** key:

| Offset | Bytes | Field |
|---|---|---|
| 0 | 1 | address length L (3 ..= 32) |
| 1 | L | address, ASCII `[a-z][a-z0-9-]*` (Q3) |
| 1+L | 65 | signing key (identity), SEC1 uncompressed `04 ‖ X ‖ Y` |
| 66+L | 32 | X25519 key |
| 98+L | 32 | SHA-256(relay token) |
| 130+L | 64 | signature over `"brev/v1/register\0"` ‖ bytes `[0, 130+L)` |

Request prefix for `/v1/lookup`, `/v1/inbox`, `/v1/inbox/ack`: 64 bytes = caller's identity id (32) ‖ relay token (32), then the payload: lookup = the address; inbox = empty; ack = n × 32-byte envelope ids, 1 ≤ n ≤ 256.

Responses: lookup 200 = signing key (65) ‖ X25519 (32), 97 bytes; inbox 200 = count u16 BE ‖ count × (length u32 BE ‖ wire envelope), at most 16 envelopes and 4 MiB (always at least one if any waits); ack 204.

## 3. Signatures

### 3.1 Keys and domains

| Secret | Where | Prompt | Used for |
|---|---|---|---|
| Identity key | Enclave `SecKey`, `[.privateKeyUsage, .biometryCurrentSet]` (CLAUDE.md §3.2, unchanged) | Touch ID each use | envelopes (preimage starts `"BREV"` 00 01), registration (`"brev/v1/register\0"`) |
| Relay token | 32 bytes from the OS RNG in `Core::create`, sealed under the DEK in `identity.keys`; the relay keeps only its SHA-256 | none; usable only while unlocked | authenticating lookup, inbox and ack |

The first bytes differ ("BREV" vs "brev"), so no preimage is valid in both domains. No third Enclave key and no change to CLAUDE.md §3.2. Swift signs **digests**: Rust computes SHA-256(preimage), Swift calls `SecKeyCreateSignature(key, .ecdsaSignatureDigestX962SHA256, digest)`. That is the signature `.ecdsaSignatureMessageX962SHA256` gives over the preimage (§0), so what is signed is still `signed_bytes` (D-0018), and 32 bytes cross the FFI instead of up to 1 MiB.

### 3.2 The letter flow across UniFFI (one letter)

No call that takes content does network I/O, and no network call takes content.

0. Swift, queue `no.brev.net`: `brev.prepareSend(contact)` (no content). Rust: gate; read address, pinned bundle and token under the session mutex; release it; token-authenticated lookup at the relay; take the mutex again. A bundle ≠ the pinned one is sealed into `pending` and gives `KeyChanged`. The pinned bundle clears `pending` and sets the **send ticket** to this contact. `Network`/`NotFound` otherwise.
1. Swift, main thread: `digest = brev.signRequest(contact:subject:subjectLen:body:bodyLen:)`. Rust, mutex held, no I/O, milliseconds: gate; `pending` set → `KeyChanged`; ticket ≠ this contact → `Malformed`; consume the ticket; pad and seal the payload, build the envelope without signature, and seal the thread and message columns for storage; keep this `PendingLetter` (ciphertext only, one slot); drop every decrypted value and the X25519 secret, scrub the stack; return SHA-256(`signed_bytes`). Swift wipes its UTF-8 copies right after the call, as Phase 2's `send` does.
2. Swift: note the lock generation; look up the identity key with an `LAContext` (`localizedFallbackTitle = ""`, reason `send.reason`) and sign the digest: **the one Touch ID prompt**. Cancel → `brev.cancelSend()`; the sheet stays open with the draft.
3. Main: `brev.attachSignature(der)`: `Signature::from_der` → raw 64 bytes, **verified against the own signing key from the identity row** (a replaced keychain item gives `Signing`, slot cleared).
4. `no.brev.net`: `brev.submit()`: copy the wire bytes under the mutex, release, POST. 202/200 → take the mutex, insert the pre-sealed thread and message in one transaction, clear the slot, return the thread id. `Network` keeps the signed slot and the sheet shows *Prøv igjen*, which calls `submit()` again (same bytes, relay answers 202 or 200, no second Touch ID). Another 4xx → `Refused`, slot cleared. No signed letter in the slot → `NotFound`.

`lock()` and `cancelSend()` clear the ticket and the slot, signed or not. `sync()` never sends a letter, so only the open sheet can retry. Nothing is stored locally until the relay has the envelope. Accepted edges (§11): a lock while `submit` is on the wire returns `Locked` after the relay stored the letter, so the recipient gets it and the sender has no copy; the same after `Network` if the relay stored it but the answer was lost, followed by *Avbryt*.

Registration uses the same two steps. `register_request(address)` validates the address, builds the body of §2.4 with SHA-256(token), keeps it in the session (cleared on lock) and returns the digest. Swift signs it with Touch ID (`register.reason`). `register(der)` converts and verifies the signature against the own key, then posts. 201/200 seal the address into `identity.address`; 409 gives `AddressTaken`; `Network` keeps the body for a retry without a second prompt.

**The send prompt does not suspend auto-lock.** Phase 2 lets unlock's Touch ID ignore resign-active (`LockState.authInFlight`), because the panel may take activation (U4, unmeasured) and nothing is on screen then. During a send the letter panes and the draft are on screen, so resign-active locks as usual (the slot is cleared, nothing is sent). WP5 measures U4 first with one Touch ID. If the panel itself makes Brev resign active, the fallback is: before the prompt, `ContentView.blankAll()` and the compose view blanks; the exemption then applies during the prompt only; content redraws after. The result goes in D-0041.

### 3.3 Encoding and verification

- Wire: raw r ‖ s, 64 bytes, either S. Both verifiers use p256's default, which accepts high-S. A low-S rule would protect nothing (the envelope id excludes the signature) and would add a failure mode for the 48.5 % of Enclave signatures that are high-S.
- `brev_proto::sig` (one implementation, used by brev-core **and** brev-relay): `verify(sec1_key, msg, sig: &[u8; 64]) -> Result<(), SigError>` = key exactly 65 bytes, first byte 04, on the curve (`VerifyingKey::from_sec1_bytes`, which alone would also take compressed keys), `Signature::from_slice` (refuses r or s = 0 or ≥ n), `VerifyingKey::verify(msg)`. `der_to_raw(der) -> Result<[u8; 64], SigError>` = `Signature::from_der(der)?.to_bytes()`; only brev-core calls it.
- p256 features: `default-features = false, features = ["ecdsa"]`. Production code never builds a `SigningKey`: test signers live in `src/test_keys.rs` (behind `#[cfg(test)]` at the `mod` line) and `tests/`; test.sh greps `core/*/src` for `SigningKey` outside `test_keys.rs`. p256 is "never independently audited" (its README); it only handles public inputs here.
- Receive order in brev-core (extends D-0020). **P** = permanent, the letter is acknowledged and dropped; **L** = local, not acknowledged, fetched again later (§5.3):
  1. addressed to me (`Malformed`, P);
  2. the keyed tag of the sender id (§6.1) finds a contact (`NotFound`, P: stranger);
  3. that contact's bundle opens under its AD and hashes to the sender id (`Corrupt`, L: the local row is damaged or swapped);
  4. **signature over `signed_bytes` with the pinned signing key** (`Crypto`, P);
  5. AEAD (`Crypto`, P); unpad and payload shape (`Malformed`, P);
  6. for a known thread: its subject opens (`Corrupt`, L) and its owner is the sender (`Malformed`, P);
  7. store (`Duplicate` on the message id, P; `Storage`/`Io`, L).

### 3.4 Identity id, bundle, identity code

- The id formula of D-0016 is unchanged (label `"brev/v0/identity"`, length byte 65). It moves to `brev_proto::identity_id` so the relay computes the same id.
- The signing key must be a valid uncompressed P-256 point (65 bytes, 04, on the curve) in `Core::create`, in a lookup answer and in relay registration; anything else is `Malformed` / 400.
- Identity code: RFC 4648 base32 (A–Z, 2–7) of the **first 150 bits** of the identity id, 30 characters in 6 groups of 5, e.g. `ABCDE FGHIJ KLMNO PQRST UVWXY Z2345` (35 ASCII bytes). 150 ≥ 128 bits (D-0016). Hand-written table lookup (not cryptography) with known-answer tests (all-zero id → `AAAAA …`, all-0xFF → `77777 …`, one real id).

### 3.5 Touch ID count

Unlock 1 (unchanged). Registration 1, once per identity. **Each letter 1.** Retrying `submit` 0. Poll, ack, lookup, add contact, key check, accepting a key: 0. The onboarding rule becomes "approve only right after «Lås opp», «Send» or «Registrer»" (§6.6).

## 4. Relay (`brev-relay`: `lib.rs` + thin `main.rs`)

### 4.1 Endpoints

| Path | Auth | Checks | Answers |
|---|---|---|---|
| `POST /v1/register` | identity signature (§2.4) | address rules; key a valid point; signature; policy | 201 new; 200 same identity, address and token hash; 409 address taken, or the identity has another address or token; 400; 401 bad signature |
| `POST /v1/lookup` | token | §4.2 | 200 97-byte bundle; 404 |
| `POST /v1/envelopes` | the envelope's own signature | `from_wire`; sender and recipient registered; `verify` with the sender's registered signing key; policy | 202 stored; 200 already waiting (same id); 400; 403 unknown sender or bad signature; 404 unknown recipient; 413; 429 |
| `POST /v1/inbox` | token | §4.2 | 200 framed envelopes, oldest first; deletes nothing |
| `POST /v1/inbox/ack` | token | 1 ≤ ids ≤ 256; only the caller's envelopes | 204 |
| `GET /v1/health` | none | – | 200 `brev-relay v1` (test.sh waits on it) |

Body limits: `MAX_WIRE` on `/v1/envelopes`, 16 KiB elsewhere. Unknown paths 404; no CORS, no redirects, no TLS in Phase 3.

### 4.2 Authentication

Registration proves possession of the identity key and binds SHA-256(token) to it. Every lookup, inbox and ack starts with id ‖ token; the relay hashes the token and compares it with the stored hash (unknown id or mismatch → 401). Comparing hashes is safe without constant time, because learning the stored hash does not give the token. No clock window and no nonce map: nothing depends on the Mac's clock. A captured token can be replayed; on loopback, capturing it needs root (packet capture) or Brev's memory, both out of scope (§2). D-0018's rule that relay requests need their own signing domain is met by registration, the only other signed body. Signed requests come back with TLS and a remote relay (Phase 4). Submit carries no token: the envelope signature authenticates the sender, and a replayed submit is harmless (§4.3).

### 4.3 Storage (SQLite via `rusqlite`, `bundled`, already in the tree)

```sql
CREATE TABLE identities (
    id          BLOB PRIMARY KEY,         -- identity id (32)
    address     TEXT NOT NULL UNIQUE,     -- routing metadata, the directory (§2)
    signing_key BLOB NOT NULL,            -- 65
    x25519      BLOB NOT NULL,            -- 32
    token_hash  BLOB NOT NULL             -- SHA-256 of the relay token
) STRICT;
CREATE TABLE envelopes (
    seq         INTEGER PRIMARY KEY,      -- arrival order
    id          BLOB NOT NULL UNIQUE,     -- SHA-256(signed_bytes)
    recipient   BLOB NOT NULL,
    wire        BLOB NOT NULL             -- the ciphertext envelope
) STRICT;
CREATE INDEX inbox ON envelopes(recipient, seq);
```

`application_id` "BRLY", `journal_mode = DELETE`, `secure_delete = ON`, `foreign_keys = ON`; the folder is created 0700, the file 0600. **Delete after delivery**: the ack runs `DELETE FROM envelopes WHERE id = ? AND recipient = ?caller`; freed cells are zeroed. No timestamps, no tombstones, no IP addresses, no request log. A submit replayed after delivery is stored and delivered again; the core drops it as `Duplicate` and acks it (already covered by D-0020's dedupe). Nothing expires in Phase 3; `release` deletes waiting envelopes with the identity. Concurrency: one `Mutex<Connection>`, a current-thread tokio runtime.

### 4.4 Hooks for Phase 4

```rust
pub trait Policy: Send + Sync {
    fn register(&self, address: &str) -> Decision;
    fn submit(&self, sender: &[u8; 32], recipient: &[u8; 32], len: usize) -> Decision;
    fn request(&self, caller: &[u8; 32], endpoint: Endpoint) -> Decision;
}
pub enum Decision { Allow, Deny }   // Deny → 429, after authentication, before any write
pub struct Open;                    // Phase 3: allows everything
```

### 4.5 Running it

`scripts/relay.sh` = `cargo run --release -p brev-relay -- serve --db "$HOME/Library/Application Support/brev-relay/relay.db" --listen 127.0.0.1:8787`. `serve` refuses any `--listen` other than `127.0.0.1:<port>`, can write the bound port to `--port-file` (tests use port 0), and with `--trace` prints one stdout line per request (path and status only; for V63/V64, never stored). Operator command: `brev-relay release --db <path> <address>` deletes that identity and its waiting envelopes (Q3). Arguments parsed by hand; `main` returns `ExitCode` (no `anyhow`). If the owner picks Q1 (B), `relay.sh` runs it as `_brevrelay` (§11).

### 4.6 Relay tests (`core/brev-relay/tests/relay.rs`, in-process on 127.0.0.1:0, p256 test signers)

`register_rules` (charset, length, first letter, taken, idempotent, a second address or another token for one identity, bad signature, compressed or off-curve key); `requests_need_the_token` (unknown id, wrong token, another identity's token → 401); `submit_checks` (unknown sender, unknown recipient, bad signature, a high-S signature is accepted, version 0, a length not in a bucket, `MAX_WIRE` accepted, `MAX_WIRE + 1` → 413); `inbox_and_ack` (only own envelopes; an ack of another recipient's id deletes nothing; oldest first; 16 / 4 MiB caps); `ack_deletes_bytes_from_the_file` (ciphertext slice present, then absent; a resubmit after the ack is 202); `policy_hook_denies_before_writing`; `release_frees_an_address`; `listen_refuses_anything_but_127_0_0_1` (`0.0.0.0`, `[::1]`, `localhost`, a LAN address).

## 5. RelayTransport in brev-core

### 5.1 Client

`core/brev-core/src/relay.rs`: one `reqwest::blocking::Client` per `Brev`, with `no_proxy()`, `redirect(Policy::none())`, `connect_timeout(3 s)`, `timeout(15 s)`; crate features `default-features = false, features = ["blocking"]` (no TLS, no system proxy, no JSON). Responses are read through `Read::take` with caps (inbox 4 MiB + `MAX_WIRE` + 66, lookup 97, others 0) and parsed strictly. The relay URL comes from Swift (Info.plist `BrevRelayURL`, build setting `BREV_RELAY_URL`, default `http://127.0.0.1:8787`) and must be exactly `http://127.0.0.1:<port>` (`Malformed` otherwise). An IP literal means no resolver runs, so no other local process can take the relay's place on `[::1]` (§0), and no build can send metadata off the Mac over plain HTTP. Only ciphertext, public data and the token pass through reqwest; the zeroing allocator covers its frees. `Transport` (CLAUDE.md §3.1, updated in WP3) becomes `send(&Envelope) -> Result<(), NetError>`, `poll() -> Result<Vec<Envelope>, NetError>` (deletes nothing), `ack(&[[u8; 32]]) -> Result<(), NetError>`. `MockTransport` stays for the Phase 1 tests (poll no longer drains; ack removes). `Core::receive_all` is removed; the loop is `sync` (§5.3).

### 5.2 Rules: no network under the session mutex, no content during network

`Brev { s: Mutex<Session>, net: RelayTransport }`. Every network call runs with the session mutex released, so `lock()` on the main thread never waits for a timeout. The calls that take letter content (`sign_request`) or a typed address for signing (`register_request`) do no I/O; `add_contact` copies the typed address into its own buffer before its lookup, so no Swift buffer is borrowed during I/O. Pattern: take the mutex, read what is needed (gated: `Locked` while locked, so a locked Brev makes no request), copy the token into a `Zeroizing` buffer, release, do the request, take the mutex again to store. A lock in between makes the second step return `Locked`: nothing is stored or acknowledged.

### 5.3 `sync()`: poll → store → ack

1. Mutex: gate; no registered address → `NotFound` without a request; copy id and token; release.
2. `poll` without the mutex.
3. Per envelope: take the mutex; locked → stop (the rest stay at the relay); `receive`; classify by §3.3 (P → ack, L → not acked; stored → ack); release. `lock()` waits for at most one envelope's commit (≤ 12 ms, §0), and nothing is decrypted after it.
4. Mutex: gate (locked → no ack; the letters come again and give `Duplicate`); release; `ack`. A lost ack means a redelivery, acked then.

Delivery is at least once to the core and exactly once into the store (message-id dedupe). A damaged local row costs no letter: it stays at the relay until the row is fixed or the store is reset. Swift runs `sync()` on the serial queue `no.brev.net` every **5 s** while unlocked and registered, once right after unlock, and once after a letter is sent; a sync still running skips the next tick; errors are logged by variant name once per change of state.

### 5.4 Errors

`BrevError` gains unit variants `KeyChanged`, `AddressTaken`, `Network` (connect, timeout, 5xx, a malformed answer) and `Refused` (another 4xx). `NotFound` also means "no such address" and "no letter to submit". No variant carries text (D-0025).

### 5.5 Sandbox and App Transport Security

Add `com.apple.security.network.client` (proven necessary in §0); never `network.server`. ATS governs the URL loading system (`URLSession`, CFNetwork); reqwest uses BSD sockets, so no `NSAppTransportSecurity` key is added. The forbidden-API grep gains `URLSession` and `NSURLConnection`, so Swift never opens a second, ATS-governed path.

### 5.6 FFI surface (exact; everything not listed is unchanged from PHASE2 §2.2)

```rust
#[derive(uniffi::Error)] pub enum BrevError { Locked, WrongKey, Crypto, NotFound, Duplicate, Malformed, Corrupt,
    Signing, Rng, Io, Storage, KeyChanged, AddressTaken, Network, Refused }

#[derive(uniffi::Record)] pub struct Limits { pub max_subject: u32, pub max_body: u32, pub chunk: u32, pub max_address: u32 }
#[derive(uniffi::Record)] pub struct ContactRow { pub id: Vec<u8> /* 16, local */, pub name: Arc<OpenText> /* the address */, pub key_changed: bool }
#[derive(uniffi::Record)] pub struct ContactInfo { pub address: Arc<OpenText>, pub code: Vec<u8> /* 35 ASCII */, pub new_code: Vec<u8> /* 35 or empty */ }
#[derive(uniffi::Record)] pub struct MeInfo { pub registered: bool, pub address: Arc<OpenText> /* empty until registered */, pub code: Vec<u8> }
// ThreadRow.contact is now the 16-byte local contact id.

#[uniffi::export] impl Brev {
    #[uniffi::constructor] pub fn create(dir: String, relay: String, dek: &[u8], signing_key: &[u8]) -> Result<Arc<Brev>, BrevError>;
    #[uniffi::constructor] pub fn open(dir: String, relay: String) -> Result<Arc<Brev>, BrevError>;
    // unlock, lock, is_locked, contacts, threads, messages, open_body: unchanged
    pub fn me(&self) -> Result<MeInfo, BrevError>;
    pub fn register_request(&self, address: &[u8], address_len: u32) -> Result<Vec<u8>, BrevError>;  // digest; no I/O
    pub fn register(&self, signature: Vec<u8>) -> Result<(), BrevError>;                               // network
    pub fn add_contact(&self, address: &[u8], address_len: u32) -> Result<Vec<u8>, BrevError>;       // network; contact id
    pub fn contact_info(&self, contact: Vec<u8>) -> Result<ContactInfo, BrevError>;
    pub fn accept_new_key(&self, contact: Vec<u8>, new_code: Vec<u8>) -> Result<(), BrevError>;
    pub fn prepare_send(&self, contact: Vec<u8>) -> Result<(), BrevError>;                             // network; no content
    pub fn sign_request(&self, contact: Vec<u8>, subject: &[u8], subject_len: u32,
                        body: &[u8], body_len: u32) -> Result<Vec<u8>, BrevError>;                  // digest; no I/O
    pub fn attach_signature(&self, signature: Vec<u8>) -> Result<(), BrevError>;
    pub fn submit(&self) -> Result<Vec<u8>, BrevError>;                                               // network; thread id
    pub fn cancel_send(&self);
    pub fn sync(&self) -> Result<u32, BrevError>;                                                      // network; letters arrived
}
```

`add_contact` copies the address out of the borrowed buffer into a `Zeroizing` value before its lookup, so no Swift buffer is borrowed during I/O; Swift wipes its copy when the call returns. `send_new` is removed. Addresses cross as bytes or `OpenText`, never `String`. The FFI surface check in test.sh allows `create(dir: String, relay: String, …)` and `open(dir: String, relay: String, …)` and adds the two `FfiConverterString.lower(relay)` lines to its known list. There is no foreign trait (§0).

## 6. Contacts by address with TOFU pinning

### 6.1 Schema v3 (`SCHEMA_VERSION = 3`; a v2 store opens as `Corrupt`; v2 stores hold only echo letters)

```sql
CREATE TABLE identity (
    id         BLOB PRIMARY KEY,           -- pt: own identity id
    keys       BLOB NOT NULL,              -- ct: X25519 secret || X25519 public || signing key (65) || relay token (32)
    address    BLOB NOT NULL               -- ct: own address; empty until registered
) STRICT;
CREATE TABLE contacts (
    id         BLOB PRIMARY KEY,           -- pt: 16 random bytes, local; kept when the key changes
    tag        BLOB NOT NULL UNIQUE,       -- pt: keyed tag of the pinned identity id (finds the sender)
    bundle     BLOB NOT NULL,              -- ct: pinned bundle
    address    BLOB NOT NULL,              -- ct: the address, also shown as the name
    pending    BLOB NOT NULL               -- ct: empty, or the other bundle the relay returned
) STRICT;
CREATE TABLE threads (
    id         BLOB PRIMARY KEY,           -- pt: 16 random bytes, shared with peer
    contact_id BLOB NOT NULL REFERENCES contacts(id),
    created_at INTEGER NOT NULL,           -- pt: unix seconds
    subject    BLOB NOT NULL               -- ct
) STRICT;
-- messages: unchanged from v2
CREATE INDEX messages_by_thread ON messages(thread_id, created_at);
```

- `tag` = HKDF-SHA256(ikm = DEK, no salt, info = `"brev/v1/contact-tag"` ‖ identity id), 32 bytes (hkdf is approved; Phase 2 already derives from the DEK this way). A reader of `brev.db` sees neither a contact's identity id nor its address, so it cannot join the file with the relay's directory.
- AD bindings (D-0021) use the **local** id: `contacts.{bundle,address,pending}` → local id; `identity.address` and `identity.keys` → own id; subject and body as before with the local contact id. The identity id is in no AD, so accepting a key updates one row instead of re-encrypting the history.
- After opening a bundle, brev-core checks that its id's tag equals the row's `tag` (`Corrupt` otherwise), so swapping values between rows is caught.
- `pending` is always sealed (an empty value pads to 256 bytes too), so the file shows no "key changed" flag.

### 6.2 Adding a contact

`add_contact(address)`: the address is typed in a `SecureComposeView` and passed like content. Normalise (ASCII lowercase) and validate; refuse the own address (`Malformed`); open the existing contacts' addresses and refuse a known one (`Duplicate`: a changed key goes through §6.3, never around it); lookup (`NotFound`, `Network`); validate the bundle; insert id = 16 random bytes, `tag`, `bundle`, `address`, `pending` = empty (`UNIQUE(tag)`: the same identity twice is `Duplicate`). That first answer is pinned (TOFU; D-0031 accepts that a lying relay is detectable only by comparing codes at first contact; in Phase 3 see Q1).

### 6.3 Key change: detect, warn, block, accept

- **Detect** in `prepare_send`, i.e. at every *Send* and nowhere else. No lookup when a contact is selected, so the relay does not see which conversation is open.
- **Block**: `sign_request` returns `KeyChanged` while `pending` is set, before sealing anything; no envelope is made, signed or sent. `ContactRow.key_changed` is true; *Nytt brev* is disabled for that contact.
- **Warn**: the contact header shows the warning (fixed text) and the old and new identity codes (`ContactInfo.code`, `new_code`), drawn in the protected layer.
- **Accept**: *Godta ny kode* → `ConfirmSheet` (fixed text) → `accept_new_key(contact, new_code)`, where `new_code` is the code the header is showing. Rust refuses with `KeyChanged` unless it equals the code of the current `pending`, so a relay that swaps the pending key between showing and accepting is caught. One transaction sets `tag`, `bundle` = pending, `pending` = empty; `UNIQUE(tag)` refuses a bundle that belongs to another contact (`Duplicate`). Old threads stay with the contact.
- Letters from the new key that arrive before acceptance come from an unknown identity and are dropped like a stranger's (Q2).

### 6.4 Contact data is content in the UI

Phase 2 treats names as content (§1.5, PHASE2 §2.2). In Phase 3 the name is the address, so addresses, the own address and identity codes are drawn **only** in protected `ContentView`s (the capture-protected layer), never through `L10n`, `InterfaceText` or the accessibility tree. Addresses cross the FFI as `OpenText` (closed on lock); codes as 35-byte `Vec<u8>`, which Swift keeps in `SecretBytes` and wipes on lock. No `Localizable.strings` entry has an address or code argument. The relay's directory necessarily holds addresses in clear (D-0031); that is routing metadata at the relay, not in the app.

### 6.5 UI (AppKit only; nothing new in SwiftUI; no pasteboard)

- **Address page** (`UI/AddressViewController.swift`): shown after unlock while `me().registered` is false (onboarding and a later retry). Fixed text, one single-line `SecureComposeView` (32 units; A–Z lowercased; anything but `a–z 0–9 -` beeps), *Registrer* (`HumanButton`). Flow: `registerRequest` → Touch ID (`register.reason`) → `register`.
- **Mail bar**: *Nytt brev*, *Legg til kontakt*, *Lås*.
- **Legg til kontakt** (`UI/AddContactSheet.swift`, hardened sheet like ComposeSheet): the same key-only field, *Avbryt*, *Legg til*. On success the list reloads with the new contact selected.
- **Contact header** (`UI/ContactHeaderView.swift`, above the thread and letter panes): fixed labels (InterfaceText) beside a protected ContentView that draws the own address and code on line 1 and the selected contact's address and code on line 2. With `key_changed`: `contact.changed`, the new code (protected) and a *Godta ny kode* `HumanButton`.
- **Compose sheet**: *Send* → "Sender …" (buttons disabled) → `prepareSend` (net) → `signRequest` (main) → Touch ID → `attachSignature` → `submit` (net) → close. `KeyChanged` shows `compose.keychanged` and keeps the sheet; `Network` after signing shows *Prøv igjen* (`submit()` only); Touch ID *Avbryt* returns to editing.
- **Sync**: `MailViewController`'s timer (5 s, common modes) dispatches to `no.brev.net`; results return to main; arrivals reload the panes as today.
- Every new sheet and button follows Phase 2's rules: sheets inherit `sharingType = .none`; `HumanButton` refuses AX presses and synthetic clicks (V67 checks).

### 6.6 Strings (`nb.lproj/Localizable.strings`; none takes an address, name or code)

| Key | Text |
|---|---|
| `address.title` / `.body` | Velg adressen din / Andre legger deg til med denne adressen. 3–32 tegn: a–z, 0–9 og bindestrek. Den kan ikke endres senere. |
| `address.register` / `register.reason` | Registrer / registrere adressen din |
| `address.error.taken` / `.invalid` | Adressen er tatt. Velg en annen. / Adressen kan bare ha a–z, 0–9 og bindestrek, og må begynne med en bokstav. |
| `net.error` | Fikk ikke kontakt med Brev-tjenesten. Prøv igjen. |
| `mail.addcontact` | Legg til kontakt |
| `contact.title` / `.field` / `.add` | Legg til kontakt / Adresse: / Legg til |
| `contact.error.notfound` / `.duplicate` / `.self` | Fant ingen med denne adressen. / Denne adressen er allerede en kontakt. / Dette er din egen adresse. |
| `header.me` / `header.code` | Du: / Sikkerhetskode: |
| `contact.changed` | Sikkerhetskoden til denne kontakten er endret. Brev blir ikke sendt før du godtar den nye koden. |
| `contact.newcode` / `contact.accept` | Ny kode: / Godta ny kode |
| `accept.confirm.title` / `.body` / `.ok` | Godta ny sikkerhetskode? / Gjør dette bare hvis du vet hvorfor koden er endret, for eksempel at kontakten har satt opp Brev på nytt. Sammenlign gjerne den nye koden med kontakten først. / Godta |
| `send.reason` / `compose.sending` | sende brevet / Sender … |
| `compose.keychanged` / `compose.retry` | Sikkerhetskoden til mottakeren er endret. Brevet ble ikke sendt. / Prøv igjen |
| `onboarding.rules.prompt` (changed) | Godkjenn Touch ID bare rett etter at du selv har trykket «Lås opp», «Send» eller «Registrer» i Brev. Ber noe annet om Touch ID for Brev, trykk Avbryt. |

## 7. Two app instances on one Mac (DoD)

Container, data folder, `.lock` and keychain items all follow from the bundle id, so the second instance is the same code built with **`PRODUCT_BUNDLE_IDENTIFIER=no.brev.app.b`, `PRODUCT_NAME="Brev B"`** (`scripts/build.sh --instance b`, derived data in `app/build-b`). Three small changes, none of which changes anything for `no.brev.app`:

1. `project.yml` entitlement `keychain-access-groups: $(AppIdentifierPrefix)$(PRODUCT_BUNDLE_IDENTIFIER)` (today the literal `…no.brev.app`, the same value for Brev).
2. `KeyStore.accessGroup = "AV26DNQ5SC." + Bundle.main.bundleIdentifier` (the bundle id is covered by the code signature).
3. `project.yml` `CFBundleName: $(PRODUCT_NAME)` and `CFBundleDisplayName: $(PRODUCT_NAME)` (today the literal `Brev`), so the Touch ID dialogs and the Dock say «Brev B». `menu.app.title` and `window.main.title` stay "Brev"; the dialog name is what tells the two apart.

Result: Brev B has its own container, `.lock`, Enclave keys and wrapped DEK in group `AV26DNQ5SC.no.brev.app.b`. Both talk to the one relay on 127.0.0.1:8787. Switching between them locks the one left (by design), so each switch costs an unlock, and a letter shows up on the recipient's first sync after unlock. The key-change run resets Brev B with V38's method (quit, move `brev.db` out, launch, *Slett alt og start på nytt*). The first build registers the App ID `no.brev.app.b` in team AV26DNQ5SC through automatic signing (Q4). Rejected: `open -n` of the same app (same container and keychain; `.lock` refuses it) and a runtime profile switch (LaunchGuard forbids argument and environment inputs). Fallback without a second App ID: a second macOS user account runs the same Brev.app, at the cost of a user switch per step.

## 8. Test plan

**brev-proto** (unit): `wire_round_trip_and_layout` (offsets of §2.1, version bytes 00 01); `from_wire_refuses` (each rule); `padded_lengths_only` (`is_padded_len` true exactly on the bucket set up to 1 MiB); `verify_rules` (good; flipped message; flipped signature; a high-S signature as produced verifies; wrong key; r = 0 and s ≥ n refused; 64-byte, compressed and off-curve keys `Malformed`); `der_to_raw` (**four committed vectors from the Swift spike**: software low-S, software high-S, Enclave, a 69-byte DER; the six malformed inputs of §0); `registration_and_request_encodings`; `identity_code_known_answers`; `identity_id_matches_d0016`.

**brev-core** (unit, `cfg(test)` hooks): `envelope_payload_is_padded` (subject/body sizes in one bucket give **equal ciphertext lengths**; payload sizes 0, 252, 253, 1020, 1021, 4092, 4093, 16380, 16381 and `MAX_PADDED − 4` give bucket + 16; `MAX_PADDED − 3` gives `Malformed`); `receive_verifies_before_decrypting` (bad signature → `Crypto`, the AEAD is never called (counter), nothing stored); `local_row_failures_are_corrupt` (a swapped `tag` or a damaged `bundle` → `Corrupt`, classified L); `attach_refuses_foreign_signature` (other key → `Signing`; a high-S DER is accepted); `sign_request_needs_a_fresh_prepare` (no ticket → `Malformed`; the ticket is used once; `lock` and `cancel_send` clear it); `sign_request_and_register_request_make_no_request` (a counting relay sees 0 requests during them); `lock_and_cancel_clear_the_pending_letter` (signed or not); `nothing_decrypted_is_alive_on_the_network` (live `Plaintext` and secret counters are 0 at every request, via the counting relay); `accept_is_bound_to_the_shown_code`; `store_holds_no_contact_id_or_address` (scan `brev.db`: no contact identity id bytes, no address marker; control: the own id is found); `schema_v3_pragmas`; `v2_store_is_refused`; `column_ad_uses_local_contact_id`; the Phase 1 and 2 tests moved to P-256 test keys, 16-byte contact ids and `sync`.

**brev-core end to end** (`tests/phase3.rs`: two `Brev` sessions in temp dirs, the relay in-process on 127.0.0.1:0, p256 test signers, the FFI API exactly as Swift uses it):
1. `two_sessions_exchange_letters_through_the_relay` (register, add each other, A→B and B→A, bodies read back, codes match).
2. `relay_file_holds_no_plaintext` (**DoD**): markers as subject and body; after the exchange, `relay.db` and any `-journal` contain no marker in UTF-8 or UTF-16LE; positive controls: both registered addresses (the directory) and a ciphertext slice are found before the ack; the slice is gone after it.
3. `changed_key_warns_and_blocks_sending` (**DoD**): `release` B's address, a fresh B′ registers it; A's `prepare_send` gives `KeyChanged`; `contacts()` shows `key_changed`; `contact_info` gives `new_code` ≠ `code`; `sign_request` gives `KeyChanged` and the relay's envelope count is unchanged; `accept_new_key` with another code gives `KeyChanged`; with `new_code` it succeeds, and after B′ adds A a letter reaches B′.
4. `ack_after_store` (lock between poll and store: nothing acked, the letter arrives after unlock; a dropped ack answer: redelivery is `Duplicate` and then acked; a tampered contact row: not acked, the letter stays at the relay; exactly one stored message).
5. `submit_retry_is_idempotent` (relay stopped: `Network`, slot kept; relay back: `submit` stores one message; no second digest asked for; `sync` in between does not send it).
6. `locked_session_makes_no_request` (a counting relay policy sees 0 requests while locked, including a sync that was polling when `lock` came: no ack follows).
7. `strangers_are_dropped_and_acked`.

**Relay**: §4.6. **Swift harness** (`app/Tests`, CLI, `MallocScribble=1` as today): case 8 `network_round_trip` (case 7 is the scribble probe of Phase 2's review round 1, D-0063). test.sh builds `brev-relay`, starts it on 127.0.0.1:0 with `--port-file`, waits on `/v1/health`, runs the harness with the URL, stops the relay in a `trap`. Two `Brev` sessions with software `SecKey`s (non-permanent, no keychain) and `Enclave.sign(digest:key:)` from `Shared/`, the code the app uses (key lookup injected; `SignService` in `Keys/` only adds the keychain lookup and Touch ID). A registers and sends a marker letter; B syncs and reads it; after wipe and lock, **0 UTF-8/UTF-16/glyph hits** (positive control while open). **test.sh**: FFI surface list; `SigningKey` grep; forbidden APIs + `URLSession`, `NSURLConnection`; `NSPasteboard` stays forbidden with no new allow-list line; `cargo tree -p brev-core` must show p256 and reqwest with exactly the features of §3.3 and §5.1; relay start/stop around the harness.

**VERIFY rows** (after V52; A = CLI, H = human). Rewritten: **V1** entitlements also list `network.client`; **V17** markers include a contact address marker, no Ekko/Speil; **V18** one store; **V26** no prompt without «Lås opp», «Send» or «Registrer»; **V40** `$D` holds `.lock`, `biometry.state` and `brev.db`; **V41** unchanged text, re-run; **V39** replaced by V65; **V42** retired (V57); capture-probe's expected pane text becomes the contact address marker. New:

| # | Check | How | A/H |
|---|---|---|---|
| V53 | Entitlements | `codesign -d --entitlements`: `app-sandbox`, `network.client`, group `AV26DNQ5SC.no.brev.app`; no `network.server` | A |
| V54 | Loopback only | `lsof -nP -iTCP -a -p <Brev>`: only 127.0.0.1:8787; `lsof -nP -iTCP -sTCP:LISTEN`: brev-relay on 127.0.0.1 only; Brev listens nowhere | A |
| V55 | Registration prompt | exactly one dialog, «Brev» … registrere adressen din, no password button | H |
| V56 | One prompt per letter | one dialog per *Send*, «… sende brevet»; *Avbryt* keeps the draft, relay count unchanged | H + A |
| V57 | Two instances exchange letters (replaces V42) | Brev and Brev B (§7): both directions arrive on the recipient's first sync after unlock; Brev B's dialog says «Brev B»; separate containers and keychain groups | H |
| V58 | Relay DB has no plaintext (DoD) | `strings -a` and a UTF-16LE grep of `relay.db*` after V57 with the marker letter: absent; control: both addresses found | A |
| V59 | Deleted after delivery | `sqlite3 relay.db 'select count(*) from envelopes'` = 0 once both have synced | A |
| V60 | Key change (DoD) | reset Brev B (V38), `brev-relay release`, B registers the same address again; in Brev: *Send* shows `compose.keychanged`, relay count unchanged, header shows the warning and both codes, *Nytt brev* disabled; after *Godta ny kode* a letter arrives in B | H + A |
| V61 | Codes match | the code Brev shows for B equals the own code in Brev B's header | H |
| V62 | App switch during the send prompt | ⌘-Tab while the send dialog is up: Brev locks; nothing sent (relay count unchanged) | H + A |
| V63 | Relay down | stop the relay: `sync failed: Network` logged once, not every 5 s; *Send* shows `net.error` and keeps the draft; after restart *Prøv igjen* sends once, no second Touch ID | H + A |
| V64 | No requests while locked | relay with `--trace`: no line while Brev is locked | A |
| V65 | Heap residue with the network | V39 rewritten: on the Verify build the marker letter comes from Brev B over the relay; after lock `selfscan u8=0 u16=0 glyph=0`, with V39's control line | H + A |
| V66 | No ATS, no URLSession, no pasteboard | `plutil -p Info.plist` has no `NSAppTransportSecurity`; `nm -u Brev` has no `NSURLSession`; the forbidden-API grep passes with `allowed-apis.txt`'s pasteboard lines unchanged (only OpaqueView's Services override) | A |
| V67 | New controls | V9 (window exclusion) on the address page, AddContactSheet and the accept ConfirmSheet; V13 (AX press refused) on *Registrer*, *Legg til*, *Godta ny kode* | A |
| V68 | No contact data in AX or capture | with a contact whose address is a marker: V11's AX dump has neither the marker nor any code; V5–V7 capture shows the header blank | A |

## 9. Work packages (in order; cut at compile boundaries)

Q1 to Q4 block nothing before WP6. Address rules live in one constant set so Q3 can change them; Q2 is one branch in `sync`'s classification.

| WP | Content | Files | Needs | Done when | Human |
|---|---|---|---|---|---|
| 0 | VERIFY rows (new and rewritten, §8); this design as `docs/PHASE3_DESIGN.md` | `docs/VERIFY.md`, `docs/PHASE3_DESIGN.md` | – | reviewed | – |
| 1 | brev-proto: version 1, wire, `is_padded_len`, `sig` (verify, `der_to_raw` via `from_der`), `identity_id`, registration and request encodings, identity code; workspace deps p256, reqwest, axum, tokio; spike sources to `tools/verify/spikes/p3/` | `core/Cargo.toml`, `brev-proto/**` | 0 | `cargo test -p brev-proto`; clippy `-D warnings`; `cargo tree -d` as in §0; `cargo audit --deny warnings` exit 0 | – |
| 2 | brev-relay: lib + bin, schema, endpoints, token check, policy, `serve`/`release`, `scripts/relay.sh` | `brev-relay/**`, `scripts/relay.sh` | 1 | `cargo test -p brev-relay` (§4.6); clippy | – |
| 3 | brev-core, store and FFI together: schema v3 with `tag`, payload padding, verify on receive, P/L split, P-256 key validation, `relay.rs`, the §5.6 surface, ticket and pending letter, `sync`; delete `echo.rs`, `Unsigned`, `Signer`, `receive_all`; remove ed25519-dalek; brev-core `rust-version = "1.88"`; CLAUDE.md §3.1 Transport text; proposed §2 edit for the owner | `brev-core/src/**`, `brev-core/Cargo.toml`, `core/Cargo.toml`, `tests/phase{1,2,3}.rs`, `CLAUDE.md` §3.1 | 1, 2 | `cargo test -p brev-core` including both DoD tests; clippy; Cargo.lock 209. **test.sh is red from here until WP4** (Swift callers) | owner applies the §2 echo edits |
| 4 | Every Swift caller and tool moved to the new surface, one package: bindings regenerated (patch step unchanged, verified); `Session`, `UnlockService` (relay URL), `KeyStore` (access group from bundle id, no peer files), `Enclave.sign(digest:key:)` in `Shared/`, `SignService`, `ComposeSheet` three-step send, `MailViewController` sync on `no.brev.net`; `network.client`, `BrevRelayURL`; `tools/viewhost`, `tools/verify/{padcheck,capture-probe,touchid-probe}`, `app/Tests` real P-256 software key and case 8; test.sh changes | `scripts/{test,gen-bindings}.sh`, `scripts/allowed-apis.txt`, `app/Sources/{Shared,Keys}/*`, `UI/{ComposeSheet,MailViewController}.swift`, `project.yml`, `Brev.entitlements`, `app/Tests/*`, `tools/**` | 3 | `scripts/test.sh` green on this Mac; case 8 passes 5 of 5; V53, V66 | – |
| 5 | New screens: address page and routing after unlock, AddContactSheet, ContactHeaderView (protected), accept ConfirmSheet, mail bar, strings including the onboarding rule; measure U4 (Touch ID panel and resign-active) and apply §3.2's rule | `UI/{AddressViewController,AddContactSheet,ContactHeaderView,MailViewController}.swift`, `App/RootViewController.swift`, `App/L10n.swift`, `Localizable.strings` | 4 | V55, V56, V61, V62, V63, V67, V68 | **yes** (Touch ID: U4 measurement, registration, a few letters) |
| 6 | Two instances and the DoD run: `build.sh --instance b`, `CFBundleName`/`CFBundleDisplayName`; run V53–V68 and every rewritten or scripted A row (V1, V9, V11, V13, V14, V17, V18, V26, V40, V41); decision entries; phase summary; README (running the relay) | `scripts/build.sh`, `app/project.yml`, `docs/*`, `README.md` | 5, Q1–Q4 | every row passes or has an owner-accepted entry | **yes** (App ID per Q4; about 15 Touch ID prompts: 2 onboardings × (unlock + register), an unlock per switch, one per letter, and the key-change run with a third onboarding) |

## 10. Decision-log entries to add

Numbered after the last entry when read (D-0035). D-0035 notes that PHASE2_DESIGN §13 plans D-0036 to D-0061 for Phase 2's own entries; if those land first, the numbers below shift to follow them, in this order.

> Numbering note (2026-09-28, merge of Phase 2's WP12): Phase 2's entries landed first, as D-0036 to D-0053 and D-0062 to D-0064 (D-0054 to D-0061 are not used). The entries below take free numbers after D-0064 when WP6 writes them, in this order. Until then, a D-number from this list, in this design and in `docs/VERIFY.md` ("the Phase 3 design's D-0053"), means the topic below, not the `docs/DECISIONS.md` entry with that number. Update (2026-09-28, vault split docs): the first of them, D-0036 (the owner answers), is written as D-0065, beside the vault split's D-0066 to D-0068; the others take numbers after D-0068.

- D-0036: Owner answers to Q1–Q4 and the CLAUDE.md §2 edits they cause (Phase 3 relay line, echo lines 57 and 61).
- D-0037: Crates and features: p256 0.14 (`ecdsa`; its `der` gives `from_der`, so no DER code of ours), reqwest 0.13 (`blocking` only: no TLS, proxy or redirects), axum 0.8 (`http1`, `tokio`), tokio 1.53 (`rt`, `net`, `macros`); ed25519-dalek removed; Cargo.lock 123 → 209; audit clean; brev-core `rust-version` 1.88 because url → idna → ICU4X 2.3 declares it (supersedes D-0015 for brev-core; brev-proto and brev-relay stay 1.85).
- D-0038: Protocol v1 wire format (§2.1), envelope id, `MAX_WIRE`, the relay's bucket check; `signed_bytes` unchanged from D-0018; version 0 → 1.
- D-0039: Envelope payload padding with Phase 2's `pad_into`/`unpad`; 1 MiB maximum in app and relay.
- D-0040: Signatures: ECDSA P-256/SHA-256, Swift signs digests, raw 64 bytes either S on the wire, one `verify` in brev-proto for core and relay, verify before decrypt (narrows D-0017's KCI), P-256 key validation (ends D-0016's opaque rule), no `SigningKey` outside tests.
- D-0041: The letter flow: `prepare_send` ticket, local `sign_request`, `attach_signature`, `submit`; no I/O with content; slot cleared on lock and cancel; no retry from `sync`; the send prompt does not suspend auto-lock (with U4's result); supersedes D-0019.
- D-0042: Relay token instead of signed relay requests: why a third Enclave key and signed polls protect nothing on loopback; signed registration; revisited with TLS in Phase 4.
- D-0043: Relay: endpoints, schema, delete on ack (no tombstones, no timestamps), policy hooks, `127.0.0.1` only, `release`.
- D-0044: RelayTransport: blocking client, no network under the mutex, one mutex hold per envelope, ack after store with the P/L split (closes D-0026), 5 s polling while unlocked, response caps, `http://127.0.0.1:<port>` only.
- D-0045: Schema v3: local contact ids, keyed contact tag, sealed addresses and `pending`, token in `identity.keys`; v2 refused.
- D-0046: Contacts by address, TOFU pin, key change detected at Send, warning, block, acceptance bound to the shown code; strangers (Q2).
- D-0047: Identity code: base32 of the first 150 bits of the identity id, 6 × 5 characters.
- D-0048: Addresses: rules, one per identity, permanence, operator `release` (Q3); registered after the first unlock.
- D-0049: Contact data (addresses, codes) is drawn only in the protected layer; no pasteboard in Phase 3 (D-0031's address copy waits for Phase 4's contact screen).
- D-0050: Sandbox `network.client`; no ATS key (reqwest is not `URLSession`); `URLSession` forbidden.
- D-0051: Echo peers and their tools removed (Phase 2's echo entry closed).
- D-0052: Two instances by bundle id ("Brev B"); access group and bundle name from build settings.
- D-0053: Phase 3 VERIFY results and summary.

## 11. Owner questions and residual risks

### Owner questions (product decisions)

1. **The local relay can be run or replaced by any program of yours (a §1 conflict, so asked, not decided).** In Phase 3 the relay runs on this Mac as your user, with its database in your Library. Any same-user process, an AI coding agent included, can edit `relay.db` or take the relay's port while it is down. It can then hand out its own key when you add a contact or when a key changes. TOFU would pin that key, and letters to that contact would be readable by the agent. The only defence is comparing codes, which is optional. It can also read the directory and, until delivery, who writes to whom. **Recommended (A):** accept this for Phase 3 only, as a §2 line: "Phase 3 only: the local relay runs as the user, so any same-user program can act as the relay; Phase 3 carries test letters only". This Mac already cannot hold real letters (§2, team signing key); the fix is a remote relay with TLS (Phase 4). (B) Run the relay as a separate hidden macOS user `_brevrelay`, with `relay.db` in `/Library/Application Support/brev-relay` at mode 0700/0600, started with `sudo -u _brevrelay` or a LaunchDaemon. That needs an admin password once and a V-row for owner and mode. The port can still be taken while the relay is stopped.
2. **Letters from people you have not added**, including a contact's new key before you accept it. **Recommended:** dropped and acknowledged in Phase 3; both people add each other first; Phase 4's contact requests replace this. Alternative: leave them at the relay unacknowledged until Phase 4 (they are fetched and refused every 5 s).
3. **Addresses.** **Recommended:** `a–z 0–9 -`, 3–32 characters, first a letter (no æøå: no look-alikes, no Unicode normalisation), one per identity, **permanent**. After a reset, a lost Mac or a fingerprint change, you need a new address unless the relay operator runs `release`. Alternative: self-service release signed by the old key (it only helps a planned reset).
4. **A second App ID.** May WP6 register `no.brev.app.b` in team AV26DNQ5SC (automatic signing) for the two-instance DoD? Alternative: a second macOS user account running the same Brev.app.

### Residual risks and limits

- **First contact trusts the relay** (D-0031): a lying relay can hand out its own key at first lookup; later swaps are caught; comparing codes catches the first one. In Phase 3 "the relay" includes any same-user program (Q1).
- **Metadata at the relay**: who writes to whom and when (until delivery), bucketed sizes, addresses, who looks up whom, and each user's unlock sessions (polling every 5 s only while unlocked). Immediate delivery links a send to its fetch (D-0030). No TLS: loopback only, enforced by brev-core's URL rule and the relay's `--listen` rule.
- **Relay token**: a bearer secret; replayable if captured, which on loopback needs root or Brev's memory. It gives fetch and delete of your waiting ciphertext, never content.
- **Own identity id** is plaintext in `brev.db` (unlock check); with `relay.db` on this Mac it maps to your own address.
- **Dropped letters**: a stranger's letter, and a contact's new key before acceptance (Q2). A contact who reinstalls is noticed only when you next press *Send*.
- **Sending edges**: a lock while `submit` is on the wire, or *Avbryt* after a lost answer, can leave the recipient with a letter the sender has no copy of.
- **Supply chain**: 77 more crates in the app binary (HTTP stack, `url`/IDNA/ICU tables, p256). They contain `unsafe`; they see only ciphertext, public data and the token; the zeroing allocator covers their frees; `cargo audit` is clean today. p256 verifies only (public inputs).
- **Relay durability**: waiting envelopes never expire in Phase 3; the relay can drop, delay or reorder letters undetected (no sequence numbers; Phase 1's residual stands).
- **Address permanence** (Q3): losing the keys loses the address without the operator.
- **No notifications**: nothing polls while locked.
- **Unverified here**: the real identity key's Touch ID signing prompt (format proven with Enclave keys without biometry), whether the Touch ID panel resigns Brev active (U4; WP5 measures it before relying on §3.2's rule), and that `CFBundleDisplayName` names Brev B in the dialog (V57).

## 12. Changes after review (29 findings)

- **Removed**: the third (mailbox) Enclave key, the `MailboxSigner` foreign trait, the signed auth block, the ±300 s clock rule and the nonce map (a token under the DEK instead, §4.2); the hand-written DER parser (`from_der`); the low-S rule; relay tombstones, timestamps and the hourly sweep; the address pasteboard and *Kopier adressen min*; auto-retry of a signed letter from `sync`; the key lookup on contact selection; the time field in registration; ed25519-dalek.
- **Changed**: the lookup moved out of the content call (`prepare_send` ticket, local `sign_request` on main); only `http://127.0.0.1:<port>`; one mutex hold per envelope; local row failures are not acknowledged; acceptance bound to the shown code; contacts found by a keyed tag, not a plaintext identity id; addresses and codes drawn only in the protected layer, no address in any string; the send prompt keeps auto-lock; the onboarding Touch ID rule names all three actions; `CFBundleName` from the build; brev-core rust-version 1.88; work packages cut at compile boundaries with tools and old VERIFY rows included and no owner gate before WP6; CLAUDE.md line 57 added to the §2 edits.
- **Added**: owner Q1 on the local relay as a §1 conflict, Q4 on the App ID; V62 (app switch during the send prompt), V67 (new controls), V68 (no contact data in AX or capture); tests for the P/L split, the ticket, no I/O in content calls and acceptance binding.
