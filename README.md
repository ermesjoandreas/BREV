# Brev

Brev (Norwegian for "letter") is a native macOS app for private correspondence between verified people. It is meant to feel like mail did before spam and AI agents: slow, personal and completely sealed. Message content is only ever visible inside the app window, to a human who has unlocked it with Touch ID. Nothing else on the Mac — no other app, AI agent, OS feature, browser extension or automation — can read messages or history, and there is deliberately no setting, API, export or integration that can change that.

**No backup, by design.** The Touch ID-gated keys that protect everything else live only in this Mac's Secure Enclave, all other keys are stored encrypted under them on this Mac only, and nothing is ever synced to iCloud. Losing the Mac means losing the message history. This is intentional and is explained during setup.

**Status:** Phases 3 (real transport) and 4 (anti-noise: contact approval, invite codes, rate limits) are code-complete, and so is the split of the Rust core into brev-vault and brev-mail ([docs/VAULT_SPLIT_PLAN.md](docs/VAULT_SPLIT_PLAN.md)). The Phase 5 items that need no human are done: cargo-deny and CI, Swift warnings as errors, the Swift memory review ([docs/SWIFT_MEMORY_REVIEW.md](docs/SWIFT_MEMORY_REVIEW.md)) and a reproducible build ([docs/REPRODUCIBLE_BUILD.md](docs/REPRODUCIBLE_BUILD.md)). The owner tested the main flows on a real Mac with Touch ID (round 1, and Phase 3's definition of done: two instances exchanging letters, no plaintext at the relay, the key-change warning); the edge-case round was skipped by the owner, so those rows are machine-tested only ([docs/VERIFY-RESULTS.md](docs/VERIFY-RESULTS.md), [docs/SECURITY.md](docs/SECURITY.md) §7). The remaining human steps stay in [docs/USER_SESSION.md](docs/USER_SESSION.md). Brev holds test letters only and is not released. For reviewers: [docs/SECURITY.md](docs/SECURITY.md) (what Brev promises, how, and what is still open) and [docs/DISTRIBUTION.md](docs/DISTRIBUTION.md) (Developer ID signing, notarization, checking a download). The phase plan is in CLAUDE.md §5.

## Prerequisites

- macOS 14 (Sonoma) or newer to run the app
- Xcode 16.2 or newer (the full Xcode, not just the command-line tools): the app uses symbols of the macOS 15.2 SDK
- Rust stable via [rustup](https://rustup.rs)
- `python3` (the bindings patch step, `scripts/patch-bindings.py`)
- [XcodeGen](https://github.com/yonaskolb/XcodeGen): `brew install xcodegen`
- An Apple Development certificate of team `AV26DNQ5SC`, with this Mac registered to the team: the app is team-signed so that its keys can live in the keychain ([docs/DECISIONS.md](docs/DECISIONS.md) D-0035). `scripts/build.sh` and the last step of `scripts/test.sh` pass `-allowProvisioningUpdates`
- Optional: `cargo install cargo-audit` and `cargo install cargo-deny --locked` (`scripts/test.sh` warns and skips each check without it)

## Build and test

    scripts/build.sh          # Rust core → UniFFI bindings → Xcode project → app/build/Build/Products/Release/Brev.app
    scripts/build.sh --open   # same, then launch it (add --debug for a Debug build)
    scripts/test.sh           # every automated check; see below

`scripts/test.sh` first generates the patched bindings and the Xcode project itself. It then runs cargo fmt, clippy, the Rust tests (also the stack-scrub tests in release), the zeroize and allocator checks, the FFI surface checks, the forbidden-API grep, cargo audit, cargo deny (`core/deny.toml`), the Swift heap-scan harness (`app/Tests`), the lock probe (`app/Tests/Lock`), a compile check of the view host (`tools/viewhost`), a type-check of the verification tools (`tools/verify`) and an Xcode Debug build. None of it opens a window on screen or asks for Touch ID.

`scripts/test.sh` and `scripts/gen-bindings.sh` also run on Linux (Rust side only), so CI without Xcode can still check the core; `.github/workflows/ci.yml` does that on Linux.

## Layout

`core/` is the Rust workspace (all logic, storage and crypto), `app/` is the AppKit app, `docs/` holds the decision log and the threat model. The full layout, the non-negotiable invariants and the phase plan are in [CLAUDE.md](CLAUDE.md); the threat model on its own is [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), and every architectural decision is in [docs/DECISIONS.md](docs/DECISIONS.md).
