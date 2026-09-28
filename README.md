# Brev

Brev (Norwegian for "letter") is a native macOS app for private correspondence between verified people. It is meant to feel like mail did before spam and AI agents: slow, personal and completely sealed. Message content is only ever visible inside the app window, to a human who has unlocked it with Touch ID. Nothing else on the Mac — no other app, AI agent, OS feature, browser extension or automation — can read messages or history, and there is deliberately no setting, API, export or integration that can change that.

**No backup, by design.** The Touch ID-gated keys that protect everything else live only in this Mac's Secure Enclave, all other keys are stored encrypted under them on this Mac only, and nothing is ever synced to iCloud. Losing the Mac means losing the message history. This is intentional and is explained during setup.

**Status:** Phase 2 (the locked UI) is code-complete; its manual verification ([docs/VERIFY.md](docs/VERIFY.md), with Touch ID) is still to be run. The app has onboarding, a Touch ID unlock with the keys in the Secure Enclave and the keychain, the three-pane mail window and the compose sheet, drawn through a capture-protected layer, with auto-lock and blank-on-lock. Letters go to two built-in echo contacts in the same process; real transport is Phase 3. The phase plan is in CLAUDE.md §5.

## Prerequisites

- macOS 14 (Sonoma) or newer to run the app
- Xcode 16.2 or newer (the full Xcode, not just the command-line tools): the app uses symbols of the macOS 15.2 SDK
- Rust stable via [rustup](https://rustup.rs)
- `python3` (the bindings patch step, `scripts/patch-bindings.py`)
- [XcodeGen](https://github.com/yonaskolb/XcodeGen): `brew install xcodegen`
- An Apple Development certificate of team `AV26DNQ5SC`, with this Mac registered to the team: the app is team-signed so that its keys can live in the keychain ([docs/DECISIONS.md](docs/DECISIONS.md) D-0035). `scripts/build.sh` and the last step of `scripts/test.sh` pass `-allowProvisioningUpdates`
- Optional: `cargo install cargo-audit` (`scripts/test.sh` warns and skips the audit without it)

## Build and test

    scripts/build.sh          # Rust core → UniFFI bindings → Xcode project → app/build/Build/Products/Release/Brev.app
    scripts/build.sh --open   # same, then launch it (add --debug for a Debug build)
    scripts/test.sh           # every automated check; see below

`scripts/test.sh` first generates the patched bindings and the Xcode project itself. It then runs cargo fmt, clippy, the Rust tests (also the stack-scrub tests in release), the zeroize and allocator checks, the FFI surface checks, the forbidden-API grep, cargo audit, the Swift heap-scan harness (`app/Tests`), the lock probe (`app/Tests/Lock`), a compile check of the view host (`tools/viewhost`), a type-check of the verification tools (`tools/verify`) and an Xcode Debug build. None of it opens a window on screen or asks for Touch ID.

`scripts/test.sh` and `scripts/gen-bindings.sh` also run on Linux (Rust side only), so CI without Xcode can still check the core.

## Layout

`core/` is the Rust workspace (all logic, storage and crypto), `app/` is the AppKit app, `docs/` holds the decision log and the threat model. The full layout, the non-negotiable invariants and the phase plan are in [CLAUDE.md](CLAUDE.md); the threat model on its own is [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), and every architectural decision is in [docs/DECISIONS.md](docs/DECISIONS.md).
