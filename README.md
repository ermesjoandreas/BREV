# Brev

Brev (Norwegian for "letter") is a native macOS app for private correspondence between verified people. It is meant to feel like mail did before spam and AI agents: slow, personal and completely sealed. Message content is only ever visible inside the app window, to a human who has unlocked it with Touch ID. Nothing else on the Mac — no other app, AI agent, OS feature, browser extension or automation — can read messages or history, and there is deliberately no setting, API, export or integration that can change that.

**No backup, by design.** The Touch ID-gated keys that protect everything else live only in this Mac's Secure Enclave, all other keys are stored encrypted under them on this Mac only, and nothing is ever synced to iCloud. Losing the Mac means losing the message history. This is intentional and is explained during setup.

**Status:** Phase 0 (scaffold). The paragraphs above describe the finished design from [CLAUDE.md](CLAUDE.md); today the app is an empty window that proves the Rust ↔ Swift toolchain. The phase plan is in CLAUDE.md §5.

## Prerequisites

- macOS 14 (Sonoma) or newer
- Xcode 15 or newer (the full Xcode, not just the command-line tools)
- Rust stable via [rustup](https://rustup.rs)
- [XcodeGen](https://github.com/yonaskolb/XcodeGen): `brew install xcodegen`
- Optional: `cargo install cargo-audit` (`scripts/test.sh` warns and skips the audit without it)

## Build and test

    scripts/build.sh          # Rust core → UniFFI bindings → Xcode project → app/build/Build/Products/Release/Brev.app
    scripts/build.sh --open   # same, then launch it (add --debug for a Debug build)
    scripts/test.sh           # cargo fmt, clippy, tests, cargo audit; plus an Xcode compile check on macOS once scripts/build.sh has run (it needs the generated project, bindings and Rust archive)

`scripts/test.sh` and `scripts/gen-bindings.sh` also run on Linux (Rust side only), so CI without Xcode can still check the core.

## Layout

`core/` is the Rust workspace (all logic, storage and crypto), `app/` is the AppKit app, `docs/` holds the decision log and the threat model. The full layout, the non-negotiable invariants and the phase plan are in [CLAUDE.md](CLAUDE.md); the threat model on its own is [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), and every architectural decision is in [docs/DECISIONS.md](docs/DECISIONS.md).
