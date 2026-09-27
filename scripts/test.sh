#!/usr/bin/env bash
# Runs every check that can run on this machine, in order: Rust formatting,
# clippy, tests, dependency audit, and (macOS with a generated project only)
# an Xcode compile check. Exits non-zero on the first failure.
#
# Usage: scripts/test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$REPO_ROOT/core/Cargo.toml"
# Pinned with --target-dir on every cargo command that builds, as
# gen-bindings.sh does: the flag overrides CARGO_TARGET_DIR and a
# `[build] target-dir` in ~/.cargo/config.toml, so the artefacts always land
# where this script and app/project.yml look for them. `cargo fmt` and
# `cargo audit` build nothing and have no such flag.
TARGET_DIR="$REPO_ROOT/core/target"

if ! command -v cargo >/dev/null 2>&1; then
  echo "error: cargo not found. Install Rust with rustup: https://rustup.rs" >&2
  exit 1
fi

echo "==> cargo fmt --check"
cargo fmt --manifest-path "$MANIFEST" --all --check

echo "==> cargo clippy (warnings are errors)"
cargo clippy --manifest-path "$MANIFEST" --target-dir "$TARGET_DIR" --workspace --all-targets -- -D warnings

echo "==> cargo test"
cargo test --manifest-path "$MANIFEST" --target-dir "$TARGET_DIR" --workspace

# scrub_stack() must survive the optimiser, so its test also runs optimised.
echo "==> cargo test --release (scrub_stack)"
cargo test --manifest-path "$MANIFEST" --target-dir "$TARGET_DIR" --release -p brev-core --lib scrub_stack

# Wipe-on-drop of every key the crypto crates hold depends on their `zeroize`
# features (CLAUDE.md §1.10). Memory cannot be inspected without `unsafe`, so
# check that each feature is actually enabled in brev-core's build.
echo "==> zeroize features"
FEATURES="$(cargo tree --manifest-path "$MANIFEST" -p brev-core -e normal -f '{p} [{f}]')"
for crate in chacha20poly1305 chacha20 poly1305 x25519-dalek curve25519-dalek sha2 block-buffer; do
  if ! grep -Eq "(^|[^a-z0-9_-])$crate v[^ ]+ \[[^]]*zeroize" <<<"$FEATURES"; then
    echo "error: $crate is built without its zeroize feature" >&2
    exit 1
  fi
done

# cargo-audit is optional on a dev machine but required clean from Phase 1 on
# (CLAUDE.md §5, Phase 1 definition of done; in CI from Phase 5), so skipping
# it is loud, never silent.
# It has no --manifest-path; it reads Cargo.lock from the working directory.
if cargo audit --version >/dev/null 2>&1; then
  echo "==> cargo audit"
  (cd "$REPO_ROOT/core" && cargo audit)
else
  echo "warning: cargo-audit is not installed; dependency audit SKIPPED." >&2
  echo "         Install it with: cargo install cargo-audit" >&2
fi

# Compile check of the Swift app. Needs macOS, Xcode, and all three things
# scripts/build.sh produces before it links: app/Brev.xcodeproj (XcodeGen),
# app/Generated/BrevCore.swift (a source file of the target) and
# core/target/release/libbrev_core.a (named by path in OTHER_LDFLAGS). The
# project alone is not enough: XcodeGen validated the source at generate time
# but Xcode does not, and the checks above only build the debug profile, so
# after `cargo clean` or `rm -rf app/Generated` a stale project would fail on
# a missing link input for reasons unrelated to the Rust checks that just
# passed. Skip with a message instead.
XCODEPROJ="$REPO_ROOT/app/Brev.xcodeproj"
BINDINGS="$REPO_ROOT/app/Generated/BrevCore.swift"
STATICLIB="$TARGET_DIR/release/libbrev_core.a"
if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "==> xcodebuild skipped: not macOS ($(uname -s))"
elif ! xcodebuild -version >/dev/null; then
  # /usr/bin/xcodebuild exists on every Mac (a shim, also with Command Line
  # Tools only), so `command -v` would pass; only running it proves Xcode is
  # there. Its stderr is left visible on purpose: it names the real cause (no
  # Xcode, wrong xcode-select path, or a license not yet accepted, which also
  # makes `xcodebuild -version` fail).
  echo "==> xcodebuild skipped: Xcode is not installed, not selected (sudo xcode-select -s /Applications/Xcode.app) or its license is not accepted (sudo xcodebuild -license accept)"
elif [[ ! -d "$XCODEPROJ" || ! -f "$BINDINGS" || ! -f "$STATICLIB" ]]; then
  echo "==> xcodebuild skipped: run scripts/build.sh first; missing:"
  [[ -d "$XCODEPROJ" ]] || echo "    $XCODEPROJ (xcodegen generate)"
  [[ -f "$BINDINGS" ]]  || echo "    $BINDINGS (scripts/gen-bindings.sh)"
  [[ -f "$STATICLIB" ]] || echo "    $STATICLIB (scripts/gen-bindings.sh)"
else
  # -destination pins the active arch to the one the Rust archive was built
  # for, read from the archive itself rather than `uname -m` (the two differ
  # when the rustup toolchain is not native to the shell), and avoids the
  # "multiple matching destinations" warning; see the comment in
  # scripts/build.sh.
  ARCH="$(lipo -archs "$STATICLIB")"
  case "$ARCH" in
    arm64|x86_64) ;;
    *)
      echo "error: $STATICLIB is built for '$ARCH'; expected exactly one of arm64 or x86_64." >&2
      echo "       Check which toolchain cargo used (rustup show) and rebuild with scripts/gen-bindings.sh." >&2
      exit 1 ;;
  esac
  echo "==> xcodebuild (Debug compile check, $ARCH)"
  xcodebuild -project "$XCODEPROJ" -scheme Brev -configuration Debug \
    -destination "platform=macOS,arch=$ARCH" ONLY_ACTIVE_ARCH=YES build
fi

echo "==> all checks passed"
