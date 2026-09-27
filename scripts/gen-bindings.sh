#!/usr/bin/env bash
# Builds brev-core in release and regenerates the UniFFI Swift bindings into
# app/Generated/ (gitignored). Runs on macOS and Linux, so a CI box without
# Xcode can still prove that the bindings generate. build.sh calls this.
#
# Usage: scripts/gen-bindings.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$REPO_ROOT/core/Cargo.toml"
# Every cargo command below pins this directory with --target-dir. The flag
# overrides both CARGO_TARGET_DIR and a `[build] target-dir` in
# ~/.cargo/config.toml, so the files checked below and the archive path that
# app/project.yml links ($(SRCROOT)/../core/target/release/libbrev_core.a)
# are always the ones cargo just wrote, never a stale copy from an earlier run.
TARGET_DIR="$REPO_ROOT/core/target"
OUT_DIR="$REPO_ROOT/app/Generated"

if ! command -v cargo >/dev/null 2>&1; then
  echo "error: cargo not found. Install Rust with rustup: https://rustup.rs" >&2
  exit 1
fi

# The app's deployment target (app/project.yml, D-0006). Without it the C
# code in the archive (bundled SQLite, built by the cc crate) targets the SDK
# version of this Mac, not the oldest macOS the app claims to run on.
if [[ "$(uname -s)" == Darwin ]]; then
  export MACOSX_DEPLOYMENT_TARGET=14.0
fi

echo "==> Building brev-core (release)"
# One build produces both artefacts: libbrev_core.a, which the app links, and
# the shared library (.dylib/.so) that bindgen reads UniFFI metadata from.
cargo build --manifest-path "$MANIFEST" --target-dir "$TARGET_DIR" --release -p brev-core

case "$(uname -s)" in
  Darwin) LIB="$TARGET_DIR/release/libbrev_core.dylib" ;;
  Linux)  LIB="$TARGET_DIR/release/libbrev_core.so" ;;
  *)      echo "error: unsupported OS '$(uname -s)' (need macOS or Linux)" >&2; exit 1 ;;
esac
for f in "$TARGET_DIR/release/libbrev_core.a" "$LIB"; do
  if [[ ! -f "$f" ]]; then
    echo "error: cargo build finished but $f does not exist" >&2
    exit 1
  fi
done

# swift-format is optional; without --no-format bindgen prints a warning when
# it is missing. A plain string (not an array) keeps this valid under `set -u`
# on the bash 3.2 that ships with macOS.
NO_FORMAT=""
if ! command -v swift-format >/dev/null 2>&1; then
  NO_FORMAT="--no-format"
fi

# Wipe stale output first so a renamed or removed binding can never linger and
# get compiled into the app by accident.
rm -rf "${OUT_DIR:?}"
mkdir -p "$OUT_DIR"

echo "==> Generating Swift bindings into $OUT_DIR"
# --config is mandatory: the tool crate's uniffi is built without the
# cargo-metadata feature, so without the [crate-roots] map the per-crate
# uniffi.toml is not found and the module comes out misnamed (brev_core.swift).
# --library is deprecated (auto-detected) in uniffi 0.32 but still accepted;
# it is kept so the intent is explicit if the tool version moves.
# shellcheck disable=SC2086  # NO_FORMAT is intentionally unquoted (empty or one flag)
cargo run --manifest-path "$MANIFEST" --target-dir "$TARGET_DIR" -p uniffi-bindgen -- generate \
  --library "$LIB" \
  --language swift \
  --config "$REPO_ROOT/core/uniffi-global.toml" \
  --out-dir "$OUT_DIR" \
  $NO_FORMAT

# The Xcode project references these exact names (project.yml adds
# Generated/BrevCore.swift; the bridging header imports BrevCoreFFI.h).
for f in BrevCore.swift BrevCoreFFI.h BrevCoreFFI.modulemap; do
  if [[ ! -f "$OUT_DIR/$f" ]]; then
    echo "error: bindgen did not produce $OUT_DIR/$f (check core/brev-core/uniffi.toml)" >&2
    exit 1
  fi
done

echo "==> Bindings written:"
ls -1 "$OUT_DIR"
