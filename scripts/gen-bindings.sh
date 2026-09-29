#!/usr/bin/env bash
# Builds brev-mail (library brev_core) in release, regenerates the UniFFI
# Swift bindings into app/Generated/ (gitignored) and patches them
# (scripts/patch-bindings.py).
# Runs on macOS and Linux, so a CI box without Xcode can still prove that the
# bindings generate. build.sh and test.sh call this.
#
# Usage: scripts/gen-bindings.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$REPO_ROOT/core/Cargo.toml"
# The uniffi release scripts/patch-bindings.py and the heap-scan harness
# (app/Tests) were checked against. Another version can change the generated
# Swift in ways the patches do not match or, worse, add a copy path they do
# not cover, so it stops the build until someone has re-checked both.
PATCHED_FOR_UNIFFI=0.32.2
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
if ! command -v python3 >/dev/null 2>&1; then
  echo "error: python3 not found; scripts/patch-bindings.py needs it." >&2
  echo "       Install it with: xcode-select --install (macOS) or your package manager (python3)" >&2
  exit 1
fi

# The app's deployment target (app/project.yml, D-0006). Without it the C
# code in the archive (bundled SQLite, built by the cc crate) targets the SDK
# version of this Mac, not the oldest macOS the app claims to run on.
if [[ "$(uname -s)" == Darwin ]]; then
  export MACOSX_DEPLOYMENT_TARGET=14.0
fi

echo "==> Building brev-mail (release)"
# One build produces both artefacts: libbrev_core.a, which the app links, and
# the shared library (.dylib/.so) that bindgen reads UniFFI metadata from.
cargo build --manifest-path "$MANIFEST" --target-dir "$TARGET_DIR" --release -p brev-mail

# The generated Swift comes from uniffi_bindgen, the runtime it calls from
# uniffi; both must be the pinned release. Each name must occur once in
# Cargo.lock: two versions of either print two lines and fail too. Read after
# the build, not before: cargo rewrites Cargo.lock when core/Cargo.toml no
# longer matches it, for the whole workspace (the uniffi-bindgen crate too),
# so this is the version bindgen below runs with.
for pkg in uniffi uniffi_bindgen; do
  VERSION="$(awk -v name="name = \"$pkg\"" '$0 == name { getline; gsub(/^version = "|"$/, ""); print }' "$REPO_ROOT/core/Cargo.lock")"
  if [[ "$VERSION" != "$PATCHED_FOR_UNIFFI" ]]; then
    echo "error: uniffi changed: re-check scripts/patch-bindings.py and the heap-scan harness, then update PATCHED_FOR_UNIFFI" >&2
    echo "       ($pkg in core/Cargo.lock: '${VERSION//$'\n'/, }'; PATCHED_FOR_UNIFFI=$PATCHED_FOR_UNIFFI)" >&2
    exit 1
  fi
done

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

# brev-mail's `test-hooks` feature (MockTransport and brev-vault's test
# counters) is for tests only (docs/VAULT_SPLIT_PLAN.md Q5): the archive the
# app links must not have it. nm's output is captured first (`grep -q` in a
# pipe could stop it with SIGPIPE under pipefail); Xcode's nm complains about
# the Rust std objects, so its stderr and exit status are ignored, and the
# ping symbol proves it read the archive. scripts/test.sh checks the other
# side: the same pattern finds the hooks in a test build.
TEST_HOOKS='MockTransport|live_plaintexts|_for_test'
ARCHIVE_SYMS="$(nm "$TARGET_DIR/release/libbrev_core.a" 2>/dev/null || true)"
if ! grep -q 'uniffi_brev_core_fn_func_ping' <<<"$ARCHIVE_SYMS"; then
  echo "error: nm found no ping symbol in libbrev_core.a; the test-hooks check cannot run" >&2
  exit 1
fi
if grep -Eq "$TEST_HOOKS" <<<"$ARCHIVE_SYMS"; then
  echo "error: libbrev_core.a has test hooks ($TEST_HOOKS): brev-mail was built with test-hooks" >&2
  exit 1
fi
# brev-mail's `allow-software-keys` (docs/VAULT_SPLIT_PLAN.md §6; D-0115)
# skips the hardware-key requirement, so a letter with a software key and no
# Touch ID goes out; it is for the test archive only. The feature compiles a
# marker into the archive, and the app's must not have it. app/project.yml's build phase checks the
# archive Xcode links the same way; scripts/test.sh checks that the test
# archive has the marker.
if grep -aq BREV-ALLOW-SOFTWARE-KEYS "$TARGET_DIR/release/libbrev_core.a"; then
  echo "error: libbrev_core.a was built with allow-software-keys, which the app must never have" >&2
  exit 1
fi

# swift-format is optional; without --no-format bindgen prints a warning when
# it is missing. A plain string (not an array) keeps this valid under `set -u`
# on the bash 3.2 that ships with macOS.
NO_FORMAT=""
if ! command -v swift-format >/dev/null 2>&1; then
  NO_FORMAT="--no-format"
fi

# Wipe stale output first so a renamed or removed binding can never linger and
# get compiled into the app by accident. Bindgen writes into a staging
# directory, and app/Generated gets the files only once they are patched: a
# failed or interrupted run leaves no bindings there, so no build (Xcode's
# included) can compile unpatched ones.
STAGE_DIR="$TARGET_DIR/bindings-staging"
rm -rf "${OUT_DIR:?}" "$STAGE_DIR"
mkdir -p "$STAGE_DIR"

echo "==> Generating Swift bindings into $STAGE_DIR"
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
  --out-dir "$STAGE_DIR" \
  $NO_FORMAT

# The Xcode project references these exact names (project.yml adds
# Generated/BrevCore.swift; the bridging header imports BrevCoreFFI.h).
for f in BrevCore.swift BrevCoreFFI.h BrevCoreFFI.modulemap; do
  if [[ ! -f "$STAGE_DIR/$f" ]]; then
    echo "error: bindgen did not produce $STAGE_DIR/$f (check core/brev-mail/uniffi.toml)" >&2
    exit 1
  fi
done

# Wipe byte buffers before they are freed (CLAUDE.md §3.1). The script exits
# non-zero when a patch does not apply exactly once, and `set -e` then stops
# here, before anything reaches app/Generated.
echo "==> Patching $STAGE_DIR/BrevCore.swift"
python3 "$REPO_ROOT/scripts/patch-bindings.py" "$STAGE_DIR/BrevCore.swift"
mv "$STAGE_DIR" "$OUT_DIR"

echo "==> Bindings written:"
ls -1 "$OUT_DIR"
