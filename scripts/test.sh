#!/usr/bin/env bash
# Runs every check that can run on this machine, in order. On macOS first the
# patched bindings (gen-bindings.sh) and the Xcode project (xcodegen), so
# every later step sees the current core. Then Rust formatting, clippy,
# tests, the zeroize and allocator checks, the FFI surface and patch-marker
# checks (macOS), the forbidden-API grep, the dependency audit, the Swift
# heap-scan harness (macOS) and an Xcode compile check (macOS with xcodegen).
# Exits non-zero on the first failure.
#
# Usage: scripts/test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$REPO_ROOT/core/Cargo.toml"
BINDINGS="$REPO_ROOT/app/Generated/BrevCore.swift"
# Pinned with --target-dir on every cargo command that builds, as
# gen-bindings.sh does: the flag overrides CARGO_TARGET_DIR and a
# `[build] target-dir` in ~/.cargo/config.toml, so the artefacts always land
# where this script and app/project.yml look for them. `cargo fmt` and
# `cargo audit` build nothing and have no such flag.
TARGET_DIR="$REPO_ROOT/core/target"
STATICLIB="$TARGET_DIR/release/libbrev_core.a"
DARWIN=no
# Same deployment target as gen-bindings.sh, so the release test below and
# the archive the app links share one SQLite build instead of rebuilding it.
if [[ "$(uname -s)" == Darwin ]]; then
  DARWIN=yes
  export MACOSX_DEPLOYMENT_TARGET=14.0
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "error: cargo not found. Install Rust with rustup: https://rustup.rs" >&2
  exit 1
fi

# First, so nothing below links a stale archive or compiles stale bindings
# (docs/DECISIONS.md D-0028 item 2): the release archive, the bindings
# patched by scripts/patch-bindings.py (gen-bindings.sh fails if a patch no
# longer applies or uniffi moved), and the Xcode project for the compile
# check at the end.
XCODEGEN=no
if [[ "$DARWIN" == yes ]]; then
  "$REPO_ROOT/scripts/gen-bindings.sh"
  if command -v xcodegen >/dev/null 2>&1; then
    echo "==> xcodegen generate"
    xcodegen generate --spec "$REPO_ROOT/app/project.yml" --project "$REPO_ROOT/app"
    XCODEGEN=yes
  else
    echo "==> xcodegen skipped: not installed (brew install xcodegen); the xcodebuild step is skipped too"
  fi
  # The harness and xcodebuild build for the arch the Rust archive was built
  # for, read from the archive itself rather than `uname -m` (the two differ
  # when the rustup toolchain is not native to the shell); see the comment
  # in scripts/build.sh.
  ARCH="$(lipo -archs "$STATICLIB")"
  case "$ARCH" in
    arm64|x86_64) ;;
    *)
      echo "error: $STATICLIB is built for '$ARCH'; expected exactly one of arm64 or x86_64." >&2
      echo "       Check which toolchain cargo used (rustup show) and rebuild with scripts/gen-bindings.sh." >&2
      exit 1 ;;
  esac
else
  echo "==> gen-bindings, xcodegen skipped: not macOS ($(uname -s))"
fi

echo "==> cargo fmt --check"
cargo fmt --manifest-path "$MANIFEST" --all --check

echo "==> cargo clippy (warnings are errors)"
cargo clippy --manifest-path "$MANIFEST" --target-dir "$TARGET_DIR" --workspace --all-targets -- -D warnings

echo "==> cargo test"
cargo test --manifest-path "$MANIFEST" --target-dir "$TARGET_DIR" --workspace

# scrub_stack() and scrub_stack_deep() must survive the optimiser, so their
# tests also run optimised (the filter matches both test names).
echo "==> cargo test --release (scrub_stack, scrub_stack_deep)"
cargo test --manifest-path "$MANIFEST" --target-dir "$TARGET_DIR" --release -p brev-core --lib scrub_stack

# Wipe-on-drop of every key the crypto crates hold depends on their `zeroize`
# features (CLAUDE.md §1.10). Memory cannot be inspected without `unsafe`, so
# check that each feature is actually enabled in brev-core's build. Every
# line for the crate must have it: a second version without the feature
# (poly1305's direct dependency only works while both resolve to one version)
# must fail the check, not hide behind the copy that has it.
echo "==> zeroize features and zeroing allocator"
FEATURES="$(cargo tree --manifest-path "$MANIFEST" -p brev-core -e normal -f '{p} [{f}]')"
for crate in chacha20poly1305 chacha20 poly1305 x25519-dalek curve25519-dalek sha2 block-buffer; do
  LINES="$(grep -E "(^|[^a-z0-9_-])$crate v" <<<"$FEATURES" || true)"
  if [[ -z "$LINES" ]] || grep -Evq "(^|[^a-z0-9_-])$crate v[^ ]+ \[[^]]*zeroize" <<<"$LINES"; then
    echo "error: $crate is built without its zeroize feature" >&2
    exit 1
  fi
done
# brev-core's global allocator zeroes every freed heap block, including the
# buffers Swift frees through UniFFI (CLAUDE.md §3.1).
if ! grep -Eq "(^|[^a-z0-9_-])zeroizing-alloc v" <<<"$FEATURES"; then
  echo "error: brev-core does not depend on zeroizing-alloc" >&2
  exit 1
fi
# The dependency alone proves nothing: without `#[global_allocator]` every
# check above still passes, and no safe test can read freed memory. The
# crate's `WIPER` is linked only when `ZeroAlloc` frees, so require it in the
# release test binary built above (no rebuild here). nm's output is captured
# first: `grep -q` in a pipe could stop nm with SIGPIPE under pipefail.
TESTBIN="$(cargo test --manifest-path "$MANIFEST" --target-dir "$TARGET_DIR" --release -p brev-core --lib --no-run --message-format=json \
  | sed -n 's/.*"executable":"\([^"]*\)".*/\1/p')"
if [[ ! -f "$TESTBIN" ]]; then
  echo "error: no release test binary of brev-core found" >&2
  exit 1
fi
SYMBOLS="$(nm "$TESTBIN")"
if ! grep -q "zeroizing_alloc5WIPER" <<<"$SYMBOLS"; then
  echo "error: brev-core's global allocator is not zeroizing_alloc::ZeroAlloc" >&2
  exit 1
fi

if [[ "$DARWIN" == yes ]]; then
  # No String carries content across the FFI (docs/PHASE2_DESIGN.md §2.2).
  # The only public functions with a String are these three, and each must
  # be found, so the grep cannot pass by matching nothing.
  echo "==> FFI surface: no content String"
  ALLOWED_FUNCS=('func ping\(\) -> String' 'func create\(dir: String, ' 'func `?open`?\(dir: String\)')
  FUNCS="$(grep -nE '^(public |open )(static )?func .*String' "$BINDINGS" || true)"
  for f in "${ALLOWED_FUNCS[@]}"; do
    if ! grep -Eq "$f" <<<"$FUNCS"; then
      echo "error: expected a public function matching '$f' in $BINDINGS; the surface check no longer matches the bindings" >&2
      exit 1
    fi
  done
  if grep -Ev "$(IFS='|'; echo "${ALLOWED_FUNCS[*]}")" <<<"$FUNCS"; then
    echo "error: the functions above pass a String across the FFI" >&2
    exit 1
  fi
  # No record field is a String (the errors' `errorDescription: String?` is
  # not a field). Control: the same pattern finds the Data fields.
  FIELD='^[[:space:]]+public (var|let) [a-zA-Z]+: '
  if grep -nE "${FIELD}String([^?]|\$)" "$BINDINGS"; then
    echo "error: the record fields above are Strings" >&2
    exit 1
  fi
  if ! grep -Eq "${FIELD}Data\$" "$BINDINGS"; then
    echo "error: the record-field pattern finds no field in $BINDINGS; fix the check" >&2
    exit 1
  fi
  # The greps above see only declarations: a String constructor, an Option,
  # Vec or map of String, an enum or error payload and a callback argument
  # all get past them. Each of those goes through a FfiConverter…String…
  # type, so every line that names one must be one of these, exactly as often
  # as listed: the converter itself, a Rust panic's message (content-free,
  # design §14.1), uniffi's two callback error helpers (always emitted; there
  # is no callback), the `dir` of create and open, and ping's reply.
  CONV_LIST=(
    'fileprivate struct FfiConverterString: FfiConverter {'
    'throw UniffiInternalError.rustPanic(try FfiConverterString.lift(callStatus.errorBuf))'
    'callStatus.pointee.errorBuf = FfiConverterString.lower(String(describing: error))'
    'callStatus.pointee.errorBuf = FfiConverterString.lower(String(describing: error))'
    'FfiConverterString.lower(dir),'
    'FfiConverterString.lower(dir),uniffiCallStatus'
    'return try!  FfiConverterString.lift(try! rustCall() {'
  )
  CONV_EXPECTED="$(printf '%s\n' "${CONV_LIST[@]}" | LC_ALL=C sort)"
  CONV_FOUND="$(grep -E 'FfiConverter[A-Za-z0-9_]*String' "$BINDINGS" \
    | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' | LC_ALL=C sort || true)"
  if [[ "$CONV_FOUND" != "$CONV_EXPECTED" ]]; then
    echo "error: String converters in $BINDINGS differ from the known uses (< known, > found):" >&2
    diff <(printf '%s\n' "$CONV_EXPECTED") <(printf '%s\n' "$CONV_FOUND") >&2 || true
    exit 1
  fi

  # gen-bindings.sh just patched the bindings; the first line proves it.
  # Must equal MARKER in scripts/patch-bindings.py.
  echo "==> bindings patched"
  if [[ "$(head -n 1 "$BINDINGS")" != "// brev: patched by scripts/patch-bindings.py" ]]; then
    echo "error: $BINDINGS is not patched (scripts/patch-bindings.py did not run)" >&2
    exit 1
  fi
else
  echo "==> FFI surface and patch-marker checks skipped: not macOS ($(uname -s))"
fi

# APIs that could put content where §1 forbids it (docs/PHASE2_DESIGN.md
# §6.3, §11). A fixed-string grep over app/Sources; each hit must be listed,
# with its reason, in scripts/allowed-apis.txt, and each listed line must
# still exist, so the list cannot go stale. The names after servicesMenu add
# checkable cases of §6.3 rules 1 and 5 that §11's list misses: the other
# ways to make a String from bytes or units, the mutable string classes, the
# copying CFString constructor (the NoCopy one does not match) and the other
# logging calls.
echo "==> forbidden APIs in app/Sources"
FORBIDDEN=(NSPasteboard NSTextView NSTextField NSTextInputClient .characters 'String(decoding' 'NSString('
           'NSAttributedString(' CTTypesetter CTFramesetter NSAlert 'print(' servicesMenu
           'String(utf16CodeUnits' 'String(data' 'String(bytes' 'String(cString' 'String(validating'
           'String(utf8String' 'String(unsafeUninitializedCapacity' NSMutableString NSMutableAttributedString
           'CFStringCreateWithCharacters(' 'NSLog(' 'debugPrint(' 'dump(' 'os_log(')
GREP_ARGS=()
for p in "${FORBIDDEN[@]}"; do GREP_ARGS+=(-e "$p"); done
# "path<TAB>trimmed line" for every hit and for every allow-list entry
# ("path | reason | trimmed line"; comments and blank lines skipped).
TAB=$'\t'
HITS="$(cd "$REPO_ROOT" && grep -rnF "${GREP_ARGS[@]}" app/Sources \
  | sed -E "s/^([^:]*):[0-9]+:[[:space:]]*/\\1${TAB}/; s/[[:space:]]+\$//" || true)"
LISTED="$(grep -vE '^[[:space:]]*(#|$)' "$REPO_ROOT/scripts/allowed-apis.txt" \
  | sed -E "s/^([^|]*[^| ]) \\| [^|]+ \\| /\\1${TAB}/" || true)"
UNLISTED="$(grep -vxF -f <(printf '%s\n' "$LISTED" | grep -v '^$' || true) <<<"$HITS" | grep -v '^$' || true)"
STALE="$(grep -vxF -f <(printf '%s\n' "$HITS" | grep -v '^$' || true) <<<"$LISTED" | grep -v '^$' || true)"
if [[ -n "$UNLISTED" ]]; then
  echo "error: forbidden API in app/Sources (list it in scripts/allowed-apis.txt with a reason, or remove it):" >&2
  echo "$UNLISTED" >&2
  exit 1
fi
if [[ -n "$STALE" ]]; then
  echo "error: scripts/allowed-apis.txt lists lines that no longer exist (or an entry is malformed):" >&2
  echo "$STALE" >&2
  exit 1
fi

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

# The Swift heap-scan harness (docs/PHASE2_DESIGN.md §11): a CLI process, so
# no window and no prompt, built from app/Sources/Shared, the patched
# bindings and the release archive. Every case runs five times and every run
# must pass: under MallocScribble=1, as the app runs (Info.plist
# LSEnvironment), except case 6's control without scribbling, which proves
# that the glyph needle works and that scribbling is what clears the glyphs
# (it finds nothing at 200 units or less, so it runs at 4096 and 65000).
if [[ "$DARWIN" == yes ]]; then
  echo "==> Swift harness (app/Tests)"
  HARNESS_DIR="$TARGET_DIR/harness"
  rm -rf "$HARNESS_DIR"
  mkdir -p "$HARNESS_DIR/tmp"
  xcrun clang -O2 -Wall -target "$ARCH-apple-macos14.0" -c "$REPO_ROOT/app/Tests/scan.c" -o "$HARNESS_DIR/scan.o"
  xcrun swiftc -O -swift-version 5 -target "$ARCH-apple-macos14.0" \
    -import-objc-header "$REPO_ROOT/app/Tests/bridging.h" -I "$REPO_ROOT/app/Generated" \
    "$REPO_ROOT"/app/Sources/Shared/*.swift "$BINDINGS" "$REPO_ROOT"/app/Tests/*.swift \
    "$HARNESS_DIR/scan.o" "$STATICLIB" -o "$HARNESS_DIR/harness"
  # run_harness <label> <scribble|none> <harness arguments...>
  run_harness() {
    local label="$1" mode="$2" i out
    shift 2
    local env_args=(TMPDIR="$HARNESS_DIR/tmp/")
    if [[ "$mode" == scribble ]]; then env_args+=(MallocScribble=1); else env_args=(-u MallocScribble "${env_args[@]}"); fi
    for i in 1 2 3 4 5; do
      if ! out="$(env "${env_args[@]}" "$HARNESS_DIR/harness" "$@" 2>&1)"; then
        echo "$out"
        echo "error: harness $label failed in run $i of 5" >&2
        exit 1
      fi
    done
    echo "    $label: 5 of 5 passed"
  }
  run_harness "case 1 (units)" scribble units
  run_harness "case 2 (InputFilter, LockState, LaunchGuard)" scribble shell
  run_harness "case 2 (EditModel, KeyTranslator)" scribble compose
  run_harness "case 3 (DEK hand-off, HPKE needles)" scribble dek
  for n in 64 200 4096 65000; do
    run_harness "case 4 (content path, $n units)" scribble content "$n"
  done
  run_harness "case 5 (kept OpenText after lock)" scribble kept
  run_harness "case 6 (a live String is seen)" scribble control
  for n in 4096 65000; do
    run_harness "case 6 (no scribbling: glyphs left, $n units)" none content "$n" --no-scribble
  done
else
  echo "==> Swift harness skipped: not macOS ($(uname -s))"
fi

# Compile check of the Swift app: the project xcodegen generated above, the
# bindings and the archive gen-bindings.sh built above.
if [[ "$DARWIN" != yes ]]; then
  echo "==> xcodebuild skipped: not macOS ($(uname -s))"
elif [[ "$XCODEGEN" != yes ]]; then
  echo "==> xcodebuild skipped: xcodegen is not installed (brew install xcodegen)"
elif ! xcodebuild -version >/dev/null; then
  # /usr/bin/xcodebuild exists on every Mac (a shim, also with Command Line
  # Tools only), so `command -v` would pass; only running it proves Xcode is
  # there. Its stderr is left visible on purpose: it names the real cause (no
  # Xcode, wrong xcode-select path, or a license not yet accepted, which also
  # makes `xcodebuild -version` fail).
  echo "==> xcodebuild skipped: Xcode is not installed, not selected (sudo xcode-select -s /Applications/Xcode.app) or its license is not accepted (sudo xcodebuild -license accept)"
else
  # -destination pins the active arch to the archive's (ARCH, above) and
  # avoids the "multiple matching destinations" warning; see the comment in
  # scripts/build.sh.
  echo "==> xcodebuild (Debug compile check, $ARCH)"
  xcodebuild -project "$REPO_ROOT/app/Brev.xcodeproj" -scheme Brev -configuration Debug \
    -destination "platform=macOS,arch=$ARCH" ONLY_ACTIVE_ARCH=YES build
fi

echo "==> all checks passed"
