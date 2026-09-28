#!/usr/bin/env bash
# Runs every check that can run on this machine, in order. On macOS first the
# patched bindings (gen-bindings.sh) and the Xcode project (xcodegen), so
# every later step sees the current core. Then Rust formatting, clippy,
# tests (without the launch guard) and the launch guard's own test, the
# zeroize, allocator and crate-feature checks, the launch-guard feature and
# its cfg sites, the cfg sites of allow-software-keys, brev-vault's
# dependency whitelist, the check that no production code makes a P-256
# signing key, the FFI surface and patch-marker checks (macOS), the test
# archive, its allow-software-keys marker and its bindings (macOS),
# the forbidden-API grep, the check that
# AVFoundation, CoreMedia and CoreVideo stay in the protected layer, the
# check that the Xcode minimum is stated alike, the dependency audit, a relay
# on 127.0.0.1 with a fresh database (macOS; stopped when the script ends),
# the Swift heap-scan harness and the lock probe against it (macOS), a
# compile check of the view host (macOS), a type-check of the verification
# tools and capture-probe's self-test (macOS) and an Xcode compile check
# (macOS with xcodegen).
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
# Also with every feature on (brev-vault's and brev-mail's `test-hooks`,
# docs/VAULT_SPLIT_PLAN.md §4).
echo "==> cargo clippy --all-features (warnings are errors)"
cargo clippy --manifest-path "$MANIFEST" --target-dir "$TARGET_DIR" --workspace --all-targets --all-features -- -D warnings

# Without the default features, which turns brev-vault's launch guard off
# (cargo sets DYLD_FALLBACK_LIBRARY_PATH, and nothing sets MallocScribble=1);
# the zeroing allocator stays on through brev-mail's dependency line
# (docs/VAULT_SPLIT_PLAN.md §4).
echo "==> cargo test (--no-default-features: launch guard off)"
cargo test --manifest-path "$MANIFEST" --target-dir "$TARGET_DIR" --workspace --no-default-features

# The launch guard on: this test process must be refused. The test must run.
echo "==> cargo test (launch guard on)"
GUARD_OUT="$(cargo test --manifest-path "$MANIFEST" --target-dir "$TARGET_DIR" -p brev-vault --features launch-guard --lib launch 2>&1)" || {
  echo "$GUARD_OUT"
  exit 1
}
echo "$GUARD_OUT" | grep -E '^test |^test result'
if ! grep -q '^test store::tests::launch_guard_refuses_this_process \.\.\. ok$' <<<"$GUARD_OUT"; then
  echo "error: the launch guard's test did not run with the feature on" >&2
  exit 1
fi

# scrub_stack() and scrub_stack_deep() must survive the optimiser, so their
# tests also run optimised (the filter matches both test names, which live in
# brev-vault; both must run, docs/VAULT_SPLIT_PLAN.md §4).
echo "==> cargo test --release (scrub_stack, scrub_stack_deep)"
SCRUB_OUT="$(cargo test --manifest-path "$MANIFEST" --target-dir "$TARGET_DIR" --release -p brev-vault --lib scrub_stack 2>&1)" || {
  echo "$SCRUB_OUT"
  exit 1
}
echo "$SCRUB_OUT" | grep -E '^test |^test result'
if ! grep -q '^test result: ok\. 2 passed' <<<"$SCRUB_OUT"; then
  echo "error: the release scrub test did not run both scrub_stack tests (expected '2 passed')" >&2
  exit 1
fi

# Wipe-on-drop of every key the crypto crates hold depends on their `zeroize`
# features (CLAUDE.md §1.10). Memory cannot be inspected without `unsafe`, so
# check that each feature is actually enabled in brev-mail's build (the app's
# archive; the ciphers reach it through brev-vault). Every
# line for the crate must have it: a second version without the feature
# (poly1305's direct dependency only works while both resolve to one version)
# must fail the check, not hide behind the copy that has it.
echo "==> zeroize features and zeroing allocator"
FEATURES="$(cargo tree --manifest-path "$MANIFEST" -p brev-mail -e normal -f '{p} [{f}]')"
for crate in chacha20poly1305 chacha20 poly1305 x25519-dalek curve25519-dalek sha2 block-buffer; do
  LINES="$(grep -E "(^|[^a-z0-9_-])$crate v" <<<"$FEATURES" || true)"
  if [[ -z "$LINES" ]] || grep -Evq "(^|[^a-z0-9_-])$crate v[^ ]+ \[[^]]*zeroize" <<<"$LINES"; then
    echo "error: $crate is built without its zeroize feature" >&2
    exit 1
  fi
done
# The global allocator (brev-vault, feature zeroing-allocator, which brev-mail
# turns on) zeroes every freed heap block, including the buffers Swift frees
# through UniFFI (CLAUDE.md §3.1).
if ! grep -Eq "(^|[^a-z0-9_-])zeroizing-alloc v" <<<"$FEATURES"; then
  echo "error: brev-mail does not depend on zeroizing-alloc" >&2
  exit 1
fi
# The dependency alone proves nothing: without `#[global_allocator]` every
# check above still passes, and no safe test can read freed memory. The
# crate's `WIPER` is linked only when `ZeroAlloc` frees, so require it in
# brev-mail's release test binary. nm's output is captured first: `grep -q` in
# a pipe could stop nm with SIGPIPE under pipefail. This build also rebuilds
# brev-mail's library with `test-hooks` (its dev-dependency on itself) in
# core/target/release/deps; the archive the app links is not replaced, and
# cargo rebuilds that library without the feature on the next gen-bindings.sh.
TESTBIN="$(cargo test --manifest-path "$MANIFEST" --target-dir "$TARGET_DIR" --release -p brev-mail --lib --no-run --message-format=json \
  | sed -n 's/.*"executable":"\([^"]*\)".*/\1/p')"
if [[ ! -f "$TESTBIN" ]]; then
  echo "error: no release test binary of brev-mail found" >&2
  exit 1
fi
SYMBOLS="$(nm "$TESTBIN")"
if ! grep -q "zeroizing_alloc5WIPER" <<<"$SYMBOLS"; then
  echo "error: brev-mail's global allocator is not zeroizing_alloc::ZeroAlloc" >&2
  exit 1
fi
# The control of gen-bindings.sh's check that the app's archive has no test
# hooks: the same pattern (TEST_HOOKS there) finds them in this test build.
if ! grep -Eq 'MockTransport|live_plaintexts|_for_test' <<<"$SYMBOLS"; then
  echo "error: the test-hooks pattern finds nothing in brev-mail's test binary; fix the check in scripts/gen-bindings.sh" >&2
  exit 1
fi

# The two Phase 3 crates in the app's graph keep exactly the features the
# design allows (docs/PHASE3_DESIGN.md §3.3, §5.1): p256 with only `ecdsa`
# (what it implies: arithmetic, digest, ecdsa-core, sha2, sha256; no
# SigningKey helpers beyond ecdsa's, no PEM, no serde), and reqwest with only
# `blocking` (no TLS, no system proxy, no JSON, no cookies). Every line of the
# crate must match, and each must be found.
echo "==> p256 and reqwest features in brev-mail"
for pin in 'p256 v[^ ]+ \[arithmetic,digest,ecdsa,ecdsa-core,sha2,sha256\]' 'reqwest v[^ ]+ \[blocking\]'; do
  crate="${pin%% *}"
  LINES="$(grep -E "(^|[^a-z0-9_-])$crate v" <<<"$FEATURES" || true)"
  if [[ -z "$LINES" ]] || grep -Evq "(^|[^a-z0-9_-])$pin( |\$)" <<<"$LINES"; then
    echo "error: $crate in brev-mail's graph has other features than docs/PHASE3_DESIGN.md allows:" >&2
    echo "${LINES:-(not found)}" >&2
    exit 1
  fi
done

# The app's archive has brev-vault's launch guard (brev-mail's default), the
# test archive below does not (docs/VAULT_SPLIT_PLAN.md §4, R7). The feature
# is the only difference between the two, so its cfg sites are counted: a
# new one fails here until it is reviewed and the count updated.
echo "==> launch guard: in the app's archive, not in the test archive; its cfg sites"
VAULT_FEATURES="$(grep -E '(^|[^a-z0-9_-])brev-vault v' <<<"$FEATURES" || true)"
if [[ -z "$VAULT_FEATURES" ]] || grep -Evq '\[[^]]*launch-guard' <<<"$VAULT_FEATURES"; then
  echo "error: brev-vault is built without launch-guard in brev-mail's default graph" >&2
  exit 1
fi
if cargo tree --manifest-path "$MANIFEST" -p brev-mail -e normal --no-default-features -f '{p} [{f}]' \
  | grep -E '(^|[^a-z0-9_-])brev-vault v' | grep -q 'launch-guard'; then
  echo "error: brev-vault has launch-guard in brev-mail's graph without default features (the test archive)" >&2
  exit 1
fi
GUARD_SITES="$(cd "$REPO_ROOT" && grep -rn 'feature = "launch-guard"' core/*/src || true)"
if [[ "$(grep -c . <<<"$GUARD_SITES")" != 2 ]]; then
  echo "error: expected 2 cfg sites of the launch-guard feature (launch.rs, its test in store/tests.rs), found:" >&2
  echo "$GUARD_SITES" >&2
  exit 1
fi

# brev-mail's allow-software-keys lets a letter go out in environment class
# C (software keys, no Touch ID; docs/VAULT_SPLIT_PLAN.md §6). Only the test
# archive has it: its marker is checked below, in gen-bindings.sh and in
# app/project.yml's build phase. Like the launch guard's, its cfg sites are
# counted (R7): a new one fails here until it is reviewed and the count
# updated.
echo "==> allow-software-keys: its cfg sites"
SOFT_SITES="$(cd "$REPO_ROOT" && grep -rn 'feature = "allow-software-keys"' core/*/src || true)"
if [[ "$(grep -c . <<<"$SOFT_SITES")" != 3 ]]; then
  echo "error: expected 3 cfg sites of allow-software-keys (the send threshold and the marker in ffi.rs, the refusal test in ffi/tests.rs), found:" >&2
  echo "$SOFT_SITES" >&2
  exit 1
fi

# brev-vault takes only the dependencies docs/VAULT_SPLIT_PLAN.md §4 lists:
# no network, no UniFFI, no mail crypto. The script checks its own control.
echo "==> brev-vault dependency whitelist"
"$REPO_ROOT/scripts/check-vault-deps.sh"

# Swift signs, Rust only verifies (docs/PHASE3_DESIGN.md §3.3): no production
# source makes a P-256 signing key. Test signers live in each crate's
# src/test_keys.rs (compiled only under cfg(test)) and in tests/. The control:
# the same grep finds the test signers.
echo "==> no SigningKey outside the test signers"
if (cd "$REPO_ROOT" && grep -rn 'SigningKey' core/*/src | grep -v '/src/test_keys\.rs:'); then
  echo "error: the lines above name SigningKey outside src/test_keys.rs (docs/PHASE3_DESIGN.md §3.3)" >&2
  exit 1
fi
if ! (cd "$REPO_ROOT" && grep -q 'SigningKey' core/brev-mail/src/test_keys.rs); then
  echo "error: the SigningKey grep finds nothing in core/brev-mail/src/test_keys.rs; fix the check" >&2
  exit 1
fi

if [[ "$DARWIN" == yes ]]; then
  # No String carries content across the FFI (docs/PHASE2_DESIGN.md §2.2;
  # docs/PHASE3_DESIGN.md §5.6). The only public functions with a String are
  # these three (the folder and the relay URL of create and open, and ping's
  # reply), and each must be found, so the grep cannot pass by matching
  # nothing.
  echo "==> FFI surface: no content String"
  ALLOWED_FUNCS=('func ping\(\) -> String' 'func create\(dir: String, relay: String, ' 'func `?open`?\(dir: String, relay: String\)')
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
  # The greps above see only declarations. Every value that crosses the FFI
  # goes through a FfiConverter type, so pin the whole surface (design §2.2;
  # docs/DECISIONS.md D-0064): every function Rust exports and every line
  # that names a converter must be listed in scripts/ffi-surface.txt, as
  # often as it occurs. A new export, argument, result, record field,
  # enum payload or type (a Vec<u16> brings a new FfiConverterSequenceUInt16)
  # changes a line and fails here until the list is reviewed and updated.
  # Content leaves Rust only as OpenText.chunk's 960-byte results; records
  # carry ids, metadata and identity codes (docs/PHASE3_DESIGN.md §5.6, §6.4).
  echo "==> FFI surface: every export and every converter use is listed"
  SURFACE_EXPECTED="$(grep -vE '^[[:space:]]*(#|$)' "$REPO_ROOT/scripts/ffi-surface.txt" | LC_ALL=C sort)"
  SURFACE_FOUND="$( { grep -oE 'uniffi_brev_core_fn_[a-z0-9_]+' "$BINDINGS" | LC_ALL=C sort -u
    grep -E 'FfiConverter' "$BINDINGS" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' | grep -v '^//'
    } | LC_ALL=C sort || true)"
  if [[ "$SURFACE_FOUND" != "$SURFACE_EXPECTED" ]]; then
    echo "error: the FFI surface in $BINDINGS differs from scripts/ffi-surface.txt (< listed, > found):" >&2
    diff <(printf '%s\n' "$SURFACE_EXPECTED") <(printf '%s\n' "$SURFACE_FOUND") >&2 || true
    exit 1
  fi

  # gen-bindings.sh just patched the bindings; the first line proves it.
  # Must equal MARKER in scripts/patch-bindings.py.
  echo "==> bindings patched"
  if [[ "$(head -n 1 "$BINDINGS")" != "// brev: patched by scripts/patch-bindings.py" ]]; then
    echo "error: $BINDINGS is not patched (scripts/patch-bindings.py did not run)" >&2
    exit 1
  fi

  # The test archive: brev-mail without its default features, so without
  # the launch guard, and with allow-software-keys, in its own target dir so
  # it never replaces the app's archive (docs/VAULT_SPLIT_PLAN.md §4, §6,
  # N4). The harness, the lock probe and the view host link it, since some
  # of their runs have no MallocScribble (the lock probe, the harness's
  # controls), and they send letters with software keys and no Touch ID
  # (environment class C). The control of the marker checks: the test
  # archive has the marker, the app's does not. Features must not change
  # the FFI: its bindings, patched, are the app's.
  echo "==> test archive (no launch guard, allow-software-keys), its marker and its bindings"
  TEST_ARCHIVE_DIR="$TARGET_DIR/test-archive"
  cargo build --manifest-path "$MANIFEST" --target-dir "$TEST_ARCHIVE_DIR" --release -p brev-mail \
    --no-default-features --features allow-software-keys
  if ! grep -aq BREV-ALLOW-SOFTWARE-KEYS "$TEST_ARCHIVE_DIR/release/libbrev_core.a"; then
    echo "error: the allow-software-keys marker is not in the test archive; fix the checks in scripts/gen-bindings.sh and app/project.yml" >&2
    exit 1
  fi
  if grep -aq BREV-ALLOW-SOFTWARE-KEYS "$STATICLIB"; then
    echo "error: the app's archive $STATICLIB has the allow-software-keys marker" >&2
    exit 1
  fi
  TEST_BINDINGS="$TEST_ARCHIVE_DIR/bindings"
  rm -rf "$TEST_BINDINGS"
  mkdir -p "$TEST_BINDINGS"
  NO_FORMAT=""
  if ! command -v swift-format >/dev/null 2>&1; then NO_FORMAT="--no-format"; fi
  # shellcheck disable=SC2086  # NO_FORMAT is empty or one flag, as in gen-bindings.sh
  cargo run --manifest-path "$MANIFEST" --target-dir "$TARGET_DIR" -p uniffi-bindgen -- generate \
    --library "$TEST_ARCHIVE_DIR/release/libbrev_core.dylib" --language swift \
    --config "$REPO_ROOT/core/uniffi-global.toml" --out-dir "$TEST_BINDINGS" $NO_FORMAT >/dev/null
  python3 "$REPO_ROOT/scripts/patch-bindings.py" "$TEST_BINDINGS/BrevCore.swift"
  for f in BrevCore.swift BrevCoreFFI.h BrevCoreFFI.modulemap; do
    if ! cmp "$TEST_BINDINGS/$f" "$REPO_ROOT/app/Generated/$f"; then
      echo "error: the test archive's $f differs from the app's: a feature changed the FFI" >&2
      exit 1
    fi
  done
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
# logging calls. URLSession and NSURLConnection (docs/PHASE3_DESIGN.md §5.5):
# the relay is reached only through brev-mail's client, so Swift never opens
# a second network path, which App Transport Security would govern.
echo "==> forbidden APIs in app/Sources"
FORBIDDEN=(NSPasteboard NSTextView NSTextField NSTextInputClient .characters 'String(decoding' 'NSString('
           'NSAttributedString(' CTTypesetter CTFramesetter NSAlert 'print(' servicesMenu
           'String(utf16CodeUnits' 'String(data' 'String(bytes' 'String(cString' 'String(validating'
           'String(utf8String' 'String(unsafeUninitializedCapacity' NSMutableString NSMutableAttributedString
           'CFStringCreateWithCharacters(' 'NSLog(' 'debugPrint(' 'dump(' 'os_log(' URLSession NSURLConnection)
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

# AVFoundation, CoreMedia and CoreVideo are approved only for the
# capture-protected content layer (CLAUDE.md §4; docs/DECISIONS.md D-0034),
# which is OpaqueView.swift. Grepping their imports cannot hold them there:
# `import AppKit` already brings in CoreVideo, and `import AVKit` or
# `import class AVFoundation.…` are other spellings. So no other file in
# app/Sources may name a symbol with their prefixes (AV, CM, CV, kCM, kCV),
# in code, strings or comments. The control: the same pattern finds the
# layer's own uses.
echo "==> AVFoundation, CoreMedia and CoreVideo only in the protected layer"
MEDIA='(^|[^A-Za-z0-9_])k?(AV|CM|CV)[A-Z][A-Za-z]'
LAYER=app/Sources/UI/OpaqueView.swift
if ! grep -Eq "$MEDIA" "$REPO_ROOT/$LAYER"; then
  echo "error: the media-symbol pattern finds nothing in $LAYER; fix the check" >&2
  exit 1
fi
if (cd "$REPO_ROOT" && grep -rnE "$MEDIA" app/Sources | grep -v "^$LAYER:"); then
  echo "error: the lines above name AVFoundation, CoreMedia or CoreVideo outside $LAYER (CLAUDE.md §4)" >&2
  exit 1
fi

# The oldest Xcode that builds Brev (the app uses macOS 15.2 SDK symbols) is
# stated three times: app/project.yml's xcodeVersion, the README and
# build.sh's install hint. They must agree.
echo "==> the Xcode minimum is stated alike"
XCODE_MIN="$(sed -nE 's/^[[:space:]]*xcodeVersion: "([0-9.]+)"$/\1/p' "$REPO_ROOT/app/project.yml")"
for f in README.md scripts/build.sh; do
  if [[ -z "$XCODE_MIN" ]] || ! grep -qF "Xcode $XCODE_MIN or newer" "$REPO_ROOT/$f"; then
    echo "error: $f does not say \"Xcode ${XCODE_MIN:-?} or newer\", the xcodeVersion of app/project.yml" >&2
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

# The relay the harness and the lock probe send letters through
# (docs/PHASE3_DESIGN.md §8): brev-relay on 127.0.0.1 with a port the OS
# picks and a fresh database under core/target, written to --port-file; the
# script waits for /v1/health and stops the relay when it ends, also on a
# failure (trap). Nothing listens anywhere but 127.0.0.1.
if [[ "$DARWIN" == yes ]]; then
  echo "==> relay for the harness and the lock probe (127.0.0.1, fresh database)"
  cargo build --manifest-path "$MANIFEST" --target-dir "$TARGET_DIR" --release -p brev-relay
  RELAY_DIR="$TARGET_DIR/test-relay"
  rm -rf "$RELAY_DIR"
  mkdir -p -m 700 "$RELAY_DIR"
  "$TARGET_DIR/release/brev-relay" serve --db "$RELAY_DIR/relay.db" --listen 127.0.0.1:0 \
    --port-file "$RELAY_DIR/port" 2>"$RELAY_DIR/relay.log" &
  RELAY_PID=$!
  trap 'kill "$RELAY_PID" 2>/dev/null || true; wait "$RELAY_PID" 2>/dev/null || true' EXIT
  for _ in $(seq 100); do
    [[ -s "$RELAY_DIR/port" ]] && break
    kill -0 "$RELAY_PID" 2>/dev/null || break
    sleep 0.1
  done
  PORT="$(cat "$RELAY_DIR/port" 2>/dev/null || true)"
  BREV_RELAY_URL="http://127.0.0.1:$PORT"
  if [[ ! "$PORT" =~ ^[0-9]+$ ]] || [[ "$(curl -sf --noproxy '*' --max-time 3 "$BREV_RELAY_URL/v1/health" || true)" != "brev-relay v1" ]]; then
    cat "$RELAY_DIR/relay.log" >&2 || true
    echo "error: the relay did not start on 127.0.0.1 (port '$PORT')" >&2
    exit 1
  fi
  echo "    $BREV_RELAY_URL"
else
  echo "==> relay skipped: not macOS ($(uname -s)); the harness and the lock probe need it"
fi

# The Swift heap-scan harness (docs/PHASE2_DESIGN.md §11): a CLI process, so
# no window and no prompt, built from app/Sources/Shared, the patched
# bindings and the test archive (the release build without the launch
# guard, with allow-software-keys). Every case runs five times and every run
# must pass: under MallocScribble=1, as the app runs (Info.plist
# LSEnvironment), except the two controls without scribbling. Case 6's
# proves that the glyph needle works and that scribbling is what clears the
# glyphs (it finds nothing at 200 units or less, so it runs at 4096 and
# 65000). Case 7's proves that the scribble probe SelfScan runs in the
# Verify build (docs/VERIFY.md V39) can fail: without scribbling, the freed
# block keeps its pattern. Cases 4, 5 and 8 send their letters through the
# relay above (BREV_RELAY_URL); case 8 is the network round trip of
# docs/PHASE3_DESIGN.md §8.
if [[ "$DARWIN" == yes ]]; then
  echo "==> Swift harness (app/Tests)"
  HARNESS_DIR="$TARGET_DIR/harness"
  rm -rf "$HARNESS_DIR"
  mkdir -p "$HARNESS_DIR/tmp"
  xcrun clang -O2 -Wall -target "$ARCH-apple-macos14.0" -c "$REPO_ROOT/app/Tests/scan.c" -o "$HARNESS_DIR/scan.o"
  xcrun swiftc -O -swift-version 5 -target "$ARCH-apple-macos14.0" \
    -import-objc-header "$REPO_ROOT/app/Tests/bridging.h" -I "$REPO_ROOT/app/Generated" \
    "$REPO_ROOT"/app/Sources/Shared/*.swift "$BINDINGS" "$REPO_ROOT"/app/Tests/*.swift \
    "$HARNESS_DIR/scan.o" "$TEST_ARCHIVE_DIR/release/libbrev_core.a" -o "$HARNESS_DIR/harness"
  # run_harness <label> <scribble|none> <harness arguments...>
  # A case may skip a part this Mac cannot run (design §11) and still pass;
  # its "skip ..." lines are shown under the result, never hidden.
  run_harness() {
    local label="$1" mode="$2" i out skips=""
    shift 2
    local env_args=(TMPDIR="$HARNESS_DIR/tmp/" BREV_RELAY_URL="$BREV_RELAY_URL")
    if [[ "$mode" == scribble ]]; then env_args+=(MallocScribble=1); else env_args=(-u MallocScribble "${env_args[@]}"); fi
    for i in 1 2 3 4 5; do
      if ! out="$(env "${env_args[@]}" "$HARNESS_DIR/harness" "$@" 2>&1)"; then
        echo "$out"
        echo "error: harness $label failed in run $i of 5" >&2
        exit 1
      fi
      skips+="$(grep '^skip ' <<<"$out" || true)"$'\n'
    done
    echo "    $label: 5 of 5 passed"
    sort -u <<<"$skips" | sed '/^$/d; s/^/      /'
  }
  run_harness "case 1 (units)" scribble units
  run_harness "case 2 (InputFilter, LockState, UnlockFailure, LaunchGuard)" scribble shell
  run_harness "case 2 (EditModel, ComposeKey, KeyTranslator)" scribble compose
  run_harness "case 3 (DEK hand-off, ECIES needles)" scribble dek
  for n in 64 200 4096 65000; do
    run_harness "case 4 (content path, $n units)" scribble content "$n"
  done
  run_harness "case 5 (kept OpenText after lock)" scribble kept
  run_harness "case 6 (a live String is seen)" scribble control
  for n in 4096 65000; do
    run_harness "case 6 (no scribbling: glyphs left, $n units)" none content "$n" --no-scribble
  done
  run_harness "case 7 (scribble probe)" scribble scribble
  run_harness "case 7 (no scribbling: the freed block is kept)" none scribble --no-scribble
  run_harness "case 8 (network round trip through the relay)" scribble network
else
  echo "==> Swift harness skipped: not macOS ($(uname -s))"
fi

# The lock probe (app/Tests/Lock): the app's own BrevApplication,
# LockController, UnlockService and content views, which the harness
# (Shared/ only) cannot reach. A CLI process built from
# app/Sources/{Shared,App,UI,Keys} and the test archive: no window on
# screen, no prompt, no keychain (software keys, which it reports to Rust as
# they are; UnlockService gets a KeyStore subclass), and no
# event posted but to itself. Its letters come through the relay above. It
# checks that a synthetic key BrevApplication drops does not move the idle
# clock (in sendEvent, and in nextEvent with a key posted to itself; that
# part is skipped, and says so, if the process may not post events), that a
# discarded unlock and the lock sequence lock the Rust session, that the
# lock sequence zeroes every content view's pixel buffers, that draw(_:) of
# a content view draws nothing, and that UnlockService locks Rust when its
# closure fails after Brev.unlock.
if [[ "$DARWIN" == yes ]]; then
  echo "==> lock probe (app/Tests/Lock)"
  LOCK_DIR="$TARGET_DIR/lock-probe"
  rm -rf "$LOCK_DIR"
  mkdir -p "$LOCK_DIR/tmp"
  xcrun swiftc -O -swift-version 5 -target "$ARCH-apple-macos14.0" \
    -import-objc-header "$REPO_ROOT/app/Tests/bridging.h" -I "$REPO_ROOT/app/Generated" \
    "$REPO_ROOT"/app/Sources/Shared/*.swift "$REPO_ROOT"/app/Sources/App/*.swift \
    "$REPO_ROOT"/app/Sources/UI/*.swift "$REPO_ROOT"/app/Sources/Keys/*.swift \
    "$BINDINGS" "$REPO_ROOT/app/Tests/Lock/main.swift" "$TEST_ARCHIVE_DIR/release/libbrev_core.a" -o "$LOCK_DIR/lock-probe"
  if ! out="$(env TMPDIR="$LOCK_DIR/tmp/" BREV_RELAY_URL="$BREV_RELAY_URL" "$LOCK_DIR/lock-probe" 2>&1)"; then
    echo "$out"
    echo "error: the lock probe failed" >&2
    exit 1
  fi
  echo "    $(grep -c '^ok ' <<<"$out") checks passed"
  grep -E '^(skip|note) ' <<<"$out" | sed 's/^/      /' || true
else
  echo "==> lock probe skipped: not macOS ($(uname -s))"
fi

# The view host (tools/viewhost): Brev's mail window with fake letters, for
# screenshots, AX dumps and its own checks. Compiled here so it keeps up
# with app/Sources; never run here (it opens a window), never linked into
# Brev.app.
if [[ "$DARWIN" == yes ]]; then
  echo "==> view host (tools/viewhost, compile only)"
  "$REPO_ROOT/tools/viewhost/build.sh" >/dev/null
else
  echo "==> view host skipped: not macOS ($(uname -s))"
fi

# The verification tools of docs/VERIFY.md (tools/verify): type-checked so
# they keep up with app/Sources (TouchIDProbe compiles Brev's Keys/ and
# Shared/ code). Never built or run here; tools/verify/build.sh builds them,
# and nothing in them is linked into Brev.app.
if [[ "$DARWIN" == yes ]]; then
  echo "==> verification tools (tools/verify, type-check only)"
  "$REPO_ROOT/tools/verify/build.sh" --check
  # capture-probe's verdict rules (V5 to V7): one line of letter text in a
  # pane counts as content at any window size, a captured window with no
  # known pane or an empty window image without its control is INVALID, and
  # the cuts never default to the current directory. Drawn panes only: no
  # window, no capture, no permission.
  echo "==> capture-probe --selftest"
  mkdir -p "$TARGET_DIR/verify-selftest"
  xcrun swiftc -suppress-warnings -swift-version 5 -target "$ARCH-apple-macos14.0" \
    "$REPO_ROOT/tools/verify/capture-probe.swift" -o "$TARGET_DIR/verify-selftest/capture-probe"
  "$TARGET_DIR/verify-selftest/capture-probe" --selftest
else
  echo "==> verification tools skipped: not macOS ($(uname -s))"
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
  # scripts/build.sh. -allowProvisioningUpdates: team signing (D-0035), as
  # in build.sh.
  echo "==> xcodebuild (Debug compile check, $ARCH)"
  xcodebuild -project "$REPO_ROOT/app/Brev.xcodeproj" -allowProvisioningUpdates -scheme Brev -configuration Debug \
    -destination "platform=macOS,arch=$ARCH" ONLY_ACTIVE_ARCH=YES build
fi

echo "==> all checks passed"
