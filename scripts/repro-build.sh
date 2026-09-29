#!/usr/bin/env bash
# Reproducible build check (CLAUDE.md §5 Phase 5; docs/REPRODUCIBLE_BUILD.md).
# Exports one commit twice (git archive, so no untracked or uncommitted file
# gets in) into two temp folders, builds the Rust archive and archives the
# Release app in each with the same toolchain, and compares:
#   - core/target/release/libbrev_core.a, byte for byte
#   - Brev.app/Contents/MacOS/Brev, byte for byte, on copies whose
#     signature is replaced by an ad-hoc one and then removed
# The other files in the bundle are compared for information only.
#
# Usage: scripts/repro-build.sh [--commit <rev>] [--against <Brev.app>] [--keep]
#   --commit <rev>        the commit to build (default: HEAD)
#   --against <Brev.app>  also compare this app's executable (a downloaded,
#                         signed Brev.app) with the rebuild, signatures removed
#   --keep                keep the build folders (default: deleted when all match)
# REPRO_WORK=<dir> puts the build folders in <dir> (default: a mktemp folder).
# Exits 0 when everything compared is identical, 1 when not.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMMIT=HEAD
KEEP=no
AGAINST=
while [[ $# -gt 0 ]]; do
  case "$1" in
    --commit)
      [[ -n "${2:-}" ]] || { echo "error: --commit takes a revision" >&2; exit 2; }
      COMMIT="$2"; shift ;;
    --against)
      [[ -f "${2:-}/Contents/MacOS/Brev" ]] || { echo "error: --against takes a Brev.app (no Contents/MacOS/Brev in '${2:-}')" >&2; exit 2; }
      AGAINST="$(cd "$2" && pwd -P)"; shift ;;
    --keep) KEEP=yes ;;
    -h|--help) sed -n '2,17p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "error: unknown argument '$1' (accepted: --commit <rev>, --against <Brev.app>, --keep)" >&2; exit 2 ;;
  esac
  shift
done

if [[ "$(uname -s)" != Darwin ]]; then
  echo "error: scripts/repro-build.sh needs macOS and Xcode (it builds Brev.app)." >&2
  exit 1
fi
for tool in git cargo python3 xcodegen xcodebuild lipo codesign shasum; do
  command -v "$tool" >/dev/null 2>&1 || { echo "error: '$tool' not found (see README.md)" >&2; exit 1; }
done

COMMIT="$(git -C "$REPO_ROOT" rev-parse --verify "$COMMIT^{commit}")"
# The commit time, not the wall clock: the same commit gives the same value
# on every machine. Read by clang (__DATE__, __TIME__) and by any build
# script that honours it.
SOURCE_DATE_EPOCH="$(git -C "$REPO_ROOT" log -1 --format=%ct "$COMMIT")"
export SOURCE_DATE_EPOCH
# ar, libtool and ld64 write 0 instead of file times (archive members and
# the debug map's object entries).
export ZERO_AR_DATE=1
CARGO_HOME_DIR="$(cd "${CARGO_HOME:-$HOME/.cargo}" && pwd -P)"
# With rustup's rust-src component installed, rustc names std's sources by
# their local path ($HOME/.rustup/...) in the panic locations of std code
# inlined into Brev's crates; without it, by /rustc/<commit>/. Mapping the
# first to the second makes both machines emit the same bytes.
RUST_SRC="$(rustc --print sysroot)/lib/rustlib/src/rust"
RUST_COMMIT="$(rustc -vV | awk '/^commit-hash:/ {print $2}')"

if [[ -n "${REPRO_WORK:-}" ]]; then
  mkdir -p "$REPRO_WORK"
  WORK="$(cd "$REPRO_WORK" && pwd -P)"
  OWN_WORK=no
else
  WORK="$(cd "$(mktemp -d -t brev-repro)" && pwd -P)"
  OWN_WORK=yes
fi
for side in a b; do
  if [[ -e "$WORK/$side" ]]; then
    echo "error: $WORK/$side exists; remove it or pick another REPRO_WORK" >&2
    exit 1
  fi
done

echo "==> Reproducible build of $COMMIT"
echo "    work folder:        $WORK"
echo "    SOURCE_DATE_EPOCH:  $SOURCE_DATE_EPOCH"
echo "    rustc:              $(rustc -V)"
echo "    cargo:              $(cargo -V)"
echo "    xcodebuild:         $(xcodebuild -version | tr '\n' ' ')"
echo "    xcodegen:           $(xcodegen --version)"
echo "    macOS:              $(sw_vers -productVersion) ($(sw_vers -buildVersion))"
if [[ -n "$(git -C "$REPO_ROOT" status --porcelain --untracked-files=no)" ]]; then
  echo "    note: the working tree has uncommitted changes; they are NOT in this build"
fi

# build_one <root>: export the commit to <root>/src and build it there, with
# Xcode's derived data in <root>/dd and the archive in <root>/Brev.xcarchive.
# Every absolute path under <root> is rewritten to /brev in what the
# compilers emit, so the two folders' names do not reach the outputs; so is
# CARGO_HOME (/cargo), so a build by someone else, whose crates sit under
# another home, can match.
# The app comes from `xcodebuild archive`, as a distributed build does
# (docs/DISTRIBUTION.md §3): Release, with the installed product stripped
# (STRIP_INSTALLED_PRODUCT). A plain `build` keeps the debug map, whose
# entries name the build folder (the Swift module's -add_ast_path, which
# Xcode passes itself and no prefix map rewrites), so it can never match
# across folders; the dSYM, which keeps those paths, is not compared.
# The app is built unsigned (CODE_SIGNING_ALLOWED=NO): no keychain, no
# provisioning profile, no network. The comparison ignores the signature
# anyway, and nobody but the owner can sign as team AV26DNQ5SC.
build_one() {
  local root="$1" src="$1/src" dd="$1/dd" log="$1/build.log"
  # Xcode standardizes /private/tmp/x and /private/var/x to /tmp/x and
  # /var/x (NSString's stringByStandardizingPath), so the Swift compiler and
  # clang see the folder without /private; cargo sees it with.
  local xroot="$root"
  case "$root" in /private/tmp/*|/private/var/*) xroot="${root#/private}" ;; esac
  mkdir -p "$src"
  git -C "$REPO_ROOT" archive --format=tar "$COMMIT" | tar -x -C "$src"
  echo "==> Building in $root (log: $log)"
  if ! (
    # Only the cargo step sees these: xcodebuild would take CFLAGS and
    # RUSTFLAGS from the environment as build settings.
    RUSTFLAGS="--remap-path-prefix=$root=/brev --remap-path-prefix=$CARGO_HOME_DIR=/cargo --remap-path-prefix=$RUST_SRC=/rustc/$RUST_COMMIT" \
    CFLAGS="-ffile-prefix-map=$root=/brev -ffile-prefix-map=$CARGO_HOME_DIR=/cargo" \
      "$src/scripts/gen-bindings.sh"
    xcodegen generate --spec "$src/app/project.yml" --project "$src/app"
    local arch
    arch="$(lipo -archs "$src/core/target/release/libbrev_core.a")"
    # ARCHS: archive ignores ONLY_ACTIVE_ARCH and would also link x86_64,
    # which the one-arch Rust archive cannot satisfy (see scripts/build.sh).
    # $(inherited) keeps project.yml's values; the flags only add the path
    # rewriting (Swift's #file strings, which Swift 5 mode makes full paths).
    xcodebuild archive \
      -project "$src/app/Brev.xcodeproj" \
      -scheme Brev \
      -configuration Release \
      -destination "platform=macOS,arch=$arch" \
      -derivedDataPath "$dd" \
      -archivePath "$root/Brev.xcarchive" \
      ARCHS="$arch" \
      ONLY_ACTIVE_ARCH=YES \
      CODE_SIGNING_ALLOWED=NO \
      COMPILER_INDEX_STORE_ENABLE=NO \
      "OTHER_SWIFT_FLAGS=\$(inherited) -file-prefix-map $xroot=/brev -file-prefix-map $root=/brev" \
      "OTHER_CFLAGS=\$(inherited) -ffile-prefix-map=$xroot=/brev -ffile-prefix-map=$root=/brev"
  ) >"$log" 2>&1; then
    tail -n 40 "$log" >&2
    echo "error: the build in $root failed (full log: $log)" >&2
    exit 1
  fi
}

build_one "$WORK/a"
build_one "$WORK/b"

LIB_A="$WORK/a/src/core/target/release/libbrev_core.a"
LIB_B="$WORK/b/src/core/target/release/libbrev_core.a"
APP_A="$WORK/a/Brev.xcarchive/Products/Applications/Brev.app"
APP_B="$WORK/b/Brev.xcarchive/Products/Applications/Brev.app"
CMP="$WORK/compare"
mkdir -p "$CMP"
for f in "$LIB_A" "$LIB_B" "$APP_A/Contents/MacOS/Brev" "$APP_B/Contents/MacOS/Brev"; do
  [[ -f "$f" ]] || { echo "error: the build did not produce $f" >&2; exit 1; }
done

sha() { shasum -a 256 "$1" | cut -d' ' -f1; }

# leaks <file>: how many times <file> names the work folder (with or without
# /private) or the home folder, which a reproducible output must not do.
# grep, not strings: Apple's strings skips the symbol table's strings.
leaks() {
  { LC_ALL=C grep -a -o -F -e "${WORK#/private}" -e "$HOME" "$1" || true; } | grep -c . || true
}

RESULT=0

# The Rust archive.
echo
echo "==> libbrev_core.a"
echo "    a: $(sha "$LIB_A")  paths leaked: $(leaks "$LIB_A")"
echo "    b: $(sha "$LIB_B")  paths leaked: $(leaks "$LIB_B")"
if cmp -s "$LIB_A" "$LIB_B"; then
  echo "    IDENTICAL"
else
  echo "    DIFFERENT ($(cmp -l "$LIB_A" "$LIB_B" 2>/dev/null | grep -c . || true) bytes differ; sizes $(wc -c <"$LIB_A" | tr -d ' ') / $(wc -c <"$LIB_B" | tr -d ' '))"
  RESULT=1
  # Which members differ: each archive unpacked into its own folder.
  for side in a b; do
    mkdir -p "$CMP/lib-$side"
    lib="$WORK/$side/src/core/target/release/libbrev_core.a"
    (cd "$CMP/lib-$side" && ar -x "$lib")
  done
  echo "    members that differ (first 20):"
  (cd "$CMP/lib-a" && find . -type f | LC_ALL=C sort) | while read -r m; do
    if ! cmp -s "$CMP/lib-a/$m" "$CMP/lib-b/$m" 2>/dev/null; then echo "      ${m#./}"; fi
  done | head -n 20
fi

# The app's executable, without its signature. unsigned_copy <exe> <out>:
# a copy of <exe>, signed ad hoc and then stripped of that signature.
# `codesign --remove-signature` alone is not enough: it leaves __LINKEDIT's
# vmsize as the removed signature needed it, so a Developer ID signature and
# the linker's ad-hoc one (Xcode's unsigned build still has it on arm64)
# leave different bytes. Replacing either with the same ad-hoc signature
# first makes the result depend on the code only. Ad-hoc signing uses no
# key and no keychain.
unsigned_copy() {
  cp "$1" "$2"
  codesign --force --sign - "$2" 2>/dev/null
  codesign --remove-signature "$2"
}
echo
echo "==> Brev.app/Contents/MacOS/Brev (signature removed)"
for side in a b; do
  unsigned_copy "$WORK/$side/Brev.xcarchive/Products/Applications/Brev.app/Contents/MacOS/Brev" "$CMP/Brev-$side"
done
for side in a b; do
  echo "    $side: $(sha "$CMP/Brev-$side")  LC_UUID $(dwarfdump --uuid "$CMP/Brev-$side" | awk '{print $2}' | head -n 1)  paths leaked: $(leaks "$CMP/Brev-$side")"
done
if cmp -s "$CMP/Brev-a" "$CMP/Brev-b"; then
  echo "    IDENTICAL"
else
  echo "    DIFFERENT ($(cmp -l "$CMP/Brev-a" "$CMP/Brev-b" 2>/dev/null | grep -c . || true) bytes differ; sizes $(wc -c <"$CMP/Brev-a" | tr -d ' ') / $(wc -c <"$CMP/Brev-b" | tr -d ' '))"
  RESULT=1
fi
if [[ -n "$AGAINST" ]]; then
  unsigned_copy "$AGAINST/Contents/MacOS/Brev" "$CMP/Brev-against"
  echo "    $AGAINST: $(sha "$CMP/Brev-against")"
  if cmp -s "$CMP/Brev-a" "$CMP/Brev-against"; then
    echo "    IDENTICAL to the rebuild"
  else
    echo "    DIFFERENT from the rebuild"
    RESULT=1
  fi
fi

# The rest of the bundle, for information: Info.plist, resources, and the
# signature folder of the linker's ad-hoc signature if there is one.
echo
echo "==> Other files in Brev.app (information only)"
(cd "$APP_A" && find . -type f ! -path ./Contents/MacOS/Brev | LC_ALL=C sort) >"$CMP/files-a"
(cd "$APP_B" && find . -type f ! -path ./Contents/MacOS/Brev | LC_ALL=C sort) >"$CMP/files-b"
if ! cmp -s "$CMP/files-a" "$CMP/files-b"; then
  echo "    the two bundles hold different files:"
  diff "$CMP/files-a" "$CMP/files-b" | sed 's/^/      /' || true
fi
while read -r f; do
  if [[ -f "$APP_B/$f" ]] && cmp -s "$APP_A/$f" "$APP_B/$f"; then
    echo "    identical  ${f#./}"
  else
    echo "    DIFFERENT  ${f#./}"
  fi
done <"$CMP/files-a"

echo
if [[ "$RESULT" -eq 0 ]]; then
  echo "==> REPRODUCIBLE: libbrev_core.a and the unsigned Brev executable are identical in both builds${AGAINST:+, and to $AGAINST}"
  if [[ "$KEEP" == no ]]; then
    rm -rf "$WORK/a" "$WORK/b" "$CMP"
    [[ "$OWN_WORK" == yes ]] && rmdir "$WORK" 2>/dev/null || true
  else
    echo "    kept: $WORK"
  fi
else
  echo "==> NOT REPRODUCIBLE: see DIFFERENT above; both builds are kept in $WORK"
fi
exit "$RESULT"
