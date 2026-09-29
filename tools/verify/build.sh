#!/usr/bin/env bash
# Builds the verification tools of docs/VERIFY.md ("Tools") and the Verify
# build of Brev. Tools only, never linked into Brev.app
# (docs/DECISIONS.md D-0051): they are separate executables in the
# output folder, and Brev's Xcode project does not name this folder.
#
#   capture-probe, capture-probe-26   V5 to V7 (screen capture paths)
#   windows                           V5, V9 (window list, sharing state)
#   axdump                            V11, V13 (AX tree, AX presses)
#   poster                            V32, V33 (synthetic keys and clicks)
#   keylisten                         V31 (listen-only tap + IOHIDManager)
#   padcheck                          V18 (padded column lengths)
#   InputLab.app                      the input spike's lab (design §14.2 U2)
#   TouchIDProbe.app                  V51 (Brev's unlock closure, needles);
#                                     team-signed with Brev's bundle id
#   TouchIDProbe.app, scrub 0 and 128 V51's negative control and next depth
#                                     (design §14.2 K): core/ copied and
#                                     brev-mail built with the unlock's deep scrub
#                                     disabled and at 128 KiB
#   Brev.app, configuration Verify    V1, V2, V39, V50 ($VAPP)
#
# Usage: tools/verify/build.sh [--tools | --check] [output dir]
#   (default)  everything above; runs scripts/gen-bindings.sh and xcodegen
#              first, as scripts/build.sh does
#   --tools    everything but the Verify build of Brev (needs the archive
#              and bindings from scripts/gen-bindings.sh)
#   --check    type-check every tool's sources and find the one line the
#              scrub variants change, build nothing; what scripts/test.sh
#              runs, so the tools keep up with app/Sources and core/
# The output folder defaults to core/target/verify. At the end it prints
#   T=<the tools' folder>  and  VAPP=<the Verify Brev.app>
# which docs/VERIFY.md's setup block uses. macOS only.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="$REPO_ROOT/tools/verify"
STATICLIB="$REPO_ROOT/core/target/release/libbrev_core.a"
BINDINGS="$REPO_ROOT/app/Generated/BrevCore.swift"

MODE=all
OUT=""
for arg in "$@"; do
  case "$arg" in
    --tools) MODE=tools ;;
    --check) MODE=check ;;
    -h|--help) sed -n '2,32p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "error: unknown argument '$arg' (accepted: --tools, --check, an output folder)" >&2; exit 2 ;;
    *) OUT="$arg" ;;
  esac
done
OUT="${OUT:-$REPO_ROOT/core/target/verify}"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: tools/verify/build.sh only runs on macOS." >&2
  exit 1
fi
if [[ "$MODE" == all ]]; then
  "$REPO_ROOT/scripts/gen-bindings.sh"
  echo "==> xcodegen generate (Brev)"
  xcodegen generate --spec "$REPO_ROOT/app/project.yml" --project "$REPO_ROOT/app"
fi
for f in "$STATICLIB" "$BINDINGS"; do
  if [[ ! -f "$f" ]]; then
    echo "error: $f is missing; run scripts/gen-bindings.sh first" >&2
    exit 1
  fi
done
# The arch the Rust archive was built for, as in scripts/build.sh.
ARCH="$(lipo -archs "$STATICLIB")"
T14="$ARCH-apple-macos14.0"
mkdir -p "$OUT"

# The sources of each tool. TouchIDProbe compiles Brev's own Keys/ and
# Shared/ code, L10n, the harness's ECIES sender and heap scanner, and the
# bindings; InputLab is the input spike's lab, unchanged.
PROBE_SOURCES=("$HERE/touchid-probe/main.swift" "$REPO_ROOT"/app/Sources/Shared/*.swift "$REPO_ROOT"/app/Sources/Keys/*.swift
               "$REPO_ROOT/app/Sources/App/L10n.swift" "$REPO_ROOT/app/Tests/ecies_needles.swift" "$BINDINGS")
LAB="$HERE/spikes/input/src"
# The one line of scrub_stack_deep that V51's variants change (the depth). It
# is in brev-vault; brev-mail's archive links it.
CRYPTO="$REPO_ROOT/core/brev-vault/src/crypto.rs"
SCRUB_LINE='let mut buf = [0xA5u8; 64 * 1024];'

if [[ "$MODE" == check ]]; then
  if [[ "$(grep -cF "$SCRUB_LINE" "$CRYPTO")" != 1 ]]; then
    echo "error: $CRYPTO no longer has exactly one '$SCRUB_LINE' (scrub_stack_deep); update V51's scrub variants in tools/verify/build.sh" >&2
    exit 1
  fi
  # One swiftc per tool, in parallel; each prints its own errors. Warnings
  # are errors (CLAUDE.md §5 Phase 5), except in capture-probe: it calls the
  # CoreGraphics captures that macOS 14 deprecates, on purpose (V7), and its
  # two deprecation warnings are not shown here. Swift 6.0 (Xcode 16.2) has
  # no switch for one warning group, and a nominal type cannot call
  # legacyCG() (it captures the script's globals), so -suppress-warnings
  # stays, for this one file.
  pids=()
  for t in windows axdump keylisten padcheck; do
    xcrun swiftc -typecheck -warnings-as-errors -swift-version 5 -target "$T14" "$HERE/$t.swift" & pids+=($!)
  done
  xcrun swiftc -typecheck -suppress-warnings -swift-version 5 -target "$T14" "$HERE/capture-probe.swift" & pids+=($!)
  xcrun swiftc -typecheck -warnings-as-errors -swift-version 5 -target "$ARCH-apple-macos26.0" "$HERE/capture-probe-26.swift" & pids+=($!)
  xcrun swiftc -typecheck -warnings-as-errors -swift-version 5 -target "$T14" -import-objc-header "$HERE/poster-shim.h" "$HERE/poster.swift" & pids+=($!)
  xcrun swiftc -typecheck -warnings-as-errors -swift-version 5 -target "$T14" -import-objc-header "$LAB/bridging.h" "$LAB/lab.swift" & pids+=($!)
  xcrun swiftc -typecheck -warnings-as-errors -swift-version 5 -target "$T14" -import-objc-header "$REPO_ROOT/app/Tests/bridging.h" \
    -I "$REPO_ROOT/app/Generated" -I "$REPO_ROOT/app/Tests" "${PROBE_SOURCES[@]}" & pids+=($!)
  failed=0
  for p in "${pids[@]}"; do wait "$p" || failed=1; done
  if [[ "$failed" != 0 ]]; then
    echo "error: a tool in tools/verify no longer type-checks (see above)" >&2
    exit 1
  fi
  echo "tools/verify: every tool type-checks"
  exit 0
fi

echo "==> CLI tools ($ARCH) -> $OUT"
# capture-probe prints two warnings that legacyCG() and cgDisplayStream()
# are deprecated in macOS 14.0: V7 calls those APIs on purpose.
for t in capture-probe windows axdump keylisten padcheck; do
  xcrun swiftc -O -swift-version 5 -target "$T14" "$HERE/$t.swift" -o "$OUT/$t"
done
# Built for 26.0: CGDisplayStream is obsoleted for that target and reached
# through dlsym (V7).
xcrun swiftc -O -swift-version 5 -target "$ARCH-apple-macos26.0" "$HERE/capture-probe-26.swift" -o "$OUT/capture-probe-26"
xcrun clang -O2 -Wall -target "$T14" -c "$HERE/poster-shim.c" -o "$OUT/poster-shim.o"
xcrun swiftc -O -swift-version 5 -target "$T14" -import-objc-header "$HERE/poster-shim.h" \
  "$HERE/poster.swift" "$OUT/poster-shim.o" -o "$OUT/poster"

echo "==> InputLab.app (the input spike's lab: ad-hoc, Hardened Runtime, App Sandbox only)"
APP="$OUT/InputLab.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
xcrun clang -O2 -target "$T14" -c "$LAB/scan.c" -o "$OUT/inputlab-scan.o"
xcrun swiftc -O -swift-version 5 -target "$T14" -module-name InputLab -import-objc-header "$LAB/bridging.h" \
  "$LAB/lab.swift" "$OUT/inputlab-scan.o" -o "$APP/Contents/MacOS/InputLab"
cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>no.brev.spike.input</string>
<key>CFBundleName</key><string>InputLab</string>
<key>CFBundleExecutable</key><string>InputLab</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.0.1</string>
<key>CFBundleVersion</key><string>1</string>
<key>LSMinimumSystemVersion</key><string>14.0</string>
<key>NSPrincipalClass</key><string>InputLab.LabApp</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
cat > "$OUT/inputlab.entitlements" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>com.apple.security.app-sandbox</key><true/></dict></plist>
PLIST
codesign --force --sign - --options runtime --entitlements "$OUT/inputlab.entitlements" "$APP" >/dev/null 2>&1

# Team-signed with Brev's bundle id and keychain group (D-0035), like Brev:
# automatic signing, so xcodebuild may fetch or renew the profile.
echo "==> TouchIDProbe.app (team-signed, Brev's bundle id and keychain group)"
xcodegen generate --spec "$HERE/touchid-probe/project.yml" --project "$HERE/touchid-probe"
xcodebuild -project "$HERE/touchid-probe/TouchIDProbe.xcodeproj" -allowProvisioningUpdates -scheme TouchIDProbe \
  -configuration Release -destination "platform=macOS,arch=$ARCH" -derivedDataPath "$OUT/touchid-probe" \
  ONLY_ACTIVE_ARCH=YES build -quiet
PROBE="$OUT/touchid-probe/Build/Products/Release/TouchIDProbe.app"
[[ -d "$PROBE" ]] || { echo "error: $PROBE is missing" >&2; exit 1; }

# V51's variants (design §14.2 K): the same probe linked against brev-mail
# with the unlock's deep scrub at 0 KiB (disabled: the negative control) and
# at 128 KiB. Built from a copy of core/ with only that depth changed, in its
# own target folder: core/ and the archive Brev links stay untouched.
SCRUB_CORE="$OUT/scrub-core"
mkdir -p "$SCRUB_CORE"
rsync -a --delete --exclude /target "$REPO_ROOT/core/" "$SCRUB_CORE/src/"
PROBES=("$PROBE")
for kib in 0 128; do
  echo "==> TouchIDProbe.app with the unlock's deep scrub at $kib KiB"
  sed "s/\[0xA5u8; 64 \* 1024\]/[0xA5u8; $kib * 1024]/" "$CRYPTO" > "$SCRUB_CORE/src/brev-vault/src/crypto.rs"
  if [[ "$(grep -cF "let mut buf = [0xA5u8; $kib * 1024];" "$SCRUB_CORE/src/brev-vault/src/crypto.rs")" != 1 ]]; then
    echo "error: the scrub depth in the copy of crypto.rs was not changed to $kib KiB" >&2
    exit 1
  fi
  MACOSX_DEPLOYMENT_TARGET=14.0 cargo build --manifest-path "$SCRUB_CORE/src/Cargo.toml" --target-dir "$SCRUB_CORE/target" \
    --release -p brev-mail --quiet
  cp "$SCRUB_CORE/target/release/libbrev_core.a" "$SCRUB_CORE/libbrev_core-scrub$kib.a"
  xcodebuild -project "$HERE/touchid-probe/TouchIDProbe.xcodeproj" -allowProvisioningUpdates -scheme TouchIDProbe \
    -configuration Release -destination "platform=macOS,arch=$ARCH" -derivedDataPath "$OUT/touchid-probe-scrub$kib" \
    ONLY_ACTIVE_ARCH=YES BREV_CORE_ARCHIVE="$SCRUB_CORE/libbrev_core-scrub$kib.a" BREV_SCRUB_KIB="$kib" build -quiet
  P="$OUT/touchid-probe-scrub$kib/Build/Products/Release/TouchIDProbe.app"
  [[ "$(plutil -extract BrevScrubKiB raw "$P/Contents/Info.plist")" == "$kib" ]] || { echo "error: $P does not say $kib KiB" >&2; exit 1; }
  PROBES+=("$P")
done

VAPP=""
if [[ "$MODE" == all ]]; then
  # Release plus the self-scan (app/project.yml, configuration Verify).
  echo "==> Brev (Verify, $ARCH)"
  xcodebuild -project "$REPO_ROOT/app/Brev.xcodeproj" -allowProvisioningUpdates -scheme Brev -configuration Verify \
    -destination "platform=macOS,arch=$ARCH" -derivedDataPath "$REPO_ROOT/app/build" ONLY_ACTIVE_ARCH=YES build -quiet
  VAPP="$REPO_ROOT/app/build/Build/Products/Verify/Brev.app"
  [[ -d "$VAPP" ]] || { echo "error: $VAPP is missing" >&2; exit 1; }
fi

echo
printf 'TouchIDProbe: %s\n' "${PROBES[@]}"
echo "InputLab:     $APP"
echo "T=$OUT"
[[ -n "$VAPP" ]] && echo "VAPP=$VAPP"
exit 0
