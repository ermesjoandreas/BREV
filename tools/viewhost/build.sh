#!/usr/bin/env bash
# Builds ViewHost.app: Brev's mail window with fake letters, for screenshots,
# AX dumps and the in-process checks in tools/viewhost/main.swift. A test
# app only, never linked into Brev.app. It compiles app/Sources/{Shared,App,UI}
# with the patched bindings, the release archive and the heap scanner of the
# CLI harness (app/Tests/scan.c), and uses no keychain and no Touch ID. As the
# Verify build, it also compiles app/Sources/Verify/SelfScan.swift with
# BREV_SELFSCAN, so its lock sequence runs SelfScan (docs/VERIFY.md V39).
#
# Usage: tools/viewhost/build.sh [output dir]   (default: core/target/viewhost)
# Needs the archive and bindings from scripts/gen-bindings.sh (test.sh runs
# it first). Prints the path of the executable. Run it from a terminal, e.g.
#   env MallocScribble=1 "$(tools/viewhost/build.sh)" --scan --snapshot /tmp/shots
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STATICLIB="$REPO_ROOT/core/target/release/libbrev_core.a"
BINDINGS="$REPO_ROOT/app/Generated/BrevCore.swift"
OUT="${1:-$REPO_ROOT/core/target/viewhost}"
APP="$OUT/ViewHost.app"

for f in "$STATICLIB" "$BINDINGS"; do
  if [[ ! -f "$f" ]]; then
    echo "error: $f is missing; run scripts/gen-bindings.sh first" >&2
    exit 1
  fi
done
# The arch the Rust archive was built for, as in scripts/test.sh.
ARCH="$(lipo -archs "$STATICLIB")"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources/nb.lproj"
cp "$REPO_ROOT/app/Sources/nb.lproj/Localizable.strings" "$APP/Contents/Resources/nb.lproj/"
cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key><string>no.brev.viewhost</string>
  <key>CFBundleName</key><string>ViewHost</string>
  <key>CFBundleExecutable</key><string>ViewHost</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleDevelopmentRegion</key><string>nb</string>
  <key>NSPrincipalClass</key><string>BrevApplication</string>
</dict>
</plist>
PLIST

xcrun clang -O2 -Wall -target "$ARCH-apple-macos14.0" -c "$REPO_ROOT/app/Tests/scan.c" -o "$OUT/scan.o"
xcrun swiftc -O -swift-version 5 -target "$ARCH-apple-macos14.0" -D BREV_SELFSCAN \
  -import-objc-header "$REPO_ROOT/app/Tests/bridging.h" -I "$REPO_ROOT/app/Generated" \
  "$REPO_ROOT"/app/Sources/Shared/*.swift "$REPO_ROOT"/app/Sources/App/*.swift "$REPO_ROOT"/app/Sources/UI/*.swift \
  "$REPO_ROOT/app/Sources/Verify/SelfScan.swift" \
  "$BINDINGS" "$REPO_ROOT/tools/viewhost/main.swift" "$OUT/scan.o" "$STATICLIB" \
  -o "$APP/Contents/MacOS/ViewHost"
codesign --force --sign - "$APP" >/dev/null 2>&1
echo "$APP/Contents/MacOS/ViewHost"
