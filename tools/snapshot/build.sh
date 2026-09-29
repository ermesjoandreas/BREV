#!/usr/bin/env bash
# Builds Snapshot.app: the offscreen snapshot tool of docs/UI_REDESIGN.md §5.
# A test app only, never linked into Brev.app and never signed with the
# team key (ad hoc, as ViewHost). It compiles app/Sources/{Shared,App,UI}
# and Keys/Attestor.swift (Session's attestor) with the patched bindings, the test archive (brev-mail without the launch guard and
# with allow-software-keys; built here in core/target/test-archive, as
# scripts/test.sh does) and tools/fixture/Fixture.swift (the relay, users
# with software keys, fake texts). No keychain, no Touch ID, no window on
# screen: the tool never orders a window in and never activates (§5.2).
# Its relay is core/target/release/brev-relay, named in the app's
# Info.plist (BrevRelayBinary); the tool starts and stops it.
#
# Usage: tools/snapshot/build.sh [output dir]   (default: core/target/snapshot)
# Needs the app's archive and bindings from scripts/gen-bindings.sh. Prints
# the path of the executable. Run that directly, never through `open`:
#   "$(tools/snapshot/build.sh)" --out tools/snapshots/out --appearance both
#   "$(tools/snapshot/build.sh)" --check
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STATICLIB="$REPO_ROOT/core/target/release/libbrev_core.a"
TEST_STATICLIB="$REPO_ROOT/core/target/test-archive/release/libbrev_core.a"
BINDINGS="$REPO_ROOT/app/Generated/BrevCore.swift"
OUT="${1:-$REPO_ROOT/core/target/snapshot}"
APP="$OUT/Snapshot.app"

for f in "$STATICLIB" "$BINDINGS"; do
  if [[ ! -f "$f" ]]; then
    echo "error: $f is missing; run scripts/gen-bindings.sh first" >&2
    exit 1
  fi
done
ARCH="$(lipo -archs "$STATICLIB")"
RELAY="$REPO_ROOT/core/target/release/brev-relay"
MACOSX_DEPLOYMENT_TARGET=14.0 cargo build --manifest-path "$REPO_ROOT/core/Cargo.toml" \
  --target-dir "$REPO_ROOT/core/target" --release -p brev-relay --quiet
MACOSX_DEPLOYMENT_TARGET=14.0 cargo build --manifest-path "$REPO_ROOT/core/Cargo.toml" \
  --target-dir "$REPO_ROOT/core/target/test-archive" --release -p brev-mail --no-default-features \
  --features allow-software-keys --quiet

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources/nb.lproj"
cp "$REPO_ROOT/app/Sources/nb.lproj/Localizable.strings" "$APP/Contents/Resources/nb.lproj/"
cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key><string>no.brev.snapshot</string>
  <key>CFBundleName</key><string>Snapshot</string>
  <key>CFBundleExecutable</key><string>Snapshot</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleDevelopmentRegion</key><string>nb</string>
  <key>NSPrincipalClass</key><string>BrevApplication</string>
  <key>LSUIElement</key><true/>
</dict>
</plist>
PLIST

xcrun swiftc -O -warnings-as-errors -swift-version 5 -target "$ARCH-apple-macos14.0" \
  -import-objc-header "$REPO_ROOT/app/Tests/bridging.h" -I "$REPO_ROOT/app/Generated" \
  "$REPO_ROOT"/app/Sources/Shared/*.swift "$REPO_ROOT"/app/Sources/App/*.swift "$REPO_ROOT"/app/Sources/UI/*.swift \
  "$REPO_ROOT/app/Sources/Keys/Attestor.swift" "$BINDINGS" "$REPO_ROOT/tools/fixture/Fixture.swift" \
  "$REPO_ROOT/tools/snapshot/main.swift" "$TEST_STATICLIB" -o "$APP/Contents/MacOS/Snapshot"
plutil -insert BrevRelayBinary -string "$RELAY" "$APP/Contents/Info.plist"
codesign --force --sign - "$APP" >/dev/null 2>&1
echo "$APP/Contents/MacOS/Snapshot"
