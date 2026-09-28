#!/bin/bash
# Builds the enclave spike:
#  - build/BrevEnclaveSpike.app: sandboxed, Hardened Runtime, ad-hoc signed,
#    bundle id no.brev.spike.enclave, entitlements identical to
#    BREV/app/Brev.entitlements, LSUIElement = true, no AppKit linked
#    (it never connects to the window server: no window, no Dock icon, no focus).
#  - build/enclave-cli: the same code as an unsandboxed command-line tool with a
#    different identifier (no.brev.spike.enclave.cli), used as "another program".
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
B="$HERE/build"
APP="$B/BrevEnclaveSpike.app"
SDK="$(xcrun --sdk macosx --show-sdk-path)"
rm -rf "$B"
mkdir -p "$APP/Contents/MacOS"

cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key><string>no.brev.spike.enclave</string>
	<key>CFBundleName</key><string>BrevEnclaveSpike</string>
	<key>CFBundleExecutable</key><string>BrevEnclaveSpike</string>
	<key>CFBundlePackageType</key><string>APPL</string>
	<key>CFBundleShortVersionString</key><string>0.0.2</string>
	<key>CFBundleVersion</key><string>2</string>
	<key>LSMinimumSystemVersion</key><string>14.0</string>
	<key>LSUIElement</key><true/>
</dict>
</plist>
PLIST

swiftc -swift-version 5 -O -target arm64-apple-macos14.0 -sdk "$SDK" \
  "$HERE/src/main.swift" -o "$APP/Contents/MacOS/BrevEnclaveSpike"
swiftc -swift-version 5 -O -D CLI -target arm64-apple-macos14.0 -sdk "$SDK" \
  "$HERE/src/main.swift" -o "$B/enclave-cli"

codesign --force --sign - --options runtime \
  --entitlements "$HERE/enclave.entitlements" "$APP"
codesign --force --sign - --options runtime \
  --identifier no.brev.spike.enclave.cli "$B/enclave-cli"

echo "== app signature"
codesign -dv "$APP" 2>&1 | grep -E "^Identifier|flags|TeamIdentifier|Signature"
echo "== app entitlements"
codesign -d --entitlements - --xml "$APP" 2>/dev/null | plutil -p -
echo "== app Info.plist"
plutil -p "$APP/Contents/Info.plist"
echo "== app linked frameworks"
otool -L "$APP/Contents/MacOS/BrevEnclaveSpike" | tail -n +2 | awk '{print $1}'
echo "== cli signature"
codesign -dv "$B/enclave-cli" 2>&1 | grep -E "^Identifier|flags"
