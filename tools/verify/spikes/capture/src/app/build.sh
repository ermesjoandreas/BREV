#!/bin/bash
# Builds SpikeCapture.app like Brev Release: ad-hoc signed, Hardened Runtime, App Sandbox only.
set -euo pipefail
D="$(cd "$(dirname "$0")/../.." && pwd)"
APP="$D/build/SpikeCapture.app"
rm -rf "$APP"; mkdir -p "$APP/Contents/MacOS"
xcrun swiftc -O -target arm64-apple-macos14.0 -swift-version 5 "$D/src/app/main.swift" -o "$APP/Contents/MacOS/SpikeCapture"
cat > "$APP/Contents/Info.plist" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>no.brev.spike.capture</string>
<key>CFBundleName</key><string>SpikeCapture</string>
<key>CFBundleExecutable</key><string>SpikeCapture</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.0.2</string>
<key>CFBundleVersion</key><string>2</string>
<key>LSMinimumSystemVersion</key><string>14.0</string>
<key>LSUIElement</key><true/>
<key>NSPrincipalClass</key><string>NSApplication</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
PL
cat > "$D/build/spike.entitlements" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>com.apple.security.app-sandbox</key><true/></dict></plist>
PL
codesign --force --sign - --options runtime --entitlements "$D/build/spike.entitlements" "$APP"
codesign -dv "$APP" 2>&1 | grep -E "Identifier|flags"
codesign -d --entitlements - "$APP" 2>/dev/null | tail -1
