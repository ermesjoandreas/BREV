#!/bin/bash
# Builds InputLab.app like Brev Release (ad-hoc, Hardened Runtime, App Sandbox only) plus the CLI tools.
set -euo pipefail
D="$(cd "$(dirname "$0")" && pwd)"
APP="$D/build/InputLab.app"
mkdir -p "$D/build" "$D/bin" "$D/out"
rm -rf "$APP"; mkdir -p "$APP/Contents/MacOS"
xcrun clang -O2 -target arm64-apple-macos14.0 -c "$D/src/scan.c" -o "$D/build/scan.o"
xcrun swiftc -O -target arm64-apple-macos14.0 -swift-version 5 -module-name InputLab \
  -import-objc-header "$D/src/bridging.h" "$D/src/lab.swift" "$D/build/scan.o" -o "$APP/Contents/MacOS/InputLab"
cat > "$APP/Contents/Info.plist" <<PL
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
PL
cat > "$D/build/lab.entitlements" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>com.apple.security.app-sandbox</key><true/></dict></plist>
PL
codesign --force --sign - --options runtime --entitlements "$D/build/lab.entitlements" "$APP"
codesign -dv "$APP" 2>&1 | grep -E "Identifier|flags"
codesign -d --entitlements - "$APP" 2>/dev/null | tail -1; echo
xcrun clang -O2 -target arm64-apple-macos14.0 -c "$D/src/axpost.c" -o "$D/build/axpost.o"
xcrun swiftc -O -target arm64-apple-macos14.0 -swift-version 5 -import-objc-header "$D/src/axpost.h" \
  "$D/src/poster.swift" "$D/build/axpost.o" -o "$D/bin/poster"
for t in axdump preflight keylisten; do
  xcrun swiftc -O -target arm64-apple-macos14.0 -swift-version 5 "$D/src/$t.swift" -o "$D/bin/$t"
done
echo "built: $APP and bin/{poster,axdump,preflight}"
