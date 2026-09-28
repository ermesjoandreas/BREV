#!/bin/bash
# Builds LockLab.app (no.brev.spike.lock) and LockOther.app (no.brev.spike.lockother) like Brev Release:
# ad-hoc signed, Hardened Runtime, App Sandbox as the only entitlement. Plus bin/ctl (unsandboxed).
set -euo pipefail
D="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$D/build" "$D/bin" "$D/out"
xcrun swiftc -O -target arm64-apple-macos14.0 -swift-version 5 -module-name LockLab \
  "$D/src/lab.swift" -o "$D/build/LockLab.bin"
cat > "$D/build/lab.entitlements" <<'PL'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>com.apple.security.app-sandbox</key><true/></dict></plist>
PL
for pair in "LockLab:no.brev.spike.lock" "LockOther:no.brev.spike.lockother"; do
  NAME=${pair%%:*}; BID=${pair#*:}
  APP="$D/build/$NAME.app"
  rm -rf "$APP"; mkdir -p "$APP/Contents/MacOS"
  cp "$D/build/LockLab.bin" "$APP/Contents/MacOS/$NAME"
  cat > "$APP/Contents/Info.plist" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>$BID</string>
<key>CFBundleName</key><string>$NAME</string>
<key>CFBundleExecutable</key><string>$NAME</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.0.1</string>
<key>CFBundleVersion</key><string>1</string>
<key>LSMinimumSystemVersion</key><string>14.0</string>
<key>NSPrincipalClass</key><string>LabApp</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
PL
  codesign --force --sign - --options runtime --entitlements "$D/build/lab.entitlements" "$APP"
  codesign -dv "$APP" 2>&1 | grep -E "^Identifier|flags"
  codesign -d --entitlements - "$APP" 2>/dev/null | tr -d '\n'; echo
done
xcrun swiftc -O -target arm64-apple-macos14.0 -swift-version 5 "$D/src/ctl.swift" -o "$D/bin/ctl"
echo "built: build/LockLab.app build/LockOther.app bin/ctl"
