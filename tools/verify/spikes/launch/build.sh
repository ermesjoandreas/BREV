#!/bin/bash
# Builds LaunchSpike.app (LSEnvironment MallocScribble=1, id no.brev.spike.launch)
# and LaunchSpikeNoEnv.app (no LSEnvironment, id no.brev.spike.launchnoenv),
# both ad-hoc signed with Hardened Runtime and exactly Brev's entitlements
# (app-sandbox only), deployment target 14.0; plus tools/poster.
set -euo pipefail
D="$(cd "$(dirname "$0")" && pwd)"
B="$D/build"
mkdir -p "$B/obj"
TARGET=arm64-apple-macos14.0
xcrun clang -O2 -target $TARGET -c "$D/src/scan.c" -o "$B/obj/scan.o"
xcrun clang -O2 -target $TARGET -c "$D/src/spike_c.c" -I "$D/src" -o "$B/obj/spike_c.o"

make_app() { # name bundle-id with-lsenv [entitlements]
    local name=$1 id=$2 lsenv=$3 ent=${4:-$D/src/spike.entitlements} app="$B/$1.app"
    rm -rf "$app"
    mkdir -p "$app/Contents/MacOS"
    xcrun swiftc -O -target $TARGET -module-name "$name" -import-objc-header "$D/src/bridging.h" \
        "$D/src/main.swift" "$D/src/keys.swift" "$B/obj/scan.o" "$B/obj/spike_c.o" \
        -o "$app/Contents/MacOS/$name"
    local env=""
    if [ "$lsenv" = 1 ]; then
        env="<key>LSEnvironment</key><dict><key>MallocScribble</key><string>1</string></dict>"
    fi
    cat > "$app/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>$id</string>
<key>CFBundleExecutable</key><string>$name</string>
<key>CFBundleName</key><string>$name</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.0.1</string>
<key>CFBundleVersion</key><string>1</string>
<key>LSMinimumSystemVersion</key><string>14.0</string>
<key>NSPrincipalClass</key><string>SpikeApplication</string>
<key>NSHighResolutionCapable</key><true/>
$env
</dict></plist>
EOF
    codesign --force --sign - --options runtime --timestamp=none \
        --entitlements "$ent" "$app"
    codesign -dv --entitlements - "$app" 2>&1 | grep -E 'Identifier|flags|Signature|app-sandbox|get-task' || true
}
make_app LaunchSpike no.brev.spike.launch 1
make_app LaunchSpikeNoEnv no.brev.spike.launchnoenv 0
make_app LaunchSpikeGTA no.brev.spike.launchgta 1 "$D/src/spike-gta.entitlements"
xcrun swiftc -O -target $TARGET "$D/tools/poster.swift" -o "$B/poster"
echo "built"
