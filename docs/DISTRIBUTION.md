# Brev — Developer ID distribution and notarization

How to sign a Release build of Brev with Developer ID, notarize it, and how
a user checks a downloaded build. `CLAUDE.md` §5 Phase 5 asks for this to be
documented; **none of it has been run yet.** Commands are written for team
`AV26DNQ5SC` and bundle id `no.brev.app`. Brev B (`no.brev.app.b`) is a test
instance and is never distributed.

Read `docs/SECURITY.md` §7 first: Developer ID signing does not remove the
risk on a Mac that holds the team's signing keys.

## 1. What changes from today's build

Today `scripts/build.sh` signs with "Apple Development" and automatic
signing, using a Mac App Development profile that lists this Mac
(`docs/DECISIONS.md` D-0035). That build runs only on registered Macs. A
Developer ID build runs on any Mac and can be notarized.

| | Today (development) | Developer ID |
|---|---|---|
| Certificate | Apple Development | Developer ID Application (the team has one) |
| Provisioning profile | Mac App Development, lists devices | Developer ID, no device list |
| Signing style | Automatic, `-allowProvisioningUpdates` | Manual, a named profile |
| Keychain access group | `AV26DNQ5SC.no.brev.app` | **the same** |
| Hardened Runtime, sandbox, entitlements | on, as in `app/project.yml` | unchanged |
| Secure timestamp | not needed | required for notarization |
| Notarized, stapled | no | yes |

The keychain access group must stay `AV26DNQ5SC.no.brev.app`. The Secure
Enclave keys and the wrapped DEK live in that group (`CLAUDE.md` §3.2), and
a build signed into another group cannot reach them (D-0035, D-0036). The
same group should let a
Developer ID build open keys a development build made, since the keychain
checks the team and the group, not the certificate. That is expected, not
verified; test it on a test install before relying on it.

## 2. One-time setup in the developer portal

1. **App ID.** `no.brev.app` already exists (automatic signing registered
   it). It needs no extra capability for keychain groups: a group with the
   team prefix is allowed by default. App Attest (DeviceCheck) is not used
   yet (`docs/PHASE4_DESIGN.md` §7.1), so do not add it.
2. **Certificate.** Check that the Developer ID Application certificate and
   its private key are in the login keychain of the build Mac:

       security find-identity -v -p codesigning | grep "Developer ID Application"

   The line shows `Developer ID Application: <name> (AV26DNQ5SC)`.
3. **Provisioning profile.** Certificates, Identifiers & Profiles →
   Profiles → + → Distribution → **Developer ID** → App ID `no.brev.app` →
   the Developer ID Application certificate → name it `Brev Developer ID`.
   Download it and double-click it, or copy it to
   `~/Library/Developer/Xcode/UserData/Provisioning Profiles/`.
4. **Check the profile** before the first build:

       security cms -D -i "Brev_Developer_ID.provisionprofile" | plutil -p - \
         | grep -A3 -E 'keychain-access-groups|application-identifier|team-identifier|get-task-allow|ProvisionedDevices'

   Expected: `com.apple.application-identifier` is `AV26DNQ5SC.no.brev.app`,
   `keychain-access-groups` contains `AV26DNQ5SC.*` or
   `AV26DNQ5SC.no.brev.app`, `com.apple.developer.team-identifier` is
   `AV26DNQ5SC`, and there is no `ProvisionedDevices` list. The profile must
   not grant `get-task-allow`.

## 3. Build and sign

The Rust archive the app links must be a release archive without test
features. `scripts/gen-bindings.sh` builds it and checks that; the app's
pre-build script fails the build if `allow-software-keys` is in the archive.

The release is built the way `scripts/repro-build.sh` builds, so a user
can rebuild it and get the same executable (`docs/REPRODUCIBLE_BUILD.md`).
That needs the same path mappings, the same folder layout (`<root>/src`
for the source, `<root>/dd` for derived data) and `ARCHS=arm64`. The flags
below are copied from the script's `build_one`; if the script changes, copy
them again.

**Architecture: arm64 only.** Build on an Apple Silicon Mac. The Rust
archive is built for this Mac's architecture only, and `xcodebuild
archive` ignores `ONLY_ACTIVE_ARCH`, so without `ARCHS=arm64` it also tries
to link x86_64 and fails.

1. From a clean checkout of the tagged commit, run the full check first:

       scripts/test.sh

2. Export the commit to a fresh folder and build the Rust archive, the
   bindings and the Xcode project there, with the script's settings. Run
   this from the checkout, in one shell (step 3 uses the variables):

       REPO="$PWD"
       COMMIT="$(git rev-parse HEAD)"
       ROOT="$(cd "$(mktemp -d -t brev-release)" && pwd -P)"
       XROOT="${ROOT#/private}"   # Xcode drops /private; both spellings are mapped
       mkdir -p "$ROOT/src" && git archive --format=tar "$COMMIT" | tar -x -C "$ROOT/src"
       export SOURCE_DATE_EPOCH="$(git log -1 --format=%ct "$COMMIT")" ZERO_AR_DATE=1
       CARGO_HOME_DIR="$(cd "${CARGO_HOME:-$HOME/.cargo}" && pwd -P)"
       RUST_SRC="$(rustc --print sysroot)/lib/rustlib/src/rust"
       RUST_COMMIT="$(rustc -vV | awk '/^commit-hash:/ {print $2}')"
       RUSTFLAGS="--remap-path-prefix=$ROOT=/brev --remap-path-prefix=$CARGO_HOME_DIR=/cargo --remap-path-prefix=$RUST_SRC=/rustc/$RUST_COMMIT" \
       CFLAGS="-ffile-prefix-map=$ROOT=/brev -ffile-prefix-map=$CARGO_HOME_DIR=/cargo" \
         "$ROOT/src/scripts/gen-bindings.sh"
       xcodegen generate --spec "$ROOT/src/app/project.yml" --project "$ROOT/src/app"

   `RUSTFLAGS` and `CFLAGS` are set for the cargo step only: `xcodebuild`
   would read them from the environment as build settings.

3. Archive with manual Developer ID signing. The overrides replace the
   automatic "Apple Development" signing of `app/project.yml` for this
   build only; `--timestamp` adds the secure timestamp notarization needs.
   Everything up to `OTHER_CFLAGS` is as in the script:

       xcodebuild archive \
         -project "$ROOT/src/app/Brev.xcodeproj" -scheme Brev -configuration Release \
         -destination "platform=macOS,arch=arm64" \
         -derivedDataPath "$ROOT/dd" \
         -archivePath "$REPO/build/Brev.xcarchive" \
         ARCHS=arm64 ONLY_ACTIVE_ARCH=YES COMPILER_INDEX_STORE_ENABLE=NO \
         "OTHER_SWIFT_FLAGS=\$(inherited) -file-prefix-map $XROOT=/brev -file-prefix-map $ROOT=/brev" \
         "OTHER_CFLAGS=\$(inherited) -ffile-prefix-map=$XROOT=/brev -ffile-prefix-map=$ROOT=/brev" \
         CODE_SIGN_STYLE=Manual \
         DEVELOPMENT_TEAM=AV26DNQ5SC \
         CODE_SIGN_IDENTITY="Developer ID Application" \
         PROVISIONING_PROFILE_SPECIFIER="Brev Developer ID" \
         OTHER_CODE_SIGN_FLAGS="--timestamp"

   Release already has what notarization needs: `ENABLE_HARDENED_RUNTIME`
   is on and `CODE_SIGN_INJECT_BASE_ENTITLEMENTS` is off, so
   `get-task-allow` is not added.

4. Export the app from the archive. Write `build/ExportOptions.plist`:

       <?xml version="1.0" encoding="UTF-8"?>
       <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
       <plist version="1.0">
       <dict>
         <key>method</key><string>developer-id</string>
         <key>teamID</key><string>AV26DNQ5SC</string>
         <key>signingStyle</key><string>manual</string>
         <key>signingCertificate</key><string>Developer ID Application</string>
         <key>provisioningProfiles</key>
         <dict><key>no.brev.app</key><string>Brev Developer ID</string></dict>
       </dict>
       </plist>

   Then:

       xcodebuild -exportArchive \
         -archivePath build/Brev.xcarchive \
         -exportOptionsPlist build/ExportOptions.plist \
         -exportPath build/export

   The app is `build/export/Brev.app`. The build folder is no longer
   needed: `rm -rf "$ROOT"`.

5. Check that a rebuild gives the same executable. This builds the commit
   twice more, unsigned, and compares both with the signed app, signatures
   removed:

       scripts/repro-build.sh --commit "$COMMIT" --against build/export/Brev.app

   The last line must start with `REPRODUCIBLE`. If it says `NOT
   REPRODUCIBLE`, do not publish; find the difference first. A Developer
   ID-signed build has not been compared yet (`docs/REPRODUCIBLE_BUILD.md`
   §4), so the first release is also that test. Publish the hashes the
   script prints with the release (`docs/REPRODUCIBLE_BUILD.md` §5).

Limit: the app runs on arm64 only. A universal (arm64 and x86_64) build is
a Phase 5 item not yet done.

## 4. Check the signed app before notarizing

    APP=build/export/Brev.app
    codesign --verify --deep --strict --verbose=2 "$APP"
    codesign --display --verbose=4 "$APP" 2>&1 | grep -E 'Identifier|Authority|TeamIdentifier|Timestamp|flags'
    codesign --display --entitlements - --xml "$APP" | plutil -p -
    security cms -D -i "$APP/Contents/embedded.provisionprofile" | plutil -p - | grep -E 'Name|TeamIdentifier'

Expected:

- `Identifier=no.brev.app`, `TeamIdentifier=AV26DNQ5SC`, the first
  `Authority=Developer ID Application: … (AV26DNQ5SC)`, a `Timestamp=` line,
  and `flags=0x10000(runtime)` (Hardened Runtime).
- Entitlements exactly: `com.apple.security.app-sandbox` true,
  `com.apple.security.network.client` true, `keychain-access-groups`
  `[AV26DNQ5SC.no.brev.app]`, and the two Xcode adds from the profile,
  `com.apple.application-identifier` and
  `com.apple.developer.team-identifier`. **Nothing else.** In particular
  none of `com.apple.security.get-task-allow`,
  `com.apple.security.cs.disable-library-validation`,
  `cs.allow-jit`, `cs.allow-unsigned-executable-memory`,
  `cs.allow-dyld-environment-variables`, `cs.debugger`,
  `network.server`, iCloud or temporary exceptions (`app/project.yml`).
- The embedded profile is `Brev Developer ID`.
- `otool -L "$APP/Contents/MacOS/Brev"` shows no `libbrev_core.dylib`.
- `plutil -p "$APP/Contents/Info.plist"` has no `NSAppleScriptEnabled`,
  `NSServices`, `CFBundleDocumentTypes` or `CFBundleURLTypes`, and has
  `LSEnvironment` with `MallocScribble = 1`.

Then install it on a test Mac (one that does not hold the team's signing
keys) and check that onboarding and unlock work. The launch guard refuses to
unlock without `MallocScribble=1`, so a working unlock also shows that
LaunchServices still applies it.

## 5. Notarize and staple

Notarization uploads the app to Apple for a malware scan. The app holds no
keys and no letters, only code and the relay URL (`http://127.0.0.1:8787`).

1. **Credentials, once.** Either an app-specific password for the Apple ID
   (appleid.apple.com → Sign-In and Security → App-Specific Passwords):

       xcrun notarytool store-credentials brev-notary \
         --apple-id "<apple-id>" --team-id AV26DNQ5SC --password "<app-specific-password>"

   or an App Store Connect API key:

       xcrun notarytool store-credentials brev-notary \
         --key AuthKey_<id>.p8 --key-id <id> --issuer <issuer-uuid>

   `store-credentials` keeps them in the keychain under the profile name
   `brev-notary`.

2. **Submit.** Zip with `ditto`, which keeps the signature and extended
   attributes (plain `zip` can break them):

       ditto -c -k --keepParent build/export/Brev.app build/Brev.zip
       xcrun notarytool submit build/Brev.zip --keychain-profile brev-notary --wait

   The result must be `status: Accepted`. On `Invalid`, read why:

       xcrun notarytool log <submission-id> --keychain-profile brev-notary

3. **Staple** the ticket to the app, so Gatekeeper can check it offline:

       xcrun stapler staple build/export/Brev.app
       xcrun stapler validate build/export/Brev.app

4. **Package for download.** Zip the stapled app again with `ditto`
   (`Brev-<version>.zip`). For a disk image instead: create it with
   `hdiutil create -volname Brev -srcfolder build/export/Brev.app -ov -format UDZO Brev-<version>.dmg`,
   sign it with `codesign --timestamp -s "Developer ID Application: <name> (AV26DNQ5SC)" Brev-<version>.dmg`,
   notarize the `.dmg` as in step 2, and staple the `.dmg`.

5. **Publish checksums** beside the download: `shasum -a 256` of the zip or
   dmg, and the app's code directory hash from
   `codesign --display --verbose=4 build/export/Brev.app 2>&1 | grep CDHash`.

## 6. How a user checks a downloaded build

Before the first launch, in Terminal:

1. **The download matches the published checksum:**

       shasum -a 256 ~/Downloads/Brev-<version>.zip

2. **Gatekeeper accepts it, as notarized Developer ID from Brev's team:**

       spctl --assess --type execute --verbose=4 /Applications/Brev.app

   Expected: `accepted`, `source=Notarized Developer ID`, and
   `origin=Developer ID Application: <name> (AV26DNQ5SC)`. For a `.dmg`:
   `spctl --assess --type open --context context:primary-signature --verbose=4 Brev-<version>.dmg`.

3. **The signature is intact and from team `AV26DNQ5SC`:**

       codesign --verify --deep --strict --verbose=2 /Applications/Brev.app
       codesign --display --verbose=4 /Applications/Brev.app 2>&1 | grep -E 'Identifier|TeamIdentifier|CDHash|flags'

   Expected: `valid on disk`, `satisfies its Designated Requirement`,
   `Identifier=no.brev.app`, `TeamIdentifier=AV26DNQ5SC`,
   `flags=0x10000(runtime)`, and the `CDHash` published with the release.

4. **The entitlements are the short list in §4:**

       codesign --display --entitlements - --xml /Applications/Brev.app | plutil -p -

5. **The notarization ticket is stapled** (needs Xcode's command-line
   tools; `spctl` in step 2 already checks notarization online):

       xcrun stapler validate /Applications/Brev.app

If any check fails, do not open the app, and report it (`docs/SECURITY.md`
§8).

What these checks prove: the app was signed by team `AV26DNQ5SC`, Apple
scanned it, and nobody changed it since. They do not prove that the binary
was built from the published source. That needs a reproducible build:
`docs/REPRODUCIBLE_BUILD.md`, and §3 above builds the release so that it
can match.

## 7. Open for the owner

- Where the Developer ID private key lives. Today the build Mac is the
  developer's Mac, which also holds the Apple Development key (D-0062).
  Keeping Developer ID signing on a separate machine or behind a password
  prompt is an owner decision.
- Which App Attest environment a Developer ID build gets on macOS, before
  the real `AppAttestor` is built (`docs/PHASE4_DESIGN.md` §7.1).
- Whether to publish a `.zip` or a `.dmg`, and where the checksums and
  CDHash are published.
- A real relay with TLS. The Developer ID build still talks only to
  `http://127.0.0.1:<port>`; a remote relay needs a new URL rule
  (`docs/SECURITY.md` §7, item 3).
