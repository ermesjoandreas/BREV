#!/usr/bin/env bash
# Full build: Rust core -> UniFFI bindings -> XcodeGen -> xcodebuild -> Brev.app.
# macOS only: only Xcode can produce the app bundle. Everything that can run
# elsewhere lives in test.sh and gen-bindings.sh.
#
# Usage: scripts/build.sh [--debug] [--open] [--instance b]
#   --debug       build the Debug configuration instead of Release
#   --open        launch the built app afterwards
#   --instance b  build the second instance "Brev B" (bundle id no.brev.app.b,
#                 its own container and keychain group) into app/build-b
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR="$REPO_ROOT/app"

CONFIGURATION=Release
OPEN_APP=no
INSTANCE=
while [[ $# -gt 0 ]]; do
  case "$1" in
    --debug)    CONFIGURATION=Debug ;;
    --open)     OPEN_APP=yes ;;
    --instance)
      if [[ "${2:-}" != b ]]; then
        echo "error: --instance takes exactly one value: b" >&2; exit 2
      fi
      INSTANCE=b; shift ;;
    -h|--help)  sed -n '2,10p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)          echo "error: unknown argument '$1' (accepted: --debug, --open, --instance b)" >&2; exit 2 ;;
  esac
  shift
done

# The second instance (docs/PHASE3_DESIGN.md §7) is the same code with
# another bundle id and name. Container, data folder, .lock and keychain
# group all follow from the bundle id, and the Touch ID dialogs and the Dock
# show the name. The default build passes no overrides at all, so nothing
# changes for no.brev.app. Its own derived data keeps the two apart.
if [[ "$INSTANCE" == b ]]; then
  PRODUCT="Brev B"
  DERIVED="$APP_DIR/build-b"
  OVERRIDES=(PRODUCT_BUNDLE_IDENTIFIER=no.brev.app.b "PRODUCT_NAME=Brev B")
else
  PRODUCT=Brev
  DERIVED="$APP_DIR/build"
  OVERRIDES=()
fi

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: scripts/build.sh only runs on macOS, because building Brev.app needs Xcode." >&2
  echo "       On $(uname -s) use scripts/test.sh (Rust checks) or scripts/gen-bindings.sh instead." >&2
  exit 1
fi

# Fail before doing any work if a tool is missing, and say how to get it.
need() { # need <command> <install hint>
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: '$1' not found. Install it with: $2" >&2
    exit 1
  fi
}
need cargo      "https://rustup.rs  (then: rustup default stable)"
need xcodegen   "brew install xcodegen"
# `command -v xcodebuild` is useless here: /usr/bin/xcodebuild is a shim that
# exists on every Mac, including Command Line Tools-only installs, and only
# fails when actually run. Ask it for its version instead, and leave its
# stderr visible: it names the real cause (no Xcode, wrong xcode-select path,
# or a license not yet accepted, which also makes `-version` fail), which
# the hint below can only guess at.
if ! xcodebuild -version >/dev/null; then
  echo "error: xcodebuild failed (see the message above). Install Xcode 16.2 or newer from the App Store, then:" >&2
  echo "       sudo xcode-select -s /Applications/Xcode.app" >&2
  echo "       If Xcode is installed and selected, accept its license with: sudo xcodebuild -license accept" >&2
  exit 1
fi

"$REPO_ROOT/scripts/gen-bindings.sh"

echo "==> Generating $APP_DIR/Brev.xcodeproj"
xcodegen generate --spec "$APP_DIR/project.yml" --project "$APP_DIR"

# ONLY_ACTIVE_ARCH: the Rust staticlib is built for one arch only in Phase 0,
# so Xcode must not attempt a universal (x86_64 + arm64) link, and
# -destination states which arch that is instead of leaving it to destination
# ordering. Without it a macOS app scheme matches several destinations on
# Apple Silicon and Xcode 15/16 warn "Using the first of multiple matching
# destinations". Not generic/platform=macOS: that destination has no active
# arch, so ONLY_ACTIVE_ARCH=YES would build both ARCHS and fail to link the
# single-arch archive.
#
# The arch is read from the archive itself, not from `uname -m`. The two differ
# whenever the rustup toolchain that cargo used is not native to this shell:
# an x86_64 toolchain on Apple Silicon (carried over from an Intel Mac by
# Migration Assistant, or `rustup default stable-x86_64-apple-darwin`), or a
# native arm64 toolchain run from an `arch -x86_64` shell. cargo builds without
# complaint either way, and xcodebuild would then fail at link time with ld's
# "building for macOS-arm64 but attempting to link with file built for
# macOS-x86_64" plus undefined uniffi_brev_core_* symbols. `lipo -archs` prints
# the archive's arch in xcodebuild's own names (arm64 or x86_64); anything else
# (a universal archive is a Phase 5 item) is refused before xcodebuild runs.
STATICLIB="$REPO_ROOT/core/target/release/libbrev_core.a"
ARCH="$(lipo -archs "$STATICLIB")"
case "$ARCH" in
  arm64|x86_64) ;;
  *)
    echo "error: $STATICLIB is built for '$ARCH'; expected exactly one of arm64 or x86_64." >&2
    echo "       Check which toolchain cargo used (rustup show) and rebuild with scripts/gen-bindings.sh." >&2
    exit 1 ;;
esac
if [[ "$ARCH" != "$(uname -m)" ]]; then
  echo "note: libbrev_core.a is $ARCH but this shell reports $(uname -m); building Brev for $ARCH to match the archive"
  echo "      (the rustup toolchain cargo used is not native to this shell; see \`rustup show\`)"
fi

# -allowProvisioningUpdates: Brev is signed by team AV26DNQ5SC with automatic
# signing (docs/DECISIONS.md D-0035), so xcodebuild may fetch or renew the
# Mac App Development profile. This Mac and the App ID are registered; the
# first --instance b build registers no.brev.app.b the same way.
echo "==> Building $PRODUCT ($CONFIGURATION, $ARCH)"
xcodebuild \
  -project "$APP_DIR/Brev.xcodeproj" \
  -allowProvisioningUpdates \
  -scheme Brev \
  -configuration "$CONFIGURATION" \
  -destination "platform=macOS,arch=$ARCH" \
  -derivedDataPath "$DERIVED" \
  ONLY_ACTIVE_ARCH=YES \
  ${OVERRIDES[@]+"${OVERRIDES[@]}"} \
  build

APP="$DERIVED/Build/Products/$CONFIGURATION/$PRODUCT.app"
if [[ ! -d "$APP" ]]; then
  echo "error: xcodebuild succeeded but $APP is missing" >&2
  exit 1
fi

echo
echo "Built: $APP"
echo "Run it with:  open \"$APP\"   (or: scripts/build.sh${INSTANCE:+ --instance $INSTANCE} --open)"

if [[ "$OPEN_APP" == yes ]]; then
  open "$APP"
fi
