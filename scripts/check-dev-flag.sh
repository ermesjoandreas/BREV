#!/usr/bin/env bash
# The dev flag BREV_DEV (CLAUDE.md §2; docs/DECISIONS.md D-0115) turns off
# capture protection and the automatic locks in Debug builds. Release must
# have none of it:
#   1. app/Brev.xcodeproj's Release and Verify configurations do not set
#      BREV_DEV in SWIFT_ACTIVE_COMPILATION_CONDITIONS; Debug does (the
#      control, so the check cannot pass by reading nothing);
#   2. no app named with --release holds DevBuild's marker
#      (app/Sources/App/DevBuild.swift) anywhere in its bundle; each app
#      named with --debug holds it (the control).
# scripts/build.sh runs it after every build, scripts/test.sh after its
# Debug compile check. Needs the generated Xcode project.
#
# Usage: scripts/check-dev-flag.sh [--release <app>]... [--debug <app>]...
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT="$REPO_ROOT/app/Brev.xcodeproj"
MARKER=BREV-DEV-BUILD-MARKER-1

# conditions <configuration>: its SWIFT_ACTIVE_COMPILATION_CONDITIONS.
conditions() {
  xcodebuild -project "$PROJECT" -target Brev -configuration "$1" -showBuildSettings 2>/dev/null \
    | sed -n 's/^ *SWIFT_ACTIVE_COMPILATION_CONDITIONS = //p'
}

if ! grep -qw BREV_DEV <<<"$(conditions Debug)"; then
  echo "error: Debug does not set BREV_DEV; fix scripts/check-dev-flag.sh or app/project.yml" >&2
  exit 1
fi
for config in Release Verify; do
  if grep -qw BREV_DEV <<<"$(conditions "$config")"; then
    echo "error: $config sets BREV_DEV in SWIFT_ACTIVE_COMPILATION_CONDITIONS (app/project.yml)" >&2
    exit 1
  fi
done

while [[ $# -gt 0 ]]; do
  kind="$1" app="${2:-}"
  shift 2 || { echo "error: $kind needs an app path" >&2; exit 2; }
  if [[ ! -d "$app/Contents" ]]; then
    echo "error: $app is not an app bundle" >&2
    exit 1
  fi
  status=0
  grep -raq "$MARKER" "$app/Contents" || status=$?
  case "$kind:$status" in
    --release:1 | --debug:0) ;;
    --release:0) echo "error: $app is a Release build with the dev flag's marker" >&2; exit 1 ;;
    --debug:1) echo "error: the marker is not in the Debug build $app; fix scripts/check-dev-flag.sh" >&2; exit 1 ;;
    *) echo "error: $kind is not --release or --debug, or $app could not be read" >&2; exit 2 ;;
  esac
done
echo "BREV_DEV: in Debug only; no Release build named holds its marker"
