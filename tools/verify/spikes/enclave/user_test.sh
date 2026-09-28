#!/bin/bash
# Brev enclave spike: the Touch ID round trip. Run this yourself; see USER_TEST.md.
#
#   ./user_test.sh           setup -> gatecheck -> unwrap (ONE Touch ID prompt) -> cleanup
#   ./user_test.sh --reuse   same, but unwrap + sign with one LAContext (see USER_TEST.md)
#   ./user_test.sh --rogue   also let a DIFFERENT program try the same key afterwards
#                            (a SECOND prompt; press Avbryt/Cancel or touch, then report)
#
# The app is a background app (LSUIElement, no AppKit): no window, no Dock icon.
# Only the system's Touch ID dialog appears. Output goes to ./out/user-*.stdout.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
APP="$HERE/build/BrevEnclaveSpike.app"
EXE="$APP/Contents/MacOS/BrevEnclaveSpike"
OUT="$HERE/out"; mkdir -p "$OUT"
REUSE=0; ROGUE=0
for a in "$@"; do
  case "$a" in --reuse) REUSE=1;; --rogue) ROGUE=1;; *) echo "unknown option $a"; exit 64;; esac
done

run() { # run <mode> <max seconds>
  local mode="$1" max="$2" f="$OUT/user-$1.stdout"
  : > "$f"; : > "$f.err"
  # open's own "Unable to block on applications" (a fast app exiting before
  # open -W starts waiting) is harmless and hidden.
  open -n -g -W --stdout "$f" --stderr "$f.err" "$APP" --args "$mode" 2>/dev/null &
  local pid=$!
  for _ in $(seq 1 "$max"); do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
  if kill -0 "$pid" 2>/dev/null; then echo "TIMEOUT in $mode"; pkill -f "$EXE"; kill "$pid" 2>/dev/null; fi
  wait "$pid" 2>/dev/null
  pgrep -f "$EXE" >/dev/null && pkill -9 -f "$EXE"
  grep -v '^EXPORT ' "$f"; cat "$f.err"
}

echo "### 0. build"
"$HERE/build.sh" > "$OUT/user-build.log" 2>&1 || { echo "build failed, see $OUT/user-build.log"; exit 1; }
echo "ok"

echo; echo "### 1. setup (no prompt)"
run setup 30

echo; echo "### 2. gatecheck (no prompt; must say GOOD)"
run gatecheck 30

echo; echo "### 3. unwrap: touch the Touch ID sensor when the dialog appears"
if [ "$REUSE" = 1 ]; then run reuse 100; else run unwrap 100; fi

if [ "$ROGUE" = 1 ]; then
  echo; echo "### 4 (optional). another program (build/enclave-cli, not sandboxed) tries the same key"
  echo "    A second dialog should appear. Note the program name it shows."
  "$HERE/build/enclave-cli" rogue "$OUT/user-setup.stdout" 2>&1 | tee "$OUT/user-rogue.stdout"
fi

echo; echo "### 5. cleanup (removes the test key blobs from the app's container)"
run cleanup 30
echo; echo "Done. Full output: $OUT/user-*.stdout"
