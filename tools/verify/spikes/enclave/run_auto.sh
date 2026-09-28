#!/bin/bash
# Launches the sandboxed spike app through LaunchServices in the background
# (open -g -j: no activation, hidden) in a NO-PROMPT mode, waits for it to exit
# (max 40 s), makes sure it is gone and prints its stdout. It never reads the
# app's container from outside (the app copies its log to stdout).
# Usage: run_auto.sh probe|restore|cleanup
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
APP="$HERE/build/BrevEnclaveSpike.app"
EXE="$APP/Contents/MacOS/BrevEnclaveSpike"
MODE="${1:?mode}"
case "$MODE" in probe|restore|cleanup) ;; *) echo "refusing mode $MODE (not an automated no-prompt mode)"; exit 64;; esac
OUT="$HERE/out"; mkdir -p "$OUT"
: > "$OUT/$MODE.stdout"; : > "$OUT/$MODE.stderr"

open -n -g -j -W --stdout "$OUT/$MODE.stdout" --stderr "$OUT/$MODE.stderr" "$APP" --args "$MODE" 2>"$OUT/$MODE.open.stderr" &
OPEN_PID=$!
for _ in $(seq 1 40); do
  kill -0 "$OPEN_PID" 2>/dev/null || break
  sleep 1
done
if kill -0 "$OPEN_PID" 2>/dev/null; then
  echo "TIMEOUT: killing"; pkill -f "$EXE"; kill "$OPEN_PID" 2>/dev/null
fi
wait "$OPEN_PID" 2>/dev/null
echo "open exit: $?"
if pgrep -f "$EXE" >/dev/null; then echo "still running -> killing"; pkill -9 -f "$EXE"; else echo "app not running (quit confirmed)"; fi
echo "---- stdout:"; cat "$OUT/$MODE.stdout"
echo "---- stderr:"; cat "$OUT/$MODE.stderr"
