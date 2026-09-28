#!/bin/bash
# run_case.sh CASE APP "OPEN_EXTRA" [ARGS...]
# Launches build/APP.app with `open -n -g -W` (background, new instance),
# stdout/stderr into out/CASE/, streams its log, posts the marker key events
# to its PID only (tools/poster), waits for it to quit itself, kills it if it
# does not, then greps every output for the marker (UTF-8 and UTF-16LE).
set -uo pipefail
D="$(cd "$(dirname "$0")" && pwd)"
CASE=$1; APP=$2; EXTRA=$3; shift 3
O="$D/out/$CASE"; rm -rf "$O"; mkdir -p "$O"
MARK=LNCHSPKMRK7QZX
/usr/bin/log stream --style compact --level debug --predicate "process == \"$APP\"" > "$O/stream.txt" 2>&1 &
LOGPID=$!
sleep 1.5
T0=$(date '+%Y-%m-%d %H:%M:%S')
# `open` passes its own environment to the app when --env/--stdout is used,
# so it runs under a minimal environment (CLEANENV=0 keeps the full one).
if [ "${CLEANENV:-1}" = 1 ]; then OPEN=(env -i HOME="$HOME" USER="$USER" LOGNAME="$USER" PATH=/usr/bin:/bin:/usr/sbin:/sbin TMPDIR="$TMPDIR" /usr/bin/open); else OPEN=(/usr/bin/open); fi
# shellcheck disable=SC2086
if [ $# -gt 0 ]; then
    "${OPEN[@]}" -n -g -W --stdout "$O/stdout.txt" --stderr "$O/stderr.txt" --env "SPIKE_PROBE=$D/probe.txt" $EXTRA -a "$D/build/$APP.app" --args "$@" &
else
    "${OPEN[@]}" -n -g -W --stdout "$O/stdout.txt" --stderr "$O/stderr.txt" --env "SPIKE_PROBE=$D/probe.txt" $EXTRA -a "$D/build/$APP.app" &
fi
OPENPID=$!
PID=""
for _ in $(seq 1 100); do
    PID=$(grep -a -m1 -o 'SPIKE ready pid=[0-9]*' "$O/stdout.txt" 2>/dev/null | sed 's/.*=//')
    [ -n "$PID" ] && break
    if ! kill -0 $OPENPID 2>/dev/null; then break; fi
    sleep 0.2
done
if [ -n "$PID" ]; then
    "$D/build/poster" "$PID" > "$O/poster.txt" 2>&1
else
    echo "no ready line" > "$O/poster.txt"
fi
for _ in $(seq 1 60); do kill -0 $OPENPID 2>/dev/null || break; sleep 0.25; done
if kill -0 $OPENPID 2>/dev/null; then
    echo "app still running after timeout; killing" >> "$O/poster.txt"
    [ -n "$PID" ] && kill "$PID" 2>/dev/null
    pkill -x "$APP" 2>/dev/null
    sleep 1
fi
wait $OPENPID 2>/dev/null; echo "open exit=$?" >> "$O/poster.txt"
sleep 1
kill $LOGPID 2>/dev/null; wait $LOGPID 2>/dev/null
/usr/bin/log show --info --debug --start "$T0" --predicate "process == \"$APP\"" > "$O/show.txt" 2>&1
pgrep -x "$APP" >/dev/null && echo "WARNING: $APP still running" | tee -a "$O/poster.txt"
count16() { python3 - "$1" "$MARK" <<'PY'
import sys
b = open(sys.argv[1], 'rb').read()
print(b.count(sys.argv[2].encode('utf-16-le')))
PY
}
{
    echo "case=$CASE app=$APP extra=[$EXTRA] args=[$*] pid=$PID"
    for f in stdout stderr stream show; do
        [ -f "$O/$f.txt" ] || { echo "$f: missing"; continue; }
        n8=$(grep -a -c "$MARK" "$O/$f.txt"); n16=$(count16 "$O/$f.txt")
        nl=$(wc -l < "$O/$f.txt" | tr -d ' ')
        tr=$(grep -a -v 'SPIKE ' "$O/$f.txt" | grep -a -c -i -E 'keydown|key down|KeyDown|NSEvent: type')
        echo "$f: lines=$nl marker_utf8_lines=$n8 marker_utf16=$n16 non-SPIKE-keydown-lines=$tr"
    done
    cat "$O/poster.txt"
} | tee "$O/summary.txt"
