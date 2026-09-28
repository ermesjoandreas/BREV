#!/bin/bash
# run_brev.sh CASE "OPEN_EXTRA" [ARGS...]: launches the copied Brev app shell
# (Release, bundle id no.brev.spike.brevshell) with `open -n -g -W` under a
# minimal environment, keeps it up for 4 s, then SIGTERMs it. No input is
# ever sent to it. CASE=direct runs the binary directly instead (no
# LaunchServices, so no LSEnvironment).
set -uo pipefail
D="$(cd "$(dirname "$0")" && pwd)"
APP="$D/brevshell/app/build/Build/Products/Release/Brev.app"
CASE=$1; EXTRA=$2; shift 2
O="$D/out/$CASE"; rm -rf "$O"; mkdir -p "$O"
/usr/bin/log stream --style compact --level debug --predicate 'process == "Brev" AND subsystem == "no.brev.app"' > "$O/stream.txt" 2>&1 &
LOGPID=$!
sleep 1.5
T0=$(date '+%Y-%m-%d %H:%M:%S')
if [ "$CASE" = direct ]; then
    env -i HOME="$HOME" PATH=/usr/bin:/bin TMPDIR="$TMPDIR" "$APP/Contents/MacOS/Brev" "$@" > "$O/stdout.txt" 2> "$O/stderr.txt" &
else
    # shellcheck disable=SC2086
    env -i HOME="$HOME" USER="$USER" LOGNAME="$USER" PATH=/usr/bin:/bin:/usr/sbin:/sbin TMPDIR="$TMPDIR" \
        /usr/bin/open -n -g -W --stdout "$O/stdout.txt" --stderr "$O/stderr.txt" $EXTRA -a "$APP" --args "$@" &
fi
RUNPID=$!
sleep 4
PIDS=$(pgrep -f "$APP/Contents/MacOS/Brev" | tr '\n' ' ')
echo "running after 4 s: [${PIDS}]" > "$O/result.txt"
[ -n "$PIDS" ] && kill $PIDS 2>/dev/null
for _ in $(seq 1 20); do kill -0 $RUNPID 2>/dev/null || break; sleep 0.25; done
wait $RUNPID 2>/dev/null; echo "runner exit=$?" >> "$O/result.txt"
sleep 1
kill $LOGPID 2>/dev/null; wait $LOGPID 2>/dev/null
/usr/bin/log show --info --debug --start "$T0" --predicate 'process == "Brev" AND subsystem == "no.brev.app"' > "$O/show.txt" 2>&1
pgrep -f "$APP/Contents/MacOS/Brev" >/dev/null && echo "WARNING: still running" >> "$O/result.txt"
echo "== $CASE [$EXTRA] [$*]"
cat "$O/result.txt"
grep -a -E 'launch|ping|second instance|route|lock reason|failed|unsafe|refused' "$O/stream.txt" | sed -E 's/^[0-9-]+ //' | cut -c1-170
echo "stderr: $(head -c 300 "$O/stderr.txt")"
