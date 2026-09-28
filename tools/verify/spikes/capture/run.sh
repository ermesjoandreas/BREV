#!/bin/bash
# run.sh <variant: base|protected> <step>...
# Launches SpikeCapture (no activation), runs probe steps, flags any new system window
# after every step, then kills the app. Steps: sck-list sck-shots sck-stream cg cgstream avcap spi sc
set -uo pipefail
D="$(cd "$(dirname "$0")" && pwd)"
P="$D/bin/probe"; O="$D/out"; mkdir -p "$O"
VAR="$1"; shift
TS=$(date +%H%M%S)
EXTRA="${VAR//+/ }"; [ "$VAR" = base ] && EXTRA=""

sysdiff() {  # print on-screen windows that were not there before the run (excluding the spike)
  "$P" syswins | sed -E 's/ bounds=.*//' | sort > "$O/sys-now.txt"
  comm -13 "$O/sys-base.txt" "$O/sys-now.txt" | sed 's/^/   NEW SYSTEM WINDOW: /'
}

"$P" syswins | sed -E 's/ bounds=.*//' | sort > "$O/sys-base.txt"
echo "== $(date +%T) launch variant=$VAR (macOS $(sw_vers -productVersion) $(sw_vers -buildVersion))"
open -n -g --stdout "$O/app-$TS.log" --stderr "$O/app-$TS.err" "$D/build/SpikeCapture.app" --args --ttl 75 $EXTRA ${APPARGS:-}   # WP11: APPARGS (e.g. --dy -468)
for i in $(seq 1 40); do grep -q '^ready' "$O/app-$TS.log" 2>/dev/null && break; sleep 0.25; done
cat "$O/app-$TS.log"
PID=$(sed -nE 's/^ready pid=([0-9]+).*/\1/p' "$O/app-$TS.log")
[ -z "$PID" ] && { echo "app did not become ready"; cat "$O/app-$TS.err"; exit 1; }
sleep 0.5
"$P" windows
sysdiff

for s in "$@"; do
  echo "== $(date +%T) step $s"
  if [ "$s" = cgds26 ]; then
    R=$("$P" backdrop-rect)
    "$D/bin/cgds26" "$O/crops/cgds26-dlsym.png" ${R//,/ }
    "$P" analyze-backdrop-rect "$O/crops/cgds26-dlsym.png" cgds26-dlsym
  elif [ "$s" = sc ]; then
    R=$("$P" backdrop-rect)
    screencapture -x "$O/tmp-x.png"; echo "screencapture -x exit=$?"
    "$P" analyze-display "$O/tmp-x.png" sc-x; rm -f "$O/tmp-x.png"
    screencapture -x -R"$R" "$O/tmp-R.png"; echo "screencapture -R$R exit=$?"
    "$P" analyze-backdrop-rect "$O/tmp-R.png" sc-R; rm -f "$O/tmp-R.png"
    "$P" ids | while read -r id t; do
      screencapture -x -o -l"$id" "$O/crops/sc-l-$t.png" 2> "$O/sc-l.err"; rc=$?
      echo "screencapture -l$id ($t) exit=$rc $(cat "$O/sc-l.err")"
      [ -s "$O/crops/sc-l-$t.png" ] && "$P" analyze-window "$O/crops/sc-l-$t.png" "sc-l-$t" "$t"
    done
    screencapture -x -V 2 "$O/tmp-V.mov"; echo "screencapture -V 2 exit=$?"
    "$P" frame "$O/tmp-V.mov" 1.0 sc-V-frame1s; rm -f "$O/tmp-V.mov"
  else
    echo "   [$(date +%T.%3N 2>/dev/null || date +%T)] start"; HOLD=${HOLD:-} "$P" "$s"; echo "   [$(date +%T)] end"
  fi
  sysdiff
done

kill "$PID" 2>/dev/null; sleep 0.5
pgrep -f "build/SpikeCapture.app" >/dev/null && { echo "app still running, SIGKILL"; pkill -9 -f "build/SpikeCapture.app"; }
pgrep -f "build/SpikeCapture.app" >/dev/null && echo "APP STILL RUNNING" || echo "== $(date +%T) app $PID quit"
sysdiff
# WP11: keep this run's crops (the probe overwrites crops/<label>.png on every run)
[ -d "$O/crops" ] && mv "$O/crops" "$O/crops-$VAR-$TS" && echo "== crops kept in out/crops-$VAR-$TS"
