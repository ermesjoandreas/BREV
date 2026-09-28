# Sourced by run.sh and human.sh. Starts/stops the spike apps. Input goes only to LockLab's own pid (bin/ctl refuses others).
D="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB="$D/build/LockLab.app"
OTHER="$D/build/LockOther.app"
C="$D/bin/ctl"
OUT="$D/out"
mkdir -p "$OUT"

# start_app <app> <logname> [app args...]   sets APID and ALOG
start_app() {
  local app=$1 name=$2; shift 2
  ALOG="$OUT/$name.log"; : > "$ALOG"
  open -n --stdout "$ALOG" --stderr "$OUT/$name.err" "$app" --args "$@"
  for _ in $(seq 1 60); do grep -q ' ready pid=' "$ALOG" 2>/dev/null && break; sleep 0.25; done
  APID=$(sed -nE 's/.* ready pid=([0-9]+).*/\1/p' "$ALOG" | head -1)
  [ -n "$APID" ] || { echo "app did not start ($name)"; return 1; }
}
lab_start()   { start_app "$LAB" "$@";   LPID=$APID; LLOG=$ALOG; echo "LockLab pid=$LPID log=$LLOG"; }
other_start() { start_app "$OTHER" "$@"; OPID=$APID; OLOG=$ALOG; echo "LockOther pid=$OPID log=$OLOG"; }
front() { lsappinfo info -only bundleid "$(lsappinfo front)" | sed -E 's/.*="?([^"]*)"?/\1/'; }
stop_pid() {  # stop_pid <bundleid> <pid>
  [ -n "${2:-}" ] || return 0
  kill -0 "$2" 2>/dev/null || { echo "$1 $2 already stopped"; return 0; }
  "$C" notify "$1" quit >/dev/null; sleep 1
  if kill -0 "$2" 2>/dev/null; then kill "$2"; sleep 0.5; fi
  if kill -0 "$2" 2>/dev/null; then kill -9 "$2"; fi
  kill -0 "$2" 2>/dev/null && echo "$1 $2 STILL RUNNING" || echo "$1 $2 stopped"
}
stop_all() {
  stop_pid no.brev.spike.lock "${LPID:-}"
  stop_pid no.brev.spike.lockother "${OPID:-}"
  pgrep -fl "LockLab.app|LockOther.app" || echo "no spike app running"
}
