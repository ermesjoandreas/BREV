# Sourced by the run scripts. Starts/stops InputLab and sends commands. Input goes only to InputLab's pid.
D="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP="$D/build/InputLab.app"
P="$D/bin/poster"
AX="$D/bin/axdump"
# lab_start <logname> [open-options...] -- [app args...]
lab_start() {
  local name=$1; shift
  local oo=() aa=()
  while [ $# -gt 0 ] && [ "$1" != "--" ]; do oo+=("$1"); shift; done
  [ "${1:-}" = "--" ] && shift
  aa=("$@")
  LOG="$D/out/$name.log"; : > "$LOG"
  open -n ${oo[@]+"${oo[@]}"} --stdout "$LOG" --stderr "$D/out/$name.err" "$APP" --args ${aa[@]+"${aa[@]}"}
  for _ in $(seq 1 60); do grep -q ' ready pid=' "$LOG" 2>/dev/null && break; sleep 0.25; done
  LPID=$(sed -nE 's/.* ready pid=([0-9]+).*/\1/p' "$LOG" | head -1)
  [ -n "$LPID" ] || { echo "lab did not start"; return 1; }
  echo "lab pid=$LPID log=$LOG"
}
cmd() { "$P" notify "$1" >/dev/null; sleep "${2:-0.4}"; }
sei_pid() { ioreg -l -w 0 | LC_ALL=C grep -a -o '"kCGSSessionSecureInputPID"=[0-9]*' | sort -u | tr '\n' ' '; echo; }
lab_stop() {
  "$P" notify quit >/dev/null; sleep 1
  if kill -0 "$LPID" 2>/dev/null; then kill "$LPID"; sleep 0.5; fi
  if kill -0 "$LPID" 2>/dev/null; then kill -9 "$LPID"; fi
  kill -0 "$LPID" 2>/dev/null && echo "lab $LPID STILL RUNNING" || echo "lab $LPID stopped"
}
