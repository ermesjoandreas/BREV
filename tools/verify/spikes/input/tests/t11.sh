#!/bin/bash
# Smoke test of the owner's step (user mode, --sei A) with posted keys only.
source "$(dirname "$0")/../lib.sh"
lab_start t11-usermode -- --ttl 30 --user --sei A && sleep 0.8
echo "ioreg (A focused at launch): $(sei_pid)"
"$P" keys $LPID private keep 1101 0 11 8 49 39 41 33 49 24 14 >/dev/null; sleep 0.4
cmd focusB; echo "ioreg (B focused): $(sei_pid)"
"$P" keys $LPID private keep 1102 0 11 8 49 39 41 33 49 24 14 >/dev/null; sleep 0.4
cmd focusA; echo "ioreg (A again): $(sei_pid)"; cmd hide 1; echo "ioreg (hidden): $(sei_pid)"
lab_stop
grep -E "SEI |SUMMARY" $LOG | sed -E 's/^t=[0-9]+ //'
