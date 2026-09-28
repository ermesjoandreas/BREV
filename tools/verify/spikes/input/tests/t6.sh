#!/bin/bash
# Press-and-hold: key down, autorepeat key downs, key up, then digit 1 (selects the first accent in the
# press-and-hold menu if one is shown). Views A and B. Input only to InputLab's pid.
source "$(dirname "$0")/../lib.sh"
lab_start t6-presshold -- --ttl 60 && sleep 0.8
HOLD="0+d+w 0+r+w 0+r+w 0+r+w 0+r+w 0+r+w 0+r+w 0+r+w 0+u+w"
for v in A B; do
  cmd focus$v; echo "== view $v"
  "$P" keys $LPID private keep 60$([ $v = A ] && echo 1 || echo 2) $HOLD; sleep 1.0
  "$P" keys $LPID private keep 61$([ $v = A ] && echo 1 || echo 2) 18; sleep 0.8
  "$P" keys $LPID private keep 62$([ $v = A ] && echo 1 || echo 2) 53; sleep 0.5
done
lab_stop
grep -E "A keyDown|B keyDown|B insertText|B setMarkedText|B doCommand|B unmarkText|B attributed|B characterIndex|CMD focus" $LOG | sed -E 's/ uid=503//; s/ layout=com.apple.keylayout.Norwegian//; s/ state=[0-9]+//' > "$D/out/t6-summary.txt"
