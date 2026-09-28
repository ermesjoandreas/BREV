#!/bin/bash
# Norwegian layout via posted key codes, views A and B, secure input off and on.
source "$(dirname "$0")/../lib.sh"
lab_start t5-norwegian -- --ttl 90 && sleep 0.8
SEQ="39 41 33 39+s 41+s 33+s 24 14 30 32 24+s 14 30+o 45 42 21+s 26+o 26+so 28+o 25+o 28+so 25+so 24 49 44"
for v in A B; do cmd focus$v
  for s in off on; do [ $s = on ] && cmd seiOn; [ $s = off ] && cmd seiOff
    echo "== view $v sei=$s"; "$P" keys $LPID private keep 5$([ $v = A ] && echo 1 || echo 2)$([ $s = on ] && echo 1 || echo 0) $SEQ; sleep 0.4; cmd status 0.3
  done; cmd seiOff
done
lab_stop
grep -E "A keyDown|B keyDown|B insertText|B setMarkedText|B doCommand|B unmarkText|B attributed|STATUS" $LOG | sed -E 's/ uid=503//; s/ layout=com.apple.keylayout.Norwegian//' > "$D/out/t5-summary.txt"
