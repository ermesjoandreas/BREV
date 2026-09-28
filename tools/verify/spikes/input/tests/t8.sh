#!/bin/bash
# U3: accessibility dump of InputLab (read-only AX API from this CLI), hit tests, AXPress.
source "$(dirname "$0")/../lib.sh"
lab_start t8-ax -- --ttl 90 && sleep 0.8
cmd focusA; "$P" keys $LPID private keep 800 text:BREV-SECRET-BODY >/dev/null
cmd focusB; "$P" keys $LPID private keep 801 text:BREV-SECRET-BODY >/dev/null
cmd focusA; sleep 0.5
G=$(grep -m1 "GEOM" $LOG); echo "$G"
pt() { echo "$G" | sed -nE "s/.* $1=([0-9]+),([0-9]+).*/\1,\2/p"; }
"$AX" $LPID > "$D/out/t8-axdump.txt" 2>&1
"$AX" $LPID --hit $(pt A) $(pt B) $(pt MIN) $(pt PLAIN) $(pt FIELD) $(pt PlainBtn) $(pt HumanBtn) > "$D/out/t8-hit.txt" 2>&1
"$AX" $LPID --press Plain Human Testvalg > "$D/out/t8-press.txt" 2>&1
sleep 0.5
lab_stop
grep -E "ACTION|Human |HumanCell" $LOG > "$D/out/t8-actions.txt"
