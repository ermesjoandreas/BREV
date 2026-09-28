#!/bin/bash
# U3 again with the naive text-input client (RAW, no overrides) present; focus on RAW, then on B.
source "$(dirname "$0")/../lib.sh"
lab_start t13-ax-raw -- --ttl 60 && sleep 0.8
G=$(grep -m1 "GEOM" $LOG); pt() { echo "$G" | sed -nE "s/.* $1=([0-9]+),([0-9]+).*/\1,\2/p"; }
for f in Raw B; do
  cmd focus$f 0.6
  "$AX" $LPID > "$D/out/t13-axdump-focus$f.txt" 2>&1
  "$AX" $LPID --hit $(pt RAW) >> "$D/out/t13-hit.txt" 2>&1
  "$AX" $LPID --menus | tail -1 >> "$D/out/t13-hit.txt"
done
lab_stop
for f in Raw B; do echo "focus $f: RAWCLIENT7f3a=$(grep -c RAWCLIENT7f3a "$D/out/t13-axdump-focus$f.txt") CTRLFIELD7f3a=$(grep -c CTRLFIELD7f3a "$D/out/t13-axdump-focus$f.txt") elements=$(tail -1 "$D/out/t13-axdump-focus$f.txt")"; done
cat "$D/out/t13-hit.txt"; grep "RAW attributedSubstring" $LOG | head -5 || true
