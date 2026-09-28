#!/bin/bash
# Keystroke accumulation (U2.5): type the 16-char marker into view A or B by posted key events (to InputLab's
# pid only), then InputLab scans its own memory: typed / after wipe / after one more key / after 3 s idle.
source "$(dirname "$0")/../lib.sh"
for scrib in unset 1; do
  for v in A B; do
    name="t7-scan-$v-scribble-$scrib"
    if [ $scrib = 1 ]; then lab_start $name --env MallocScribble=1 -- --ttl 60; else lab_start $name -- --ttl 60; fi
    sleep 0.8; cmd focus$v; cmd scan 1.5
    "$P" keys $LPID private keep 700 text:BREV-SECRET-BODY >/dev/null; sleep 0.5
    cmd scan 1.5; cmd wipe; cmd scan 1.5
    "$P" keys $LPID private keep 701 0 >/dev/null; sleep 0.3; cmd scan 1.5
    sleep 3; cmd scan 1.5
    lab_stop >/dev/null
    echo "$v scribble=$scrib: $(grep -E 'SCAN' $LOG | sed -E 's/.*SCAN cmd (u8=[0-9]+ u16=[0-9]+).*tags=(\[[^]]*\]) scribble=([^ ]*).*/\1 tags=\2 env=\3/' | tr '\n' '|')"
  done
done
