#!/bin/bash
# Which menu items does macOS add, and are they enabled with A, B or the text field focused?
# Run 1: Brev-like menus (no Edit menu). Run 2: --editmenu (a standard Edit menu).
source "$(dirname "$0")/../lib.sh"
for variant in noedit editmenu; do
  if [ $variant = editmenu ]; then lab_start t9-$variant -- --ttl 60 --editmenu; else lab_start t9-$variant -- --ttl 60; fi
  sleep 1.5
  for f in A B Field; do
    cmd focus$f 0.6; echo "== $variant focus=$f"; "$AX" $LPID --menus
  done
  cmd menus; cmd services
  lab_stop >/dev/null
  echo "-- app-side menu dump ($variant):"; grep -E "MENU|SERVICES|WRITINGTOOLS" $LOG | sed -E 's/^t=[0-9]+ //'

done
