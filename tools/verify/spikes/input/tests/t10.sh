#!/bin/bash
# (a) listen-only tap for InputLab's pid only: SEI off -> on -> off, posted keys each time.
# (b) secure input after InputLab is killed with SIGKILL while SEI is on.
source "$(dirname "$0")/../lib.sh"
lab_start t10-tap -- --ttl 60 && sleep 0.8; cmd focusA
"$P" tap $LPID 9 > "$D/out/t10-tap.txt" 2>&1 & TP=$!; sleep 1
echo "== off"; "$P" keys $LPID private keep 1001 11 8 >/dev/null; sleep 0.5
cmd seiOn; echo "== on  ioreg: $(sei_pid)"; "$P" keys $LPID private keep 1002 14 3 >/dev/null; sleep 0.5
cmd seiOff; echo "== off ioreg: $(sei_pid)"; "$P" keys $LPID private keep 1003 5 4 >/dev/null; sleep 0.5
wait $TP
echo "== (b) SEI on, then kill -9"; cmd seiOn; echo "ioreg before kill: $(sei_pid)"
kill -9 $LPID; sleep 1; echo "ioreg after kill -9: $(sei_pid)"; kill -0 $LPID 2>/dev/null && echo "still running" || echo "lab $LPID gone"
echo "---- tap"; cat "$D/out/t10-tap.txt"
echo "---- lab keys"; grep -E "A keyDown" $LOG | sed -E 's/^t=[0-9]+ //; s/ layout=[^ ]*//; s/ state=[0-9]+//; s/ uid=503//'
