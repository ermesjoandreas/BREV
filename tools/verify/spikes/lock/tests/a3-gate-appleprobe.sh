#!/bin/bash
# A3: touchid mode in DRY form (never evaluates an LAContext, so no prompt is possible):
#   (a) the unlock action invoked without a human click (from a command handler) is refused by the gate;
#       a click posted with postToPid arrives with windowNumber 0 and does not reach the button at all;
#   (b) "dryunlock" runs the path up to the prompt: biometric SE key + HPKE wrap in the sandboxed app, no prompt.
# Plus: a com.apple.* distributed notification name (nobody else listens to it) reaches the sandboxed app.
set -u
source "$(dirname "$0")/../lib.sh"
now() { python3 -c 'import datetime;print(datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3])'; }
step() { echo "STEP $(now) $*"; }
trap stop_all EXIT
echo "front before: $(front)"
lab_start a3-lab --mode touchid --dry --ttl 40
sleep 2
XY=$(sed -nE 's/.*BUTTON-CG x=([0-9-]+) y=([0-9-]+) win=([0-9]+).*/\1 \2 \3/p' "$LLOG" | head -1); echo "button at $XY"
step "a1 posted click on the button"; "$C" click "$LPID" $XY; sleep 1.5
step "a2 action called without a click (gatecheck)"; "$C" notify no.brev.spike.lock gatecheck; sleep 1
step "a3 com.apple.* probe while active"; "$C" appleprobe; sleep 1
step "b1 dryunlock: key creation + wrap, stops before any prompt"; "$C" notify no.brev.spike.lock dryunlock; sleep 3
step "b2 end front=$(front)"
