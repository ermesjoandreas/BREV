#!/bin/bash
# A2: ⌘H (posted to LockLab's own pid only), NSRunningApplication.hide, idle counters in the sandbox,
# whether a posted event resets them, and timers during menu tracking.
set -u
source "$(dirname "$0")/../lib.sh"
now() { python3 -c 'import datetime;print(datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3])'; }
step() { echo "STEP $(now) $*"; }
trap stop_all EXIT
echo "front before: $(front)"
lab_start a2-lab --mode auto --ttl 120
sleep 3
step "1 idle: sandboxed ticks vs unsandboxed CLI"; "$C" idle; sleep 1; "$C" idle
step "2 ⌘H posted with postToPid to LockLab (pid $LPID), source=combined"
"$C" key "$LPID" 4 1 combined; sleep 3; step "2b front=$(front)"
step "3 unhide by 'open LockLab.app'"; open "$LAB"; sleep 3; step "3b front=$(front)"
step "4 NSRunningApplication.hide() from the CLI"; "$C" hide no.brev.spike.lock; sleep 3; step "4b front=$(front)"
step "5 unhide by 'open LockLab.app'"; open "$LAB"; sleep 3; step "5b front=$(front)"
for src in combined hid private; do
  step "6-$src wait until idle >= 3 s, then post key 'a' (keycode 0, no modifier) to LockLab pid, source=$src"
  for _ in $(seq 1 20); do
    v=$("$C" idle | sed -E 's/.*idleC=([0-9.]+).*/\1/'); python3 -c "import sys; sys.exit(0 if float('$v')>=3 else 1)" && break; sleep 1
  done
  "$C" idle; "$C" key "$LPID" 0 0 "$src"; sleep 0.3; "$C" idle; sleep 2.5
done
step "7 menu tracking: .common vs .default timers (popup closes itself after 3 s)"
"$C" notify no.brev.spike.lock menutest; sleep 5
step "8 end front=$(front)"
