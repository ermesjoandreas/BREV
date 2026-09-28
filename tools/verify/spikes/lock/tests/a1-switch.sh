#!/bin/bash
# A1: app switching (⌘-Tab stand-in via LaunchServices and NSRunningApplication), and distributed-notification
# delivery to the sandboxed app while it is active and while it is inactive.
set -u
source "$(dirname "$0")/../lib.sh"
now() { python3 -c 'import datetime;print(datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3])'; }
step() { echo "STEP $(now) $*"; }
trap stop_all EXIT
echo "front before: $(front)"
lab_start a1-lab --mode auto --ttl 90
sleep 2
step "1 front=$(front); probe while LockLab active, poster deliverImmediately=0"
"$C" probe 0; sleep 1.5
step "2 launch LockOther (open -n activates it)"
other_start a1-other --ttl 80
sleep 2; step "2b front=$(front)"
step "3 probe while LockLab INACTIVE, poster deliverImmediately=0"
"$C" probe 0; sleep 2
step "4 probe while LockLab INACTIVE, poster deliverImmediately=1"
"$C" probe 1; sleep 2
step "5 reactivate LockLab with 'open LockLab.app' (running instance)"
open "$LAB"; sleep 2; step "5b front=$(front)"
step "6 NSRunningApplication.activate(LockOther) from the CLI"
"$C" activate no.brev.spike.lockother; sleep 2; step "6b front=$(front)"
step "7 LockLab self-activation from the background: NSApp.activate(ignoringOtherApps: true)"
"$C" notify no.brev.spike.lock activate; sleep 2; step "7b front=$(front)"
step "8 make LockOther front again with 'open LockOther.app', then LockLab self-activation with NSApp.activate() (14+)"
open "$OTHER"; sleep 2; step "8a front=$(front)"
"$C" notify no.brev.spike.lock activate14; sleep 2; step "8b front=$(front)"
step "9 reactivate LockLab with 'open LockLab.app' (end state)"
open "$LAB"; sleep 2; step "9b front=$(front)"
