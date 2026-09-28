#!/bin/bash
# Automated part of the U4 lock spike (no prompt, no screen lock, input only to LockLab's own pid).
# Builds, runs A1-A3, leaves logs in out/. Each test quits its apps on exit.
set -u
D="$(cd "$(dirname "$0")" && pwd)"
"$D/build.sh" | tail -1
for t in a1-switch a2-hide-idle-menu a3-gate-appleprobe; do
  echo "== $t"; "$D/tests/$t.sh" > "$D/out/${t%%-*}-runner.txt" 2>&1; tail -2 "$D/out/${t%%-*}-runner.txt"
done
LSR=/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister
"$LSR" -u "$D/build/LockLab.app"; "$LSR" -u "$D/build/LockOther.app"
pgrep -fl "LockLab.app|LockOther.app" || echo "no spike app running"
