#!/bin/bash
# show_m.sh CASE: the M-relevant lines of a case's stdout.
D="$(cd "$(dirname "$0")" && pwd)"
echo "=== $1"
grep -a -E 'start|MallocScribble|reexec|scribble|freed|cfstring|csops|sandbox_check|argv count|psn|done|FAILED' "$D/out/$1/stdout.txt" | grep -v 'env names' | sed 's/^SPIKE //' | cut -c1-220
echo "stderr: $(head -c 400 "$D/out/$1/stderr.txt")"
