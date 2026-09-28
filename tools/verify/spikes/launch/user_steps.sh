#!/bin/bash
# user_steps.sh finder|dock|typing — the human half of spike "launch" (§14.2 L and M).
# Uses only the test apps in ./build (bundle ids no.brev.spike.*). Sends no
# input anywhere; the human does the clicking and typing. Prints counts only.
set -uo pipefail
D="$(cd "$(dirname "$0")" && pwd)"
APP="$D/build/LaunchSpike.app"
GTA="$D/build/LaunchSpikeGTA.app"
O="$D/out/user"; mkdir -p "$O"

report_launch() { # $1 = label, $2 = start time
    sleep 1
    /usr/bin/log show --start "$2" --predicate 'process == "LaunchSpike" AND subsystem == "no.brev.spike.launch"' > "$O/$1.log" 2>&1
    echo "---- $1 ----"
    if ! grep -q 'SPIKE start' "$O/$1.log"; then echo "Fant ingen oppstart av LaunchSpike i loggen."; return; fi
    grep -a -E 'SPIKE (argv count|psn arg present|early env MallocScribble=|early scribble scan|willTerminate)' "$O/$1.log" \
        | sed -E 's/.*SPIKE //; s/argv0=[^ ]* //' | cut -c1-160
    grep -a -o -E 'SPIKE early env names=.*' "$O/$1.log" | head -1 | cut -c1-900
}

wait_for_launch() { # waits up to 120 s for LaunchSpike to start, then for it to quit
    echo "Venter på at LaunchSpike starter (opptil 2 minutter) ..."
    for _ in $(seq 1 240); do pgrep -x LaunchSpike >/dev/null && break; sleep 0.5; done
    if ! pgrep -x LaunchSpike >/dev/null; then echo "LaunchSpike startet ikke."; return 1; fi
    echo "LaunchSpike kjører; den avslutter seg selv etter 6 sekunder."
    for _ in $(seq 1 40); do pgrep -x LaunchSpike >/dev/null || break; sleep 0.5; done
    pkill -x LaunchSpike 2>/dev/null
    return 0
}

keyargs() {
    while read -r k; do case "$k" in *Level) v=9;; *) v=YES;; esac; printf '%s\n%s\n' "-$k" "$v"; done < <(cat "$D/keys-batch.txt" "$D/keys-batch2.txt")
}

typing_run() { # $1 = label, $2 = app
    local out="$O/$1"; rm -rf "$out"; mkdir -p "$out"
    local args=(); while IFS= read -r a; do args+=("$a"); done < <(keyargs)
    echo
    echo "Et lite vindu ('spike') åpner seg nede til venstre. Skriv:  brev  (fire bokstaver) nå."
    echo "Vinduet lukker seg selv etter 20 sekunder."
    # DRYRUN=1 (spike author only): background launch, 4 s, so no real keystroke can reach it.
    local bg=() secs=20; [ "${DRYRUN:-0}" = 1 ] && { bg=(-g); secs=4; }
    /usr/bin/open -n -W "${bg[@]}" --stdout "$out/stdout.txt" --stderr "$out/stderr.txt" --env SPIKE_SECS=$secs -a "$2" --args "${args[@]}"
    echo "---- $1 ----"
    local n0 nx
    n0=$(grep -a -c 'SPIKE event keyDown.*srcpid=0 ' "$out/stdout.txt")
    nx=$(grep -a 'SPIKE event keyDown' "$out/stdout.txt" | grep -a -v -c 'srcpid=0 ')
    echo "tastetrykk appen fikk: srcpid=0: $n0, annen srcpid: $nx"
    grep -a -o 'srcpid=[0-9-]*' "$out/stdout.txt" | sort | uniq -c | tr '\n' ' '; echo
    echo "stderr-linjer: $(wc -l < "$out/stderr.txt" | tr -d ' ')"
    echo "linjer med tegn eller tastekoder: chars=: $(grep -a -c 'chars="' "$out/stderr.txt"), keyCode=: $(grep -a -c 'keyCode=' "$out/stderr.txt"), virtualKeyCode=: $(grep -a -c 'virtualKeyCode=' "$out/stderr.txt"), keychar: $(grep -a -c 'keychar' "$out/stderr.txt"), 'Received event': $(grep -a -c 'Received event' "$out/stderr.txt")"
    for c in b r e v; do printf '%s' "chars=\"$c\": $(grep -a -c "chars=\"$c\"" "$out/stderr.txt")  "; done; echo
}

case "${1:-}" in
    finder)
        T0=$(date '+%Y-%m-%d %H:%M:%S')
        /usr/bin/open -R "$APP"
        echo "Finder viser nå LaunchSpike.app. Dobbeltklikk den."
        wait_for_launch && report_launch finder "$T0"
        ;;
    dock)
        T0=$(date '+%Y-%m-%d %H:%M:%S')
        echo "Start LaunchSpike fra Dock nå."
        wait_for_launch && report_launch dock "$T0"
        ;;
    typing)
        typing_run release "$APP"
        typing_run control-get-task-allow "$GTA"
        ;;
    *)
        echo "bruk: $0 finder|dock|typing"; exit 2 ;;
esac
pgrep -f "$D/build/" >/dev/null && { echo "Rydder: avslutter testapp som fortsatt kjører."; pkill -f "$D/build/"; }
exit 0
