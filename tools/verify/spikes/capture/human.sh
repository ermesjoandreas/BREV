#!/bin/bash
# human.sh — de få stegene i U1 som trenger et menneske ved Macen.
# Ingenting her ber om Touch ID, passord eller tillatelser. Testvinduene er små (øverst til høyre),
# tar ikke fokus fra Terminal, og lukker seg selv (TTL). Kjør fra Terminal (som har Skjermopptak).
set -u
D="$(cd "$(dirname "$0")" && pwd)"
APP="$D/build/SpikeCapture.app"
launch() {  # $1 = ttl sekunder, resten = variant-argumenter
  local ttl=$1; shift
  open -n -g --stdout "$D/out/human-app.log" --stderr "$D/out/human-app.err" "$APP" --args --ttl "$ttl" "$@"
  for i in $(seq 1 40); do grep -q '^ready' "$D/out/human-app.log" 2>/dev/null && break; sleep 0.25; done
  sed -nE 's/^ready pid=([0-9]+).*/\1/p' "$D/out/human-app.log"
}
stop() { kill "$1" 2>/dev/null; sleep 0.5; pgrep -f "$APP" >/dev/null && pkill -9 -f "$APP"; echo "Testappen er lukket."; }
case "${1:-}" in
  vis)   # Steg 1: se at beskyttet innhold faktisk vises på skjermen
    PID=$(launch 25 protected); echo "Vinduene vises i 25 sekunder øverst til høyre. Se etter lilla PROT-7f3a og PROTX-7f3a."
    sleep 25; stop "$PID" ;;
  bilder) # Steg 2 (og 4): ⇧⌘4 og ⇧⌘5 mot testvinduene
    PID=$(launch 120 protected); echo "Vinduene vises i 2 minutter. Ta skjermbildene nå (se USER_STEPS.md)."
    sleep 120; stop "$PID" ;;
  indikator) # Steg 3: vises opptaksikonet i menylinjen?
    PID=$(launch 60)
    echo; echo ">>> FASE A (6 s): CGDisplayStream. Se på menylinjen øverst til høyre NÅ."; HOLD=6 "$D/bin/probe" cgstream | grep -E "EXCL|holding"
    echo; echo "    pause 5 s"; sleep 5
    echo ">>> FASE B (6 s): AVCaptureScreenInput. Se på menylinjen NÅ."; HOLD=6 "$D/bin/probe" avcap | grep -E "EXCL|holding"
    echo; echo "    pause 5 s"; sleep 5
    echo ">>> FASE C (6 s): ScreenCaptureKit. Se på menylinjen NÅ."; HOLD=6 "$D/bin/probe" sck-stream1 | grep -E "EXCL|holding"
    echo; stop "$PID" ;;
  rydd)  # Til slutt: fjern testappenes registrering i LaunchServices (ingenting annet)
    LSR=/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister
    for a in "$APP" "$D/../build/SpikeCapture.app"; do [ -d "$a" ] && "$LSR" -u "$a" && echo "avregistrert: $a"; done ;;
  *) echo "bruk: $0 vis | bilder | indikator | rydd" ;;
esac
