#!/bin/bash
# human.sh — de få stegene i U2/U3 som trenger et menneske ved tastaturet.
# Ingenting her ber om Touch ID, passord eller nye tillatelser. Testvinduet er lite (øverst til høyre)
# og lukker seg selv. Kjør fra Terminal.
#   skriv      steg 1: skriv i testvinduet (maskinvare-tastatur), med en «keylogger» som bare teller
#   tjenester  steg 2 (valgfritt): aksentmeny, emoji, diktering, slå opp, høyreklikk
#   rydd       fjern testappens registrering i LaunchServices
set -u
D="$(cd "$(dirname "$0")" && pwd)"
APP="$D/build/InputLab.app"
OUT="$D/out"
mkdir -p "$OUT"

start_lab() {  # $1 = loggnavn, resten = app-argumenter
  local name=$1; shift
  LOG="$OUT/$name.log"; : > "$LOG"
  open -n --stdout "$LOG" --stderr "$OUT/$name.err" "$APP" --args "$@"
  for _ in $(seq 1 60); do grep -q ' ready pid=' "$LOG" 2>/dev/null && break; sleep 0.25; done
  LPID=$(sed -nE 's/.* ready pid=([0-9]+).*/\1/p' "$LOG" | head -1)
  [ -n "$LPID" ] || { echo "Testappen startet ikke."; exit 1; }
}
wait_lab() { while kill -0 "$LPID" 2>/dev/null; do sleep 0.5; done; echo "Testappen er lukket."; }

summary_common() {
  echo; echo "---- Oppsummering (maskinen leser dette; du trenger ikke tolke det) ----"
  grep -E "SUMMARY (A|B) typed" "$LOG" | sed -E 's/^t=[0-9]+ SUMMARY //'
  echo "Hendelseskilder (type: 1/2 museklikk, 10/11 tast, 12 modifikator, 22 rulling; pid=0 = fra maskinvare):"
  grep -E "SUMMARY EVSRC" "$LOG" | sed -E 's/^t=[0-9]+ SUMMARY EVSRC /  /'
  grep -E "ACTION|Human sendAction" "$LOG" | sed -E 's/^t=[0-9]+ /  /'
}

case "${1:-}" in
  skriv)
    "$D/bin/keylisten" 75 > "$OUT/human-keylisten.txt" 2>&1 &
    KL=$!
    sleep 1
    start_lab human-skriv --user --sei A --ttl 60
    cat <<'TXT'

Vinduet «InputLab» vises øverst til høyre i 60 sekunder. Venstre boks har fokus (grønn ramme).
  a) Skriv:  abc æøå ´e      (´ er tasten til venstre for rettetasten; trykk den, så e)
  b) Klikk i høyre boks og skriv det samme.
  c) Klikk på knappen «Plain», så på «Human».
  d) Vent til vinduet lukker seg selv.
TXT
    wait_lab
    kill "$KL" 2>/dev/null; wait "$KL" 2>/dev/null
    summary_common
    echo "Keylogger-test (bare antall; ingen tegn er lagret):"
    awk -v L="$LOG" '
      BEGIN { n = 0; while ((getline line < L) > 0) {
                if (line ~ /SEI enable/)  { sub(/.*abs=/, "", line); on[n] = line + 0 }
                if (line ~ /SEI disable/) { sub(/.*abs=/, "", line); off[n] = line + 0; n++ } } }
      /^KL (tap|hid)/ { split($3, a, "="); t = a[2] + 0; sec = 0
        for (i = 0; i < n; i++) if (t >= on[i] && t <= off[i]) sec = 1
        k = $2 (sec ? " med sikker inntasting" : " uten sikker inntasting"); c[k]++ }
      END { for (k in c) printf "  %-32s %d tastetrykk sett\n", k, c[k]; if (length(c) == 0) print "  ingen tastetrykk sett" }
    ' "$OUT/human-keylisten.txt"
    grep -E "^(preflight|session tap|IOHIDManagerOpen|no listen)" "$OUT/human-keylisten.txt" | sed 's/^/  /'
    echo; echo "Send tilbake: «1 ferdig», og om teksten i boksene ble riktig (abc æøå é)." ;;

  tjenester)
    start_lab human-tjenester --user --sei AB --ttl 150
    cat <<'TXT'

Vinduet «InputLab» vises øverst til høyre i 150 sekunder. Gjør dette først i venstre boks, så i høyre boks
(klikk i boksen først):
  1) Hold tasten e nede i 2 sekunder. Kommer en aksentmeny, trykk 2.
  2) Trykk 🌐+E (globustasten og E) for emoji. Kommer vinduet, klikk på en emoji.
  3) Trykk mikrofontasten (F5) eller 🌐 to ganger for diktering, og si «hei». Spør Macen om å slå på
     diktering, trykk Avbryt.
  4) Hold pekeren over boksen og trykk ⌃⌘D (slå opp).
  5) Høyreklikk i boksen.
Lukk vinduet med ⌘Q når du er ferdig.
TXT
    wait_lab
    summary_common
    echo "Innsetting utenom tastetrykk, og spørsmål om tekst fra systemet:"
    grep -E "inKeyDown=false|setMarkedText|attributedSubstring|characterIndex|unmarkText|(A|B) keyDown .*repeat=true|(A|B) keyDown .* pid=[1-9]|ACTION|EV type=1[01] .*pid=[1-9]" "$LOG" \
      | sed -E 's/^t=[0-9]+ /  /; s/ layout=[^ ]*//' | tail -40
    echo; echo "Send tilbake: «2 ferdig», og for venstre og høyre boks: hva skjedde i 1–5 (ingenting / meny / tekst kom inn)." ;;

  rydd)
    LSR=/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister
    "$LSR" -u "$APP" && echo "avregistrert: $APP" ;;

  *) echo "bruk: $0 skriv | tjenester | rydd" ;;
esac
