#!/bin/bash
# human.sh — de få stegene i U4 som trenger et menneske. Kjør fra Terminal.
#   las       ⌘-Tab, ⌘H og ⌃⌘Q (skjermlås) med testappen LockLab foran
#   touchid   Touch ID-dialogen: gir den fra seg «aktiv»? Feilkoder for Avbryt og feil finger
#   skjerm    (valgfritt) skjermen slukkes med pmset displaysleepnow
#   sov       (valgfritt) Macen sover med pmset sleepnow
#   rydd      fjern testappenes registrering i LaunchServices
# Loggene havner i out/human-*.log. Maskinen leser dem selv.
set -u
source "$(cd "$(dirname "$0")" && pwd)/lib.sh"

wait_lab() { while kill -0 "$LPID" 2>/dev/null; do sleep 0.5; done; echo; echo "LockLab er lukket."; }
summary() {  # $1 = log
  echo; echo "---- Oppsummering (maskinen leser dette; du trenger ikke tolke det) ----"
  sed -E 's/^t=[0-9.]+ up=[0-9.]+ //' "$1" | grep -E \
    "APP NSApplication(Did|Will)(Resign|Become)Active|APP NSApplicationDid(Hide|Unhide)|WIN NSWindowDid(Resign|Become)Key|^wall=[^ ]+ WS |WSAPP NSWorkspaceDidActivate|DIST|CHANGE scrLocked|WAKE|AUTH|EV type=1[01] .*cmd=true|DONE" \
    | grep -v "brevspike\|lock.probe"
  local n; n=$(grep -c "scrLocked=1 " "$1"); echo "sekunder med CGSSessionScreenIsLocked=1 i loggen: $n"
  grep "scrLocked=1 " "$1" | sed -E 's/^t=[0-9.]+ up=[0-9.]+ //' | sed -n '1p;$p'
}

case "${1:-}" in
  las)
    lab_start human-las --mode human --ttl 300 --quit-after-wake >/dev/null
    cat <<'TXT'

Vinduet «LockLab» er nå foran, øverst til høyre. Gjør dette i rekkefølge:
  a) Trykk ⌘-Tab og velg Terminal. Trykk ⌘-Tab igjen og velg LockLab.
  b) Trykk ⌘H. LockLab blir borte. Trykk ⌘-Tab og velg LockLab igjen.
  c) Trykk ⌃⌘Q (Control, Kommando og Q). Skjermen låses.
     Vent ca. 5 sekunder. Lås opp som vanlig.
  d) Vent. LockLab lukker seg selv ca. 8 sekunder etter at du har låst opp.
TXT
    wait_lab; summary "$LLOG"
    echo; echo "Send tilbake: «las ferdig»." ;;
  touchid)
    lab_start human-touchid --mode touchid --ttl 240 >/dev/null
    cat <<'TXT'

Vinduet «LockLab» har tre knapper: «Innebygd (test)», «Lås opp (test)» og «Ferdig».
Det kommer én Touch ID-dialog per klikk på «Lås opp (test)». Ingen annen dialog skal komme.
  a) Klikk «Lås opp (test)». Se på dialogen: er det en knapp «Bruk passord …»? Legg så fingeren på sensoren.
  b) Klikk «Lås opp (test)» igjen. Trykk «Avbryt» i dialogen.
  c) Klikk «Lås opp (test)» igjen. Legg en finger som IKKE er registrert (for eksempel en knoke) på sensoren,
     til dialogen lukker seg. Høyst 3 ganger. Står den fortsatt etter 3 forsøk, trykk «Avbryt».
     (Ikke flere forsøk: etter 5 feil sperrer macOS Touch ID til du skriver passordet.)
  d) Klikk «Innebygd (test)». Nå skal et lite fingeravtrykk-ikon komme inne i LockLab-vinduet, uten vanlig dialog.
     Legg fingeren på sensoren. Kommer det likevel en vanlig dialog, legg fingeren på og husk det.
  e) Klikk «Ferdig».
TXT
    wait_lab; summary "$LLOG"
    echo; echo "Send tilbake: «touchid ferdig», og ja/nei for: a) «Bruk passord»-knapp i dialogen?  d) ikon i vinduet?  d) vanlig dialog i tillegg?" ;;
  skjerm)
    lab_start human-skjerm --mode human --ttl 240 --quit-after-wake >/dev/null
    echo; echo "LockLab er foran. Ikke rør mus eller tastatur. Skjermen slukkes om 5 sekunder."
    sleep 5; pmset displaysleepnow
    echo "Vent 5 sekunder. Vekk skjermen (trykk Shift eller beveg musa). Lås opp hvis Macen ber om det."
    echo "LockLab lukker seg selv ca. 8 sekunder etter at skjermen er våken og ulåst."
    wait_lab; summary "$LLOG"
    echo; echo "Send tilbake: «skjerm ferdig», og ja/nei: måtte du låse opp?" ;;
  sov)
    lab_start human-sov --mode human --ttl 300 --quit-after-wake >/dev/null
    echo; echo "LockLab er foran. Macen sovner om 5 sekunder."
    sleep 5; pmset sleepnow
    echo "Vent 10 sekunder. Vekk Macen og lås opp."
    echo "LockLab lukker seg selv ca. 8 sekunder etter at du har låst opp."
    wait_lab; summary "$LLOG"
    echo; echo "Send tilbake: «sov ferdig»." ;;
  rydd)
    LSR=/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister
    for a in "$LAB" "$OTHER"; do "$LSR" -u "$a" 2>/dev/null; done
    pgrep -fl "LockLab.app|LockOther.app" || echo "Ingen testapp kjører. Ferdig." ;;
  *)
    echo "Bruk: $0 las | touchid | skjerm | sov | rydd" ;;
esac
