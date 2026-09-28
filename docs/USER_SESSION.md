# Brev: det du må gjøre (fase 2, fase 3 og delingen av kjernen)

Skrevet 28. september 2026 for eieren. Kjør alt i Terminal fra `~/BREV`. Ber macOS om en tillatelse du ikke venter: trykk «Ikke tillat» og noter det.

## Hvor vi er

- Fase 2 og fase 3 er ferdig kodet på grenen `claude/laughing-knuth-yhp8ji` (`cc7dbd6`). Ingenting er pushet.
- Rust-kjernen er delt i `brev-vault` og `brev-mail`. Svarene dine (Q1 til Q6) er bygget inn.
- Alle automatiske tester er grønne (`scripts/test.sh`, 28. september kl. 17).
- Maskinen har kjørt alt den kan uten deg (`docs/VERIFY-RESULTS.md`). V9 feiler som skrevet (beslutning 7).
- Brev har aldri vært installert her. Alt med Touch ID, ekte brev og Brev B venter på deg.
- Brev B mangler: `scripts/build.sh --instance b` finnes ikke ennå (fase 3, WP6). Se Runde 1, steg 7.
- Avgjort: signeringsnøkkelen (godtatt for testbrev), releet kjører som deg, og App ID `no.brev.app.b`.

## Beslutninger som gjenstår

Svar kort, for eksempel «2c 4b 5a 6b 7a».

**2. Touch ID-vinduet og lås ved opplåsing.** Brev låser når en annen app kommer foran. Tar Touch ID-vinduet over, havner du på låseskjermen rett etter opplåsing. Svaret kommer i Runde 1, steg 5.
- a) Vent inntil 1,5 sekunder på at Brev blir aktiv igjen, bare etter Touch ID.
- b) Vis Touch ID inne i Brev-vinduet (et nytt rammeverk du må godkjenne).
- c) Behold regelen som den er.
- Anbefaling: c hvis opplåsingen virker, ellers a.

**4. Hvilke miljøvariabler Brev godtar ved oppstart.** I dag en forbudsliste. Rust nekter i tillegg `DYLD_*` og krever `MallocScribble=1`.
- a) Behold forbudslisten.
- b) En tillatsliste: bare det macOS selv setter. Alt annet regnes som utrygt.
- Anbefaling: b, når V49 (Runde 2, A) har vist hva Finder og Dock setter.

**5. Falske tastetrykk og klikk (V32, V33).** Ikke testet: systemets felles kø, System Events, Tilgjengelighetstastatur og Skjermdeling.
- a) Kjør testen mens du sitter ved Macen.
- b) La hullet stå åpent til senere.
- Anbefaling: a. Skriver noe seg selv inn i Brev: stopp og si fra.

**6. ⌘Q mens et ark er åpent** (skrivevinduet eller «Slett alt»-arket). macOS ignorerer da «Avslutt», også fra Dock og ved utlogging. Brev står ulåst til en annen lås slår inn.
- a) La det være. Slik gjør alle Mac-apper.
- b) ⌘Q låser og avslutter. Et halvskrevet brev forsvinner, som ved ⌘-Tab.
- Anbefaling: b.

**7. V9 og fire usynlige menylinje-vinduer.** Alle apper har dem. De viser bare menylinjen (Brev, Arkiv).
- a) V9 teller bare vinduene Brev lager selv.
- b) La V9 feile og godta det som restrisiko.
- Anbefaling: a.

## Runde 1 (ca. 25 min)

Byggingen kommer i tillegg. Noter hver rad: nummer, pass eller feil, og hva du så. Filen lages i steg 3.

1. **Rydd skjermen (1 min).** «Terminal vil ha tilgang til data fra andre apper»: trykk «Ikke tillat». Andre gamle dialoger (krasjrapport, tilgjengelighet): «Ignorer» eller lukk.
2. **Bygg.** `scripts/build.sh && tools/verify/build.sh && (cd core && cargo build --release -p brev-relay)`
3. **Tre Terminal-vinduer i `~/BREV` (2 min).** Lim inn blokken under «Setup» i `docs/VERIFY.md` i alle tre.
   - Vindu 3, releet (tomt fra start): `[ -e "$RD" ] && mv "$RD" "$R/relay-before-$(date +%s)"`, så `"$RELAY" serve --db "$RDB" --listen 127.0.0.1:8787 --trace > "$R/relay.log"`
   - Vindu 2, loggen: `/usr/bin/log stream --level debug --predicate 'process == "Brev"' > "$R/stream.log"`
   - Vindu 1: `curl -s http://127.0.0.1:8787/v1/health; echo; head -1 "$R/stream.log"`. Forventet: `brev-relay v1` og `Filtering the log data …`.
   - Vindu 1: `{ sw_vers; xcodebuild -version; git rev-parse --short HEAD; } > "$R/miljo.txt"; touch "$R/resultater.txt"; open -e "$R/resultater.txt"`
4. **V51, før Brev finnes (3 min).** I vindu 1. `--dry` gir ingen dialog. Hver `--unlock` gir én Touch ID-dialog uten passordknapp.
   ```
   PROBE="$T/touchid-probe/Build/Products/Release/TouchIDProbe.app"
   PROBE0="$T/touchid-probe-scrub0/Build/Products/Release/TouchIDProbe.app"
   open -W --stdout "$R/v51-dry.txt" "$PROBE" --args --dry
   open -W --stdout "$R/v51.txt" "$PROBE" --args --unlock
   open -W --stdout "$R/v51-scrub0.txt" "$PROBE0" --args --unlock
   ```
   Noter: `PASS` i alle tre, og om `v51-scrub0.txt` sier `NEGATIVE CONTROL: residue` eller `NEGATIVE CONTROL EMPTY`. Står det `FAIL` i `v51.txt`: si fra.
5. **Første onboarding og opplåsing (5 min).** `open "$APP"`
   - V36: fem regler på bokmål. «Opprett nøkler» er grå til du krysser av «Jeg forstår …».
   - V29: mens onboarding vises, `open -n "$APP"`, så `pgrep -x Brev`. Én PID.
   - V37: trykk «Opprett nøkler», så `pkill -9 -x Brev` og `open "$APP"`. Onboarding skal komme tilbake.
   - Gå gjennom til slutt. «Lås opp med Touch ID»: én dialog, ingen passordknapp, navnet «Brev» (V27).
   - Havner du på låseskjermen rett etter Touch ID, noter det (beslutning 2). Kjør så `/usr/bin/log show --last 5m --predicate 'subsystem == "no.brev.app" AND category == "touchid"'` og noter linjen `resign active during Touch ID (unlock)`, eller «ingen linje».
   - `grep -E 'open failed|unlockExpired' "$R/stream.log"` skal ikke gi noe. Et treff er en feil å melde, ikke skadede filer.
6. **Registrer adressen (2 min).** Skriv `brev-secret-me`, trykk «Registrer» (V55). Én dialog: «Brev» … «registrere adressen din», ingen passordknapp. Kjør `log show`-linjen fra steg 5 igjen. Står det `resign active during Touch ID (sign)`: si fra. Da må en bryter slås på og Brev bygges på nytt.
7. **Bygg og start Brev B (4 min).** `scripts/build.sh --help`. Står ikke `--instance` der, er WP6 ikke gjort (slik er det i `cc7dbd6`). Stopp runden her og si fra, så lager jeg det. Ellers:
   - `scripts/build.sh --instance b`. Første gang registreres App ID `no.brev.app.b`.
   - `open "$APPB"`. Onboarding, så «Lås opp med Touch ID»: dialogen skal si «Brev B». Registrer `brev-secret-peer`.
8. **Legg til hverandre (2 min).** I Brev: «Legg til kontakt», skriv `brev-secret-peer`, «Legg til». I Brev B det samme med `brev-secret-me`. Ingen Touch ID her (V26).
9. **Ett brev hver vei (5 min).** Skriv `BREV-SECRET-BODY æøå` i emne og tekst. «Send»: én dialog per brev, «… sende brevet», ingen passordknapp, riktig navn (V56, V57).
   - Mens brevet venter, i vindu 1: `waiting; hits "$M" "$RD"`. Et tall på 1 eller mer, og ingen treff (V58).
   - Bytt til mottakeren og lås opp. Brevet kommer ved første synk, i alle tre rutene.
   - Etter begge: `waiting` skal gi `0` (V59).

Se etter hele tiden: én dialog per trykk, aldri en passordknapp, riktig navn («Brev» eller «Brev B»), og aldri en dialog du ikke selv utløste (V26).

## Runde 2 (resten av sjekklisten, ca. 2 timer)

Kommandoene står under «Commands» i `docs/VERIFY.md`, merket med radnummer. De som trenger Brev ulåst, starter med `sleep 30;`: kjør, bytt til Brev, lås opp og gjør klart. Gi Terminal en tillatelse bare når en gruppe trenger den. Et markørbrev betyr et brev med `BREV-SECRET-BODY æøå`.

**A. Oppstarter (10 min).** Avslutt Brev før hver.
- V28: kjør linjene. Kjør `defaults delete -g …` med en gang etter hver `defaults write -g`.
- V49: start med `open "$APP"`, fra Finder og fra Dock. Lagre `ps -wwE -p "$(pgrep -x Brev)"` for Finder og Dock i `$R/v49-finder.txt` og `$R/v49-dock.txt` (til beslutning 4).
- V26: `osascript -e 'activate application "Brev"'`. Ingen Touch ID-dialog.
- V3: `osascript -e 'tell application "Brev" to get name of every window'` (gi Automatisering). Noter feilkoden. -1708 er forventet.
- På låseskjermen: V27 «Avbryt», V43, første del av V70, og V48s sperre: feil finger til «Touch ID er sperret …». Aldri en passordknapp. Etterpå trenger Macen passordet ditt én gang.

**B. Kontakter og relé (20 min).** Gi Terminal Tilgjengelighet.
- V67 for «Legg til kontakt»-arket og «Legg til» med `brev-secret-peer` skrevet.
- V58 andre del, V61 (koden Brev viser for Brev B er lik Brev Bs egen kode), V56 («Avbryt» i dialogen beholder utkastet, `waiting` uendret).
- V54, V64, V62 (⌘-Tab mens send-dialogen står), V63 (to deler, med den tidsstyrte linjen).

**C. Opptak og tilgjengelighet (20 min).** Gi Terminal Skjermopptak. Et markørbrev åpent.
- V4 (⇧⌘4 vindu og område, ⇧⌘5 opptak), V5 til V7 (`capture-probe`), V9 med skrivevinduet åpent, V10 (Accessibility Inspector), V11, V12 (gi Automatisering for System Events), V13 på «Send» og «Lås opp med Touch ID», V68.
- V8 trenger en annen Mac eller iPad. Har du ingen: noter «ikke kjørt».
- Synes et brev i et opptak: stopp og si fra.

**D. Skriving og utklipp (20 min).** Skrivevinduet åpent.
- V30, V31 (gi Inndataovervåking), V34, V35, andre del av V70, V14, V15, V16.
- V32 og V33 bare etter beslutning 5.

**E. Disk, logg og lås (20 min).** Gi Terminal tilgang til data fra andre apper.
- V17, V40, V41, V21 (fra `~/BREV`).
- V22, V23 (⌃⌘Q), V24 (dvale), V25 (5 min uten å røre noe, også med Brev-menyen åpen), V46, V47. V44 til slutt.

**F. Etter avslutning (10 min).** Brev avsluttet: V17 og V41 igjen, og V18. Så V65: Brev B sender et nytt markørbrev. `open "$VAPP"`, send et markørbrev til Brev B, åpne brevet fra Brev B, og lås med det åpent (⌘L).

**G. Til slutt, det som ødelegger (25 min).** I denne rekkefølgen:
1. V20 (`kill -SEGV`), så V17 og V41 igjen.
2. V60 på Brev B: nullstill som i V38, så `"$RELAY" release --db "$RDB" "$ADDR_B"`. Ta V67-delene for «Godta ny kode» og «Godta» før du trykker selv.
3. Kopier Brev-mappen til side: `cp -Rp "$D" "$R/D-kopi"`
4. V38, med V9s del for «Slett alt»-arket og V13-trykkene på «Slett alt og start på nytt» og «Slett alt» før du trykker selv.
5. Ny onboarding. På adressesiden, uten å registrere: V46s del for siden og V67s del for siden og «Registrer» med `brev-secret-me` skrevet.
6. V52: avslutt Brev, `cp -p "$R/D-kopi/brev.db" "$D/brev.db"`, start. Forventet: «Filene til Brev er skadet. Brevene kan ikke åpnes.»
7. Aller sist V48: legg til et fingeravtrykk i Systeminnstillinger. Forventet: «Fingeravtrykkene på denne Macen ser ut til å være endret …». Både Brev og Brev B blir ulesbare, og andre apper som bruker Touch ID slik, mister nøklene sine.
8. Stopp loggen (⌃C i vindu 2) og kjør V19s linjer.

## Rydd opp (5 min)

1. Stopp releet: ⌃C i vindu 3.
2. `defaults read -g NSTraceEvents; defaults read -g TSMEventTracing`. Begge skal si `does not exist`. Står en der: `defaults delete -g` og navnet.
3. Systeminnstillinger → Personvern og sikkerhet: ta Terminal bort fra Tilgjengelighet, Skjermopptak, Inndataovervåking, Automatisering og tilgang til andre apps data.
4. Fingeravtrykket fra V48 kan du slette igjen.
5. `echo "$R"` og send meg stien. Jeg fører resultatene inn i D-0053 og lukker fase 2 og fase 3.
