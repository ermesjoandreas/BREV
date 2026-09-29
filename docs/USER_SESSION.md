# Brev: det du må gjøre (fase 2, 3 og 4 på én gang)

Skrevet 29. september 2026 for eieren. Denne listen erstatter fase 3-listen på den andre grenen. Kjør alt i Terminal fra en utsjekk av `claude/phase4` (for eksempel `~/BREV` etter `git switch claude/phase4`; nekter git fordi grenen er sjekket ut et annet sted, si fra til meg). Ber macOS om en tillatelse du ikke venter: trykk «Ikke tillat» og noter det.

## Hvor vi er

- Fase 3, delingen av kjernen og fase 4 er ferdig kodet på grenen `claude/phase4`. Ingenting er pushet.
- Fase 5 uten menneske er gjort: cargo-deny og CI, Swift-advarsler som feil, minnegjennomgangen og reproduserbar bygging.
- Én kjøring tester fase 2, 3 og 4. Fase 4 godtar ikke filer fra fase 3, så relé og Brev starter tomme.
- Alt med Touch ID, ekte brev og Brev B venter på deg. Radene står i `docs/VERIFY.md`.
- Avgjort: utklippet tømmes etter 60 s og når Brev avsluttes, ikke ved lås. Signeringsnøkkelen er godtatt for testbrev.

## Beslutninger som gjenstår

Svar kort, for eksempel «2c 4b 5a 6b 7a».

**2. Touch ID-vinduet og lås ved opplåsing.** Brev låser når en annen app kommer foran. Tar Touch ID-vinduet over, havner du på låseskjermen rett etter opplåsing. Svaret kommer i Runde 1, steg 4.
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

Før en ekte utgivelse, ikke nå: punktene i `docs/DISTRIBUTION.md` §7.

## Runde 1 (ca. 30 min)

Byggingen kommer i tillegg. Noter hver rad: nummer, pass eller feil, og hva du så. Filen lages i steg 3.

1. **Rydd skjermen (1 min).** «Terminal vil ha tilgang til data fra andre apper»: trykk «Ikke tillat». Andre gamle dialoger: «Ignorer» eller lukk.
2. **Bygg.** `scripts/build.sh && scripts/build.sh --instance b && tools/verify/build.sh && (cd core && cargo build --release -p brev-relay)`
3. **Tre Terminal-vinduer (3 min).** Lim inn blokken under «Setup» i `docs/VERIFY.md` i alle tre.
   - Vindu 3, releet (tomt fra start): `[ -e "$RD" ] && mv "$RD" "$R/relay-before-$(date +%s)"`, så `scripts/relay.sh --trace > "$R/relay.log"`
   - Vindu 2, loggen: `/usr/bin/log stream --level debug --predicate 'process == "Brev"' > "$R/stream.log"`
   - Vindu 1: `curl -s http://127.0.0.1:8787/v1/health; echo; head -1 "$R/stream.log"`. Forventet: `brev-relay v1` og `Filtering the log data …`.
   - Vindu 1: `{ sw_vers; xcodebuild -version; git rev-parse --short HEAD; } > "$R/miljo.txt"; touch "$R/resultater.txt"; open -e "$R/resultater.txt"`
   - Vindu 1, fire rot-invitasjoner: `for i in 1 2 3 4; do "$RELAY" invite --db "$RDB" > "$R/root-$i"; done; cat "$R"/root-*`. Fire linjer som starter med `brev1.`. Lim inn `id_of() { … }` fra starten av «Phase 4» i «Commands». Så `pbcopy < "$R/root-1"`.
4. **Brev: første oppstart (5 min).** `open "$APP"`
   - Står det «Filene til Brev er skadet» (en gammel Brev): «Slett alt og start på nytt», så «Slett alt».
   - Kryss av «Jeg forstår …», trykk «Opprett nøkler», så «Lås opp med Touch ID». Én dialog, ingen passordknapp, navnet «Brev» (V27).
   - Havner du på låseskjermen rett etter Touch ID, noter det (beslutning 2). Kjør `/usr/bin/log show --last 5m --predicate 'subsystem == "no.brev.app" AND category == "touchid"'` og noter linjen `resign active during Touch ID (unlock)`, eller «ingen linje».
5. **Brev: invitasjon og adresse (3 min).** På «Lim inn invitasjonen»: ⌘V i feltet.
   - V72: kom det et varsel fra macOS om utklippstavlen? Noter ja eller nei. Ja betyr at jeg bygger variant (b).
   - «Fortsett»: «Invitasjon fra Brev-tjenesten.» Skriv `brev-secret-me` og trykk «Registrer» (V55). Én dialog, «registrere adressen din», ingen passordknapp.
   - Kjør `log show`-linjen fra steg 4 igjen. Står det `resign active during Touch ID (sign)`: si fra. Da må en bryter slås på og Brev bygges på nytt.
6. **Brev B til adressesiden (3 min).** `open "$APPB"`. Onboarding og opplåsing som i steg 4, men dialogen skal si «Brev B». Stopp på «Lim inn invitasjonen».
7. **Inviter Brev B (5 min, V71 og V77).** Vindu 1: `n="$(wc -l < "$R/relay.log")"`.
   - I Brev: lås opp, «Kontakter», «Lag invitasjon». En kode vises, ingen Touch ID. Trykk «Kopier koden». Nå har du 60 sekunder.
   - I Brev B: lås opp, ⌘V. V77: ⌘→, så ← 27 ganger, ⌫, skriv en annen bokstav (a–z eller 2–7), «Fortsett». Forventet: «Invitasjonskoden stemmer ikke …», og ingen «Invitert av».
   - Slett feltet med ⌫, ⌘V igjen, «Fortsett». Forventet: «Invitert av:», med `brev-secret-me` og samme kode som Brev viser for seg selv.
   - Limes ingenting inn, er de 60 sekundene gått: lag og kopier en ny kode i Brev.
8. **Registrer Brev B (2 min).** Skriv `brev-secret-peer`, «Registrer». Én dialog, «Brev B».
   - Etter noen sekunder viser begge den andre med «Bekreftet med invitasjon». Ingen forespørsel, ingen «Godta».
   - Vindu 1: `tail -n +"$((n + 1))" "$R/relay.log" | grep -E '/v1/(invites/open|register|invites/redeem)'`. To `/v1/invites/open` før første `/v1/register` (V77).
   - Vindu 1: de to `rq`-linjene under «V71» i «Commands». Forventet står bak hver linje.
9. **Ett brev hver vei (5 min).** Skriv `BREV-SECRET-BODY æøå` i emne og tekst. «Send»: én dialog per brev, «… sende brevet», ingen passordknapp, riktig navn (V56, V57).
   - Mens brevet venter, i vindu 1: `waiting; hits "$M" "$RD"`. Et tall på 1 eller mer, og ingen treff (V58).
   - Bytt til mottakeren og lås opp. Brevet kommer ved første synk, i alle tre rutene.
   - Etter begge: `waiting` skal gi `0` (V59).
10. **Blokker én gang (3 min, V81).** I Brev B: velg Brev i kontaktlisten, «Blokker». Ett klikk, ingen Touch ID.
    - Vindu 1: `n="$(wc -l < "$R/relay.log")"`. I Brev: nytt brev til Brev B, «Send». Forventet: «Mottakeren har ikke godtatt deg ennå …», ingen Touch ID.
    - Brev B kan ikke skrive til Brev: ingen Touch ID-dialog, ingenting sendt.
    - Vindu 1: linjene under «V75 and V81» i «Commands», med `P="$ADDR_B"` i stedet for `P="$ADDR_D"`. Forventet `2`, og `0` for `/v1/envelopes`.

Se etter hele tiden: én dialog per trykk, aldri en passordknapp, riktig navn («Brev» eller «Brev B»), og aldri en dialog du ikke selv utløste (V26).

## Runde 2 (resten av sjekklisten, ca. 3 timer)

Kommandoene står under «Commands» i `docs/VERIFY.md`, merket med radnummer. De som trenger Brev ulåst, starter med `sleep 30;`: kjør, bytt til Brev, lås opp og gjør klart. Gi Terminal en tillatelse bare når en gruppe trenger den. Et markørbrev betyr et brev med `BREV-SECRET-BODY æøå`.

Nullstill Brev B betyr: avslutt Brev B, `mv "$DB/brev.db" "$R/brevb-$(date +%s).db"`, `open "$APPB"`, «Slett alt og start på nytt», «Slett alt», så onboarding.

**A. Oppstarter (10 min).** Avslutt Brev før hver.
- V28: kjør linjene. Kjør `defaults delete -g …` med en gang etter hver `defaults write -g`.
- V49: start med `open "$APP"`, fra Finder og fra Dock. Lagre `ps -wwE -p "$(pgrep -x Brev)"` for Finder og Dock i `$R/v49-finder.txt` og `$R/v49-dock.txt` (til beslutning 4).
- V26: `osascript -e 'activate application "Brev"'`. Ingen Touch ID-dialog.
- V3: `osascript -e 'tell application "Brev" to get name of every window'` (gi Automatisering). -1708 er forventet.
- På låseskjermen: V27 «Avbryt», V43, første del av V70, og V48s sperre: feil finger til «Touch ID er sperret …». Etterpå trenger Macen passordet ditt én gang.

**B. Par 2: forespørsel (25 min).** `pbcopy < "$R/root-2"`, nullstill Brev B, og på adressesiden: ⌘V, «Fortsett», registrer `brev-secret-new`. Brev B er nå `$ADDR_C`: der en rad sier `$ADDR_B`, bruk `$ADDR_C`.
- I Brev, «Kontakter»: V79s trykk på «Legg til» med `brev-secret-new` skrevet. Så «Legg til» selv: V74 frem til forespørselen.
- Før Brev B svarer: V76s app-del. I Brev B: V79s trykk på «Godta» og «Avslå», og AX-dump og opptak med forespørselen valgt.
- «Godta» i Brev B: resten av V74, med ett markørbrev hver vei.
- V79s resten: V9 med «Kontakter» åpent, trykk på «Kopier adressen min», «Lag invitasjon», «Kopier koden» og «Blokker». V73 med den tidsstyrte linjen. Maks 3 invitasjoner per døgn.

**C. Relé og koder (20 min).** Gi Terminal Tilgjengelighet.
- V58 andre del, V61 (koden Brev viser for Brev B er lik Brev Bs egen kode), V56 («Avbryt» i dialogen beholder utkastet, `waiting` uendret).
- V54, V64, V62 (⌘-Tab mens send-dialogen står), V63 (to deler, med den tidsstyrte linjen).

**D. Opptak og tilgjengelighet (25 min).** Gi Terminal Skjermopptak. Et markørbrev åpent.
- V4 (⇧⌘4 vindu og område, ⇧⌘5 opptak), V5 til V7 (`capture-probe`), V9 med skrivevinduet åpent, V10 (Accessibility Inspector), V11, V12 (gi Automatisering for System Events), V13 på «Send» og «Lås opp med Touch ID», V68 med Brev B valgt.
- V8 trenger en annen Mac eller iPad. Har du ingen: noter «ikke kjørt».
- Synes et brev, en adresse eller en kode i et opptak: stopp og si fra.

**E. Skriving og utklipp (20 min).** Skrivevinduet åpent.
- V30, V31 (gi Inndataovervåking), V34, V35, andre del av V70, V14 (også kontaktlisten og feltet i «Kontakter»), V15, V16.
- V32 og V33 bare etter beslutning 5.

**F. Disk, logg og lås (20 min).** Gi Terminal tilgang til data fra andre apper.
- V17, V40, V41, V21 (fra repoet).
- V22, V23 (⌃⌘Q), V24 (dvale), V25 (5 min uten å røre noe, også med Brev-menyen åpen), V46, V47. V44 til slutt.

**G. Grensen for brev (10 min).** V78 som i «Commands»: start releet på nytt med `--letters-per-day`. Etterpå: ⌃C, og `scripts/relay.sh --trace >> "$R/relay.log"` igjen.

**H. Etter avslutning (10 min).** Brev avsluttet: V17 og V41 igjen, og V18. Så V65: Brev B sender et nytt markørbrev. `open "$VAPP"`, send et markørbrev til Brev B, åpne brevet fra Brev B, og lås med det åpent (⌘L).

**I. Par 3: avslag (10 min).** `pbcopy < "$R/root-3"`, nullstill Brev B, registrer `brev-secret-last`. Så V75 (i «Commands»: `P="$ADDR_D"`).

**J. Til slutt, det som ødelegger (35 min).** I denne rekkefølgen:
1. V20 (`kill -SEGV`), så V17 og V41 igjen.
2. V60: `"$RELAY" release --db "$RDB" "$ADDR_C"`, `pbcopy < "$R/root-4"`, nullstill Brev B, registrer `brev-secret-new` igjen. Ta V67-delene for «Godta ny kode» og «Godta» før du trykker selv. Viser appen noe annet enn raden sier (fase 4 kan be om en ny forespørsel): noter hva du så.
3. Kopier Brev-mappen til side: `cp -Rp "$D" "$R/D-kopi"`
4. V38, med V9s del for «Slett alt»-arket og V13-trykkene på «Slett alt og start på nytt» og «Slett alt» før du trykker selv.
5. Avslutt Brev. V51 nå, mens Brev ikke har nøkler: linjene under V51 i «Commands» (den siste bare ved `FAIL`). Hver `--unlock` gir én dialog uten passordknapp. Noter `PASS` og hva `v51-scrub0.txt` sier. Står det `FAIL` i `v51.txt`: si fra.
6. Ny onboarding: V36, V29 og V37. På invitasjonssteget, med `pbcopy < "$R/root-1"` (brukt kode): V46s del for siden og V79s del (V9, og V13 på «Fortsett»). Registrer ikke.
7. V52: avslutt Brev, `cp -p "$R/D-kopi/brev.db" "$D/brev.db"`, start. Forventet: «Filene til Brev er skadet. Brevene kan ikke åpnes.»
8. V80 som i «Commands», men med `for i in 1 2 3 4` i begge løkkene.
9. Aller sist V48: legg til et fingeravtrykk i Systeminnstillinger. Forventet: «Fingeravtrykkene på denne Macen ser ut til å være endret …». Både Brev og Brev B blir ulesbare.
10. Stopp loggen (⌃C i vindu 2) og kjør V19s linjer.

Radene uten menneske (V1, V2, V45, V50, V53, V66, V69, og halvparten av V3 og V21) kjører maskinen på de samme byggene.

## Hand-test (ca. 15 min)

Brevene har et bevis på hvordan de ble skrevet (D-0111). Nå sendes et brev bare når alle kravene holder, og merket sier bare «Skrevet i Brev» eller «Ikke verifisert» (D-0115). Radene er V82 til V84 i `docs/VERIFY.md`. Noter pass eller feil for hver.

Beviset og lageret er nye (profil hand-v2, lager v7). Gamle lagre kan ikke åpnes. Testen starter derfor blankt:

0. **Klargjør (10 min).**
   - Bygg: `scripts/build.sh && scripts/build.sh --instance b && (cd core && cargo build --release -p brev-relay)`
   - Terminal: lim inn blokken under «Setup» i `docs/VERIFY.md`.
   - Nytt relé: `[ -e "$RD" ] && mv "$RD" "$R/relay-v2-$(date +%s)"`, så `scripts/relay.sh --trace > "$R/relay.log"` i et eget vindu.
   - Én rot-invitasjon: `"$RELAY" invite --db "$RDB" | pbcopy`
   - `open "$APP"`: «Filene til Brev er skadet» → «Slett alt og start på nytt» → «Slett alt». Onboarding, Touch ID, ⌘V invitasjonen, adresse `brev-secret-me`, «Registrer».
   - `open "$APPB"`: det samme, men stopp på «Lim inn invitasjonen».
   - I Brev: «Kontakter» → «Lag invitasjon» → «Kopier koden». I Brev B: ⌘V, «Fortsett», adresse `brev-secret-peer`, «Registrer».

1. **Ett brev, én Touch ID (V84).** I Brev: nytt brev til Brev B, skriv noe, «Send». Forventet: nøyaktig én dialog, «… sende brevet», ingen passordknapp. Brevet kommer frem hos Brev B.
   - Et nytt brev, «Send», og «Avbryt» i dialogen. Forventet: tilbake til utkastet, ingenting sendt, ingen ny dialog.
2. **Merket (V83).** Lås opp Brev B. Brevet har et lite segl i listen. Åpne brevet. Øverst i brevet står «Skrevet i Brev». Ditt eget brev i Brev har ikke noe merke.
   - Klikk på merket. Et ark viser tallene: nøkkel i maskinvare, andre vinduer, AI-programmer, admin, blokkerte forsøk, skrivetid, SIP og sudo. Siste linje: «Appen er ikke bekreftet av Apple (støttes ikke på Mac)». «Lukk» eller Escape lukker arket.
3. **sudo låser Brev (V82).** Brev låser seg når Terminal kommer foran, så sudo må starte forsinket. I Terminal: `sudo -v && sleep 15 && sudo sleep 20`, skriv passordet, og lås opp Brev innen 15 sekunder.
   - Når sudo starter, låser Brev seg innen et par sekunder og skriver «Brev låste seg fordi sudo kjører.».
   - Prøv å låse opp mens `sleep` går. Forventet: «Brev kan ikke åpnes mens sudo kjører.».
   - Vent til Terminal er ferdig, og lås opp igjen. Nå virker det.

## Rydd opp (5 min)

1. Stopp releet: ⌃C i vindu 3.
2. `defaults read -g NSTraceEvents; defaults read -g TSMEventTracing`. Begge skal si `does not exist`. Står en der: `defaults delete -g` og navnet.
3. Systeminnstillinger → Personvern og sikkerhet: ta Terminal bort fra Tilgjengelighet, Skjermopptak, Inndataovervåking, Automatisering og tilgang til andre apps data.
4. Fingeravtrykket fra V48 kan du slette igjen.
5. `echo "$R"` og send meg stien. Jeg fører resultatene inn og lukker fase 2, 3 og 4.
