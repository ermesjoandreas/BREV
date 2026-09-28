# Brev: det du må gjøre (fase 2)

Skrevet 28. september 2026 for eieren. Alt står i rekkefølge. Kjør kommandoene i Terminal fra `~/BREV`.

## Dette skjedde i natt

- Fase 2 er ferdig kodet: onboarding, Touch ID-opplåsing, postvinduet, skrivevinduet, autolås og vern mot skjermopptak.
- Alle arbeidspakkene er committet på grenen `claude/laughing-knuth-yhp8ji`. Ingenting er pushet.
- To gjennomganger av hele fasen fant 32 mulige feil. 21 er rettet, 10 var ikke reelle, og 1 venter på deg (beslutning 6).
- Alle automatiske tester er grønne (`scripts/test.sh`, 28. september kl. 12:56).
- Beslutningene står i `docs/DECISIONS.md` (D-0036 til D-0053, og «Phase 2 summary» til slutt).
- Det meste av sjekklisten (`docs/VERIFY.md`) trenger deg og Touch ID. Det står under.
- Ingen Touch ID- eller passorddialog ble åpnet. Én tillatelsesdialog står igjen fra en agent (se A1).

## Beslutninger du må ta

**1. Signeringsnøkkelen på denne Macen.** Med nøkkelen her kan et hvilket som helst program du kjører, også en AI-agent, late som det er Brev overfor nøkkelringen. Du godtok dette 28. september kl. 11:28, for testbrev.
- a) Passord hver gang `codesign` bruker nøkkelen (hver bygging spør).
- b) Ekte brev bare på en Mac uten nøkkelen, med Developer ID-bygg laget et annet sted.
- c) Godta det mens Brev bare har testbrev.
- Anbefaling: c nå og b før ekte brev. Det er det du valgte. Bare si fra hvis det har endret seg.

**2. Touch ID-vinduet og lås ved appbytte.** Brev låser når en annen app kommer foran. Hvis Touch ID-vinduet regnes som en annen app, låser Brev seg rett etter opplåsing. Det vet vi først etter V27 og V47.
- a) Vent inntil 1,5 sekunder på at Brev blir aktiv igjen, men bare hvis det var Touch ID-vinduet som tok over.
- b) Vis Touch ID inne i Brev-vinduet (et nytt rammeverk som du må godkjenne).
- c) Behold regelen som den er, hvis opplåsingen virker.
- Anbefaling: c hvis V27 virker, ellers a.

**3. Feilkoder for sperret Touch ID og endrede fingeravtrykk.** Å måle dem krever fem feil fingre, og et nytt fingeravtrykk som gjør alle slike nøkler på Macen ubrukelige.
- a) Hopp over. Ukjente feil viser «Prøv igjen», og «fingeravtrykk endret» vises bare når fingeravtrykkene også er endret.
- b) Mål dem senere med et eget skript.
- Anbefaling: a. Slik er det bygget. V48 viser kodene i loggen uansett.

**4. Oppstart: hvilke miljøvariabler Brev godtar.** I dag fjerner Brev kjente farlige variabler (en forbudsliste).
- a) Behold forbudslisten.
- b) Godta bare variablene macOS selv setter (en tillatsliste). Alt annet regnes som utrygt.
- Anbefaling: b, men først når steg B4 har vist hva Finder setter. TSMEventTracing er allerede ordnet: Brev låser ikke opp når den er på.

**5. Falske tastetrykk fra andre programmer (V32, V33).** Det er ikke testet om tastetrykk sendt via systemets felles kø, System Events, Tilgjengelighetstastatur eller Skjermdeling slipper inn.
- a) Kjør testen mens du sitter ved Macen.
- b) La hullet stå åpent til senere.
- Anbefaling: a. Skriver noe seg selv inn i Brev: stopp og si fra.

**6. ⌘Q mens skrivevinduet er åpent.** macOS ignorerer da «Avslutt». Brev blir stående ulåst til en annen lås slår inn (appbytte, skjermlås, dvale eller 5 minutter uten bruk).
- a) La det være. Slik gjør alle Mac-apper.
- b) ⌘Q låser og avslutter. Et halvskrevet brev forsvinner, som ved ⌘-Tab.
- Anbefaling: b.

**7. V9 og fire usynlige menylinje-vinduer.** Alle apper har fire slike vinduer som kan tas opp. De viser bare menylinjen (Brev, Arkiv).
- a) V9 teller bare vinduene Brev lager selv.
- b) La V9 feile og godta det som restrisiko.
- Anbefaling: a.

## Ting bare du kan gjøre ved Mac-en

Ber macOS om en tillatelse du ikke venter, trykk «Ikke tillat» og noter det.

**A. Rydd skjermen (2 min)**
1. Dialogen «Terminal vil ha tilgang til data fra andre apper»: trykk «Ikke tillat». Den kom fra en agent i natt.
2. Andre gamle dialoger (krasjrapport, tilgjengelighet, varsler): «Ignorer», «Avslå» eller lukk.

**B. Små tester før Brev (ca. 8 min)**
1. Bygg testappene (2 min):
   ```
   cd ~/BREV/tools/verify/spikes
   (cd capture && mkdir -p bin out && xcrun swiftc -O -target arm64-apple-macos14.0 src/probe/main.swift -o bin/probe && bash src/app/build.sh)
   input/build.sh && launch/build.sh
   ```
2. Opptaksikonet (1 min): `capture/human.sh indikator`. Se på menylinjen øverst til høyre i fase A, B og C. Noter: kom et opptaksikon (ja/nei)?
3. Ekte tastatur (1,5 min): `input/human.sh skriv`. Gjør a til d som skriptet sier. Ikke skriv passord det minuttet. Noter: står det `abc æøå é` i begge boksene?
4. Start fra Finder (1 min): `launch/user_steps.sh finder`. Dobbeltklikk `LaunchSpike.app`. Se etter `psn arg present=false` og `MallocScribble=1`. Står det `true`: si fra.
5. Tastelogg med feilsøkingsbrytere (1 min): `launch/user_steps.sh typing`. Skriv `brev` i hvert av de to vinduene. Forventet: `release` viser `chars=: 0`, og kontrollen viser mer enn 0.
6. Rydd: `capture/human.sh rydd; input/human.sh rydd`.
7. Lim utskriftene fra 2 til 5 inn i en fil, for eksempel `~/Desktop/brev-steg-B.txt`.

**C. Første ekte Brev (ca. 15 min)**
1. Bygg (3 min): `cd ~/BREV && scripts/build.sh && tools/verify/build.sh`.
2. Åpne to Terminal-vinduer i `~/BREV`. Lim inn blokken under «Setup» i `docs/VERIFY.md` i begge.
3. Start loggen i vindu 2: `/usr/bin/log stream --level debug --predicate 'process == "Brev"' > "$R/stream.log"`
4. Steg 1 i «Order of a run» ble kjørt i natt (D-0053). Du kan hoppe over det.
5. V51 før Brev er installert (3 min). Bruk kommandoene under «V51» i `docs/VERIFY.md`. `--dry` gir ingen dialog. Hver `--unlock` gir én Touch ID-dialog uten passordknapp. Se etter `PASS`.
6. Første onboarding (5 min): `open "$APP"`.
   - V36: fem regler på norsk. «Opprett nøkler» er grå til du krysser av.
   - V29: `open -n "$APP"` mens onboarding vises. Den nye starten skal lukke seg.
   - V37: trykk «Opprett nøkler», kjør `pkill -9 -x Brev`, og start igjen. Onboarding skal komme tilbake.
   - Gå gjennom til slutt. «Lås opp med Touch ID» gir én dialog uten passordknapp (V27).
7. V40 og V41 leser Brevs mappe. Da trenger Terminal tilgang til data fra andre apper. Gi den bare mens du tester, og ta den bort etterpå. Eller hopp over radene og noter det. Det samme gjelder V17, V18, V29 og V52 senere.

**D. Resten av sjekklisten (60 til 90 min)**
Følg steg 3 til 6 i «Order of a run». Kommandoene står under «Commands». Skriv inn et brev med `BREV-SECRET-BODY æøå` i emne og tekst.
1. Oppstarter (steg 3): V28 (slett `defaults`-innstillingen med en gang), V49 fra Finder og Dock, V26, V3. På låseskjermen: V27 «Avbryt», V43, første del av V54, sperre-delen av V48.
2. Ulåst (steg 4): V42 først. Gi Terminal Tilgjengelighet før opptaksradene. Så V4 til V17, V19, V22 til V25, V30 til V35 (V32 og V33 etter beslutning 5), V46, V47, andre del av V54, og V44 til slutt. V8 trenger en annen Mac eller iPad.
3. Etter avslutning (steg 5): V17, V18 og V41, så V39 med Verify-bygget (`open "$VAPP"`).
4. Til slutt (steg 6): V20, V17 og V41 igjen, kopi av mappen, V38, V52. Aller sist V48 med et nytt fingeravtrykk. Det gjør testinstallasjonen ulesbar, og nøkler i andre apper som bruker Touch ID slik, slutter å virke.
5. Noter pass eller feil for hver rad i `$R/resultater.txt`. Så fører jeg dem inn.

**E. Rydd opp (3 min)**
1. Finder: ⇧⌘G, skriv `~/Library/Containers/`. Dra alle mapper som heter `no.brev.spike.…` til papirkurven. Ikke rør `no.brev.app`. Bruk Finder, ikke Terminal: Terminal ville spurt om tillatelse.
2. La du `LaunchSpike.app` i Dock: høyreklikk, Valg, Fjern fra Dock.
3. Ga du Terminal tillatelser bare for testen (C7, D2): ta dem bort igjen.

## Neste steg

- Når sjekklisten er kjørt, fører jeg inn resultatene (D-0053) og lukker fase 2.
- Fase 3 (ekte sending via en relé-server) er allerede i gang på grenen `claude/phase3`.
