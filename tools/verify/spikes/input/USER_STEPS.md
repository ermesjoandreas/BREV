# U2 og U3 tastatur: det som trenger deg (ca. 2 minutter, pluss 3 valgfrie)

Alt annet er testet automatisk. Ingenting her ber om Touch ID eller passord.
Testvinduet «InputLab» er lite, ligger øverst til høyre og lukker seg selv.
Kjør kommandoene i Terminal.

Kjør først denne linjen (den lager en snarvei som stegene under bruker):

```
H=/private/tmp/claude-503/-Users-andypandy/01f11233-b284-49b2-9c90-391fa2f358ef/scratchpad/p2/input/human.sh
```

## 1. Skriv i testvinduet (ca. 1,5 minutter)

```
$H skriv
```

Vinduet vises i 60 sekunder. Venstre boks har fokus (grønn ramme).

- a) Skriv `abc æøå ´e`. (´ er tasten til venstre for rettetasten. Trykk den, så e.)
- b) Klikk i høyre boks og skriv det samme.
- c) Klikk på knappen «Plain», så på «Human».
- d) Vent til vinduet lukker seg selv.

Mens vinduet er åpent, teller en test-«keylogger» hvor mange tastetrykk den ser.
Den lagrer ikke hvilke taster du trykker. Den stopper etter 75 sekunder.
Skriv derfor ikke noe annet, for eksempel et passord, i løpet av det minuttet.

Send tilbake: «1 ferdig», og om teksten i begge boksene ble `abc æøå é`.

## 2. Valgfritt: systemfunksjoner (ca. 3 minutter)

```
$H tjenester
```

Gjør dette først i venstre boks, så i høyre boks. Klikk i boksen først.

1. Hold tasten e nede i 2 sekunder. Kommer en aksentmeny, trykk 2.
2. Trykk 🌐 og E samtidig (emoji). Kommer vinduet, klikk på en emoji.
3. Trykk mikrofontasten (F5), eller 🌐 to ganger, og si «hei». Spør Macen om å slå på diktering, trykk «Avbryt».
4. Hold pekeren over boksen og trykk ⌃⌘D (slå opp).
5. Høyreklikk i boksen.

Lukk vinduet med ⌘Q når du er ferdig.

Send tilbake: «2 ferdig», og for hver boks (venstre og høyre): hva skjedde i punkt 1–5?
Svar med ett ord per punkt: ingenting, meny eller tekst.

## 3. Rydd opp

```
$H rydd
```

Denne fjerner bare testappens registrering i macOS (LaunchServices).

## Send tilbake

For eksempel: `1 ferdig, tekst riktig ja` · `2: venstre ingenting/ingenting/ingenting/ingenting/ingenting, høyre meny/tekst/ingenting/ingenting/ingenting`

Maskinen leser resten selv fra loggene i `out/`.
Ber macOS om en tillatelse underveis, trykk «Ikke tillat» og si ifra.
