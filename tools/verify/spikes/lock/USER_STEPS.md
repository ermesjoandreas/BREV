# U4 autolås: det som trenger deg (ca. 3 minutter, pluss 2 valgfrie)

Alt annet er testet automatisk.
Testvinduet «LockLab» er lite og ligger øverst til høyre. Det lukker seg selv.
Kjør kommandoene i Terminal.

Kjør først denne linjen. Den lager en snarvei som stegene under bruker:

```
H=/private/tmp/claude-503/-Users-andypandy/01f11233-b284-49b2-9c90-391fa2f358ef/scratchpad/p2/lock/human.sh
```

## 1. Bytt app, skjul, og lås skjermen (ca. 1 minutt)

```
$H las
```

LockLab kommer foran. Gjør så dette:

- a) Trykk ⌘-Tab og velg Terminal. Trykk ⌘-Tab igjen og velg LockLab.
- b) Trykk ⌘H. LockLab blir borte. Trykk ⌘-Tab og velg LockLab igjen.
- c) Trykk ⌃⌘Q (Control + Kommando + Q). Skjermen låses. Vent ca. 5 sekunder. Lås opp som vanlig.
- d) Vent. LockLab lukker seg selv ca. 8 sekunder etter at du har låst opp.

Send tilbake: «las ferdig».

## 2. Touch ID (ca. 1,5 minutter)

```
$H touchid
```

Det kommer én Touch ID-dialog hver gang du klikker «Lås opp (test)». Ingen annen dialog skal komme.

- a) Klikk «Lås opp (test)». Se etter en knapp «Bruk passord …» i dialogen. Legg så fingeren på sensoren.
- b) Klikk «Lås opp (test)» igjen. Trykk «Avbryt» i dialogen.
- c) Klikk «Lås opp (test)» igjen. Legg en finger som ikke er registrert (for eksempel en knoke) på sensoren.
  Gjør det høyst 3 ganger. Står dialogen fortsatt, trykk «Avbryt».
  Ikke prøv flere ganger: etter 5 feil sperrer macOS Touch ID til du skriver passordet.
- d) Klikk «Innebygd (test)». Nå skal et lite fingeravtrykk-ikon vises inne i LockLab-vinduet.
  Legg fingeren på sensoren. Kommer det en vanlig dialog i tillegg, legg fingeren på og husk det.
- e) Klikk «Ferdig».

Send tilbake: «touchid ferdig», og ja eller nei for hvert spørsmål:
- a: Var det en knapp «Bruk passord»?
- d: Kom ikonet inne i vinduet?
- d: Kom det en vanlig dialog i tillegg?

## 3. Valgfritt: skjermen slukkes (ca. 30 sekunder)

```
$H skjerm
```

Ikke rør noe. Skjermen slukkes etter 5 sekunder.
Vent 5 sekunder. Vekk skjermen med Shift. Lås opp hvis Macen ber om det.

Send tilbake: «skjerm ferdig», og ja eller nei: måtte du låse opp?

## 4. Valgfritt: Macen sover (ca. 30 sekunder)

```
$H sov
```

Macen sovner etter 5 sekunder. Vent 10 sekunder. Vekk den og lås opp.

Send tilbake: «sov ferdig».

## 5. Rydd opp

```
$H rydd
```

Denne fjerner bare testappenes registrering i macOS.
Testappene har også en liten loggmappe hver i `~/Library/Containers/` (LockLab og LockOther).
Vil du fjerne dem, dra dem til papirkurven i Finder.

## Send tilbake

For eksempel: `las ferdig · touchid ferdig, a nei, d ja, d nei · skjerm ferdig, ja · sov ikke gjort`

Maskinen leser resten selv fra loggene i `out/`.
Ber macOS om en tillatelse underveis, trykk «Ikke tillat» og si fra.
