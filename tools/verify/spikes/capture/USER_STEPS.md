# U1 skjermopptak: det som trenger deg (ca. 5 minutter)

Alt annet er testet automatisk. Ingenting her ber om Touch ID eller passord.
Testvinduene er små, ligger øverst til høyre, tar ikke fokus fra Terminal og lukker seg selv.
Kjør kommandoene i Terminal (den har tillatelse til skjermopptak).

Kjør først denne linjen i Terminal (den lager en snarvei som stegene under bruker):

```
H=/private/tmp/claude-503/-Users-andypandy/01f11233-b284-49b2-9c90-391fa2f358ef/scratchpad/p2/capture/v2/human.sh
```

## 1. Ser du teksten på skjermen? (25 sekunder)

```
$H vis
```

Se øverst til høyre. Svar ja eller nei for hver:
- 1a: rosa vindu med **SPIKE-7f3a**
- 1b: lilla vindu med **PROT-7f3a**
- 1c: lilla vindu med **PROTX-7f3a**

## 2. Skjermbilde og opptak med tastene (2 minutter)

```
$H bilder
```

Mens vinduene vises:
- 2a: Trykk ⇧⌘4, så mellomrom, og klikk på det rosa vinduet (SPIKE-7f3a). Hva ble bildet? (et bilde av vinduet, av noe bak det, eller ingenting)
- 2b: Trykk ⇧⌘4 og dra et rektangel over alle testvinduene.
- 2c: Trykk ⇧⌘5, velg «Ta opp hele skjermen», ta opp i ca. 3 sekunder og stopp med knappen i menylinjen.

Åpne filene på skrivebordet. For 2a, 2b og 2c: hvilke av disse tekstene kan du lese i filen?
**SPIKE-7f3a**, **CTRL-7f3a**, **PROT-7f3a**, **PROTX-7f3a**.
Slett filene etterpå.

## 3. Vises opptaksikonet? (ca. 30 sekunder)

```
$H indikator
```

Skriptet tar opp skjermen på tre måter, 6 sekunder hver, og sier fra når hver fase starter.
Se på menylinjen øverst til høyre. For fase A, B og C: kom det et opptaksikon i menylinjen (ja eller nei)?

## 4. Bare hvis du har en annen Mac eller en iPad (valgfritt)

Del denne skjermen til den andre enheten: Skjermdeling fra den andre Macen, AirPlay-speiling eller Sidecar.
Kjør så `$H bilder` og se på den andre enheten.
Hvilke av tekstene i steg 2 kan du lese der? Si også hvilken måte du brukte.

## 5. Rydd opp

```
$H rydd
```

Denne fjerner bare testappens registrering i macOS (LaunchServices).

## Send tilbake

For eksempel: `1: ja/ja/ja · 2a: … · 2b: SPIKE nei, CTRL ja, PROT nei, PROTX nei · 2c: … · 3: A nei, B nei, C ja · 4: ikke gjort`
