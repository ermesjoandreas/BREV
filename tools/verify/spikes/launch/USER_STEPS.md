# Spike «launch»: det du må gjøre selv

Alt annet er testet fra terminalen. Dette gjenstår, fordi det trengs en person ved Macen.

- Ingen Touch ID og ingen passord.
- Appene er testapper (LaunchSpike). De har ingenting med Brev-dataene dine å gjøre.
- Hver app viser et lite vindu nede til venstre og lukker seg selv.

Gå først til mappen:

```
cd /private/tmp/claude-503/-Users-andypandy/01f11233-b284-49b2-9c90-391fa2f358ef/scratchpad/p2/launch
```

## Steg 1: start fra Finder (viktig)

Spørsmål: får appen et `-psn_`-argument når den startes fra Finder? Og er `MallocScribble=1` på?

```
./user_steps.sh finder
```

1. Finder åpner seg med `LaunchSpike.app` markert.
2. Dobbeltklikk den.
3. Et lite vindu vises i 6 sekunder og lukker seg.

Hvis macOS i stedet viser en melding om at appen ikke kan åpnes, trykk Ferdig og si fra. Da skal du ikke overstyre det.

Skriptet skriver ut en rapport. **Send meg alle linjene under `---- finder ----`.**

Forventet: `argv count=1`, `psn arg present=false`, `MallocScribble=1` og `afterfree=0`.
Hvis du ser `psn arg present=true`, er det viktig å si fra. Da ville Brev ha nektet å starte fra Finder.

## Steg 2: skriv fire bokstaver (anbefalt, ca. 1 minutt)

Spørsmål: logger macOS tastene du skriver når feilsøkingsbrytere er slått på?

```
./user_steps.sh typing
```

1. Et lite vindu («spike») kommer frem. Skriv `brev`.
2. Vent til vinduet lukker seg (20 sekunder).
3. Et nytt, likt vindu kommer frem. Skriv `brev` igjen.

**Send meg de to blokkene `---- release ----` og `---- control-get-task-allow ----`.**

Forventet:
- **release**: `chars=: 0` og `keyCode=: 0`. Tastene dine blir ikke logget.
- **control**: `chars="b"` og de andre bokstavene er større enn 0. Denne kontrollen viser at testen faktisk kan se det, når macOS logger taster.

Linjen `tastetrykk appen fikk` viser også hvilken `srcpid` ekte tastetrykk har. Det er nyttig for input-spiken.

## Steg 3 (valgfritt): start fra Dock

Dette gjelder samme spørsmål som steg 1, men for Dock. Hopp over det hvis du vil.

1. Dra `LaunchSpike.app` fra Finder-vinduet i steg 1 ned i Dock.
2. Kjør `./user_steps.sh dock` og klikk ikonet i Dock.
3. Send meg linjene under `---- dock ----`.
4. Fjern ikonet fra Dock etterpå. Høyreklikk det og velg Valg → Fjern fra Dock.
