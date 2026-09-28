# Brev enclave-spike: Touch ID-test du kjører selv

Denne testen viser hele runden med ekte Touch ID:
en Secure Enclave-nøkkel låser opp en 32-byte DEK.
Jeg kunne ikke kjøre dette selv. Det krever en finger på sensoren.

## Før du starter

- Tar under ett minutt.
- Det kommer **én** Touch ID-dialog (to hvis du bruker `--reuse` eller `--rogue`).
- Ingen vinduer åpnes. Ikke noe Dock-ikon. Appen kjører i bakgrunnen.
- Ingenting lagres i nøkkelringen. Alt ryddes til slutt.

## Kjør

```bash
cd /private/tmp/claude-503/-Users-andypandy/01f11233-b284-49b2-9c90-391fa2f358ef/scratchpad/p2/enclave
./user_test.sh
```

## Hva du skal se

**0. build**: skriver `ok`.

**1. setup**: ingen dialog. Linjen skal ende med:
`OK. KEK pub fp …; the test DEK is kept only as its SHA-256`

**2. gatecheck**: ingen dialog. Her prøver appen å låse opp *uten* å få vise noe.
Det skal feile. Du skal se:
`GOOD: unwrap refused without interaction: …`
Hvis det likevel kommer en Touch ID-dialog her: trykk Avbryt og si fra. Det er et funn.

**3. unwrap**: nå kommer Touch ID-dialogen. Se etter dette:
- Navnet **BrevEnclaveSpike**.
- Teksten **«låse opp Brev-spike (test)»** (eller en generell tekst, noter hvilken).
- En knapp **Avbryt**.
- **Ingen** «Bruk passord …» / «Use Password …»-knapp.

Legg fingeren på sensoren. Da skal du se:
`HPKE unwrap after Touch ID: DEK MATCHES (round trip OK)`

Trykker du Avbryt, kommer en `FAILED …`-linje med en feilkode. Det er også nyttig å få.

**5. cleanup**: sletter testnøklene. Linjene sier `cleanup: removed …`.

## Send meg dette

1. Linjen fra steg 2 (`GOOD …` eller noe annet).
2. Linjen fra steg 3 (`DEK MATCHES …` eller `FAILED …`).
3. Hva dialogen viste: navn, tekst, knapper. Var det en passord-knapp eller et passordfelt?

## Valgfritt

- `./user_test.sh --reuse`: låser opp og signerer med samme godkjenning.
  Si om du fikk **én eller to** dialoger. Svaret sier om én Touch ID kan dekke både opplåsing og signering.
- `./user_test.sh --rogue`: etter steg 3 prøver et **annet program** (`enclave-cli`) å bruke samme nøkkel.
  Da kommer en dialog til. Noter **hvilket programnavn** den viser. Trykk gjerne Avbryt.
  Dette viser hva brukeren ser hvis et annet program har kopiert nøkkelfilen.

## Hvis noe går galt

- Ingen dialog i steg 3: skriptet gir opp etter ca. 90 sekunder og skriver `WATCHDOG` eller `TIMEOUT`.
- All utskrift ligger i `out/user-*.stdout`.

## Rydding etterpå (valgfritt)

Appens mappe blir igjen med bare en loggfil:
`~/Library/Containers/no.brev.spike.enclave`
Slett den i Finder hvis du vil. `rm` fra Terminal kan gi et macOS-spørsmål om tilgang til andre apper sine data.
