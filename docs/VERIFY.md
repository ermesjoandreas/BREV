# Brev — Phase 2, Phase 3 and Phase 4 verification

The manual checklist that CLAUDE.md §5 (Phase 2) asks for, built from
`docs/PHASE2_DESIGN.md` §10. Its results are recorded in D-0053 (the design's
D-0058; `docs/DECISIONS.md` maps the design's decision numbers).
Rows V1–V45 follow the design's table, except where "Changes from the design"
at the end says otherwise. V46–V52, V69 and V70 cover mechanisms that the
table had no row for (see "Coverage" below).

Phase 3 ("Real transport") adds V53–V68 from `docs/PHASE3_DESIGN.md` §8 and
rewrites V1, V17, V18, V26, V40 and V41 for it. V65 replaces V39. V42 is
retired with the echo contacts; V57 replaces it. Phase 3's WP6 runs the rows
and records the results in the Phase 3 design's D-0053 (its §10 numbers
follow Phase 2's entries).

Phase 4 ("Human-only guarantees") adds V71–V80 from `docs/PHASE4_DESIGN.md`
§8 and V81 for *Blokker* (the owner's answer 6 at the end of that design).
It rewrites V14, V66 and V69, and V15 if spike P1 takes variant (b)
(Legend). Phase 4's WP5 and WP6 run the rows; the results go to Phase 4's
decision entries (design §10). From Phase 4's WP5 on, `ContactSheet`
replaces `AddContactSheet`, adding a contact sends a request, and
registering needs an invite. The other rows keep their text: Phase 3's WP6
runs its rows on the Phase 3 build, and V71–V81 check the Phase 4 flows.

The UI redesign (docs/UI_REDESIGN.md, DECISIONS.md «D-XXXX (UI redesign)»)
changes what the rows call the panes, not what they check. Read "the three
panes" as the sidebar (the requests and contacts lists), the message list
(was the thread list; one row per thread) and the reading pane (the reading
header and the letter); "the contact header" as the ContactBar over the
message list (one contact's address and code; the own address and code are
on the Kontakter sheet now, which «Legg til kontakt» in the sidebar opens);
"Nytt brev" and "Lås" as the toolbar's items (the menu keeps ⌘N and ⌘L).
Brev no longer opens a letter by itself: select one first. The machine
checks of the new layout run offscreen in `tools/snapshot --check`
(scripts/test.sh); its PNGs (`--out`) show each screen in light and dark.

Status: written in WP0, 2026-09-27, and revised after its review. WP4
(2026-09-28) built the tools in `tools/verify/` and ran every row a machine
can run without Touch ID; the results are in `docs/VERIFY-RESULTS.md`. Rows
marked "per D-0052" become final after the human GUI-spike session. Review
round 1 (2026-09-28) changed V39, V41, V43 and V51 and added two rows;
review round 2 changed V28 and the lock probe (V45) (see "Changes from the
design"). Round 1 numbered its rows V53 and V54, as D-0063 and D-0053 still
do; Phase 3 already used those numbers, so they are V69 and V70 here. WP12
ran the Phase 2 machine rows again at `fb6f140` (D-0053); the human run is
still to come (`docs/USER_SESSION.md`). The Phase 3 rows were written in
Phase 3's WP0 (2026-09-28) and revised after its review. After the vault
split (D-0066 to D-0068), the rows a machine can run ran again at `60d4e1b`
(`docs/VERIFY-RESULTS.md`); of the Phase 3 rows, that covers V53, V66 and
V69. The Phase 4 rows were written in Phase 4's WP0 (2026-09-28), before
any Phase 4 code.

## Setup

- Run every row on a **Release** build from `scripts/build.sh`. Debug builds
  have no Hardened Runtime (D-0013). V65 (V39 before Phase 3) and the control
  in V50 use the Verify build from `tools/verify/build.sh` (`$VAPP`). V1, V2
  and V53 run on both builds, so V65 measures a process that is signed and
  configured like Release.
- Tools live in `tools/verify/` and are built by `tools/verify/build.sh`
  (WP4) into `core/target/verify` (`$T`). They are never linked into
  Brev.app (D-0051).
- Brev locks as soon as another app is active, Terminal included. For an A
  part that needs Brev unlocked with a letter or the compose sheet open,
  start the command with a delay (`sleep 30; …`), switch to Brev, unlock,
  and set up the state before it runs. The tools never activate themselves.
- Type the marker `BREV-SECRET-BODY æøå` into the subject and the body of
  every new letter. The searches below look for its ASCII part, which is the
  same in every encoding that keeps ASCII, and for its UTF-16LE form.
- Phase 3: register Brev as `$ADDR_A` and Brev B as `$ADDR_B` (V55, V57).
  The addresses are markers too. Brev seals them (Phase 3 design §6.1), so
  V17 searches for them; the relay's directory holds them in clear, so V58
  uses them as its control. Brev's contact is Brev B, so `$ADDR_B` is the
  contact address marker: the name in Brev's contacts pane and header. Both
  follow the address rules (a–z, 0–9 and `-`, 3–32 characters, first a
  letter; design Q3), and no address marker contains another (Phase 4
  adds `$ADDR_C` and `$ADDR_D`).
- Phase 3 needs the relay and a second instance, Brev B (design §7). Build
  the relay with `cargo build --release -p brev-relay` in `core/`, and Brev B
  with `scripts/build.sh --instance b`. Before the first launch, start the
  relay in a third terminal with the block below pasted in, and leave it
  running: `"$RELAY" serve --db "$RDB" --listen 127.0.0.1:8787 --trace > "$R/relay.log"`.
  The trace holds one line per request, path and status only (design §4.5);
  V63, V64 and V67 read it. `curl -s http://127.0.0.1:8787/v1/health` must
  print `brev-relay v1`.
- Every full run starts with an empty relay. Addresses are permanent (Q3)
  and waiting letters never expire (design §4.3), so a relay left from WP5
  or an earlier run still holds `$ADDR_A` for an identity that is gone, and
  V55 would get `address.error.taken`. Before starting the relay, stop any
  relay that still runs and move its folder aside:
  `[ -e "$RD" ] && mv "$RD" "$R/relay-before-$(date +%s)"`. Brev B then
  starts with no `$DB` too (run order step 2).
- Owner question Q1 (design §11) is answered (A) in D-0065: the relay runs
  as the user, with its folder at `RD` in the block below. Only if (B) were
  built would the relay run as `_brevrelay` with its folder in `/Library/Application Support/brev-relay`:
  change `RD`, and run the commands that read or move that folder, `release`
  and the relay's `lsof` with `sudo`. V63's timed line then stops and starts
  the relay as that user (`sudo pkill -x brev-relay`,
  `sudo -u _brevrelay "$RELAY" serve …`, or `launchctl` for a LaunchDaemon);
  run `sudo -v` just before it, so it does not wait at a password prompt.
- Phase 4 (`docs/PHASE4_DESIGN.md`): registering needs an invite code
  (design §3.1). An identity that nobody invites uses a root invite, which
  the operator mints with the relay running:
  `"$RELAY" invite --db "$RDB" > "$R/root-1"` writes one code (`brev1.`
  and 26 characters). Each code works once and lives 7 days. Phase 4's run
  mints three, `root-1` to `root-3` ("Order of a run (Phase 4)").
  `pbcopy < "$R/root-1"` puts one on the pasteboard for ⌘V on the address
  page. The files are test secrets in `$R`; V80 uses them.
- Phase 4: the relay runs with its default limits (owner answer 3: per
  identity and UTC day 50 letters, 10 requests and 3 invites made; 5 open
  invites; 16 pending requests per recipient; invites live 7 days). Only
  V78 restarts it with `--letters-per-day`. The block below adds two
  address markers for Brev B's second and third identities, `$ADDR_C` and
  `$ADDR_D` (the order of the run says why), and `rq`, a read-only query of
  the relay's file.
- Start Brev with `open "$APP"`, not `open -a Brev`: the Debug build in
  DerivedData has the same name and bundle id.
- Paste the block below into two terminals (three in Phase 3: the third runs
  the relay). It gives the same `R` in all of them.
  Before the first launch, start the log capture from V19 in the second one,
  and check from the first that it writes. Log lines that other rows name
  (`lock reason=…`, `dropped synthetic`, `second instance`,
  `launch refused: arguments`, `selfscan …`, `sync failed: …`) are read from
  that capture.
- Record the macOS build (`sw_vers`), the Xcode version
  (`xcodebuild -version`) and the commit (`git rev-parse --short HEAD`).

```sh
setopt interactivecomments 2>/dev/null
# From the repo root, in zsh or bash. The line above is for zsh: without it,
# an interactive zsh passes every "# …" below to the command as arguments.
APP="$PWD/app/build/Build/Products/Release/Brev.app"
VAPP="$PWD/app/build/Build/Products/Verify/Brev.app"     # the VAPP= line tools/verify/build.sh prints
T="$PWD/core/target/verify"                              # the T= line tools/verify/build.sh prints: the tools
C="$HOME/Library/Containers/no.brev.app"
D="$C/Data/Library/Application Support/Brev"
CACHE_DIR="$(getconf DARWIN_USER_CACHE_DIR)no.brev.app"   # frameworks write here for a sandboxed app (Metal cache)
TEMP_DIR="$(getconf DARWIN_USER_TEMP_DIR)no.brev.app"     # may not exist
M='BREV-SECRET-BODY'
R="${TMPDIR%/}/brev-verify-$(git rev-parse --short HEAD)" # captures and logs of this run: the same path in both terminals
mkdir -p -m 700 "$R"
START="$(date '+%Y-%m-%d %H:%M:%S')"
# Phase 3 (docs/PHASE3_DESIGN.md): Brev B, the relay, the address markers
APPB="$PWD/app/build-b/Build/Products/Release/Brev B.app"   # scripts/build.sh --instance b (design §7)
CB="$HOME/Library/Containers/no.brev.app.b"
DB="$CB/Data/Library/Application Support/Brev"
RELAY="$PWD/core/target/release/brev-relay"                 # cargo build --release -p brev-relay (in core/)
RD="$HOME/Library/Application Support/brev-relay"           # the relay's folder, as scripts/relay.sh uses it (Q1 (B) moves it)
RDB="$RD/relay.db"
ADDR_A='brev-secret-me'                                     # the address Brev registers (V55)
ADDR_B='brev-secret-peer'                                   # the address Brev B registers (V57): the contact address marker

hits() {  # hits NEEDLE PATH...: every file under PATH that holds NEEDLE as UTF-8 or UTF-16LE
  n="$1"; shift
  find "$@" -type f -exec sh -c 'strings -a "$1" | grep -qF -- "$2" && echo "utf-8    $1"' _ {} "$n" \;
  find "$@" -type f -exec perl -0777 -ne 'BEGIN { $n = join("\0", split(//, shift)) . "\0" } print "utf-16le $ARGV\n" if index($_, $n) >= 0' "$n" {} +
}
waiting() {  # the number of letters the relay holds (Phase 3; read-only)
  sqlite3 -readonly "$RDB" 'select count(*) from envelopes'
}
# Phase 4 (docs/PHASE4_DESIGN.md): Brev B's later identities, and read-only queries of the relay's file
ADDR_C='brev-secret-new'                                    # Brev B's second identity (Order of a run (Phase 4), pair 2)
ADDR_D='brev-secret-last'                                   # Brev B's third identity (pair 3)
rq() {  # rq SQL: one read-only query of the relay's file (Phase 4)
  sqlite3 -readonly "$RDB" "$1"
}
```

## Legend

- **A**: the check itself runs from a CLI. A human may need to grant a
  permission once (Screen Recording, Accessibility, Automation, Input
  Monitoring, access to another app's data). Combined values say who does
  what: "A (H opens)" means a human opens the sheet and the CLI checks.
- **H**: needs a human at the Mac.
- **Positive control**: every A row that reads through a permission has one
  in the same run. Without it, "nothing found" can also mean "nothing could
  be read".
- **per D-0052**: the procedure or the expected result depends on a GUI-spike
  fact (the §14.2 item is in brackets; D-0052 holds the design's D-0057).
  Update the row from D-0052 before the run. Where the spike
  says "stop and ask the owner", the row waits for the answer. The design's
  open questions 1 (file substitution) and 3 (backup exclusion) are answered
  in D-0033 items 2 and 4: onboarding shows the `onboarding.rules.gone`
  warning, and the folder is excluded from backups.
- **Q4**, **U4 (WP5)** (Phase 3): the row depends on an owner question or
  a measurement in `docs/PHASE3_DESIGN.md`. Q4 is the owner question on the
  App ID `no.brev.app.b` for Brev B (design §11), approved in D-0065; only
  if registering it fails does the row run with the design's fallback, a
  second macOS user account. U4 (WP5) is Phase 3 WP5's
  measurement of whether the Touch ID panel makes Brev resign active (the
  part of the GUI-spike item U4 that is still unmeasured; design §3.2), and
  the send-prompt rule WP5 applies from it. WP5 built the rule for both
  outcomes behind one switch, `LockState.signPanelTakesActivation`, which is
  false (the prompt keeps auto-lock, the safe side) until the owner measures
  U4: the first Send or Registrer on the Release build, then
  `/usr/bin/log show --last 5m --predicate 'subsystem == "no.brev.app" AND category == "touchid"'`.
  No line: the panel does not take activation, and false stays. The line
  `resign active during Touch ID (sign)` (Brev also locked at once, and the
  lock log says `lock reason=resignActive`): the panel takes activation; set
  the switch to true and rebuild, and Brev then blanks every content view
  for the prompt, ignores resigning active during it only, and locks when it
  ends unless Brev is the active app again (V62 still locks, at the prompt's
  end). Every unlock already logs `resign active during Touch ID (unlock)`
  when its panel takes activation (without locking), so the unlock rows
  measure the same thing with no extra prompt. Update the row from the
  answer before the run. Under Q4's fallback, Brev B is the same Brev.app run by
  the second user: its container and processes are that user's, so
  `pgrep -x Brev` also matches it (use `pgrep -x -u "$USER" Brev`) and V54's
  `lsof` needs `sudo` to see its sockets. Q1 (B) changes where the relay's
  files are and who runs the relay: the commands of Setup's Q1 item and V63's
  stop and restart.
- **P1 (WP5)** (Phase 4): spike P1 (`docs/PHASE4_DESIGN.md` §6.2) decides
  how ⌘V reaches `ContactField`: variant (a) handles ⌘V in `keyDown` and
  reads the pasteboard there, with no Edit menu; variant (b) adds a
  «Rediger» menu with only «Lim inn» (`paste:`), enabled only in
  `ContactField`. WP5 (2026-09-29) built variant (a), and kept (b) ready
  behind the Swift compilation condition `BREV_PASTE_MENU` (off; test.sh
  type-checks it). Whether macOS shows a pasteboard alert on the first
  ⌘V needs a human: V72. If it does, build with `BREV_PASTE_MENU`, rewrite
  V15 for (b), and run V72 again.
- **self-clear (WP5)** (Phase 4): settled by the owner on 2026-09-29. The
  design's clear at a lock would empty the pasteboard as soon as another
  app is active (Brev locks then, V22), before a code can be pasted there.
  So Brev empties the pasteboard 60 s after its copy and when it quits, if
  nothing was copied since, and not at a lock. V71, V73 and V77 follow
  that rule.
- Only V1, V2, V45, V50, V53, V66, V69, the `sdef` half of V3 and the binary
  half of V21 need no human and no running Brev. Every other row needs a
  store or a running Brev, and a human sets that up with Touch ID.

## Checklist

| # | Check | How | A/H | Depends on |
|---|---|---|---|---|
| V1 | Sandboxed + hardened | on `$APP` and `$VAPP`: `codesign -dv`: `runtime`, `TeamIdentifier=AV26DNQ5SC`; entitlements only `app-sandbox`, `network.client` (Phase 3), `keychain-access-groups` = `AV26DNQ5SC.no.brev.app`, and the `application-identifier` and `team-identifier` the profile adds; no `get-task-allow` | A | – |
| V2 | Plist and bundle | on `$APP` and `$VAPP`: `plutil -p`: none of D-0009's keys; `NSPrincipalClass = BrevApplication`; `LSEnvironment.MallocScribble = 1`. No extension, App Intents metadata, XPC service, sdef, Quick Look or Spotlight plug-in, bundle, framework or nested app anywhere in the bundle, and `Contents` holds only `Info.plist`, `MacOS`, `PkgInfo`, `Resources`, `_CodeSignature` and `embedded.provisionprofile` (team signing, D-0035) | A | – |
| V3 | No AppleScript | `sdef` fails; with Brev running, `osascript -e 'tell application "Brev" to get name of every window'` must fail with an error from Brev itself (expected -1708, errAEEventNotHandled; record the code). -1743 (not permitted) or -600 (not running) means the event never reached Brev and fails the row (grant Automation first) | A | – |
| V4 | ⇧⌘4 (window and area), ⇧⌘5 recording | a marker letter open: content absent or black | H | per D-0052 (U1) |
| V5 | `screencapture` | `-x` and `-V 3` show no letter; `-l <id>` (id from `$T/windows`) fails; control: another app's window is visible. `$T/capture-probe --screencapture` runs all four with its own control window and judges each | A | per D-0052 (U1) |
| V6 | ScreenCaptureKit | `$T/capture-probe`: display filter, window filter (`includeChildWindows`), `captureImage(in:)`, `captureScreenshot(…)` (26), one `SCStream` frame each with a display and a window filter; no letter in any (the window excluded, or its panes empty); control: its control window and text are visible | H grants, A runs | per D-0052 (U1) |
| V7 | Legacy CG capture, and the paths `.none` does not stop | a marker letter open: `$T/capture-probe --legacy` (built for 14.0): `CGWindowListCreateImage`, `CGDisplayCreateImage`, `CGDisplayStream` and `AVCaptureScreenInput`; and one `CGDisplayStream` frame through `dlsym` from a binary built for 26.0 (`$T/capture-probe-26`, which `--legacy` runs). No letter in any: the last three show the window with empty panes (the protected layer, D-0034); control as V6 | A | per D-0052 (U1) |
| V8 | Screen Sharing / ARD / AirPlay | a second Mac views, observes, mirrors: no letter visible | H | per D-0052 (U1) |
| V9 | Every window excluded | `$T/windows`: `kCGWindowSharingState == 0` for all Brev windows, once with the compose sheet open and once with `ConfirmSheet` open (it only exists in an error state, so do it during V38); control: the sheet is listed as its own window. On macOS 26.2 every regular app owns four off-screen menu-bar-sized windows with sharing state 1; the tool marks them and still counts them (see `docs/VERIFY-RESULTS.md`) | A (H opens) | – |
| V10 | Accessibility Inspector | the contacts and requests lists, the message list, the ContactBar's address and code, the reading header's subject and name, the letter, the compose fields and the recipient show no text; Innboks and Sendt show only as static text with no action | H | per D-0052 (U3) |
| V11 | AX dump | `$T/axdump Brev`: all attributes and parameterized attributes of every element; marker absent; control: title "Brev" present | A (H grants AX) | per D-0052 (U3) |
| V12 | GUI scripting | System Events `entire contents of window 1`: marker absent; control: the button titles are listed | A | per D-0052 (U3) |
| V13 | AX press refused | `$T/axdump Brev --press` on *Send* (compose sheet open, marker typed) and *Lås opp med Touch ID*, and during V38 on *Slett alt og start på nytt* and `ConfirmSheet`'s *Slett alt*: the files in `$D` are unchanged (a send rewrites `brev.db`, an unlock rewrites `biometry.state`, a reset deletes files), no Touch ID prompt appears, and the `AXError` axdump prints is recorded. Menu items and the mail toolbar's two items (*Nytt brev*, which opens an empty compose sheet as ⌘N does, and *Lås*, which locks): only harmless actions; control: pressing *Lås Brev* through AX locks | A + H looks | per D-0052 (U3) |
| V14 | ⌘C, ⌘X, ⌘A, ⌘V | `printf PB-CONTROL \| pbcopy` first; in the letter and compose views nothing happens and ⌘V inserts nothing; `pbpaste` still prints `PB-CONTROL`. Phase 4: the same in the contacts list and the requests section. ⌘V pastes only in `ContactField` (`ContactSheet` and the address page), where it inserts `pb-control` (the field folds A–Z; the control that the pasteboard held the text); ⌘C, ⌘X and ⌘A in `ContactField` copy nothing, so `pbpaste` still prints `PB-CONTROL` | H + A | P1 (WP5) |
| V15 | Menus | only Brev and Arkiv next to the Apple menu, so no Edit menu with Copy or Paste; right-click in content shows no menu. Phase 4, only if P1 takes variant (b): also «Rediger», with only «Lim inn», enabled only while `ContactField` has focus; no Kopier, Klipp ut or Merk alt in any menu; right-click in `ContactField` shows no menu either | H | P1 (WP5) |
| V16 | Drag | dragging in a letter, onto TextEdit and the Finder, moves nothing out | H | – |
| V17 | No plaintext on disk | `strings -a` and a UTF-16LE grep over every file in the container and in Brev's per-user cache and temp folders: the letter marker, the contact address marker `$ADDR_B` and Brev's own address `$ADDR_A` absent (no `Ekko` or `Speil` since Phase 3); control: `SQLite format 3` found in `brev.db`. Run while unlocked, again after V44's quit, and again after V20's crash | A | – |
| V18 | Padding | `$T/padcheck`: every sealed column length in `brev.db`, the one store of schema v6 (incl. `contacts.flags`, `invites.body` and `messages.proof`), is nonce + bucket + tag; control: it checked more than 0 columns | A | – |
| V19 | No plaintext in logs | `/usr/bin/log stream --level debug` for the whole run, and `/usr/bin/log show --info --debug` from the run's start afterwards (predicate `process == "Brev"`): the letter marker and the address markers `$ADDR_A` and `$ADDR_B` absent (UTF-8 and UTF-16LE) in both; control: `lock reason=` lines present | A | – |
| V20 | Crash report | `kill -SEGV` an unlocked Brev with a marker letter open (start with a delay: Terminal in front locks Brev); wait for the report of that kill (it is written a few seconds later, so the newest `Brev*.ips` right after the kill is an older one) and scan it: the letter marker and both address markers absent; control: the report names `SIGSEGV` and the killed PID, and the V19 stream's last lock or unlock line before the kill is `unlocked` | A | – |
| V21 | Spotlight | `mdfind BREV-SECRET-BODY`: no path outside this checkout (the repo's docs hold the marker; Brev's container is not indexed, and V17 covers it); control: indexing is enabled and `mdfind` finds `docs/VERIFY.md`. The binary links no CoreSpotlight and references no `CSSearchable…` or `NSUserActivity` class (donation through the API) | A | – |
| V22 | Switching app locks | ⌘-Tab away: the lock screen; log `lock reason=resignActive` | H + A | per D-0052 (U4) |
| V23 | Screen lock locks | ⌃⌘Q: `lock reason=screenLocked` | H + A | per D-0052 (U4) |
| V24 | Sleep locks | sleep and wake: locked | H | per D-0052 (U4) |
| V25 | Idle locks | 5 min without input, also with the Brev menu left open: locked | H | per D-0052 (U4.2) |
| V26 | No prompt without a human | `open "$APP"`; `osascript -e 'activate application "Brev"'`: no Touch ID dialog. For the whole run, a dialog appears only right after a human presses *Lås opp med Touch ID*, *Send* or *Registrer*: never on its own, at a sync or an arriving letter, when adding a contact, at *Prøv igjen* or when accepting a new code | H | – |
| V27 | Touch ID | exactly one prompt; no password button; *Avbryt* returns to the lock screen (check this on the regular lock screen: at onboarding's first unlock, *Avbryt* stays on that page, design §5.3 step 8) | H | per D-0052 (U4.1) |
| V28 | Launch hygiene | Brev quit first. `open "$APP" --args -NSTraceEvents YES` exits; `defaults write -g NSTraceEvents -bool YES` then launch → only `launch.error.unsafe`, no unlock button; delete the default right after; the same with `TSMEventTracing` (HIToolbox's key-event trace, which works in Release, D-0064); `open --env NSZombieEnabled=YES "$APP"` → a re-executed process without the variable, or `launch.error.unsafe` if re-exec does not work in the sandbox | A + H looks | per D-0052 (L, M) |
| V29 | Second instance | during onboarding, `open -n "$APP"`: the second instance exits (log `second instance`); files unchanged | A | – |
| V30 | Secure input flag | `ioreg -l -w 0 \| grep kCGSSessionSecureInputPID` = Brev's PID only while a compose field has focus | A (H focuses) | per D-0052 (U2.4) |
| V31 | Keyloggers see nothing | `$T/keylisten` (listen-only CGEventTap + IOHIDManager, Input Monitoring granted) while typing the marker in compose: no key values; control: it sees keys typed in TextEdit. If IOHIDManager sees key values: stop and ask the owner | H + A | per D-0052 (U2.4) |
| V32 | Synthetic keys | `$T/poster key <pid> --via all --global` (CGEventPost at HID and session taps, `CGEventPostToPid`, each with field 41 untouched, set to 0, and set to Brev's PID; `AXUIElementPostKeyboardEvent`; `IOHIDPostEvent`; the taps and `IOHIDPostEvent` post only while Brev is in front, so start it with a delay); System Events `keystroke`: nothing typed; log `dropped synthetic`; control: the same posts type into TextEdit | A | per D-0052 (U2.2) |
| V33 | Synthetic clicks | `$T/poster click <pid> <x> <y> --via all --global` on *Send* / *Lås opp med Touch ID* (their `AXPosition` and `AXSize` from `$T/axdump`) with the same variants: no effect; control as V32 | A | per D-0052 (U2.2) |
| V34 | Text services | dictation, emoji picker, Character Viewer, press-and-hold, Writing Tools, Look Up (⌃⌘D, force click), text replacement, Services shortcuts, Touch Bar suggestions: none reach compose. No autocorrect, spell-check or predictions: `teh ` stays `teh `, no spelling underline, no inline-prediction text | H | per D-0052 (U2.3) |
| V35 | Norwegian input | æ ø å Æ Ø Å; ´+e → é; ¨+u → ü; ⇧´+e → è; ⌥¨ then n → ñ; @ (the key left of Return); ⇧4 $; ⌥7 \|; ⇧⌥7 \\; ⌥8/⌥9 [ ]; ⇧⌥8/⇧⌥9 { }; Caps Lock; key repeat | H | per D-0052 (U2.1) |
| V36 | Onboarding | the five rules texts (`touchid`, `nobackup`, `fingers`, `prompt`, and `gone`, the warning D-0033 item 2 chose) appear in bokmål; *Opprett nøkler* stays disabled until *Jeg forstår …* is ticked | H | – |
| V37 | Crash during onboarding | `kill -9` after *Opprett nøkler*, before the first unlock: relaunch shows onboarding; only fresh files exist after the next attempt | A + H | – |
| V38 | Damaged and reset | Brev quit, move `brev.db` out of `$D`, launch: `unlock.error.damaged` with only *Slett alt og start på nytt*; files unchanged after *Avbryt* in `ConfirmSheet`; after *Slett alt* onboarding starts and `$D` holds only `.lock`; quit and launch again: onboarding (the wrapped-DEK item is gone too) | H + A | – |
| V39 | Heap residue in the real app | Replaced by V65 in Phase 3: the echo contact Ekko is gone, so the letter comes from Brev B over the relay. Phase 2's text (after review round 1): Verify build: send and read a marker letter to Ekko, lock; log `selfscan u8=0 u16=0 glyph=0 scribble=0 probe=<n>` with n > 0. `scribble` is the scribble probe (`app/Tests/scan.c`): a 32 KiB block filled with a pattern and freed keeps no copy of it, so `MallocScribble` takes effect in this process (V49 only reads the variable); `probe` counts the same block while it is allocated (its positive control). `glyph` counts the marker's glyph ids in `GlyphFlush.attrs`'s font (stored XORed, as in harness case 4): after the lock it shows that `GlyphFlush` cleared the control's line of the marker. A typed marker letter leaves no glyph ids even without scribbling (its lines are short, and libmalloc zeroes small freed blocks itself), so `glyph` says nothing about scribbling. Control: the `selfscan control` line (at the start of the lock, the letter still open) shows u16 > 0 and needle > 0; its glyph is 0 (see "Changes from the design"). Harness case 7 (V45) runs the same probe without scribbling and must find the freed block kept, so the probe can fail | – (V65) | – |
| V40 | Key storage | no key file: `$D` holds only `.lock` (0 B), `biometry.state` (32 B, if written) and `brev.db` (Phase 3: the one store); all files 0600, the directory 0700; `security find-generic-password -s no.brev.app` finds nothing (the keys and the wrapped DEK are in the data protection keychain, which `security` cannot list; a copy in a file keychain would be a bug); `xattr`/`tmutil isexcluded` shows the folder excluded | A | – |
| V41 | Nothing else written | no `Saved Application State`; in Application Support only `.lock`, `biometry.state` and `brev.db` (Phase 2 also had `peer-1.db` and `peer-2.db`; design §5.1's table still lists the key files D-0035 removed; any of them fails the row). Run after onboarding, again after V44's quit, and again after V20's crash | A | – |
| V42 | Echo | Retired in Phase 3 with the echo contacts (Phase 3 design §1.2); V57 checks the three panes with a real contact. Phase 2's text: the three panes show Ekko and Speil, the threads and the letters; a letter to Ekko and one to Speil show as sent; each echo arrives within 3 s in the same thread | – (V57) | – |
| V43 | Dock / title | the minimise button is disabled (shown grey: the window has no `.miniaturizable`), and clicking it or ⌘M does not minimise the window, so there is no Dock thumbnail of it; title "Brev"; the Dock window list shows only "Brev" | H | – |
| V44 | Quit while unlocked | relaunch starts on the lock screen | H | – |
| V45 | Automated suite | `scripts/test.sh` exits 0 on this Mac (including the Swift harness, the lock probe and the forbidden-API grep) | A | – |
| V46 | Manual lock, blank-on-lock | with a marker letter open: ⌘L, the *Lås* button and the menu item *Lås Brev*; with the compose sheet open and the marker typed: ⌘L and *Lås Brev* (the sheet blocks clicks on the *Lås* button behind it). Each shows only the lock screen at once; the sheet is gone and secure input is off; after the next unlock the draft is gone; log `lock reason=manual`. Phase 3 (addresses are content, design §6.4): the same with ⌘L, once with `AddContactSheet` open and `$ADDR_B` typed (after the next unlock a new sheet's field is empty), and once on the address page with `$ADDR_A` typed, before V55 (after the next unlock the page's field is empty) | H + A | – |
| V47 | Unlock that ends while Brev is inactive | click *Lås opp med Touch ID*, switch to another app while the Touch ID panel is up, then authenticate: Brev stays on the lock screen | H | per D-0052 (U4.1) |
| V48 | Unlock errors | wrong fingers until Touch ID locks out: `unlock.error.lockout`, never a password button. Then, as the last row of the run: add a fingerprint in System Settings: `unlock.error.fingers` with the reset button. This makes the test install unreadable, as designed, and also invalidates other apps' `.biometryCurrentSet` keys | H | per D-0052 (U4.3) |
| V49 | Malloc scribbling in the real process | `ps -wwE` shows `MallocScribble=1` for Brev started with `open "$APP"`, from the Finder and from the Dock; `open --env MallocScribble=0 "$APP"` → a re-executed process with `MallocScribble=1`, or `launch.error.unsafe` | A + H launches | per D-0052 (M) |
| V50 | Release has no Verify code | `nm` on the Release binary finds no `SelfScan` or `brev_scan` symbol; control: the same grep finds them in the Verify build | A | – |
| V51 | Unlock stack residue | `TouchIDProbe.app --unlock` (built by `tools/verify/build.sh`, team-signed with Brev's bundle id and keychain group) with the final `brev-core`: the exact §5.4 closure (`UnlockService.unlock`, unchanged: KEK lookup, `SecKeyCreateDecryptedData` with ECIES, `brev.unlock`, in-place wipe), needles for the DEK, the ECDH output, the AES key and the IV: it prints PASS, i.e. 0 hits for the ECDH output, AES key and IV after the closure, 0 for everything after lock, at the scrub depth recorded for the unlock drop guard (D-0039); control: while unlocked, the DEK needle finds Rust's copy, and each needle is found once when made on purpose. Negative control (design §14.2 K): the same run with the build whose unlock scrub is disabled (`touchid-probe-scrub0`) prints `NEGATIVE CONTROL: residue …` and PASS for its own controls, so the scrub is what removes the residue; if it prints `NEGATIVE CONTROL EMPTY` instead, record that the PASS above does not show that the scrub works. If the shipped build fails, run the 128 KiB build (`touchid-probe-scrub128`); a change of depth goes to the owner (design §2.5). It uses Brev's own keychain names, so it runs only with Brev quit and not installed (run order step 2), and deletes what it made | H + A | per D-0052 (K) |
| V52 | File substitution | copy the stores in `$D` aside before V38 (three in Phase 2, only `brev.db` since Phase 3); after the new onboarding, Brev quit, put the old stores back: the unlock fails with `unlock.error.damaged` (the new DEK does not open them), and nothing unlocks | H + A | – |
| V53 | Entitlements | on `$APP` and `$VAPP`: `codesign -d --entitlements`: `app-sandbox`, `network.client`, group `AV26DNQ5SC.no.brev.app`; no `network.server` | A | – |
| V54 | Loopback only | Brev unlocked: `lsof -nP -iTCP -a -p <Brev>`: only 127.0.0.1:8787, and at least one connection (Brev polls every 5 s); `lsof -nP -iTCP -sTCP:LISTEN`: brev-relay on 127.0.0.1 only; Brev and Brev B listen nowhere | A | Q4 |
| V55 | Registration prompt | on the address page, *Registrer* with `$ADDR_A`: exactly one dialog, «Brev» … registrere adressen din, no password button | H | U4 (WP5) |
| V56 | One prompt per letter | one dialog per *Send*, «… sende brevet», no password button; *Avbryt* keeps the draft, relay count (`waiting`) unchanged | H + A | U4 (WP5) |
| V57 | Two instances exchange letters (replaces V42) | Brev and Brev B (Phase 3 design §7) add each other by address; a marker letter each way arrives on the recipient's first sync after unlock and shows in its three panes; Brev B's dialog says «Brev B»; separate containers (`$C`, `$CB`) and keychain groups (`AV26DNQ5SC.no.brev.app`, `AV26DNQ5SC.no.brev.app.b`) | H | Q4 |
| V58 | Relay DB has no plaintext (DoD) | `strings -a` and a UTF-16LE grep of `relay.db*` after V57 with the marker letter, and once during V57 while a marker letter waits at the relay (`waiting` ≥ 1): marker absent; control: both addresses found | A | Q4 |
| V59 | Deleted after delivery | `sqlite3 relay.db 'select count(*) from envelopes'` (`waiting`) = 0 once both have synced | A | – |
| V60 | Key change (DoD) | reset Brev B (V38's method, on `$DB`), `brev-relay release` of `$ADDR_B`, Brev B registers `$ADDR_B` again. In Brev, a new letter to it: *Send* shows `compose.keychanged` with no Touch ID dialog, relay count unchanged; the contact header then shows the warning (`contact.changed`) and both codes, and *Nytt brev* is disabled for it. After *Godta ny kode*, and after Brev B adds `$ADDR_A` again (letters from strangers are dropped, Q2), a letter arrives in Brev B | H + A | Q4 |
| V61 | Codes match | the code Brev shows for Brev B equals the own code in Brev B's header | H | Q4 |
| V62 | App switch during the send prompt | ⌘-Tab while the send dialog is up: Brev locks; nothing sent (relay count unchanged) | H + A | U4 (WP5) |
| V63 | Relay down | stop the relay: `sync failed: Network` logged once, not every 5 s; *Send* shows `net.error` and keeps the draft. After a restart, *Prøv igjen* sends once, with no second Touch ID: it appears only when the relay fails after signing, so the relay is stopped while the send dialog is up, and restarted, by a timed command (Terminal in front would lock Brev and clear the signed letter) | H + A | – |
| V64 | No requests while locked | relay with `--trace`: no line while Brev and Brev B are locked; controls: `/v1/inbox` lines while one of them is unlocked, and a `/v1/health` request right after the quiet minute adds one line (the relay was up and tracing) | A | – |
| V65 | Heap residue with the network | V39 rewritten, with both of its halves: on the Verify build, write a marker letter to Brev B and send it (*Send*, one Touch ID), and read the new marker letter Brev B sent over the relay (it arrives on the first sync after unlock); lock with that letter open: log `selfscan u8=0 u16=0 glyph=0 scribble=0 probe=<n>` with n > 0 (V39's scribble probe), with V39's control line (at the start of the lock, the letter still open: u16 > 0 and needle > 0; its glyph is 0). `SelfScan`'s needle is the letter marker only, so this row does not measure address residue after lock | H + A | Q4; per D-0052 (M) |
| V66 | No ATS, no URLSession, no pasteboard outside the contact screen | `plutil -p Info.plist` has no `NSAppTransportSecurity`; `nm -u Brev` has no `NSURLSession`; the forbidden-API grep passes, and `allowed-apis.txt`'s pasteboard lines are OpaqueView's Services override and, from Phase 4's WP5 on, `ContactPasteboard.swift`'s lines, nothing else. Phase 4: test.sh's pasteboard greps pass too (design §6.2): `ContactPasteboard` is named only in its own file, `ContactField.swift` (the one read), `ContactSheet.swift` (the two writes) and `AppDelegate.swift` (the self-clear at quit); no responder method or selector names `copy:`, `cut:`, `paste:`, `pasteAsPlainText:`, `pasteAsRichText:` or `selectAll:` but EnvironmentProbe's list of the actions it checks, and, only inside `#if BREV_PASTE_MENU` (P1's variant (b)), `ContactField`'s `paste:` and MainMenu's «Lim inn» | A | P1 (WP5) |
| V67 | New controls | V9 (window exclusion) on the address page, `AddContactSheet` and the accept `ConfirmSheet`; V13 (AX press refused) on *Registrer* with `$ADDR_A` typed, *Legg til* with `$ADDR_B` typed (a valid address, so that a press that gets through shows a dialog, a request or a new contact, not an address error), *Godta ny kode* and the accept `ConfirmSheet`'s *Godta*: no Touch ID dialog, no `/v1/register` or `/v1/lookup` in the relay trace, no new sheet, `$D` unchanged; record the `AXError` | A (H opens and looks, as in V9 and V13) | per D-0052 (U3) |
| V68 | No contact data in AX or capture | with a contact whose address is a marker (`$ADDR_B`, selected, so the header shows both addresses and codes): V11's AX dump has neither address marker nor any identity code (6 groups of 5 of A–Z and 2–7); V5–V7's capture (`capture-probe` with the header's protected view as a `--pane`) shows the header blank, while a control `--pane` over one of the header's labels shows ink in every path that captures the window, and Brev does not lock during the run (`--pane` turns off the probe's own check for that); controls as in V11 and V6 | A | per D-0052 (U1, U3) |
| V69 | The view host's checks | no Brev needed; on the Release commit, nobody using the Mac: the view host (`tools/viewhost`: Brev's mail window, compose sheet, lock sequence and triggers with fake letters and a software KEK) prints PASS in mail mode (`--hold 1 --scan --post`: the protected layer, `draw(_:)` empty, pixel buffers zeroed on scroll-out and on lock, the Rust session locked, hardened sheets and child windows, a posted key dropped, the scribble probe), compose mode (`--compose --hold 1 --scan --post`: key-only typing, the ways in that must fail, secure input, the sheet wiped and freed after a send, Escape and a lock) contacts mode (`--contacts --hold 1`; Phase 4, design §8: the address page with its invite step (`ContactField`, ⌘V, *Fortsett*, «Invitert av») and *Registrer*; `ContactSheet`, which replaces Phase 3's `AddContactSheet` (*Kopier adressen min*, *Lag invitasjon*, the code, *Kopier koden*, `ContactField`, *Legg til*, *Godta invitasjonen*); the requests section with *Godta* and *Avslå*; the contact header with *Blokker*; and Phase 3's changed key with *Godta ny kode* and the accept `ConfirmSheet`. Each is hardened, and each of those buttons refuses a click made in code and an AX press: no signature, no pasteboard write, no new line in the relay's trace. The accessibility tree holds no address marker, identity code or invite code; addresses, codes and requests are only in the protected layer; the pasteboard is read only in `ContactField`; its two writes are for this Mac only (no Universal Clipboard) and set the text after both markers; its self-clear runs after a shortened timer, leaves another app's later copy alone, and is not run by a lock; ⌘V pastes nothing outside `ContactField`; under P1's variant (a) no responder answers `paste:` and the `pasteboardDisabled` probe holds while `ContactSheet` is key (under (b) it would report false then and true after the sheet closes, design §5.5); and the lock sequence wipes all of it. The view host uses a named pasteboard (no pasteboard alert, the user's own untouched). While the screen is locked or the display sleeps, the protected layer displays no frame, so the view host checks the layer's buffers, `draw(_:)` and `cacheDisplay` only and prints a `skip layer` line. This is the machine half of V67, V68 and V79, run in process; during its holds a driver can also run `$T/windows`, `$T/axdump` and `$T/axdump --press` against it) and `--triggers switch` (switching app locks, not while an unlock is in flight, which logs U4's measurement line). The compose and switch runs make the view host active, and the switch run brings the Finder to the front | A | P1 (WP5) |
| V70 | Open-documents event | Brev running (onboarding or the lock screen), and again unlocked with the compose sheet open and a field focused (start with a delay): `open -a "$APP" <any file>` adds no window to `$T/windows Brev` (AppKit's "cannot open" alert would be an unhardened window with sharing state 1 that takes key from the sheet and turns secure input off); with the sheet open, `kCGSSessionSecureInputPID` is still Brev's PID; log `open event ignored count=1` | A (H opens) | – |
| V71 | Invite onboarding | the relay empty and `root-1` minted (Setup). Brev, on the address page: `pbcopy < "$R/root-1"`, then ⌘V into the field and *Fortsett*: `invite.root`; then `$ADDR_A` and *Registrer* (one Touch ID dialog, as V55). Brev, *Kontakter*: *Lag invitasjon* shows a code (protected, two lines) with no Touch ID dialog (owner answer 7); then *Kopier koden*. Brev B, on its address page: ⌘V and *Fortsett*: «Invitert av:» with `$ADDR_A` and Brev's identity code (protected; the same as the own code in Brev's header, V61); then `$ADDR_B` and *Registrer* (one dialog, «Brev B»). After one sync each, each contact list shows the other with «Bekreftet med invitasjon», with no request and no *Godta*; a marker letter each way arrives. The relay: Brev's `invited_by` is empty, Brev B's is Brev's id | H + A | P1 (WP5) |
| V72 | P1: paste without an alert | the first ⌘V in `ContactField` (V71's root code, on Brev's address page): the code appears in the field, and macOS shows no pasteboard alert. Record the variant WP5 built and any alert (design §6.2: if both variants alert, one alert is accepted and recorded) | H | P1 (WP5) |
| V73 | Pasteboard only on the contact screen | right after *Kopier koden* (and the same after *Kopier adressen min*): the general pasteboard's types are `public.utf8-plain-text`, `org.nspasteboard.ConcealedType` and `org.nspasteboard.TransientType` (AppKit also lists `NSStringPboardType`, its old name for plain text); 60 s after the copy it has no types. After *Kopier adressen min* and ⌘L: the types are still there (the owner's rule: no clear at a lock), and gone 60 s after the copy. After *Kopier adressen min* and ⌘Q: no types right away. After *Kopier adressen min*, a copy in another app, and 60 s: the other app's text is still there. ⌘V in the compose and letter views inserts nothing (V14). A letter sent right after *Kopier adressen min*, with the sheet closed, goes out without `compose.environment`: `pasteboardDisabled` is true at *Send* (class A needs it) | H + A | P1 (WP5) |
| V74 | Request and approval | pair 2 (Order of a run (Phase 4)): Brev, *Kontakter*: `$ADDR_C`, *Legg til*: `request.sent`, and the contact shows «Venter på svar»; the relay holds one event, a request. Brev B: «Forespørsler» lists it (address and code in the protected layer, `request.body`); *Godta*: one click, no Touch ID dialog, no confirm; Brev is at once an ordinary contact there. Brev's next sync clears «Venter på svar», and after it the relay holds no event. A marker letter each way arrives on the recipient's first sync after unlock (immediate delivery, D-0030) | H + A | – |
| V75 | Decline | pair 3: Brev adds `$ADDR_D` as in V74. Brev B: *Avslå*: one click, no Touch ID dialog; the request leaves the list and does not come back at the next syncs; the relay holds no event, and its link from Brev B to Brev is declined (state 2). Brev's *Send* to Brev B: `compose.notapproved`, no Touch ID dialog, `waiting` unchanged, no `/v1/envelopes` line in the trace. Nothing tells Brev about the decline (owner answer 5): the contact still shows «Venter på svar». Brev adds `$ADDR_D` again: `contact.error.duplicate`, and no `/v1/requests` line (a declined requester's later requests are relay test 6, in V45) | H + A | – |
| V76 | Unapproved sender (DoD) | relay test 5 (`unapproved_sender_cannot_reach_an_inbox`) and brev-mail test 4 (`a_stranger_cannot_reach_an_inbox`, whose forced submit reaches a relay on 127.0.0.1 over HTTP and gets 409) pass in V45 and by name (Commands). The app half, in V74 before *Godta*: Brev's *Send* to Brev B shows `compose.notapproved` with no Touch ID dialog; the trace has `/v1/lookup` and no `/v1/envelopes`; `waiting` unchanged | A (H sends) | – |
| V77 | Wrong fingerprint (DoD) | brev-mail test 1 (`invite_with_wrong_fingerprint_is_rejected`) passes in V45 and by name (Commands). In V71, before the right code: on Brev B's address page, ⌘V, then ⌘→, ← 27 times (the caret now stands at the end of the fingerprint, before `.` and the secret), ⌫ and another letter of a–z or 2–7, then *Fortsett*: `invite.error.mismatch`, and no «Invitert av»; since the paste, the trace has `/v1/invites/open` and no `/v1/register` or `/v1/invites/redeem`. Then empty the field for V71 | H + A | P1 (WP5) |
| V78 | Rate limit | pair 2, after V74: restart the relay with `--letters-per-day` set to one more than Brev's letters that UTC day (Commands; the same file). One more letter from Brev goes. The next: one Touch ID dialog (the relay decides after the signature), then `compose.ratelimited`; the draft stays; `waiting` and Brev's count are unchanged. Then restart the relay with its defaults | H + A | – |
| V79 | New UI hardened; no contact data in AX or capture | V67 and V68 for Phase 4's new UI. V9 (window exclusion) with `ContactSheet` open, and on the address page's invite step. V13 (AX press refused) on *Fortsett* (a code pasted), *Kopier adressen min*, *Lag invitasjon*, *Kopier koden* (a code shown), *Legg til* (`$ADDR_C` typed), *Godta* and *Avslå* (a request pending, before a human answers it) and *Blokker* (before V81): no Touch ID dialog, no new line in the relay trace, no new sheet, `$D` (or `$DB`) unchanged, and the pasteboard's change count unchanged; record the `AXError`. V68's AX dump with `ContactSheet` open and a code shown, and with a request selected: no address marker, no identity code, no `brev1.`; V68's capture with the code's view and the request's header as `--pane`s: blank, with a label as the control. *Godta invitasjonen* is V69's (this run redeems no code while registered) | A (H opens and looks) | – |
| V80 | Relay file | after the run's last letter: the hex of each `relay.db*` file (`xxd -p`, joined into one line) holds neither `s` nor `a` of any of the three root codes, nor the letter marker; control: the hex of each code's `SHA-256(a)` is found (Commands) | A | – |
| V81 | Blokker | pair 2, after V78: Brev B, on Brev's contact, *Blokker*: one click, no Touch ID dialog; the relay's link from Brev B to Brev is declined (state 2). Brev's *Send* to Brev B: `compose.notapproved`, no Touch ID dialog, `waiting` unchanged. Brev B cannot write to Brev: no Touch ID dialog, no `/v1/envelopes` line. The relay test and the brev-mail test for *Blokker* (owner answer 6) pass in V45 | H + A | – |
| V82 | Hand: sudo locks Brev | **Pass, owner 2026-09-29** (D-0112; the parts marked A not run). Brev locks when Terminal comes to the front, so start sudo with a delay: `sudo -v && sleep 15 && sudo sleep 20`, then unlock Brev within the 15 s. Brev unlocked, the mail window showing. In another terminal: `sudo sleep 20` (the password once). Within about 2 s Brev locks: the mail is gone, the lock screen says «Brev låste seg fordi sudo kjører.», and the log has `lock reason=environment`. While `sleep` still runs: «Lås opp med Touch ID» (one dialog) ends on the lock screen with «Brev kan ikke åpnes mens sudo kjører.». After `sleep` has ended: the unlock works and the mail shows | H + A | – |
| V83 | Hand: the badge and its detail | **Pass, owner 2026-09-29** (D-0112; V9 and V11 parts not run). The Release builds with the Enclave keys, pair 1 (Runde 1): a letter from Brev to Brev B, then Brev B unlocked. In Brev B the letter's header shows «Skrevet i Brev · klasse A»; the sender's own copy in Brev shows no badge. A click on the badge opens a sheet (V9: sharing state 0) with «Nøkkel i maskinvare med Touch ID: ja (oppgitt av avsenderens app)», «Andre vinduer synlige: N», «Kjente AI-programmer i gang: N», «Admin: ja», «Blokkerte forsøk på å skrive inn: 0», «Skrivetid: … min», «SIP: på», «sudo: nei», and last «Appen er ikke bekreftet av Apple (støttes ikke på Mac)»; Escape or «Lukk» closes it. V11's AX dump of the letter pane shows the badge's text and nothing else of it | H + A | – |
| V84 | Hand: one Touch ID per letter | **Pass, owner 2026-09-29** (D-0112; one dialog, Avbryt; the ⌘L part not run). «Send» on a letter: exactly one Touch ID dialog («… sende brevet», no password button), which signs both the authorship token and the envelope; the letter arrives (one `/v1/envelopes` line in the relay trace). «Avbryt» in that dialog: back to the draft, nothing sent, no second dialog. ⌘L while the dialog is up: the dialog goes away, Brev is locked, nothing sent | H + A | – |

## Commands

For the A parts of the rows above. Each comment says what a pass looks like.

```sh
# V1, V2 and V53, on both builds
for A in "$APP" "$VAPP"; do
  codesign -dv "$A" 2>&1 | grep -E 'flags|TeamIdentifier' # flags=0x10000(runtime); TeamIdentifier=AV26DNQ5SC
  codesign -d --entitlements - --xml "$A" | plutil -p -   # only app-sandbox => true, network.client => true, keychain-access-groups =>
                                                          # [AV26DNQ5SC.no.brev.app], com.apple.application-identifier, com.apple.developer.team-identifier
  codesign -d --entitlements - --xml "$A" | plutil -p - | grep -c 'security.network.client'   # 1 (V53)
  codesign -d --entitlements - --xml "$A" | plutil -p - | grep -c 'security.network.server'   # 0 (V53)
  P="$A/Contents/Info.plist"
  plutil -p "$P" | grep -E 'NSAppleScriptEnabled|NSServices|CFBundleDocumentTypes|CFBundleURLTypes|UTExportedTypeDeclarations|NSUserActivityTypes|NSAppleEventsUsageDescription|Intents|NSMainNibFile'   # nothing
  plutil -extract NSPrincipalClass raw "$P"               # BrevApplication
  plutil -extract LSEnvironment.MallocScribble raw "$P"   # 1
  find "$A" -mindepth 1 \( -name '*.appex' -o -name '*.appintents' -o -name '*.xpc' -o -name '*.sdef' -o -name '*.qlgenerator' -o -name '*.mdimporter' -o -name '*.plugin' -o -name '*.bundle' -o -name '*.framework' -o -name '*.app' \)   # nothing
  ls -A "$A/Contents"                                     # only Info.plist MacOS PkgInfo Resources _CodeSignature embedded.provisionprofile
done

# V3
sdef "$APP"                                                # couldn't get sdef … (error -192), exit 1
osascript -e 'tell application "Brev" to get name of every window'   # Brev running: an error from Brev; record the code

# V5 (a marker letter open; another app's window visible)
screencapture -x "$R/v5.png"
screencapture -x -V 3 "$R/v5.mov"
screencapture -x -l <id> "$R/v5-window.png"                # fails: could not create image from window

# V12 (a marker letter open; Brev in front when the delay ends)
sleep 30; osascript -e 'tell application "System Events" to get entire contents of window 1 of process "Brev"' > "$R/v12.txt"
grep -c "$M" "$R/v12.txt"                                  # 0
grep -c 'Nytt brev' "$R/v12.txt"                           # > 0 (control)

# V5 to V7 (a marker letter open; each run leaves only cuts of its own stage area in $R). When the delay
# ends: Brev in front with the letter open, the pointer off its window, and no system dialog over it (the
# probe counts both as ink).
sleep 30; for m in screencapture sck legacy; do "$T/capture-probe" --$m --out "$R/capture-$m" > "$R/capture-$m.txt"; echo "$m exit=$?"; done
grep '^RESULT' "$R"/capture-*.txt                          # every line "pass"; exit 0 each. Look at the cuts too.
                                                           # INVALID (exit 2): that run judged nothing (Brev locked or not on its
                                                           # mail window, no Accessibility for Terminal, a control not seen); run again

# V9 (the compose sheet open; again with ConfirmSheet during V38)
sleep 30; "$T/windows" Brev > "$R/v9.txt"                  # kCGWindowSharingState=0 on every line (see the row)

# V11 (a marker letter open)
sleep 30; "$T/axdump" Brev > "$R/v11.txt"
grep -c "$M" "$R/v11.txt"                                  # 0
grep -c 'AXTitle = "Brev"' "$R/v11.txt"                    # > 0 (control)

# V13: a list of $D before and after each press (size, mtime in ns, inode: a rename also counts).
# For Send: Brev in front, unlocked, the compose sheet open and the marker typed when the delay ends
# (the list is taken after the delay, because an unlock rewrites biometry.state).
sleep 30; find "$D" -type f -exec stat -f '%N %z %Fm %i' {} + | sort > "$R/v13-before"
"$T/axdump" Brev --press '<button title>'                  # record the AXError it prints; no Touch ID prompt appears
find "$D" -type f -exec stat -f '%N %z %Fm %i' {} + | sort | diff "$R/v13-before" -   # no output

# V17 (the run while unlocked: Brev in front, unlocked, a marker letter open when the delay ends;
# the runs after V44's quit and V20's crash need no delay)
sleep 30; hits "$M" "$C" "$CACHE_DIR" "$TEMP_DIR"          # nothing (a missing TEMP_DIR is fine)
hits "$ADDR_B" "$C" "$CACHE_DIR" "$TEMP_DIR"               # nothing: the contact address marker
hits "$ADDR_A" "$C" "$CACHE_DIR" "$TEMP_DIR"               # nothing: Brev's own address
strings -a "$D/brev.db" | grep -c 'SQLite format 3'        # 1 (control)

# V18 (Brev quit)
"$T/padcheck" "$D"                                         # padcheck: pass; brev.db: more than 0 sealed values checked

# V19: the stream runs in the second terminal from before the first launch; stop it with ⌃C after the last row.
/usr/bin/log stream --level debug --predicate 'process == "Brev"' > "$R/stream.log"
head -1 "$R/stream.log"                                    # in the first terminal, before the first launch: Filtering the log data using …
/usr/bin/log show --info --debug --predicate 'process == "Brev"' --start "$START" > "$R/show.log"
hits "$M" "$R/stream.log" "$R/show.log"                    # nothing
hits "$ADDR_A" "$R/stream.log" "$R/show.log"               # nothing (Phase 3: the address markers)
hits "$ADDR_B" "$R/stream.log" "$R/show.log"               # nothing
grep -c 'lock reason=' "$R/stream.log"                     # > 0 (control)

# V20 (Brev in front, unlocked, a marker letter open when the delay ends)
sleep 30; PID="$(pgrep -x Brev)"; touch "$R/v20-mark"; kill -SEGV "$PID"
grep -E 'lock reason=|\] unlocked' "$R/stream.log" | tail -1   # ends in "] unlocked" (control: Brev was unlocked when it was killed)
for i in $(seq 60); do IPS="$(find ~/Library/Logs/DiagnosticReports -name 'Brev*.ips' -newer "$R/v20-mark" | head -1)"; [ -n "$IPS" ] && break; sleep 1; done
echo "$IPS"                                                # one path (none after 60 s fails the row)
hits "$M" "$IPS"                                           # nothing
hits "$ADDR_A" "$IPS"; hits "$ADDR_B" "$IPS"               # nothing (Phase 3: the address markers)
grep -c SIGSEGV "$IPS"                                     # > 0 (control)
grep -c "\"pid\" : $PID," "$IPS"                           # 1 (control: the report of this kill)

# V21
mdutil -s /                                                # Indexing enabled. (control)
mdfind "$M" 2>/dev/null | grep -v "^$PWD/"                 # nothing outside this checkout
mdfind "$M" 2>/dev/null | grep -cx "$PWD/docs/VERIFY.md"   # 1 (control: the index is live and finds the marker)
otool -L "$APP/Contents/MacOS/Brev" | grep -c CoreSpotlight                  # 0
nm -u "$APP/Contents/MacOS/Brev" | grep -Eci 'CSSearchable|NSUserActivity'   # 0

# V28 (Brev quit first)
open "$APP" --args -NSTraceEvents YES                      # Brev exits; log: launch refused: arguments
defaults write -g NSTraceEvents -bool YES; open "$APP"     # only launch.error.unsafe; then quit Brev
defaults delete -g NSTraceEvents                           # at once: the global default reaches every app launched meanwhile
defaults write -g TSMEventTracing -bool YES; open "$APP"   # only launch.error.unsafe; then quit Brev
defaults delete -g TSMEventTracing                         # at once, as above
open --env NSZombieEnabled=YES "$APP"
ps -wwE -p "$(pgrep -x Brev)" | tr ' ' '\n' | grep -E '^(NSZombieEnabled|MallocScribble)='   # re-exec: MallocScribble=1 only

# V29 (during onboarding)
find "$D" -type f -exec stat -f '%N %z %m %Sp' {} + | sort > "$R/v29-before"
open -n "$APP"                                             # the new instance exits
pgrep -x Brev                                              # one PID
find "$D" -type f -exec stat -f '%N %z %m %Sp' {} + | sort | diff "$R/v29-before" -   # no output

# V30 (Brev in front when the delay ends: once with a compose field focused, once unlocked with no field focused)
sleep 30; pgrep -x Brev; ioreg -l -w 0 | grep kCGSSessionSecureInputPID   # that PID only in the run with a field focused

# V31 (Input Monitoring granted to Terminal; type the marker in compose within the 60 s, then in TextEdit)
"$T/keylisten" 60 > "$R/v31.txt"                           # no "KL" line while typing in Brev; "KL tap … uniLen=1" in TextEdit

# V32 and V33 (compose open with the marker typed; Brev in front when the delay ends)
sleep 30; "$T/poster" key "$(pgrep -x Brev)" --via all --global > "$R/v32.txt"
grep -c 'dropped synthetic' "$R/stream.log"                # > 0; nothing typed

# V40
stat -f '%Sp %z %N' "$D" "$D/.lock" "$D"/*                 # drwx------; files -rw-------; sizes as in the row
security find-generic-password -s no.brev.app              # could not be found
tmutil isexcluded "$D"                                     # [Excluded]
xattr -l "$D"                                              # com.apple.metadata:com_apple_backup_excludeItem

# V41
ls -A "$C/Data/Library/Saved Application State"            # no such file or directory, or empty
ls -A "$D"                                                 # only .lock biometry.state brev.db (Phase 2 also had peer-1.db peer-2.db)

# V49 (launch with open, from the Finder and from the Dock)
ps -wwE -p "$(pgrep -x Brev)" | tr ' ' '\n' | grep '^MallocScribble='   # MallocScribble=1
open --env MallocScribble=0 "$APP"                         # after quitting; then the same ps

# V50
nm "$APP/Contents/MacOS/Brev" | grep -Eci 'selfscan|brev_scan'           # 0
nm "$VAPP/Contents/MacOS/Brev" | grep -Eci 'selfscan|brev_scan'         # > 0 (control)

# V51 (Brev quit and not installed: run order step 2). Each --unlock asks for Touch ID once.
PROBE="$T/touchid-probe/Build/Products/Release/TouchIDProbe.app"             # brev-core as shipped: scrub=64 KiB
PROBE0="$T/touchid-probe-scrub0/Build/Products/Release/TouchIDProbe.app"     # the unlock's deep scrub disabled
PROBE128="$T/touchid-probe-scrub128/Build/Products/Release/TouchIDProbe.app" # the scrub at 128 KiB
open -W --stdout "$R/v51-dry.txt" "$PROBE" --args --dry  # no prompt; PASS (checks the setup)
open -W --stdout "$R/v51.txt" "$PROBE" --args --unlock   # exactly one Touch ID prompt, no password button; PASS
open -W --stdout "$R/v51-scrub0.txt" "$PROBE0" --args --unlock      # NEGATIVE CONTROL: residue …; PASS (record EMPTY if it says so)
open -W --stdout "$R/v51-scrub128.txt" "$PROBE128" --args --unlock  # only if v51.txt says FAIL

# Phase 3 (V53 to V68). V53 is in the V1 loop above. The relay runs in the third terminal (Setup).

# V54 (Brev in front and unlocked when the delay ends)
sleep 30; lsof -nP -iTCP -a -p "$(pgrep -x Brev)"           # each connection 127.0.0.1:<port>->127.0.0.1:8787; at least one (none: run again, a poll runs every 5 s)
lsof -nP -iTCP -sTCP:LISTEN                                 # brev-relay on 127.0.0.1:8787 only; no line for Brev or Brev B

# V56, V60 and V62: the relay's count before Send and after (the recipient locked, so a sent letter would wait)
waiting                                                     # the same number after Avbryt (V56), compose.keychanged (V60) or the lock (V62)

# V57 (the CLI half of "separate containers and keychain groups")
codesign -d --entitlements - --xml "$APPB" | plutil -p - | grep -A1 keychain-access-groups   # AV26DNQ5SC.no.brev.app.b
ls -d "$C" "$CB"                                            # both exist

# V58 (once while a marker letter waits: sent, the recipient not yet unlocked; again after V57)
waiting                                                     # >= 1 the first time
hits "$M" "$RD"                                             # nothing (relay.db and any -journal)
strings -a "$RDB" | grep -cF -- "$ADDR_A"                   # > 0 (control: the directory)
strings -a "$RDB" | grep -cF -- "$ADDR_B"                   # > 0 (control)

# V59 (both instances have synced)
waiting                                                     # 0

# V60 (after Brev B's reset by V38's method on "$DB"; before Brev B registers again)
"$RELAY" release --db "$RDB" "$ADDR_B"                      # frees the address and deletes its waiting letters

# V63, part 1: note the stream's length first. Then stop the relay (⌃C in its terminal); switch to Brev, unlock, wait 30 s,
# press Send once (net.error, no dialog), and come back.
s="$(wc -l < "$R/stream.log")"
tail -n +"$((s + 1))" "$R/stream.log" | grep -c 'sync failed: Network'   # 1: once for the outage, not once per 5 s
# V63, part 2: start the relay again as in Setup, with >> instead of >. Then run the line below, switch to Brev, unlock,
# write a letter and press Send so that the dialog is up when the relay stops (at 30 s). Authenticate after that:
# Prøv igjen appears. The relay is back at 60 s: press Prøv igjen once.
wc -l < "$R/relay.log" > "$R/v63-n"; sleep 30; pkill -x brev-relay; sleep 30; "$RELAY" serve --db "$RDB" --listen 127.0.0.1:8787 --trace >> "$R/relay.log"
tail -n +"$(($(cat "$R/v63-n") + 1))" "$R/relay.log" | grep '/v1/envelopes'   # (another terminal) exactly one line, status 202; no second Touch ID

# V64 (Terminal in front: Brev and Brev B locked)
a="$(wc -l < "$R/relay.log")"; sleep 60; b="$(wc -l < "$R/relay.log")"; echo "$a $b"   # the same number twice
curl -s http://127.0.0.1:8787/v1/health; echo; sleep 1; wc -l < "$R/relay.log"   # brev-relay v1, then b + 1 (control: the relay was up and tracing)
grep -c '/v1/inbox' "$R/relay.log"                         # > 0 (control: unlocked sessions poll)

# V65 (V39's command; Verify build, after it sent a marker letter to Brev B and read Brev B's; from the V19 stream)
grep -o 'selfscan .*' "$R/stream.log"                      # after the lock: selfscan u8=0 u16=0 glyph=0 scribble=0 probe=<n>, n > 0;
                                                           # the control line: u16 > 0 and needle > 0

# V66 (the forbidden-API grep itself runs in V45)
for A in "$APP" "$VAPP"; do plutil -p "$A/Contents/Info.plist" | grep -c NSAppTransportSecurity; done   # 0 twice
nm -u "$APP/Contents/MacOS/Brev" | grep -Eci 'URLSession|NSURLConnection'                             # 0
grep -v '^#' scripts/allowed-apis.txt | grep -i pasteboard | cut -d'|' -f1   # app/Sources/UI/OpaqueView.swift twice; from Phase 4's WP5 on
                                                           # also app/Sources/UI/ContactPasteboard.swift; nothing else

# V67: V9's command with the address page, AddContactSheet and the accept ConfirmSheet open. V13's command for Registrer
# ($ADDR_A typed on the address page first), Legg til ($ADDR_B typed in AddContactSheet first), Godta ny kode and the
# ConfirmSheet's Godta, with the relay trace and the window list checked too:
sleep 30; n="$(wc -l < "$R/relay.log")"; "$T/windows" Brev > "$R/v67-win"; find "$D" -type f -exec stat -f '%N %z %Fm %i' {} + | sort > "$R/v67-before"
"$T/axdump" Brev --press '<button title>'; sleep 5          # record the AXError; no Touch ID dialog appears
find "$D" -type f -exec stat -f '%N %z %Fm %i' {} + | sort | diff "$R/v67-before" -   # no output
"$T/windows" Brev | diff "$R/v67-win" -                    # no output: no new sheet
tail -n +"$((n + 1))" "$R/relay.log" | grep -E 'register|lookup'   # nothing

# V68 (Brev B's contact selected, the header showing both addresses and codes; Brev in front when each delay ends)
sleep 30; "$T/axdump" Brev > "$R/v68.txt"
grep -cF -e "$ADDR_A" -e "$ADDR_B" "$R/v68.txt"            # 0
grep -Ec '[A-Z2-7]{5}( [A-Z2-7]{5}){5}' "$R/v68.txt"       # 0: no identity code
grep -c 'AXTitle = "Brev"' "$R/v68.txt"                    # > 0 (control)
# <x,y,w,h>: the header's protected view in global points, origin top left. It has no AX element (OpaqueView), so axdump
# and --hit cannot give its frame: take it from the AXPosition and AXSize in $R/v68.txt of what surrounds it, the header's
# labels (Du:, Sikkerhetskode:) and the tops of the thread and letter scroll areas below, with no label inside it (one
# --pane each if the labels split it). <label>: one label's frame grown by 6 points on each side (the probe insets every
# pane by 6): the control. --pane turns off the probe's own check for a lock during the run, so the stream is checked
# instead: stay on Brev until the last number prints.
sleep 30; s="$(wc -l < "$R/stream.log")"; for m in screencapture sck legacy; do "$T/capture-probe" --$m --pane header=<x,y,w,h> --pane label=<label> --out "$R/v68-$m" > "$R/v68-$m.txt"; echo "$m exit=$?"; done; sleep 2; tail -n +"$((s + 1))" "$R/stream.log" | grep -c 'lock reason='
                                                           # 0: Brev did not lock during the run
grep -h '^RESULT' "$R"/v68-*.txt                           # each line "pass" with the window excluded (or empty while the same method
                                                           # shows the control window), or "window captured, ink in label"; never
                                                           # "header" or INVALID. A captured window with every pane empty means the
                                                           # label control was missed: the rects are off, run again. Exit 1 is
                                                           # expected where the label shows ink
grep -c 'window captured, ink in label$' "$R/v68-legacy.txt"   # > 0 (control: the paths of V7 that capture the window)

# V69 (V53 in D-0063; no Brev needed; nobody uses the Mac meanwhile: the compose and switch runs take activation)
VH="$(tools/viewhost/build.sh)"                            # needs the archive and bindings (scripts/test.sh or build.sh ran)
env MallocScribble=1 "$VH" --hold 1 --scan --post > "$R/v69-mail.txt"; echo "exit=$?"              # exit=0
env MallocScribble=1 "$VH" --compose --hold 1 --scan --post > "$R/v69-compose.txt"; echo "exit=$?"  # exit=0
env MallocScribble=1 "$VH" --contacts --hold 1 > "$R/v69-contacts.txt"; echo "exit=$?"             # exit=0
"$VH" --triggers switch > "$R/v69-switch.txt"; echo "exit=$?"                                       # exit=0
tail -n 1 "$R"/v69-*.txt                                   # PASS in each; no FAIL line anywhere

# V70 (V54 in D-0063; Brev running on onboarding or the lock screen; then again, with a delay, unlocked with the compose
# sheet open and a field focused when the delay ends)
printf 'V70\n' > "$R/v70.txt"
sleep 30; "$T/windows" Brev > "$R/v70-before.txt"; open -a "$APP" "$R/v70.txt"; sleep 2; "$T/windows" Brev > "$R/v70-after.txt"
ioreg -l -w 0 | grep kCGSSessionSecureInputPID              # with the sheet open: Brev's PID
diff "$R/v70-before.txt" "$R/v70-after.txt"                # no output
grep -c 'open event ignored count=1' "$R/stream.log"       # > 0

# Phase 4 (V71 to V81; docs/PHASE4_DESIGN.md §8). The relay runs in the third terminal (Setup).
id_of() {  # id_of ADDRESS: the relay's id for an address, as SQL
  printf "(select id from identities where address = '%s')" "$1"
}

# Root invites (Setup), with the relay running
for i in 1 2 3; do "$RELAY" invite --db "$RDB" > "$R/root-$i"; done
cat "$R"/root-*                                             # three lines, each brev1. and 26 characters
pbcopy < "$R/root-1"                                        # before ⌘V on Brev's address page (V71, V72); root-2 and root-3 for Brev B's later identities

# V71 (both registered)
rq "select address, invited_by is null from identities order by address"   # brev-secret-me|1, brev-secret-peer|0
rq "select (select invited_by from identities where address = '$ADDR_B') = $(id_of "$ADDR_A")"   # 1: Brev invited Brev B

# V73: the pasteboard's types while Brev is in front (types only; nothing reads the text). Start the line, switch to
# Brev, and press Kopier koden within 30 s; stay on Brev, unlocked, until the second file is written (95 s).
PBT='ObjC.import("AppKit"); JSON.stringify(ObjC.deepUnwrap($.NSPasteboard.generalPasteboard.types) || [])'
sleep 30; osascript -l JavaScript -e "$PBT" > "$R/v73-copied"; sleep 65; osascript -l JavaScript -e "$PBT" > "$R/v73-60s"
cat "$R/v73-copied"                                        # public.utf8-plain-text, org.nspasteboard.ConcealedType, org.nspasteboard.TransientType
cat "$R/v73-60s"                                           # []
osascript -l JavaScript -e "$PBT"                          # after Kopier adressen min and ⌘L: []
# V79: the change count before and after an AX press on Kopier adressen min or Kopier koden: the same number
osascript -l JavaScript -e 'ObjC.import("AppKit"); $.NSPasteboard.generalPasteboard.changeCount'

# V74 (after Legg til; again after Brev's next sync that follows Godta)
rq 'select kind from events'                               # 1 (a request); after the sync: nothing
# V75 and V81: the link from the one who declined or blocked (P) to Brev
P="$ADDR_D"                                                # V75; P="$ADDR_C" for V81
rq "select state from links where owner = $(id_of "$P") and peer = $(id_of "$ADDR_A")"   # 2
rq 'select count(*) from events'                           # 0 (V75)

# V75, V76 and V81: note the trace's length, switch to Brev, press Send, come back
n="$(wc -l < "$R/relay.log")"
tail -n +"$((n + 1))" "$R/relay.log" | grep -c '/v1/envelopes'   # 0
tail -n +"$((n + 1))" "$R/relay.log" | grep -c '/v1/lookup'      # > 0 (control: Brev asked the relay)

# V77: note the trace's length before the edited code's Fortsett on Brev B's address page; after it:
tail -n +"$((n + 1))" "$R/relay.log" | grep -cE '/v1/register|/v1/invites/redeem'   # 0
tail -n +"$((n + 1))" "$R/relay.log" | grep -c '/v1/invites/open'                   # > 0 (control)

# V76, V77, V78 and immediate delivery: the design's DoD tests by name (they also run in V45)
cargo test --manifest-path core/Cargo.toml --target-dir core/target --workspace --no-default-features -- \
  cannot_reach_an_inbox invite_with_wrong_fingerprint_is_rejected letters_are_rate_limited_per_identity_per_day \
  approved_envelope_is_delivered_on_the_next_poll 2>&1 | grep -E '^test .* \.\.\. '
                                                           # five lines, each ending "ok": unapproved_sender_cannot_reach_an_inbox,
                                                           # a_stranger_cannot_reach_an_inbox, invite_with_wrong_fingerprint_is_rejected,
                                                           # letters_are_rate_limited_per_identity_per_day, approved_envelope_is_delivered_on_the_next_poll

# V78 (pair 2, after V74): Brev's letters this UTC day, then ⌃C the relay and start it with a limit of one more
day=$(($(date +%s) / 86400))
nl="$(rq "select n from counts where kind = 1 and day = $day and identity = $(id_of "$ADDR_A")")"; nl="${nl:-0}"; echo "$nl"
"$RELAY" serve --db "$RDB" --listen 127.0.0.1:8787 --trace --letters-per-day $((nl + 1)) >> "$R/relay.log"
# (another terminal) one letter goes; before the next Send and after its compose.ratelimited:
waiting                                                     # the same number both times
rq "select n from counts where kind = 1 and day = $day and identity = $(id_of "$ADDR_A")"   # nl + 1, both times
# then ⌃C, and the relay again as in Setup, with >> instead of >

# V80 (after the run's last letter): the hex of each file on one line, then each root code's s, a and SHA-256(a)
for f in "$RD"/relay.db*; do xxd -p "$f" | tr -d '\n'; echo; done > "$R/v80-db.hex"
for i in 1 2 3; do python3 - "$(cat "$R/root-$i")" <<'EOF'
import sys, base64, hashlib
s = base64.b32decode(sys.argv[1].strip().split('.')[-1].upper() + '======')   # the secret: 26 base32 characters, 16 bytes
a = hashlib.sha256(b'brev/invite/relay\0' + s).digest()
print(s.hex(), a.hex(), hashlib.sha256(a).hexdigest())
EOF
done > "$R/v80-needles"
while read -r s a h; do echo "$(grep -c "$s" "$R/v80-db.hex") $(grep -c "$a" "$R/v80-db.hex") $(grep -c "$h" "$R/v80-db.hex")"; done < "$R/v80-needles"
                                                           # three lines "0 0 <k>", k > 0: s and a absent; SHA-256(a) found (control)
grep -c "$(printf %s "$M" | xxd -p | tr -d '\n')" "$R/v80-db.hex"   # 0: the letter marker
```

## Tools

| Tool | What it does | Rows |
|---|---|---|
| `tools/verify/build.sh` | builds the tools below into `$T` (`core/target/verify`) and the Verify build of Brev, and prints `T=` and `VAPP=`; `--tools` skips the Verify build; `--check` only type-checks (scripts/test.sh runs it) | V1, V2, V50, V53, V65 |
| `$T/capture-probe` | sets a stage (a green backdrop right behind Brev's largest window, a cyan control window with text beside it), captures through every path, saves only cuts of that stage (to `--out`, by default a new private folder under `$TMPDIR`), and judges each path: control visible, window excluded, or ink in the content panes (Brev's AX scroll areas, so Terminal needs Accessibility; or `--pane`). A pane shows content when its ink covers one glyph's area, so one line of text counts at any window size. INVALID (exit 2) when a path judged nothing: the window captured but no pane known, the panes changed during the run (a lock), or a window-level capture empty while the same method does not show the control window either. Default ScreenCaptureKit, `--legacy` CoreGraphics, `CGDisplayStream` and `AVCaptureScreenInput` (built for 14.0), `--screencapture` the `screencapture` tool; `--selftest` checks the verdict rules on drawn panes (scripts/test.sh). Expected pane text (Phase 3): the contacts pane shows the contact address marker (`$ADDR_B`, the contact's name since Phase 3), the contact header both addresses and codes (V68), the thread and letter panes one line of the letter marker's length; `--selftest` draws these (Phase 2's version drew "Ekko" and "Speil"; Phase 3's WP4 changes the tool) | V5, V6, V7, V68 |
| `$T/capture-probe-26` | one `CGDisplayStream` frame through `dlsym`, built for 26.0; `capture-probe --legacy` runs it | V7 |
| `$T/windows` | lists an app's windows with id, level, `kCGWindowSharingState`, on screen or not | V5, V9 |
| `$T/axdump` | dumps every AX attribute and parameterized attribute (the read-only ones called; never `AXReplaceRangeWithText`); `--press` sends `AXPress` and prints the `AXError` it returns; `--menus`, `--hit` | V11, V13 |
| `$T/poster` | posts synthetic keys (`key`) and clicks (`click`) in every variant of V32; the session and HID taps and `IOHIDPostEvent` need `--global` and post only while the target is in front | V32, V33 |
| `$T/keylisten` | listen-only event tap + IOHIDManager; prints only whether a key value was seen | V31 |
| `$T/padcheck` | checks every sealed column length in `brev.db`, read-only (Phase 2's version read the three stores) | V18 |
| `$RELAY` (`core/target/release/brev-relay`) | the relay (Phase 3 design §4): `serve` listens on `127.0.0.1` only, and with `--trace` prints one line per request (path and status; nothing stored); `release --db <path> <address>` frees an address and deletes its waiting letters. Phase 4 (design §4.6): `invite --db <path>` prints one root invite code and stores only `SHA-256(a)`; `serve` takes a flag for each limit (`--letters-per-day` and the others of design §4.4); `release` also deletes the identity's links, events, invites and counts | V54, V57–V60, V62–V64, V67, V71, V78, V80 |
| `TouchIDProbe.app` (`$T/touchid-probe/Build/Products/Release/`) | runs Brev's unlock closure (`UnlockService`) with a real Enclave KEK and scans for the DEK and ECIES needles; `--dry` stops before the prompt. Also built against a copy of brev-core with the unlock's deep scrub disabled (`$T/touchid-probe-scrub0/…`, the negative control) and at 128 KiB (`$T/touchid-probe-scrub128/…`); each prints its `scrub=` depth | V51 |
| `$T/InputLab.app`, `tools/verify/spikes/` | the GUI-spike lab and the spikes' sources (design §14.2); the rogue-Brev and anchor probes were dropped with D-0035 | – |
| `tools/viewhost` (`tools/viewhost/build.sh` prints its path) | Brev's mail window, compose sheet, lock sequence and lock triggers with fake letters and a software KEK (no keychain, no Touch ID), and in-process checks of them; SelfScan compiled in, as in the Verify build. Phase 4's WP5 extends `--contacts` to the new contact screen (V69) | V69, V79 |
| `app/Tests/Lock` (the lock probe; scripts/test.sh builds and runs it) | a CLI without a window on screen: a synthetic key that `BrevApplication` drops, in `sendEvent` and posted to the probe itself through `nextEvent`, does not move the idle clock (the drop log is the control; the posted part is skipped if the process may not post events), a discarded unlock and the lock sequence lock the Rust session, the lock sequence zeroes every content view's pixel buffers, `draw(_:)` of a content view draws nothing, `UnlockService` locks Rust when its closure fails after `Brev.unlock` | V45 |

## Coverage

The Phase 2 tables name V39 and V42 as Phase 2 ran them. From Phase 3 on,
V65 covers what V39 covered (it sends and reads a marker letter in the
scanned process, as V39 did), and V57 what V42 covered, except the echo
contacts, which Phase 3 removes.

CLAUDE.md §5, Phase 2:

| §5 line | Rows |
|---|---|
| Onboarding explains "no backup, Touch ID only" and fingerprint changes, in Norwegian | V36 |
| Onboarding creates Enclave keys and wraps a fresh DEK | V40, V37, V27 |
| Unlock screen → Touch ID → `core.unlock(dek)` | V26, V27, V47, V48, V51, V45 (lock probe) |
| Three-pane window; content panes use `SecureTextView` | V42, V10, V11 |
| Compose: secure event input | V30, V31 |
| Compose: synthetic event rejection | V32, V33, V13 |
| Compose: no pasteboard | V14, V16 |
| Compose: no autocorrect, `writingToolsBehavior = .none` | V34 |
| Window capture exclusion | V4–V9 |
| Auto-lock | V22–V25, V69 |
| Blank-on-lock | V46, V22, V39, V45 (lock probe), V69 |
| Two hard-coded contacts through `MockTransport` | V42 |
| Stored content padded (schema v2) | V18, V45 |
| Checklist: screenshot (⇧⌘4) shows black or empty content | V4, V5–V8 |
| Checklist: Accessibility Inspector shows no text for content views | V10, V11, V12 |
| Checklist: ⌘C does nothing; no Edit menu with Copy/Paste | V14, V15 |
| Checklist: `strings` on the SQLite file finds no message text | V17 |
| Checklist: AppleScript `tell application "Brev" to …` fails | V3 |
| Checklist: switching to another app locks Brev | V22 |
| Definition of done: sandboxed + hardened | V1, V2 |

New mechanisms in the design:

| Mechanism (design §) | Rows |
|---|---|
| UniFFI surface without content `String`s, and pinned whole: every export and every converter use listed in `scripts/ffi-surface.txt`; 960-byte `OpenText` chunks (§2.2) | V45 |
| `OpenText` registry; lock closes open texts (§2.4) | V45, V39 |
| `unlock` drop guard, poison handling, 64 KiB scrub (§2.3, §2.5), which reaches the peer DEKs' copies (`unlock_all` not inlined) | V45, V51 |
| Zeroing allocator (§2.6) | V45, V39 |
| Echo peers, HKDF peer DEKs, `sync` (§2.7, §9) | V42, V17, V18, V45 |
| Stored padding, schema v2 (§2.8, §2.9) | V18, V45 |
| Binding patches and the uniffi pin (§3) | V45 |
| `SecretBytes`, `SecretText`, CTLine-only layout, `GlyphFlush` (§6) | V45, V39, V69 |
| `MallocScribble` through `LSEnvironment` (§6.4) | V2, V49, V39 |
| Keys and the wrapped DEK in the keychain, no key file, 0600/0700, backup exclusion (§5.1 as changed by D-0035) | V1, V40, V41 |
| Install atomicity and known-name cleanup (§2.10, §5.2, §5.3) | V37 |
| Instance lock (§5.2) | V29 |
| Unlock: one prompt, no prompt without a human, the post-unlock rule (§4.3, §5.4); a discarded or failed unlock locks Rust | V26, V27, V47, V45 (lock probe) |
| Error mapping, `biometry.state`, reset, `ConfirmSheet` (§5.5) | V38, V48, V9, V13 |
| `OpaqueView` (§7.1) | V10, V11, V12, V15, V16, V69 |
| `HumanButton` (§7.1) | V13, V33 |
| `SecureTextView`, `SecureListView`, `LetterStackView`, sync timer (§7.2) | V42, V10 |
| Compose by `keyDown` + `UCKeyTranslate`, no `NSTextInputClient`, inert ⌘ keys (§7.3) | V35, V34, V14 |
| `SecureInput` (§7.3) | V30, V31, V46, V69 |
| `Hardening.apply` on every window; not minimisable, no tabbing, not restorable (§8.1); no AppKit alert from an open-documents event | V9, V43, V41, V69, V70 |
| Capture exclusion and the second defence (§8.2) | V4–V8, V69 |
| Lock triggers, own idle clock, common-mode timers (§8.3); dropped input does not move the idle clock | V22–V25, V69, V45 (lock probe) |
| Lock sequence (§8.4), including the Rust lock (step 5) and the pixel buffers | V46, V39, V19, V45 (lock probe), V69 |
| Menus Brev and Arkiv (§8.5) | V15, V13 |
| Plist and no scripting (§8.5) | V2, V3 |
| Synthetic-input filter in `sendEvent` and `nextEvent` (§8.5) | V32, V33, V45, V69 |
| Launch hygiene (§8.6) | V28, V49 |
| Verify configuration and `SelfScan` (§4.1) | V39, V50 |
| Replaced stores do not unlock (§2, D-0035) | V52 |
| FFI surface check, forbidden-API grep, Swift harness (§11) | V45 |

CLAUDE.md §5, Phase 3 (`docs/PHASE3_DESIGN.md` §1.1). V45 includes the Rust
tests of design §8, the relay tests of §4.6 and harness case 8, the network
round trip (case 7 is the scribble probe):

| §5 line | Rows |
|---|---|
| `brev-relay`: register an address, look up an address, submit, poll | V55, V57, V45 |
| Relay stores only ciphertext and routing metadata; deletes envelopes after delivery | V58, V59, V45 |
| `RelayTransport`: HTTP, polling every N seconds, no websockets | V57, V54, V63, V64 |
| Envelope signatures from the Secure Enclave with Touch ID; the relay and brev-core verify them | V55, V56, V26, V45 |
| Payload padding to the buckets; 1 MiB maximum in app and relay | V18, V45 |
| Contacts by address; the relay returns the keys; TOFU pin; warning and no sending on a changed key | V57, V60, V45 |
| Identity code shown per contact; comparing is optional | V61, V60, V68 |
| Definition of done: two app instances exchange letters through a local relay | V57 |
| Definition of done: the relay DB contains no plaintext (tested) | V58, V45 |
| Definition of done: a changed key triggers the warning and blocks sending (tested) | V60, V45 |

New mechanisms in the Phase 3 design:

| Mechanism (design §) | Rows |
|---|---|
| `network.client`, never `network.server`; no ATS key; `URLSession` forbidden (§5.5) | V1, V53, V66 |
| `127.0.0.1` only: brev-core's URL rule and the relay's `--listen` rule (§4.5, §5.1) | V54, V45 |
| No request while locked; no network under the session mutex (§5.2, §5.3) | V64, V62, V45 |
| One Touch ID per letter, none to retry; the send prompt keeps auto-lock (§3.2, §3.5), or with U4's switch on blanks the content and locks at the prompt's end unless Brev is active | V56, V63, V62, V26, V45 (lock probe, both positions) |
| Address page and registration after the first unlock; address rules (§3.2, §6.5, Q3) | V55, V67, V69 (contacts mode), V45 (harness: the address charset; lock probe: wiped on lock) |
| Schema v3: one store, sealed addresses and `pending` (§6.1) | V17, V18, V40, V41 |
| Contact data drawn only in the protected layer; addresses in no log or crash report and gone on lock (§6.4) | V68, V17, V19, V20, V46, V69 (contacts mode), V45 (lock probe) |
| New sheets and buttons: `AddContactSheet`, contact header, accept `ConfirmSheet` (§6.5) | V67, V60, V68, V69 (contacts mode) |
| Heap residue with letters to and from the network (the draft and `sign_request`'s UTF-8 copies, §3.2) | V65 |
| Two instances by bundle id (§7) | V57 |
| Echo peers removed (§1.2) | V17, V41 |

CLAUDE.md §5, Phase 4 (`docs/PHASE4_DESIGN.md` §1.1 and the owner's
answers). V45 includes the Rust tests of design §8 and harness case 9, the
invite round trip:

| §5 line | Rows |
|---|---|
| Letters only from approved contacts | V76, V74, V75, V45 |
| One request otherwise, with no text; approved or declined with one click | V74, V75, V79, V69 |
| The requester is not told about a decline | V75, V45 |
| *Blokker*: one click undoes an approval | V81, V79, V69, V45 |
| Invite codes: one-time text codes with the inviter's address and fingerprint | V71, V77, V80, V45 |
| Redeeming makes both approved contacts, the inviter's key verified | V71, V77, V45 |
| A new identity needs an invite to register; the relay tracks the invite graph | V71, V45 |
| Creating an invite: one human click, no Touch ID | V71, V79 |
| Codes are text, never links; copy and paste of addresses and codes only on the contact screen | V73, V72, V14, V15, V66, V69 |
| Rate limits per identity and day, enforced by the relay | V78, V45 |
| Delivery on the next poll, nothing held (D-0030) | V74, V45 |
| App Attest stub behind a feature flag; `IdentityVerifier` with `DevVerifier` | V45 (relay test 11) |
| Definition of done: an unapproved sender cannot reach an inbox | V76 |
| Definition of done: a code whose fingerprint does not match is rejected | V77 |
| Definition of done: rate limits and immediate delivery in relay tests | V78, V45 |

New mechanisms in the Phase 4 design:

| Mechanism (design §) | Rows |
|---|---|
| Invite code text, base32 decoding, `a` and the tag (§3.1) | V45, V77, V80 |
| Registration v2 and its check order, no directory probe (§3.2, §4.3) | V71, V45 |
| Both directions of a code's check; forged *invited* events dropped (§3.4) | V71, V77, V45 |
| Submit carries the sender's token (§3.2, §4.3) | V45 |
| Relay schema v2: links, events, invites, counts; no `s` or `a` in the file (§4.2) | V80, V71, V74, V75, V81, V45 |
| Uniform 202 for requests, the pending cap, events in kind order (§4.3, §4.4) | V45 |
| Mail schema v5: sealed flags and local invites; requests and opened invites only in the session (§5.1) | V45 |
| Contact states «Venter på svar» and «Bekreftet med invitasjon» (§5.2) | V74, V75, V71 |
| `ContactSheet`, `ContactField`, the address page's invite step, the requests section, the header's buttons (§6.1) | V71, V74, V75, V81, V79, V69 |
| `ContactPasteboard`: two writers, Concealed and Transient types, the self-clear, reads only in `ContactField` (§6.2) | V73, V72, V66, V14, V69 |
| `pasteboardDisabled` at *Send* (§5.5) | V73, V69 |
| FFI additions and the four new errors (§5.4) | V45 |
| App Attest stub and `IdentityVerifier` (§7) | V45 |

## Order of a run

The order below is Phase 3's run. V26 holds for the whole run.

1. Before any launch: V1, V2 and V53 (both builds), V66, V45, V50, V69, the
   `sdef` half of V3, the binary half of V21. Build the relay and Brev B,
   start the relay with its trace (Setup), and check `/v1/health`. Start the
   V19 stream and check that it writes.
2. With no `$D` (first run or after a reset): V51 with `TouchIDProbe.app`
   (it uses Brev's own keychain names, so it runs only while Brev is not
   installed, and deletes them again), V36, V29, V37, then onboarding to the
   end (the first unlock is V27's one prompt with no password button), V40,
   V41. On the address page: V46's part for the page, V67's parts for the
   page and *Registrer* (with `$ADDR_A` typed), then V55 with `$ADDR_A`.
   Then Brev B, also with no `$DB`: onboarding and `$ADDR_B` (its dialogs
   say «Brev B», V57).
3. Launches, with Brev quit before each: V28 (delete the global default at
   once), V49, V26's launch part, the `osascript` half of V3. On the lock
   screen: V27's *Avbryt*, V43, the first half of V70, V48's lockout part.
4. Unlocked: V67's parts for `AddContactSheet` and *Legg til* (with
   `$ADDR_B` typed), then Brev adds `$ADDR_B` and Brev B adds `$ADDR_A`. Marker letters both ways: V57,
   with V58's first part while a letter waits, V59, V58's second part, V61,
   V56. Then the capture, accessibility (V13 on *Send* and *Lås opp med
   Touch ID*), V68, input (with V70's compose half), pasteboard, disk, log
   and lock rows, V46, V47, V54, V64, V62, V63, and V44 last. Grant Terminal
   Accessibility before the capture rows: `capture-probe` finds Brev's panes
   through it.
5. With Brev quit after V44's relaunch: V17 and V41 again, so that what the
   lock, discard and quit paths wrote is scanned. Then V65: Brev B sends
   Brev a new marker letter; then, on the Verify build, write and send a
   marker letter to Brev B, open Brev B's letter, and lock with it open.
6. Destructive rows last: V20, then V17 and V41 again (the crash path). V60
   on Brev B, with V67's parts for *Godta ny kode* and the accept
   `ConfirmSheet` before a human presses them (Brev's store must still be
   whole, so V60 comes before V38). Copy `$D` aside (V52 needs it, and it
   restores the install if a V13 press gets through). V38, with V9's
   `ConfirmSheet` part and V13's presses on *Slett alt og start på nytt* and
   `ConfirmSheet`'s *Slett alt* before a human presses either. V52. Then
   V48's fingerprint step as the very last (it also makes Brev B's keys
   unusable).

### Order of a run (Phase 4)

Phase 4's WP6 runs after Phase 3's run is signed off (owner answer 1),
with no `$D`, no `$DB` and an empty relay: Phase 4 refuses Phase 3's
stores and relay file (design §1.2). V26 holds for the whole run. The rows
need three pairs of identities that the relay has not linked yet. An invite
links a pair when the invitee registers (V71). A pair's request can be
answered only once: after *Godta* or *Avslå*, the requester keeps its row
(adding again is `contact.error.duplicate`), and a request the other way is
approved at once, with no click (design §4.3). So Brev onboards once and
Brev B three times, reset by V38's method on `$DB` between pairs, each time
with a new address. The design (§9, WP6) counted two onboardings.

A code stays shown only while Brev stays unlocked, and a `pbcopy` in
Terminal replaces it on the pasteboard, so pair 1 brings Brev B to its
address page before Brev makes the code.

1. Before any launch: V45 (and the tests of V76, V77 and V78 by name), V66,
   V69, and V1, V2 and V53 on the new builds. Build the relay and Brev B,
   start the relay empty with its trace (Setup), mint `root-1` to `root-3`,
   and start the V19 stream.
2. Pair 1, by invite. Brev's onboarding; on the address page V72 (the first
   ⌘V, with `root-1`), V79's press on *Fortsett*, then the rest of V71's
   first half; then V14. Brev B's
   onboarding, up to its address page. Back in Brev, *Kontakter*: V79's
   presses on *Kopier adressen min* and *Lag invitasjon*, then
   *Lag invitasjon* (the code V71 uses); with the code shown, V79's press on
   *Kopier koden*, its AX dump and capture, and V73's first part (Brev stays
   in front and unlocked, so the code stays shown). Then *Kopier koden* once
   more, and in Brev B: V77, then V71's second half with `$ADDR_B`, and a
   marker letter each way (V73's letter part in Brev). Then V73's lock
   part.
3. Pair 2, by request. Reset Brev B; its onboarding registers `$ADDR_C` with
   `root-2`. In Brev, V79's press on *Legg til* with `$ADDR_C` typed, then
   V74 up to the request. Before Brev B answers: V76's app half, and in
   Brev B V79's presses on *Godta* and *Avslå* and its AX dump and capture
   with the request selected. Then the rest of V74, V78, V79's *Blokker*
   press, and V81.
4. Pair 3, the decline. Reset Brev B; its onboarding registers `$ADDR_D`
   with `root-3`. V75.
5. Last: V80, and V15 if P1 took variant (b).

## Failures and results

A row passes only as written. A failed row is fixed and run again, or it gets
a D-entry that the owner accepts. Never reword a failure as residual risk
without the owner (design §14.2). Where a row or its spike item says "stop and
ask the owner" (V31; V32 and V33 if a posted event gets through; V4–V8 on a
capture leak), that area stops until the owner answers.

Results go to D-0053: the macOS build, the commit, and for each row pass,
fail, or the D-entry that accepts it. `docs/VERIFY-RESULTS.md` holds the
machine-run part (WP4). Phase 3's results go to the Phase 3 design's D-0053
(renumbered after Phase 2's entries, design §10) in the same form. Phase 4's
go to the Phase 4 design's D-0080 (its §10: numbered after Phase 3's WP6
entries), in the same form.

One open item was not a row: on a Mac that holds Brev's team signing key,
any same-user process can sign itself into Brev's App ID and keychain group
(CLAUDE.md §2; D-0062). This Mac holds that key. The owner accepted it on
2026-09-28 while Brev holds only test letters (CLAUDE.md §2, commit
`1aeccc5`); real letters go only on a Mac without that key. D-0053 records
it.

## Changes from the design

- V39 and design §8.4 step 9: `SelfScan` logs
  `selfscan u8=<n> u16=<n> glyph=<n> scribble=<n> probe=<n>`. The design
  meant `glyph` to show whether `MallocScribble` and `GlyphFlush` work in
  the real app. Review round 1 found that it cannot for a typed letter: in
  the view host with Brev's views, a one-line marker letter left no glyph
  ids after the lock even with both switched off, because libmalloc zeroes
  freed blocks of 1 KiB or less itself (spike M); only long lines left any
  without scribbling (a 4 KiB letter left 55). After the lock, `glyph`
  shows that `GlyphFlush` cleared the control's line of the marker. The
  scribble probe (`scan.c`) does not depend on Core Text: `scribble` is 0
  only if a freed 32 KiB block is overwritten in this process, and harness
  case 7 (V45) shows that the same probe finds the block kept without
  scribbling. So the evidence for scribbling in the real app is `scribble`
  (with V49 for the variable), not `glyph`.
- V39's control (WP7): content views draw each line into pixel buffers of
  their own (`ContentView`; since WP11 the protected layer's, D-0034) and
  AppKit's `draw(_:)` gets nothing, because AppKit's display list kept the
  glyph ids of drawn lines until after the lock. So no
  glyph id of a shown letter stays live, and the design's control
  "glyph > 0 while the letter is open" can never pass: `glyph` is 0 at the
  start of the lock too. `SelfScan`'s control line adds `needle`, the glyph
  count while it holds a CTLine of the marker in the same font, which proves
  that the needle is set and seen in the process; the lock sequence clears
  that line like any other. `tools/viewhost --scan` runs the same control and
  the real lock sequence. D-0045 and D-0052 record this (the design's D-0044
  and D-0057).
- V21: the design's `mdfind BREV-SECRET-BODY` finds this repo's own docs, so
  the row could never pass. It now ignores the checkout, has a control, and
  checks the binary for the Spotlight donation APIs.
- V13: the design's "the log shows no send, unlock or reset" names log lines
  that nothing writes. The evidence is the state of `$D`, the `AXError`, and
  a human who sees no Touch ID prompt.
- V7 (WP11, D-0034): on macOS 26.2 `CGDisplayStream` (also through
  `dlsym` from a binary built for 26.0) and `AVCaptureScreenInput` capture a
  `sharingType = .none` window, also at Brev's window level 0 (capture spike,
  re-run in WP11). V7 adds them. Content views draw into an
  `AVSampleBufferDisplayLayer` with `preventsCapture = true`, which all
  capture paths leave empty. `tools/viewhost --control` with `--capturable`
  and `--unprotected` runs the same matrix against the real views, with a
  negative control that shows the letters.
- Keys in the keychain (D-0035, WP5): there are no key files and no
  `dek.hpke`. V1 expects the team signature and the keychain access group, and V2
  the embedded provisioning profile;
  V38 damages the stores instead of moving `kek.se`; V40 and V41 list the
  files that remain; V51 uses the ECIES secrets; V52, which depended on the
  dropped anchor (WP9), now checks that stores put back from an older
  install do not unlock. This binding holds on a Mac that does not hold
  Brev's team signing key; on one that does, any same-user process can sign
  itself into Brev's App ID and keychain group (CLAUDE.md §2, D-0062), and
  V52 says nothing about that.
- Tools (WP4): the tools are built into `core/target/verify` (`$T`), not
  next to their sources; the rows and commands name them there. The
  rogue-Brev app and the anchor probe are not built: the keys are keychain
  items bound to Brev's signing identity (D-0035), so the rogue test (R) and
  the anchor (A, WP9) no longer apply, on a Mac that does not hold Brev's
  team signing key (on one that does, see D-0062). V51 moves to run order step 2,
  because `TouchIDProbe.app` has to use Brev's own keychain names to run the
  unchanged `UnlockService` closure. `capture-probe` judges each path itself
  (control visible; window excluded or content panes without ink), with a
  negative control run in `docs/VERIFY-RESULTS.md`. Every A part that needs
  Brev unlocked starts with a delay, because Terminal in front locks Brev.
- WP4 review: `capture-probe` judges a pane by the area of its ink (one
  glyph), not by its share of the pane, which let one line of text pass in
  a large window; a captured window with no known pane, panes that change
  during the run, and an empty window-level capture without its control are
  INVALID instead of pass. Its negative control was run again with one-line
  letters at the default width and in a window that fills the screen
  (`docs/VERIFY-RESULTS.md`). V51 gets K's two other depths as separate
  builds (`build.sh`): the negative control with the scrub disabled, and
  128 KiB for a failure at 64 KiB.
- Review round 1 (2026-09-28, D-0063): V39 gets the scribble probe (above).
  V41 names the files that remain after D-0035 instead of design §5.1's
  table. V43 expects a disabled minimise button: a titled window without
  `.miniaturizable` still shows it, greyed out (V11 saw `AXEnabled = 0`).
  V51 adds needles for the echo peers' DEKs. V69 (V53 in D-0063) makes the
  view host's checks a row: they are the only ones of the protected layer,
  the pixel buffers and the Rust lock that run the real views in a window.
  The lock probe in scripts/test.sh (V45) covers the Rust lock, the pixel
  buffers and `draw(_:)` without a window. V70 (V54 in D-0063) checks the
  open-documents event, which made AppKit show an unhardened alert in Brev.
- Review round 2 (2026-09-28, D-0064): V28 also sets `TSMEventTracing`,
  which LaunchGuard now refuses: the launch spike found it to be the one
  key-event trace that works without get-task-allow, and the design's list
  had only AppKit's and Foundation's keys. The lock probe (V45) checks that
  dropped synthetic input does not move Brev's idle clock; before, only the
  view host's `--triggers idle --post` run did, which no row requires. The
  FFI surface check (V45) pins every export and every converter use, not
  only the `String` and `Data` ones.

### Phase 3 (`docs/PHASE3_DESIGN.md` §8)

The rows follow the design's list and table. Where they say more than the
design, it is here:

- Address markers: the design names "a contact address marker". The setup
  fixes two, `$ADDR_A` for Brev and `$ADDR_B` for Brev B, both valid under
  the address rules. V17 also searches for Brev's own address, which Brev
  seals like the contact's (design §6.1, §6.4). Addresses are content that
  is wiped on lock (design §6.4), so V19 and V20 also search the logs and
  the crash report for both, and V46 also locks with an address typed in
  `AddContactSheet` and on the address page.
- Setup: every full run starts with an empty relay (its folder moved
  aside) and a Brev B with no `$DB`. Addresses are permanent and waiting
  letters never expire, so an old relay would refuse `$ADDR_A` in V55.
- V26 adds *Prøv igjen* to the actions that never prompt (design §3.5:
  retrying a submit costs no Touch ID).
- V54 also checks that Brev B listens nowhere, and has a control: at least
  one connection, so an empty list cannot pass.
- V56 checks that the send dialog has no password button, as V27 and V55
  do: its `LAContext` has `localizedFallbackTitle = ""` (design §3.2
  step 2).
- V58 also runs while a marker letter waits at the relay. After V57 the
  envelope is already deleted, so only that run has ciphertext in the file.
- V60: Brev B adds Brev again before the last letter, because letters from
  people not added are dropped (Q2; design §6.3 and its test 3). *Send*
  shows no Touch ID dialog, because `prepare_send` refuses before anything
  is signed (design §3.2 step 0).
- V63: *Prøv igjen* appears only when the relay fails after signing (design
  §6.5), so the row stops the relay while the send dialog is up, with a
  timed command. Both parts count only the lines written after a noted line
  count: the trace has no restart line.
- V64 names Brev B too (with two instances, "no line" holds only when both
  are locked) and has two controls: `/v1/inbox` lines, and a `/v1/health`
  request right after the quiet minute that adds one line, so a relay that
  stopped, or stopped tracing, cannot pass.
- V65 keeps V39's send half: the Verify build also writes and sends a
  marker letter, so the compose sheet, the draft kept through the Touch ID
  prompt and `sign_request`'s UTF-8 copies (design §3.2 step 1) are in the
  process `SelfScan` scans. The design names only the letter from Brev B.
  `SelfScan` counts the letter marker only; address needles would be a
  change to the tool.
- V67 is marked "A (H opens and looks)", as V9 and V13 are: a human opens
  the page and sheets and watches for a Touch ID dialog. It also presses the
  accept `ConfirmSheet`'s *Godta* through AX, since pressing both buttons
  would accept a new key. Its V13 part also checks the relay trace (no
  `/v1/register` or `/v1/lookup`) and the window list (no new sheet), and
  types a valid address before *Registrer* and *Legg til*: with an empty
  field, a press that got through would end in an address error with no
  dialog, request or write.
- V68 judges the contact header by giving its frame to `capture-probe` as a
  `--pane`, since the probe finds only scroll areas by itself. The protected
  view has no AX element, so the frame comes from the labels and scroll
  areas around it. A second `--pane` over a label is the control that the
  rects are right, and the V19 stream shows that Brev did not lock during
  the run, because `--pane` turns off the probe's re-read of the panes.
- `capture-probe --selftest` also draws the contact header's two addresses
  and codes (Tools); the design names only the contacts pane's text.
- The "Depends on" column names Q4 and U4 (WP5) (Legend). V54 carries Q4
  too: under Q4's fallback its `lsof` sees the other user's Brev B only with
  `sudo`. Q1 (B) also changes who runs the relay, so V63's stop and restart
  change with it (Setup).
- V52 is not in the design's list, but its "three stores" no longer exist:
  it now copies the stores that are there (`brev.db` since Phase 3).
- Phase 2's review round 1 (D-0063) reached this branch after these rows
  were written. V65 logs and checks V39's scribble probe
  (`scribble=0 probe=<n>`). V41 keeps the round's list of files by name,
  now `brev.db` only. V51 drops the round's needles for the echo peers'
  DEKs with the echo peers: Phase 3's unlock derives no key from the DEK.
  The round's two new rows are V69 and V70, because V53 and V54 were taken.
- Phase 2's review round 2 (D-0064) and WP12's entries (D-0036 to D-0053)
  reached this branch after these rows were written. V28 and the lock
  probe (V45) take the round's changes as they are. The FFI surface check
  (V45) pins Phase 3's surface: `scripts/ffi-surface.txt` lists its exports
  and converter uses. D-0053 and the Phase 2 summary name V69 and V70 V53
  and V54, as D-0063 does.

### Phase 4 (`docs/PHASE4_DESIGN.md` §8)

The rows follow the design's list and table, with the owner's answers at
the end of the design. Where they say more than the design, it is here:

- V81 is new: owner answer 6 adds *Blokker*. Its button is also in V79 and
  V69.
- Order of a run (Phase 4): three pairs of identities, so Brev B onboards
  three times and two more address markers exist (`$ADDR_C`, `$ADDR_D`).
  With the design's two onboardings, V71, V74 and V75 cannot all run.
- V76: Brev never sends a stranger's envelope. `prepare_send` stops at the
  lookup's status with `NotApproved`, before any digest (design §5.3), so
  the run's trace can show no 409 from Brev. The row checks that the trace
  has no `/v1/envelopes` line, and takes the 409 from relay test 5 and from
  brev-mail test 4, whose forced submit goes over HTTP to a relay on
  127.0.0.1.
- V75: the design's "A's new request does not appear at B" has no path in
  the app. After the decline, Brev keeps its row («Venter på svar», design
  §5.2), and adding the same address again ends in Phase 3's
  `contact.error.duplicate` before any request. The row checks that, and
  the relay's `links` and `events`; relay test 6 covers a declined
  requester's later requests.
- V71, V74, V75 and V81 also read the relay's file (`rq`, read-only, as
  `waiting` does): `invited_by`, `events` and `links`.
- V77 says which character to change: the fingerprint's last one, with the
  arrow keys in `ContactField`. The secret stays right, so the relay
  answers; a changed secret would give `invite.error.invalid` instead.
- V78 sets the limit to one more than Brev's letters that UTC day, not to
  2: earlier rows have sent letters by then, and the count is per day.
- V80 uses the root codes, which the operator's command writes to `$R`: a
  code Brev makes reaches a CLI only through the pasteboard. The design's
  "harness's byte scan" is this `xxd` and `grep` scan, with its positive
  control.
- V79 leaves *Godta invitasjonen* to V69, because the run redeems no code
  while registered. It also checks the pasteboard's change count after the
  presses on *Kopier …*.
- V14 gets a positive control: ⌘V in `ContactField` inserts `pb-control`.
- V73 checks that ⌘L does not clear the pasteboard and ⌘Q does (the
  owner's rule of 2026-09-29, Legend "self-clear (WP5)"), and
  `pasteboardDisabled` at *Send* through the letter going out in class A.
