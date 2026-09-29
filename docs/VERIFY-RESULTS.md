# Brev — verification: machine-run results

The rows of `docs/VERIFY.md` that a machine could run with nobody at the
Mac. Two runs are recorded here: the Phase 3 branch after the vault split
(below, D-0066 to D-0068), and Phase 2's WP4 run, which D-0053 records with
WP12's re-run of V1, V2, V3 (`sdef`), V21, V45, V50 and V69 at `fb6f140`.
The run of the whole checklist with a human is still to come; this file
does not replace it.

## Owner run, round 1 (2026-09-29, `1d368cb`)

Environment: ProductName:		macOS; ProductVersion:		26.2; BuildVersion:		25C56; Xcode 26.2; Build version 17C52; 1d368cb. Brev and Brev B built with `scripts/build.sh` and `--instance b`; relay started with `scripts/relay.sh --trace` on a fresh folder; four root invites made with `brev-relay invite`. The owner did the Touch ID and screen steps; Claude read the relay trace, `relay.db` and the unified log.

| Row | Result | What was seen |
|---|---|---|
| V27 | pass | Onboarding og opplåsing: én Touch ID-dialog, navnet «Brev», ingen passordknapp. |
| U4 | info | Touch ID-panelet tar fokus ved opplåsing (logg: "resign active during Touch ID (unlock)"); Brev låser seg ikke, opplåsing lykkes. Ved signering (registrering): ingen slik linje. |
| V72 | pass | ⌘V av invitasjonskoden: ingen varsel fra macOS om utklippstavlen (variant a beholdes). |
| V55 | pass | Registrering av brev-secret-me: én dialog, ingen passordknapp; relay: /v1/invites/open 200, /v1/register 201. |
| V71 | pass | Invitasjon Brev -> Brev B: «Lag invitasjon» uten Touch ID, kopiert, limt inn i Brev B (invite checked root=false), Brev B registrert (brev-secret-peer); relay: /v1/invites 201, /v1/invites/open 200, /v1/register 201, /v1/events/answer 204; links=2 (begge veier godkjent). V77 (feil fingeravtrykk) ikke kjørt. |
| V56 | pass | Send: én Touch ID-dialog per brev, ingen passordknapp (eierens observasjon); relay: 2 x /v1/envelopes 202. |
| V57 | pass | Brev -> Brev B og Brev B -> Brev kom fram (sync arrived=1 i begge); eieren ser brevene i innboksen. |
| V58 | pass | relay.db: 0 treff på BREV-SECRET-BODY (UTF-8 og UTF-16) mens et brev ventet; kontroll: adressen brev-secret-peer funnet 2 ganger. |
| V59 | pass | Etter at begge har synket: 0 brev venter i relay.db (slettet etter levering). |
| V81 | pass | Blokker i Brev B: ett klikk, ingen Touch ID; relay /v1/block 204; Brev sin Send gir NotApproved uten Touch ID-dialog, ingen ny /v1/envelopes (fortsatt 2). Eieren bekrefter at Brev B heller ikke kan skrive. |

Not run in round 1: V77 (tampered invite fingerprint), V60 (key change, part of Phase 3's definition of done), and every round-2 row in `docs/USER_SESSION.md`.

## Phase 3 branch after the vault split (`60d4e1b`)

### The run

- 2026-09-28, 17:05 to 17:30. macOS 26.2 (25C56), Xcode 26.2 (17C52),
  Apple silicon (arm64), rustc 1.91.1. Nobody at the Mac.
- App code under test: `60d4e1b` (branch `claude/phase3`: Phase 3 WP0 to
  WP5 and the vault split, steps 1 to 3).
- `$APP`: the Release build from `scripts/build.sh` (exit 0). `$VAPP`: the
  Verify build from `tools/verify/build.sh` (exit 0), which also built the
  tools into `$T` (`core/target/verify`).
- Brev is not installed on this Mac (no wrapped-DEK item), so every launch
  showed onboarding (`route onboarding`), and no launch opened a store.
  Launches used `open`, as in VERIFY's setup, with
  `log stream --level debug --predicate 'process == "Brev"'` running the
  whole time; each launch was ended with SIGTERM (no new `Brev*` report in
  `~/Library/Logs/DiagnosticReports` afterwards, and no Brev, view host or
  relay process left).

What the run did not do, and why:

- No Touch ID, password, keychain or permission prompt, and no reads in
  Brev's container (`$D`), as in the WP4 run below. So every row that needs
  a store, an unlocked Brev, a letter, the compose sheet, Brev B or the
  relay with letters waits for the human run.
- No `capture-probe` against Brev: without a letter it can only judge the
  onboarding window (WP4 did that), and ScreenCaptureKit can bring up the
  system's periodic screen-recording reminder, which would sit on screen
  with nobody there. The protected layer was checked in-process by V69.
- No `osascript` (Automation prompt), no `defaults write -g`, no crash.
- Before the launch rows, the permissions of this session's responsible
  app were read with the preflight calls, which never prompt: screen capture,
  Accessibility, posting and listening to events were all granted, so
  `axdump` and `windows` ran without a prompt.

### Rows

| # | What ran | Result | Status |
|---|---|---|---|
| V1 | `codesign -dv`, `codesign -d --entitlements - --xml` and `codesign --verify --strict` on `$APP` and `$VAPP` | both: `flags=0x10000(runtime)`, `TeamIdentifier=AV26DNQ5SC`; entitlements exactly `app-sandbox`, `network.client`, `keychain-access-groups` = [`AV26DNQ5SC.no.brev.app`], `com.apple.application-identifier`, `com.apple.developer.team-identifier`; no `get-task-allow`; signatures valid | pass |
| V2 | the V2 commands on `$APP` and `$VAPP` | both: 0 forbidden plist keys; `NSPrincipalClass` = `BrevApplication`; `LSEnvironment.MallocScribble` = `1`; no nested bundle of any listed kind; `Contents` = `_CodeSignature embedded.provisionprofile Info.plist MacOS PkgInfo Resources` | pass |
| V3 | `sdef "$APP"` | `couldn't get sdef … (error -192)`, exit 1 | partial: the `osascript` half waits for the human run |
| V9 | `$T/windows Brev` on onboarding | the onboarding window: `kCGWindowSharingState=0`. The same 4 off-screen menu-bar windows (1512×33) with state 1 as in WP4; `windows` exits 1 | **fails as written**, as before (D-0053); the sheet parts wait for the human run |
| V11 | `$T/axdump Brev` on onboarding | 526 lines; marker 0; `AXTitle = "Brev"` found (control); only interface text: the welcome title and body, *Fortsett*, the menus Brev and Arkiv | partial: no letter |
| V13 | `$T/axdump Brev --press Fortsett` | `AXError=0`; a second dump still shows «Velkommen til Brev» and not «Dette må du vite»: the press did nothing | partial: *Send* and *Lås opp med Touch ID* need an install |
| V19 | the log stream from before the first launch, and `log show --info --debug` from the run's start, for `process == "Brev"` | 10 649 and 1 502 lines; the marker 0 times as UTF-8 and as UTF-16LE in each; `lock reason=` 3 times in each (control) | partial: no letter or address was ever written |
| V21 | the V21 commands | binary half: `otool -L` finds no CoreSpotlight; `nm -u` finds 0 `CSSearchable…`/`NSUserActivity` of 712 undefined symbols. Search half: `mdutil -s /` says "Index is read-only." (WP4 saw "Indexing enabled."; the same with the command sandbox off). `mdfind BREV-SECRET-BODY` finds 18 files, all in the main checkout `/Users/andypandy/BREV` (the same repository: docs, tests, tools), and none elsewhere. This run's checkout is a worktree under `/private/tmp`, which Spotlight does not index, so its own `docs/VERIFY.md` (the control) is not found | partial: the binary half passes; the search half's control ("indexing is enabled") is not met, so it waits for the human run from the main checkout |
| V22 | Brev in front on onboarding, then `open -b com.apple.finder` | Finder in front; one new log line, `lock reason=resignActive` | partial: the row asks for ⌘-Tab with a letter open |
| V26 | the on-screen window list before the first launch and after the last (6 launches, one of them `open -n`, and an `open -a` with a file) | the only new owner is the Finder (brought to the front by V22); no Touch ID or other system window was on screen (one that came and went between the two lists would not show) | partial: `osascript activate` not run |
| V28 | `open "$APP" --args -NSTraceEvents YES`; `open --env NSZombieEnabled=YES "$APP"` | the first: no Brev process after 5 s, log `launch refused: arguments`. The second: log `launch unsafe: environment; re-executing`, then `route onboarding`; `ps -wwE` shows `MallocScribble=1`, `BREV_LAUNCH_CLEANED=1` and no `NSZombieEnabled` | partial: the `defaults write -g` part waits for the human run |
| V29 | Brev on onboarding, `open -n "$APP"` | the new instance logs `second instance` and exits; `pgrep -x Brev` shows one PID | partial: "files unchanged" needs reads of `$D` |
| V40 | `security find-generic-password -s no.brev.app` | "could not be found", exit 44 | partial: the rest needs an install and reads of `$D` |
| V45 | `scripts/test.sh` | exit 0 in 3 min 9 s: fmt; clippy with default and all features; 136 Rust tests with the launch guard off (brev-mail 57 unit, 11 + 9 + 8 integration; brev-vault 28 and 3 doctests; brev-proto 9; brev-relay 11), 2 with it on, and the 2 release scrub tests; the zeroize, allocator, feature-graph, cfg-site, vault-whitelist, FFI-surface, patch, test-archive-marker, forbidden-API, AV/CM/CV and Xcode-minimum checks; `cargo audit` clean over 210 crates and 1 273 advisories; 15 harness lines, each 5 of 5; the lock probe's 26 checks (note: 0 ms from `Brev.unlock` to the completion on main, of the 2 000 ms confirm window); `capture-probe --selftest`; the Debug build | pass |
| V49 | `open "$APP"`; `open --env MallocScribble=0 "$APP"`; `ps -wwE` | `MallocScribble=1` in both; the second re-executed (log `launch unsafe: environment; re-executing`, `BREV_LAUNCH_CLEANED=1`) | partial: Finder and Dock launches need a human |
| V50 | `nm` on both binaries | Release: 0 `selfscan`/`brev_scan` symbols; Verify: 10 (control) | pass |
| V53 | the V53 lines of the V1 loop | both builds: `security.network.client` 1, `security.network.server` 0, group `AV26DNQ5SC.no.brev.app` | pass |
| V66 | the V66 commands | `NSAppTransportSecurity` 0 in both plists; `URLSession`/`NSURLConnection` 0 in `nm -u` of the Release binary; the pasteboard lines of `allowed-apis.txt` name `app/Sources/UI/OpaqueView.swift` twice and nothing else; the forbidden-API grep passed in V45 | pass |
| V69 | the four view host runs (`tools/viewhost/build.sh`) | mail (`--hold 1 --scan --post`): 38 checks; compose (`--compose --hold 1 --scan --post`): 49, among them the environment report before ⌘↩ (a software key, no Touch ID, every defence in place); contacts (`--contacts --hold 1`): 63; `--triggers switch`: 23, among them `lock reason=resignActive` once and U4's measurement line once. Each printed PASS and exited 0; no view host or relay process was left | pass |
| V70 | Brev on onboarding: `$T/windows Brev` before and after `open -a "$APP" <file>` | the window list is unchanged; log `open event ignored count=1`. First run on a Release build (review round 1 ran it on Debug) | partial: the half with the compose sheet open waits for the human run |

Not run, and why: V5, V6 and V7 (capture; above), V12 (System Events needs
Automation), V17, V18, V20, V41, V54, V58, V59, V64 and V68 (a store, an
unlocked Brev, Brev B or the relay with letters), V32 and V33 (the compose
sheet). The other rows need a human.

Also run, with no row of its own:

- **The release guard for `allow-software-keys`** (D-0068). `grep -a` finds
  the marker in the test archive, and not in the app's archive or the
  Release binary. The Xcode phase, proven in a scratch copy of `app/` with
  the test archive at the path it reads: `xcodebuild -configuration Release
  CODE_SIGNING_ALLOWED=NO` fails with the phase's error (exit 65); with the
  app's archive there, it succeeds.
- **Test code in the app** (D-0066). The Release binary has
  `zeroizing_alloc5WIPER` once and no `MockTransport`, `live_plaintexts` or
  `_for_test` symbol.
- **`DYLD_*` at launch** (owner answer Q2, D-0067). `open --env
  DYLD_BREV_TEST=1 "$APP"`: `ps -wwE` lists the variable, but Brev did not
  re-execute and went on to `route onboarding`. dyld takes `DYLD_*` out of
  the environment of a process with the hardened runtime: an ad-hoc probe
  signed with `-o runtime` saw no `DYLD_BREV_TEST` through `ProcessInfo` or
  `getenv`, and the same binary without the flag saw it. So in Release
  neither LaunchGuard nor Rust meets one; the stripping acts in Debug
  builds.
- **The split's bindings** (D-0066). `scripts/gen-bindings.sh` in
  `git archive` copies of `3ef953b` and `15f3e50`: `BrevCore.swift`,
  `BrevCoreFFI.h` and `BrevCoreFFI.modulemap` are byte-identical.

### What the split changes for the human run

These rows now also exercise the checks Rust took over (D-0067, D-0068):

- **The first launch with a store** (V27, V37, V40, V41, and every row
  after onboarding) is the first run of Rust's folder lock inside the App
  Sandbox container (plan R10); no machine run opened a store. A log line
  `open failed: Io` or `open failed: Unsafe` after a launch is a failure to
  report, not a damaged store.
- **The first unlock after onboarding** (V36, V37, V27) runs inside Rust's
  2 s confirm window, with onboarding's keychain writes in it (plan R4). A
  lock with `lock reason=unlockExpired` right after Touch ID means the
  window was missed.
- **V25**: Swift still locks at 300 s. Rust's own deadline, 320 s, is a
  backstop and shows only if Swift's lock fails.
- **V56, V57, V65**: a letter goes out only in environment class A. A
  refusal says «Brevet ble ikke sendt: …» and names the check that failed;
  record it. V18's `padcheck` expects schema v4.
- **V38, V52**: after a reset while a sync is still in flight, onboarding's
  create can get `Busy` for up to 15 s (plan R9).
- **V51**: `TouchIDProbe.app` links the app's archive, launch guard
  included, so Rust refuses to unlock without `MallocScribble=1`. Its
  `LSEnvironment` sets it when it is started with `open`, as V51's commands
  do, and the probe itself stops without it.
- **V28, V49**: in Release, dyld hides `DYLD_*` from Brev (above), so the
  `DYLD_*` stripping is not visible there.

The rows that need a human and a machine together, for the owner's run
(`docs/USER_SESSION.md` has the order): V6, V9, V11, V13, V14, V22, V23,
V28, V30, V31, V37, V38, V46, V49, V51, V52, V56, V60, V62, V63, V65, V67
and V70.

## WP4 run (Phase 2, `b6f2e3c`)

### The run

- macOS 26.2 (25C56), Xcode 26.2 (17C52), Apple silicon (arm64).
- App code under test: commit `b6f2e3c` (WP4 adds only tools and docs).
- `$APP`: the Release build from `scripts/build.sh`.
  `$VAPP`: the Verify build from `tools/verify/build.sh`. `$T`:
  `core/target/verify`, the tools from `tools/verify/build.sh`.
- Brev was not installed on this Mac (no wrapped-DEK item), so every launch
  showed onboarding. The launches ran from 07:12:54 to 07:16, with
  `log stream --level debug --predicate 'process == "Brev"'` running the whole
  time.

What the run did not do, and why:

- No Touch ID, password or keychain prompt. Without Touch ID there is no
  install, no unlocked Brev, no letter and no compose sheet. So every row that
  needs a store, a letter or the compose sheet waits for the human run.
- No reads inside Brev's container (`$D`). Terminal is not allowed to read
  other apps' data, so a read would raise the macOS prompt "Terminal vil ha
  tilgang til data fra andre apper". One such prompt was already on screen
  (see "Found during the run").
- No `defaults write -g` (it changes a setting for every app), no
  `osascript` to Brev or System Events (they need an Automation permission,
  which would prompt), no crash of Brev (it leaves a dialog on screen).
- Posted events went only to Brev's own PID (`CGEventPostToPid`,
  `AXUIElementPostKeyboardEvent`), and only keys `a` and `b` and clicks on
  *Fortsett*. Nothing posted at the session or HID tap.

"Partial" below means: the part a machine could run passed, and the row is
still open for the human run.

### Rows

| # | What ran | Result | Status |
|---|---|---|---|
| V1 | `codesign -dv` and `codesign -d --entitlements - --xml` on `$APP` and `$VAPP`; `codesign --verify --strict` | both: `flags=0x10000(runtime)`, `TeamIdentifier=AV26DNQ5SC`; entitlements exactly `app-sandbox` = true, `keychain-access-groups` = [`AV26DNQ5SC.no.brev.app`], `com.apple.application-identifier`, `com.apple.developer.team-identifier`; no `get-task-allow`; signatures valid | pass |
| V2 | the V2 commands on `$APP` and `$VAPP` | both: 0 forbidden plist keys; `NSPrincipalClass` = `BrevApplication`; `LSEnvironment.MallocScribble` = `1`; no nested bundle of any listed kind; `Contents` = `_CodeSignature embedded.provisionprofile Info.plist MacOS PkgInfo Resources` | pass |
| V3 | `sdef "$APP"` | `couldn't get sdef … (error -192)`, exit 1 | partial: the `osascript` half needs the Automation permission (a prompt), so it waits for the human run |
| V4 | – | – | deferred to human |
| V5 | `$T/capture-probe --screencapture` on the onboarding window | `-x`, `-R` and `-V 3`: window excluded (the probe's backdrop shows); `-l12500`: exit 1, "could not create image from window"; control visible in every path | partial: no letter can be open without Touch ID; deferred to human |
| V6 | `$T/capture-probe` (ScreenCaptureKit) on the onboarding window | window listed by `SCShareableContent` but excluded in all 8 paths: display filter, display excluding no apps, window filter with `includeChildWindows`, window filter stream, `captureImage(in:)`, `captureScreenshot(contentFilter:)`, `captureScreenshot(rect:)`, display stream; control visible | partial: no letter; deferred to human |
| V7 | `$T/capture-probe --legacy` on the onboarding window | `CGWindowListCreateImage` (screen and window) and `CGDisplayCreateImage` (display and rect): window excluded. `CGDisplayStream`, `AVCaptureScreenInput` and `CGDisplayStream` through `dlsym` from the 26.0 build: the window shows, with its interface text (not content), as expected; it has no content panes yet (the probe as revised after the review marks these three INVALID: no pane to judge) | partial: no letter; deferred to human |
| V8 | – | – | deferred to human |
| V9 | `$T/windows Brev` on onboarding | the onboarding window: `kCGWindowSharingState=0`. Brev also owns 4 off-screen windows of 1512×33 at (0,0), the menu bar's size, with `kCGWindowSharingState=1`. Every regular app on this Mac has the same 4 (Finder, Terminal, Xcode, Mail and others checked). `windows` exits 1 | **fails as written** (partial run): WP12 or the owner must decide on these 4 windows. The compose-sheet and `ConfirmSheet` parts wait for the human run |
| V10 | – | – | deferred to human |
| V11 | `$T/axdump Brev` on onboarding | 32 elements; marker 0; `AXTitle = "Brev"` found (control). Exposed text is interface text only: "Velkommen til Brev", the welcome body, "Fortsett", the menus. The minimise button is there with `AXEnabled = 0` | partial: no letter; deferred to human |
| V12 | – | needs System Events (Automation prompt) | deferred to human |
| V13 | `$T/axdump Brev --press Fortsett` (a `HumanButton`) | `AXError=0`, but the page did not change: a second dump still shows "Velkommen til Brev" and not "Dette må du vite". As the input spike found, the returned code says nothing; the effect does | partial: *Send* and *Lås opp med Touch ID* need an install; deferred to human |
| V14–V16 | – | – | deferred to human |
| V17 | – | needs stores (Touch ID) and reads of `$D` (prompt) | deferred to human |
| V18 | – | needs stores and reads of `$D`. Tool check below: `padcheck` passes on real stores and catches an unpadded value | deferred to human |
| V19 | the log stream and `log show --info --debug --start "2026-09-28 07:12:54"` for `process == "Brev"`, scanned with the `hits` function | 8303 and 1284 lines; marker 0 (UTF-8 and UTF-16LE); `lock reason=` 3 times in each (control); `hits` finds a planted marker (control) | partial: no letter was ever written, so the row waits for the full human run |
| V20 | – | needs an unlocked Brev with a letter open | deferred to human |
| V21 | the V21 commands | `mdutil -s /`: indexing enabled; nothing outside this checkout; `docs/VERIFY.md` found (control); `otool -L`: no CoreSpotlight; `nm -u`: 0 `CSSearchable…`/`NSUserActivity` of 660 undefined symbols | pass |
| V22 | Brev in front on onboarding, then `open -b com.apple.Terminal` | Terminal in front; log `lock reason=resignActive` | partial: the row asks for ⌘-Tab with a letter open; deferred to human |
| V23–V25 | – | – | deferred to human |
| V26 | the on-screen window list before the first of 5 launches and after the last | the only new window: Brev's own; no Touch ID or other system window was on screen (a window that came and went between the two lists would not show) | partial: `osascript activate` not run; deferred to human |
| V27 | – | – | deferred to human |
| V28 | `open "$APP" --args -NSTraceEvents YES`; `open --env NSZombieEnabled=YES "$APP"` | the first: no Brev process after 4 s, log `launch refused: arguments`. The second: log `launch unsafe: environment; re-executing`, then `route onboarding` in the same PID; `ps -wwE` shows `MallocScribble=1` and no `NSZombieEnabled` | partial: the `defaults write -g` part changes a setting for every app; deferred to human |
| V29 | Brev on onboarding, `open -n "$APP"` | the new instance logs `second instance` and exits; `pgrep -x Brev` shows the one PID before and after | partial: "files unchanged" needs reads of `$D`; deferred to human |
| V30–V35 | – | need the compose sheet | deferred to human |
| V36 | – | the rules page needs a human click | deferred to human |
| V37–V39 | – | – | deferred to human |
| V40 | `security find-generic-password -s no.brev.app` | "could not be found", exit 44 | partial: the rest needs an install and reads of `$D`; deferred to human |
| V41 | – | reads of `$D` | deferred to human |
| V42–V44 | – | – | deferred to human |
| V45 | `scripts/test.sh` | exit 0 in 1 min 57 s, with this package's new step (the tools type-check) | pass |
| V46–V48 | – | – | deferred to human |
| V49 | `open "$APP"`; `open --env MallocScribble=0 "$APP"`; `ps -wwE` | `MallocScribble=1` in both; the second re-executed (log `launch unsafe: environment; re-executing`) | partial: Finder and Dock launches need a human |
| V50 | `nm` on both binaries | Release: 0 `selfscan`/`brev_scan` symbols; Verify: 9 (control) | pass |
| V51 | – | needs Touch ID. Tool check below: `TouchIDProbe.app --dry` passes | deferred to human |
| V52 | – | – | deferred to human |

Also run, with no row of its own: `$T/poster key <pid> --via topid` and
`--via ax`, and `$T/poster click <pid> 756 482 --via topid` on *Fortsett*,
against Brev on onboarding (V32 and V33 need the compose sheet). The log
shows 18 `dropped synthetic` lines, all with the poster's PID: 6 key-downs,
6 key-ups, 3 mouse-downs, 3 mouse-ups. The 4 keys sent with
`AXUIElementPostKeyboardEvent` did not arrive. The page did not change.

### Tool checks

These check the tools, not Brev. They ran against `tools/viewhost` (Brev's
real mail window with fake letters, no keychain) where Brev itself needs
Touch ID.

- `capture-probe`, all three modes, against the view host in three variants.
  Protected (as Brev): every path passes; the window is excluded everywhere
  except `CGDisplayStream`, `AVCaptureScreenInput` and the `dlsym` build,
  which show the window with every pane empty (ink 0.00%). Negative control
  (`--capturable --unprotected`): every one of the 19 paths reports ink in
  all three panes and the probe exits 1; the cuts show the fake letters. The
  layer alone (`--capturable`): the window shows in 18 of the 19 paths (the
  window-filter stream returned an empty frame) and every pane stays empty. The panes came from Brev's AX scroll areas and matched
  the view host's own rects.
- `capture-probe` again after the WP4 review (ink judged by area, not by
  share of the pane; INVALID when nothing is judged). The view host had
  one-line letters, as VERIFY types them: one letter to Ekko and one to
  Speil, subject and body one line each, and their echoes. Two sizes: the
  default width (900 × 484, placed so that no old system dialog lies over a
  pane) and a window that fills the screen (1512 × 905).
  - Protected (as Brev): all 19 paths pass, with 0 pt² of ink in every pane,
    at both sizes. In the full-screen window the panes were given with
    `--pane` around the two old dialogs; with the AX panes, the dialogs
    themselves count as ink in the paths that capture the screen.
  - The layer alone (`--capturable`, default width): 19 of 19 pass; the
    window is captured in 18.
  - Negative control (`--capturable --unprotected`): all 19 paths report ink
    in all three panes, at both sizes. Ink at the default width: contacts
    4805, threads 1062, letters 2165 pt² (one glyph is 12).
  - The probe from before the review, on the full-screen negative control:
    the threads pane (0.48 % ink) passed in every path, and the letters pane
    (0.26 %) passed in the window-level paths. Only the contacts pane's
    selection fill made those paths report ink.
  - A capturable window with text and no scroll area: every path that
    captured it is INVALID, exit 2 (before the review: pass, exit 0).
  - A view host that resized its window during the run: the run ends with
    `panes-after-the-run INVALID`.
- `TouchIDProbe.app --dry` for the two builds of V51's variants (scrub 0 and
  128 KiB): PASS; each prints its `scrub=` depth. The disassembly of
  `scrub_stack_deep` in the three linked probes reserves 64 KiB, nothing and
  128 KiB of stack.
- `padcheck` on the view host's three stores: pass (14, 9 and 6 sealed
  values). On a copy where one body was set to 300 bytes: `NOT PADDED:
  rowid 1 length 300`, FAIL.
- `TouchIDProbe.app --dry` (Brev not running, not installed): made Brev's
  two Enclave keys with no prompt, wrapped a DEK with the X9.63 ECIES sender
  (checked against Security first), set the four needles, and found each
  needle once when made on purpose; the DEK was nowhere after `create`.
  Cleanup deleted the keys; PASS. Its signature: team `AV26DNQ5SC`, bundle
  id `no.brev.app`, runtime flag, no `get-task-allow`, `MallocScribble=1` in
  effect.
- `keylisten --check`: listen access already granted; the session tap and
  IOHIDManager opened and closed; no event read.
- `axdump` and `windows` on the view host: 41 elements, no marker, no
  contact name; one window with sharing state 0.
- `poster key --via topid` and `--via ax` on the view host: 16
  `dropped synthetic` lines. 12 carry the poster's PID. The other 4 are the
  keys sent with `AXUIElementPostKeyboardEvent`: they arrived with the view
  host's own PID and were dropped, because the rule has no exception for the
  app's own PID (D-0048). At Brev on
  onboarding (above) the same 4 keys did not arrive at all.
- `InputLab.app` started (sandboxed, hardened, ad hoc) and quit.
- `poster --via session` refuses without `--global`. The session, HID and
  `IOHIDPostEvent` ways were built but not run.

### Found during the run

1. **V9 as written fails on macOS 26.2.** Every regular app, Brev included,
   owns 4 off-screen windows of the menu bar's size with sharing state 1.
   They are the system's, not Brev's `NSWindow`s, and show only the menu bar
   (Brev and Arkiv). `windows` marks them and still counts them. Whether V9
   should count them is for WP12 or the owner.
2. **Old system dialogs are on screen**, from before WP4 (their window
   numbers are lower than WP11's, and WP11 had to move its test windows
   around two of them): "Terminal vil ha tilgang til data fra andre apper"
   (*Ikke tillat* / *Tillat*), a crash-report dialog (*Åpne igjen* /
   *Rapporter…* / *Ignorer*), and a `universalAccessAuthWarn` window. Nobody
   answered them here. The first one shows that a read of an app container
   from Terminal prompts on this Mac, which is why no row read `$D`.
3. With Terminal in front, Brev locks, so a human cannot type a command while
   Brev is unlocked. VERIFY.md now says to start such commands with a delay.
