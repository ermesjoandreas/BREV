# Brev — Phase 2 verification: machine-run results (WP4)

These are the rows of `docs/VERIFY.md` that a machine could run on
2026-09-28, with nobody at the Mac. D-0053 records them, with WP12's re-run
of V1, V2, V3 (`sdef`), V21, V45, V50 and V53 at `fb6f140`. The run of the
whole checklist with a human is still to come; this file does not replace
it.

## The run

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

## Rows

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

## Tool checks

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

## Found during the run

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
