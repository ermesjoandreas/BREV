# Brev — Phase 2 verification

The manual checklist that CLAUDE.md §5 (Phase 2) asks for, built from
`docs/PHASE2_DESIGN.md` §10. Its results are recorded in D-0053 (the design's
D-0058; `docs/DECISIONS.md` maps the design's decision numbers).
Rows V1–V45 follow the design's table, except where "Changes from the design"
at the end says otherwise. V46–V54 cover mechanisms that the table had no row
for (see "Coverage" below).

Status: written in WP0, 2026-09-27, and revised after its review. WP4
(2026-09-28) built the tools in `tools/verify/` and ran every row a machine
can run without Touch ID; the results are in `docs/VERIFY-RESULTS.md`. Rows
marked "per D-0052" become final after the human GUI-spike session. Review
round 1 (2026-09-28) changed V39, V41, V43 and V51 and added V53 and V54;
review round 2 changed V28 and the lock probe (V45) (see "Changes from the
design"). WP12 ran the machine rows again at `fb6f140` (D-0053); the human
run is still to come (`docs/USER_SESSION.md`).

## Setup

- Run every row on a **Release** build from `scripts/build.sh`. Debug builds
  have no Hardened Runtime (D-0013). V39 and the control in V50 use the Verify
  build from `tools/verify/build.sh` (`$VAPP`). V1 and V2 run on both builds,
  so V39 measures a process that is signed and configured like Release.
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
- Start Brev with `open "$APP"`, not `open -a Brev`: the Debug build in
  DerivedData has the same name and bundle id.
- Paste the block below into two terminals. It gives the same `R` in both.
  Before the first launch, start the log capture from V19 in the second one,
  and check from the first that it writes. Log lines that other rows name
  (`lock reason=…`, `dropped synthetic`, `second instance`,
  `launch refused: arguments`, `selfscan …`) are read from that capture.
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

hits() {  # hits NEEDLE PATH...: every file under PATH that holds NEEDLE as UTF-8 or UTF-16LE
  n="$1"; shift
  find "$@" -type f -exec sh -c 'strings -a "$1" | grep -qF -- "$2" && echo "utf-8    $1"' _ {} "$n" \;
  find "$@" -type f -exec perl -0777 -ne 'BEGIN { $n = join("\0", split(//, shift)) . "\0" } print "utf-16le $ARGV\n" if index($_, $n) >= 0' "$n" {} +
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
- Only V1, V2, V45, V50, V53, the `sdef` half of V3 and the binary half of
  V21 need no human and no running Brev. Every other row needs a store or a
  running Brev, and a human sets that up with Touch ID.

## Checklist

| # | Check | How | A/H | Depends on |
|---|---|---|---|---|
| V1 | Sandboxed + hardened | on `$APP` and `$VAPP`: `codesign -dv`: `runtime`, `TeamIdentifier=AV26DNQ5SC`; entitlements only `app-sandbox`, `keychain-access-groups` = `AV26DNQ5SC.no.brev.app`, and the `application-identifier` and `team-identifier` the profile adds; no `get-task-allow` | A | – |
| V2 | Plist and bundle | on `$APP` and `$VAPP`: `plutil -p`: none of D-0009's keys; `NSPrincipalClass = BrevApplication`; `LSEnvironment.MallocScribble = 1`. No extension, App Intents metadata, XPC service, sdef, Quick Look or Spotlight plug-in, bundle, framework or nested app anywhere in the bundle, and `Contents` holds only `Info.plist`, `MacOS`, `PkgInfo`, `Resources`, `_CodeSignature` and `embedded.provisionprofile` (team signing, D-0035) | A | – |
| V3 | No AppleScript | `sdef` fails; with Brev running, `osascript -e 'tell application "Brev" to get name of every window'` must fail with an error from Brev itself (expected -1708, errAEEventNotHandled; record the code). -1743 (not permitted) or -600 (not running) means the event never reached Brev and fails the row (grant Automation first) | A | – |
| V4 | ⇧⌘4 (window and area), ⇧⌘5 recording | a marker letter open: content absent or black | H | per D-0052 (U1) |
| V5 | `screencapture` | `-x` and `-V 3` show no letter; `-l <id>` (id from `$T/windows`) fails; control: another app's window is visible. `$T/capture-probe --screencapture` runs all four with its own control window and judges each | A | per D-0052 (U1) |
| V6 | ScreenCaptureKit | `$T/capture-probe`: display filter, window filter (`includeChildWindows`), `captureImage(in:)`, `captureScreenshot(…)` (26), one `SCStream` frame each with a display and a window filter; no letter in any (the window excluded, or its panes empty); control: its control window and text are visible | H grants, A runs | per D-0052 (U1) |
| V7 | Legacy CG capture, and the paths `.none` does not stop | a marker letter open: `$T/capture-probe --legacy` (built for 14.0): `CGWindowListCreateImage`, `CGDisplayCreateImage`, `CGDisplayStream` and `AVCaptureScreenInput`; and one `CGDisplayStream` frame through `dlsym` from a binary built for 26.0 (`$T/capture-probe-26`, which `--legacy` runs). No letter in any: the last three show the window with empty panes (the protected layer, D-0034); control as V6 | A | per D-0052 (U1) |
| V8 | Screen Sharing / ARD / AirPlay | a second Mac views, observes, mirrors: no letter visible | H | per D-0052 (U1) |
| V9 | Every window excluded | `$T/windows`: `kCGWindowSharingState == 0` for all Brev windows, once with the compose sheet open and once with `ConfirmSheet` open (it only exists in an error state, so do it during V38); control: the sheet is listed as its own window. On macOS 26.2 every regular app owns four off-screen menu-bar-sized windows with sharing state 1; the tool marks them and still counts them (see `docs/VERIFY-RESULTS.md`) | A (H opens) | – |
| V10 | Accessibility Inspector | the contacts list, the thread list, the letter, the compose fields and the recipient show no text | H | per D-0052 (U3) |
| V11 | AX dump | `$T/axdump Brev`: all attributes and parameterized attributes of every element; marker absent; control: title "Brev" present | A (H grants AX) | per D-0052 (U3) |
| V12 | GUI scripting | System Events `entire contents of window 1`: marker absent; control: the button titles are listed | A | per D-0052 (U3) |
| V13 | AX press refused | `$T/axdump Brev --press` on *Send* (compose sheet open, marker typed) and *Lås opp med Touch ID*, and during V38 on *Slett alt og start på nytt* and `ConfirmSheet`'s *Slett alt*: the files in `$D` are unchanged (a send rewrites `brev.db`, an unlock rewrites `biometry.state`, a reset deletes files), no Touch ID prompt appears, and the `AXError` axdump prints is recorded. Menu items: only harmless actions; control: pressing *Lås Brev* through AX locks | A + H looks | per D-0052 (U3) |
| V14 | ⌘C, ⌘X, ⌘A, ⌘V | `printf PB-CONTROL \| pbcopy` first; in the letter and compose views nothing happens and ⌘V inserts nothing; `pbpaste` still prints `PB-CONTROL` | H + A | – |
| V15 | Menus | only Brev and Arkiv next to the Apple menu, so no Edit menu with Copy or Paste; right-click in content shows no menu | H | – |
| V16 | Drag | dragging in a letter, onto TextEdit and the Finder, moves nothing out | H | – |
| V17 | No plaintext on disk | `strings -a` and a UTF-16LE grep over every file in the container and in Brev's per-user cache and temp folders: marker, `Ekko` and `Speil` absent; control: `SQLite format 3` found in `brev.db`. Run while unlocked, again after V44's quit, and again after V20's crash | A | – |
| V18 | Padding | `$T/padcheck`: every sealed column length is nonce + bucket + tag in all three stores; control: it checked more than 0 columns in each store | A | – |
| V19 | No plaintext in logs | `/usr/bin/log stream --level debug` for the whole run, and `/usr/bin/log show --info --debug` from the run's start afterwards (predicate `process == "Brev"`): marker absent (UTF-8 and UTF-16LE) in both; control: `lock reason=` lines present | A | – |
| V20 | Crash report | `kill -SEGV` an unlocked Brev with a marker letter open (start with a delay: Terminal in front locks Brev); wait for the report of that kill (it is written a few seconds later, so the newest `Brev*.ips` right after the kill is an older one) and scan it: marker absent; control: the report names `SIGSEGV` and the killed PID, and the V19 stream's last lock or unlock line before the kill is `unlocked` | A | – |
| V21 | Spotlight | `mdfind BREV-SECRET-BODY`: no path outside this checkout (the repo's docs hold the marker; Brev's container is not indexed, and V17 covers it); control: indexing is enabled and `mdfind` finds `docs/VERIFY.md`. The binary links no CoreSpotlight and references no `CSSearchable…` or `NSUserActivity` class (donation through the API) | A | – |
| V22 | Switching app locks | ⌘-Tab away: the lock screen; log `lock reason=resignActive` | H + A | per D-0052 (U4) |
| V23 | Screen lock locks | ⌃⌘Q: `lock reason=screenLocked` | H + A | per D-0052 (U4) |
| V24 | Sleep locks | sleep and wake: locked | H | per D-0052 (U4) |
| V25 | Idle locks | 5 min without input, also with the Brev menu left open: locked | H | per D-0052 (U4.2) |
| V26 | No prompt without a human | `open "$APP"`; `osascript -e 'activate application "Brev"'`: no Touch ID dialog | H | – |
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
| V39 | Heap residue in the real app | Verify build: send and read a marker letter to Ekko, lock; log `selfscan u8=0 u16=0 glyph=0 scribble=0 probe=<n>` with n > 0. `scribble` is the scribble probe (`app/Tests/scan.c`): a 32 KiB block filled with a pattern and freed keeps no copy of it, so `MallocScribble` takes effect in this process (V49 only reads the variable); `probe` counts the same block while it is allocated (its positive control). `glyph` counts the marker's glyph ids in `GlyphFlush.attrs`'s font (stored XORed, as in harness case 4): after the lock it shows that `GlyphFlush` cleared the control's line of the marker. A typed marker letter leaves no glyph ids even without scribbling (its lines are short, and libmalloc zeroes small freed blocks itself), so `glyph` says nothing about scribbling. Control: the `selfscan control` line (at the start of the lock, the letter still open) shows u16 > 0 and needle > 0; its glyph is 0 (see "Changes from the design"). Harness case 7 (V45) runs the same probe without scribbling and must find the freed block kept, so the probe can fail | H + A | per D-0052 (M) |
| V40 | Key storage | no key file: `$D` holds only `.lock` (0 B), `biometry.state` (32 B, if written) and the three stores; all files 0600, the directory 0700; `security find-generic-password -s no.brev.app` finds nothing (the keys and the wrapped DEK are in the data protection keychain, which `security` cannot list; a copy in a file keychain would be a bug); `xattr`/`tmutil isexcluded` shows the folder excluded | A | – |
| V41 | Nothing else written | no `Saved Application State`; in Application Support only `.lock`, `biometry.state`, `brev.db`, `peer-1.db` and `peer-2.db` (design §5.1's table still lists the key files D-0035 removed; any of them fails the row). Run after onboarding, again after V44's quit, and again after V20's crash | A | – |
| V42 | Echo | the three panes show Ekko and Speil, the threads and the letters; a letter to Ekko and one to Speil show as sent; each echo arrives within 3 s in the same thread | H | – |
| V43 | Dock / title | the minimise button is disabled (shown grey: the window has no `.miniaturizable`), and clicking it or ⌘M does not minimise the window, so there is no Dock thumbnail of it; title "Brev"; the Dock window list shows only "Brev" | H | – |
| V44 | Quit while unlocked | relaunch starts on the lock screen | H | – |
| V45 | Automated suite | `scripts/test.sh` exits 0 on this Mac (including the Swift harness, the lock probe and the forbidden-API grep) | A | – |
| V46 | Manual lock, blank-on-lock | with a marker letter open: ⌘L, the *Lås* button and the menu item *Lås Brev*; with the compose sheet open and the marker typed: ⌘L and *Lås Brev* (the sheet blocks clicks on the *Lås* button behind it). Each shows only the lock screen at once; the sheet is gone and secure input is off; after the next unlock the draft is gone; log `lock reason=manual` | H + A | – |
| V47 | Unlock that ends while Brev is inactive | click *Lås opp med Touch ID*, switch to another app while the Touch ID panel is up, then authenticate: Brev stays on the lock screen | H | per D-0052 (U4.1) |
| V48 | Unlock errors | wrong fingers until Touch ID locks out: `unlock.error.lockout`, never a password button. Then, as the last row of the run: add a fingerprint in System Settings: `unlock.error.fingers` with the reset button. This makes the test install unreadable, as designed, and also invalidates other apps' `.biometryCurrentSet` keys | H | per D-0052 (U4.3) |
| V49 | Malloc scribbling in the real process | `ps -wwE` shows `MallocScribble=1` for Brev started with `open "$APP"`, from the Finder and from the Dock; `open --env MallocScribble=0 "$APP"` → a re-executed process with `MallocScribble=1`, or `launch.error.unsafe` | A + H launches | per D-0052 (M) |
| V50 | Release has no Verify code | `nm` on the Release binary finds no `SelfScan` or `brev_scan` symbol; control: the same grep finds them in the Verify build | A | – |
| V51 | Unlock stack residue | `TouchIDProbe.app --unlock` (built by `tools/verify/build.sh`, team-signed with Brev's bundle id and keychain group) with the final `brev-core`: the exact §5.4 closure (`UnlockService.unlock`, unchanged: KEK lookup, `SecKeyCreateDecryptedData` with ECIES, `brev.unlock`, in-place wipe), needles for the DEK, the ECDH output, the AES key, the IV and the two echo peers' DEKs (which `Brev.unlock` derives from the DEK): it prints PASS, i.e. 0 hits for the ECDH output, AES key and IV after the closure, 0 for everything after lock, at the scrub depth recorded for the unlock drop guard (D-0039); control: while unlocked, the DEK and peer-DEK needles find Rust's copies (one each), and each needle is found once when made on purpose. Negative control (design §14.2 K): the same run with the build whose unlock scrub is disabled (`touchid-probe-scrub0`) prints `NEGATIVE CONTROL: residue …` and PASS for its own controls, so the scrub is what removes the residue; if it prints `NEGATIVE CONTROL EMPTY` instead, record that the PASS above does not show that the scrub works. If the shipped build fails, run the 128 KiB build (`touchid-probe-scrub128`); a change of depth goes to the owner (design §2.5). It uses Brev's own keychain names, so it runs only with Brev quit and not installed (run order step 2), and deletes what it made | H + A | per D-0052 (K) |
| V52 | File substitution | copy the three stores in `$D` aside before V38; after the new onboarding, Brev quit, put the old stores back: the unlock fails with `unlock.error.damaged` (the new DEK does not open them), and nothing unlocks | H + A | – |
| V53 | The view host's checks | no Brev needed; on the Release commit, nobody using the Mac: the view host (`tools/viewhost`: Brev's mail window, compose sheet, lock sequence and triggers with fake letters and a software KEK) prints PASS in mail mode (`--hold 1 --scan --post`: the protected layer, `draw(_:)` empty, pixel buffers zeroed on scroll-out and on lock, the Rust session locked, hardened sheets and child windows, a posted key dropped, the scribble probe), compose mode (`--compose --hold 1 --scan --post`: key-only typing, the ways in that must fail, secure input, the sheet wiped and freed after a send, Escape and a lock) and `--triggers switch` (switching app locks, not while an unlock is in flight). The compose and switch runs make the view host active, and the switch run brings the Finder to the front | A | – |
| V54 | Open-documents event | Brev running (onboarding or the lock screen), and again unlocked with the compose sheet open and a field focused (start with a delay): `open -a "$APP" <any file>` adds no window to `$T/windows Brev` (AppKit's "cannot open" alert would be an unhardened window with sharing state 1 that takes key from the sheet and turns secure input off); with the sheet open, `kCGSSessionSecureInputPID` is still Brev's PID; log `open event ignored count=1` | A (H opens) | – |

## Commands

For the A parts of the rows above. Each comment says what a pass looks like.

```sh
# V1 and V2, on both builds
for A in "$APP" "$VAPP"; do
  codesign -dv "$A" 2>&1 | grep -E 'flags|TeamIdentifier' # flags=0x10000(runtime); TeamIdentifier=AV26DNQ5SC
  codesign -d --entitlements - --xml "$A" | plutil -p -   # only app-sandbox => true, keychain-access-groups => [AV26DNQ5SC.no.brev.app],
                                                          # com.apple.application-identifier, com.apple.developer.team-identifier
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
hits Ekko "$C" "$CACHE_DIR" "$TEMP_DIR"                    # nothing
hits Speil "$C" "$CACHE_DIR" "$TEMP_DIR"                   # nothing
strings -a "$D/brev.db" | grep -c 'SQLite format 3'        # 1 (control)

# V18 (Brev quit)
"$T/padcheck" "$D"                                         # padcheck: pass; each store: more than 0 sealed values checked

# V19: the stream runs in the second terminal from before the first launch; stop it with ⌃C after the last row.
/usr/bin/log stream --level debug --predicate 'process == "Brev"' > "$R/stream.log"
head -1 "$R/stream.log"                                    # in the first terminal, before the first launch: Filtering the log data using …
/usr/bin/log show --info --debug --predicate 'process == "Brev"' --start "$START" > "$R/show.log"
hits "$M" "$R/stream.log" "$R/show.log"                    # nothing
grep -c 'lock reason=' "$R/stream.log"                     # > 0 (control)

# V20 (Brev in front, unlocked, a marker letter open when the delay ends)
sleep 30; PID="$(pgrep -x Brev)"; touch "$R/v20-mark"; kill -SEGV "$PID"
grep -E 'lock reason=|\] unlocked' "$R/stream.log" | tail -1   # ends in "] unlocked" (control: Brev was unlocked when it was killed)
for i in $(seq 60); do IPS="$(find ~/Library/Logs/DiagnosticReports -name 'Brev*.ips' -newer "$R/v20-mark" | head -1)"; [ -n "$IPS" ] && break; sleep 1; done
echo "$IPS"                                                # one path (none after 60 s fails the row)
hits "$M" "$IPS"                                           # nothing
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

# V39 (Verify build; from the V19 stream)
grep -o 'selfscan .*' "$R/stream.log"                      # after the lock: selfscan u8=0 u16=0 glyph=0 scribble=0 probe=<n>, n > 0;
                                                           # the control line: u16 > 0 and needle > 0

# V40
stat -f '%Sp %z %N' "$D" "$D/.lock" "$D"/*                 # drwx------; files -rw-------; sizes as in the row
security find-generic-password -s no.brev.app              # could not be found
tmutil isexcluded "$D"                                     # [Excluded]
xattr -l "$D"                                              # com.apple.metadata:com_apple_backup_excludeItem

# V41
ls -A "$C/Data/Library/Saved Application State"            # no such file or directory, or empty
ls -A "$D"                                                 # only .lock biometry.state brev.db peer-1.db peer-2.db

# V49 (launch with open, from the Finder and from the Dock)
ps -wwE -p "$(pgrep -x Brev)" | tr ' ' '\n' | grep '^MallocScribble='   # MallocScribble=1
open --env MallocScribble=0 "$APP"                         # after quitting; then the same ps

# V50
nm "$APP/Contents/MacOS/Brev" | grep -Eci 'selfscan|brev_scan'           # 0
nm "$VAPP/Contents/MacOS/Brev" | grep -Eci 'selfscan|brev_scan'         # > 0 (control)

# V53 (no Brev needed; nobody uses the Mac meanwhile: the compose and switch runs take activation)
VH="$(tools/viewhost/build.sh)"                            # needs the archive and bindings (scripts/test.sh or build.sh ran)
env MallocScribble=1 "$VH" --hold 1 --scan --post > "$R/v53-mail.txt"; echo "exit=$?"              # exit=0
env MallocScribble=1 "$VH" --compose --hold 1 --scan --post > "$R/v53-compose.txt"; echo "exit=$?"  # exit=0
"$VH" --triggers switch > "$R/v53-switch.txt"; echo "exit=$?"                                       # exit=0
tail -n 1 "$R"/v53-*.txt                                   # PASS in each; no FAIL line anywhere

# V54 (Brev running on onboarding or the lock screen; then again, with a delay, unlocked with the compose
# sheet open and a field focused when the delay ends)
printf 'V54\n' > "$R/v54.txt"
sleep 30; "$T/windows" Brev > "$R/v54-before.txt"; open -a "$APP" "$R/v54.txt"; sleep 2; "$T/windows" Brev > "$R/v54-after.txt"
ioreg -l -w 0 | grep kCGSSessionSecureInputPID              # with the sheet open: Brev's PID
diff "$R/v54-before.txt" "$R/v54-after.txt"                # no output
grep -c 'open event ignored count=1' "$R/stream.log"       # > 0

# V51 (Brev quit and not installed: run order step 2). Each --unlock asks for Touch ID once.
PROBE="$T/touchid-probe/Build/Products/Release/TouchIDProbe.app"             # brev-core as shipped: scrub=64 KiB
PROBE0="$T/touchid-probe-scrub0/Build/Products/Release/TouchIDProbe.app"     # the unlock's deep scrub disabled
PROBE128="$T/touchid-probe-scrub128/Build/Products/Release/TouchIDProbe.app" # the scrub at 128 KiB
open -W --stdout "$R/v51-dry.txt" "$PROBE" --args --dry  # no prompt; PASS (checks the setup)
open -W --stdout "$R/v51.txt" "$PROBE" --args --unlock   # exactly one Touch ID prompt, no password button; PASS
open -W --stdout "$R/v51-scrub0.txt" "$PROBE0" --args --unlock      # NEGATIVE CONTROL: residue …; PASS (record EMPTY if it says so)
open -W --stdout "$R/v51-scrub128.txt" "$PROBE128" --args --unlock  # only if v51.txt says FAIL
```

## Tools

| Tool | What it does | Rows |
|---|---|---|
| `tools/verify/build.sh` | builds the tools below into `$T` (`core/target/verify`) and the Verify build of Brev, and prints `T=` and `VAPP=`; `--tools` skips the Verify build; `--check` only type-checks (scripts/test.sh runs it) | V1, V2, V39, V50 |
| `$T/capture-probe` | sets a stage (a green backdrop right behind Brev's largest window, a cyan control window with text beside it), captures through every path, saves only cuts of that stage (to `--out`, by default a new private folder under `$TMPDIR`), and judges each path: control visible, window excluded, or ink in the content panes (Brev's AX scroll areas, so Terminal needs Accessibility; or `--pane`). A pane shows content when its ink covers one glyph's area, so one line of text counts at any window size. INVALID (exit 2) when a path judged nothing: the window captured but no pane known, the panes changed during the run (a lock), or a window-level capture empty while the same method does not show the control window either. Default ScreenCaptureKit, `--legacy` CoreGraphics, `CGDisplayStream` and `AVCaptureScreenInput` (built for 14.0), `--screencapture` the `screencapture` tool; `--selftest` checks the verdict rules on drawn panes (scripts/test.sh) | V5, V6, V7 |
| `$T/capture-probe-26` | one `CGDisplayStream` frame through `dlsym`, built for 26.0; `capture-probe --legacy` runs it | V7 |
| `$T/windows` | lists an app's windows with id, level, `kCGWindowSharingState`, on screen or not | V5, V9 |
| `$T/axdump` | dumps every AX attribute and parameterized attribute (the read-only ones called; never `AXReplaceRangeWithText`); `--press` sends `AXPress` and prints the `AXError` it returns; `--menus`, `--hit` | V11, V13 |
| `$T/poster` | posts synthetic keys (`key`) and clicks (`click`) in every variant of V32; the session and HID taps and `IOHIDPostEvent` need `--global` and post only while the target is in front | V32, V33 |
| `$T/keylisten` | listen-only event tap + IOHIDManager; prints only whether a key value was seen | V31 |
| `$T/padcheck` | checks every sealed column length in the three stores, read-only | V18 |
| `TouchIDProbe.app` (`$T/touchid-probe/Build/Products/Release/`) | runs Brev's unlock closure (`UnlockService`) with a real Enclave KEK and scans for the DEK, ECIES and peer-DEK needles; `--dry` stops before the prompt. Also built against a copy of brev-core with the unlock's deep scrub disabled (`$T/touchid-probe-scrub0/…`, the negative control) and at 128 KiB (`$T/touchid-probe-scrub128/…`); each prints its `scrub=` depth | V51 |
| `$T/InputLab.app`, `tools/verify/spikes/` | the GUI-spike lab and the spikes' sources (design §14.2); the rogue-Brev and anchor probes were dropped with D-0035 | – |
| `tools/viewhost` (`tools/viewhost/build.sh` prints its path) | Brev's mail window, compose sheet, lock sequence and lock triggers with fake letters and a software KEK (no keychain, no Touch ID), and in-process checks of them; SelfScan compiled in, as in the Verify build | V53 |
| `app/Tests/Lock` (the lock probe; scripts/test.sh builds and runs it) | a CLI without a window on screen: a synthetic key that `BrevApplication` drops, in `sendEvent` and posted to the probe itself through `nextEvent`, does not move the idle clock (the drop log is the control; the posted part is skipped if the process may not post events), a discarded unlock and the lock sequence lock the Rust session, the lock sequence zeroes every content view's pixel buffers, `draw(_:)` of a content view draws nothing, `UnlockService` locks Rust when its closure fails after `Brev.unlock` | V45 |

## Coverage

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
| Auto-lock | V22–V25, V53 |
| Blank-on-lock | V46, V22, V39, V45 (lock probe), V53 |
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
| `SecretBytes`, `SecretText`, CTLine-only layout, `GlyphFlush` (§6) | V45, V39, V53 |
| `MallocScribble` through `LSEnvironment` (§6.4) | V2, V49, V39 |
| Keys and the wrapped DEK in the keychain, no key file, 0600/0700, backup exclusion (§5.1 as changed by D-0035) | V1, V40, V41 |
| Install atomicity and known-name cleanup (§2.10, §5.2, §5.3) | V37 |
| Instance lock (§5.2) | V29 |
| Unlock: one prompt, no prompt without a human, the post-unlock rule (§4.3, §5.4); a discarded or failed unlock locks Rust | V26, V27, V47, V45 (lock probe) |
| Error mapping, `biometry.state`, reset, `ConfirmSheet` (§5.5) | V38, V48, V9, V13 |
| `OpaqueView` (§7.1) | V10, V11, V12, V15, V16, V53 |
| `HumanButton` (§7.1) | V13, V33 |
| `SecureTextView`, `SecureListView`, `LetterStackView`, sync timer (§7.2) | V42, V10 |
| Compose by `keyDown` + `UCKeyTranslate`, no `NSTextInputClient`, inert ⌘ keys (§7.3) | V35, V34, V14 |
| `SecureInput` (§7.3) | V30, V31, V46, V53 |
| `Hardening.apply` on every window; not minimisable, no tabbing, not restorable (§8.1); no AppKit alert from an open-documents event | V9, V43, V41, V53, V54 |
| Capture exclusion and the second defence (§8.2) | V4–V8, V53 |
| Lock triggers, own idle clock, common-mode timers (§8.3); dropped input does not move the idle clock | V22–V25, V53, V45 (lock probe) |
| Lock sequence (§8.4), including the Rust lock (step 5) and the pixel buffers | V46, V39, V19, V45 (lock probe), V53 |
| Menus Brev and Arkiv (§8.5) | V15, V13 |
| Plist and no scripting (§8.5) | V2, V3 |
| Synthetic-input filter in `sendEvent` and `nextEvent` (§8.5) | V32, V33, V45, V53 |
| Launch hygiene (§8.6) | V28, V49 |
| Verify configuration and `SelfScan` (§4.1) | V39, V50 |
| Replaced stores do not unlock (§2, D-0035) | V52 |
| FFI surface check, forbidden-API grep, Swift harness (§11) | V45 |

## Order of a run

1. Before any launch: V1 and V2 (both builds), V45, V50, V53, the `sdef`
   half of V3, the binary half of V21. Start the V19 stream and check that
   it writes.
2. With no `$D` (first run or after a reset): V51 with `TouchIDProbe.app`
   (it uses Brev's own keychain names, so it runs only while Brev is not
   installed, and deletes them again), V36, V29, V37, then onboarding to the
   end (the first unlock is V27's one prompt with no password button), V40,
   V41.
3. Launches, with Brev quit before each: V28 (delete the global default at
   once), V49, V26, the `osascript` half of V3. On the lock screen: V27's
   *Avbryt*, V43, the first half of V54, V48's lockout part.
4. Unlocked, with marker letters to Ekko and Speil: V42, then the capture,
   accessibility (V13 on *Send* and *Lås opp med Touch ID*), input
   (with V54's compose half), pasteboard, disk, log and lock rows, V46, V47,
   and V44 last. Grant
   Terminal Accessibility before the capture rows: `capture-probe` finds
   Brev's panes through it.
5. With Brev quit after V44's relaunch: V17 and V41 again, so that what the
   lock, discard and quit paths wrote is scanned. Then V39 on the Verify
   build.
6. Destructive rows last: V20, then V17 and V41 again (the crash path). Copy
   `$D` aside (V52 needs it, and it restores the install if a V13 press gets
   through). V38, with V9's `ConfirmSheet` part and V13's presses on
   *Slett alt og start på nytt* and `ConfirmSheet`'s *Slett alt* before a
   human presses either. V52. Then V48's fingerprint step as the very last.

## Failures and results

A row passes only as written. A failed row is fixed and run again, or it gets
a D-entry that the owner accepts. Never reword a failure as residual risk
without the owner (design §14.2). Where a row or its spike item says "stop and
ask the owner" (V31; V32 and V33 if a posted event gets through; V4–V8 on a
capture leak), that area stops until the owner answers.

Results go to D-0053: the macOS build, the commit, and for each row pass,
fail, or the D-entry that accepts it. `docs/VERIFY-RESULTS.md` holds the
machine-run part (WP4).

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
  V51 adds needles for the echo peers' DEKs. V53 makes the view host's
  checks a row: they are the only ones of the protected layer, the pixel
  buffers and the Rust lock that run the real views in a window. The lock
  probe in scripts/test.sh (V45) covers the Rust lock, the pixel buffers and
  `draw(_:)` without a window. V54 checks the open-documents event, which
  made AppKit show an unhardened alert in Brev.
- Review round 2 (2026-09-28, D-0064): V28 also sets `TSMEventTracing`,
  which LaunchGuard now refuses: the launch spike found it to be the one
  key-event trace that works without get-task-allow, and the design's list
  had only AppKit's and Foundation's keys. The lock probe (V45) checks that
  dropped synthetic input does not move Brev's idle clock; before, only the
  view host's `--triggers idle --post` run did, which no row requires. The
  FFI surface check (V45) pins every export and every converter use, not
  only the `String` and `Data` ones.
