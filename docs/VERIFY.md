# Brev — Phase 2 verification

The manual checklist that CLAUDE.md §5 (Phase 2) asks for, built from
`docs/PHASE2_DESIGN.md` §10. WP12 runs it and records the results in D-0058.
Rows V1–V45 follow the design's table, except where "Changes from the design"
at the end says otherwise. V46–V52 cover mechanisms that the table had no row
for (see "Coverage" below).

Status: written in WP0, 2026-09-27, and revised after its review. The tools
in `tools/verify/` do not exist yet; WP4 builds them. Rows marked "per D-0057"
become final after WP4's human GUI-spike session.

## Setup

- Run every row on a **Release** build from `scripts/build.sh`. Debug builds
  have no Hardened Runtime (D-0013). V39 and the control in V50 use the Verify
  build from `tools/verify/build.sh` (`$VAPP`). V1 and V2 run on both builds,
  so V39 measures a process that is signed and configured like Release.
- Tools live in `tools/verify/` and are built by `tools/verify/build.sh`
  (WP4). They are never linked into Brev.app (D-0054).
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
VAPP='<Verify Brev.app>'                                  # the path tools/verify/build.sh prints
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
- **per D-0057**: the procedure or the expected result depends on a GUI-spike
  fact (the §14.2 item is in brackets). Update the row from D-0057 before the
  run. Where the spike says "stop and ask the owner", the row waits for the
  answer. **per D-0055**: it depends on the owner's answer to the design's
  open question 1 (file substitution). **per D-0037 (Q3)**: it depends on the
  answer to open question 3 (backup exclusion).
- Only V1, V2, V45, V50, the `sdef` half of V3 and the binary half of V21
  need no human and no running Brev. Every other row needs a store or a
  running Brev, and a human sets that up with Touch ID.

## Checklist

| # | Check | How | A/H | Depends on |
|---|---|---|---|---|
| V1 | Sandboxed + hardened | on `$APP` and `$VAPP`: `codesign -dv`: `runtime`; entitlements only `app-sandbox`; no `get-task-allow` | A | – |
| V2 | Plist and bundle | on `$APP` and `$VAPP`: `plutil -p`: none of D-0009's keys; `NSPrincipalClass = BrevApplication`; `LSEnvironment.MallocScribble = 1`. No extension, App Intents metadata, XPC service, sdef, Quick Look or Spotlight plug-in, bundle, framework or nested app anywhere in the bundle, and `Contents` holds only `Info.plist`, `MacOS`, `PkgInfo`, `Resources`, `_CodeSignature` | A | – |
| V3 | No AppleScript | `sdef` fails; with Brev running, `osascript -e 'tell application "Brev" to get name of every window'` must fail with an error from Brev itself (expected -1708, errAEEventNotHandled; record the code). -1743 (not permitted) or -600 (not running) means the event never reached Brev and fails the row (grant Automation first) | A | – |
| V4 | ⇧⌘4 (window and area), ⇧⌘5 recording | a marker letter open: content absent or black | H | per D-0057 (U1) |
| V5 | `screencapture` | `-x` and `-V 3` show no letter; `-l <id>` (id from `tools/verify/windows`) fails; control: another app's window is visible | A | per D-0057 (U1) |
| V6 | ScreenCaptureKit | `tools/verify/capture-probe`: display filter, window filter (`includeChildWindows`), `captureImage(in:)`, `captureScreenshot(…)` (26); control: a control window is visible | H grants, A runs | per D-0057 (U1) |
| V7 | Legacy CG capture | `tools/verify/capture-probe --legacy` (built for 14.0): `CGWindowListCreateImage`, `CGDisplayCreateImage`; control as V6 | A | per D-0057 (U1) |
| V8 | Screen Sharing / ARD / AirPlay | a second Mac views, observes, mirrors: no letter visible | H | per D-0057 (U1) |
| V9 | Every window excluded | `tools/verify/windows`: `kCGWindowSharingState == 0` for all Brev windows, once with the compose sheet open and once with `ConfirmSheet` open (it only exists in an error state, so do it during V38); control: the sheet is listed as its own window | A (H opens) | – |
| V10 | Accessibility Inspector | the contacts list, the thread list, the letter, the compose fields and the recipient show no text | H | per D-0057 (U3) |
| V11 | AX dump | `tools/verify/axdump Brev`: all attributes and parameterized attributes of every element; marker absent; control: title "Brev" present | A (H grants AX) | per D-0057 (U3) |
| V12 | GUI scripting | System Events `entire contents of window 1`: marker absent; control: the button titles are listed | A | per D-0057 (U3) |
| V13 | AX press refused | `tools/verify/axdump --press` on *Send* (compose sheet open, marker typed) and *Lås opp med Touch ID*, and during V38 on *Slett alt og start på nytt* and `ConfirmSheet`'s *Slett alt*: the files in `$D` are unchanged (a send rewrites `brev.db`, an unlock rewrites `biometry.state`, a reset deletes files), no Touch ID prompt appears, and the `AXError` axdump prints is recorded. Menu items: only harmless actions; control: pressing *Lås Brev* through AX locks | A + H looks | per D-0057 (U3) |
| V14 | ⌘C, ⌘X, ⌘A, ⌘V | `printf PB-CONTROL \| pbcopy` first; in the letter and compose views nothing happens and ⌘V inserts nothing; `pbpaste` still prints `PB-CONTROL` | H + A | – |
| V15 | Menus | only Brev and Arkiv next to the Apple menu, so no Edit menu with Copy or Paste; right-click in content shows no menu | H | – |
| V16 | Drag | dragging in a letter, onto TextEdit and the Finder, moves nothing out | H | – |
| V17 | No plaintext on disk | `strings -a` and a UTF-16LE grep over every file in the container and in Brev's per-user cache and temp folders: marker, `Ekko` and `Speil` absent; control: `SQLite format 3` found in `brev.db`. Run while unlocked, again after V44's quit, and again after V20's crash | A | – |
| V18 | Padding | `tools/verify/padcheck`: every sealed column length is nonce + bucket + tag in all three stores; control: it checked more than 0 columns in each store | A | – |
| V19 | No plaintext in logs | `/usr/bin/log stream --level debug` for the whole run, and `/usr/bin/log show --info --debug` from the run's start afterwards (predicate `process == "Brev"`): marker absent (UTF-8 and UTF-16LE) in both; control: `lock reason=` lines present | A | – |
| V20 | Crash report | `kill -SEGV` an unlocked Brev with a marker letter open; wait for the report of that kill (it is written a few seconds later, so the newest `Brev*.ips` right after the kill is an older one) and scan it: marker absent; control: the report names `SIGSEGV` and the killed PID | A | – |
| V21 | Spotlight | `mdfind BREV-SECRET-BODY`: no path outside this checkout (the repo's docs hold the marker; Brev's container is not indexed, and V17 covers it); control: indexing is enabled and `mdfind` finds `docs/VERIFY.md`. The binary links no CoreSpotlight and references no `CSSearchable…` or `NSUserActivity` class (donation through the API) | A | – |
| V22 | Switching app locks | ⌘-Tab away: the lock screen; log `lock reason=resignActive` | H + A | per D-0057 (U4) |
| V23 | Screen lock locks | ⌃⌘Q: `lock reason=screenLocked` | H + A | per D-0057 (U4) |
| V24 | Sleep locks | sleep and wake: locked | H | per D-0057 (U4) |
| V25 | Idle locks | 5 min without input, also with the Brev menu left open: locked | H | per D-0057 (U4.2) |
| V26 | No prompt without a human | `open "$APP"`; `osascript -e 'activate application "Brev"'`: no Touch ID dialog | H | – |
| V27 | Touch ID | exactly one prompt; no password button; *Avbryt* returns to the lock screen (check this on the regular lock screen: at onboarding's first unlock, *Avbryt* stays on that page, design §5.3 step 8) | H | per D-0057 (U4.1) |
| V28 | Launch hygiene | Brev quit first. `open "$APP" --args -NSTraceEvents YES` exits; `defaults write -g NSTraceEvents -bool YES` then launch → only `launch.error.unsafe`, no unlock button; delete the default right after; `open --env NSZombieEnabled=YES "$APP"` → a re-executed process without the variable, or `launch.error.unsafe` if re-exec does not work in the sandbox | A + H looks | per D-0057 (L, M) |
| V29 | Second instance | during onboarding, `open -n "$APP"`: the second instance exits (log `second instance`); files unchanged | A | – |
| V30 | Secure input flag | `ioreg -l -w 0 \| grep kCGSSessionSecureInputPID` = Brev's PID only while a compose field has focus | A (H focuses) | per D-0057 (U2.4) |
| V31 | Keyloggers see nothing | `tools/verify/keylisten` (listen-only CGEventTap + IOHIDManager, Input Monitoring granted) while typing the marker in compose: no key values; control: it sees keys typed in TextEdit. If IOHIDManager sees key values: stop and ask the owner | H + A | per D-0057 (U2.4) |
| V32 | Synthetic keys | `tools/verify/poster key` (CGEventPost at HID and session taps, `CGEventPostToPid`, each with field 41 untouched, set to 0, and set to Brev's PID; `AXUIElementPostKeyboardEvent`; `IOHIDPostEvent`); System Events `keystroke`: nothing typed; log `dropped synthetic`; control: the same posts type into TextEdit | A | per D-0057 (U2.2) |
| V33 | Synthetic clicks | `tools/verify/poster click` on *Send* / *Lås opp med Touch ID* with the same variants: no effect; control as V32 | A | per D-0057 (U2.2) |
| V34 | Text services | dictation, emoji picker, Character Viewer, press-and-hold, Writing Tools, Look Up (⌃⌘D, force click), text replacement, Services shortcuts, Touch Bar suggestions: none reach compose. No autocorrect, spell-check or predictions: `teh ` stays `teh `, no spelling underline, no inline-prediction text | H | per D-0057 (U2.3) |
| V35 | Norwegian input | æ ø å Æ Ø Å; ´+e → é; ¨+u → ü; ⇧´+e → è; ⌥¨ then n → ñ; @ (the key left of Return); ⇧4 $; ⌥7 \|; ⇧⌥7 \\; ⌥8/⌥9 [ ]; ⇧⌥8/⇧⌥9 { }; Caps Lock; key repeat | H | per D-0057 (U2.1) |
| V36 | Onboarding | the four rules texts (`touchid`, `nobackup`, `fingers`, `prompt`) appear in bokmål, plus `onboarding.rules.gone` if D-0055 chose the warning; *Opprett nøkler* stays disabled until *Jeg forstår …* is ticked | H | per D-0055 |
| V37 | Crash during onboarding | `kill -9` after *Opprett nøkler*, before the first unlock: relaunch shows onboarding; only fresh files exist after the next attempt | A + H | – |
| V38 | Damaged and reset | move `kek.se` out of `$D`: `unlock.error.damaged`; files unchanged after *Avbryt* in `ConfirmSheet`; gone only after *Slett alt*; onboarding starts | H + A | – |
| V39 | Heap residue in the real app | Verify build: send and read a marker letter to Ekko, lock; log `selfscan u8=0 u16=0 glyph=0`. `glyph` counts the marker's glyph ids in `GlyphFlush.attrs`'s font (stored XORed, as in harness case 4); it is the only count that sees the residue `MallocScribble` and `GlyphFlush` remove. Control: a scan while the letter is open shows u16 > 0 and glyph > 0 | H + A | per D-0057 (M) |
| V40 | Key files | `identity.se`, `kek.se` 569 B; `biometry.state` 32 B (if written); `dek.hpke` 113 B; all files 0600, the directory 0700; `security find-generic-password -s no.brev.app` finds nothing (if WP9 is built: only the anchor item); `xattr`/`tmutil isexcluded` shows the folder excluded (if the owner allows backups: not excluded) | A | per D-0055, D-0057 (A); per D-0037 (Q3) |
| V41 | Nothing else written | no `Saved Application State`; only §5.1's files in Application Support. Run after onboarding, again after V44's quit, and again after V20's crash | A | – |
| V42 | Echo | the three panes show Ekko and Speil, the threads and the letters; a letter to Ekko and one to Speil show as sent; each echo arrives within 3 s in the same thread | H | – |
| V43 | Dock / title | no minimise button; title "Brev"; the Dock window list shows only "Brev" | H | – |
| V44 | Quit while unlocked | relaunch starts on the lock screen | H | – |
| V45 | Automated suite | `scripts/test.sh` exits 0 on this Mac (including the Swift harness and the forbidden-API grep) | A | – |
| V46 | Manual lock, blank-on-lock | with a marker letter open: ⌘L, the *Lås* button and the menu item *Lås Brev*; with the compose sheet open and the marker typed: ⌘L and *Lås Brev* (the sheet blocks clicks on the *Lås* button behind it). Each shows only the lock screen at once; the sheet is gone and secure input is off; after the next unlock the draft is gone; log `lock reason=manual` | H + A | – |
| V47 | Unlock that ends while Brev is inactive | click *Lås opp med Touch ID*, switch to another app while the Touch ID panel is up, then authenticate: Brev stays on the lock screen | H | per D-0057 (U4.1) |
| V48 | Unlock errors | wrong fingers until Touch ID locks out: `unlock.error.lockout`, never a password button. Then, as the last row of the run: add a fingerprint in System Settings: `unlock.error.fingers` with the reset button. This makes the test install unreadable, as designed, and also invalidates other apps' `.biometryCurrentSet` keys | H | per D-0057 (U4.3) |
| V49 | Malloc scribbling in the real process | `ps -wwE` shows `MallocScribble=1` for Brev started with `open "$APP"`, from the Finder and from the Dock; `open --env MallocScribble=0 "$APP"` → a re-executed process with `MallocScribble=1`, or `launch.error.unsafe` | A + H launches | per D-0057 (M) |
| V50 | Release has no Verify code | `nm` on the Release binary finds no `SelfScan` or `brev_scan` symbol; control: the same grep finds them in the Verify build | A | – |
| V51 | Unlock stack residue | `tools/verify/touchid-probe` with the final `brev-core`: the exact §5.4 closure, needles for the DEK, the P-256 DH output, the HPKE KEM shared secret, the AEAD key and the base nonce: 0 hits after the closure at the scrub depth D-0035 names; control: while unlocked, the DEK needle finds Rust's copy | H + A | per D-0057 (K) |
| V52 | File substitution | only if WP9 is built: copy `$D` aside before V38; after the new onboarding, put the old `kek.se`, `dek.hpke` and stores back: `unlock.error.tampered`, and no unlock | H + A | per D-0055, D-0057 (A) |

## Commands

For the A parts of the rows above. Each comment says what a pass looks like.

```sh
# V1 and V2, on both builds
for A in "$APP" "$VAPP"; do
  codesign -dv "$A" 2>&1 | grep flags                     # flags=0x10002(adhoc,runtime)
  codesign -d --entitlements - --xml "$A" | plutil -p -   # only "com.apple.security.app-sandbox" => true
  P="$A/Contents/Info.plist"
  plutil -p "$P" | grep -E 'NSAppleScriptEnabled|NSServices|CFBundleDocumentTypes|CFBundleURLTypes|UTExportedTypeDeclarations|NSUserActivityTypes|NSAppleEventsUsageDescription|Intents|NSMainNibFile'   # nothing
  plutil -extract NSPrincipalClass raw "$P"               # BrevApplication
  plutil -extract LSEnvironment.MallocScribble raw "$P"   # 1
  find "$A" -mindepth 1 \( -name '*.appex' -o -name '*.appintents' -o -name '*.xpc' -o -name '*.sdef' -o -name '*.qlgenerator' -o -name '*.mdimporter' -o -name '*.plugin' -o -name '*.bundle' -o -name '*.framework' -o -name '*.app' \)   # nothing
  ls -A "$A/Contents"                                     # only Info.plist MacOS PkgInfo Resources _CodeSignature
done

# V3
sdef "$APP"                                                # couldn't get sdef … (error -192), exit 1
osascript -e 'tell application "Brev" to get name of every window'   # Brev running: an error from Brev; record the code

# V5 (a marker letter open; another app's window visible)
screencapture -x "$R/v5.png"
screencapture -x -V 3 "$R/v5.mov"
screencapture -x -l <id> "$R/v5-window.png"                # fails: could not create image from window

# V12
osascript -e 'tell application "System Events" to get entire contents of window 1 of process "Brev"' > "$R/v12.txt"
grep -c "$M" "$R/v12.txt"                                  # 0
grep -c 'Nytt brev' "$R/v12.txt"                           # > 0 (control)

# V13: a list of $D before and after each press (size, mtime in ns, inode: a rename also counts)
find "$D" -type f -exec stat -f '%N %z %Fm %i' {} + | sort > "$R/v13-before"
tools/verify/axdump --press '<button title>'               # record the AXError it prints; no Touch ID prompt appears
find "$D" -type f -exec stat -f '%N %z %Fm %i' {} + | sort | diff "$R/v13-before" -   # no output

# V17
hits "$M" "$C" "$CACHE_DIR" "$TEMP_DIR"                    # nothing (a missing TEMP_DIR is fine)
hits Ekko "$C" "$CACHE_DIR" "$TEMP_DIR"                    # nothing
hits Speil "$C" "$CACHE_DIR" "$TEMP_DIR"                   # nothing
strings -a "$D/brev.db" | grep -c 'SQLite format 3'        # 1 (control)

# V19: the stream runs in the second terminal from before the first launch; stop it with ⌃C after the last row.
/usr/bin/log stream --level debug --predicate 'process == "Brev"' > "$R/stream.log"
head -1 "$R/stream.log"                                    # in the first terminal, before the first launch: Filtering the log data using …
/usr/bin/log show --info --debug --predicate 'process == "Brev"' --start "$START" > "$R/show.log"
hits "$M" "$R/stream.log" "$R/show.log"                    # nothing
grep -c 'lock reason=' "$R/stream.log"                     # > 0 (control)

# V20 (unlocked, a marker letter open)
PID="$(pgrep -x Brev)"; touch "$R/v20-mark"
kill -SEGV "$PID"
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
open --env NSZombieEnabled=YES "$APP"
ps -wwE -p "$(pgrep -x Brev)" | tr ' ' '\n' | grep -E '^(NSZombieEnabled|MallocScribble)='   # re-exec: MallocScribble=1 only

# V29 (during onboarding)
find "$D" -type f -exec stat -f '%N %z %m %Sp' {} + | sort > "$R/v29-before"
open -n "$APP"                                             # the new instance exits
pgrep -x Brev                                              # one PID
find "$D" -type f -exec stat -f '%N %z %m %Sp' {} + | sort | diff "$R/v29-before" -   # no output

# V30
pgrep -x Brev
ioreg -l -w 0 | grep kCGSSessionSecureInputPID             # that PID only while a compose field has focus

# V39 (Verify build; from the V19 stream)
grep -o 'selfscan .*' "$R/stream.log"                      # after the lock: selfscan u8=0 u16=0 glyph=0; the control scan: u16 > 0 and glyph > 0

# V40
stat -f '%Sp %z %N' "$D" "$D/.lock" "$D"/*                 # drwx------; files -rw-------; sizes as in the row
security find-generic-password -s no.brev.app              # could not be found (if WP9 is built: only the anchor item)
tmutil isexcluded "$D"                                     # [Excluded] (if the owner allows backups: [Included])
xattr -l "$D"                                              # com.apple.metadata:com_apple_backup_excludeItem (if backups are allowed: absent)

# V41
ls -A "$C/Data/Library/Saved Application State"            # no such file or directory, or empty
ls -A "$D"                                                 # only .lock identity.se kek.se biometry.state brev.db peer-1.db peer-2.db dek.hpke

# V49 (launch with open, from the Finder and from the Dock)
ps -wwE -p "$(pgrep -x Brev)" | tr ' ' '\n' | grep '^MallocScribble='   # MallocScribble=1
open --env MallocScribble=0 "$APP"                         # after quitting; then the same ps

# V50
nm "$APP/Contents/MacOS/Brev" | grep -Eci 'selfscan|brev_scan'           # 0
nm "$VAPP/Contents/MacOS/Brev" | grep -Eci 'selfscan|brev_scan'         # > 0 (control)
```

## Tools

| Tool | What it does | Rows |
|---|---|---|
| `tools/verify/build.sh` | builds the tools below and the Verify build of Brev, and prints the Verify build's path (`$VAPP`) | V1, V2, V39, V50 |
| `tools/verify/capture-probe` | ScreenCaptureKit captures; `--legacy`: CG captures from a binary built for 14.0 | V6, V7 |
| `tools/verify/windows` | lists windows with id, owner and `kCGWindowSharingState` | V5, V9 |
| `tools/verify/axdump` | dumps every AX attribute and parameterized attribute; `--press` sends `AXPress` and prints the `AXError` it returns | V11, V13 |
| `tools/verify/poster` | posts synthetic keys (`key`) and clicks (`click`) in every variant of V32 | V32, V33 |
| `tools/verify/keylisten` | listen-only event tap + IOHIDManager | V31 |
| `tools/verify/padcheck` | checks every sealed column length in the three stores | V18 |
| `tools/verify/touchid-probe` | runs the §5.4 unlock closure and scans for needles | V51 |
| `tools/verify/InputLab.app`, `rogue-brev.app`, `anchor-probe`, `spikes/` | GUI spike only (design §14.2) | – |

## Coverage

CLAUDE.md §5, Phase 2:

| §5 line | Rows |
|---|---|
| Onboarding explains "no backup, Touch ID only" and fingerprint changes, in Norwegian | V36 |
| Onboarding creates Enclave keys and wraps a fresh DEK | V40, V37, V27 |
| Unlock screen → Touch ID → `core.unlock(dek)` | V26, V27, V47, V48, V51 |
| Three-pane window; content panes use `SecureTextView` | V42, V10, V11 |
| Compose: secure event input | V30, V31 |
| Compose: synthetic event rejection | V32, V33, V13 |
| Compose: no pasteboard | V14, V16 |
| Compose: no autocorrect, `writingToolsBehavior = .none` | V34 |
| Window capture exclusion | V4–V9 |
| Auto-lock | V22–V25 |
| Blank-on-lock | V46, V22, V39 |
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
| UniFFI surface without content `String`s; 960-byte `OpenText` chunks (§2.2) | V45 |
| `OpenText` registry; lock closes open texts (§2.4) | V45, V39 |
| `unlock` drop guard, poison handling, 64 KiB scrub (§2.3, §2.5) | V45, V51 |
| Zeroing allocator (§2.6) | V45, V39 |
| Echo peers, HKDF peer DEKs, `sync` (§2.7, §9) | V42, V17, V18, V45 |
| Stored padding, schema v2 (§2.8, §2.9) | V18, V45 |
| Binding patches and the uniffi pin (§3) | V45 |
| `SecretBytes`, `SecretText`, CTLine-only layout, `GlyphFlush` (§6) | V45, V39 |
| `MallocScribble` through `LSEnvironment` (§6.4) | V2, V49, V39 |
| Key files, 0600/0700, backup exclusion, no keychain item (§5.1) | V40, V41 |
| Install atomicity and known-name cleanup (§2.10, §5.2, §5.3) | V37 |
| Instance lock (§5.2) | V29 |
| Unlock: one prompt, no prompt without a human, the post-unlock rule (§4.3, §5.4) | V26, V27, V47 |
| Error mapping, `biometry.state`, reset, `ConfirmSheet` (§5.5) | V38, V48, V9, V13 |
| `OpaqueView` (§7.1) | V10, V11, V12, V15, V16 |
| `HumanButton` (§7.1) | V13, V33 |
| `SecureTextView`, `SecureListView`, `LetterStackView`, sync timer (§7.2) | V42, V10 |
| Compose by `keyDown` + `UCKeyTranslate`, no `NSTextInputClient`, inert ⌘ keys (§7.3) | V35, V34, V14 |
| `SecureInput` (§7.3) | V30, V31, V46 |
| `Hardening.apply` on every window; no minimise, no tabbing, not restorable (§8.1) | V9, V43, V41 |
| Capture exclusion and the second defence (§8.2) | V4–V8 |
| Lock triggers, own idle clock, common-mode timers (§8.3) | V22–V25 |
| Lock sequence (§8.4) | V46, V39, V19 |
| Menus Brev and Arkiv (§8.5) | V15, V13 |
| Plist and no scripting (§8.5) | V2, V3 |
| Synthetic-input filter in `sendEvent` and `nextEvent` (§8.5) | V32, V33, V45 |
| Launch hygiene (§8.6) | V28, V49 |
| Verify configuration and `SelfScan` (§4.1) | V39, V50 |
| Anchor against file substitution (WP9, only if built) | V52 |
| FFI surface check, forbidden-API grep, Swift harness (§11) | V45 |

## Order of a run

1. Before any launch: V1 and V2 (both builds), V45, V50, the `sdef` half of
   V3, the binary half of V21. Start the V19 stream and check that it writes.
2. With no `$D` (first run or after a reset): V36, V29, V37, then onboarding
   to the end (the first unlock is V27's one prompt with no password button),
   V40, V41.
3. Launches, with Brev quit before each: V28 (delete the global default at
   once), V49, V26, the `osascript` half of V3. On the lock screen: V27's
   *Avbryt*, V43, V48's lockout part.
4. Unlocked, with marker letters to Ekko and Speil: V42, then the capture,
   accessibility (V13 on *Send* and *Lås opp med Touch ID*), input,
   pasteboard, disk, log and lock rows, V46, V47, and V44 last.
5. With Brev quit after V44's relaunch: V17 and V41 again, so that what the
   lock, discard and quit paths wrote is scanned. Then V39 on the Verify build
   and V51 with `touchid-probe`.
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

Results go to D-0058: the macOS build, the commit, and for each row pass,
fail, or the D-entry that accepts it.

## Changes from the design

- V39 and design §8.4 step 9: `SelfScan` logs
  `selfscan u8=<n> u16=<n> glyph=<n>`. Without scribbling, UTF-8 and UTF-16
  are already 0 after lock and only glyph ids remain (§0), so without the
  glyph count V39 could not fail when `MallocScribble` or `GlyphFlush` does
  not work in the real app.
- V21: the design's `mdfind BREV-SECRET-BODY` finds this repo's own docs, so
  the row could never pass. It now ignores the checkout, has a control, and
  checks the binary for the Spotlight donation APIs.
- V13: the design's "the log shows no send, unlock or reset" names log lines
  that nothing writes. The evidence is the state of `$D`, the `AXError`, and
  a human who sees no Touch ID prompt.
