# Brev — architecture decision log

Every architectural decision is recorded here, as CLAUDE.md §1 ("ALWAYS")
requires. Entries are append-only once committed: a reversed decision gets a
new entry that points back to the old one, so the reasoning at the time stays
readable.

Each entry has:

- **Date** — when it was decided (YYYY-MM-DD).
- **Decision** — what was chosen, concretely (file names, flags, values).
- **Reasoning** — why, with the CLAUDE.md section or threat it serves.
- **Verified** — where and how it was checked, or an honest "not yet".

Numbering is `D-NNNN` and never reused.

---

## Phase 0 — scaffold (2026-09-26)

### D-0001 — Workspace lint policy; release profile left at cargo's default

- **Date:** 2026-09-26
- **Decision:** `core/Cargo.toml` sets workspace-wide
  `[workspace.lints.rust] unsafe_code = "forbid"`, `missing_docs = "warn"`
  and `[workspace.lints.clippy] all = "deny"` (priority -1 so single lints can
  still be overridden). Every crate opts in with `[lints] workspace = true`.
  `[profile.release]` is empty: no `strip`, no `lto`, no `codegen-units`,
  default `panic = "unwind"`.
- **Reasoning:** CLAUDE.md §1.7 and §6 forbid `unsafe` outside the UniFFI
  boundary and require clippy-clean code; enforcing both at the workspace
  level means a new crate cannot forget them. The release profile was first
  written with `strip = true` and `lto = true` and both were reverted during
  review: `strip` removes the ELF symbol table on Linux, and library-mode
  `uniffi-bindgen` finds its `UNIFFI_META_*` entries through that table, so
  bindings could not be generated from a release `.so`; `lto` is silently not
  applied by cargo to a unit whose crate types include `lib` (an rlib), so it
  never reached the staticlib the app links, while the working directory
  still suggested it had. Both settings belong in Phase 5 (reproducible,
  stripped, universal build) where their effect on the shipped binary can be
  measured. Panics must keep unwinding, not abort, so `Drop`-based
  zeroization of keys and plaintext still runs on the way out (§1.10).
- **Verified:** Linux, 2026-09-26: `cargo fmt --check`, `cargo clippy
  --workspace --all-targets -D warnings` and `cargo test --workspace` pass via
  `scripts/test.sh`; bindgen succeeds against the release `.so` once `strip`
  is gone.

### D-0002 — UniFFI proc-macro mode, library-mode bindgen, explicit crate-roots config

- **Date:** 2026-09-26
- **Decision:** `brev-core` uses `uniffi::setup_scaffolding!()` and
  `#[uniffi::export]` (proc-macro mode; no `.udl` file). Bindings are
  generated in library mode from the built shared library by a tool crate
  `core/uniffi-bindgen` that calls `uniffi::uniffi_bindgen_main()`. Every
  bindgen call passes `--config core/uniffi-global.toml`, which maps
  `[crate-roots] brev_core = "brev-core"`; per-crate Swift settings live in
  `core/brev-core/uniffi.toml`.
- **Reasoning:** Proc-macro mode keeps the interface next to the Rust code and
  keeps the exported surface minimal and opaque (§3.1, §6). Library mode reads
  the interface from the compiled crate, so the bindings can never drift from
  what was actually built. Generating with a workspace-local tool crate pins
  the bindgen to the exact `uniffi` version that compiled the core. The
  `[crate-roots]` map is required, not optional: the tool crate's `uniffi` is
  built with default features off (only `cli`), so the `cargo-metadata`
  discovery of per-crate `uniffi.toml` is unavailable; without the map the
  Swift module comes out misnamed (`brev_core.swift`) and the Xcode project
  cannot find it.
- **Verified:** Linux, 2026-09-26: `scripts/gen-bindings.sh` produces exactly
  `app/Generated/BrevCore.swift`, `BrevCoreFFI.h`, `BrevCoreFFI.modulemap`,
  byte-identical across runs and independent of the current directory.

### D-0003 — Swift module names, bridging-header FFI wiring, archive linked by path

- **Date:** 2026-09-26
- **Decision:** `uniffi.toml` sets `module_name = "BrevCore"`,
  `ffi_module_name = "BrevCoreFFI"`, `generate_module_map = true`. The app
  uses UniFFI's "compiled inline" path: `app/Sources/Brev-Bridging-Header.h`
  does `#import "BrevCoreFFI.h"`; `project.yml` sets
  `SWIFT_OBJC_BRIDGING_HEADER`, `HEADER_SEARCH_PATHS += $(SRCROOT)/Generated`
  and `OTHER_LDFLAGS += $(SRCROOT)/../core/target/release/libbrev_core.a`.
  There is no `-lbrev_core` and no `LIBRARY_SEARCH_PATHS` entry for
  `core/target/release`. Only the single file `Generated/BrevCore.swift` is
  added as a source, never the whole `Generated/` directory.
- **Reasoning:** Compiling the generated Swift into the app target avoids a
  separate framework or Swift package, which is the smallest thing that works.
  The generated file's `#if canImport(BrevCoreFFI)` is then false and the C
  declarations arrive via the bridging header, exactly as the UniFFI Swift
  documentation describes. Listing only the `.swift` keeps the header and
  modulemap out of the Xcode project, so the build cannot come to depend on
  them by accident (an implicit `BrevCoreFFI` module would flip that
  `canImport`). The archive is named by path because `core/target/release`
  also holds `libbrev_core.dylib` (the cdylib bindgen reads, D-0004) and ld64
  / ld-prime resolve `-lx` as `libx.dylib` before `libx.a` in the same
  directory. `-lbrev_core` would therefore bind `Brev` to a dylib outside the
  bundle whose install name is an absolute path on the build machine: the
  `.app` would not be self-contained, would stop launching after
  `cargo clean`, and Hardened Runtime library validation could reject the
  dylib. Naming the archive by path means no `-l` search happens; dropping
  the search path means a reintroduced `-lbrev_core` fails loudly. No other
  `-l` flags are needed: on Apple targets Rust's std and `libc` only pull in
  libSystem re-exports that Xcode's link driver adds anyway.
- **Verified:** Generated file names and contents checked on Linux. The Xcode
  build itself is not yet verified (D-0010); the Mac check is
  `otool -L Brev.app/Contents/MacOS/Brev` listing no `libbrev_core.dylib`.

### D-0004 — Rust staticlib, host architecture only in Phase 0

- **Date:** 2026-09-26
- **Decision:** `brev-core` has `crate-type = ["lib", "staticlib", "cdylib"]`.
  The app links the staticlib from `core/target/release` built with no
  `--target` (host arch), and `xcodebuild` is always invoked with
  `ONLY_ACTIVE_ARCH=YES` (also set in `project.yml` for both configurations)
  and a `-destination` whose arch is read from the archive (D-0011).
  Universal (x86_64 + arm64, `lipo`) builds are deferred to Phase 5.
- **Reasoning:** A universal build needs two cargo targets and a lipo step; in
  Phase 0 the goal is to prove the toolchain end to end on the developer's
  own Mac. The `cdylib` exists only so library-mode bindgen can read UniFFI
  metadata on any host (it needs a `.dylib` or `.so`); it is never shipped.
  The `lib` target is what tests and, later, the relay use.
- **Verified:** Linux: both `libbrev_core.a` and `libbrev_core.so` are
  produced by one `cargo build --release -p brev-core`.

### D-0005 — Ad-hoc signing with Hardened Runtime and App Sandbox from day one

- **Date:** 2026-09-26
- **Decision:** `CODE_SIGN_IDENTITY = "-"`, `CODE_SIGN_STYLE = Manual`,
  `DEVELOPMENT_TEAM` empty, `ENABLE_HARDENED_RUNTIME = YES`,
  `ENABLE_APP_SANDBOX = YES`, `CODE_SIGN_ENTITLEMENTS = Brev.entitlements`
  (containing only `com.apple.security.app-sandbox = true`),
  `ENABLE_USER_SCRIPT_SANDBOXING = YES`, `DEAD_CODE_STRIPPING = YES`. In
  Release only: `CODE_SIGN_INJECT_BASE_ENTITLEMENTS = NO` and
  `STRIP_INSTALLED_PRODUCT = YES`. Debug keeps Xcode's default injection of
  `com.apple.security.get-task-allow`.
- **Reasoning:** §3.2 requires Hardened Runtime, App Sandbox, library
  validation and `get-task-allow` OFF. Ad-hoc signing lets a clean checkout
  build without an Apple team while still enforcing sandbox and hardened
  runtime locally; Developer ID signing and notarization are Phase 5. Library
  validation is implied by Hardened Runtime as long as
  `cs.disable-library-validation` is never granted. Xcode injects
  `get-task-allow` into every build by default, which would let a debugger or
  agent attach and read plaintext from memory (§1.1, §2); turning injection
  off in Release keeps it out of the shipped bundle. Debug keeps it so lldb
  can attach during development, and that exception is stated in
  `project.yml` next to the setting. `STRIP_INSTALLED_PRODUCT` only takes
  effect on install/archive builds, which `scripts/build.sh` does not run, so
  the Release app it produces today is not stripped; a stripped, notarized
  build is Phase 5.
- **Verified:** Not yet; needs a Mac (`codesign -d --entitlements :- Brev.app`
  on a Release build must show only `app-sandbox`).

### D-0006 — Deployment target macOS 14.0, Swift 5 mode, AppKit only, Norwegian only

- **Date:** 2026-09-26
- **Decision:** `MACOSX_DEPLOYMENT_TARGET = 14.0`, `SWIFT_VERSION = 5.0`,
  `SWIFT_STRICT_CONCURRENCY = minimal`, development region `nb` with
  `app/Sources/nb.lproj/Localizable.strings` as the only localization. No
  SwiftUI, no storyboards, no xibs, no asset catalog in Phase 0. Bundle id
  `no.brev.app`, product `Brev`.
- **Reasoning:** macOS 14 gives cooperative activation, current
  `LAContext`/Secure Enclave behaviour and the ScreenCaptureKit semantics we
  will need to defend against (§2); supporting older releases would mean two
  sets of capture-exclusion behaviour. AppKit is required for every content
  view (§3.2), and Phase 0 has no non-content screens that would justify
  SwiftUI. Swift 5 mode avoids Swift 6 strict-concurrency churn in generated
  bindings; tightening is a later-phase item. UI language is bokmål per §3.2.
- **Verified:** Not yet compiled; needs a Mac.

### D-0007 — Window hardening flags applied already in Phase 0

- **Date:** 2026-09-26
- **Decision:** `MainWindow` (the only window class) sets `sharingType = .none`,
  `isExcludedFromWindowsMenu = true`, `isRestorable = false`,
  `titlebarAppearsTransparent = true`, title exactly "Brev", no frame autosave
  name, `isReleasedWhenClosed = false`. The main menu is built in code and has
  only the app menu with "Avslutt Brev" (⌘Q): no Edit, Services, Share,
  Window or Help menus. `applicationSupportsSecureRestorableState` returns
  true; closing the last window quits. The `ping()` reply is logged with
  `os.Logger` at `.info` (memory-only by default) and `.public` privacy, which
  is acceptable only because the string is content-free by construction.
- **Reasoning:** The window is empty in Phase 0, but every later
  content-bearing window is created through this class, so the flags cannot
  drift (§2 screenshot exclusion, §1.5 no content in titles, §1.1 nothing
  persisted, §1.3/§1.4 no Edit/Services/Share menus). Doing it now also means
  the Phase 2 manual checklist (`docs/VERIFY.md`) tests something that has
  been in place since the first build. If macOS stops honouring
  `sharingType` under ScreenCaptureKit, a second defence is to be added here
  and logged (§6).
- **Verified:** Source reviewed; runtime behaviour not yet verified on a Mac.

### D-0008 — `brev-relay` is a dependency-free placeholder until Phase 3

- **Date:** 2026-09-26
- **Decision:** `core/brev-relay` is a binary crate depending only on
  `brev-proto`; it prints that it is unimplemented. `tokio`, `axum` and
  `reqwest` are not in the workspace yet. `brev-proto` holds only
  `PROTOCOL_VERSION = 0`.
- **Reasoning:** The §3 layout should exist from the first commit so nothing
  is moved later, but pulling the async and HTTP stack in now would add
  dozens of crates to `cargo audit` and review before any code uses them
  (§1.7: audited crates only, ask before adding). The envelope type arrives
  in Phase 1.
- **Verified:** Linux: builds, tests, clippy clean; `cargo audit` reports no
  vulnerabilities over the current 81 dependencies.

### D-0009 — Info.plist and entitlements generated by XcodeGen, with explicit absences

- **Date:** 2026-09-26
- **Decision:** `Info.plist` and `Brev.entitlements` are generated from the
  `info:` and `entitlements:` blocks in `app/project.yml`; the project file
  itself is generated and gitignored. `app/Info.plist` is gitignored too (it
  is rewritten by every `xcodegen generate`); `app/Brev.entitlements` is
  checked in so the entitlement set is reviewable in a diff, and XcodeGen
  leaves it untouched when its parsed content already matches. The plist has
  `CFBundleName`, `CFBundleDisplayName`, `CFBundleIdentifier`, versions,
  `LSMinimumSystemVersion`, `NSPrincipalClass`, `CFBundleDevelopmentRegion
  nb`, `LSApplicationCategoryType`, `NSHighResolutionCapable`,
  `NSHumanReadableCopyright`. It must never contain `NSAppleScriptEnabled`,
  `NSServices`, `CFBundleDocumentTypes`, `CFBundleURLTypes`,
  `UTExportedTypeDeclarations`, `NSUserActivityTypes`,
  `NSAppleEventsUsageDescription`, any Intents/App Shortcuts key, or
  `NSMainNibFile`.
- **Reasoning:** §1.4 forbids every programmatic interface that could return
  content; each of the listed keys advertises one (scripting, Services,
  documents, URL schemes, Handoff, Shortcuts). Keeping the plist in
  `project.yml` makes the absence reviewable in one place, rather than an
  Xcode UI setting nobody notices.
- **Verified:** `project.yml` reviewed on Linux and parses as YAML; the
  generated plist has not been inspected yet (needs `xcodegen` on a Mac).

### D-0010 — Phase 0 verification status: Rust side verified on Linux, Xcode side pending

- **Date:** 2026-09-26
- **Decision:** Phase 0 is recorded as "Rust side done, Mac side pending"
  rather than "done". Nothing under `app/` has been compiled.
- **Reasoning:** The development container for this phase is Linux with cargo
  but no `xcodegen`, `xcodebuild` or `swiftc`. The Swift sources,
  `project.yml`, entitlements and build scripts were written for macOS
  14+/Xcode 15–16 from documentation and careful reading of the generated
  bindings, but §5's Phase 0 definition of done ("build.sh produces a
  runnable .app from a clean checkout; the window opens") can only be met on
  a Mac. Claiming otherwise would violate the spirit of §6.
- **Verified on Linux, 2026-09-26:** `scripts/test.sh` end to end (fmt,
  clippy with `-D warnings`, 3 tests, `cargo audit` clean, xcodebuild step
  skipped with a message); `scripts/gen-bindings.sh` from an unrelated working
  directory, idempotent on rerun; `scripts/build.sh` refuses on Linux with
  exit 1 and a pointer to `test.sh`; `docs/THREAT_MODEL.md` diffed against
  CLAUDE.md §1–§2 (identical).
- **To verify on a Mac before Phase 0 is closed:**
  1. `xcodegen generate` accepts `project.yml`; afterwards `git status` shows
     nothing new (only ignored `app/Brev.xcodeproj`, `app/Info.plist`) and
     `app/Brev.entitlements` is unchanged.
  2. `plutil -p app/Info.plist` contains none of the keys forbidden in D-0009.
  3. `scripts/build.sh` produces `app/build/Build/Products/Release/Brev.app`;
     `otool -L Brev.app/Contents/MacOS/Brev` lists no `libbrev_core.dylib`;
     `lipo -archs` of the binary equals that of `libbrev_core.a`; no
     "multiple matching destinations" warning.
  4. Release entitlements (`codesign -d --entitlements :- --xml`) contain only
     `com.apple.security.app-sandbox`; `codesign -dv` shows the `runtime`
     flag; a Debug build contains `get-task-allow` (expected).
  5. The app launches sandboxed, the window is titled "Brev", the app menu
     has only "Avslutt Brev", ⌘Q quits, closing the window quits.
  6. `/usr/bin/log stream --level info --predicate 'subsystem == "no.brev.app"'`
     (full path: `log` is a shell builtin in zsh), started before launch, shows `brev-core ping: brev-core 0.0.1 ok`
     (the line is `.info`, so Console.app hides it unless "Include Info
     Messages" is on, and `log show` after quit will not return it).
  7. Nothing appears under `~/Library/Containers/no.brev.app/Data/Library/Saved
     Application State/` after quit.
  8. ⇧⌘4 and screen recording render the window empty (`sharingType = .none`);
     any ScreenCaptureKit deviation goes into a new entry here (§6).
  9. Clean-checkout end to end: `git clone` → `scripts/build.sh` → `open`,
     then `cargo clean --release -p brev-core` and relaunch to prove the
     `.app` is self-contained.
  10. `scripts/test.sh` after `build.sh` runs the Debug compile check under
      macOS's bash 3.2, and prints the exact skip messages when the project,
      bindings or archive are missing.

### D-0011 — Build scripts: Linux-capable where possible, pinned target dir, arch read from the archive

- **Date:** 2026-09-26
- **Decision:** Three bash scripts (`set -euo pipefail`, repo root resolved
  from the script path, executable). `scripts/gen-bindings.sh` builds
  `brev-core` in release and generates the Swift bindings on macOS or Linux.
  `scripts/test.sh` runs fmt, clippy (`-D warnings`), tests, `cargo audit`
  (skipped with a loud warning if not installed) and, only on macOS with a
  working Xcode and all three link inputs present (`app/Brev.xcodeproj`,
  `app/Generated/BrevCore.swift`, `core/target/release/libbrev_core.a`), an
  `xcodebuild` Debug compile. `scripts/build.sh` refuses to run off macOS and
  otherwise chains gen-bindings → `xcodegen generate` → `xcodebuild`
  (`--debug`, `--open`). Every cargo command that builds passes
  `--target-dir core/target`. Both macOS scripts test for Xcode with
  `xcodebuild -version` (stderr visible) and pass `xcodebuild` a
  `-destination "platform=macOS,arch=$(lipo -archs libbrev_core.a)"`.
- **Reasoning:** The Rust side must be checkable on a Linux CI box without
  Xcode (§5: every phase ends with a passing `scripts/test.sh`). The
  `--target-dir` flag overrides `CARGO_TARGET_DIR` and a `[build] target-dir`
  in `~/.cargo/config.toml`, so the archive path hard-coded in `project.yml`
  is always the one cargo just wrote, never a stale copy. `/usr/bin/xcodebuild`
  is a shim present on every Mac, including Command Line Tools-only installs
  and Macs whose Xcode license is not yet accepted, so `command -v` proves
  nothing; only running it does, and its own stderr names the real cause.
  Without `-destination`, a macOS app scheme matches several destinations on
  Apple Silicon and Xcode warns "Using the first of multiple matching
  destinations"; the arch is read from the archive rather than `uname -m`
  because the two differ whenever the rustup toolchain is not native to the
  shell (an x86_64 toolchain on Apple Silicon, or an `arch -x86_64` shell),
  and a mismatch would otherwise surface only as an ld error with nothing
  naming the cause. `cargo audit` has no `--manifest-path`, so it runs in
  `core/`.
- **Verified:** Linux, 2026-09-26, as listed in D-0010; with
  `CARGO_TARGET_DIR` pointed at a scratch directory that directory stays
  empty. Not yet run on macOS.

### D-0012 — `docs/THREAT_MODEL.md` is a verbatim copy of CLAUDE.md §1–§2

- **Date:** 2026-09-26
- **Decision:** The file is a title, one line saying it is a copy to keep in
  sync, then §1 and §2 of CLAUDE.md word for word with the same numbering. It
  is not edited independently; CLAUDE.md is changed first and the copy is
  re-extracted.
- **Reasoning:** §3 asks for the copy "kept in sync". A verbatim copy can be
  checked mechanically (`diff` against the extracted sections), whereas a
  reworded version would drift silently. External reviewers get one file
  without the build instructions around it.
- **Verified:** Linux, 2026-09-26: `diff` of the extracted sections is empty.

### D-0013 — Phase 0 Mac checklist run on macOS 26.2: all ten points pass

- **Date:** 2026-09-27
- **Decision:** Phase 0 is closed. The checklist in D-0010 was run on macOS
  26.2 (25C56), Xcode 26.2 (17C52), Apple Silicon, at commit `bd41a4f`. No
  source change was needed; `sharingType = .none` stays the only capture
  defence for now.
- **Verified:**
  1. `xcodegen generate` accepted `project.yml`; `git status` clean afterwards.
  2. The generated `Info.plist` has none of the keys forbidden in D-0009.
  3. `scripts/build.sh` succeeded on the first run; no dylib linked; arm64.
  4. Release: `flags=0x10002(adhoc,runtime)`, entitlements are only
     `com.apple.security.app-sandbox`. Debug: `app-sandbox` plus
     `get-task-allow`, as expected.
  5. Window titled "Brev"; menu bar has the Apple menu and "Brev"; ⌘Q quits;
     the red close button quits and the app leaves the Dock.
  6. The log shows `brev-core ping: brev-core 0.0.1 ok`.
  7. Nothing under `Saved Application State` after three launches.
  8. With the Brev window frontmost (`CGWindowListCopyWindowInfo`: z-order 0,
     `kCGWindowSharingState` 0): a full-screen `screencapture` shows the
     desktop and the windows behind it, as if Brev were not there; a 3-second
     `screencapture -V` recording likewise; `screencapture -l <window id>`
     fails with "could not create image from window".
  9. Fresh clone from GitHub → `scripts/build.sh` → the app launches, also
     after `cargo clean --release -p brev-core`.
  10. `scripts/test.sh` passes under bash 3.2.57 including the Debug compile;
      in a fresh clone it prints the "xcodebuild skipped: run scripts/build.sh
      first; missing:" message with all three paths and exits 0.
- **Deviations and findings:**
  - The capture result is stronger than the checklist wording: the window is
    absent from the capture, not rendered empty. Only Apple's `screencapture`
    was tested; a third-party ScreenCaptureKit client was not.
  - Debug builds have no Hardened Runtime. Xcode prints "Disabling hardened
    runtime with ad-hoc codesigning" and signs with `flags=0x2(adhoc)`.
    Release is unaffected. Debug builds must never be used for the Phase 2
    verification checklist.
  - The `scripts/test.sh` Debug build lands in
    `~/Library/Developer/Xcode/DerivedData`, not under `app/build`.
  - The "Brev" menu has a second item, "Avslutt og behold vinduer". macOS
    adds it itself as the Option-key alternate of Quit. Point 7 shows that no
    window state is saved.
  - Points 5 and 8 were driven through System Events (Accessibility), which
    could read the window title and menu names, click the close button and
    send ⌘Q. That is fine while the window is empty; Phase 2 must make content
    views opaque to it and reject synthetic input (§1.2, §2).
  - `cargo-audit` is not installed on this Mac, so `test.sh` skipped the
    audit with its warning. It must be installed before Phase 1, whose
    definition of done requires `cargo audit` clean.
  - Point 6 as written failed in zsh, where `log` is a builtin; the checklist
    now says `/usr/bin/log`.

---

## Phase 0 summary

**Done (verified on Linux, 2026-09-26):** Rust workspace `core/` with
`brev-core` (`ping()` over UniFFI, proc-macro mode), `brev-proto`
(`PROTOCOL_VERSION`), `brev-relay` (placeholder) and the `uniffi-bindgen`
tool crate; workspace-wide `forbid(unsafe_code)` and `deny(clippy::all)`;
`.gitignore`; Swift bindings generation (`BrevCore.swift`, `BrevCoreFFI.h`,
`BrevCoreFFI.modulemap`) into the gitignored `app/Generated/`;
`scripts/gen-bindings.sh`, `scripts/test.sh` and `scripts/build.sh`;
`docs/THREAT_MODEL.md` (verbatim §1–§2) and this log; `README.md`.

**Written but not compiled (needs a Mac):** `app/project.yml` (XcodeGen spec
with a hardened, sandboxed, ad-hoc-signed single target),
`app/Brev.entitlements`, `app/Sources/main.swift`, `AppDelegate.swift`,
`MainWindow.swift`, `Brev-Bridging-Header.h`, `nb.lproj/Localizable.strings`.

**Definition of done status:** met on 2026-09-27. `cargo test` passes,
`scripts/build.sh` produces a runnable `.app` from a clean checkout, and the
window opens (Mac checklist in D-0010, results in D-0013). Before Phase 1:
install `cargo-audit`.
