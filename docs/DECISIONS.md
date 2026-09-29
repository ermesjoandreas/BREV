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

---

## Phase 1 — encrypted core (2026-09-27)

### D-0014 — Crates and features for the encrypted core

- **Date:** 2026-09-27
- **Decision:** `core/Cargo.toml` adds these workspace dependencies:
  `rusqlite 0.40.2` (default features off, `bundled`), `chacha20poly1305
  0.11.0` (default features off, `zeroize`), `poly1305 0.9.1` (default
  features off, `zeroize`), `x25519-dalek 3.0.0` (default features off,
  `static_secrets`, `zeroize`, `precomputed-tables`), `hkdf 0.13.0`,
  `sha2 0.11.0` (default features off, `zeroize`), `rand 0.10.3` (default
  features off, `sys_rng`), `zeroize 1.9.0`, `ed25519-dalek 3.0.0`.
  `brev-core` uses all of them except `ed25519-dalek`, which is a
  dev-dependency only (the test signer). The dev-dependency on `rusqlite`
  adds its `trace` feature (no extra crate) for the SQL trace tests.
  `poly1305` is never imported: it is a direct dependency only to turn on
  its `zeroize` feature. No serde. No `=` pins: `Cargo.lock` pins, and
  `cargo update` stays free for security fixes. `scripts/test.sh` fails if
  any `cargo tree -p brev-core` line for chacha20poly1305, chacha20,
  poly1305, x25519-dalek, curve25519-dalek, sha2 or block-buffer lacks
  `zeroize`.
- **Reasoning:** Every crate is in §4 (§1.7). The `zeroize` features are
  what make these crates wipe keys on drop (§1.10). On chacha20poly1305 the
  feature wipes the cipher key and the Poly1305 key buffer, and turns on
  chacha20's (the HChaCha subkey state). On x25519-dalek it wipes
  `StaticSecret` and `SharedSecret`. On sha2 it turns on `digest/zeroize`
  and, through feature unification, `block-buffer/zeroize`, which wipes the
  XChaCha keystream buffer. chacha20poly1305's feature does not reach
  poly1305, so the Poly1305 state was dropped unwiped until poly1305 was
  added directly (ed2cf07, once §4 approved it, D-0027). Without
  `static_secrets`, `StaticSecret` does not exist. rusqlite without default
  features drops the statement-cache crate. Memory cannot be read back
  without `unsafe`, so test.sh checks the features instead; it checks every
  line, so a second copy of a crate without the feature cannot hide behind
  the copy that has it (review round 2). The two binary layouts (envelope,
  payload) are written by hand, so serde would only add copies (P6).
- **Verified:** macOS 26.2, 2026-09-27, at `af02935`:
  `cargo tree -p brev-core -e normal -f '{p} [{f}]'` shows
  chacha20 `[cipher,xchacha,zeroize]`, chacha20poly1305 `[zeroize]`,
  poly1305 `[zeroize]`, x25519-dalek
  `[precomputed-tables,static_secrets,zeroize]`, curve25519-dalek
  `[precomputed-tables,zeroize]`, sha2 `[zeroize]`, block-buffer
  `[zeroize]`, rand `[sys_rng]`, rusqlite `[bundled,modern_sqlite]` (no
  `trace`), and no ed25519-dalek. `cargo tree -d` lists only indexmap,
  memchr, syn (2 and 3) and winnow twice; no crypto crate has two versions.
  `Cargo.lock` went from 81 packages (at `b6b0a23`) to 122.
  `cargo audit --deny warnings`: 1271 advisories, 122 crates, exit 0. The
  test.sh zeroize step passes; commit ed2cf07 records that it fails when
  poly1305's feature is removed.

### D-0015 — `uniffi-bindgen` declares rust-version 1.88; shipped crates stay at 1.85

- **Date:** 2026-09-27
- **Decision:** `core/uniffi-bindgen/Cargo.toml` sets `rust-version =
  "1.88"` instead of inheriting the workspace value (b7493d1). The
  workspace keeps `rust-version = "1.85"`, so `brev-core`, `brev-proto` and
  `brev-relay` still declare 1.85. Phase 1 adds nothing that needs a newer
  compiler.
- **Reasoning:** The tool crate's `uniffi` `cli` feature pulls in askama
  0.16.1, which needs rustc 1.88. That was already true in Phase 0, so the
  workspace's 1.85 was a false claim for this one crate. The tool crate is
  never shipped; it only generates bindings on the developer's machine. A
  build tool should not raise the minimum of the crates that ship.
- **Verified:** macOS 26.2, 2026-09-27, rustc 1.91.1:
  `cargo metadata --no-deps` reports rust-version 1.85 for
  brev-core, brev-proto and brev-relay and 1.88 for uniffi-bindgen.
  askama 0.16.1's `Cargo.toml` in `~/.cargo/registry` says
  `rust-version = "1.88"`. The highest rust-version declared by any of the
  84 packages in the brev-core and brev-proto graph (normal, build and dev
  edges) is 1.85. clippy's `incompatible_msrv` lint is on under
  `-D clippy::all` (checked with a scratch crate that uses a std API stable
  since 1.88: clippy fails it), and test.sh's clippy step passes, so no std
  API newer than 1.85 is used. Not compiled with a 1.85 toolchain after the
  review fixes, because only 1.91.1 is installed; the pre-review prototype
  passed its tests on 1.85.0.

### D-0016 — Identity id: SHA-256 over both public keys

- **Date:** 2026-09-27
- **Decision:** `IdentityId` = SHA-256(`"brev/v0/identity"` ‖ u8 length ‖
  signing key ‖ X25519 public key). The signing key is opaque and 1..=255
  bytes (`Malformed` otherwise): a 32-byte Ed25519 test key in Phase 1, the
  Secure Enclave P-256 public key later. `PublicBundle` {signing key,
  X25519 key} is everything public about an identity. The id is the
  envelope's sender or recipient and the primary key of `contacts`. Any
  Phase 3 identity code must carry at least 128 bits of the id (26 base32
  characters).
- **Reasoning:** An id that commits to both keys means nobody can swap the
  X25519 key behind a known id, and letters are bound to ids (D-0017). The
  length byte makes the encoding unambiguous. The hash is unkeyed and fast,
  so a k-bit prefix can be matched in about 2^k tries; a short identity
  code would let an attacker make a look-alike identity.
- **Verified:** macOS 26.2, 2026-09-27, passing in `scripts/test.sh`:
  `identity_id_commits_to_both_keys` (changing either key
  changes the id); `receive_rejects_strangers_misrouted_self_and_replays`
  (a 0-byte or 256-byte signing key gives `Malformed` and adds no contact;
  the own bundle as a contact gives `Malformed`);
  `signature_slot_holds_a_verifiable_signature_and_signing_can_fail`
  (`bundle().signing_key` is the test verifying key). The 128-bit rule has
  nothing to test until Phase 3.

### D-0017 — Message crypto: static-static X25519, HKDF-SHA256, XChaCha20-Poly1305

- **Date:** 2026-09-27
- **Decision:** For each message: a random 24-byte nonce; key =
  HKDF-SHA256(salt = nonce, ikm = X25519(own static secret, peer's static
  public key), info = `"brev/v0/message-key"` ‖ sender id ‖ recipient id,
  32 bytes); cipher = XChaCha20-Poly1305 with that nonce and AD = the
  envelope header (D-0018). A non-contributory (low-order) DH result gives
  `Crypto`. The tag is checked before anything is decrypted. No ephemeral
  keys, no ratchet.
- **Reasoning:** The §5 envelope has no field for an ephemeral key, and
  static-static authenticates the sender (only the two parties can compute
  the key), which matters while clients do not verify signatures (D-0019).
  The nonce is also the salt, so each key is used once. The ids in `info`
  and in the AD bind the key to both identities, which stops redirection,
  reflection and unknown-key-share. Known costs, accepted for now:
  - The key is symmetric, so a sender can decrypt its own envelopes.
  - Whoever holds one party's X25519 secret can read all recorded traffic
    between that party and every contact, in both directions, and can forge
    letters *to* that party (key-compromise impersonation).
  - No forward secrecy.

  Ephemeral-static would protect nothing extra today: the sender's secret
  sits under the same DEK as the sender's stored copy of every letter. That
  holds only while every sent letter is kept. Message deletion or
  disappearing letters would require ephemeral-static or a ratchet.
- **Verified:** macOS 26.2, 2026-09-27, passing in `scripts/test.sh`:
  `round_trip_a_encrypts_b_decrypts`;
  `tamper_any_flipped_byte_fails` (a flipped bit in every ciphertext byte,
  and in the nonce, gives `Crypto`);
  `only_the_two_parties_can_open_a_message` (a third party, and the sender
  given the header with sender and recipient swapped, get `Crypto`);
  `a_letter_is_bound_to_both_ids` (another sender or recipient id with the
  same keys gives `Crypto`); `low_order_public_key_is_rejected`;
  `every_seal_uses_a_fresh_nonce`. That a sender can open its own envelope
  was shown by a probe during design; no test pins it.

### D-0018 — Envelope layout

- **Date:** 2026-09-27
- **Decision:** `brev_proto::Envelope` = {sender [32], recipient [32],
  nonce [24], ciphertext (payload ‖ 16-byte tag), signature (opaque bytes)}.
  `header_bytes` = `"BREV"` ‖ `PROTOCOL_VERSION` (u16 BE, still 0) ‖ sender
  ‖ recipient ‖ nonce, 94 bytes (`HEADER_LEN`). The AEAD AD is the header;
  the signed bytes are header ‖ ciphertext. No wire encoding in Phase 1:
  `MockTransport` moves `Envelope` values.
- **Reasoning:** These are exactly the fields §5 asks for. Every field but
  the last has a fixed length, so the signed bytes are unambiguous without
  length prefixes. `"BREV"` ‖ version is the signing-domain prefix; Phase
  3's own signed relay requests must use a different one. Phase 3 picks
  the wire encoding under one rule: the relay must be able to rebuild
  `signed_bytes` byte for byte. The version stays 0 because nothing has
  been released.
- **Verified:** macOS 26.2, 2026-09-27, passing in `scripts/test.sh`:
  `signed_bytes_layout_is_fixed` (offsets of magic, version,
  both ids, nonce and ciphertext); `tamper_any_flipped_byte_fails`;
  `no_plaintext_in_any_file` (no marker in `signed_bytes` ‖ `signature`).

### D-0019 — Signature slot filled through a fallible `Signer`; not verified by the core in Phase 1

- **Date:** 2026-09-27
- **Decision:** `send` takes `&dyn Signer`
  (`fn sign(&self, &[u8]) -> Result<Vec<u8>, Error>`). It seals the letter
  first, drops every decrypted value and the X25519 secret, scrubs the
  stack, then signs `signed_bytes()`, and only then stores its own copy. A
  refused signature gives `Signing` and stores nothing. `receive` does not
  check the signature in Phase 1; the key agreement authenticates the
  sender (D-0017). Phase 3 signs through the two-step
  `sign_request`/`attach_signature` flow of §5, built on
  `Envelope::signed_bytes` and `Envelope::signature`, not through a Swift
  `Signer`. The envelope does not change.
- **Reasoning:** §5 asks for an Ed25519 test key in Phase 1; the trait
  keeps that key in the tests (P2). A signer called inside
  `send(&mut self)` blocks `lock()` while it runs, and a Touch ID prompt
  can take seconds. The ordering makes sure nothing secret is alive then;
  the two-step flow will let auto-lock run during the prompt. Client-side
  verification needs a P-256 verifier, which comes in Phase 3 (`p256`,
  D-0027).
- **Verified:** macOS 26.2, 2026-09-27, passing in `scripts/test.sh`:
  `signature_slot_holds_a_verifiable_signature_and_signing_can_fail`
  (`verify_strict` passes on the envelope and fails after one ciphertext
  bit flip; a refusing signer gives `Signing` and the thread still has one
  message); `nothing_decrypted_is_alive_while_signing` (inside the signer,
  the test-build counters of live `Plaintext` values and live X25519
  secrets both read 0; positive controls show each counter sees a
  decrypted subject, an encoded payload and a decrypted identity). Review
  rounds 1 to 3 widened this test from `Plaintext` only to the payload and
  the secret.

### D-0020 — Payload, message ids and the receive checks

- **Date:** 2026-09-27
- **Decision:** Payload (inside the message AEAD) = message id [16] ‖
  thread id [16] ‖ subject length (u16 BE) ‖ subject ‖ body. The sender
  picks both ids at random; the message id is the primary key in both
  stores. A thread belongs to one contact. `receive` checks, in this order:
  addressed to this identity (`Malformed`), sender is a contact
  (`NotFound`), AEAD (`Crypto`), payload shape (`Malformed`), and for a
  known thread that its authenticated owner is the sender (`Malformed`).
  Then one transaction inserts the thread (if new) and the message with
  `ON CONFLICT(id) DO NOTHING`; zero rows gives `Duplicate` and rolls back.
- **Reasoning:** Sender-chosen ids make dedupe work across both stores.
  Dedupe runs only after authentication, so a stranger cannot block an id.
  A failed envelope stores nothing. No payload is ever stored (each store
  keeps per-column ciphertext), so Phase 3 can extend the payload, for
  example with a sender timestamp or padding, without a migration.
- **Verified:** macOS 26.2, 2026-09-27, passing in `scripts/test.sh`:
  `payload_round_trip_and_truncation`;
  `receive_rejects_thread_owned_by_another_contact` (a real contact naming
  another contact's thread gets `Malformed`; with the thread re-pointed at
  it in the file, `Crypto`; the thread keeps one message);
  `failed_receive_leaves_no_new_thread` (a stored message id under a new
  thread id gives `Duplicate` and no new thread);
  `receive_rejects_strangers_misrouted_self_and_replays` (stranger
  `NotFound`, misaddressed `Malformed`, replay `Duplicate` with one message
  stored; `new_thread` with a subject over 65535 bytes gives `Malformed`
  and makes no thread; `mark_read` of an unknown id gives `NotFound`).

### D-0021 — Column encryption under the DEK, bound to each row's immutable fields

- **Date:** 2026-09-27
- **Decision:** Every content column is `nonce [24] ‖ ciphertext ‖ tag
  [16]`: XChaCha20-Poly1305 under the DEK, with a fresh OS-random nonce on
  every write. AD = `"brev/v0/column/"` ‖ label ‖ 0x00 ‖ fixed-length
  fields:
  - `identity.keys`: own id;
  - `contacts.bundle`, `contacts.name`: contact id;
  - `threads.subject`: thread id, contact id, `created_at`;
  - `messages.body`: message id, thread id, the thread's contact id (by
    join), `outgoing`, `created_at`.

  `read` is mutable and not bound. `send` opens the thread's subject before
  it encrypts to the thread's contact, `receive` opens a known thread's
  subject before trusting its owner, and `new_thread` opens the contact's
  bundle first.
- **Reasoning:** A filesystem agent can edit plaintext metadata. With every
  immutable field in the AD, moving a ciphertext to another row or column,
  or editing a bound field, makes the next read fail with `Crypto` instead
  of showing content under the wrong contact, thread or direction. Opening
  the subject first means a redirected thread gives `Crypto` and no
  envelope. Random nonces need no counter, so restoring an old file cannot
  cause nonce reuse. Not added (offered in review round 1): a check in
  `contact_bundle` that the decoded bundle hashes to the row id. The AD
  already catches a swapped bundle, and the extra check would make the
  tests unable to tell which defence caught it.
- **Verified:** macOS 26.2, 2026-09-27, passing in `scripts/test.sh`:
  `column_round_trip_and_ad_binding` (another row's AD, another column's
  AD, another DEK: `Crypto`); `every_seal_uses_a_fresh_nonce`;
  `round_trip_a_encrypts_b_decrypts` (`mark_read` sets only that message's
  flag, and its body still opens); `stored_metadata_is_bound_to_ciphertext`,
  which edits the file with raw rusqlite: a thread re-pointed at another
  contact (`send`, `threads`, `read_body` give `Crypto`, no envelope); a
  message moved to a thread of another contact and to one of the same
  contact; `outgoing` flipped; a message's `created_at` raised by one; a
  thread's `created_at` raised by one; subject and time swapped between two
  threads of one contact; `contacts.bundle` swapped between two contacts
  (`send` and `new_thread` give `Crypto`); `contacts.name` swapped
  (`contacts` gives `Crypto`); a body copied between rows; a subject copied
  into `contacts.name`; `identity.id` edited (`unlock` gives `WrongKey`).
  Every edit that is undone reads back again. Review round 1 (91f1803)
  added most of these.

### D-0022 — Schema v1

- **Date:** 2026-09-27
- **Decision:** Four `STRICT` tables, `identity (id, keys)`,
  `contacts (id, bundle, name)`,
  `threads (id, contact_id, created_at, subject)` and
  `messages (id, thread_id, created_at, outgoing, read, body)`, plus the
  index `messages_by_thread (thread_id, created_at)`. `create` writes, in
  one transaction: `application_id = 0x42524556` ("BREV"), the schema, the
  identity row, `user_version = 1`. Plaintext is only ids, `created_at`,
  `outgoing`, `read`, `application_id` and `user_version`; names, subjects,
  bodies
  and even public keys are ciphertext (P4). `identity.keys` holds X25519
  secret (32) ‖ X25519 public key (32) ‖ signing public key. The identity
  row is also the wrong-DEK check: `unlock` opens it, and a failed tag
  gives `WrongKey`. `messages()` returns metadata and decrypts nothing;
  `read_body` decrypts one body.
- **Reasoning:** §3.1 allows only queryable metadata in plaintext, never
  subjects or bodies. `STRICT` stops a content column from silently holding
  TEXT. Encrypting the public keys too keeps the rule free of exceptions.
  The X25519 public key sits next to the secret (review round 2, b35bab7)
  so that `bundle()` and `unlock()` never rebuild the secret. The key check
  needs no extra column; a false accept has a chance of about 2^-128.
  `SCHEMA_VERSION` stayed 1 through that layout change because no store has
  shipped. Dev stores created before b35bab7 now fail to open with
  `Corrupt`, because the schema text changed (D-0023).
- **Verified:** macOS 26.2, 2026-09-27, passing in `scripts/test.sh`:
  `pragmas_are_applied` (application_id, user_version 1);
  `stored_metadata_is_bound_to_ciphertext` (`messages()` of a thread lists
  only that thread's messages);
  `no_plaintext_in_any_file` (three markers go in as name, subject and body
  and read back through the API; every file in the store directory is
  scanned with connections open and again after close, and none is found;
  positive controls: A's plaintext id is found, and a marker written with
  raw rusqlite is found); `sqlite_never_receives_plaintext` (every
  statement on both cores is traced with bound values expanded: more than
  10 statements, no marker as text or hex; positive control: `SELECT ?1`
  with the marker is seen); `lock_zeroes_the_dek_buffer` (`unlock` and
  `bundle()` leave the counter of built X25519 secrets unchanged).

### D-0023 — SQLite connection and file hardening

- **Date:** 2026-09-27
- **Decision:**
  - `create` and `open` accept only absolute paths. Any other path gives
    `Malformed` and touches no file.
  - `create` refuses an existing path (`OpenOptions::create_new`, so
    `Io(AlreadyExists)`) and removes the new file if a later step fails.
  - Connections open with `READ_WRITE | NO_MUTEX`, never CREATE.
  - On every connection: `DBCONFIG_DEFENSIVE` on,
    `DBCONFIG_TRUSTED_SCHEMA` off, `secure_delete = ON`,
    `temp_store = MEMORY`, `foreign_keys = ON`, `cell_size_check = ON`,
    `fullfsync = ON`.
  - `open` refuses with `Corrupt`, before writing anything, unless
    `application_id` and `user_version` match and
    `SELECT type, name, tbl_name, sql FROM sqlite_schema` equals the same
    query on an in-memory database built from `SCHEMA`. A file SQLite
    cannot parse (NotADatabase, DatabaseCorrupt, or plain SQLITE_ERROR for
    an unsupported schema format) is `Corrupt` too, not `Storage`.
  - Only after that check, `journal_mode = DELETE` is set and read back
    (`Corrupt` if the answer is not `delete`).
- **Reasoning:**
  - The bundled SQLite is compiled with `-DSQLITE_USE_URI`, so a name that
    starts with `file:` is parsed as a URI whatever the open flags say; a
    design probe opened `file:<abs>?mode=ro` read-only. Turning URIs off
    needs `sqlite3_config`, which is unsafe FFI (P5). An absolute path
    starts with `/` and is always taken literally.
  - DEFENSIVE, trusted_schema off, cell_size_check and the exact schema
    check limit what a crafted file can do; a planted trigger, view, index
    or altered table is refused.
  - `secure_delete` zero-fills freed cells. They only ever held ciphertext
    or metadata, but this limits recovery of old ciphertext if the DEK
    leaks later. `temp_store = MEMORY` keeps sorters and statement journals
    out of `$TMPDIR`.
  - DELETE mode means no `-wal` or `-shm` file, ever; `-journal` exists
    only during a write and holds only what SQLite was given. WAL mode is
    saved in the file, so `open` switches back a store an agent set to WAL.
  - `fullfsync` (review round 2): macOS `fsync(2)` flushes to the drive
    but not the drive's own cache, which may write late and out of order
    (its man page says so). A power cut mid-commit could corrupt the only
    copy of the history. Commits get slower; letters are rare.
  - Cost of the exact schema check: it compares SQL text, comments
    included, so any edit to `SCHEMA`, even a comment, needs a
    `user_version` bump and a migration.
- **Verified:** macOS 26.2, 2026-09-27, passing in `scripts/test.sh`:
  `pragmas_are_applied` reads back journal_mode `delete`,
  secure_delete 1, temp_store 2, foreign_keys 1, cell_size_check 1,
  fullfsync 1, trusted_schema 0 and DEFENSIVE on.
  `create_and_open_refuse_bad_files`: `file:u.db`, `file:<abs>?mode=ro`,
  `u.db`, `:memory:` and `""` give `Malformed` from both calls and make no
  file; a `file:` URI naming a real store is refused, not opened
  read-only; `create` on an existing store gives `AlreadyExists` and
  leaves its bytes unchanged; a directory at `<path>-journal` makes
  `create` fail after the file exists, and the file is removed; a foreign
  SQLite file, a WAL-mode foreign file, random bytes, a truncated store and
  a header naming schema format 5 each give `Corrupt` with their bytes
  unchanged; a wrong application_id or user_version, an
  `ALTER TABLE … ADD COLUMN` and a planted trigger give `Corrupt`; `open`
  on a missing path creates nothing.
  `open_turns_a_wal_store_back_to_delete_mode` (after a write only `a.db`
  exists). `no_plaintext_in_any_file` (after close only `a.db` and `b.db`
  exist). `libsqlite3-sys-0.38.2/build.rs` line 167 passes
  `-DSQLITE_USE_URI`; the bundled SQLite is 3.53.2.

### D-0024 — The DEK, the lock state and zeroization

- **Date:** 2026-09-27
- **Decision:**
  - The DEK lives in one `Box<Zeroizing<[u8; 32]>>` per `Core`, allocated
    once and never moved. `create` and `unlock` copy the caller's
    `&mut [u8; 32]` into it and zero the caller's array before any step
    that can fail.
  - All zeros is never a key: `create` refuses it (`Malformed`), `unlock`
    refuses it (`WrongKey`). A wiped buffer is all zeros, so a retry with
    one cannot seal or open a store.
  - The state is `unlocked: bool` plus that box; `open` starts locked.
    Every call except `create`, `open`, `unlock`, `lock` and `is_locked`
    goes through one gate (`dek()`) and returns `Locked` while locked. That
    includes `messages`, `mark_read` and `bundle`, which return no content,
    because one rule is easier to audit than a list.
  - `lock()` zeroes the box in place, marks the core locked and scrubs the
    stack. It cannot fail and can be repeated. Every failed `unlock` locks,
    also a core that was unlocked.
  - The core caches no key and no plaintext between calls, so the
    "cached plaintext" that §3.1 wipes on lock is the empty set. The X25519
    secret is built for one operation (`init`, `send`, `receive`) inside a
    block that ends before signing (`send`) or before the commit (`init`,
    `receive`). `unlock` and `bundle` never build it.
  - `scrub_stack()` overwrites 16 KiB of stack after every AEAD, DH, HKDF
    and X25519 base-point operation, in `me()`, before signing, and in
    `lock()`. It is best effort.
  - The DEK test accessors are `#[cfg(test)]` private methods, stricter
    than the debug-only accessor §5 allows.
- **Reasoning:** §3.1 and §1.10: when locked, the DEK and all plaintext
  are gone and every content call fails. A box at a fixed address means
  `lock()` wipes the only copy, and a test can check the address. Zeroing
  the caller's copy first means the wipe happens on every exit path. Some
  key-equivalent stack copies inside the crates cannot be wiped without
  `unsafe` (the HChaCha20 state, the HKDF PRK, x25519-dalek's by-value
  secret copies). The product owner accepted them as residual risk in
  CLAUDE.md §2 (8c461b2), with `scrub_stack()` as the mitigation.
- **Verified:** macOS 26.2, 2026-09-27, passing in `scripts/test.sh`:
  `lock_zeroes_the_dek_buffer`: after `create` the caller's
  array is zero and the box holds the DEK; after `lock()` the box is zero
  at the same address; a wrong `unlock` zeroes its argument and leaves the
  core locked with a zero box; the right DEK restores it at the same
  address; an all-zero `unlock` on an unlocked core locks it; so does a
  failure unrelated to the key (identity row deleted, `NotFound`).
  `unlock_refuses_all_zero_dek` (a store sealed under zeros, built through
  the private `init`). `locked_core_refuses_every_content_call`: all 11
  gated methods give `Locked`; a locked `mark_read` writes nothing; a
  reopened store starts locked; `unlock` zeroes the right DEK after use.
  Compile-time checks that the DEK box and `Plaintext`'s buffer are
  `ZeroizeOnDrop` (in `lock_zeroes_the_dek_buffer` and
  `plaintext_wipes_on_drop`); `init` builds the identity row as a
  `Plaintext` too. `nothing_decrypted_is_alive_while_receive_commits`
  (live `Plaintext` and secret counters read 0 at both COMMITs).
  `create_and_open_refuse_bad_files` (the DEK is zeroed on the `Io`,
  relative-path and empty-key refusals; a retry with the wiped buffer gives
  `Malformed` and makes no file). `scrub_stack_wipes_its_buffer` passes in
  debug and in `--release`; commit 8c461b2 records that the release run
  fails (16384 != 0) with the wipe removed. `init`'s block scoping has no
  test: `init` opens its own connection, so no trace hook can watch its
  commit without `unsafe` (review round 3); it holds by structure.

### D-0025 — Content API: bytes in, `Plaintext` out

- **Date:** 2026-09-27
- **Decision:** Content goes in as `&[u8]` and comes out as `Plaintext`, a
  wrapper around `Zeroizing<Vec<u8>>` with a private field and only
  `Deref<Target = [u8]>`: no `Debug`, `Clone` or `DerefMut`. `Contact` and
  `Thread` hold `Plaintext` and have no `Debug`. `Message` is metadata
  only. UTF-8 is not checked. Content is never a `String` (P6); the only
  `String`s in the core are schema rows, the journal-mode readback and the
  `ping()` reply. No `Error` variant carries content: every message is
  static except the wrapped io and SQLite errors, and SQLite only ever
  sees ids, metadata and ciphertext. Internal plaintext buffers are
  allocated at their final size, checked with `debug_assert_eq!` on the
  capacity. The UniFFI surface is still only `ping()` (P1).
- **Reasoning:** A bare `Zeroizing<Vec<u8>>` is `Debug` (content in
  `{:?}`, `dbg!`, panic messages) and `DerefMut<Vec>` (growing it frees an
  unwiped copy). A read-only type that cannot be printed closes both.
  Listing a thread should not decrypt every body (§1.10). Phase 2 designs
  the FFI shape.
- **Verified:** macOS 26.2, 2026-09-27, passing in `scripts/test.sh`:
  three doctests on `Plaintext`: a positive control that
  reads one through the public path, and two `compile_fail` tests
  (`format!("{p:?}")` and `p.push(0)`). `sqlite_never_receives_plaintext`.
  After `scripts/gen-bindings.sh`,
  `nm -gU core/target/release/libbrev_core.dylib` shows one UniFFI
  function, `uniffi_brev_core_fn_func_ping`.

### D-0026 — `Transport`, `MockTransport` and `receive_all`

- **Date:** 2026-09-27
- **Decision:** `trait Transport { fn send(&self, Envelope); fn poll(&self)
  -> Vec<Envelope>; }`, the §3.1 shape. `MockTransport::pair()` returns two
  ends cross-wired through two `Arc<Mutex<Vec<Envelope>>>` queues; `poll`
  drains the queue. It ships in the library, not under `cfg(test)`, for
  Phase 2's two hard-coded contacts, and has no adversary hooks. `Core`
  does not own a transport: sending is `net.send(core.send(..)?)`.
  `Core::receive_all(&dyn Transport)` is the receive loop. It returns
  `Locked` before polling, handles each envelope on its own, and returns a
  content-free `Delivery { received, rejected }`.
- **Reasoning:** A caller-written `for e in poll() { receive(&e)? }` would
  lose every envelope after the first bad one, because `poll` has already
  drained them. Handled one by one, a replay, a stranger or a tampered
  letter never costs the letters behind it. Gating before `poll` means a
  locked core drains nothing. Delivery is at most once, like the Phase 3
  relay's delete-after-delivery: an envelope that fails for a local reason
  (disk full) is reported and lost, so Phase 3 needs
  acknowledge-after-store. A poisoned mutex is recovered, because the queue
  only holds ciphertext.
- **Verified:** macOS 26.2, 2026-09-27, passing in `scripts/test.sh`:
  `receive_all_isolates_bad_envelopes_and_waits_while_locked` (a queue of
  replay, stranger, tampered and good gives one received letter that reads
  back, and rejected `[Duplicate, NotFound, Crypto]`; while
  locked, `Locked` and nothing drained; after unlock the waiting letter is
  stored); `round_trip_a_encrypts_b_decrypts` (two cores over
  `MockTransport::pair()`, both directions);
  `core_and_transport_can_move_between_threads` (`Core: Send`,
  `MockTransport: Send + Sync`).

### D-0027 — Product-owner decisions made during Phase 1

- **Date:** 2026-09-27
- **Decision:** The product owner changed CLAUDE.md (664e23c, 8c461b2), and
  `docs/THREAT_MODEL.md` was re-synced:
  - §1.5 and §3.2: a notification says exactly "Ny melding": no sender
    name, no content. Contact names stay encrypted.
  - §4: `p256` (feature `ecdsa`) is approved. From Phase 3, `brev-core`
    verifies the Enclave P-256 signature on receive and the relay verifies
    it too; Swift only signs.
  - §4: `poly1305` is approved, feature `zeroize` only (used in D-0014).
  - Phase 3 padding: the payload is padded before encryption, in
    `brev-proto`, to 256 B / 1 KiB / 4 KiB / 16 KiB and above that to the
    next multiple of 16 KiB, with a length prefix. Hard maximum 1 MiB
    padded, enforced by app and relay. Tests for equal length within a
    bucket and for boundary sizes. A TODO in `brev-proto/src/lib.rs`
    records it.
  - §2: the transient stack copies of D-0024 are accepted residual risk.
- **Reasoning:** These answer open questions from the Phase 1 design. The
  old notification text, "Ny melding fra <navn>", needed a contact name,
  but names are ciphertext under the DEK (P4), and the DEK is gone while
  the app is locked. Verification in Rust needed a P-256 crate, which was
  not in §4. Wiping the Poly1305 state needed poly1305 as a direct
  dependency, which was not in §4 either.
- **Verified:** macOS 26.2, 2026-09-27: CLAUDE.md §1–§2 (extracted with
  `awk`) diffed against `docs/THREAT_MODEL.md`:
  identical apart from one trailing blank line left by the extraction.
  `cargo tree` shows `poly1305 [zeroize]`. `p256` is not in `Cargo.lock`
  yet (Phase 3). The notification rule has no code until Phase 2.

### D-0028 — macOS facts found while verifying Phase 1

- **Date:** 2026-09-27
- **Decision:** Record two facts. Neither is fixed in Phase 1.
  1. The bundled SQLite object in `libbrev_core.a` is built for macOS 26.2
     (the installed SDK), while the app's deployment target is 14.0.
     Linking the app prints `ld: warning: object file
     (…/libbrev_core.a[46](…-sqlite3.o)) was built for newer 'macOS'
     version (26.2) than being linked (14.0)`. `MACOSX_DEPLOYMENT_TARGET`
     was not set in the shell. Proposed fix, at the start of Phase 2: set
     `MACOSX_DEPLOYMENT_TARGET=14.0` for the cargo build in
     `scripts/gen-bindings.sh` (which `build.sh` calls), to match
     `project.yml`, and check that the warning is gone.
  2. The `xcodebuild` step of `scripts/test.sh` links whatever
     `core/target/release/libbrev_core.a` exists. test.sh does not rebuild
     that archive (its release step builds only a test binary);
     `gen-bindings.sh` does. On the first test.sh run for this entry, the
     archive was older than the three review rounds. Run
     `scripts/gen-bindings.sh` first when the Xcode check should cover the
     current core.
- **Reasoning:** §6 asks for macOS surprises to be written down. With (1),
  the app claims to run on macOS 14 but contains C code compiled for 26.2.
  It has not been run on an older macOS, so whether it fails there is
  unknown. In Phase 1 the app only calls `ping()`, so nothing in it calls
  SQLite yet. (2) is why the warning did not appear on the first run.
- **Verified:** macOS 26.2 (25C56), Xcode 26.2 (17C52), Apple Silicon,
  rustc 1.91.1, 2026-09-27, at `af02935`. A first `scripts/test.sh` run
  passed with no warning, and the archive kept its 14:49 timestamp (the
  review rounds were committed between 15:13 and 16:48).
  `scripts/gen-bindings.sh` then `scripts/test.sh`: exit 0, with the
  warning above. `otool -l` on the `sqlite3.o` taken from the
  archive: `minos 26.2`, `sdk 26.2`; on a `brev_core` object from the same
  archive: `minos 11.0`. `otool -L` on the Debug `Brev.app` lists no
  `libsqlite3`, and `nm` finds 294 `_sqlite3_` symbols in
  `Brev.debug.dylib`: SQLite is linked statically. `nm -gU` on the archive
  shows it exports 282 `_sqlite3_*` functions, so the app must never also
  link the system `libsqlite3`.

### D-0029 — Follow-ups after the review: `scrub_stack` call sites tested, SQLite built for macOS 14.0

- **Date:** 2026-09-27
- **Decision:**
  1. `scrub_stack()` counts its calls in test builds (a thread-local, like
     the other test counters in D-0024). Two tests pin the call sites:
     `public_key`, `seal_column`, `open_column`, `seal_message` and
     `open_message` scrub exactly once each; `me()` and `lock()` add one
     of their own. This closes the deferred review finding "no test checks
     that it is called".
  2. `scripts/gen-bindings.sh` exports `MACOSX_DEPLOYMENT_TARGET=14.0` on
     macOS before the cargo build, matching `app/project.yml`. This fixes
     D-0028 item 1 now instead of in Phase 2. `scripts/test.sh` exports
     the same value, so its release test shares one SQLite build with the
     archive instead of rebuilding it.
- **Reasoning:** The product owner asked for a release test that proves
  `scrub_stack()` actually runs (D-0027). The release test proves the wipe
  survives the optimiser; without the counter, removing the calls would
  still pass. The deployment target matters because the app claims macOS
  14 and now contains C code (SQLite).
- **Verified:** macOS 26.2, 2026-09-27, at `ea95ae0`: removing the scrub
  in `me()`, or the one in `open_column`, fails the new tests (1 != 2, and
  the per-operation count). After `scripts/build.sh`, `otool -l` on
  `sqlite3.o` from `libbrev_core.a` shows `minos 14.0`, the app binary
  `minos 14.0`, and the linker warning is gone. The remaining objects with
  `minos 11.0` are Rust's own precompiled ones, which are older than 14.0
  and therefore fine. The app launches and logs
  `brev-core ping: brev-core 0.0.1 ok`. `scripts/test.sh` exits 0.

---

## Phase 1 summary

**Built (2026-09-27, commits `0fa9fae` to `ea95ae0`):**

- `brev-proto`: `Envelope`, `HEADER_LEN`, `header_bytes`, `signed_bytes`
  (D-0018), and the Phase 3 padding TODO (D-0027).
- `brev-core/src/crypto.rs`: OS randomness, the identity id, column and
  message sealing, HKDF, `Plaintext`, `scrub_stack` (D-0016, D-0017,
  D-0021, D-0025).
- `brev-core/src/store.rs`: `Core` with `create`, `open`, `unlock`, `lock`,
  the encrypted SQLite store, contacts, threads, messages, `send`,
  `receive`, `receive_all` (D-0019 to D-0024).
- `brev-core/src/transport.rs`: `Transport` and `MockTransport` (D-0026).
- `brev-core/src/lib.rs`: `Error`, `Signer` and re-exports. `ping()` is
  still the only UniFFI export.
- `scripts/test.sh`: a release run of the scrub test, and the zeroize
  feature check.
- Tests: 37 in `cargo test --workspace` (brev-core: 21 unit, 11
  integration, 3 doctests; brev-proto: 2), plus the release scrub test.
  0fa9fae had 25; the review and D-0029 added the rest.

**Review:** three rounds after `0fa9fae` (`91f1803`, `b35bab7`,
`af02935`). Each applied finding is in the entry it belongs to. The code
changes: files SQLite cannot parse give `Corrupt`; `unlock` and `bundle`
never build the X25519 secret (the identity row now also holds the public
key); `fullfsync`; the secret and the decrypted letter are dropped before
`receive` and `init` commit. The rest are tests: every AD binding, nonce
freshness, the send ordering (now counting the payload and the secret),
the failure paths of `create`, `open`, `unlock` and `receive`, and the
wipe-on-drop types. Two deferred findings, both saying the send-ordering
test counted only `Plaintext`, were closed by rounds 2 and 3. One item was
skipped: a test of `init`'s commit-time scoping (D-0024).

**Definition of done status (CLAUDE.md §5, Phase 1): met on 2026-09-27.**
Checked with `scripts/gen-bindings.sh` then `scripts/test.sh` at
`af02935` on macOS 26.2, exit 0, and again with `scripts/build.sh` then
`scripts/test.sh` at `ea95ae0`.

- Data model, encrypted SQLite store, DEK column encryption,
  `Locked`/`Unlocked` state machine and zeroization: D-0020 to D-0025.
- X25519 + HKDF + XChaCha20-Poly1305 for bodies; an envelope with sender
  id, recipient id, ciphertext, nonce and signature slot; an Ed25519 test
  key: D-0017 to D-0019.
- `MockTransport` between two `Core`s in one process:
  `round_trip_a_encrypts_b_decrypts` and
  `receive_all_isolates_bad_envelopes_and_waits_while_locked`.
- Round-trip test: `round_trip_a_encrypts_b_decrypts`.
- Tamper test: `tamper_any_flipped_byte_fails` (every ciphertext byte,
  plus the nonce).
- No-plaintext test: `no_plaintext_in_any_file`, backed by
  `sqlite_never_receives_plaintext`.
- Lock test: `locked_core_refuses_every_content_call` (`Err(Locked)`) and
  `lock_zeroes_the_dek_buffer` (DEK memory zeroed, through a
  `#[cfg(test)]` accessor).
- All tests pass: fmt, clippy `-D warnings`, the 37 tests, the release
  scrub test, the zeroize check and the Xcode Debug compile.
- `cargo audit` clean: `cargo audit --deny warnings` exits 0 over 122
  crates and 1271 advisories.
- No `unsafe` outside the UniFFI boundary: `unsafe_code = "forbid"` for
  the workspace and `#![forbid(unsafe_code)]` in each crate root; a grep
  of the hand-written sources finds `unsafe` only in those attributes and
  in comments.

**Residual risks and limits**

What the tests cannot prove:

- Stack and register residue inside the crypto crates (D-0024), accepted
  in CLAUDE.md §2. The release test proves `scrub_stack()`'s wipe
  survives the optimiser, and a test counter proves each crypto operation
  calls it (D-0029). What it cannot prove is that the wipe reaches every
  stale copy.
- The send and receive orderings are tested for live values (counters),
  not for dead stack copies. `init`'s ordering holds by structure only.
- Returned plaintext: `lock()` cannot wipe a `Plaintext` the caller still
  holds, and a caller can copy one out with `to_vec()`. Phase 2 must drop
  them on lock and when a message is closed.
- The no-plaintext evidence covers the store directory and everything
  given to SQLite on the core's connections. It says nothing about OS
  copies (page cache, swap, APFS snapshots, Time Machine), which hold
  ciphertext anyway. `temp_store = MEMORY` is checked by readback only.

Accepted for Phase 1:

- No forward secrecy; symmetric static keys; key-compromise impersonation
  until clients verify signatures in Phase 3 (D-0017).
- The relay can reorder, delay and drop envelopes, and nobody notices.
  `created_at` is local time at each end, so the two sides can order a
  thread differently. Phase 3 should add a sender timestamp, and a
  per-sender sequence number if drops should be detected.
- At-most-once delivery (D-0026).
- A filesystem agent can restore an older file, delete rows, add fake
  message rows (they are listed, but `read_body` fails) or flip `read`.
  Edits to content and bound metadata are caught on read; there is no
  freshness guarantee.
- Visible metadata. On disk: the contact graph, counts, timestamps,
  direction, read state and exact content lengths. To the relay: sender and
  recipient ids, timing, and exact envelope length until Phase 3 padding.
- Replay dedupe keys on the message id. Only the original sender can
  re-encrypt a letter under a new id.
- A contact's bundle is trusted as given to `add_contact`; out-of-band
  checking of identity codes is Phase 3.
- A corrupted identity row looks the same as a wrong DEK (`WrongKey`).

Store lifecycle (deferred review findings):

- `create` is not crash-atomic. A crash between making the file and the
  commit leaves a file that `create` (`AlreadyExists`) and `open`
  (`Corrupt`) both refuse. Phase 2 onboarding must handle it.
- The schema check compares SQL text, comments included (D-0023). Any edit
  to `SCHEMA`, even a comment, makes every existing store `Corrupt`, while
  all tests, which create fresh stores, still pass. This has happened once
  already: dev stores created before `b35bab7` no longer open (D-0022).

Supply chain and platform:

- The RustCrypto and dalek major versions in use are newer than their
  known audits.
- The SQLite parser still runs over a file an attacker can write. D-0023
  limits this; it does not remove it.
- The staticlib exports SQLite's symbols, so the app must never also link
  the system `libsqlite3` (D-0028). The bundled SQLite now targets macOS
  14.0 (D-0029), but the app has not been run on macOS 14.
- FFI copies in Phase 2: `Vec<u8>` values that cross UniFFI go through a
  `RustBuffer` that is freed without being zeroed. The DEK passed to
  `unlock` and every body returned by `read_body` would leave copies in
  freed memory. Phase 2 must design those two calls with this in mind and
  not export the Phase 1 signatures as they are.

**Open questions for the product owner:**

1. Length padding. Envelope padding is decided for Phase 3 (D-0027).
   Still open: should stored content (names, subjects, bodies in the
   database) be padded too, so the file does not show exact lengths?
2. Client-side signature verification before Phase 3 (a `p256` crate
   outside §4, or a Swift CryptoKit callback). Answered in `664e23c`: it
   comes in Phase 3, in `brev-core` with `p256`, now in §4. Swift never
   verifies, so there is no CryptoKit callback.
3. Notification sender names while locked vs §1.5. Answered in `664e23c`:
   the text is only "Ny melding".
4. Wiping the Poly1305 state needs `poly1305` as a direct dependency
   outside §4 (the design recommended not to). Answered in `664e23c`:
   `poly1305` is approved with `zeroize` only, and was added in `ed2cf07`.

---

## Spec changes

D-0030 and D-0031 were written in a parallel session on 2026-09-27 and
first pushed as D-0013 and D-0014. Those numbers were already used on this
machine (D-0013: Phase 0 Mac checklist; D-0014: Phase 1 crates), so they
were renumbered in the merge; the text is unchanged. CLAUDE.md points to
the new numbers.

### D-0030 — Immediate delivery, like ordinary email; no fixed delivery times

- **Date:** 2026-09-27
- **Decision:** The Phase 4 bullet "Delayed delivery: relay releases
  envelopes at fixed 'postombæring' times (default 08:00 and 18:00 local)" is
  removed from CLAUDE.md. The relay delivers an envelope on the recipient's
  next poll as soon as it has passed the signature, contact-approval and
  rate-limit checks. The Phase 4 definition of done now asks for relay tests
  of rate limits and of immediate delivery instead of delivery windows.
  CLAUDE.md §2 and `docs/THREAT_MODEL.md` list the anti-noise defences as
  identity, contact approval, invite codes and rate limits.
- **Reasoning:** Product decision by the project owner: Brev should deliver
  like an ordinary email service, and holding a letter for up to half a day
  made the product feel broken rather than calm. Delivery timing is not part
  of any §1 invariant, so content protection is unchanged. Spam and mass
  messaging are still stopped by the defences that actually gate who can
  write to whom: an invite to get an identity, approval before a sender can
  reach an inbox, and a daily per-identity quota. One property is lost and
  is recorded here so it is not rediscovered later: fixed release times
  batched deliveries, which hid the exact moment a letter was sent from
  anyone watching when recipients fetched. With immediate delivery the relay
  (and anyone observing its traffic) can link a send to the matching fetch
  more precisely. The relay already sees routing metadata (§2), so this is a
  small change in metadata exposure, not in content exposure. Phase 3
  polling every N seconds means "immediate" is bounded by that interval.
- **Verified:** Specification change only; no relay code exists yet. The
  §2 copy in `docs/THREAT_MODEL.md` was re-diffed against CLAUDE.md.

### D-0031 — Contacts by address plus invite codes; key check is optional

- **Date:** 2026-09-27
- **Decision:** Mandatory out-of-band exchange of identity codes, by phone or
  in person, is dropped. Contacts are made in two ways, as Signal does:
  1. **By address, like email (Phase 3).** Each identity registers a short,
     unique address with the relay. Adding a contact means typing their
     address; the relay returns their public keys; the recipient approves
     the contact request with one click (Phase 4). The app pins a contact's
     identity key on first sight (trust on first use). If the relay later
     returns a different key, the app shows a warning and sends nothing until
     the user accepts the new key.
  2. **By invite code (Phase 4).** A one-time text code carries the inviter's
     address and identity-key fingerprint. Redeeming it makes the two people
     approved contacts of each other, with the key checked against the
     fingerprint, so the relay cannot substitute it. A new identity needs one
     to register, which is the existing invite-graph requirement.
  The identity code (base32 of the public-key hash) stays, shown per contact
  as an optional safety code for people who want to compare it.
  CLAUDE.md §2 now states that the relay serves the address directory and
  what makes a false key detectable; `docs/THREAT_MODEL.md` is re-synced.
- **Reasoning:** Product decision by the project owner: requiring a phone
  call or a meeting before two people can write was too much friction for
  an email-like product. Four options were compared: (1) address lookup,
  (2) invite code sent over any channel, (3) searching a directory of
  BankID-verified names, (4) matching phone numbers from the address book.
  (1) is the simplest but trusts the relay at first contact; (2) is
  verified by construction and fits the invite requirement Phase 4 already
  has. (3) was rejected because it turns the relay into a searchable
  register of who uses Brev; BankID stays a Phase 4 verification stub only.
  (4) was rejected because it needs Contacts access and uploads the user's
  address book, which conflicts with Brev's privacy stance. The trade-off
  accepted: for contacts added by address, a malicious relay could hand out
  a false key the first time. Pinning means any later swap is caught, the
  optional safety code catches the first one for people who compare, and
  invite codes avoid it entirely. Content protection under §1 is unchanged.
  Invites are text rather than links because §1.4 forbids URL schemes.
  Addresses and invite codes are not message content, so §1.3 does not
  forbid copying them; copy and paste is limited to the contact screen so
  it can never reach a content view.
- **Verified:** Specification change only; no relay or contact code exists
  yet. The §2 copy in `docs/THREAT_MODEL.md` was re-diffed against
  CLAUDE.md.

---

## Phase 2 — locked UI (2026-09-27)

### D-0032 — Product-owner decisions before Phase 2: key files, HPKE, zeroing allocator, patched bindings, stored padding

- **Date:** 2026-09-27
- **Decision:** The product owner accepted all seven recommendations from the
  Phase 2 spikes. CLAUDE.md §1.9, §2, §3.1, §3.2, §3.3, §4 and §5 Phase 2
  were changed to match, and `docs/THREAT_MODEL.md` was re-synced.
  1. The two Secure Enclave keys are CryptoKit `SecureEnclave.P256` keys.
     Their `dataRepresentation` is stored as files in the app container,
     not in the keychain. The DEK is wrapped with HPKE (RFC 9180,
     `P256_SHA256_AES_GCM_256`) instead of `SecKeyCreateDecryptedData`.
     Keychain storage returns in Phase 5 with a Developer ID.
  2. Accepted residual risk: the key files are not bound to Brev (§2).
  3. `.biometryCurrentSet` stays. Adding or removing a fingerprint loses the
     history and identity, and onboarding says so (§1.9).
  4. `zeroizing-alloc` (1Password) is approved as `brev-core`'s global
     allocator (§4).
  5. `scripts/gen-bindings.sh` patches the generated Swift bindings to wipe
     byte buffers before they are freed, and fails the build if a patch
     does not apply. This is an exception to D-0002's "generated, not
     written".
  6. Accepted residual risk: internal copies in Core Text / CoreGraphics
     and CryptoKit / Security (§2), mitigated by drawing one line at a time
     and a 64 KiB stack scrub in `unlock`.
  7. Stored content (contact names, subjects, bodies) is padded to the
     envelope buckets in Phase 2, with schema v2, before any real store
     exists.
- **Reasoning:** Facts from the Phase 2 spikes on this Mac (macOS 26.2):
  - Keychain: `SecKeyCreateRandomKey` with `kSecAttrIsPermanent` fails with
    -34018 (`errSecMissingEntitlement`) for an ad-hoc signed sandboxed
    app, with or without the data protection keychain (TN3137: it needs a
    provisioning profile). CryptoKit Secure Enclave keys can be created and
    their blobs restored in a later launch without any prompt; HPKE wrap to
    the KEK needs no prompt.
  - Key blobs: a no-biometry blob worked from another, unsandboxed binary,
    so a blob is not bound to the app that made it. Whether the system
    dialog names the other program is still to be confirmed by the user's
    Touch ID test.
  - FFI: with stock uniffi 0.32, a `Vec<u8>` returned to Swift left copies
    in freed memory at 5 places; `&[u8]` arguments are zero-copy and left
    none. With a zeroing allocator plus the patched bindings, residue was 0
    on all six byte paths at 4 KiB, 64 KiB and 1 MiB (one run each). The
    allocator cost about 8–10 ms extra per GiB of cache-hot 4 KiB churn.
  - Core Text: laying out a whole body with `CTFramesetter` left a full copy
    in freed memory; drawing one `CTLine` per line left at most one line of
    glyph ids, overwritten by the next line of the same length.
  - Stored padding: adding it after real stores exist would need every row
    re-encrypted; Phase 2 is the last point where it is free.
- **Verified:** Spike results are in the session scratchpad (not in the
  repo); each spike was re-checked by a second agent, whose corrections are
  reflected above (for example "one run each"). Still open: the user's
  Touch ID test of the full HPKE unwrap, and the GUI spikes on screen
  capture, input, accessibility and lock triggers.

### D-0033 — Owner decisions after the Phase 2 design and the Touch ID test

- **Date:** 2026-09-27
- **Decision:** The product owner accepted the Phase 2 design's three open
  questions and a corrected version of D-0032 item 2. CLAUDE.md §1.9, §2 and
  §5 Phase 5 were changed and `docs/THREAT_MODEL.md` re-synced:
  1. Key files not bound to Brev: accepted again on corrected facts. The
     Touch ID dialog is not a mitigation; the rule is behavioural (Brev asks
     only right after "Lås opp"; onboarding says to cancel any other
     request).
  2. File substitution by a process that can write the container: accepted
     for Phase 2, with the onboarding warning, and a login-keychain anchor
     if the GUI session shows it works without prompts.
  3. New accepted residual risks: keystrokes in macOS event objects and the
     window server; letter pixels in backing stores until blank-on-lock; the
     Phase 2 echo contacts' copies; reliance on `MallocScribble=1`.
  4. Brev's container is excluded from Time Machine.
  5. Developer ID and keychain storage are required before Brev holds real
     letters (Phase 5 at the latest). This closes items 1 and 2.
- **Reasoning:** The owner's Touch ID test on 2026-09-27 (enclave spike,
  `user_test.sh --rogue`, macOS 26.2): unwrapping without interaction was
  refused (LocalAuthentication -1004); the HPKE unwrap after Touch ID
  matched (1.9 s including the prompt); a different, unsandboxed binary
  unwrapped the same DEK from a copy of the KEK blob after Touch ID; neither
  dialog offered a password; the owner could not tell the two dialogs
  apart. Keychain items under a Developer ID are bound to the app's signing
  identity, so other processes can neither use nor replace them.
- **Verified:** The test output is in the session scratchpad
  (`p2/enclave/out/user-*.stdout`). The dialog observations are the owner's.
- **Numbering:** `docs/PHASE2_DESIGN.md` §13 planned D-0033 to D-0058. Those
  entries shift by one (D-0034 to D-0059); its D-0055 and D-0056 topics are
  covered here.

### D-0034 — Capture defence: protected content layer, AVFoundation approved

- **Date:** 2026-09-28
- **Decision:** The product owner approved AVFoundation, CoreMedia and
  CoreVideo (§4), only for the capture-protected content layer. Every view
  that can show content draws into pixel buffers shown through an
  `AVSampleBufferDisplayLayer` with `preventsCapture = true`, and
  `sharingType = .none` stays as the first defence (§3.2). The pixel
  buffers are zeroed in place on lock. This defence (design WP11) is part
  of Phase 2's definition of done, not conditional.
- **Reasoning:** Capture spike on macOS 26.2 (25C56), 2026-09-27, with a
  sandboxed, hardened, ad-hoc-signed test app, checked by a second agent:
  `sharingType = .none` kept the window out of ScreenCaptureKit (every valid
  filter), `screencapture` and `CGWindowListCreateImage`/
  `CGDisplayCreateImage`, but not out of `CGDisplayStream` (obsoleted for
  new deployment targets, still reachable through `dlsym`) or
  `AVCaptureScreenInput` (not deprecated). The checker viewed the images:
  the marker text of the `.none` window was readable through both. A
  default-sharing sheet or child window of a `.none` window was captured by
  every path. In the same runs, a window drawn through the protected layer
  showed as an empty dark area on the leaking paths. Detecting capture, and
  window levels and collection behaviours, were tried and are not shown to
  help. This breaks §1's promise and matches two §2 threats, so it is not
  accepted as residual risk.
- **Verified / still open:** Verified with preserved logs at window levels
  4 and 25. Before WP11 is built on it, two runs are repeated because their
  logs were overwritten: the leak at level 0 (Brev's windows), and the
  negative control that shows the layer hides content only with
  `preventsCapture = true`. Whether the leaking paths need the Screen
  Recording permission is not documented and not yet tested.
- **Numbering:** the entries planned in `docs/PHASE2_DESIGN.md` §13 now
  shift by two (D-0035 to D-0060).

### D-0035 — Keys in the keychain now: team signing, Secure Enclave SecKeys, ECIES (reverses D-0032 items 1–2)

- **Date:** 2026-09-28
- **Decision:** The product owner has a paid Apple Developer team
  (`AV26DNQ5SC`) and approved using it now. Brev is signed by that team with
  a Mac App Development provisioning profile (automatic signing registered
  the App ID `no.brev.app` and this Mac). Both Secure Enclave keys are
  permanent `SecKey`s in the data protection keychain, access group
  `AV26DNQ5SC.no.brev.app`; the wrapped DEK is a generic-password item in the
  same group. The DEK is unwrapped with `SecKeyCreateDecryptedData` (ECIES)
  as the original §3.3 said. This reverses D-0032 item 1 (container files +
  HPKE) and closes D-0032 item 2 and D-0033 items 1 and 5: no key material
  is left in files, and other programs can neither use nor replace it.
  File substitution now only affects the stores (§2). D-0005's ad-hoc
  signing is replaced for app builds; Developer ID distribution stays in
  Phase 5.
- **Reasoning:** Keychain items are bound to the app's signing identity
  and entitlements, which is what the key-file approach lacked (the owner's
  Touch ID test showed another program could use a copied key blob, and
  the dialog did not tell them apart). Doing it before WP5 means no
  migration from key files later.
- **Verified:** macOS 26.2, 2026-09-28, with a windowless probe app
  (bundle id `no.brev.app`, sandboxed, hardened, signed "Apple
  Development", team `AV26DNQ5SC`, entitlements `application-identifier`,
  `team-identifier`, `keychain-access-groups`). `xcodebuild
  -allowProvisioningUpdates -allowProvisioningDeviceRegistration` built it
  (the first attempt without device registration failed with "Device …
  isn't registered"). Launched with `open -g`: a permanent Secure Enclave
  key with `[.privateKeyUsage, .biometryCurrentSet]` was created with no
  prompt; `SecItemCopyMatching` found it (status 0); ECIES wrap of 32 bytes
  gave 113 bytes with no prompt; the item was deleted (status 0). Unwrap
  with Touch ID is not yet tested with this key type in the app.
- **Numbering:** the entries planned in `docs/PHASE2_DESIGN.md` §13 now
  shift by three (D-0036 to D-0061).

WP12 wrote the entries `docs/PHASE2_DESIGN.md` §13 plans as D-0036 to
D-0053, on 2026-09-28. Where one entry holds several planned topics they
were merged, the key topics follow D-0035 (keychain, not key files), and the
anchor (design A, WP9) is dropped. D-0054 to D-0061 are not used. D-0062 to
D-0064 were written before WP12 and keep their numbers. Comments,
`docs/VERIFY.md` and `docs/VERIFY-RESULTS.md` now cite the entries below.
Older text (D-0064, and the design itself) cites the design's numbers or the
shifted ones; this table maps both:

| Design §13 | Shifted (cited before WP12) | Topic | Now |
|---|---|---|---|
| D-0033, D-0034, D-0051 | D-0036, D-0037, D-0054 | UniFFI surface, `OpenText` registry, limits | D-0038 |
| D-0035 | D-0038 | `unlock` drop guard, deep scrub, poison | D-0039 |
| D-0036, D-0037 | D-0039, D-0040 | install marker, container, instance lock | D-0036 |
| D-0038 | D-0041 | `biometry.state`, unlock errors, reset | D-0037 |
| D-0039 | D-0042 | stored padding, schema v2 | D-0041 |
| D-0040 | D-0043 | binding patches (and the zeroing allocator) | D-0040 |
| D-0041 | D-0044 | echo peers | D-0042 |
| D-0042, D-0050 | D-0045, D-0053 | AppKit shell, menus | D-0043 |
| D-0043 | D-0046 | Swift secret memory | D-0044 |
| D-0044 | D-0047 | rendering | D-0045 |
| D-0045 | D-0048 | launch hygiene | D-0047 |
| D-0046 | D-0049 | compose input | D-0049 |
| D-0047 | D-0050 | synthetic input, `HumanButton` | D-0048 |
| D-0048 | D-0051 | window hardening, capture defence | D-0046 |
| D-0049 | D-0052 | lock triggers, lock sequence | D-0050 |
| D-0052, D-0053, D-0054 | D-0055, D-0056, D-0057 | tests, Verify build, `tools/verify/` | D-0051 |
| D-0055, D-0056 | D-0058, D-0059 | file substitution, new residual risks | D-0033 items 2 and 3 |
| D-0057 | D-0060 | GUI-spike facts | D-0052 |
| D-0058 | D-0061 | VERIFY results, phase summary | D-0053 and "Phase 2 summary" |

### D-0036 — Keys, install marker, container and instance lock (D-0035 as built)

- **Date:** 2026-09-28
- **Decision:** Design §5.1 to §5.3 and §2.10, adapted to D-0035 (WP5,
  `app/Sources/Keys/KeyStore.swift`, `UnlockService.swift`):
  1. **Keychain names.** The identity key (tag `no.brev.app.identity`) and
     the KEK (tag `no.brev.app.kek`) are permanent Secure Enclave keys with
     `[.privateKeyUsage, .biometryCurrentSet]` and
     `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`; the wrapped DEK is a
     generic-password item (service `no.brev.app`, account `wrapped-dek`).
     All three are in the data protection keychain, access group
     `AV26DNQ5SC.no.brev.app`, never synchronizable. Every query that does
     not unwrap carries an `LAContext` with `interactionNotAllowed`, so it
     fails instead of showing UI; only the unwrap prompts.
  2. **Install marker.** Brev counts as installed when the wrapped-DEK item
     exists. It is written last, inside the first unlock closure, right
     after `brev.unlock` succeeds and before the post-unlock rule (D-0037),
     so a successful first unlock always completes the install, and a crash
     or quit before it leaves Brev uninstalled. This replaces design §2.10's
     `dek.hpke` and closes Phase 1's "`create` is not crash-atomic". A
     second store of the item is refused (-25299).
  3. **Known-name cleanup.** Before every onboarding attempt, and on reset,
     Brev deletes the three keychain items and only the files it writes:
     `brev.db`, `peer-1.db`, `peer-2.db`, their `-journal` files,
     `biometry.state` and `biometry.state.tmp`. Nothing else is ever
     deleted.
  4. **Folder.** `~/Library/Containers/no.brev.app/Data/Library/Application
     Support/Brev`, mode 0700, excluded from backups
     (`isExcludedFromBackup`) when the folder is created, so it never exists
     without the exclusion (D-0033 item 4). The stores are 0600 (D-0041);
     `biometry.state` is written 0600 with `O_EXCL` and `F_FULLFSYNC` to a
     `.tmp` name, renamed, and the folder synced.
  5. **Instance lock.** `.lock` in that folder, opened with `O_EXLOCK |
     O_NONBLOCK` and held for the process lifetime. A second instance logs
     `second instance`, activates the running Brev through
     `NSRunningApplication` and quits. If the folder or `.lock` cannot be
     prepared for any other reason, or the keychain cannot be read at launch
     (an ad-hoc build), Brev fails closed: the `unlock.error.damaged` notice
     with no reset button.
- **Reasoning:** CLAUDE.md §1.9 and §3.2/§3.3 as changed by D-0035: no key
  material in files, so the design's key-file list, `dek.hpke` and the
  anchor are gone, and file substitution only affects the stores (§2). The
  binding to Brev's signing identity holds only on a Mac without the team
  signing key (D-0062; accepted by the owner for test letters, CLAUDE.md
  §2). A marker written after the first real unlock is the simplest way to
  make onboarding restartable.
- **Verified:**
  - WP5, macOS 26.2: a windowless team-signed probe (bundle id
    `no.brev.app`, same group) compiled the repo's `KeyStore.swift`,
    `Enclave.swift` and `SecretBytes.swift` and never unwrapped. `makeKeys`
    made both keys with no prompt (token `com.apple.setoken`, ACL `akpu`
    with biometry, group `AV26DNQ5SC.no.brev.app`, `sync=0`); the ECIES wrap
    gave 113 bytes; `storeWrapped` made the state "installed" (item
    `pdmn=akpu`, `sync=0`) and read back equal; a second store gave -25299;
    the KEK was found with a no-interaction context; `biometry.state` was
    0600 with no `.tmp` left; the folder was 0700 and excluded from backup;
    `deleteKnownNames` returned it to "fresh" (-25300 for key and item) with
    no files left.
  - WP4 run of the Release build (`docs/VERIFY-RESULTS.md`): `open -n`
    during onboarding logged `second instance` and exited, one PID before
    and after (V29, process part); `security find-generic-password -s
    no.brev.app` found nothing (V40, keychain part). Every launch showed
    onboarding (`route onboarding`), since nothing was installed.
  - Not yet run (Touch ID, and reads of the container that would prompt):
    V37, V38, the file parts of V29, V40 and V41, and V52.

### D-0037 — Unlock, error mapping, `biometry.state` and reset

- **Date:** 2026-09-28
- **Decision:** Design §5.3 to §5.5, adapted to D-0035 (WP5):
  1. **The unlock closure** (`UnlockService`, serial queue
     `no.brev.unlock`): an `LAContext` with `localizedFallbackTitle = ""`,
     cancel title *Avbryt* and reason «låse opp brevene dine»; the KEK
     lookup; `SecKeyCreateDecryptedData` with
     `.eciesEncryptionCofactorVariableIVX963SHA256AESGCM` (the one Touch ID
     prompt); `brev.unlock(dek:)` on the same thread, zero-copy; the
     returned `CFData` zeroed in place on every path, also when a later step
     throws. Any error after `Brev.unlock` locks the session again. Brev
     never prompts on its own: only a human click (`HumanButton`, D-0048) on
     the lock screen or on onboarding's first-unlock page starts it.
  2. **Post-unlock rule** (design §5.4 step 3, the simple rule): back on
     main, if the lock generation changed, or Brev is not the active app,
     the session is locked and the lock screen shown. The activation wait
     and `LAAuthenticationView` from the lock spike are not built; they wait
     for V27/V47 and the owner.
  3. **Error mapping** (`Shared/UnlockFailure.swift`, so the harness tests
     it): `LAError` user/system/app cancel and `TKError` -4 → the lock
     screen with no text; lockout → `unlock.error.lockout`; biometry not
     available or not enrolled → `unlock.error.unavailable`;
     `errSecItemNotFound`, malformed lengths, `TKError` -3 and Rust
     `WrongKey`/`Corrupt` → `unlock.error.damaged`; any other keychain or
     Enclave failure → `unlock.error.fingers` only if the saved
     `biometry.state` exists and differs from the current hash, else
     `unlock.error.retry`; everything else → retry. The log line `unlock
     failed class=<x> errors=[domain code, …]` gives V48 the codes. The
     error codes of design §14.2 U4.3 were not measured (the lock spike's
     option (a), skip them).
  4. **`biometry.state`** is a hint: the enrolled-fingers hash, written at
     onboarding and rewritten after every successful unwrap, inside the
     closure (even if the post-unlock rule then locks). A hash change alone
     never counts as "fingers".
  5. **Reset.** Only the reset button followed by *Slett alt* in
     `ConfirmSheet` (Brev's own hardened sheet with two `HumanButton`s;
     Escape is *Avbryt*) deletes anything, and then only the known names
     (D-0036). While an unlock is in flight every button on the page is
     disabled, and `AppDelegate.reset()` refuses (`reset refused: unlock in
     flight`). After a damaged or fingers failure the unlock button stays
     beside the reset button, so a wrong guess never forces a reset; when
     `Brev.open` fails, only the reset is offered. The first-unlock page is
     `UnlockViewController` in a first-unlock mode, which offers the reset
     on any failure but a cancel.
- **Reasoning:** CLAUDE.md §1.8 (no password path), §1.9 (a fingerprint
  change loses the keys, and Brev says so) and §1.10. The lock spike and the
  enclave skeptic: a hash change is not evidence on its own (it can change
  across OS versions), and collecting the invalidated-key code would
  invalidate every `.biometryCurrentSet` key on the Mac.
- **Verified:**
  - `scripts/test.sh` at `fb6f140` (macOS 26.2): harness case 2 (the
    `UnlockFailure` table) 5 of 5; case 1 (the unwrap zeroes the same
    `CFData`, also when the body throws) and case 3 (`Brev.unlock` got the
    same address; all zero after the unwrap) 5 of 5 each. WP5 review: with
    the wipe removed, `harness units` and `harness dek` fail; with a wipe
    only on success, `harness units` fails.
  - The lock probe (`app/Tests/Lock`, in test.sh, 12 checks pass): a
    discarded unlock leaves Rust locked, and `UnlockService` locks Rust when
    its closure fails after `Brev.unlock` (D-0063 item 4).
  - WP5 review, the reset race: an AppKit check in the scratchpad built the
    real `UnlockViewController` and `PageView`; against `33fa863` the reset
    button stayed enabled while an unlock was working (`[false, true]`),
    with the fix both buttons were disabled.
  - Not yet run (Touch ID): V26, V27, V47, V48, V38 and V51.

### D-0038 — The Phase 2 UniFFI surface: `Brev`, `OpenText`, limits and the lock registry

- **Date:** 2026-09-28
- **Decision:** Design §2.2 to §2.4 as built (WP1,
  `core/brev-core/src/ffi.rs`):
  1. Two objects, `Brev` and `OpenText`; `ping()` and `limits()`;
     `Brev.create`, `open`, `unlock`, `lock`, `is_locked`, `contacts`,
     `threads`, `messages`, `open_body`, `send_new`, `sync`;
     `OpenText.byte_len`, `chunk`, `close`. With the clone and free
     functions that is 20 exported symbols, listed in
     `scripts/ffi-surface.txt`.
  2. `BrevError` has unit variants only. Records carry ids and metadata;
     every name, subject and body is an `OpenText` handle.
  3. Content goes in only as `&[u8]` plus a used length, from a fixed
     `SecretBytes` of at least 64 bytes; content comes out only through
     `OpenText.chunk`, always exactly `CHUNK` = 960 bytes. No `String`
     carries content: the only ones are `ping()` and `dir`.
  4. Limits (`limits()`): subject 256 bytes, body 64 KiB of UTF-8.
  5. Lock registry: the session keeps a `Weak` to every `OpenText`; `lock()`
     and `Drop` for `Brev` close them all, after which `chunk` returns
     `Locked` and `byte_len` 0. Swift reads a text completely and closes it
     at once (`TextReader`).
  6. Not in Phase 2 (design §1.3): replies (every letter starts a thread),
     read state, deletion, search, attachments, drafts that survive a lock.
  The whole surface is pinned by test.sh against `scripts/ffi-surface.txt`
  (D-0064 item 1).
- **Reasoning:** The Phase 1 summary's deferred FFI copies (`RustBuffer`s
  freed unzeroed, `read_body` and `unlock` not exportable as they were);
  CLAUDE.md §1.10 and §6 ("keep the UniFFI surface minimal and opaque").
  Small fixed chunks keep every buffer on both sides at or under 1 KiB, on
  top of the allocator and the patches (D-0040).
- **Verified:**
  - `scripts/test.sh` at `fb6f140`: `locked_session_refuses_every_export`,
    `lock_closes_every_open_text`, `drop_closes_every_open_text`,
    `chunk_is_exactly_960_zero_padded` and
    `send_uses_only_the_length_prefix` pass, and both FFI surface checks
    pass.
  - WP1 mutations: `lock_all` not closing the open texts, and `send_new`
    ignoring the used length, each fail their test. Review round 2: bindings
    from three Rust mutants (`OpenText::units() -> Vec<u16>`,
    `ContactRow.name_units: Vec<u16>`, `OpenText::byte_at(i) -> u32`) fail
    the surface check (D-0064).

### D-0039 — The `unlock` drop guard, the 64 KiB scrub and poison handling

- **Date:** 2026-09-28
- **Decision:** Design §2.3 and §2.5 as built (WP1, review round 1):
  1. `Brev::unlock` builds a `Finish` drop guard before it takes the session
     mutex. It runs on every exit, including a panic unwind and a poisoned
     mutex: it locks all three cores unless the unlock succeeded, then runs
     `scrub_stack_deep()` (64 KiB). A DEK that is not 32 bytes gives
     `WrongKey`.
  2. A poisoned mutex: `session()` recovers the guard, locks everything,
     clears the poison and returns `Locked`; `lock()` clears the poison
     while it still holds the guard; `Drop` recovers and locks.
  3. `unlock_all` and `create_in` are `#[inline(never)]`, so the deep scrub
     reaches the copies of the two peer DEKs (D-0063 item 1), and
     `Brev::create` scrubs after `create_in`.
  4. Swift calls `brev.lock()` after any error from `unlock` (D-0037). The
     depth stays 64 KiB, as CLAUDE.md §2 says, until V51 measures it with
     the real Enclave unwrap; a change of depth goes to the owner.
- **Reasoning:** CLAUDE.md §2 (Security framework copies during the unwrap,
  mitigated by the 64 KiB scrub in `unlock`) and §1.10. The scrub is for
  residue on the calling thread whether or not Rust used the DEK, so it also
  runs on the poisoned path.
- **Verified:**
  - `scripts/test.sh` at `fb6f140`:
    `panic_in_unlock_locks_all_scrubs_and_poison_returns_locked`,
    `unlock_scrubs_deep_on_every_path`,
    `poison_while_unlocked_locks_all_on_next_call` and
    `create_scrubs_the_stack_after_create_in` pass; the release run of
    `scrub_stack_deep_wipes_its_buffer` passes.
  - WP1 mutations: a `Finish` that does not lock on failure, and one built
    after the mutex is taken (no scrub on the poisoned path), each fail.
    Review round 1: harness case 3 with the archive from before
    `#[inline(never)]` failed 6 of 6 (two copies of each peer DEK on a stack
    after the lock), and passed 8 of 8 with it.
  - WP4: the disassembly of `scrub_stack_deep` in the three `TouchIDProbe`
    builds reserves 64 KiB, nothing and 128 KiB; each passes `--dry` with no
    prompt. V51 (`--unlock`, one Touch ID prompt) is not yet run.

### D-0040 — The zeroing allocator and the patched bindings (implements D-0032 items 4 and 5)

- **Date:** 2026-09-28
- **Decision:** (WP1, WP2)
  1. `brev-core`'s global allocator is
     `zeroizing_alloc::ZeroAlloc<std::alloc::System>` (`zeroizing-alloc`
     0.1.1, safe code; `#![forbid(unsafe_code)]` stays). test.sh checks
     `cargo tree` and that the release test binary contains
     `zeroizing_alloc5WIPER`, which is linked only when the allocator is in
     use.
  2. `scripts/patch-bindings.py` applies design §3's patches A to D to the
     generated Swift. bindgen writes into `core/target/bindings-staging`;
     the files are patched there and moved to `app/Generated` only after the
     patch succeeds, so no build can ever compile unpatched bindings.
     `gen-bindings.sh` reads the `uniffi` and `uniffi_bindgen` versions from
     `Cargo.lock` after `cargo build` and refuses anything but
     `PATCHED_FOR_UNIFFI=0.32.2`. A marker line refuses a second run, and
     test.sh checks the marker.
- **Reasoning:** CLAUDE.md §3.1: every freed Rust buffer, including
  UniFFI's, is wiped, and byte buffers are wiped before Swift frees them. A
  patch that no longer applies must fail the build, not pass silently.
- **Verified:**
  - `scripts/test.sh` at `fb6f140`: the allocator and patch-marker steps
    pass.
  - WP1 review: with `#[global_allocator]` deleted, fmt, clippy and every
    test stayed green and test.sh stopped with "brev-core's global allocator
    is not zeroizing_alloc::ZeroAlloc". The crates.io source of 0.1.1 is
    byte-identical to the copy the design proved (`diff -r`).
  - WP2, each mutation put between bindgen and the patch step: a changed
    stock `deallocate()` exits 1 ("expected exactly 1 match, found 0"), a
    second copy of the stock `Data.read` exits 1 ("found 2"),
    `PATCHED_FOR_UNIFFI=0.32.3` exits 1 ("uniffi changed …"), and a second
    patch run exits 1. WP2 review: with pattern D made to miss, the old
    script left stock bindings in `app/Generated`; the new one left none,
    and xcodebuild then failed ("Build input file cannot be found"). A
    `Cargo.lock` bumped to 0.32.3 by `cargo build` is now refused.

### D-0041 — Padding of every stored column, schema v2 (implements D-0032 item 7)

- **Date:** 2026-09-28
- **Decision:** Design §2.8 and §2.9 as built (WP1). `brev-proto` has
  `MAX_PADDED` (1 MiB), `padded_len`, `pad_into` (a u32 big-endian length,
  the content, zeros), `unpad` (refuses anything `pad_into` could not have
  written) and `PadError`. Every sealed column (names, subjects, bodies,
  identity keys, bundles) is padded to 256 B, 1 KiB, 4 KiB or 16 KiB, and
  above that to the next multiple of 16 KiB, before it is encrypted; a bad
  pad is `Crypto`. `SCHEMA_VERSION` is 2 and the `SCHEMA` text is unchanged;
  a v1 store opens as `Corrupt`. New store files are created with mode 0600.
- **Reasoning:** D-0032 item 7: padding after real stores exist would mean
  re-encrypting every row. One code path for every column, so key rows leak
  no lengths either. Phase 3's envelope reuses the same functions.
- **Verified:**
  - `scripts/test.sh` at `fb6f140`: `padding_boundaries`,
    `padding_is_strict`, `column_padding_is_enforced`,
    `column_lengths_are_bucketed`, `v1_store_is_refused`,
    `store_files_are_0600` and `no_plaintext_in_any_file` (Phase 2, all
    three stores) pass.
  - WP4: `padcheck` passed on the view host's three stores (14, 9 and 6
    sealed values) and failed on a copy with one body set to 300 bytes (`NOT
    PADDED: rowid 1 length 300`). V18 on Brev's own stores waits for the
    human run.

### D-0042 — The echo contacts Ekko and Speil (removed in Phase 3)

- **Date:** 2026-09-28
- **Decision:** Design §9 as built (WP1, `core/brev-core/src/echo.rs`). Two
  real in-process `Core`s with their own stores (`peer-1.db`, `peer-2.db`),
  each under DEK = HKDF-SHA256(the user's DEK, `"brev/v0/demo-peer/" ‖
  index`), scrubbed also on its error path. Each peer is a contact of the
  user ("Ekko", "Speil") and has the user as "Deg", over its own
  `MockTransport` pair, and echoes every letter into the same thread.
  `send_new` routes the envelope to the peer whose bundle id equals the
  recipient (errors are returned, not skipped). `sync()` runs every 3 s in
  the common run-loop modes while unlocked; the pump drops each plaintext
  before the envelope is queued. Envelopes in flight are lost on quit.
  Envelopes are unsigned (`Unsigned`, D-0019).
- **Reasoning:** CLAUDE.md §5 Phase 2 ("two contacts hard-coded through
  `MockTransport` so you can send a message to yourself"); Phase 1 forbids a
  self-contact. The copies in two more stores are an accepted Phase 2
  residual risk (D-0033 item 3, CLAUDE.md §2).
- **Verified:**
  - `scripts/test.sh` at `fb6f140`:
    `sync_echoes_each_letter_once_into_the_same_thread`,
    `echo_pump_holds_no_plaintext_after_sync` (the live plaintext count is 0
    at every send), `create_returns_locked_session_with_two_contacts` and
    `no_plaintext_in_any_file` (which also looks for "Ekko" and "Speil" in
    all three stores) pass.
  - WP7, 10 view host runs: the sync timer showed the new thread and kept
    the selection by id. V42 in the real app waits for the human run.

### D-0043 — The app shell: AppKit only, `BrevApplication`, `RootViewController`, menus Brev and Arkiv

- **Date:** 2026-09-28
- **Decision:** (WP3, WP5, WP7)
  1. AppKit only, no SwiftUI, also for onboarding: interface text on the
     onboarding pages, the lock screen and `ConfirmSheet` is drawn by a
     small `InterfaceText` view (readable by VoiceOver, never content),
     because the forbidden-API grep keeps `NSTextField` out of
     `app/Sources`.
  2. `NSPrincipalClass` is `BrevApplication` (D-0048). `RootViewController`
     swaps onboarding, the lock screen and the mail screen inside one fixed
     root, so the window never resizes; the lock screen replaces the current
     screen only if Brev was unlocked, so a lock never hides onboarding or
     an error.
  3. Menus are built in code: **Brev** (*Lås Brev* ⌘L, *Avslutt Brev* ⌘Q)
     and **Arkiv** (*Nytt brev* ⌘N, enabled only while unlocked, a contact
     is selected and no sheet is open). No Edit, View, Window, Help,
     Services or Share menu; `servicesMenu` is never set; no Dock menu or
     badge.
  4. `AppDelegate` ignores open-documents events (D-0063 item 6).
  5. The mail screen is an `NSSplitView` with minimum pane widths 150, 200
     and 300 pt; threads are listed newest first, letters oldest first. The
     48 strings are in `nb.lproj/Localizable.strings`.
- **Reasoning:** CLAUDE.md §3.2 and §1.4. The input spike: without an Edit
  menu macOS 26.2 adds no Writing Tools, AutoFill, Start Dictation or Emoji
  & Symbols items; with a standard Edit menu it adds all four.
- **Verified:**
  - WP3: `OBJC_CLASS_$_BrevApplication` is in the Release, Verify and Debug
    binaries; the 48 keys in `Localizable.strings` match the 48 that `L10n`
    uses.
  - WP4, `axdump` on Brev's onboarding window: 32 elements, only interface
    text, the menus Brev and Arkiv; the minimise button has `AXEnabled = 0`.
  - WP7 review: the view host's pane-minimum checks fail with the old split
    code (a pane dragged to 0) and pass with the constraints. V15 and V43
    wait for the human run.

### D-0044 — Secret memory in Swift

- **Date:** 2026-09-28
- **Decision:** Design §6 as built (WP2, WP5, WP6): `SecretBytes` (a fixed
  allocation of at least 64 bytes, wiped with `memset_s`), `SecretText`
  (UTF-16 in a fixed buffer, edited in place; `composedRange` shows Core
  Text at most 446 units), `Transcode` and `TextReader`. The only `Data`
  that holds a secret is a 960-byte chunk from `OpenText.chunk` and the
  unwrapped DEK's `CFData` (ECIES now, D-0035; CryptoKit is no longer used
  by app code). One keystroke lives in a stack tuple inside
  `KeyTranslator.translate` and is wiped before it returns. The rules of
  design §6.3 hold; the forbidden-API grep enforces the checkable ones,
  widened in WP2's review with `String(data`, `String(bytes`,
  `String(cString`, `String(utf16CodeUnits`, `NSMutableString`,
  `CFStringCreateWithCharacters(`, `NSLog(`, `debugPrint(`, `dump(`,
  `os_log(` and others.
- **Reasoning:** CLAUDE.md §6 ("no `String` for message content in views")
  and §1.10.
- **Verified:**
  - `scripts/test.sh` at `fb6f140`: harness case 1 (units), case 4 at 64,
    200, 4 096 and 65 000 units (live hits while open; 0 UTF-8, 0 UTF-16 and
    0 glyph hits after the wipe, `GlyphFlush` and the lock), case 5 (a kept
    `OpenText` after the lock) and case 6 (a live `String` of a letter is
    seen, so the scanner works): 5 of 5 each.
  - WP2 review: a probe file with one line per new grep pattern passed the
    old grep and failed the new one on all 14 lines.

### D-0045 — Rendering: one `CTLine` at a time into the protected layer's pixel buffers

- **Date:** 2026-09-28
- **Decision:** Design §6.4 and §7.2 as built, with D-0034 (WP2, WP7, WP11):
  1. Layout is `CTLine` only (no `CTTypesetter`, `CTFramesetter` or
     `NSLayoutManager`): windows of at most 448 units, broken at a space,
     never splitting a surrogate pair. One content font app-wide
     (`NSFont.systemFont(ofSize: 13)`; metadata 11 pt).
  2. Content views (`ContentView` in `UI/OpaqueView.swift`) draw each line
     straight into IOSurface-backed `CVPixelBuffer`s shown through the
     protected layer (D-0046); `draw(_:)` draws nothing. A view holds three
     buffers, sized from its bounds within its clip view, rounded up to 256
     px. They are zeroed in place when its text is wiped and on lock, and
     zeroed and dropped when the view scrolls out of sight or leaves its
     window.
  3. `LSEnvironment` sets `MallocScribble=1`, and LaunchGuard refuses a
     launch without it (D-0047). `GlyphFlush` lays out and draws filler
     lines of every length 1 to 448 once in the lock sequence and after
     every compose close.
  4. The Verify build's `SelfScan` logs `selfscan u8 u16 glyph scribble
     probe` after the lock and a control line with `needle` at its start;
     see `docs/VERIFY.md` "Changes from the design" for why `glyph` is 0
     even while a letter is shown.
- **Reasoning:** CLAUDE.md §2 (framework copies: one line at a time from a
  wipeable buffer), §1.10, and D-0034. On macOS 26.2, drawing in `draw(_:)`
  made AppKit's display list (`CG::DisplayListEntryGlyphs`) keep the glyph
  ids of every drawn line until the lock's run-loop turn ended; drawing into
  Brev's own buffers leaves nothing there.
- **Verified:**
  - WP7: with lines drawn straight into AppKit's context, the view host left
    `glyph=3` after the lock (the 3 subjects in the thread list;
    `malloc_logger` backtraces end in
    `CG::DisplayListEntryGlyphs::setGlyphsAndPositions` under
    `SecureListView.drawContent`); drawn into Brev's own bitmap, 0 in 3 of 3
    and 10 of 10 runs.
  - `scripts/test.sh` at `fb6f140`: harness case 4 (above), case 6 without
    scribbling (glyph ids left after the lock at 4 096 and 65 000 units, so
    the needle and scribbling matter), case 7 (the scribble probe: a freed
    32 KiB block keeps no copy with scribbling, and keeps it without): 5 of
    5 each. The lock probe: the lock sequence zeroes every content view's
    pixel buffers and `draw(_:)` draws nothing (a `draw(_:)` that draws
    content fails it).
  - WP11 review: the view host's checks "scrolled out of sight: a content
    view holds no pixel buffers, and its old ones are zero" and "scrolling
    in: a letter keeps one pool" fail on `32a9682` and pass on the fix (3 of
    3); 30 letters scrolled in 10 pt steps held 27 MiB of buffers instead of
    189 MiB. V39 on the Verify build waits for the human run.

### D-0046 — Window hardening and the capture defence as built (D-0034)

- **Date:** 2026-09-28
- **Decision:** Design §8.1 and §8.2 with D-0034 (WP3, WP11, review round
  1):
  1. `Hardening.apply` sets `sharingType = .none`,
     `isExcludedFromWindowsMenu`, `isRestorable = false` and `tabbingMode =
     .disallowed`, and recurses into child windows and sheets.
     `HardenedWindow` (the main window and `ConfirmSheet`; the compose sheet
     is presented on the main window) applies it in `beginSheet`,
     `beginCriticalSheet` and `addChildWindow`.
     `NSWindow.allowsAutomaticWindowTabbing = false`. The main window has no
     `.miniaturizable` (AppKit shows the button, disabled). There is no
     `NSAlert`; the open-documents event is ignored so AppKit shows none
     (D-0063).
  2. Every view that can show content, the compose sheet's recipient,
     subject and body and the letter headers included, draws through an
     `AVSampleBufferDisplayLayer` with `preventsCapture = true` (D-0045).
     `sharingType = .none` stays the first defence.
  3. Only `UI/OpaqueView.swift` may name an `AV…`, `CM…` or `CV…` symbol
     (test.sh), so AVFoundation, CoreMedia and CoreVideo stay in the
     protected layer (CLAUDE.md §4).
  4. Not used: detecting capture, window levels and collection behaviours
     (the capture spike found no protection or signal in them).
- **Reasoning:** CLAUDE.md §2 (screenshot, recording and screen-reading
  agents), §3.2 ("sheets and child windows get the same settings as their
  parent") and D-0034. The capture spike captured a default sheet and a
  default child window of a `.none` window through every path.
- **Verified:**
  - The capture re-run and the view host matrix: D-0052 (the protected layer
    leaves every pane empty on every path, including the two that capture
    `.none` windows).
  - WP11: the view host check "a default-sharing sheet and child window on
    `MainWindow` get `.none`, not restorable, excluded from the Windows
    menu" passes. WP11 review: `CVPixelBufferCreate` with only `import
    AppKit`, `import AVKit` and `import class
    AVFoundation.AVSampleBufferDisplayLayer` each passed the old import grep
    and fail the symbol check; test.sh at `fb6f140` passes it.
  - WP4, `capture-probe` on Brev's onboarding window (Release): excluded
    from all 8 ScreenCaptureKit paths, from
    `CGWindowListCreateImage`/`CGDisplayCreateImage` and from `screencapture
    -x/-R/-V`; `-l` fails; `CGDisplayStream`, `AVCaptureScreenInput` and the
    `dlsym` build show the window with interface text only (it has no
    content pane yet).
  - V9 fails as written: `windows` finds 4 off-screen menu-bar-sized windows
    with sharing state 1 that every app owns (D-0052, D-0053). V4 to V8 with
    a letter open wait for the human run.

### D-0047 — Launch hygiene

- **Date:** 2026-09-28
- **Decision:** Design §8.6 as built (WP3, review round 2),
  `Shared/LaunchGuard.swift`, the first thing `main.swift` runs:
  1. Release and Verify refuse any argument besides `argv[0]` (`launch
     refused: arguments`, `exit(64)`). No `-psn_` exception: `open` passes
     none, and a Finder or Dock launch is not yet measured.
  2. The argument domain is emptied with `removeVolatileDomain` followed by
     `setVolatileDomain([:])`, because on macOS 26.2 `removeVolatileDomain`
     alone does nothing.
  3. A launch is unsafe if an environment variable starts with `NSZombie`,
     `CFZombie`, `NSDebug`, `NSTrace`, `NSDeallocateZombies`,
     `NSObjCMessageLogging`, `OBJC_`, `MallocStackLogging`, `CFLOG` or
     `OS_ACTIVITY_DT_MODE`, or `MallocScribble` is not `1`: Brev then
     re-executes itself once with those variables removed and
     `MallocScribble=1` (marker `BREV_LAUNCH_CLEANED=1`). It is also unsafe,
     with no re-exec, if `NSTraceEvents`, `NSZombieEnabled`,
     `NSDebugEnabled`, `NSDeallocateZombies`, `TSMEventTracing` or one of
     its 13 `TSMTrace…` siblings is true in `UserDefaults.standard` (global
     domain included). A launch that stays unsafe shows only
     `launch.error.unsafe`, and nothing is decrypted in that process.
  4. The environment is cleaned by a prefix denylist. The launch spike's
     alternative, an allowlist of what LaunchServices sets, is not built: it
     waits for the Finder and Dock environments and the owner.
- **Reasoning:** CLAUDE.md §1.1 and §2 (keyloggers). `NSTraceEvents` only
  traces with get-task-allow, but that gate is undocumented, so the check
  stays as the second defence §6 asks for. `TSMEventTracing` traces key
  events in Release (D-0052, D-0064). An argument-domain override cannot
  neutralise a `defaults write -g`, because HIToolbox reads the global
  domain first.
- **Verified:**
  - `scripts/test.sh` at `fb6f140`: harness case 2 (LaunchGuard on injected
    environments and defaults, `TSMEventTracing` asserted by name, and a
    helper run started with `-NSTraceEvents YES -NSZombieEnabled YES` whose
    domain is empty afterwards) 5 of 5. WP3 mutations: a remove-only
    argument domain and a list without `OBJC_` each fail it; the helper run
    shows removal alone leaves 2 of 2 defaults set.
  - WP4, the Release build: `open "$APP" --args -NSTraceEvents YES` left no
    Brev process after 4 s and logged `launch refused: arguments`; `open
    --env NSZombieEnabled=YES` logged `launch unsafe: environment;
    re-executing`, then `route onboarding` in the same PID, and `ps -wwE`
    showed `MallocScribble=1` and no `NSZombieEnabled`; `open --env
    MallocScribble=0` re-executed with `MallocScribble=1`.
  - Not yet run: the `defaults write -g` parts of V28, and V49 from the
    Finder and the Dock.

### D-0048 — Synthetic input: the PID rule and `HumanButton`

- **Date:** 2026-09-28
- **Decision:** Design §7.1 and §8.5 as built (WP3, WP5, WP8):
  1. `InputFilter` keeps CLAUDE.md §3.2's rule unchanged: an input event
     with no `CGEvent`, or with `.eventSourceUnixProcessID != 0`, is
     dropped, with no exception for Brev's own PID. `BrevApplication`
     applies it in `sendEvent` and in `nextEvent` to every input type (keys,
     modifier flags, all mouse buttons, moves and drags, scrolling, gestures
     including `.quickLook`, `.directTouch` and `.changeMode`, tablets), and
     logs `dropped synthetic <type> pid=<n>`. Other events (the window
     server's with PID 0, AppKit's own with Brev's PID) are never filtered.
     `SecureComposeView` checks again.
  2. Only accepted input stamps the idle clock (D-0050) and marks
     `inHumanDispatch`.
  3. `HumanButton` (every button that unlocks, creates keys, confirms,
     resets or sends, and the onboarding checkbox): `sendAction` runs only
     inside human dispatch with a mouse-up or key event that passes the
     filter; `accessibilityPerformPress` returns false on the button and its
     cell. Opprett nøkler is enabled only by the checkbox's own human
     action. An AX press returns success and does nothing, so V13 judges the
     effect.
  4. Open: that hardware events carry PID 0 is believed, not measured. If
     the real keyboard types nothing in the compose sheet, the rule rejects
     hardware too, and the work stops for the owner. `CGEventPost` at the
     HID and session taps, System Events, Accessibility Keyboard and Screen
     Sharing are not yet tested (V32, V33 under the owner's supervision).
- **Reasoning:** CLAUDE.md §2 (synthetic input is rejected in the app) and
  §3.2. The input spike measured that the window server does not deliver a
  posted event with the PID its poster wrote (D-0052), so the rule holds for
  the paths tested. Widening the rule would need that evidence and a new
  entry.
- **Verified:**
  - `scripts/test.sh` at `fb6f140`: harness case 2 (`InputFilter` on
    in-memory `CGEvent`s: PID 0 kept; own PID, another PID and none dropped)
    5 of 5; an own-PID exception fails it (WP3). The lock probe: a synthetic
    key dropped in `sendEvent`, and one posted to the probe's own PID and
    dropped in `nextEvent`, do not move the idle clock (the review's B-U32
    mutant fails it).
  - WP4 at Brev on onboarding: `poster key --via topid` and `--via ax`, and
    `poster click` on *Fortsett*: 18 `dropped synthetic` lines, all with the
    poster's PID (6 key-downs, 6 key-ups, 3 mouse-downs, 3 mouse-ups); the 4
    keys sent with `AXUIElementPostKeyboardEvent` did not arrive; the page
    did not change. `axdump --press Fortsett` returned `AXError=0` and the
    page did not change.
  - WP8, view host compose mode: `a`, ⌘↩ and Escape posted to its own PID
    changed nothing (`dropped synthetic 10` ×4, `11` ×3); an AX press on
    *Send* did nothing.

### D-0049 — Compose input and secure event input

- **Date:** 2026-09-28
- **Decision:** Design §7.3 as built (WP6, WP8); the §7.4 fallback stays
  shelved:
  1. `SecureComposeView` takes keys in `keyDown` only: `ComposeKey` maps key
     code and flags to an action (⌘↩ sends, ⌘-arrows move, every other ⌘ and
     ⌃ combination does nothing), and every other key goes to
     `UCKeyTranslate` on `TISCopyCurrentKeyboardLayoutInputSource()`. It is
     not an `NSTextInputClient`, `inputContext` is nil, `insertText` is
     ignored, every `NSTextInputTraits` trait is `.no`,
     `writingToolsBehavior = .none`, `writingToolsCoordinator = nil`, no
     Touch Bar. `NSEvent.characters` is never read.
  2. Dead keys: pending means 0 units and a state that is not 0 (the state
     keeps upper bits after a composition). The state is reset on focus
     loss, on a keyboard-layout switch (compared by input source id) and by
     any named key; Delete removes only a waiting accent. A key repeat is
     translated with `kUCKeyActionAutoKey`, so a held ´ stays one waiting
     accent.
  3. `EditModel` over a `SecretText` (subject 256 units on one line, body 65
     536): caret moves by composed character, visual line and document;
     control characters (Home, End, page and function keys) are refused
     silently; a newline comes only from Return; only an insert over the
     byte limit beeps. The sheet is a fixed 600 × 460 pt.
  4. `SecureInput` enables secure event input only while a field is first
     responder, its window is key and Brev is active, and disables it on
     blur, resign key, resign active, sheet close and lock, keeping its own
     Bool so the counted calls balance.
- **Reasoning:** CLAUDE.md §1.6 and §2 (keyloggers, system AI features). The
  input spike: the key-only view produced the whole Norwegian table in a
  sandboxed hardened app, with secure input on and off; it has no input
  context, so dictation, pickers, press-and-hold, autocorrect and inline
  predictions have nothing to deliver text to; secure input stays registered
  while the app is hidden or inactive, so disabling it is required (D-0052).
- **Verified:**
  - `scripts/test.sh` at `fb6f140`: harness case 2 (EditModel, ComposeKey,
    KeyTranslator: the V35 table and the dead keys on
    `com.apple.keylayout.Norwegian`, ¨ then e on the U.S. layout gives e, a
    held ´ stays one accent, every ⌘ and ⌃ key that must do nothing does
    nothing, a typed marker leaves 0 hits after the wipe) 5 of 5. WP6: eight
    mutations (for example no control-character filter, or the modifiers not
    passed to `UCKeyTranslate`) each fail it; WP6 review: without the
    layout-switch reset, ¨ then e on the U.S. layout gave è.
  - WP8, view host compose mode: secure input on exactly while a field has
    focus in the key sheet of the active app (`kCGSSessionSecureInputPID` =
    the host), off after a send, Escape and the lock sequence, and none
    after quit; 50 AX elements with no marker; `NSTextInputContext.current`
    nil with a field focused; the pasteboard's `changeCount` unchanged; 0.00
    % ink in the three fields on every capture path (negative control 2.5 to
    9.0 %).
  - Not yet run (real keyboard): V30, V31, V34, V35.

### D-0050 — Lock triggers and the lock sequence

- **Date:** 2026-09-28
- **Decision:** Design §8.3 and §8.4 as built (WP3, WP10):
  1. **Triggers**, all of which only lock: `didResignActive` (except while
     an unlock is in flight); the distributed `com.apple.screenIsLocked`,
     observed through the selector API with `.deliverImmediately`;
     `NSWorkspace` `willSleep`, `screensDidSleep` and
     `sessionDidResignActive`; ⌘L, *Lås* and *Lås Brev*; quit
     (`applicationWillTerminate`). `screenIsUnlocked` and `didWake` are only
     logged, and Brev never calls `activate(ignoringOtherApps:)`.
  2. **Idle:** 300 s without accepted input on Brev's own `CLOCK_MONOTONIC`
     clock (D-0048), checked every 15 s. Every lock and sync timer runs in
     the common run-loop modes, so it fires while a menu is open.
  3. **Not built:** the `CGSessionCopyCurrentDictionary` poll (its
     `CGSSessionScreenIsLocked` key is undocumented and its value while
     locked was never seen; added only if V23 fails), a `didHide` trigger (a
     hide was always followed by resign active), and the activation wait
     after an unlock (D-0037).
  4. **Lock sequence** (idempotent, main thread): new generation, timers
     stopped, `SecureInput` off, tracking cancelled on the main menu and on
     every submenu (the main menu's own call did not close a popped-up
     submenu); sheets wiped and ended (the draft is discarded); the current
     screen wiped; `ContentView.blankAll()` zeroes every pixel buffer in
     place; `GlyphFlush`; `brev.lock()`; the lock screen (if Brev was
     unlocked); `window.display()` and `CATransaction.flush()`, so the
     window server holds the blank frame in the same run-loop turn; `lock
     reason=<…>`; in the Verify build, `SelfScan`.
  5. **Known gap (deferred, for the owner):** while the compose sheet or
     `ConfirmSheet` is attached, AppKit drops a quit (the menu item and the
     quit Apple Event) without asking the delegate, so quit does not run the
     lock. Every other trigger still locks.
- **Reasoning:** CLAUDE.md §3.2 (auto-lock, blank-on-lock) and §1.10. The
  lock spike and WP10 probes (D-0052): posted events reset the system's HID
  idle counter, so idle must be Brev's own clock; distributed notifications
  can be held back while an app is inactive; `display()` alone left the new
  layer tree uncommitted until the turn ended.
- **Verified:**
  - WP10: `tools/viewhost --triggers switch` passed 4 of 4 (with an unlock
    in flight the Finder becoming active did not lock; once unlocked it ran
    the whole sequence and logged exactly `lock reason=resignActive`).
    `--triggers idle --post` locked 301 s after the last input with `lock
    reason=idle`; 13 ↓ keys posted to the host were dropped and did not
    reset the clock; the Brev menu, popped up at 290 s, was closed by the
    lock. The team-signed Release build, frontmost on onboarding: after
    `open -b com.apple.finder` it logged `lock reason=resignActive`.
  - WP10 probes: after `display()` alone the old view was still on the
    window server in 3 of 3 rounds, with `CATransaction.flush()` the lock
    screen in 3 of 3; a zeroed pixel buffer showed blank at once.
  - `scripts/test.sh` at `fb6f140`: the lock probe's 12 checks (the lock
    sequence locks Rust, zeroes every pixel buffer, wipes lists and letters
    and shows the lock screen; dropped input does not move the idle clock)
    pass.
  - Review round 1: with a titled sheet attached, `terminate` and a quit
    Apple Event returned and the process was alive 3 to 4 s later, in three
    separate builds; without a sheet it quit. Not yet run: V22 to V25, V46,
    V47.

### D-0051 — Tests and verification tools

- **Date:** 2026-09-28
- **Decision:** Design §4.1 (Verify), §10 and §11 as built (WP2 to WP4, WP7,
  review rounds):
  1. No XCTest. The Swift CLI harness (`app/Tests`) runs cases 1 to 7, each
     5 times under `MallocScribble=1`, plus the negative controls without
     scribbling (case 6 at 4 096 and 65 000 units, case 7). The lock probe
     (`app/Tests/Lock`) runs `LockController` and `UnlockService` with a
     software KEK and no window on screen. Both run in test.sh.
  2. The view host (`tools/viewhost`) runs Brev's real mail window, compose
     sheet, lock sequence and triggers with fake letters and a software KEK;
     test.sh only compiles it, VERIFY V53 runs it.
  3. The Verify configuration is Release plus `BREV_SELFSCAN`
     (`SelfScan.swift`, `scan.c`); `scripts/build.sh` never builds it, and
     V50 checks that Release holds no self-scan symbol.
  4. `tools/verify/` holds the verification tools (`capture-probe`,
     `capture-probe-26`, `windows`, `axdump`, `poster`, `keylisten`,
     `padcheck`, `TouchIDProbe.app` and its scrub-0 and scrub-128 variants,
     `InputLab.app`), built into `core/target/verify` and never linked into
     Brev.app, and `tools/verify/spikes/` the spikes' sources. The
     rogue-Brev app and the anchor probe are not built (D-0035).
  5. test.sh on macOS: `gen-bindings.sh`, `xcodegen generate`, fmt, clippy,
     the tests, the release scrub tests, the allocator check, the FFI
     surface checks, the patch marker, the forbidden-API grep (allow-list
     `scripts/allowed-apis.txt` with reasons), the AV/CM/CV symbol check,
     the Xcode-minimum check, `cargo audit`, the harness, the lock probe,
     the view host compile, the tools' type-check and `capture-probe
     --selftest`, and a team-signed Xcode Debug build. This closes D-0028
     item 2 (a stale archive).
- **Reasoning:** CLAUDE.md §1 "ALWAYS" (tests that prove the invariants, and
  can fail). A hosted XCTest bundle would put a window on screen; nothing in
  test.sh opens a window or asks for Touch ID.
- **Verified:**
  - `scripts/test.sh` at `fb6f140`, macOS 26.2, 2026-09-28: exit 0 in 2 min
    45 s. Rust: 59 tests (brev-core 31 unit, 11 Phase 1, 10 Phase 2, 3
    doctests; brev-proto 4) and the 2 release scrub tests; `cargo audit`
    clean over 123 crates and 1 273 advisories; 14 harness lines, each 5 of
    5; the lock probe's 12 checks; `capture-probe --selftest` 21 checks; `**
    BUILD SUCCEEDED **` for the Debug build.
  - WP4 review: with the old verdict rules put back, 15 of the self-test's
    checks fail.

### D-0052 — Facts from the GUI spikes and the capture re-run (macOS 26.2, 25C56)

- **Date:** 2026-09-28
- **Decision:** Facts only; the decisions that use them are D-0034, D-0035
  and D-0045 to D-0050. The spikes ran on 2026-09-27/28 with small
  sandboxed, hardened, ad-hoc-signed test apps (bundle ids
  `no.brev.spike.*`), each checked by a second agent; where the checker
  disputed a claim, the corrected wording is what is recorded here. Sources
  are in `tools/verify/spikes/`.
  1. **Capture (U1) and the re-run.** `sharingType = .none` keeps a window
     out of every ScreenCaptureKit path tested (display filter, display
     excluding applications, including filters, `captureImage(in:)`,
     `captureScreenshot(contentFilter:)` and `(rect:)`, window filter with
     `includeChildWindows`, `SCStream` frames), out of `screencapture
     -x/-R/-V` (`-l` fails on a lone `.none` window) and out of
     `CGWindowListCreateImage`/`CGDisplayCreateImage` from a 14.0 build. It
     does not keep it out of `CGDisplayStream` (also through `dlsym` from a
     26.0 build) or `AVCaptureScreenInput`. A default sheet or child window
     of a `.none` window has sharing state 1 and is captured by every path.
     WP11 re-ran the two runs whose logs had been lost, with logs kept: a
     `.none` window at level 0 was captured with its marker readable through
     `CGDisplayStream` (M = 83.8 %), the `dlsym` build (83.8 %) and
     `AVCaptureScreenInput` (83.7 %), and excluded everywhere else; the
     control window was visible on every path (C = 85.3 to 85.4 %). The
     negative control: with `preventsCapture = false` the protected content
     was captured (P = 92.4 %/91.3 % through `CGDisplayStream` and `dlsym`,
     92.2 %/91.1 % through `AVCaptureScreenInput`, 92.4 % through SCK and
     `screencapture` for the default-sharing window); with `true` only the
     window background showed (100 %) on every path, at level 0 and at
     levels 3/4. Against the view host's real views: `--capturable
     --unprotected` showed the letters on every path (ink 13.9 % letters,
     8.4 % contacts, 3.1 % threads); the layer alone (`--capturable`) gave
     0.00 % ink in all three panes on every path; Brev's default gave 0.00 %
     on the three paths that capture the window and was excluded from the
     others. Detecting capture and window levels or collection behaviours
     were not shown to help. Not tested: whether the two leaking paths need
     the Screen Recording permission, and whether the menu-bar recording
     indicator shows for them (a window-list watcher saw a Control Center
     indicator only for SCK and `screencapture`).
  2. **Input: the PID rewrite (U2).** 20 variants of `CGEventPostToPid`
     (source nil, private, combined state or HID state, with field 41 left,
     set to 0, to the target's PID, to 1, or to 0 with state 1) all arrived
     with a distinct non-zero PID, very likely the poster's, never 0, 1 or
     the target's; across all runs none of 536 posted key and click events
     had PID 0 and none reached `sendEvent` without a `CGEvent`.
     `eventSourceStateID` and `eventSourceUserData` arrive as the poster set
     them, so neither tells a human from a script; every posted event had
     uid 503, and whether a poster can change the uid, or what hardware
     events carry, was not tried. The posted clicks tried arrived with
     window number 0 and did not press the button.
     Posted keys reach the first responder of a hidden, inactive app.
     `AXUIElementPostKeyboardEvent` returns success and delivered nothing to
     InputLab or to Brev; to the view host its keys arrived with the view
     host's own PID and were dropped (WP4). Autorepeat key-downs sent with
     `CGEventPostToPid` never arrived. Not measured: hardware events' PID,
     state and uid, and `CGEventPost` at the session and HID taps, System
     Events, Accessibility Keyboard, Voice Control, Screen Sharing and
     Universal Control.
  3. **Input: text, secure input, accessibility (U2, U3).** The key-only
     view produced every V35 entry from posted key codes except Caps Lock
     and key repeat, identically with secure input on and off;
     `TISCopyCurrentKeyboardLayoutInputSource` still returns the Norwegian
     layout under secure input. `UCKeyTranslate` leaves upper bits in the
     dead-key state after a composition (0x10000 to 0x50000). Secure input
     works in the sandboxed hardened app, and stays registered session-wide
     while the app is hidden or inactive until it calls Disable. A
     listen-only tap for the app's PID saw posted keys with their values
     while secure input was off and nothing while it was on. With no Edit
     menu macOS adds no Writing Tools, AutoFill, Dictation or Emoji items.
     Custom views with the overrides, and even a plain `NSView` or a naive
     `NSTextInputClient`, expose no text to Accessibility; AX hit tests over
     views whose `accessibilityHitTest` returns nil give -25208; an AX press
     on a `HumanButton` returns 0 and does nothing; menu items are
     AX-pressable with no current event. Every element lists the
     undocumented `AXReplaceRangeWithText`; four guessed parameter shapes
     changed nothing.
  4. **Lock triggers (U4).** Resign active arrived 2 to 10 ms after another
     app's activation notification (launch, reopen,
     `NSRunningApplication.activate` from a CLI, another app's
     self-activation), and 2 to 16 ms after each of 5 hides. Named
     distributed notifications, also `com.apple.*` names, reach the
     sandboxed app; in 2 of 2 spike runs a default (block) observer got
     nothing while the app was inactive until a deliver-immediately post
     came, while WP10's probe saw no hold-back for an accessory app.
     `CGSessionCopyCurrentDictionary` works in the sandbox (11 keys;
     `CGSSessionScreenIsLocked` absent while unlocked).
     `CGEventSource.secondsSinceLastEventType(.combinedSessionState, …)`
     works in the sandbox and matches an unsandboxed reading; `postToPid`
     events reset the `.hidSystemState` counter (6 of 6) and not
     `.combinedSessionState`. A timer in the common modes fired during menu
     tracking (12 ticks, 0 for the default mode).
     `NSApp.activate(ignoringOtherApps:)` activated an app from the
     background; `NSApp.currentEvent` still held the last posted event
     inside a notification handler. Not measured: real ⌘-Tab, ⌃⌘Q, sleep,
     display sleep, and whether the Touch ID panel takes activation (U4.1);
     the lock spike's own Touch ID step tested the CryptoKit + HPKE path
     D-0035 replaced.
  5. **Launch (L, M).** AppKit reads `NSTraceEvents` in `-[NSApplication
     init]`, and `_DPSSetEventsTraced` turns tracing on only with the
     get-task-allow entitlement or on internal OS builds (disassembly),
     which matched the runs: in a build without get-task-allow, `--args
     -NSTraceEvents YES` logged nothing, while the get-task-allow control
     printed every key event with its characters on stderr.
     `removeVolatileDomain` alone left the argument domain in place (the
     control traced); followed by `setVolatileDomain([:])` it cleared it;
     WP3 saw the same in Brev's harness. `NSTraceEvents` and 154 debug keys
     as environment variables had no effect. With 126 and then 28 debug keys
     of AppKit, Foundation, CoreFoundation and HIToolbox set as arguments,
     the only key-event output without get-task-allow came from
     `TSMEventTracing` (TSM queue traces with dead-key state); by static
     analysis the same flag gates `TSMProcessRawKeyEvent: …
     virtualKeyCode=%x, modifiers=%x`, and HIToolbox reads it from the
     global domain first. `open` passes no `-psn_` argument and passes the
     caller's whole environment; `--env` overrides `LSEnvironment`.
     `LSEnvironment`'s `MallocScribble=1` is in effect after `open` (a scan
     after free found 0 marker hits in 79 of 79 runs with it, and 18 686 in
     each of 6 controls without it); libmalloc scribbles whenever the
     variable is present, whatever its value; freed blocks of 1 KiB or less
     were zeroed even without it. `execve` of its own binary works in the
     sandbox and keeps the PID, the sandbox and the hardened flags; running
     the binary directly skips `LSEnvironment`. Review round 2: the view
     host started with `-TSMEventTracing YES` (no LaunchGuard) traced every
     key-down and key-up of 3 posted keys to stderr (28 lines) with a
     compose field focused and secure input on. Not measured: Finder and
     Dock launches, and real typing with all debug keys on.
  6. **Keys and signing (the anchor spike A, and the keychain spike).** A
     login-keychain item made by an ad-hoc sandboxed app was created and
     read back in a later launch with no prompt, but a rebuild could not
     read it (-25293); any same-user process could overwrite its value
     silently (`SecItemUpdate`), and an unsandboxed one could delete such an
     item silently with `SecKeychainItemDelete` (checked on an item an
     unsandboxed program made; `SecItemDelete` gave -25244); none of 5
     variants planted a value its creator then read silently. So the anchor
     would be tamper-evident at best, and it was dropped with D-0035. The
     owner's Apple Development keys of team `AV26DNQ5SC` let
     `/usr/bin/codesign` sign without a prompt (partition list includes
     `apple:`), and a wildcard "Mac Team Provisioning Profile: *"
     (`AV26DNQ5SC.*`) is installed, which Brev itself is signed with.
     Verified: an agent session got a profile with `xcodebuild
     -allowProvisioningUpdates -allowProvisioningDeviceRegistration`, signed
     a program that is not Brev (the keychain probe) with Brev's App ID and
     keychain group `AV26DNQ5SC.no.brev.app`, and created, found and deleted
     a Secure Enclave key in that group, with no prompt (no SecurityAgent
     log entry). WP5's probe and WP4's `TouchIDProbe` did the same with
     Brev's own key names. Not tested: a second program reading or replacing
     items that the real Brev made. This is the risk D-0062 raised and
     CLAUDE.md §2 now accepts for test letters only.
  7. **Found while building.** Secure Enclave key items in the keychain
     report `pdmn=dk` while their ACL says `akpu` (the Enclave enforces the
     ACL; `sync=0`). Security's software ECIES returns `errSecParam` (-50)
     for a tampered wrapped DEK. Every regular app, Brev included, owns 4
     off-screen windows of the menu bar's size with sharing state 1, which
     show only the menu bar (WP4). `open -a Brev <file>` made AppKit show an
     unhardened alert with sharing state 1 until Brev ignored the event
     (D-0063). A quit is dropped while a sheet is attached (D-0050).
- **Reasoning:** CLAUDE.md §6: where macOS behaves differently from its
  documentation (`sharingType`, `removeVolatileDomain`), record it and add a
  second defence. Design §14.2 sends these results here.
- **Verified:**
  - The spike and checker results, with their logs, are in the session
    scratchpad (`p2/{capture,input,lock,launch,anchor}` and the `*-skeptic`
    folders; volatile) and in the workflow journals. The WP11 re-run logs
    are `p2impl2/wp11/capture/out/log-check1-level0.txt` and
    `log-check2-level{0,4}-{nocp,cp}.txt`, with crops.
  - Human steps still pending: see `docs/USER_SESSION.md` (the capture
    indicator, typing with the real keyboard, the Finder launch and typing
    with all debug keys on); the rest is covered by VERIFY rows on the real
    Brev.

### D-0053 — Phase 2 verification: the machine-run rows, the human rows pending

- **Date:** 2026-09-28
- **Decision:** Phase 2 is code-complete and its automated checks pass; its
  definition of done (CLAUDE.md §5: the checklist passes, the build is
  sandboxed and hardened) is not yet met, because most of `docs/VERIFY.md`
  needs a human with Touch ID. The machine-run part is recorded below and in
  `docs/VERIFY-RESULTS.md`. What still needs the owner: the human run
  (`docs/USER_SESSION.md`); V9, which fails as written because of the 4
  system menu-bar windows (count only the windows Brev makes, or accept);
  and the open items in the Phase 2 summary. The open item that was not a
  row, the signing key on this Mac (D-0062), was accepted by the owner on
  2026-09-28 for test letters only (CLAUDE.md §2, commit `1aeccc5`); real
  letters go only on a Mac without that key.
- **Reasoning:** CLAUDE.md §5 and `docs/VERIFY.md` "Failures and results": a
  row passes only as written, and a failure is never reworded as residual
  risk without the owner.
- **Verified:**
  - At `fb6f140`, macOS 26.2 (25C56), Xcode 26.2 (17C52), 2026-09-28, nobody
    at the Mac, on a Release build from `scripts/build.sh` and a Verify
    build from `tools/verify/build.sh` (both exit 0): V1 passes on both
    (`flags=0x10000(runtime)`, `TeamIdentifier=AV26DNQ5SC`; entitlements
    exactly `app-sandbox`, `keychain-access-groups` =
    [`AV26DNQ5SC.no.brev.app`], `com.apple.application-identifier` and
    `com.apple.developer.team-identifier`; no `get-task-allow`; `codesign
    --verify --strict` ok). V2 passes on both (0 forbidden plist keys,
    `BrevApplication`, `MallocScribble` 1, no nested bundle, `Contents` =
    `_CodeSignature embedded.provisionprofile Info.plist MacOS PkgInfo
    Resources`). The `sdef` half of V3 passes (error -192, exit 1). V21
    passes (indexing enabled; nothing found outside the checkout;
    `docs/VERIFY.md` found once; no CoreSpotlight, 0
    `CSSearchable…`/`NSUserActivity` symbols). V50 passes (Release 0
    self-scan symbols, Verify 10). V45 passes (`scripts/test.sh` exit 0,
    D-0051). V53 passes: the view host's mail run (37 checks), compose run
    (46) and `--triggers switch` run (21) each printed PASS and exited 0,
    and no view host process was left.
  - WP4 run at `b6f2e3c` (`docs/VERIFY-RESULTS.md`): V1, V2, V21, V45 and
    V50 pass; partial passes for V3 (`sdef` half), V5 to V7, V11, V13 and
    V26 (onboarding window only), V19 (no letter written), V22 (resign
    active, not ⌘-Tab), V28 (arguments and environment), V29 (process part),
    V40 (keychain part) and V49 (`open` launches); V9 fails as written.
  - Review round 1: the view host's mail and `--triggers switch` runs passed
    and its compose run passed 6 of 6 (V53); `open -a <Brev.app> <file>` to
    a running Debug build added no window and logged `open event ignored
    count=1` (V54's first part, not yet on Release).
  - Every other row, and the human half of each partial row, waits for the
    owner: V3 (`osascript`), V4, V5 to V8 with a letter open, V9 (compose
    sheet and `ConfirmSheet`), V10, V12 to V20, V22 to V27, V28 (`defaults
    write -g`), V29 (files), V30 to V44, V46 to V49, V51, V52 and V54.

### D-0062 — Spec change: the keychain binding does not hold on a Mac with Brev's signing key (records 39e1858; open for the owner)

- **Date:** 2026-09-28
- **Decision:** Commit 39e1858 changed CLAUDE.md §2 and §3.2 and
  `docs/THREAT_MODEL.md` without an entry; this is that entry, and it
  narrows D-0035. On a Mac that holds Brev's team signing key (a
  developer's Mac), any same-user process can sign its own program with
  Brev's App ID and keychain group, without a prompt, and so replace
  Brev's keychain items (both Enclave keys and the wrapped DEK) together
  with the stores, or ask for Touch ID on Brev's keys. D-0035's "other
  programs can neither use nor replace it", and its closing of D-0032
  item 2 and D-0033 items 1 and 5, hold only on a Mac without that key.
  This Mac holds it, and it is the only Mac Brev runs on. The owner has
  not decided: the remedies §2 names are real letters only on a Mac
  without the key, or the key behind a password prompt. Until the owner
  decides, the §2 item is open, not accepted residual risk (§2 now says
  so), and Phase 2 is not done (`docs/VERIFY.md`, "Failures and
  results"). The unqualified claims were qualified: the header of
  `app/Sources/Keys/KeyStore.swift` and VERIFY's "Changes from the
  design" (V52, and why the rogue-Brev test was dropped).
- **Reasoning:** Entries are append-only and a narrowed decision gets a
  new entry that points back (this file's rules; CLAUDE.md §1 "ALWAYS").
  Without it, D-0035 read as closing D-0033 item 5 ("Developer ID and
  keychain storage are required before Brev holds real letters") on this
  Mac too, and a reviewer of Phase 2 could sign it off with the item
  untracked. V52 checks only that old stores put back do not unlock; it
  says nothing about stores and keychain items replaced together by a
  program signed into Brev's identity. VERIFY forbids calling a failure
  residual risk without the owner.
- **Verified:** The fact is the one §2 records: on 2026-09-28 an agent
  session signed its own program into Brev's App ID and keychain group
  with `xcodebuild -allowProvisioningUpdates`, with no prompt. Review
  round 1 checked that 39e1858 touches only CLAUDE.md and
  `docs/THREAT_MODEL.md`. The owner's decision is still open.

### D-0063 — Phase 2 review round 1: residue, tests that can fail, an ignored open event, spec text

- **Date:** 2026-09-28
- **Decision:** The confirmed findings of review round 1 are fixed:
  1. **Peer DEKs on the unlock stack.** `unlock_all` (and `create_in`) in
     `ffi.rs` are `#[inline(never)]`. Inlined into `Brev::unlock`, moving
     the two peer DEKs into their array left copies in the frame that
     calls `Finish`'s 64 KiB scrub, above the area it overwrites, so they
     survived the lock on the unlock thread's stack. Harness case 3 and
     `TouchIDProbe` (V51) get needles for both peer DEKs (CryptoKit HKDF
     in the helper, as `echo::peer_dek` derives them): one copy each while
     unlocked (Rust's), none after create and after lock.
  2. **Scrub call sites pinned.** The scrub-count tests cover
     `echo::peer_dek` (crypto.rs) and the scrub `Brev::create` runs after
     `create_in` (ffi.rs).
  3. **V39 can fail when scribbling does not work.** `SelfScan` runs a
     scribble probe after the lock (`app/Tests/scan.c`): a 32 KiB block
     filled with a pattern and freed must keep no copy of it
     (`scribble=0`), and is seen while allocated (`probe`). The glyph
     count cannot show this for a typed letter (small freed blocks are
     zeroed without scribbling). Harness case 7 runs the probe with
     scribbling (0 left) and without (the block kept), in test.sh.
  4. **The app's lock paths are tested.** A lock probe
     (`app/Tests/Lock`, run by test.sh, no window on screen, no prompt)
     runs `LockController` and `UnlockService` with a software KEK: a
     discarded unlock and the lock sequence lock Rust, the lock sequence
     zeroes every content view's pixel buffers, `draw(_:)` of a content
     view draws nothing, and `UnlockService` locks Rust when its closure
     fails after `Brev.unlock` (a `KeyStore` subclass whose install fails;
     `KeyStore` is no longer `final` for this). VERIFY V53 makes the view
     host's own runs (mail, compose, lock triggers) a required row.
  5. **FFI surface.** test.sh pins every use of a `FfiConverter…Data`
     type in the bindings, as it pins the String converters, so a body or
     a name cannot cross as `Data` unnoticed (design §2.2).
  6. **Open-documents event.** `AppDelegate` implements
     `application(_:open:)` and ignores the event (Brev opens no files,
     §1.4, §3.2). Without it AppKit showed its "cannot open" alert: an
     unhardened, capturable window that took key from a compose sheet,
     which turned secure input off while Brev stayed unlocked. VERIFY V54.
  7. **View host.** Its cacheDisplay checks are named for the layer tree
     they check; new checks call `draw(_:)` into a bitmap (cacheDisplay
     never calls it for a view that updates its layer). Its "sent sheet
     is freed" check first posts one in-process event, because AppKit's
     `currentEvent` kept the sent sheet alive until the next event.
     After the lock it runs the scribble probe.
  8. **Spec text.** CLAUDE.md §3.2's `SecureTextView` bullet follows
     D-0034: Core Text into the protected layer's pixel buffers,
     `draw(_:)` draws nothing. VERIFY V41 names the files left after
     D-0035, and V43 expects a disabled minimise button (AppKit shows one,
     greyed out, on a titled window without `.miniaturizable`).
     `docs/PHASE2_DESIGN.md` says under its title what D-0034 and D-0035
     superseded. The README describes Phase 2 and its build prerequisites.
- **Reasoning:** CLAUDE.md §1.10 and §3.1 (keys and plaintext zeroized on
  lock) and §1 "ALWAYS" (security-relevant code has tests that prove the
  invariant): each fix comes with a check that fails without it. The
  echo peers' DEKs open stores holding every letter. The alert broke
  design §7.1 ("no NSAlert anywhere") and §8.1 ("Hardening.apply runs on
  every window"). No fix needs the owner or adds a dependency.
- **Verified:** macOS 26.2, 2026-09-28, each check against its fix
  reverted: harness case 3 with the old archive failed 6 of 6 runs (two
  copies of each peer DEK on a stack after lock, VM tag 30) and passed 8
  of 8 with the fix; the new scrub-count assertions fail with either
  scrub deleted; harness case 7 finds the freed block kept without
  scribbling and empty with it (5 of 5 each); the lock probe fails with
  each of `LockController`'s two `brev.lock()` calls deleted, the one in
  `UnlockService`'s catch deleted, the zeroing in `blank()` or
  `release()` deleted, the lock sequence's `wipeContent()` deleted, and
  with a `draw(_:)` that draws content; the view host's new `draw(_:)`
  check fails on that last one, where its cacheDisplay check passes; the
  Data surface check fails on bindings generated from a Rust mutant that
  adds a `body_bytes` export and a `name_bytes` field; the view host's
  compose run passed 6 of 6 (the sent-sheet check failed 2 of 5 before),
  and still fails with a retain cycle in `ComposeSheet`; its mail and
  `--triggers switch` runs pass. `open -a <Brev.app> <file>` to a running
  Debug build with the handler added no window and logged `open event
  ignored count=1`; the same event to the Release build of 1873eed added a
  layer-8 window with sharing state 1 (the alert).

### D-0064 — Phase 2 review round 2: the whole FFI surface pinned, TSMEventTracing refused, the idle clock tested, the Xcode minimum

- **Date:** 2026-09-28
- **Decision:** The confirmed findings of review round 2 are fixed:
  1. **The whole FFI surface.** D-0063 item 5 held only for `String` and
     bytes. Any other element type crosses through a converter that neither
     pin named: a `Vec<u16>` export or record field becomes a Swift
     `[UInt16]` (`FfiConverterSequenceUInt16`) that nothing wipes, so a
     whole letter could leave Rust in one call and test.sh stayed green.
     test.sh now compares the bindings with `scripts/ffi-surface.txt`: every
     function Rust exports (`uniffi_brev_core_fn_…`) and every line that
     names a `FfiConverter` type, exactly as often as it occurs. Every value
     that crosses the FFI goes through a converter, so a new export,
     argument, result, record field, enum payload or type fails the check
     until the list is reviewed and updated. The list replaces test.sh's
     String and Data lists (their lines and reasons are in it); the
     declaration checks for `String` stay. This narrows D-0063 item 5,
     which said a body or a name cannot cross unnoticed.
  2. **TSMEventTracing.** `LaunchGuard.unsafeDefaultKeys` adds HIToolbox's
     key-event trace `TSMEventTracing` and its thirteen `TSMTrace…`
     siblings from the launch spike's scan (`tools/verify/spikes/launch/
     keys-batch.txt`), as the spike recommended; design §8.6 and §14.2 L
     left the list to the spike. Harness case 2 asserts `TSMEventTracing`
     by name. VERIFY V28 sets it with `defaults write -g`, as it does
     `NSTraceEvents`.
  3. **The idle clock.** The lock probe checks that a synthetic key that
     `BrevApplication` drops does not stamp `lastHumanInput`: one made in
     the process and sent through `sendEvent`, and a ↓ key posted to the
     probe's own PID and pumped through `nextEvent`. The drop log
     (`dropped synthetic 10/11 pid=…`, read with `OSLogStore`) is the
     control that the events arrived. The posted part is skipped, and says
     so, when `CGPreflightPostEventAccess()` is false; it never asks.
  4. **The Xcode minimum.** `scripts/build.sh`'s install hint and
     `app/project.yml`'s `xcodeVersion` say Xcode 16.2, as the README has
     since round 1 (the app uses macOS 15.2 SDK symbols; XcodeGen writes
     `xcodeVersion` only as `LastUpgradeCheck`). test.sh checks that the
     three agree.
- **Reasoning:** CLAUDE.md §1.10 and §3.1 (content crosses the FFI only in
  960-byte chunks, and the Swift side leaves no buffer unwiped). §2's
  keylogger threat: secure event input hides keystrokes from event taps,
  and a trace on stderr would give their count and timing, and by the
  checker's static analysis their key codes. Design §8.3: only accepted
  input stamps the idle clock, so posted events cannot keep Brev from
  idle-locking; before, only the view host's `--triggers idle --post` run
  checked it, and no VERIFY row requires that run. §1 "ALWAYS": each fix
  has a check that fails without it. No fix needs the owner or adds a
  dependency. D-0063 stays as written (entries are append-only).
- **Spike facts for WP12:** The launch spike (facts 6 and 7) and its
  checker found: with 126 debug keys of AppKit, Foundation, CoreFoundation
  and HIToolbox set at once, in a build without get-task-allow, the only
  key-event output came from `TSMEventTracing` (TSM queue traces with
  dead-key state, on stderr). By static analysis of HIToolbox, the same
  flag gates `TSMProcessRawKeyEvent: Processing …, virtualKeyCode=%x,
  modifiers=%x`, with no get-task-allow check. HIToolbox reads its keys
  from the global domain (`kCFPreferencesAnyApplication`) before the app's
  search list, so an argument-domain override cannot neutralise a
  `defaults write -g`; the spike's option to set the keys false in the
  argument domain was not taken for that reason. LaunchGuard reads through
  `UserDefaults.standard`, whose search list holds the global domain; V28
  checks that in the real app. WP12's entries on launch hygiene and on the
  GUI-spike results (design D-0045 and D-0057; D-0048 and D-0060 after the
  renumbering) take these facts over.
- **Verified:** macOS 26.2, 2026-09-28, each check against its fix
  reverted or against a mutant. The surface check fails on bindings
  generated from three Rust mutants: `OpenText::units() -> Vec<u16>` and
  `ContactRow.name_units: Vec<u16>` (the review's B-F04 and B-F05; round
  1's checks pass the first) and `OpenText::byte_at(i) -> u32`, which needs
  no new converter type. Harness case 2 fails with LaunchGuard's old key
  list. The lock probe fails with the idle stamp moved above the synthetic
  check in `nextEvent` (the review's B-U32) and in `sendEvent`. The Xcode
  check fails with build.sh's old hint and with project.yml's old version.
  The review measured the trace: the view host in compose mode, started
  with `-TSMEventTracing YES` (no LaunchGuard), traced every key-down and
  key-up of 3 posted keys to stderr (28 lines) with the body focused and
  secure input on.
  `scripts/test.sh` passes.

---

## Phase 2 summary

**Built (2026-09-27 to 2026-09-28, after the design `8dd9b2b`, commits
`4fda538` to `fb6f140`):**

- WP0: `docs/VERIFY.md`, now 54 rows with commands, tools, coverage and a
  run order (`4fda538`, `2fc4530`, revised by later packages).
- WP1: `brev-core`'s UniFFI surface (`ffi.rs`), the echo peers (`echo.rs`),
  padded columns and schema v2, the zeroing allocator (`08a5670`,
  `de3e6bb`): D-0038 to D-0042.
- WP2: the binding patches and the uniffi pin, Swift secret memory, the CLI
  heap-scan harness (`0fec87d`, `dc2a9ca`): D-0040, D-0044, D-0051.
- WP3: the app shell: LaunchGuard, the input filter, `BrevApplication`,
  menus, hardening, the lock sequence, the Verify configuration (`f1c2d30`):
  D-0043, D-0047, D-0048, D-0050.
- WP6: the headless compose core, `EditModel` and `KeyTranslator`
  (`7be0029`, `d27899c`): D-0049.
- WP5: keychain keys, onboarding, unlock, errors and reset (`33fa863`,
  `fa2862f`): D-0036, D-0037.
- WP7: the content views, the mail window, the sync timer and the view host
  (`7844525`, `a29572f`): D-0043, D-0045.
- WP11: the protected content layer, hardened sheets and child windows
  (`32a9682`, `29522b9`): D-0045, D-0046.
- WP8: the compose sheet, secure input and key-only text entry (`388e71c`):
  D-0049.
- WP10: the lock triggers and the blank-on-lock order (`b6f2e3c`): D-0050.
- WP4: the verification tools, the spike sources and the machine-run VERIFY
  results (`1a9b723`, `1873eed`): D-0051, D-0053.
- The review rounds (`3e87bef`, `fb6f140`): D-0063, D-0064.
- The owner's spec changes during the phase: D-0033 (`db2654a`), D-0034
  (`e5fd002`), D-0035 (`9398f2c`), the signing-key item (`39e1858`, D-0062;
  accepted for test letters in `1aeccc5`) and the Phase 3 relay item
  (`e4f8e1a`).
- WP9 (the anchor) was dropped with D-0035. WP12 is D-0036 to D-0053 and
  this summary, without the human run.
- Automated checks at `fb6f140`: 59 Rust tests and 2 release scrub tests, 14
  harness lines of 5 runs each, the lock probe's 12 checks, `capture-probe
  --selftest`'s 21 checks, and the FFI surface, grep and build checks
  (D-0051).

**Definition of done status (CLAUDE.md §5, Phase 2): not met. Phase 2 is
code-complete; the human verification is pending.**

| §5 line | Entries | Status |
|---|---|---|
| Onboarding explains the trade-offs in Norwegian, creates Enclave keys, wraps a fresh DEK | D-0036, D-0037 | built; V36, V37, V40, V41 pending |
| Unlock screen → Touch ID → `core.unlock(dek)` | D-0037, D-0039 | built; the lock probe passes; V26, V27, V47, V48, V51 pending |
| Three-pane window, content panes use `SecureTextView` | D-0043, D-0045 | built; the view host passes (V53); V10, V42 pending |
| Compose sheet: secure input, synthetic rejection, no pasteboard, no autocorrect, `writingToolsBehavior = .none` | D-0048, D-0049 | built; the view host passes; V13, V14, V30 to V35 pending |
| Capture exclusion with the protected layer, auto-lock, blank-on-lock | D-0045, D-0046, D-0050 | built; the view host passes; V4 to V8, V22 to V25, V46 pending; V9 fails as written |
| Two hard-coded contacts through `MockTransport` | D-0042 | built; the Rust tests pass; V42 pending |
| Stored content padded, schema v2 | D-0041 | built; the Rust tests pass; V18 pending |
| `docs/VERIFY.md` written and run | D-0053 | written; the machine part run |
| Checklist passes; build sandboxed and hardened | D-0053 | V1 and V2 pass; the checklist is pending |

Machine-run rows (D-0053, `docs/VERIFY-RESULTS.md`): at `fb6f140`, V1, V2,
the `sdef` half of V3, V21, V45, V50 and V53 pass. WP4's run at `b6f2e3c`
passed the parts of V5 to V7, V11, V13, V19, V22, V26, V28, V29, V40 and V49
that need no Touch ID. V9 fails as written. The first part of V54 passed on
a Debug build in review round 1.

Pending, because they need a human with Touch ID or a permission prompt: V3
(`osascript`), V4 to V8 with a letter open, the sheet parts of V9, V10, V12
to V20, V22 to V27, V28 (`defaults write -g`), V29 (files), V30 to V44, V46
to V49, V51, V52 and V54. The owner's list, in order, is
`docs/USER_SESSION.md`.

**Residual risks and limits**

Accepted in CLAUDE.md §2: transient key copies in audited crates and in
Apple's frameworks; file substitution of the stores; on a Mac that holds
Brev's team signing key, any same-user program can sign itself into Brev's
keychain group (accepted on 2026-09-28 while Brev holds only test letters;
real letters go only on a Mac without the key); keystrokes in event objects
and the window server; letter pixels in backing stores and the protected
layer's buffers until blank-on-lock; the echo stores (Phase 2 only); the
reliance on `MallocScribble=1`.

Not proven, or open until the human run or the owner decides:

- Hardware input is believed to carry source PID 0 but is not measured. If
  the real keyboard types nothing in the compose sheet, the work stops for
  the owner (D-0048).
- `CGEventPost` at the HID and session taps, System Events, Accessibility
  Keyboard and Screen Sharing are not tested (V32 and V33, under the owner's
  supervision). Accessibility Keyboard, Voice Control and Switch Control are
  expected to be rejected, and VoiceOver cannot read letters.
- Whether the Touch ID panel takes activation. If it does, every unlock ends
  on the lock screen, and the owner chooses the fix (D-0037, V27, V47).
- The unlock's stack residue with the real Enclave (V51), and the heap
  residue in the real app (V39).
- Whether `com.apple.screenIsLocked` reaches the sandboxed Brev (V23), and
  sleep and display sleep (V24).
- Whether `CGDisplayStream` and `AVCaptureScreenInput` need the Screen
  Recording permission. The protected layer hides content from them either
  way.
- LaunchGuard cleans the environment with a denylist; an allowlist waits for
  the Finder and Dock environments (D-0047).
- V9: every app has 4 system menu-bar windows with sharing state 1; the
  owner decides how V9 counts them.
- The error codes for a lockout and a changed fingerprint are not measured:
  unknown errors show «Prøv igjen», and "fingers" also needs a changed hash
  (D-0037).
- A quit is dropped while a sheet is open (below).
- Accepted by the design for Phase 2: drafts are discarded on every lock;
  envelopes are unsigned; bucketed sizes, counts and times are visible on
  disk.

**Review results**

- Every package had a security and a correctness reviewer, and every finding
  a skeptic: 67 findings over the eleven packages. 43 were confirmed and
  fixed in the package's review commit, 20 were judged not real, and 4 were
  deferred and closed later (WP3's file-based install marker in WP5, WP5's
  signing-key finding in D-0062, WP7's V39 control in WP7's review).
- Review round 1 over the whole phase (five finders, three skeptics per
  finding): 22 findings; 15 confirmed and fixed (`3e87bef`, D-0063), 6 not
  real, 1 deferred.
- Review round 2: 10 findings; 6 confirmed and fixed as 4 changes
  (`fb6f140`, D-0064), 4 not real.
- Deferred, for the owner: "Quit is silently dropped while the compose sheet
  or ConfirmSheet is open, so quit never runs the lock". While a sheet is
  attached, AppKit drops ⌘Q, *Avslutt Brev* and a quit Apple Event (Dock,
  logout, restart) without asking Brev. Nothing leaks, and every other lock
  trigger still fires. The skeptics split one each way (fix, defer, not
  real): the fix (lock, then quit) would also discard a half-written letter
  on ⌘Q, which is a product choice.

**Next:** Phase 3 (real transport) has started on its own branch. Phase 2
closes when the human run passes, or each failure has an entry the owner
accepts.

---

## Phase 3 — owner answers and the vault split (2026-09-28)

Phase 3's own entries (`docs/PHASE3_DESIGN.md` §10) come with its WP6. Two
things are recorded here first: the owner's answers, which the design plans
as its first entry (its D-0036), and the split of brev-core into brev-vault
and brev-mail (`docs/VAULT_SPLIT_PLAN.md`, owner answers at its end). The
design's other entries take numbers after D-0068, in its order.

### D-0065 — Owner answers to Phase 3's questions; the signing key accepted for test letters (closes D-0062)

- **Date:** 2026-09-28
- **Decision:**
  1. **Q1, the local relay:** option (A). In Phase 3 the relay runs as the
     user on this Mac, so any same-user program can act as the relay: edit
     `relay.db`, take its port while it is down, or hand out its own key at
     first contact or at a key change. This is accepted residual risk for
     Phase 3 only, which carries test letters only; a remote relay with TLS
     replaces it. CLAUDE.md §2 has the line since `e4f8e1a`. Option (B), the
     relay as a hidden `_brevrelay` user, is not built: `scripts/relay.sh`
     keeps the relay's folder in the user's Library.
  2. **Q4, a second App ID:** approved (`e4f8e1a`'s message). WP6 may
     register `no.brev.app.b` in team `AV26DNQ5SC` through automatic
     signing, for Brev B in the two-instance run: its own container,
     `.lock`, Enclave keys and wrapped DEK, in group
     `AV26DNQ5SC.no.brev.app.b`. The fallback, a second macOS user account,
     is not needed.
  3. **Q2, letters from people not added** (a stranger, or a contact's new
     key before it is accepted): dropped and acknowledged; both people add
     each other first; Phase 4's contact requests replace this. **Q3,
     addresses:** 3 to 32 characters of `a–z`, `0–9` and `-`, the first a
     letter; one per identity; permanent, so only the operator's
     `brev-relay release` frees one. Both are the design's recommendations
     (§11), and Phase 3's WP2, WP3 and WP5 built them.
  4. **The signing key on this Mac (D-0062):** accepted on 2026-09-28 while
     Brev holds only test letters (`1aeccc5`). Nothing changes on this Mac;
     real letters go only on a Mac without the team signing key. The other
     remedy D-0062 named, the key behind a password prompt, is not taken.
     CLAUDE.md §2 lists the item as accepted residual risk, so D-0062 is
     closed.
  5. **The §2 edits these answers caused:** the relay line (`e4f8e1a`), the
     signing-key line (`1aeccc5`), and the two echo edits Phase 3 left for
     the owner (`ba70411`: file substitution names only `brev.db`, and the
     Phase 2 echo line is gone). `docs/THREAT_MODEL.md` was re-synced in
     each.
- **Reasoning:** Q1 is a §1 conflict. A program that acts as the relay can
  pin its own key for a contact and read the letters to it, and comparing
  codes, which is optional, is the only defence. So it was asked, not
  decided (design §11). The owner accepted it because Phase 3 carries test
  letters only, and this Mac cannot hold real letters anyway (item 4). Q4:
  a second bundle id gives Brev B its own container and keychain group
  without a runtime switch, which LaunchGuard would refuse (design §7). Q2
  keeps Phase 3 free of a stranger inbox before Phase 4's approval. Q3:
  ASCII addresses have no look-alikes and need no Unicode normalisation.
  D-0062 had left the signing-key item open, and an open §2 item kept Phase
  2 from being signed off (`docs/VERIFY.md`, "Failures and results").
- **Verified:**
  - `git show --stat e4f8e1a 1aeccc5 ba70411`: each changes only CLAUDE.md
    §2 and the same lines of `docs/THREAT_MODEL.md` (one line each in the
    first two, two in the third). `e4f8e1a`'s message records Q1 and Q4,
    `1aeccc5`'s the answer to D-0062.
  - At `60d4e1b`, 2026-09-28: CLAUDE.md §1–§2, extracted with `awk`, diffed
    against `docs/THREAT_MODEL.md`: identical but for one trailing blank
    line of the extraction.
  - Q2 and Q3 in the code: `strangers_are_dropped_and_acked` (brev-mail
    `tests/phase3.rs`), `register_rules` and `release_frees_an_address`
    (brev-relay `tests/relay.rs`) pass in `scripts/test.sh` at `60d4e1b`.
    The rule is `brev_proto::is_valid_address`.
  - Not found: a commit or document with the owner's own words on Q2 and
    Q3. They reached this entry, with Q1 and Q4, as the owner's answers in
    the form "the design's recommendations"; the owner may correct them
    here. The comment on `is_valid_address` still says the rule is the
    design's recommendation "until it is answered".

### D-0066 — The vault split: brev-vault and brev-mail (`docs/VAULT_SPLIT_PLAN.md`, step 1)

- **Date:** 2026-09-28
- **Decision:** (`15f3e50`; the plan is `573516e`.)
  1. **Layout.** `core/brev-core` became two crates. `core/brev-vault` is
     new: an rlib with no UniFFI and no network, `#![forbid(unsafe_code)]`.
     It holds what knows nothing about mail: the store (`Vault`,
     `VaultConfig`, `DekSlot`, `check_path`, the pragmas, the exact schema
     check, the journal mode, file mode 0600), the DEK and its
     `Locked`/`Unlocked` state with the single gate `Vault::dek`, column
     encryption (`seal_column`, `open_column`, `column_ad`, `aead_seal`,
     `aead_open`, `pad`), `Plaintext`, the chunked `Text` that a lock
     closes (`CHUNK` = 960, with the registry of open texts), the stack
     scrubs, the OS RNG, the padding (moved from brev-proto) and the zeroing
     global allocator. `core/brev-mail` is a `git mv` of brev-core and keeps
     the identity, contacts, threads and letters, the message crypto
     (X25519, HKDF, the contact tag), the relay client, `MockTransport` and
     the whole UniFFI surface (`ffi.rs`). `Core` wraps a `Vault`. brev-proto
     re-exports the vault's padding with the same API. Steps 2 and 3 added
     the vault's `clock`, `dirlock`, `launch` and `platform` modules
     (D-0067, D-0068). `docs/ARCHITECTURE-REUSE.md` has the full map.
  2. **Naming and the module-path rule.** The package is `brev-mail`; its
     `[lib] name` stays `brev_core`. So the UniFFI symbols
     (`uniffi_brev_core_*`, `ffi_brev_core_*`) and checksums,
     `libbrev_core.a`, `uniffi.toml` (`BrevCore`, `BrevCoreFFI`), the patch
     targets, `app/project.yml`'s archive path and the generated
     `BrevCore.swift` keep their names, and `ping()` still answers
     "brev-core". No `#[uniffi::export]` item and no UniFFI type left
     `brev_core::ffi` or the crate root, because UniFFI's checksums include
     the module path (plan R1). `core/uniffi-global.toml` maps
     `brev_core = "brev-mail"`.
  3. **`VaultConfig`.** What a store is comes from its caller: `file_name`,
     `application_id`, `schema`, `schema_version`. brev-mail's `MAIL` is
     `brev.db`, `0x42524556` ("BREV"), its schema, version 3 at the split
     (4 since D-0068). The Rust `Core` API still takes a full path; the FFI
     builds it with `MAIL.path_in(dir)`.
  4. **Features.** brev-vault: `zeroing-allocator` (the
     `#[global_allocator]`), `launch-guard` (D-0067) and `test-hooks` (test
     counters and accessors); the first two by default. brev-mail takes the
     vault with `default-features = false, features = ["zeroing-allocator"]`
     and has `launch-guard` (default, D-0067), `test-hooks`
     (`MockTransport` and the vault's hooks; owner answer Q5; its own tests
     turn it on through a dev-dependency on the crate itself) and
     `allow-software-keys` (D-0068). brev-proto takes the vault with no
     features, so the relay has no zeroing allocator.
  5. **Dependency whitelist.** `scripts/check-vault-deps.sh`, run by
     `scripts/test.sh`: with every feature on, each direct normal dependency
     of brev-vault is one of chacha20poly1305, poly1305, rand, rusqlite,
     thiserror, zeroize and zeroizing-alloc, and its whole normal graph has
     no reqwest, hyper, tokio, axum, p256, x25519-dalek, curve25519-dalek,
     hkdf, serde, uniffi or brev-proto. The control runs the same check on
     brev-mail and must find reqwest. No new dependency: all of these were
     in CLAUDE.md §4 and in `Cargo.lock` already.
  6. **Test code stays out of the app.** `scripts/gen-bindings.sh` fails if
     the app's archive has a `MockTransport`, `live_plaintexts` or
     `_for_test` symbol, and `scripts/test.sh` checks that the same pattern
     finds them in a test build.
  7. **No behaviour change.** Swift, the bindings and the tests stayed as
     they were, apart from the test lines the plan lists (§7, accepted by
     the owner as Q1) and those forced by moved code: a test that built a
     store through the private `init` lets the vault create the file; the
     registry of open texts is read through a test accessor; the renames
     `encrypt` → `aead_seal` and `brev_proto::MAX_PADDED` →
     `crate::padding::MAX_PADDED`.
  8. **Line counts** (`wc -l` of `src/`; "without tests" leaves out the
     `tests.rs` files, `test_keys.rs` and the inline
     `#[cfg(test)] mod tests` blocks):

     | Crate | at `15f3e50` (step 1) | at `60d4e1b` (step 3) |
     |---|---|---|
     | brev-vault | 937 (789 without tests) | 2 233 (1 429) |
     | brev-mail | 4 500 (2 579) | 5 208 (2 893) |

     brev-core before the split (`3ef953b`) had 4 860 (2 870). brev-mail's
     integration tests (`tests/`) are another 1 972 lines at `15f3e50` and
     2 029 at `60d4e1b`. The vault is the smaller half with and without
     tests (plan §9, step 1 check 6).
- **Reasoning:** The map in ARCHITECTURE-REUSE.md (`a04ca0f`) showed a part
  of brev-core that knows nothing about mail. Split out, it is a store that
  a second app can use without UniFFI, the relay client, P-256 or Brev's
  schema, and the crate that holds the DEK has no network and no FFI in its
  graph. Keeping the library name keeps Swift, the bindings pipeline and
  every tool unchanged. `VaultConfig`, not constants in the vault, because
  a store's identity (file name, magic, schema) is the caller's. The
  allocator as a feature keeps it out of the relay.
- **Verified:**
  - Step 1 at `15f3e50` (its commit message; the plan's §9 step 1 checks):
    `BrevCore.swift`, `BrevCoreFFI.h` and `BrevCoreFFI.modulemap` equal to
    the baseline built at `3ef953b` (`cmp`); the `cargo test -- --list`
    names equal, and 105 tests passing before and after (the three
    `Plaintext` doctests now in brev_vault); the Release app's 59 UniFFI
    symbol names, its entitlements and its Info.plist equal to the
    baseline, with `zeroizing_alloc5WIPER` and no test hook;
    `scripts/test.sh` green; `tools/verify/build.sh --check` passes.
  - Run again for this entry, 2026-09-28: `scripts/gen-bindings.sh` in
    `git archive` copies of `3ef953b` and `15f3e50`, each in its own scratch
    folder and target dir. `cmp` finds `BrevCore.swift` (71 518 bytes),
    `BrevCoreFFI.h` (32 500) and `BrevCoreFFI.modulemap` (132) identical;
    `BrevCore.swift` has the same SHA-256 (`33af68d6…209af9`) in both.
  - At `60d4e1b`: `grep -rn uniffi core/brev-vault` finds nothing;
    `cargo tree -p brev-relay -e features | grep -c zeroing-allocator`
    gives 0, and `zeroizing-alloc` is not in the relay's graph, although
    brev-vault is. `scripts/test.sh` exits 0 in 3 min 9 s: `check-vault-deps.sh`
    prints "only whitelisted dependencies (control: brev-mail fails the
    same check)", clippy passes with the default and with all features, the
    release scrub run says `2 passed`, the app archive has no test hook,
    and 136 Rust tests pass; `cargo audit` is clean over 210 crates and
    1 273 advisories. The Release binary from `scripts/build.sh` has
    `zeroizing_alloc5WIPER` once and no `MockTransport`, `live_plaintexts`
    or `_for_test` symbol.
  - Not tested: the declared minimum Rust with an older toolchain; only
    1.91.1 is installed (as in D-0015).

### D-0067 — Five checks moved into Rust: folder lock, modes, launch guard, two-step unlock, idle deadline (plan step 2)

- **Date:** 2026-09-28
- **Decision:** (`64a484c`.) brev-vault now enforces five checks that only
  Swift made before:
  1. **One store per folder.** The vault opens the store's folder and holds
     a flock on it (`File::try_lock`, in `DirLock`) for as long as the
     `Vault` lives: another open store in it gives `Busy`, any other failure
     `Io`. The folder is locked, not the file: a flock on the database file
     broke SQLite's own locking (both connections got `DatabaseBusy` in the
     plan's re-run), and a lock file would add a name that the tests and
     Swift's reset list would see. Swift's `.lock` (D-0036) stays.
  2. **Modes.** The folder must be 0700 (checked on the opened folder,
     before the lock) and the file 0600 (after `verify_store`, before the
     journal mode is written): `Unsafe` otherwise. A foreign 0644 file still
     gives `Corrupt`, and nothing is written to a file whose mode is
     unchecked. `open` runs `check_path`, the launch check, the folder
     (open, mode, lock), connect, `verify_store`, the file mode, then the
     journal mode. `create` runs mail's `Malformed` checks, the launch
     check, the folder, `create_new` with 0600, then as before; a failed
     create removes the file while the folder is still locked.
  3. **Launch guard** (feature `launch-guard`: in brev-mail's default, so
     in the app's archive; off in `cargo test --no-default-features` and in
     the test archive). `create`, `open` and `unlock` give `Unsafe` if a
     variable's name starts with `DYLD_` or `MallocScribble` is not exactly
     `1`. `unlock` copies and zeroes the caller's DEK first and stays
     locked. Swift's LaunchGuard strips `DYLD_*` too and re-executes once,
     and a Debug build logs that it did (owner answer Q2 and its addition).
  4. **Two-step unlock.** `unlock` and `create` leave the vault `Armed`: the
     DEK is loaded, but the gate gives `Locked` until `confirm_active()`
     comes within `CONFIRM_WINDOW` (2 s). Late, it locks and gives `Locked`.
     Swift confirms in `LockController.endUnlock`, after its own post-unlock
     rule passed (D-0037); a refusal runs the lock sequence with the new
     `LockReason.unlockExpired`.
  5. **Idle deadline.** `Active` lasts `idle_secs` without
     `note_activity()`; the FFI takes it in `unlock(dek, idle_secs)`, 1 to
     3600, `Malformed` otherwise. Swift passes `LockState.rustIdleSecs` =
     320 (owner answer Q3: its own 300 s, plus its 15 s poll, plus 5 s),
     keeps locking at 300 s, and also locks when `isLocked()` is true while
     it thinks it is unlocked. `BrevApplication` calls `noteActivity()` at
     most once a second, and only for input that passed the synthetic-event
     filter, so posted events cannot keep Rust unlocked.
  6. **The clock and its timer.** A deadline is kept on two clocks:
     `Instant`, which on Apple is `CLOCK_UPTIME_RAW` and stops while the Mac
     sleeps, and the wall clock, which counts only while it has not gone
     back since the deadline was set. While a deadline is set, the thread
     `brev-vault-timer` waits at most 1 s at a time, so a deadline the wall
     clock passed during sleep is seen within a second of waking; while
     locked, it waits until it is woken. It never holds the clock's mutex
     while it takes the
     session's (lock order: session, then clock), and wipes through
     `Holder::lock_all` if the deadline has passed. `Brev::session()` makes
     the same check first, so whoever takes the mutex first after a deadline
     wipes and moves the epoch before anything else runs. The timer holds
     only a `Weak`. `Brev`'s fields are ordered timer, session, relay
     client, so dropping `Brev` joins the timer, then drops the session and
     its flock, before `drop` returns.
  7. **Errors and FFI.** `Busy` and `Unsafe` are appended after `Refused` in
     the vault's `Error`, mail's `Error` and `BrevError`, so no index moves.
     At launch, AppDelegate maps `Unsafe` from `Session.open` to
     `launch.error.unsafe`, and `Busy` to the second-instance path. The
     bindings gain `unlock(dek:idleSecs:)`, `confirmActive`,
     `noteActivity`, `Busy` and `Unsafe`, and nothing else.
  8. **Builds.** Workspace `rust-version` 1.89 (`File::try_lock`). Rust tests
     run with `--no-default-features`, plus `cargo test -p brev-vault
     --features launch-guard --lib launch`. The Swift harness, the lock
     probe and the view host run without `MallocScribble`, so they link a
     test archive (`core/target/test-archive`, no default features; with
     `allow-software-keys` since D-0068). `TouchIDProbe` (V51) keeps the
     app's archive, guard included. `scripts/test.sh` checks that the guard
     is in the app archive's feature graph and not in the test archive's,
     and that the feature has exactly 2 cfg sites.
- **Reasoning:** ARCHITECTURE-REUSE.md §3 (`a04ca0f`) listed the single
  instance, the folder mode, launch hygiene, the post-unlock rule and the
  idle lock as Swift's alone: a Swift bug left Rust open, and Rust could
  not tell when a lock was missing. Now Rust refuses and wipes on its own,
  and any app built on the vault gets the same. The limits, from the plan's
  §10: Rust cannot blank the screen, so Swift's 300 s lock stays first and
  Rust's 320 s is the backstop, and Swift's 15 s poll blanks the screen if
  Rust locked first (R3). The 2 s window runs from Rust's `unlock` to
  main's `endUnlock`, with onboarding's keychain writes inside it (R4). A
  `Brev` still alive after a reset (a `sync` in flight) makes onboarding's
  `create` `Busy` for up to 15 s (R9).
- **Verified:**
  - Step 2 at `64a484c` (the plan's §9 step 2 checks, as that step
    reported them): `cargo test --workspace --no-default-features` and the
    guard-on run pass; the diff of `BrevCore.swift` against step 1's stays
    within the five FFI changes above; `scripts/test.sh` is green.
  - At `60d4e1b`, in `scripts/test.sh` (exit 0): brev-vault's
    `a_directory_holds_one_open_store`,
    `directory_must_be_0700_and_the_file_0600`,
    `unlock_is_armed_until_confirmed`, `a_late_confirm_locks_and_wipes`,
    `the_timer_wipes_an_unconfirmed_unlock`,
    `the_timer_wipes_when_idle_and_activity_postpones_it`,
    `activity_while_armed_does_nothing`,
    `the_timer_waits_for_a_held_holder`,
    `dropping_the_timer_joins_its_thread`, `armed_confirms_only_in_time`,
    `idle_deadline_and_activity`,
    `wall_clock_catches_sleep_but_not_going_back`,
    `a_deadline_too_far_passes_at_once` and
    `launch_check_needs_scribble_and_no_dyld`; the guard-on run's
    `launch_guard_refuses_this_process` (cargo sets
    `DYLD_FALLBACK_LIBRARY_PATH`); brev-mail's
    `one_session_per_folder_and_drop_frees_it` (a second `open` and a
    `create` in the folder give `Busy`; 100 rounds of `drop` then `open`
    never do), `folder_and_file_modes_are_checked`,
    `unlock_is_armed_until_confirmed`,
    `an_unconfirmed_unlock_is_wiped_after_2_s`,
    `idle_wipes_and_activity_postpones_it` and
    `a_passed_deadline_moves_the_epoch_before_anything_runs`. The lock
    probe's 26 checks pass, among them "an unlock opens Rust only once it is
    confirmed"; it noted 0 ms from `Brev.unlock` to the completion on main,
    of the 2 000 ms window.
  - The Release build from `scripts/build.sh` at `60d4e1b`, launched with
    `open` and ended with SIGTERM (`docs/VERIFY-RESULTS.md`): with
    `MallocScribble=0` and with `NSZombieEnabled=YES` it re-executed once
    (`launch unsafe: environment; re-executing`; `ps -wwE` then shows
    `MallocScribble=1` and `BREV_LAUNCH_CLEANED=1`) and reached `route
    onboarding`. A second instance (`open -n`) logged `second instance` and
    exited. With `DYLD_BREV_TEST=1`, `ps -wwE` still lists the variable, but
    nothing re-executed: dyld takes `DYLD_*` out of the environment of a
    process with the hardened runtime, so in Release neither LaunchGuard nor
    Rust ever sees one. Checked with a small probe, ad-hoc signed once with
    `-o runtime` (neither `ProcessInfo` nor `getenv` saw `DYLD_BREV_TEST`)
    and once without (both saw it). The stripping of owner answer Q2
    therefore acts in Debug builds, which have no hardened runtime (D-0013).
  - Not yet run: the flock inside the App Sandbox container with a real
    store (plan R10: Brev is not installed on this Mac, so every launch
    shows onboarding and opens no store), and the confirm window on a real
    onboarding with Touch ID (R4). Both need the human run
    (`docs/VERIFY-RESULTS.md`).

### D-0068 — The environment class and the class-A send rule (plan step 3)

- **Date:** 2026-09-28
- **Decision:** (`60d4e1b`.)
  1. **Classes** (brev-vault, `platform.rs`). An `EnvironmentReport` holds
     `key_origin` (`SecureEnclave`, `Tpm`, `Software`, `Unknown`),
     `biometric_used` and five defences: `capture_excluded`,
     `secure_input_active`, `synthetic_input_rejected`,
     `accessibility_opaque` and `pasteboard_disabled`. `classify` gives A
     for a hardware key (Secure Enclave or TPM), a biometric check and all
     five; B for the key and the check without all five; C otherwise.
     `failed_fields` names the fields short of A, and is empty exactly for
     A. A platform layer reports through the `Platform` trait.
  2. **The send rule** (brev-mail). `Brev::report_environment(report)` is
     gated, and the report is kept until the next one or any lock.
     `prepare_send` checks it after the credentials, so a locked or
     unregistered session still gets `Locked` or `NotFound`, and before any
     request. Below class A it gives `BrevError::Environment { failed }`,
     and the relay sees no request. `failed` names the report's fields short
     of A; it is empty when no report came since the unlock. `Environment`
     is the one `BrevError` variant that is not a unit variant. The ticket
     and the signed letter carry the class, and `store_sent` writes it.
  3. **Schema v4.** `messages.env_class INTEGER`, plaintext and nullable: 1
     (A) on a letter the app sent; NULL on received letters and on sends
     through `Core` in tests. It is not in the body's AD, so the body format
     is unchanged, and a process that can write the file can change it; it
     is informational, like `read` (plan R5). No migration: a v3 store opens
     as `Corrupt` and must be reset (the plan's Q4). `padcheck` and V18
     expect v4.
  4. **What Swift reports** (`App/EnvironmentProbe.swift`, on main right
     before `prepareSend`): the identity key's origin from its own
     `kSecAttrTokenID`; Touch ID if this unlock's generation unwrapped the
     DEK with the Secure Enclave KEK (the KEK's access control needs
     `.biometryCurrentSet`, so the use is inferred, not read from an
     `LAContext`); every window with `sharingType == .none` and every
     content view's layer with `preventsCapture`; `SecureInput.isOn` and
     `IsSecureEventInputEnabled()`; `NSApp is BrevApplication`; every
     content view without an AX element, value, text or children; no
     responder for `copy:`, `cut:` or `paste:`. A refusal shows
     `compose.environment`, «Brevet ble ikke sendt: %@.», with the failed
     checks by name, for example «opptaksvern av» (owner answer Q6's
     addition), not the generic compose error.
  5. **The rule is self-reported.** Rust classifies what Swift says. A
     program that can call the FFI can send any report, so the rule catches
     a Swift regression that turns a defence off, not an attacker. Until
     attestation lands, CLAUDE.md §2 and `docs/THREAT_MODEL.md` carry this
     as accepted residual risk, in the plan's words (owner addition).
  6. **Test builds and the release guard.** brev-mail's feature
     `allow-software-keys` lowers the threshold to C, for the test archive
     that the harness, the lock probe and the view host link: they have
     software keys and no Touch ID, and report `.software` as it is. The
     feature compiles `#[used] static SOFTWARE_KEYS_MARKER =
     *b"BREV-ALLOW-SOFTWARE-KEYS-1"` into the archive.
     `scripts/gen-bindings.sh` fails if the app's archive holds the marker.
     An XcodeGen pre-build phase, "Rust archive has no test features", fails
     any app build whose linked `libbrev_core.a` holds it, in every
     configuration (Release, Verify, Debug, and Archive from the IDE).
     `scripts/test.sh` checks that the test archive has the marker and the
     app's does not, and that the feature has exactly 3 cfg sites (the
     threshold, the marker, and a test left out under the feature). This is
     the owner's earlier addition: a build-time check fails if
     `allow-software-keys` is on in a release build.
- **Reasoning:** ARCHITECTURE-REUSE.md §3 (`a04ca0f`) listed every AppKit
  defence with "Rust knows: nothing", and Rust sent a letter whatever state
  Swift was in. Now Rust refuses to send while Swift reports a defence
  missing, and each sent letter records the class it went out in. The owner
  asked that the rule be described as what it is: until attestation (App
  Attest, Phase 4), it catches Swift bugs, not attackers. The test archive
  must send in class C, because its callers have no Secure Enclave key and
  no Touch ID; the marker and two build-time checks keep that archive out of
  every app build. Naming the failed checks tells the owner which defence
  broke.
- **Verified:**
  - Step 3 at `60d4e1b`: the one-off proof of the Xcode phase copied the
    test archive over the app's archive and ran `xcodebuild -configuration
    Release` with `CODE_SIGNING_ALLOWED=NO` and a scratch derived-data
    folder: it failed at the phase. The app's archive was restored from a
    saved copy, and the signed Release build from `scripts/build.sh` ran the
    phase and passed.
  - At `60d4e1b`, in `scripts/test.sh` (exit 0): brev-vault's
    `everything_in_place_is_class_a`, `one_defence_off_is_class_b` (each of
    the five alone), `a_tpm_counts_as_the_secure_enclave`,
    `a_software_or_unknown_key_or_no_biometric_is_class_c`,
    `failed_fields_agree_with_the_class` and `rank_orders_and_code_stores`;
    brev-mail's `prepare_send_needs_class_a` (B, C and no report give
    `Environment` with the fields short of A, and the relay's request count
    does not move), `may_send_compares_ranks`,
    `the_sent_row_keeps_its_environment_class`,
    `a_report_needs_the_gate_and_a_lock_forgets_it` and
    `v3_store_is_refused`; test.sh's marker and cfg-site checks. The view
    host's compose run (V69) checks the report before ⌘↩: a software key,
    no Touch ID, and every defence in place.
  - For this entry: `grep -aq BREV-ALLOW-SOFTWARE-KEYS` finds the marker in
    `core/target/test-archive/release/libbrev_core.a`, and not in
    `core/target/release/libbrev_core.a` or the Release binary. The Xcode
    phase proven again without touching the worktree's archive: a scratch
    copy of `app/` (sources, bindings, tests, `project.yml`,
    entitlements), `xcodegen generate`, and the test archive at the path
    the phase reads (`../core/target/release/libbrev_core.a`).
    `xcodebuild -configuration Release CODE_SIGNING_ALLOWED=NO` with its own
    derived-data folder: `** BUILD FAILED **` (exit 65), whose only error is
    the phase's "was built with allow-software-keys (a test archive)". With
    the app's archive copied there instead: the phase ran, and `** BUILD
    SUCCEEDED **`.
  - CLAUDE.md §1–§2 against `docs/THREAT_MODEL.md`: identical (D-0065).
  - Not yet run: a letter from the real app, which needs Touch ID (V56 and
    V57 in the human run). Only then does a real report reach class A.

---

## Phase 3 — real transport (2026-09-28)

The entries `docs/PHASE3_DESIGN.md` §10 plans as its D-0037 to D-0052,
written on 2026-09-29 for what is built on `claude/phase4`. Its D-0036 (the
owner answers) is D-0065. Its D-0053 (VERIFY results and the phase summary)
is not written: the rows that need Touch ID, Brev B or letters wait for the
human run (`docs/USER_SESSION.md`). "At `60d4e1b`" below means the machine
run of `docs/VERIFY-RESULTS.md` (V45: `scripts/test.sh` exit 0, 136 Rust
tests), which covers Phase 3 WP0 to WP5 and the vault split. brev-core is
called brev-mail since D-0066. Where a design, `docs/VERIFY.md` or a commit
cites a design number, this table gives the entry:

| Design §10 | Topic | Entry |
|---|---|---|
| D-0036 | owner answers Q1–Q4 | D-0065 |
| D-0037 | crates and features | D-0069 |
| D-0038 | protocol v1 wire | D-0070 |
| D-0039 | payload padding | D-0071 |
| D-0040 | signatures | D-0072 |
| D-0041 | the letter flow | D-0073 |
| D-0042 | relay token | D-0074 |
| D-0043 | relay | D-0075 |
| D-0044 | RelayTransport | D-0076 |
| D-0045 | schema v3 | D-0077 |
| D-0046 | contacts by address, TOFU | D-0078 |
| D-0047 | identity code | D-0079 |
| D-0048 | addresses | D-0080 |
| D-0049 | contact data in the protected layer | D-0081 |
| D-0050 | `network.client`, no ATS | D-0082 |
| D-0051 | echo peers removed | D-0083 |
| D-0052 | two instances | D-0084 |
| D-0053 | VERIFY results, summary | not yet (human run) |

### D-0069 — Crates and features for the transport

- **Date:** 2026-09-28
- **Decision:** Workspace dependencies `p256` 0.14 (default features off,
  `ecdsa`), `reqwest` 0.13 (default features off, `blocking`: no TLS, no
  system proxy, no JSON), `axum` 0.8 (`http1`, `tokio`) and `tokio` 1.53
  (`rt`, `net`, `macros`). p256 is a normal dependency of brev-proto only
  (the one verifier, D-0072) and a dev-dependency of brev-mail and
  brev-relay (test signers); reqwest is brev-mail's client and the relay
  tests' client; axum and tokio are brev-relay's. `ed25519-dalek` is gone
  from both manifests. No DER code of ours: p256 always turns on ecdsa's
  `der`, so `Signature::from_der` exists. brev-core's `rust-version` became
  1.88 (url → idna → ICU4X 2.3 declares it), superseding D-0015 for that
  crate; D-0067 has since raised the whole workspace to 1.89, so the
  design's "brev-proto and brev-relay stay at 1.85" no longer holds.
  `uniffi-bindgen` stays at 1.88. `scripts/test.sh` pins p256's and
  reqwest's features in `cargo tree`.
- **Reasoning:** All four crates are in CLAUDE.md §4, each with the smallest
  feature set that works: reqwest without `system-proxy` links no
  CF/SC/Security symbol and cannot be sent through a proxy; axum without its
  defaults parses no HTTP/2, JSON or forms. p256 is not independently
  audited (its README) and only handles public inputs here. The Ed25519 test
  signer had no user left once envelopes carry P-256 signatures (D-0072).
- **Verified:** `eafae9b` (Cargo.lock 123 → 139, `cargo audit` clean),
  `fae89f9` (→ 211), `2f1d4a6` (→ 209 once ed25519 and ed25519-dalek left;
  audit clean over 209 crates), `239de4a` (the feature pins in test.sh).
  Design §0: `nm -u libbrev_core.a` names no CF/SC/Security symbol. At
  `60d4e1b`: `cargo audit` clean over 210 crates (brev-vault added, D-0066).
  Phase 4 added no crate: `Cargo.lock` still lists 210 packages.

### D-0070 — Protocol v1 wire format

- **Date:** 2026-09-28
- **Decision:** `PROTOCOL_VERSION` 0 → 1. The wire is `"BREV"` ‖ version
  (u16 BE) ‖ sender id 32 ‖ recipient id 32 ‖ nonce 24 ‖ ciphertext (padded
  payload ‖ 16-byte tag) ‖ signature 64 (raw r ‖ s). `signed_bytes` is
  D-0018's layout, everything before the signature. The envelope id is
  SHA-256(`signed_bytes`); the relay dedupes and acks by it. At least 430
  bytes; `MAX_WIRE` = 1 048 750. `from_wire` refuses a length outside that
  range, wrong magic, a version other than 1, and a ciphertext that is not a
  padded length plus 16; `to_wire` refuses a signature that is not 64 bytes.
  The other relay bodies are binary `POST`s (design §2.4). Phase 4 keeps
  version 1 and changes only the relay bodies around the wire (D-0087,
  D-0090).
- **Reasoning:** The plaintext inside the AEAD changed (D-0071), so a v0
  reader would misparse it; the version is in the AD and in the signed
  bytes, so a v0 envelope fails everywhere. Fixed-length header and
  signature make the parse unambiguous without length fields, and the relay
  rebuilds `signed_bytes` byte for byte (D-0018's rule). The id leaves out
  the signature, so signature malleability changes no id.
- **Verified:** `eafae9b`: `wire_round_trip_and_layout`,
  `from_wire_refuses`, `identity_id_matches_d0016`. `fae89f9`: brev-relay's
  `submit_checks` (`MAX_WIRE + 1` gives 413). All pass at `60d4e1b`.

### D-0071 — Envelope payload padding

- **Date:** 2026-09-28
- **Decision:** `seal_message` pads the payload (D-0020) with Phase 2's
  `pad_into` (u32 BE length ‖ content ‖ zeros) to 256 B, 1 KiB, 4 KiB, 16
  KiB, then multiples of 16 KiB; `open_message` calls `unpad`, and bad
  padding under a valid tag is `Malformed`. The hard maximum of 1 MiB padded
  holds in the app (`padded_len` gives none: `Malformed`) and at the relay
  (`from_wire`, and axum's `DefaultBodyLimit` answers 413 before parsing). A
  real letter pads to at most 80 KiB (256-byte subject, 64 KiB body). The
  padding functions live in brev-vault since D-0066; brev-proto re-exports
  them.
- **Reasoning:** This implements D-0027's padding item and closes the Phase
  1 TODO: the relay sees a bucket, not a length. The stored columns already
  use the same functions (D-0041).
- **Verified:** `2f1d4a6`: `envelope_payload_is_padded` (design §8: sizes
  within one bucket give equal ciphertext lengths; the boundary sizes;
  `MAX_PADDED − 3` is `Malformed`); `padded_lengths_only`; the relay's
  `submit_checks`. All pass at `60d4e1b`.

### D-0072 — Signatures: P-256 from the Enclave, verified in Rust before decryption

- **Date:** 2026-09-28
- **Decision:**
  - ECDSA P-256/SHA-256 with the identity key (the Enclave `SecKey` of
    CLAUDE.md §3.2, unchanged). Rust computes SHA-256 of the preimage and
    Swift signs that digest with `.ecdsaSignatureDigestX962SHA256`
    (`Enclave.sign(digest:key:)` in `Shared/`), so 32 bytes cross the FFI
    and what is signed is still `signed_bytes`. Domains: envelopes start
    with `"BREV"`, registration with `"brev/v1/register\0"` (v2 since
    D-0087); no preimage is valid in both.
  - On the wire, raw r ‖ s, 64 bytes, either S (Security.framework does not
    normalise; about half are high-S). `brev_proto::sig::verify` is the one
    verifier, used by brev-mail and brev-relay: the key exactly 65 bytes,
    `04`, on the curve; `Signature::from_slice`; p256's verify. `der_to_raw`
    uses `from_der`.
  - A signing key must be a valid uncompressed P-256 point in
    `Core::create`, in a lookup answer and at registration. This ends
    D-0016's "opaque, 1..=255 bytes".
  - Receive order (extends D-0020): addressed to me; the keyed tag finds a
    contact; the pinned bundle opens and hashes to the sender; the signature
    with the pinned key; only then AEAD, unpad, payload, thread owner and
    insert. Each failure is permanent (acked and dropped) or local (a
    damaged row or a failed write: not acked, fetched again), D-0076.
  - No `SigningKey` in production code: test signers are in
    `src/test_keys.rs` (`cfg(test)`) and `tests/`, and test.sh greps for it.
- **Reasoning:** CLAUDE.md §5 Phase 3 and D-0027: Swift only signs, Rust
  verifies. A letter not signed by the pinned key never reaches the AEAD,
  and D-0017's key-compromise impersonation narrows: a leaked X25519 secret
  no longer lets anyone forge letters to its owner. A low-S rule would
  protect nothing, since the id leaves out the signature.
- **Verified:** Design §0: 550 of 550 Security.framework signatures (150
  from Enclave keys) parse from DER and verify with p256 0.14 as produced.
  `eafae9b`: `verify_rules`, `der_to_raw` with four committed Swift vectors.
  `2f1d4a6`: `receive_verifies_before_decrypting`,
  `attach_refuses_foreign_signature`. `239de4a`: the `SigningKey` grep. All
  pass at `60d4e1b`. The real identity key's Touch ID signature (V55, V56):
  pending human run.

### D-0073 — The letter flow across UniFFI (supersedes D-0019)

- **Date:** 2026-09-28
- **Decision:** No call that takes content does network I/O, and no network
  call takes content. One letter:
  1. `prepare_send(contact)` on the serial queue `no.brev.net`: a token
     lookup of the contact's key, without the session mutex. A changed key
     goes into `pending` and gives `KeyChanged`; otherwise a one-use send
     ticket is set. (Since D-0068 the class-A check runs first; since Phase
     4 the lookup's status can give `NotApproved`, D-0088.)
  2. `sign_request(contact, subject, body)` on main, no I/O: takes the
     ticket, pads and seals the payload, builds the unsigned envelope and
     the rows to store, keeps them in one slot, drops every plaintext and
     the X25519 secret, and returns the digest.
  3. Swift signs with Touch ID (`send.reason`): the one prompt per letter. A
     cancel calls `cancel_send()`, and the draft stays.
  4. `attach_signature(der)` checks the signature against the own key in the
     identity row (`Signing` otherwise). `submit()` posts the wire and
     stores the letter only after 202 or 200. `Network` keeps the signed
     slot, and *Prøv igjen* calls `submit()` again with no second prompt;
     another 4xx clears it.

  `lock()` and `cancel_send()` clear ticket and slot; `sync()` never sends.
  Registration uses the same two steps (`register_request`, `register`). The
  send prompt does not suspend auto-lock:
  `LockState.signPanelTakesActivation` is false, every signature goes
  through `LockController.beginSign`/`endSign`, and the design's fallback
  (every content view blank during the prompt) is built behind that switch.
- **Reasoning:** §5 Phase 3's `sign_request` → Touch ID →
  `attach_signature`. With the lookup outside the content call, no Swift
  buffer is borrowed during I/O and a lock never waits on the network. The
  draft and the letter panes are on screen during the send prompt, so
  resign-active must lock unless U4 shows that the Touch ID panel itself
  takes activation.
- **Verified:** `2f1d4a6`: `sign_request_needs_a_fresh_prepare`,
  `sign_request_and_register_request_make_no_request`,
  `lock_and_cancel_clear_the_pending_letter`,
  `nothing_decrypted_is_alive_on_the_network`, `submit_retry_is_idempotent`.
  `ab2f14d`: harness case 2 and the lock probe run the switch in both
  positions. All pass at `60d4e1b`. U4 (logged in category `touchid`), V56,
  V62 and V63: pending human run.

### D-0074 — A relay token instead of signed relay requests

- **Date:** 2026-09-28
- **Decision:** `Core::create` draws a 32-byte relay token from the OS RNG
  and seals it in `identity.keys`. Registration, signed with the identity
  key, carries SHA-256(token), and the relay keeps only that hash. Lookup,
  inbox and ack start with a 64-byte prefix, caller id ‖ token; an unknown
  id or a wrong token gives 401. No clock window and no nonce map. In Phase
  3 submit carried no token (the envelope's signature names the sender);
  Phase 4 adds the prefix to submit and to every new endpoint except invite
  open (D-0090).
- **Reasoning:** The design review dropped a third Enclave key, signed
  polls, a ±300 s clock rule and a nonce map (design §12): on loopback,
  capturing the token needs root or Brev's memory, both outside CLAUDE.md
  §2. The token is usable only while Brev is unlocked. The stored hash does
  not give the token, so the comparison needs no constant time. Signed
  requests were to return with TLS and a remote relay; Phase 4 kept the
  local relay (D-0085), so the token stays.
- **Verified:** `fae89f9`: `requests_need_the_token` (unknown id, wrong
  token, another identity's token: 401); passes at `60d4e1b`. A captured
  token can be replayed; design §11 lists it with the residual risks.

### D-0075 — The relay

- **Date:** 2026-09-28
- **Decision:** `brev-relay` is a library and a thin binary. Binary `POST`
  endpoints: `/v1/register` (201, 200 for the same registration, 409, 400,
  401), `/v1/lookup` (the 97-byte bundle, 404), `/v1/envelopes` (202 stored,
  200 already waiting, 400, 403, 404, 413), `/v1/inbox` (oldest first, at
  most 16 envelopes and 4 MiB, deletes nothing), `/v1/inbox/ack` (204, only
  the caller's envelopes); `GET /v1/health`. Body limits: `MAX_WIRE` on
  envelopes, 16 KiB elsewhere. SQLite schema v1 (`identities`, `envelopes`,
  index `inbox`), `application_id` "BRLY", `journal_mode = DELETE`,
  `secure_delete = ON`, folder 0700, file 0600, absolute paths only. The ack
  deletes the row; no timestamps, tombstones, IP addresses or request log.
  An envelope's recipient is looked up only after its signature verifies, so
  an unsigned request cannot probe the directory. `Policy` hooks (register,
  submit, request; Deny is 429 before any write), `Open` in Phase 3. `serve`
  binds `127.0.0.1:<port>` only (`--port-file`; `--trace` prints path and
  status per request, stores nothing). `release --db <path> <address>` is
  the operator's command. One `Mutex<Connection>` on a current-thread tokio
  runtime. `scripts/relay.sh` serves on 127.0.0.1:8787 with the database in
  `~/Library/Application Support/brev-relay/`. Phase 4 replaces the schema
  and adds its rules (D-0089).
- **Reasoning:** CLAUDE.md §5 Phase 3: a minimal axum server that stores
  only ciphertext and routing metadata, deletes after delivery and has no
  accounts beyond a key and its address. `secure_delete` zeroes the cells of
  delivered envelopes. Loopback only, because there is no TLS; the owner
  accepted the local relay for test letters (D-0065 item 1).
- **Verified:** `fae89f9`: `register_rules`, `requests_need_the_token`,
  `submit_checks`, `inbox_and_ack`, `ack_deletes_bytes_from_the_file`,
  `relay_file_holds_no_plaintext`, `policy_hook_denies_before_writing`,
  `release_frees_an_address`, `listen_refuses_anything_but_127_0_0_1`; with
  `secure_delete` off both file tests failed. `2f1d4a6`: brev-mail's
  `relay_file_holds_no_plaintext` (a DoD test). test.sh passes at `60d4e1b`.
  V54, V58, V59 and V64 on the real relay: pending human run.

### D-0076 — RelayTransport: the client, the mutex rule and `sync`

- **Date:** 2026-09-28
- **Decision:**
  - `relay.rs` in brev-mail: one `reqwest::blocking::Client` per `Brev` with
    `no_proxy()`, no redirects, 3 s to connect, 15 s in all. Answers are
    read through caps and parsed strictly; 4xx is `Refused`, anything else
    that is not the expected answer is `Network`. The relay URL comes from
    Info.plist `BrevRelayURL` (build setting `BREV_RELAY_URL`, default
    `http://127.0.0.1:8787`) and must be exactly `http://127.0.0.1:<port>`
    (`Malformed` otherwise).
  - No network call holds the session mutex: gate and copy under it, release
    it, do the request, take it again. A lock epoch makes that second half
    return `Locked`, so nothing is stored or acked after a lock.
  - `Transport` is `send`, `poll` (deletes nothing) and `ack`; `receive_all`
    is gone. `sync()` polls, stores each envelope under its own mutex hold,
    then acks the stored ones and the ones refused for good (D-0072); a
    local failure stays at the relay. Delivery is at least once to the core
    and exactly once into the store (message-id dedupe), which closes
    D-0026's at-most-once.
  - Swift syncs on `no.brev.net` right after unlock, every 5 s while
    unlocked and registered, and after a send; a tick is skipped while a
    sync runs, and failures are logged once per change.
  - `BrevError` gains the unit variants `KeyChanged`, `AddressTaken`,
    `Network` and `Refused`.
- **Reasoning:** An IP literal means no resolver runs, so no local process
  can answer for `localhost` on `[::1]` (design §0), and no build can send
  metadata off the Mac over plain HTTP. Only ciphertext, public data and the
  token pass through reqwest, and the zeroing allocator covers its frees.
  `lock()` on main never waits on a timeout.
- **Verified:** `2f1d4a6`: `no_network_under_the_session_mutex`,
  `ack_after_store`, `locked_session_makes_no_request`. `8997ead`:
  `redirects_are_not_followed`, `an_answer_over_its_cap_is_network`,
  `inbox_reads_no_further_than_its_cap` and `proxy_variables_are_ignored`,
  each shown to fail with its protection removed. All pass at `60d4e1b`. V63
  and V64: pending human run.

### D-0077 — Schema v3

- **Date:** 2026-09-28
- **Decision:** `SCHEMA_VERSION` 3; a v2 store opens as `Corrupt` and must
  be reset. `identity.keys` holds X25519 secret ‖ X25519 public ‖ P-256 key
  (65) ‖ relay token (32); `identity.address` is sealed and empty until
  registered. `contacts` has a local id (16 random bytes, kept across a key
  change), `tag` (HKDF-SHA256 over the identity id under the DEK, info
  `"brev/v1/contact-tag"`, UNIQUE), and sealed `bundle`, `address` and
  `pending` (always sealed, so the file shows no "key changed" flag). Column
  ADs use the local id and no AD holds the identity id, so accepting a key
  re-encrypts nothing. A bundle whose id's tag is not the row's tag is
  `Corrupt`. D-0068 made the schema v4, Phase 4 v5 (D-0091).
- **Reasoning:** A reader of `brev.db` sees neither a contact's identity id
  nor its address, so the file cannot be joined with the relay's directory
  (CLAUDE.md §3.1: only queryable metadata in plaintext). v2 stores held
  only echo letters, so no migration.
- **Verified:** `2f1d4a6`: `store_holds_no_contact_id_or_address`,
  `column_ad_uses_local_contact_id`, `local_row_failures_are_corrupt`,
  `v2_store_is_refused`; all pass at `60d4e1b`.

### D-0078 — Contacts by address, pinned on first use; a changed key blocks sending

- **Date:** 2026-09-28
- **Decision:** `add_contact(address)` takes an address typed in a key-only
  field and passed like content: normalise and validate it, refuse the own
  address (`Malformed`) and a known one (`Duplicate`), look it up with the
  token, and pin the answer (TOFU). A key change is detected only in
  `prepare_send`, at each *Send*: the other bundle goes into `pending`,
  `sign_request` gives `KeyChanged` before it seals anything,
  `ContactRow.key_changed` turns *Nytt brev* off, and the header shows the
  warning and both codes. *Godta ny kode* opens `ConfirmSheet`, then
  `accept_new_key(contact, new_code)`, which Rust refuses unless `new_code`
  is the code of the current `pending`. Letters from a new key that is not
  yet accepted are a stranger's: dropped and acked (D-0065, Q2). Phase 4
  puts contact requests in front of this (D-0088).
- **Reasoning:** D-0031. There is no lookup when a contact is selected, so
  the relay does not learn which conversation is open. Binding the
  acceptance to the code on screen catches a relay that swaps the pending
  key between showing and accepting. First contact trusts the relay;
  comparing codes (D-0079) or an invite (D-0086) catches a false first key.
- **Verified:** `2f1d4a6`: `changed_key_warns_and_blocks_sending` (a DoD
  test), `accept_is_bound_to_the_shown_code`,
  `registration_and_contacts_by_address`, `strangers_are_dropped_and_acked`.
  `ab2f14d`: the view host's `--contacts` run makes a real key change
  (`brev-relay release`, a new identity) and accepts it; PASS at `60d4e1b`
  (V69). V60 in the two apps: pending human run.

### D-0079 — Identity code

- **Date:** 2026-09-28
- **Decision:** RFC 4648 base32 (A–Z, 2–7) of the first 150 bits of the
  identity id: 30 characters in 6 groups of 5, 35 ASCII bytes
  (`brev_proto::identity_code`, a hand-written table lookup). The id formula
  is D-0016's, moved to `brev_proto::identity_id` so the relay computes the
  same id. Shown for oneself and per contact; comparing it is optional; no
  QR code, no link. Phase 4 uses the same 150 bits, without spaces, as an
  invite's fingerprint (D-0086).
- **Reasoning:** D-0016 asks for at least 128 bits, because a k-bit prefix
  can be matched in about 2^k tries. Groups of 5 can be read aloud.
- **Verified:** `eafae9b`: `identity_code_known_answers` (design §3.4's
  known answers), `identity_id_matches_d0016`; both pass at `60d4e1b`. V61
  (the code Brev shows for Brev B equals Brev B's own): pending human run.

### D-0080 — Addresses

- **Date:** 2026-09-28
- **Decision:** 3 to 32 characters of `a–z`, `0–9` and `-`, the first a
  letter, checked in one place (`brev_proto::is_valid_address`); one per
  identity; permanent, so only the operator's `brev-relay release` frees one
  (D-0065, Q3). The address is registered after the first unlock, on the
  address page (`AddressViewController`): a key-only field (A–Z folded,
  anything else beeps), *Registrer*, one Touch ID. A 409 shows
  `address.error.taken`; after `Network` the same signed body is posted
  again with no second prompt. Phase 4 adds an invite step before it
  (D-0087).
- **Reasoning:** ASCII addresses have no look-alikes and need no Unicode
  normalisation. A permanent address keeps self-service release, which would
  need a request signed by the old key, out of the relay.
- **Verified:** `fae89f9`: `register_rules` (charset, length, first letter,
  taken, idempotent), `release_frees_an_address`. `ab2f14d`: the address
  page in the view host's `--contacts` run; PASS at `60d4e1b`. V55: pending
  human run.

### D-0081 — Contact data is drawn only in the protected layer

- **Date:** 2026-09-28
- **Decision:** Addresses (one's own and each contact's) and identity codes
  are content in the UI. They are drawn only by `ContactTextView`s in the
  capture-protected layer, never through `L10n`, `InterfaceText` or the
  accessibility tree. Addresses cross the FFI as `OpenText` (closed on
  lock); codes as 35-byte `Vec<u8>`, which Swift keeps in `SecretBytes` and
  wipes on lock. No string in `Localizable.strings` takes an address, a name
  or a code. No pasteboard in Phase 3: D-0031's address copy came with Phase
  4's contact screen (D-0094).
- **Reasoning:** A contact's name is its address, and Phase 2 treats names
  as content (CLAUDE.md §1.5). The relay's directory holds addresses in
  clear, but there they are routing metadata, not something shown by the
  app.
- **Verified:** `ab2f14d`: the lock probe draws the header's addresses and
  codes and checks that the lock sequence wipes them and zeroes their
  pixels; the view host's `--contacts` run finds no address marker or code
  in the AX tree. `244175e` (the review of Phase 3 WP5, although its subject
  says Phase 2): a replaced header line now zeroes its pixels, and a lock no
  longer reads contacts through the compose sheet's close; the lock probe
  fails on the code before the fix. V69 PASS at `60d4e1b`. V68 on the real
  app with a contact: pending human run.

### D-0082 — `network.client`, no ATS key, no `URLSession`

- **Date:** 2026-09-28
- **Decision:** The entitlements add `com.apple.security.network.client`,
  never `network.server`. Info.plist has no `NSAppTransportSecurity` key:
  reqwest uses BSD sockets, which ATS does not govern. The forbidden-API
  grep adds `URLSession` and `NSURLConnection`, so Swift never opens a
  second, ATS-governed path.
- **Reasoning:** Design §0: a sandboxed probe could not connect to the
  loopback relay without the entitlement. An ATS exception would only
  suggest a URL-loading path that does not exist.
- **Verified:** `239de4a` (entitlement, grep). At `60d4e1b`: V1 and V53 pass
  on the Release and Verify builds (`network.client` present,
  `network.server` absent); V66 passes (no ATS key; no `URLSession` or
  `NSURLConnection` in `nm -u`). V54 (Brev connects only to 127.0.0.1:8787
  and listens nowhere): pending human run.

### D-0083 — The echo peers are removed (closes D-0042)

- **Date:** 2026-09-28
- **Decision:** `echo.rs`, the stores `peer-1.db` and `peer-2.db`,
  `Unsigned`, `Signer`, `send_new`, `receive_all`, `Delivery` and the echo
  `sync` are deleted, and `KeyStore`'s known names lose the peer files. The
  tools that used them moved to the relay (`239de4a`): the harness, the lock
  probe, the view host (its own relay and users), `padcheck` (one store),
  `capture-probe` and `TouchIDProbe`. The owner's edit `ba70411` removed the
  two CLAUDE.md §2 mentions of the echo stores; `docs/THREAT_MODEL.md` was
  re-synced.
- **Reasoning:** CLAUDE.md §5 Phase 3 replaces the `MockTransport` contacts
  with the relay. The echo stores were a Phase 2 residual risk (D-0033 item
  3). `MockTransport` stays for the Rust tests behind `test-hooks` (D-0066).
- **Verified:** `2f1d4a6` (the deletions; Cargo.lock 211 → 209), `239de4a`,
  `ba70411`. At `60d4e1b` the Release binary has no `MockTransport` symbol
  (D-0066).

### D-0084 — Two instances by bundle id ("Brev B")

- **Date:** 2026-09-28
- **Decision:** The second instance is the same code built with
  `PRODUCT_BUNDLE_IDENTIFIER=no.brev.app.b` and `PRODUCT_NAME="Brev B"`:
  `scripts/build.sh --instance b`, derived data in `app/build-b`. The
  keychain group entitlement is
  `$(AppIdentifierPrefix)$(PRODUCT_BUNDLE_IDENTIFIER)` and
  `KeyStore.accessGroup` is `AV26DNQ5SC.` plus the bundle id (`239de4a`);
  `CFBundleName` and `CFBundleDisplayName` come from `$(PRODUCT_NAME)`, so
  the Dock and the Touch ID dialogs say «Brev B» (`63fc44f`). Brev B has its
  own container, `.lock`, Enclave keys and wrapped DEK in group
  `AV26DNQ5SC.no.brev.app.b`; both apps use the one relay. The default build
  passes no overrides.

  **No App ID was registered:** automatic signing signed Brev B with the
  team's wildcard profile `Mac Team Provisioning Profile: *`
  (`AV26DNQ5SC.*`, D-0052 item 6), as it signs Brev, so the approval of a
  second App ID `no.brev.app.b` (D-0065 item 2) was not used. The comment in
  `scripts/build.sh` and design §7 still say the first build registers it.
- **Reasoning:** Container, data folder, `.lock` and keychain items all
  follow from the bundle id, which the code signature covers. Rejected:
  `open -n` of the same app (same container; `.lock` refuses it) and a
  runtime switch (LaunchGuard refuses arguments and environment).
- **Verified:** `63fc44f`: the default Release build's entitlements, built
  Info.plist, bundle id, signature summary and embedded profile are
  byte-identical before and after; Brev B was built once and not launched
  (`no.brev.app.b`, «Brev B», group `AV26DNQ5SC.no.brev.app.b`, the wildcard
  profile); test.sh green. V57, the two-instance DoD run: pending human run.

---

## Phase 4 — anti-noise (2026-09-28 to 2026-09-29)

The entries `docs/PHASE4_DESIGN.md` §10 plans as D-0069 to D-0080, and one
for *Blokker*, which the owner added. The design expected its numbers to
move up by 17 once Phase 3's entries landed; Phase 3 took 16 (D-0069 to
D-0084) and *Blokker* has an entry of its own, so:

| Design §10 | Topic | Entry |
|---|---|---|
| D-0069 | owner answers Q1–Q7 | D-0085 |
| D-0070 | invite codes | D-0086 |
| D-0071 | registration v2 | D-0087 |
| D-0072 | approval at the relay | D-0088 |
| D-0073 | relay schema v2, clock, `release` | D-0089 |
| D-0074 | rate limits | D-0090 |
| D-0075 | brev-mail schema v5, events | D-0091 |
| – | *Blokker* (owner answer 6) | D-0092 |
| D-0076 | FFI additions | D-0093 |
| D-0077 | pasteboard | D-0094 |
| D-0078 | App Attest stub | D-0095 |
| D-0079 | `IdentityVerifier` | D-0096 |
| D-0080 | review record; VERIFY results | D-0097 (results not yet: human run) |

"test.sh green at `4c8c231`" below is what the commit messages of WP4 and
WP5 and their reviews record.

### D-0085 — Owner answers to Phase 4's questions

- **Date:** 2026-09-28
- **Decision:** Yes to all seven recommendations (`cff3e69`, the design's
  "Owner answers"):
  1. Phase order (b): WP0 to WP2 at once on branch `claude/phase4`; WP3
     onward after the Phase 3 DoD run is signed off.
  2. A contact request carries no text: address and safety code only.
  3. Limits per identity and UTC day: 50 letters, 10 requests, 3 invites
     made; 5 open invites; 16 pending requests per recipient; invites live 7
     days. All are relay flags (D-0090).
  4. The relay keeps the approval graph, and CLAUDE.md §2's local-relay line
     covers Phases 3 and 4.
  5. A requester is not told of a decline.
  6. *Blokker* is added now (D-0092).
  7. Creating an invite is one human click, no Touch ID.

  Later, in WP5 (2026-09-29), the owner decided that the contact pasteboard
  clears after 60 s and at quit, not at a lock (D-0094). As built, WP3 to
  WP5 followed on 2026-09-29 (`c05a7ba` to `4c8c231`) before the Phase 3 DoD
  run, and `docs/USER_SESSION.md` (`f40794a`) now tests Phases 2 to 4 in one
  human run. Not found: a commit or document in which the owner changed
  answer 1.
- **Reasoning:** Answer 4 is the price of D-0030's relay-side approval
  check: who takes letters from whom now stays at the relay, where Phase 3
  kept who writes to whom only until delivery. Answer 2 adds no content path
  and leaves a spammer only a 32-character address. Answer 7: the invitee's
  registration is signed, and the inviter checks the invitee's tag (D-0086).
- **Verified:** `0c7ac4b`: CLAUDE.md §2 (answer 4: the line names the
  invite and approval graphs as relay metadata) and §5 Phase 4 (answers 2,
  5, 6 and 7) edited, `docs/THREAT_MODEL.md` synced. `c93850e`:
  `config_defaults_are_the_owners_values` pins answer 3.

### D-0086 — Invite codes

- **Date:** 2026-09-28
- **Decision:**
  - Text `brev1.<address>.<fingerprint>.<secret>`, lower-case ASCII, at most
    96 bytes; a root invite (made by the operator, no inviter) is
    `brev1.<secret>`. The fingerprint is the inviter's identity code without
    spaces (D-0079). The secret `s` is 16 bytes from the OS RNG in base32
    (26 characters, padding bits zero). `parse` trims whitespace, folds
    case, and needs the prefix, 2 or 4 parts, a valid address and canonical
    base32; it writes `s` into a buffer the caller owns and zeroes it on a
    refusal. Codes are text, never links.
  - The relay sees only `a` = SHA-256(`"brev/invite/relay\0"` ‖ s) and
    stores SHA-256(a); it never parses a code. The invitee's proof to the
    inviter is `tag` = HKDF-SHA256(ikm = s, info = `"brev/invite/peer\0"` ‖
    invitee id ‖ inviter id ‖ L ‖ invitee address).
  - Both directions are checked. The invitee checks the relay's answer to
    `a` against the code's form, address and fingerprint (`InviteMismatch`:
    nothing stored or sent). The inviter keeps `s` sealed (D-0091) and pins
    an invitee only when a tag recomputed from the event's bundle and
    address matches.
  - One use, a 7-day life; 5 open and 3 made a day per identity (D-0090).
- **Reasoning:** D-0031 and CLAUDE.md §5 Phase 4: redeeming makes both
  people approved contacts with the inviter's key verified. A lying relay
  cannot fit a 150-bit fingerprint to its own key, and knowing only `a` it
  can neither forge an *invited* event nor swap the invitee's key or name.
  The invitee's address is in the tag because the id covers only the keys
  (`bd4c1fc`).
- **Verified:** `cff9b26`, `bd4c1fc`:
  `invite_code_round_trip_and_known_answers`, `invite_parse_refuses`,
  `base32_decode_inverts_identity_code`, `invite_derivations_known_answers`
  (vectors recomputed with Python's `hmac`; reverting the address in the
  info fails it). brev-mail (`c05a7ba`, `b565da4`):
  `invite_with_wrong_fingerprint_is_rejected` (a DoD test, five cases),
  `invite_makes_both_approved_and_verified`,
  `forged_invited_event_is_dropped`, `open_invite_on_existing_contact`.
  brev-relay: `relay_file_holds_no_invite_secret`. Harness case 9
  (`8ac082e`, `4c97502`): an edited fingerprint gives `InviteMismatch`, and
  after the lock there is no copy of the secret as text or as its 16 raw
  bytes, 5 of 5. test.sh green at `4c8c231`. V71 and V77: pending human run.

### D-0087 — Registration v2 needs an invite

- **Date:** 2026-09-28
- **Decision:** The body is `L ‖ address ‖ signing key 65 ‖ X25519 32 ‖
  SHA-256(token) ‖ a ‖ tag ‖ signature 64 ‖ attestation length u16 ‖
  attestation` (0 to 8 192 bytes), signed over `"brev/v2/register\0"` ‖
  bytes [0, 194 + L), so a v1 body never verifies. The attestation is made
  over the signed digest and is not itself signed. The relay's order: parse,
  signature, attestation (feature `app-attest`, D-0095), the same
  registration again (200), the invite (403 if unknown, used or expired),
  only then an address or id conflict (409), `IdentityVerifier` (428),
  `Policy` (429). A 409 does not use up the invite. `invited_by` records the
  inviter (NULL for a root invite); a non-root invite approves both
  directions and queues an *invited* event for the inviter. The address page
  gets an invite step first: paste the code, *Fortsett* (`open_invite`),
  then «Invitert av:» with the inviter's address and code (protected) or
  `invite.root`, then Phase 3's address field and *Registrer*. `brev-relay
  invite --db <path>` prints a root code, the only way in for the first
  identity.
- **Reasoning:** CLAUDE.md §5 Phase 4: a new identity needs an invite, and
  the relay tracks the invite graph. Checking the invite before the conflict
  keeps Phase 3's promise that nobody without an invite can probe which
  addresses are taken (design §12, finding 7). The 8 KiB cap keeps the
  largest body under the 16 KiB limit (finding 9).
- **Verified:** `cff9b26`: `registration_v2_layout`. `c93850e`:
  `registration_needs_an_invite` (the largest body through the real router),
  `registration_does_not_probe_the_directory`, `invite_graph_is_recorded`,
  `invites_are_one_time_and_expire`, `invite_command_prints_a_root_code`.
  `cb3af17`: the invite step in the view host's `--contacts` run; `4c8c231`:
  the lock probe wipes step 2's field and the inviter's address and code.
  test.sh green at `4c8c231`. V71: pending human run.

### D-0088 — Approval at the relay

- **Date:** 2026-09-28
- **Decision:**
  - The relay keeps directed `links(owner, peer)`, approved (the owner takes
    letters from the peer) or declined. An envelope S→R is stored only if
    `links(R, S)` is approved; otherwise 409, and nothing is written.
  - `add_contact` always sends a request (`/v1/requests`, prefix ‖ address,
    no text). It approves the other direction for the requester, lifts the
    requester's own earlier decline, and, unless R already approved S, gives
    R a *request* event. The answer is 202 for new, pending, declined and
    over R's cap of 16 pending requests alike, so a requester cannot learn
    of a decline; at the daily limit every request gets 429.
  - *Godta* and *Avslå* are one `HumanButton` click, no Touch ID.
    `/v1/events` returns at most 32, *invited* and *approved* before
    requests, each oldest first; an *approved* event never replaces a
    waiting *invited* one.
  - The lookup answer gains a status byte (1: the target takes my letters).
    `prepare_send` gives `NotApproved` on 0, before any digest or prompt;
    `submit`'s 409 is `NotApproved` too.
  - Locally a contact exists only for a peer the user added, approved or
    verified by invite, and brev-mail still drops letters from non-contacts,
    so a relay cannot widen who reaches the inbox.
- **Reasoning:** CLAUDE.md §5 Phase 4: letters only from approved contacts,
  and one short request, approved or declined with one click. The relay's
  check keeps spam out of its store; the client's holds even against the
  relay. Invites and approvals come first so that 16 old requests can never
  hide them (finding 5).
- **Verified:** `c93850e`: `unapproved_sender_cannot_reach_an_inbox` (DoD),
  `requests_once_per_pair`, `event_answer_rules`,
  `crossing_requests_approve_each_other`,
  `request_answers_do_not_reveal_a_decline`,
  `re_adding_a_declined_peer_unblocks_them`,
  `events_put_invited_and_approved_before_requests`,
  `approved_envelope_is_delivered_on_the_next_poll` (DoD, immediate
  delivery); 14 mutations of the rules each fail a test. `c05a7ba`:
  `a_stranger_cannot_reach_an_inbox` (DoD), `request_approve_and_decline`,
  `add_contact_always_requests`. Harness case 9 (`8ac082e`): C cannot send
  to A until A's one click. test.sh green at `4c8c231`. V74, V75 and V76:
  pending human run.

### D-0089 — Relay schema v2, the UTC-day clock and `release`

- **Date:** 2026-09-28
- **Decision:** `user_version` 2; a v1 file is refused as `NotRelay` and
  left untouched. New: `identities.invited_by` (NULL for a root invite),
  `links`, `events` (one per pair; a newer event replaces the older),
  `invites` (SHA-256(a), inviter, UTC day, `redeemed_by`) and `counts`
  (identity, kind, day, n). Days only, never times: `Clock` gives `unix_secs
  / 86 400`, and tests use a manual clock. Each invite write deletes expired
  invites, and a count row from an older day is reset on write. Each rule
  runs in one transaction that only a success commits, so a 403, 404, 409,
  428 or 429 writes nothing. `release` also deletes the identity's links,
  events, invites made and counts; its invitees keep a dangling
  `invited_by`. New endpoints: `/v1/requests`, `/v1/events`,
  `/v1/events/answer`, `/v1/invites`, `/v1/invites/open` (no prefix),
  `/v1/invites/redeem` and `/v1/block`. WP2's transitional `serve --phase3`
  mode was removed in WP4 (`8ac082e`).
- **Reasoning:** What the relay learns now (design §4.5): the invite graph
  for an identity's life, the approval graph for good (answer 4), pending
  requests, and each identity's counts for the day; never content, contact
  names or `s`. On a local relay the user can move the clock (design §11).
- **Verified:** `c93850e`: `v1_relay_file_is_refused`,
  `release_deletes_links_events_invites_counts`,
  `serve_takes_the_limit_flags`; 38 relay tests green with and without
  `app-attest`. test.sh green at `4c8c231`. V80, the byte scan of the real
  `relay.db`: pending human run.

### D-0090 — Rate limits, and the sender's token on submit

- **Date:** 2026-09-28
- **Decision:** Per identity and UTC day: 50 letters, 10 requests, 3 invites
  made; 5 open invites; 16 pending requests per recipient; invites live 7
  days (answer 3; `Config` defaults and `serve` flags). Submit is `prefix ‖
  wire`: the token must match and the caller must be the envelope's sender
  (403); then approval (409); then an envelope already waiting answers 200;
  then the letter count (429). Only an inserted letter (202) counts. Lookups
  are not limited.
- **Reasoning:** CLAUDE.md §5 Phase 4: at most N letters a day per identity,
  enforced by the relay. With the token on submit, nobody holding a signed
  wire, the recipient included, can spend the sender's quota by replaying it
  (finding 6). A waiting envelope is answered first, so a retry of a stored
  letter is never told 429. What the caps do not stop: without real App
  Attest or BankID each identity can bring in 3 more a day (design §4.4,
  §11).
- **Verified:** `c93850e`: `letters_are_rate_limited_per_identity_per_day`
  (DoD), `requests_are_rate_limited`, `invites_are_capped`,
  `pending_requests_per_recipient_are_capped`,
  `submit_needs_the_senders_token`. `5406ac9`: a blocked sender's resend
  gets 409 before the duplicate check, not 200 (from which it would learn
  the blocker's read state). `c05a7ba`: `rate_limited_maps_to_error`.
  test.sh green at `4c8c231`. V78: pending human run.

### D-0091 — brev-mail schema v5 and the order of `sync`

- **Date:** 2026-09-29
- **Decision:**
  - `SCHEMA_VERSION` 5; a v4 store opens as `Corrupt` and must be reset.
    `contacts.flags` is one sealed byte (`APPROVED_ME` 1, `VERIFIED` 2,
    `BLOCKED` 4, `BLOCK_UNTOLD` 8) with AD `contacts.flags` ‖ local id ‖ the
    row's `tag`, so a flags cell from before `accept_new_key` does not open
    under the new key (`b565da4`). A sealed `invites` table holds `s` ‖ UTC
    day for each open invite. Incoming requests and an opened invite live
    only in the session and are cleared on lock.
  - `sync` runs in this order: delete local invites past 7 days; tell the
    relay of each block it has not answered (D-0092); handle the relay's
    events (a stranger's request goes to the session; a contact's request is
    answered yes if the key is the same, and puts a changed key into
    `pending`; an *invited* event pins only on a tag match; *approved* sets
    `APPROVED_ME`), answered without the mutex; then the letters (poll,
    store, ack). It returns `SyncResult { letters, contacts_changed,
    requests }`.
  - Accepting a changed key clears the old key's flags; a block stays.
- **Reasoning:** Events come before letters so that a letter from an invitee
  or an approver arrives in the same sync that pins its sender; in the other
  order it would meet an unknown sender, which the stranger rule drops and
  acks. Sealed flags keep the file from showing who is approved, verified or
  blocked.
- **Verified:** `c05a7ba`: `schema_v5`, `v4_store_is_refused`,
  `flags_and_invites_are_sealed`, `expired_local_invites_are_deleted`,
  `session_invite_and_requests_cleared_on_lock`,
  `events_are_processed_once`, `invite_calls_carry_no_content`,
  `invite_makes_both_approved_and_verified` (letters both ways); `b565da4`:
  `key_change_through_a_request` writes the old flags cell back and gets
  `Crypto`. test.sh green at `4c8c231`. Found while writing this entry:
  `tools/verify/padcheck.swift` still requires `user_version` 4 and does not
  check `contacts.flags` or `invites.body`, and V18 still names schema v4,
  so V18 fails as written on a v5 store until both are updated. V18: pending
  human run.

### D-0092 — *Blokker* (owner answer 6)

- **Date:** 2026-09-28 (relay), 2026-09-29 (app)
- **Decision:** One click in the contact header (a `HumanButton`, no Touch
  ID). `block_contact` first seals `BLOCKED | BLOCK_UNTOLD` into the
  contact's flags and forgets any send ticket, then calls `/v1/block`
  (prefix ‖ peer id). The relay sets `links(me, them)` declined, drops
  pending events about them, and drops the blocker's own request waiting at
  them (its answer would put an *approved* event in the blocker's queue).
  `BLOCK_UNTOLD` is cleared when the relay answers 204 or 404; until then
  each sync tells the relay again first, without the mutex (`4c8c231`). A
  blocked contact cannot be written to (`NotApproved` at the seal, *Nytt
  brev* off), its events are declined, and its letters get 409 at the relay.
  A block survives `accept_new_key`; the user lifts it by sending the peer a
  request. Residual: another invite code of the blocker's that the peer
  holds overrides the relay link when redeemed; the sealed local flag still
  keeps the peer out.
- **Reasoning:** Without it an approval, or a stolen invite code (a bearer
  secret that sits on the pasteboard), could not be undone in Phase 4
  (design Q6). The retry through sync means a relay that was down, a 4xx or
  a lock cannot leave the link approved.
- **Verified:** `c93850e`, `5406ac9`: `blokker_stops_letters_and_requests`
  (a letter stored before the block, sent again, gets 409). `c05a7ba`,
  `b565da4`, `4c8c231`: `blokker_blocks_sending_and_receiving` (a ticket
  from before the block is forgotten; one set after it is refused at the
  seal), `blokker_holds_through_a_key_change`,
  `a_blocked_peer_cannot_reach_the_blockers_queue`, and
  `a_block_the_relay_missed_is_told_by_the_next_sync`, which fails without
  the retry and without the clear. Harness case 9: after the block neither
  side can send. test.sh green at `4c8c231`. V81: pending human run.

### D-0093 — Phase 4 FFI additions

- **Date:** 2026-09-29
- **Decision:** `BrevError` gains `NotApproved`, `RateLimited`,
  `InviteInvalid` and `InviteMismatch`, appended after `Environment` so no
  index moves (D-0067's practice). `Limits.max_invite` (96). `ContactRow`
  and `ContactInfo` gain `waiting`, `verified` and `blocked`. New records
  `RequestRow` (peer id, address as `OpenText`, code), `InviteInfo` (root
  flag, address, code) and `SyncResult`. New calls `create_invite`,
  `open_invite(code, code_len)` (copies the code out before its request,
  like `add_contact`), `redeem_invite`, `requests` (no I/O),
  `answer_request(peer, approve)` and `block_contact`; `register(signature,
  attestation)` and `sync()` changed. Codes cross as bytes and addresses as
  `OpenText`, never `String`. In Swift, `Session` keeps codes in
  `SecretBytes` and wipes the FFI copies.
- **Reasoning:** CLAUDE.md §6: a minimal, opaque surface. D-0038's rules for
  content also hold for contact data (D-0081).
- **Verified:** `c05a7ba`: `scripts/ffi-surface.txt` updated. `8ac082e`: the
  Swift callers; test.sh green, including the surface check. `4c97502`: case
  9 scans for the invite secret's 16 raw bytes, and fails with
  `Opened.secret` as a plain array or with a lock that does not clear the
  opened invite.

### D-0094 — The pasteboard, on the contact screen only

- **Date:** 2026-09-29
- **Decision:**
  - `UI/ContactPasteboard.swift` is the only pasteboard user besides
    OpaqueView's Services override. Two writes, from *Kopier adressen min*
    (the bytes of the own address) and *Kopier koden* (the bytes
    `create_invite` returned): `prepareForNewContents(with:
    .currentHostOnly)`, then the `org.nspasteboard.ConcealedType` and
    `TransientType` markers, then `.string`; the change count is kept.
  - Self-clear 60 s after the write and when Brev quits, and only if the
    change count is still Brev's; not at a lock (the owner's decision,
    2026-09-29).
  - One read, for ⌘V in `ContactField` only: at most 256 bytes into a
    `SecretBytes`, through the contact charset filter into the field's
    `EditModel`, never a `String`, drawn only in the protected layer.
  - Spike P1, variant (a): ⌘V is handled in `keyDown` (hardware key-downs
    only, no repeat, no ⇧, ⌥ or ⌃). Variant (b), a «Rediger» › «Lim inn»
    menu with a `paste:` action, is kept behind the compilation condition
    `BREV_PASTE_MENU`, off.
  - Letter and compose views stay without a pasteboard. `pasteboardDisabled`
    in the class-A report keeps its meaning: no responder takes copy, cut or
    paste at *Send*.
- **Reasoning:** D-0031 and CLAUDE.md §5 Phase 4: copy and paste of
  addresses and codes only on the contact screen, never near content (§1.3).
  The markers go first because only the clear moves the change count, so the
  text is never there without them; host-only because Universal Clipboard
  would offer a code to the owner's other devices (`4c8c231`). The owner
  chose not to clear at a lock because Brev locks when another app becomes
  active, which would clear the code before it could be pasted there.
- **Verified:** `cb3af17`, `4c8c231`: test.sh's pasteboard greps (with
  controls) and `allowed-apis.txt`'s two new lines; harness case 2 (the
  paste rule); the view host's `--contacts` run (copy, self-clear on a named
  pasteboard, a later copy by another app kept, refused pastes, the markers
  present when the text is set, host-only; each half of the review fix
  reverted fails two checks) PASS. P1 on the real pasteboard (V72: whether
  ⌘V raises a system alert) and V73: pending human run.

### D-0095 — App Attest is a stub

- **Date:** 2026-09-28
- **Decision:** brev-relay's feature `app-attest` (off by default) adds
  `AttestVerifier` in `gates.rs` with `DevAttest`, which accepts only the
  16-byte marker `BREV-DEV-ATTEST1`; with the feature on, a missing or
  failing attestation gives 428 before any read, and with it off the field
  is parsed (at most 8 192 bytes) and ignored. The attested data is the
  registration digest, so a real attestation would bind this key, address,
  token and invite. Swift has `Attestor` and `NoAttestor` (empty): no
  `DCAppAttestService` call and no entitlement. Later, for the owner: a real
  verifier needs CBOR and X.509 crates outside CLAUDE.md §4, must accept
  both App IDs or drop Brev B from real builds, and depends on which App
  Attest environment a Developer ID build gets.
- **Reasoning:** `DCAppAttestService.isSupported` is false without the
  entitlement, and `attestKey` talks to Apple, off loopback (design §0). An
  attestation at registration would prove the app genuine once, not that its
  defences are on, so CLAUDE.md §2's class-A line stays as it is (D-0068).
- **Verified:** `c93850e`: `attestation_gate` (design §8, relay test 11);
  the relay tests pass with and without the feature. `8ac082e`: `NoAttestor`
  in `Session.register`; test.sh green.

### D-0096 — `IdentityVerifier` and the BankID / ID-porten task

- **Date:** 2026-09-28
- **Decision:** `gates.rs` has `IdentityVerifier` with `DevVerifier` (always
  yes), asked at registration with empty evidence; a no gives 428 and writes
  nothing. The real integration is documented, not built (design §7.3): the
  operator runs an ID-porten/BankID web login outside Brev that hands out a
  one-time text code, pasted like an invite (no URL scheme, §1.4);
  registration v3 would carry it, and the relay would keep only
  SHA-256(pairwise `sub` ‖ relay salt): one person, one identity, at the
  price of linking each identity to a real person.
- **Reasoning:** CLAUDE.md §5 Phase 4 asks for the interface, a dev stub and
  a documented integration. Until then any build registers and one person
  can hold several identities, limited by invites (`docs/SECURITY.md` §7
  item 4).
- **Verified:** `c93850e`: `identity_verifier_is_consulted` (a refusing
  verifier gives 428 and nothing is written).

### D-0097 — Phase 4 review record

- **Date:** 2026-09-29
- **Decision:** What the reviews changed:
  - The design critic's 11 findings, all confirmed and applied (design §12):
    a daily cap on invites made and a cap on pending requests per recipient;
    the relay sees `a`, not `s`, and the inviter checks the invitee's tag;
    `add_contact` always requests; uniform 202 answers; *invited* and
    *approved* events first; the sender's token on submit; no directory
    probe at registration; `open_invite` on an existing contact; the 8 KiB
    attestation cap; V80 as a hex byte scan; the design's base commit, both
    App IDs and the pasteboard exposure.
  - The package reviews: the invite tag binds the invitee's address
    (`bd4c1fc`); a blocked sender's resend gets 409 before the duplicate
    check (`5406ac9`); `contacts.flags` bound to the pinned key's tag, and
    the Blokker and root-form invite checks pinned by tests (`b565da4`);
    case 9 scans for the invite secret's raw bytes with an opened invite
    held over the lock (`4c97502`); Blokker retried by sync, the
    pasteboard's markers first and host-only, the address page's step 2 in
    the lock probe (`4c8c231`).
  - Phase 4's VERIFY results (V71 to V81 and the rewritten rows) are not
    recorded here; they need the human run and go in a later entry.
- **Reasoning:** CLAUDE.md §1 "ALWAYS": a reviewer finds here what changed
  and why, and each package fix came with a check that fails without it.
- **Verified:** Each review commit above records a mutation or a revert that
  fails its new check. test.sh green and the view host's `--contacts --hold
  1` PASS at `4c8c231`. The human rows: pending human run.

---

## Phase 5 — the items that need no human (2026-09-29)

### D-0098 — cargo-deny policy and a CI workflow file

- **Date:** 2026-09-29
- **Decision:** `core/deny.toml` checks the graph with every feature on.
  Advisories: vulnerabilities, unmaintained and unsound crates anywhere in
  the graph, and yanked versions all fail. Licences: only those `Cargo.lock`
  needs today (Apache-2.0, BSD-3-Clause, MIT, MPL-2.0, Unicode-3.0, read
  from `cargo deny list -l license`); a new one needs the owner. Bans:
  multiple versions warn (syn 2 and 3 today); wildcards fail, except the
  workspace's own path dependencies. Sources: crates.io only, no git.
  `scripts/test.sh` runs `cargo deny check` after `cargo audit` and skips it
  loudly if cargo-deny is missing. `.github/workflows/ci.yml` runs on
  `ubuntu-latest` with Rust 1.91.1: fmt, clippy with default and with all
  features (`-D warnings`), `cargo test --no-default-features`, `cargo
  audit` and `cargo deny check`. The Swift, Xcode, harness and relay steps
  stay on the Mac.
- **Reasoning:** CLAUDE.md §4 (tooling) and §5 Phase 5. `cargo audit` covers
  only advisories; the policy also makes a new licence, registry or git
  source fail. CI checks the Rust side on a machine that is not the
  developer's Mac.
- **Verified:** `8378819` records the policy and the workflow file; its
  message records no `cargo deny check` result. The workflow has never run:
  nothing is pushed, so the Linux run is pending (it needs the owner to
  push).

### D-0099 — Swift and C warnings are errors

- **Date:** 2026-09-29
- **Decision:** `app/project.yml` sets `SWIFT_TREAT_WARNINGS_AS_ERRORS` and
  `GCC_TREAT_WARNINGS_AS_ERRORS` to YES in the Brev target's base settings,
  so for Debug, Release and Verify. Every build `scripts/test.sh` runs does
  the same: `swiftc -warnings-as-errors` for the harness, the lock probe, P1
  variant (b), the view host and the `tools/verify` type-checks, and `clang
  -Werror` for `scan.c`. One exception: `tools/verify/capture-probe.swift`
  keeps `-suppress-warnings`, for that file only. It calls the capture APIs
  that macOS 14 deprecates on purpose (V7), Swift 6.0 (Xcode 16.2, the
  stated minimum) has no switch per warning group, and a protocol-witness
  shim cannot call its script-mode functions.
- **Reasoning:** CLAUDE.md §5 Phase 5. A warning in security code (an unused
  result, a deprecated call) should stop the build instead of scrolling
  past. The probe is a verification tool and is never linked into Brev.app.
- **Verified:** `807d99e`: no source had a warning when the settings were
  turned on.

### D-0100 — Swift memory review

- **Date:** 2026-09-29
- **Decision:** `docs/SWIFT_MEMORY_REVIEW.md` lists every place Swift holds
  content, contact data or key material, over `app/Sources` and the patched
  bindings: the type, the owner, the wipe point and the check. No code gap
  was found: each such value is in a `SecretBytes` or `SecretText` (or, for
  one call, a no-copy view of one, a `CFData` wiped in place or an FFI
  `Data` wiped in place), never a `String`, `[UInt8]` or `NSString`. Three
  coverage gaps were closed: harness case 3 wraps the DEK in-process and
  scans after onboarding's `Enclave.wrap`; case 9 scans for an address
  (UTF-16) and an identity code while held and after the wipe and the lock;
  the lock probe checks that a lock zeroes the compose sheet's draft and its
  copy of the recipient's name. Not covered by a heap scan: the AppKit
  holders (the lock probe checks those), single keystrokes, and Swift's own
  stack frames.
- **Reasoning:** CLAUDE.md §5 Phase 5: find every place plaintext exists in
  Swift and make sure it is a zeroed buffer, never a `String` that lingers.
  The rules are D-0044's.
- **Verified:** `6e7f4a5`: each new check has a positive control and fails
  with its wipe left out (case 9 with `infoB` unwiped:
  `needles=[0,0,1,1,…]`, run by hand). The review asked for this entry.

### D-0101 — Reproducible build: one Mac, two folders, identical

- **Date:** 2026-09-29
- **Decision:**
  - `scripts/repro-build.sh` exports one commit twice with `git archive`
    into two temp folders, builds the Rust archive and an unsigned
    `xcodebuild archive` of Release in each (`CODE_SIGNING_ALLOWED=NO`,
    `ARCHS` from the Rust archive), and compares `libbrev_core.a` and the
    app executable after replacing its signature with an ad-hoc one and then
    removing it. `--against <Brev.app>` compares a downloaded build too.
  - Remapped: the build folder, `CARGO_HOME` and rustup's `rust-src` path
    (`--remap-path-prefix`, `-ffile-prefix-map`, Swift's `-file-prefix-map`,
    both spellings of `/tmp`). `ZERO_AR_DATE=1`; `SOURCE_DATE_EPOCH` is the
    commit's time. `archive` strips the installed product, so Xcode's debug
    map is not in the executable.
  - The release profile stays cargo's default: no `lto`, `strip` or
    `codegen-units` (D-0001 left them to this phase; the archive is
    identical without them). No `rust-toolchain.toml`; CI uses 1.91.1.
  - `scripts/build.sh` stays for development: its executables name the build
    folder. A release is built as `docs/DISTRIBUTION.md` §3 says, with the
    script's flags and folder layout.
- **Reasoning:** CLAUDE.md §5 Phase 5: a user can check that a download is
  what the published source builds. The signature is replaced before it is
  removed because `codesign --remove-signature` alone leaves `__LINKEDIT`'s
  `vmsize` sized for the old signature.
- **Verified:** `e68bac3`, `docs/REPRODUCIBLE_BUILD.md` §1: commit `6e7f4a5`
  built twice on this Mac (macOS 26.2, Xcode 26.2, rustc 1.91.1, XcodeGen
  2.46.0): `libbrev_core.a` and the executable identical (same LC_UUID), and
  neither names the build or home folder; the dSYM differs and is not
  compared. `--against` matched a copy re-signed ad hoc with the hardened
  runtime and the entitlements. Not checked: a second Mac, a real Developer
  ID signature, Intel, and a universal build (D-0004's universal build is
  still open).

### D-0102 — `docs/SECURITY.md` and `docs/DISTRIBUTION.md`

- **Date:** 2026-09-29
- **Decision:** `docs/SECURITY.md` is for outside reviewers: the promise
  (CLAUDE.md §1), the threat model by reference, the components and what
  Rust enforces versus what it takes from Swift, key management, what the
  relay sees, how to verify, the known gaps (§7: the human run pending, this
  Mac's signing key, the local relay, the self-reported class, the Phase 5
  items left, the design limits) and a placeholder for reporting.
  `docs/DISTRIBUTION.md` covers Developer ID signing with a Developer ID
  provisioning profile and the same keychain group `AV26DNQ5SC.no.brev.app`,
  the entitlement and hardened-runtime checks, a release built the way
  `scripts/repro-build.sh` builds and checked with `--against`, `notarytool`
  and stapling, and how a user checks a download with `codesign` and
  `spctl`.
- **Reasoning:** CLAUDE.md §5 Phase 5, and D-0033 item 5: Developer ID
  before Brev holds real letters. The gaps are listed, not left for a
  reviewer to find.
- **Verified:** `dffa394` ("documented, not run"); `f40794a` brought both in
  line with the Phase 5 state. No Developer ID build, notarization or
  `spctl` check has been made: pending the owner, who holds the Developer ID
  certificate. That a Developer ID build opens the keys a development build
  made is expected, not verified (`docs/DISTRIBUTION.md` §1).

### D-0103 — Corrections after the Phase 3–5 log: phase order, cargo-deny result, padcheck for schema v5

- **Date:** 2026-09-29
- **Decision:**
  1. **Phase order (corrects D-0085).** The owner wrote "CONTINUE" on
     2026-09-29 at about 00:50, after the Phase 4 WP0–WP2 report that said
     the rest waited for the Phase 3 run, and at about 01:00 asked for "as
     much work as possible" overnight. Phase 4 WP3–WP5 and the no-human
     Phase 5 items were built on that instruction, on `claude/phase4`,
     leaving `/Users/andypandy/BREV` on the Phase 3 code for the owner's
     session. The human DoD runs of Phases 3 and 4 are still open.
  2. **cargo-deny result (D-0098 did not record one).** `cargo deny check`
     in `core/` at this commit's parent: advisories ok, bans ok, licenses
     ok, sources ok; exit 0; one warning, `syn` in two versions (allowed as
     a warning by `deny.toml`).
  3. **padcheck and V18 for schema v5 (noted in D-0091).**
     `tools/verify/padcheck.swift` now requires `user_version` 5 and also
     checks `contacts.flags` and `invites.body`; V18's text says v5. The
     `scripts/build.sh` comment no longer claims the first `--instance b`
     build registers an App ID (D-0084).
- **Verified:** `xcrun swiftc -typecheck -warnings-as-errors` on
  `padcheck.swift` passes; `bash -n scripts/build.sh` passes; the
  `cargo deny check` output is as quoted. `scripts/test.sh` was not run
  (Mac on low battery); it runs padcheck only through the type-check.

### D-0104 — Owner run, round 1: real Touch ID, two instances, letters both ways, Blokker

- **Date:** 2026-09-29
- **Decision:** Record the first human run on the newest code (`1d368cb`)
  and what it settles.
  1. **U4 settled (open decision 2 in USER_SESSION.md):** the Touch ID
     panel makes Brev resign active during the unlock's ECIES unwrap; the
     in-flight exception keeps Brev from locking, and the unlock completes.
     The signing prompt (registration) did not resign Brev active. The
     rule stays as built; `LockState.signPanelTakesActivation` stays false.
  2. **P1 / V72 settled:** ⌘V of an invite code raised no macOS
     pasteboard alert, so the primary paste variant (a) stays and the
     fallback (b), with its missing human-input gate, is not needed.
- **Verified:** docs/VERIFY-RESULTS.md, "Owner run, round 1": V27, V55,
  V56, V57, V58, V59, V71, V72, V81 pass. With the relay trace and
  `relay.db` read by Claude: both registrations 201, two envelopes 202,
  0 plaintext marker hits in UTF-8 or UTF-16 with the address control found,
  0 envelopes waiting after both syncs, `/v1/block` 204 and the blocked
  send refused as NotApproved with no Touch ID. Still open for Phase 3's
  definition of done: V60 (key change); for Phase 4's: V77 and the relay's
  rate-limit and delivery rows are machine-tested only.

### D-0105 — Phase 3's definition of done is met on the owner's Mac

- **Date:** 2026-09-29
- **Decision:** Phase 3 (real transport) is closed for its definition of
  done in CLAUDE.md §5: two app instances with separate data dirs
  exchanged letters through the local relay (V57), the relay's database
  held no plaintext (V58, also covered by `relay_file_holds_no_plaintext`),
  and a changed key for a pinned contact triggered the warning and blocked
  sending (V60). Phase 3's remaining VERIFY rows are in round 2.
- **Verified:** docs/VERIFY-RESULTS.md, "Owner run, round 1" (V57, V58)
  and the V60 row added to it: KeyChanged at Send with no Touch ID and an
  unchanged envelope count, the warning with both codes, then after
  acceptance and Brev B re-adding Brev a letter delivered and deleted.

### D-0106 — Owner skips the edge-case round (round 2); development continues

- **Date:** 2026-09-29
- **Decision:** After round 1 and V60 passed, the owner chose not to run
  round 2 of `docs/USER_SESSION.md` and to continue development, "knowing
  that such edge cases are not tested". The untested rows are listed in
  `docs/SECURITY.md` §7 item 1; `docs/USER_SESSION.md` keeps them for a
  later run. Phase 2's and Phase 4's definitions of done ("checklist
  passes") are therefore met only for the machine-run rows and the round-1
  rows; Phase 3's is met (D-0105).
- **Reasoning:** Round 1 exercised the core promise end to end on real
  hardware; round 2 (about 3 hours) probes edge cases and destructive
  paths. The owner prefers to move on and accept that these are covered by
  machine tests and design only.
- **Verified:** Not applicable (a decision not to run tests). The list of
  untested rows was checked against `docs/VERIFY-RESULTS.md`.

### D-0107 — Authorship attestation ("Hand"): owner decisions before the spike

- **Date:** 2026-09-29
- **Decision:** The owner asked for Phase 3b, authorship attestation
  ("Hand"): each letter carries a signed, App-Attest-backed token proving
  it was written in Brev, with Touch ID at send and a measured environment,
  and the recipient verifies it. Before any code the owner approved:
  1. New crates: `ciborium` (CBOR) and `x509-cert` with `der`/`spki`
     (RustCrypto) for the token and App Attest verification; added to
     CLAUDE.md §4. The content hash is SHA-256 (already approved), not
     BLAKE3.
  2. Hand lives in a new crate `brev-hand`, beside `brev-vault`, so the
     vault's dependency whitelist stays as it is.
  3. An environment fact the app cannot read (for example because the
     sandbox blocks it) gives class B, never A.
  4. The inbox badge says «Skrevet i Brev · klasse A», not «Menneske ·
     verifisert»: on a Mac holding the team signing key a modified Brev can
     also be attested, so the badge must not claim more than is proven.
  Hand is built on top of the existing relay and Phase 4 code (the spec's
  "before the relay and Phase 4" no longer applies; both are built).
- **Reasoning:** CBOR and X.509 parsing of attacker-supplied bytes should
  use maintained libraries, not hand-written parsers. A separate crate
  keeps the vault small and its whitelist meaningful.
- **Verified:** decision only. First step: a spike on App Attest support
  and on which environment facts a sandboxed, team-signed app can read.

### D-0108 — Hand on Mac: class A without App Attest; the spike's results

- **Date:** 2026-09-29
- **Decision:** App Attest is not available to native Mac apps, so on Mac
  class A does not require it. Class A needs the Secure Enclave signature,
  one fresh Touch ID for the letter, and every measured fact good
  (docs/AUTHORSHIP.md §4). The token then carries no `"app-attest"` claim,
  and the detail view says «Appen er ikke bekreftet av Apple (støttes ikke
  på Mac)». A missing attestation never raises a class. An attestation that
  is present must verify, and until a verifier exists it fails. The inbox
  badge stays «Skrevet i Brev · klasse A» (D-0107 item 4). CLAUDE.md §2's
  note that the class catches Swift bugs, not attackers, stays true on Mac.
- **Spike (macOS 26.2 25C56, Xcode 26.2, team AV26DNQ5SC; sources and
  Apple's root in `tools/verify/spikes/hand/`):**
  - `DCAppAttestService.isSupported` was false in every build, with and
    without a profile. devicecheckd logs that the `os_feature` flag
    `DeviceCheck/mac` is off. Xcode's copy of the portal capability list
    offers `APP_ATTEST` for iOS, tvOS and visionOS only.
  - `xcodebuild -allowProvisioningUpdates` dropped the App Attest
    entitlement without a warning. No account or profile changed. No test
    vectors can come from this Mac.
  - Apple App Attestation Root CA (P-384, valid 2020–2045), from
    apple.com/certificateauthority: SHA-256 of the DER is
    `1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932`.
    Checking its chain will need `p384`, which is not approved yet.
  - A sandboxed, team-signed app can read every fact without a prompt:
    - admin group: `mbr_check_membership`;
    - SIP: `csr_get_active_config` (via dlsym), and `csrutil status` as a
      child process;
    - processes: `sysctl KERN_PROC_ALL` (`proc_listallpids` is blocked);
    - windows: `CGWindowListCopyWindowInfo` gives owners without Screen
      Recording permission, but not titles;
    - sudo: a live `sudo` is visible, a cached sudo login is not.
- **Reasoning:** Requiring App Attest would make every Mac letter class B
  until Apple changes the OS. The honest line in the detail view keeps the
  badge from claiming more than is proven.
- **Verified:** Spike runs 1–3; the logs are in the spike folder's history
  (scratchpad) and the facts are summarised above.

### D-0109 — Hand: one Touch ID per letter; sudo and SIP lock Brev; the rest are numbers

- **Date:** 2026-09-29
- **Decision:** The owner answered on docs/AUTHORSHIP.md:
  1. One Touch ID per letter covers both signatures (token and envelope),
     with one fresh `LAContext` (§3.2).
  2. Other apps' windows, known AI programs and admin membership are
     shown to the recipient as numbers. They do not lower the class and
     do not lock Brev.
  3. Brev locks while a `sudo` or `su` process runs or SIP is off, and
     refuses to unlock until neither holds (§4.3). The adapter samples
     every 2 s while Brev is unlocked. An unreadable fact does not lock;
     it gives class B.
  4. Go for the work order in §9.
- **Reasoning:** Locking is a clear rule the user can see and fix. A
  lowered class only shows up for the recipient. Agents and windows are
  too weak, or too common, to lock on: most Mac users are admins, and the
  owner runs AI tools all day.
- **Verified:** decision only.

### D-0110 — Hand step 2: envelope v2 with the token, `received_at`, the facts-not-flags FFI, store v6

- **Date:** 2026-09-29
- **Decision:** Step 2 of docs/AUTHORSHIP.md §9, and the Rust half of step
  4, as the owner's brief for this step fixed them (Rust only; the Swift
  adapter is step 3, and the app build is red until it lands):
  1. **Envelope.** `brev_proto::PROTOCOL_VERSION` is 2; nothing else in the
     envelope changed. The payload inside the AEAD is `letter length (u32
     BE) || letter || token length (u16 BE) || token`, `letter` being the old
     payload (`encode_payload`), parsed strictly (the lengths make up the
     whole unpadded payload; the token is at most `MAX_TOKEN`, 2 KiB), padded
     as before. The relay and the app refuse version 1. A short letter now
     fills the 1 KiB bucket.
  2. **`received_at`.** The relay's file is version 3: `envelopes.received_at`,
     its own clock in Unix seconds when it first stores an envelope; a
     resubmit keeps it, the ack deletes it. The inbox answer is `count (u16
     BE) || per envelope: received_at (u64 BE) || length (u32 BE) || wire`.
     This is the only time of day the relay keeps (brev-relay's doc says
     so). `Transport::poll` gives `(received_at, Envelope)`; `MockTransport`
     stamps what it gets, with the system clock or `set_time`.
  3. **FFI (facts, not flags).** `report_environment`, `EnvironmentReport`,
     `ReportField` and the session's stored report are gone. New:
     `observe(sample) -> [LockCause]`, `compose_started(design, admin,
     key_origin)`, `compose_closed()`, `synthetic_dropped()`,
     `paste_accepted()`, `attach_token_signature(der) -> envelope digest`,
     `letter_proof(message) -> Proof?`; `confirm_active`, `prepare_send` and
     `sign_request` take a `Sample`. Records `Sample`, `Window`, `Design`,
     `Proof`; enum `LockCause` (`Sudo`, `SipOff`; not `LockReason`, which
     the app already defines). `BrevError::Environment` now carries the
     token's fact names (`Vec<String>`: `"key"`, `"max-gap"`, `"sip"`, …)
     instead of `ReportField`s, since neither the lock reasons nor the new
     facts fit that enum. The compose session keeps a brev-hand `FactLog`
     on an `Instant` taken at `compose_started` (ms); `own_pid` is
     `std::process::id()`.
  4. **Send.** `prepare_send` computes the class of the log's facts with its
     sample as an early exit; `sign_request` freezes them with its sample,
     refuses below the threshold (unchanged, `allow-software-keys` as
     before), and otherwise keeps the letter's plaintext (a vault
     `Plaintext` in a `Draft`) and the claims, and returns the token digest.
     `attach_token_signature` checks the signature with the own key over
     `token::signed_bytes`, assembles the token, seals the letter with it and
     wipes the plaintext; a bad signature forgets the letter and the ticket
     (`Signing`). `cancel_send` and every lock wipe the plaintext, the
     sealed letter, the ticket and the compose session. The own copy keeps
     `env_class`. `Core::seal_letter` now seals a `Draft` with a token.
  5. **Receive, store v6.** After the envelope's checks and the AEAD,
     `brev_hand::verify(letter, token, pinned signing key, received_at)`
     runs, and `Verification::encode` (a byte of per-check pass bits, then
     the token) is sealed in the new column `messages.proof` (empty for a
     sent letter), in the same transaction. A failing token does not refuse
     the letter. Replay stays the stored message id (`Duplicate`), which
     replaces the nonce cache §9 still mentions (§6 step 5). padcheck and
     V18 check `messages.proof` and `user_version` 6.
  6. **Badge.** `letter_proof` decodes the stored result: `verified`,
     `class` (1/2/3 when verified), `failed` (the fixed check names
     `"token"`, `"signature"`, `"app-attest"`, `"content"`, `"iat"`, and
     for the class check the facts), `attested` (always false), and the
     §4.2 numbers plus `sip` and `sudo` as options. `None` for a sent
     letter. `scripts/ffi-surface.txt` pins the new surface.
- **Choices the brief left open, taken the conservative way:**
  1. The samples handed over with `prepare_send` and `sign_request` follow
     the lock rule too (lock everything, `Environment` naming the facts),
     not only those of `observe` and `confirm_active` (§4.3 says "a
     sample").
  2. `Proof`'s numbers are given only for a verified token; a failed one
     shows no class and none of the sender's counts.
  3. `prepare_send` forgets a letter waiting for its token signature, and
     *Blokker* forgets one to the blocked contact, so the plaintext lives no
     longer than one send attempt.
  4. `Core::draft` checks the pinned bundle before the prompt, and
     `seal_letter` checks the key change and the block again after it.
  5. `Verification::decode` refuses stored bits the token contradicts (form
     or class), and `letter_proof` opens `messages.proof` under an AD that
     holds the direction before it answers `None` for a sent letter; either
     mismatch is `Corrupt`, never a guess.
  6. The new calls give `Locked` while locked or armed, `compose_closed`
     too.
- **Reasoning:** The token must be inside the ciphertext and cover the
  exact letter, so the letter is fixed (and held) between the two
  signatures of one Touch ID (D-0109 item 1). `received_at` is the only
  independent time the recipient has (§6 step 6). Passing raw observations
  and computing counts and class in Rust keeps the adapter from asserting
  a class (§3.1).
- **Verified:** `cargo fmt --check`; `cargo clippy --workspace
  --all-targets -D warnings`, with and without `--all-features`; `cargo test
  --workspace --no-default-features`: 237 tests pass (brev-hand 35,
  brev-mail unit 69 and integration 44, brev-proto 19, brev-relay 39,
  brev-vault 28, doc tests 3). New tests: the round trip A → B through
  `MockTransport` verified as class A with the counts A's app saw, a
  tampered token (signature, a token moved to another letter, a late
  `received_at`) stored as not verified with that check, replay
  `Duplicate`, a sudo sample locking with 0 live plaintexts, `confirm_active`
  with SIP off refused and locked, a 6 s gap refusing `sign_request` and
  clearing the pending letter, cancel and lock during the prompt, a wrong
  token signature, `received_at` kept on resubmit at the relay, the stored
  result's round trip. The bindings were generated from the release build
  into a scratch folder and patched by `scripts/patch-bindings.py`; their
  surface equals `scripts/ffi-surface.txt`, and the String checks of
  `scripts/test.sh` pass on them. `padcheck.swift` type-checks. cargo-deny
  bans, licenses and sources pass. Not run: `scripts/test.sh` (its Swift
  steps fail until step 3), the app, `app/Generated` (not touched).
