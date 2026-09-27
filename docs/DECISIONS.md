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
