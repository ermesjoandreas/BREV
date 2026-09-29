# Brev — reproducible build

How to rebuild Brev from source and check that the result is the same, byte
for byte, as another build of the same commit. `CLAUDE.md` §5 Phase 5 asks
for this. The script is `scripts/repro-build.sh`.

## 1. What was checked, and the result

On 2026-09-29 the script built commit `6e7f4a5` twice on one Mac, each time
from a fresh `git archive` export in its own temp folder:

| | |
|---|---|
| Mac | Apple Silicon (arm64), macOS 26.2 (25C56) |
| Rust | rustc 1.91.1 (ed61e7d7e 2025-11-07), cargo 1.91.1 |
| Xcode | 26.2 (17C52), macOS 26.2 SDK (25C57) |
| XcodeGen | 2.46.0 |

| Output | Result |
|---|---|
| `libbrev_core.a` (the Rust archive the app links) | **identical** |
| `Brev.app/Contents/MacOS/Brev`, signature removed | **identical** (same LC_UUID too) |
| `Info.plist`, `PkgInfo`, `nb.lproj/Localizable.strings` | identical |
| the dSYM (`Brev.xcarchive/dSYMs`) | differs; not compared (§4) |

SHA-256 for commit `6e7f4a5` with the tools above:

    libbrev_core.a                                  5c243c2e11915e346393febf65aac48d94348073dcedb8c49c55962287289da4
    Brev executable (after §2's replace-and-remove) 5fae33e5cc78b39b159c64f1eb5aa8e5867cec1de790248f21df0b850ba87394

Neither output names the build folder or the home folder: the script
counts such strings and found none.

This is **one Mac, one toolchain, two folders**. It shows that the build
does not depend on where the source sits or on the time of the build. It
has not been checked on a second Mac. A second Mac with the same Xcode,
Rust and architecture should give the same bytes (§4 lists what could
still differ), but that is expected, not shown.

## 2. How to rebuild and compare

You need an Apple Silicon Mac, the Xcode build, the Rust version and the
XcodeGen version listed for the release you check (for the result above:
Xcode 26.2 (17C52), rustc 1.91.1, XcodeGen 2.46.0). Another Xcode or Rust
version gives other bytes; that says nothing about the source.

1. Get the source and the commit the release was built from:

       git clone <Brev repository> brev && cd brev
       git checkout <release commit>

2. Install the Rust version and check the tools:

       rustup toolchain install 1.91.1 && rustup default 1.91.1
       xcodebuild -version && xcodegen --version

3. Rebuild twice and compare, and compare with the app you downloaded:

       scripts/repro-build.sh --against /Applications/Brev.app

   The first run downloads the crates in `core/Cargo.lock` (network). It
   builds unsigned: it needs no Apple account, no keychain and no Touch ID.

4. Read the last line. `REPRODUCIBLE: ... and to /Applications/Brev.app`
   means the executable in your Brev.app is the one this source builds.
   On any `DIFFERENT`, the script keeps both builds and prints where.

Without `--against`, the script only checks that two builds on your Mac
agree. The hashes it prints for `libbrev_core.a` and the executable can
also be compared with hashes the release publishes.

### Doing the comparison by hand

What the script does to each executable before it compares them:

    cp Brev.app/Contents/MacOS/Brev /tmp/Brev
    codesign --force --sign - /tmp/Brev      # replace the signature with an ad-hoc one
    codesign --remove-signature /tmp/Brev    # then remove it
    shasum -a 256 /tmp/Brev

`codesign --remove-signature` alone is not enough. It leaves the
`__LINKEDIT` segment's `vmsize` as the removed signature needed it, so a
Developer ID signature and the linker's ad-hoc signature leave copies that
differ in that one field. Replacing either with the same ad-hoc signature
first removes the difference. Ad-hoc signing uses no key.

## 3. What the script does against each source of difference

| Source of difference | What the script does |
|---|---|
| Uncommitted or untracked files | Builds from `git archive <commit>`, never from the working tree. |
| The build folder's path (in panic messages, Swift `#file` strings, debug info) | Rust: `--remap-path-prefix=<folder>=/brev`. C in the crates (bundled SQLite): `-ffile-prefix-map`. Swift and clang in Xcode: `-file-prefix-map` / `-ffile-prefix-map`. |
| `/private/tmp` vs `/tmp` | Xcode standardizes `/private/tmp/x` to `/tmp/x`, cargo does not; the Xcode flags map both spellings. |
| The crate cache (`~/.cargo/registry/...`) | `--remap-path-prefix=<CARGO_HOME>=/cargo`. |
| rustup's `rust-src` component | With it installed, rustc names std's sources by their local path (`~/.rustup/...`) in std code inlined into Brev; without it, by `/rustc/<commit>/`. The script maps the first to the second, so both kinds of machines give the same bytes. In the first test run, without this, 89 strings in the executable named the home folder. |
| File times in archives and the debug map | `ZERO_AR_DATE=1` for `ar`, `libtool` and `ld`. |
| The time of the build | `SOURCE_DATE_EPOCH` = the commit's time (for clang's `__DATE__`/`__TIME__`; nothing in Brev uses them today). |
| Xcode's debug map (object file paths, and the Swift module path that Xcode passes to the linker with `-add_ast_path`, which no prefix map reaches) | The app is built with `xcodebuild archive`, as `docs/DISTRIBUTION.md` §3 does. Release strips the installed product (`STRIP_INSTALLED_PRODUCT`), so the debug map is not in the executable. A plain `xcodebuild build` keeps it, and its executables differ between folders (tested: one byte, the folder name, in the Swift module path). |
| The code signature | Built with `CODE_SIGNING_ALLOWED=NO`; compared after the ad-hoc replace-and-remove in §2. |
| Architecture | `ARCHS` = the Rust archive's architecture (`archive` ignores `ONLY_ACTIVE_ARCH`). |

The release profile in `core/Cargo.toml` is unchanged (cargo's default).
The script sets no `lto`, `strip` or `codegen-units`; with them at their
defaults the archive came out identical anyway.

## 4. What is not reproduced, or not checked

- **The dSYM differs** between the two folders: it keeps the absolute paths
  of the object files. It is for crash symbolication and does not ship
  inside Brev.app. Not compared.
- **The `.xcarchive`'s own `Info.plist`** holds its creation date. Not
  compared; only `Products/Applications/Brev.app` is.
- **Another Mac is not tested.** The app's `Info.plist` records the build
  machine (`BuildMachineOSBuild`, `DTXcodeBuild`, `DTSDKBuild`,
  `DTPlatformBuild`). The same Xcode on another macOS build gives another
  `BuildMachineOSBuild`, so the `Info.plist` can differ while the
  executable matches. The executable itself may still pick up something
  machine-specific that one Mac cannot show.
- **A Developer ID-signed build is not tested.** `--against` was tried on a
  copy of the rebuild signed again ad hoc with the hardened runtime, the
  entitlements and the identifier `no.brev.app` (another signature, same
  code); that matched. A real Developer ID signature has not been made
  yet (`docs/DISTRIBUTION.md`).
- **Intel Macs and universal builds.** Only arm64 was built. The app
  still links a one-architecture Rust archive.

## 5. For the owner: making a release verifiable

A user can only match a release whose executable was built the way this
script builds. `scripts/build.sh` does not pass the path mappings above, so
its executables name the build folder and will not match a user's rebuild;
it is for development only. `docs/DISTRIBUTION.md` §3 builds the release
with the script's `RUSTFLAGS`, `CFLAGS`, `OTHER_SWIFT_FLAGS`,
`OTHER_CFLAGS`, `ARCHS=arm64` and folder layout, then checks the signed app
with `scripts/repro-build.sh --against`.

Publish with each release: the commit, the Xcode build, the
Rust version, the XcodeGen version, and the SHA-256 of the executable after
the replace-and-remove step in §2.

The repository does not pin the Rust version (no `rust-toolchain.toml`);
CI uses 1.91.1 (`.github/workflows/ci.yml`).
