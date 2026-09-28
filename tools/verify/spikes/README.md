# Spike sources (Phase 2 and 3)

The sources of the Phase 2 spikes, copied from the session scratchpad
(`/private/tmp/claude-503/…/scratchpad/p2/`, which is volatile) so the GUI-spike
facts behind docs/VERIFY.md ("per D-0060") and the pending human steps can be
rebuilt. Sources only: no build output, logs or screenshots. Nothing here is
built by `tools/verify/build.sh` or linked into Brev.app, except InputLab
(`input/src/lab.swift`), which `build.sh` builds as `$T/InputLab.app`.

| Folder | Spike | Results | State |
|---|---|---|---|
| `capture/` | U1, screen capture (`v2`, with WP11's re-run changes: `--dy`, `APPARGS`, kept crops) | D-0034 | human steps in `USER_STEPS.md` pending |
| `input/` | U2, input: InputLab, poster, axdump, keylisten, the scanner | GUI-spike facts (D-0060) | human steps 1 and 2 pending |
| `lock/` | U4, lock triggers: LockLab, LockOther | D-0060 | human steps pending; its Touch ID part tests the CryptoKit + HPKE path that D-0035 replaced |
| `launch/` | L and M, launch hygiene and `MallocScribble` | D-0060 | human steps (Finder, Dock, typing) pending |
| `enclave/` | the CryptoKit Secure Enclave keys + HPKE, and the owner's Touch ID test | D-0032, D-0033 | superseded by D-0035 (keychain keys, ECIES) |
| `ffi/` | FFI copies, zeroing allocator, binding patches, Core Text | D-0032 | done; `core/` is the spike's modified Phase 1 core the harness links |
| `keychain/` | the team-signed keychain probe | D-0035 | done |
| `p3/` | Phase 3: Security.framework P-256 signatures verified with p256, and the four vectors brev-proto's tests commit (its own README; copied from `…/scratchpad/p3/`) | docs/PHASE3_DESIGN.md §0 | done |

The anchor spike (A) is not kept: the anchor it tested (WP9) is obsolete with
D-0035. The `USER_STEPS.md` files name the scratchpad paths they were written
in; the same scripts run from here. Each spike's `build.sh` or `run.sh`
writes `build/`, `bin/` and `out/` next to itself, and `ffi/core` writes
`target/`; `.gitignore` keeps those out of the repo. Where a skeptic disputed
a spike's claim, the correction in the D-entry is what holds.
