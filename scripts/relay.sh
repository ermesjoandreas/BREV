#!/usr/bin/env bash
# Runs the local Brev relay (docs/PHASE4_DESIGN.md §4) on 127.0.0.1:8787,
# with its database in ~/Library/Application Support/brev-relay/relay.db
# (folder 0700, file 0600). It stores ciphertext and routing metadata, and
# the approval graph, pending requests and daily counts; no
# content. A Phase 3 relay file there is refused: move it away first (test
# letters only; no migration). Stop it with Ctrl-C.
#
# Usage: scripts/relay.sh [--trace] [--letters-per-day N] [--requests-per-day N]
#          [--pending-requests N]
#   --trace   print one line per request to stdout: path and status
#   limits    per identity per UTC day 50 letters and 10 requests; 16
#             pending requests per recipient
# Registration is open: anyone registers an address (D-0116).
#
# Operator command (the relay may be running):
#   free an address, deleting its waiting letters, links, events and counts
#     core/target/release/brev-relay release --db "$HOME/Library/Application Support/brev-relay/relay.db" <address>
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DB="$HOME/Library/Application Support/brev-relay/relay.db"

# The flags are checked here and passed through to `brev-relay serve`, which
# checks them again (a limit is a number).
NEEDS=""
for arg in "$@"; do
  if [[ -n "$NEEDS" ]]; then
    [[ "$arg" =~ ^[0-9]+$ ]] || { echo "error: $NEEDS needs a number" >&2; exit 2; }
    NEEDS=""
    continue
  fi
  case "$arg" in
    --trace) ;;
    --letters-per-day|--requests-per-day|--pending-requests)
      NEEDS="$arg" ;;
    -h|--help) sed -n '2,18p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)         echo "error: unknown argument '$arg' (see --help)" >&2; exit 2 ;;
  esac
done
if [[ -n "$NEEDS" ]]; then
  echo "error: $NEEDS needs a number" >&2
  exit 2
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "error: cargo not found. Install Rust with rustup: https://rustup.rs" >&2
  exit 1
fi

# --target-dir as in test.sh, so the binary is core/target/release/brev-relay
# (docs/VERIFY.md's $RELAY).
exec cargo run --release --manifest-path "$REPO_ROOT/core/Cargo.toml" \
  --target-dir "$REPO_ROOT/core/target" -p brev-relay -- \
  serve --db "$DB" --listen 127.0.0.1:8787 "$@"
