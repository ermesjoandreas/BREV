#!/usr/bin/env bash
# Runs the local Brev relay (docs/PHASE4_DESIGN.md §4) on 127.0.0.1:8787,
# with its database in ~/Library/Application Support/brev-relay/relay.db
# (folder 0700, file 0600). It stores ciphertext and routing metadata, and
# the invite and approval graphs, pending requests and daily counts; no
# content. A Phase 3 relay file there is refused: move it away first (test
# letters only; no migration). Stop it with Ctrl-C.
#
# Usage: scripts/relay.sh [--trace] [--letters-per-day N] [--requests-per-day N]
#          [--invites-per-day N] [--open-invites N] [--pending-requests N]
#          [--invite-days N] [--phase3]
#   --trace   print one line per request to stdout: path and status
#   limits    per identity per UTC day 50 letters, 10 requests, 3 invites
#             made; 5 open invites; 16 pending requests per recipient;
#             invites live 7 days
#   --phase3  Phase 3's bodies without any Phase 4 check, for the Phase 3 app
#             until Phase 4 WP4 (takes no limits)
#
# Operator commands (the relay may be running):
#   print a root invite, the only way to bring in the first identity
#     core/target/release/brev-relay invite --db "$HOME/Library/Application Support/brev-relay/relay.db"
#   free an address, deleting its waiting letters, links, events, invites and counts
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
    --trace|--phase3) ;;
    --letters-per-day|--requests-per-day|--invites-per-day|--open-invites|--pending-requests|--invite-days)
      NEEDS="$arg" ;;
    -h|--help) sed -n '2,23p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
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
