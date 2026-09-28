#!/usr/bin/env bash
# Runs the local Brev relay (docs/PHASE3_DESIGN.md §4.5) on 127.0.0.1:8787,
# with its database in ~/Library/Application Support/brev-relay/relay.db
# (folder 0700, file 0600). It stores ciphertext and routing metadata only.
# Stop it with Ctrl-C.
#
# Usage: scripts/relay.sh [--trace]
#   --trace  print one line per request to stdout: path and status
#
# Operator command: free an address and delete the letters waiting for it
#   core/target/release/brev-relay release --db "$HOME/Library/Application Support/brev-relay/relay.db" <address>
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DB="$HOME/Library/Application Support/brev-relay/relay.db"

for arg in "$@"; do
  case "$arg" in
    --trace)   ;;
    -h|--help) sed -n '2,11p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)         echo "error: unknown argument '$arg' (accepted: --trace)" >&2; exit 2 ;;
  esac
done

if ! command -v cargo >/dev/null 2>&1; then
  echo "error: cargo not found. Install Rust with rustup: https://rustup.rs" >&2
  exit 1
fi

# --target-dir as in test.sh, so the binary is core/target/release/brev-relay
# (docs/VERIFY.md's $RELAY).
exec cargo run --release --manifest-path "$REPO_ROOT/core/Cargo.toml" \
  --target-dir "$REPO_ROOT/core/target" -p brev-relay -- \
  serve --db "$DB" --listen 127.0.0.1:8787 "$@"
