#!/usr/bin/env bash
# brev-vault's dependency whitelist (docs/VAULT_SPLIT_PLAN.md §4). The vault
# holds the store, the DEK and the zeroing allocator, and stays free of the
# network, UniFFI and the mail code. With every feature on:
#   1. each direct normal dependency is one of ALLOWED;
#   2. the whole normal graph holds none of FORBIDDEN.
# The control: the same check on brev-mail must fail and name reqwest, so it
# cannot pass by reading nothing. scripts/test.sh runs this.
#
# Usage: scripts/check-vault-deps.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$REPO_ROOT/core/Cargo.toml"
ALLOWED=(chacha20poly1305 poly1305 rand rusqlite thiserror zeroize zeroizing-alloc)
FORBIDDEN=(reqwest hyper tokio axum p256 x25519-dalek curve25519-dalek hkdf serde uniffi brev-proto)

# violations <package>: one line per dependency that breaks rule 1 or 2.
violations() {
  local pkg="$1" direct all name
  # The first line is the package itself.
  direct="$(cargo tree --manifest-path "$MANIFEST" -p "$pkg" --all-features -e normal --depth 1 \
    --prefix none -f '{p}' | tail -n +2)"
  all="$(cargo tree --manifest-path "$MANIFEST" -p "$pkg" --all-features -e normal --prefix none -f '{p}')"
  while read -r name _; do
    [[ -z "$name" ]] && continue
    if ! printf '%s\n' "${ALLOWED[@]}" | grep -qxF "$name"; then
      echo "  direct dependency not on the list: $name"
    fi
  done <<<"$direct"
  for name in "${FORBIDDEN[@]}"; do
    if grep -q "^$name v" <<<"$all"; then
      echo "  forbidden in the graph: $name"
    fi
  done
}

FOUND="$(violations brev-vault)"
if [[ -n "$FOUND" ]]; then
  echo "error: brev-vault's dependencies break its whitelist (docs/VAULT_SPLIT_PLAN.md §4):" >&2
  echo "$FOUND" >&2
  exit 1
fi
if ! grep -q 'reqwest' <<<"$(violations brev-mail)"; then
  echo "error: the whitelist check finds no reqwest in brev-mail; fix scripts/check-vault-deps.sh" >&2
  exit 1
fi
echo "brev-vault: only whitelisted dependencies (control: brev-mail fails the same check)"
