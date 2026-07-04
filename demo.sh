#!/usr/bin/env bash
#
# demo.sh — reproducible end-to-end demo for LP-0002 (Private M-of-N Multisig).
#
# Drives the SDK + Risc0 approval circuit through the full
# propose → approve → verify → double-vote-rejection flow via the
# `quickstart` binary. No on-chain dependencies: it runs the cryptographic
# core in-process so an evaluator can confirm the primitive works on a
# standard laptop before any deployment.
#
# Usage:
#   ./demo.sh                       # fast dev-mode proofs (~30s warm cache)
#   ./demo.sh --real                # real proofs, RISC0_DEV_MODE=0 (~3 min/receipt)
#   M=3 N=5 ACTION="treasury-xfer" ./demo.sh   # override the multisig shape
#
# Environment overrides:
#   M        approval threshold           (default: 2)
#   N        total member count           (default: 3; must be >= M)
#   ACTION   UTF-8 action committed to the proposal (default: demo-action)
#   REAL     set to 1 (or pass --real) to run real proofs under Docker
#
# Real-proof mode sets RISC0_DEV_MODE=0 and RISC0_USE_DOCKER=1 so the freshly
# built guest image-id matches the canonical pin and proof generation is real
# (the terminal output shows the multi-minute prove time, satisfying the
# "recording must show RISC0_DEV_MODE=0" evaluation criterion).
#
set -euo pipefail

# Run from the repo root regardless of the caller's cwd.
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

M="${M:-2}"
N="${N:-3}"
ACTION="${ACTION:-quickstart-demo-action}"
REAL="${REAL:-0}"
CARGO_FLAGS=()

for arg in "$@"; do
  case "$arg" in
    --real) REAL=1 ;;
    -h|--help)
      sed -n '3,/^set -euo/p' "${BASH_SOURCE[0]}" | grep '^#' | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

echo "=============================================================="
echo " LP-0002 Private M-of-N Multisig — end-to-end demo"
echo " threshold M=$M  members N=$N  action=\"$ACTION\""
if [[ "$REAL" == "1" ]]; then
  echo " mode: REAL proofs (RISC0_DEV_MODE=0, Docker guest build)"
else
  echo " mode: dev proofs (RISC0_DEV_MODE=1) — pass --real for real proofs"
fi
echo "=============================================================="
echo

if ! command -v cargo >/dev/null 2>&1; then
  echo "error: cargo not found. Install Rust: https://rustup.rs" >&2
  exit 1
fi

if [[ "$REAL" == "1" ]]; then
  export RISC0_DEV_MODE=0
  export RISC0_USE_DOCKER=1
  CARGO_FLAGS+=(--release)
  echo "Real-proof mode: first run pulls the Risc0 guest-builder image and"
  echo "cross-compiles the guest in Docker (~20 min cold, cached thereafter)."
  echo "Each of the $M receipts then takes several minutes to prove."
  echo
else
  export RISC0_DEV_MODE=1
fi

set -x
cargo run ${CARGO_FLAGS[@]+"${CARGO_FLAGS[@]}"} \
  --manifest-path e2e_tests/Cargo.toml --bin quickstart -- \
  --mode layer-a --threshold "$M" --members "$N" --action "$ACTION"
set +x

echo
echo "Demo complete. See README.md §Quickstart and PLAN.md §Verification for"
echo "the on-chain (LEZ testnet) follow-on flow and CLI/Basecamp usage."
