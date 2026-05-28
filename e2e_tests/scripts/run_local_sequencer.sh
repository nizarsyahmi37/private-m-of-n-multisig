#!/usr/bin/env bash
#
# run_local_sequencer.sh — bring up a standing local LEZ stack
# (Bedrock + sequencer + indexer + explorer) for manual smoke-testing of
# the LP-0002 multisig flow.
#
# NOTE: the automated Layer-B test (`make test-e2e-full`) does NOT need
# this script — its `TestContext` spins up Bedrock via `testcontainers`
# and runs the sequencer + indexer in-process, on throwaway ports. Use
# this script only when you want a *standing* stack to poke at by hand
# (e.g. with the wallet CLI) outside the test harness.
#
# Modelled on the Logos Execution Zone `Justfile` targets (`run-bedrock`,
# `run-sequencer`, `run-indexer`) and its all-in-one `docker-compose.yml`
# at tag v0.2.0-rc3.
#
# Prerequisites:
#   - Docker daemon running.
#   - logos-blockchain-circuits v0.4.2 on disk (only needed if you build
#     the sequencer from source rather than the published image).
#   - A checkout of logos-execution-zone. By default we reuse Cargo's git
#     checkout; override with $LEZ_REPO to point at your own clone.
#
# Usage:
#   e2e_tests/scripts/run_local_sequencer.sh [up|down]
#
#   up    (default) bring the stack up in the foreground
#   down  tear the stack down and remove volumes
#
# Environment:
#   LEZ_REPO        Path to a logos-execution-zone checkout. If unset, the
#                   newest Cargo git checkout is used.
#   RISC0_DEV_MODE  Defaults to 1 (fast, insecure dev proofs). Set to 0 for
#                   real proofs (matches the nightly benchmark job).
#   PORT            Host port to expose the Bedrock node on (default 8080).

set -euo pipefail

ACTION="${1:-up}"
export RISC0_DEV_MODE="${RISC0_DEV_MODE:-1}"
export PORT="${PORT:-8080}"

die() {
    echo "error: $*" >&2
    exit 1
}

# --- Locate a logos-execution-zone checkout -------------------------------
find_lez_repo() {
    if [[ -n "${LEZ_REPO:-}" ]]; then
        echo "$LEZ_REPO"
        return
    fi
    # Cargo stores git deps under ~/.cargo/git/checkouts/<name>-<hash>/<rev>.
    local base="${CARGO_HOME:-$HOME/.cargo}/git/checkouts"
    local newest
    newest=$(find "$base" -maxdepth 2 -type d -path '*logos-execution-zone*/*' 2>/dev/null \
        | sort | tail -n 1)
    [[ -n "$newest" ]] || die "no logos-execution-zone checkout found; set \$LEZ_REPO"
    echo "$newest"
}

# --- Preflight ------------------------------------------------------------
command -v docker >/dev/null 2>&1 || die "docker not found on PATH"
docker info >/dev/null 2>&1 || die "docker daemon not reachable; is Docker running?"

LEZ_REPO="$(find_lez_repo)"
COMPOSE_FILE="$LEZ_REPO/docker-compose.yml"
[[ -f "$COMPOSE_FILE" ]] || die "compose file not found at $COMPOSE_FILE"

echo "Using LEZ checkout: $LEZ_REPO"
echo "RISC0_DEV_MODE=$RISC0_DEV_MODE  PORT=$PORT"

case "$ACTION" in
    up)
        # Warn (don't fail) if the circuits prerequisite is absent — the
        # published images bundle their own circuits, but a from-source
        # build would need it.
        if [[ -z "${LOGOS_BLOCKCHAIN_CIRCUITS:-}" && ! -d "$HOME/.logos-blockchain-circuits" ]]; then
            echo "warning: logos-blockchain-circuits not found at ~/.logos-blockchain-circuits" >&2
            echo "         (fine when using the published images; required for source builds)" >&2
        fi
        echo "Bringing up the LEZ stack (Ctrl-C to stop)…"
        docker compose -f "$COMPOSE_FILE" up
        ;;
    down)
        echo "Tearing down the LEZ stack and volumes…"
        docker compose -f "$COMPOSE_FILE" down -v
        ;;
    *)
        die "unknown action '$ACTION' (expected 'up' or 'down')"
        ;;
esac
