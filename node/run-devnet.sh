#!/usr/bin/env bash
set -euo pipefail

CHAIN_ID="${SYNERGY_CHAIN_ID:-8453001}"
PUBLIC_RPC_HOST="${SYNERGY_RPC_HOST:-127.0.0.1}"
PUBLIC_RPC_PORT="${SYNERGY_RPC_PORT:-9545}"
BACKEND_HOST="127.0.0.1"
BACKEND_PORT="${SYNERGY_BACKEND_PORT:-9546}"
STATE_DIR="${SYNERGY_STATE_DIR:-$HOME/.synergy-l1}"
STATE_FILE="$STATE_DIR/anvil-state.json"
VENV="$STATE_DIR/venv"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

command -v anvil >/dev/null 2>&1 || {
  echo "anvil not found. Install Foundry first." >&2
  exit 1
}
command -v python3 >/dev/null 2>&1 || {
  echo "python3 not found" >&2
  exit 1
}

if [[ -z "${SYNERGY_DEVNET_MNEMONIC:-}" ]]; then
  echo "SYNERGY_DEVNET_MNEMONIC must be set. Do not use Anvil's public default mnemonic." >&2
  exit 1
fi

mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"

if [[ ! -x "$VENV/bin/python" ]]; then
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install --upgrade pip
  "$VENV/bin/pip" install -r "$SCRIPT_DIR/requirements.txt"
fi

cleanup() {
  if [[ -n "${ANVIL_PID:-}" ]]; then
    kill "$ANVIL_PID" >/dev/null 2>&1 || true
    wait "$ANVIL_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

anvil \
  --host "$BACKEND_HOST" \
  --port "$BACKEND_PORT" \
  --chain-id "$CHAIN_ID" \
  --block-time 2 \
  --state "$STATE_FILE" \
  --state-interval 10 \
  --mnemonic "$SYNERGY_DEVNET_MNEMONIC" \
  --silent &
ANVIL_PID=$!

export SYNERGY_CHAIN_ID="$CHAIN_ID"
export SYNERGY_RPC_HOST="$PUBLIC_RPC_HOST"
export SYNERGY_RPC_PORT="$PUBLIC_RPC_PORT"
export SYNERGY_BACKEND_RPC="http://$BACKEND_HOST:$BACKEND_PORT"
export SYNERGY_STATE_DIR="$STATE_DIR"

for _ in $(seq 1 50); do
  if curl -fsS \
      -H 'content-type: application/json' \
      --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' \
      "$SYNERGY_BACKEND_RPC" >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done

exec "$VENV/bin/python" "$SCRIPT_DIR/pq_rpc_gateway.py"
