#!/bin/bash
# Smoke-проверка двух узлов после деплоя. Запускать с узла 1.
# Требует: node.env заполнен на обоих узлах, сервис запущен.
# Public IPs: e2-1 51.170.89.241, e2-2 129.151.138.7 (recreated 29.09.2026)
set -euo pipefail
: "${PEER_ADDR:?PEER_ADDR не задан — заполни node.env}"
PEER_TCP="${PEER_MESH_TCP_PORT:-41001}"

echo "[1/3] cargo test (ядро, включая фазы 1-3)..."
cargo test --manifest-path "$(dirname "$0")/../../Cargo.toml" -q 2>&1 | tail -3

echo "[2/3] TCP до пира $PEER_ADDR:$PEER_TCP..."
timeout 10 bash -c "cat < /dev/null > /dev/tcp/$PEER_ADDR/$PEER_TCP" \
  && echo "TCP OK" || { echo "TCP FAIL"; exit 1; }

echo "[3/3] Сверка NodeSetSnapshot..."
echo "Сравни коммитмент снапшота эпохи $EPOCH на обоих узлах:"
echo "  узел 1: journalctl -u synergy-node | grep -i snapshot | tail -2"
echo "  узел 2: (ssh) journalctl -u synergy-node | grep -i snapshot | tail -2"
echo "Коммитменты обязаны совпасть, иначе PeerDirectory разошёлся."
echo "SMOKE DONE"
