#!/bin/bash
# Поднимает kernel-TUN для PQ-mesh (fail-closed транспорт).
# Пакетный насос TUN<->mesh: src/mesh_tunnel.rs MemoryTunnelDevice (API),
# userspace-демон — следующий шаг; интерфейс и маршруты готовы заранее.
# Использование: sudo TUN_IF=synergy0 TUN_ADDR=10.99.0.1/24 ./tunnel-up.sh
set -euo pipefail
TUN_IF="${TUN_IF:-synergy0}"
TUN_ADDR="${TUN_ADDR:?задай TUN_ADDR, например 10.99.0.1/24 (узел1) / 10.99.0.2/24 (узел2)}"

if ! ip link show "$TUN_IF" >/dev/null 2>&1; then
  ip tuntap add dev "$TUN_IF" mode tun
fi
ip addr replace "$TUN_ADDR" dev "$TUN_IF"
ip link set "$TUN_IF" up
# Маршрут TUN-подсети через интерфейс (без перехвата default — управление по SSH живо).
ip route replace 10.99.0.0/24 dev "$TUN_IF" 2>/dev/null || true
echo "TUN UP: $TUN_IF $TUN_ADDR"
ip addr show "$TUN_IF" | grep -E 'inet '
