#!/bin/bash
# Fail-closed firewall для PQ-узла (nftables).
# Логика: разрешён только mesh-порт + established; весь остальной egress
# идёт через TUN-интерфейс; если TUN лежит — DROP (kill-switch).
# Использование: MESH_UDP_PORT=41002 TUN_IF=synergy0 ./firewall-failclosed.sh up|down
set -euo pipefail
MESH_UDP_PORT="${MESH_UDP_PORT:-41002}"
MESH_TCP_PORT="${MESH_TCP_PORT:-41001}"
TUN_IF="${TUN_IF:-synergy0}"
MODE="${1:-up}"

if [ "$MODE" = "up" ]; then
  nft flush ruleset
  nft -f - <<EOF
table inet synergy {
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    udp dport { $MESH_UDP_PORT } accept
    tcp dport { $MESH_TCP_PORT } accept
    iif lo accept
  }
  chain output {
    type filter hook output priority 0; policy drop;
    ct state established,related accept
    udp dport { $MESH_UDP_PORT } accept
    tcp dport { $MESH_TCP_PORT } accept
    oifname { "$TUN_IF", "lo" } accept
  }
}
EOF
  echo "fail-closed firewall UP (mesh only + $TUN_IF)"
else
  nft flush ruleset
  nft -f - <<EOF
table inet synergy {
  chain input { type filter hook input priority 0; policy drop; iif lo accept; }
  chain output { type filter hook output priority 0; policy drop; iif lo accept; oif lo accept; }
}
EOF
  echo "kill-switch DOWN (all dropped)"
fi
