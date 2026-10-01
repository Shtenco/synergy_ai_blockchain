#!/bin/bash
# Fail-closed iptables для PQ-узла: default-DROP обе стороны, разрешены
# только loopback, established, SSH, mesh-порты, DNS/HTTP(S) для обновлений
# и TUN-интерфейс. Идемпотентен, сохраняется через netfilter-persistent.
# Использование: sudo ./firewall-iptables.sh  (MESH_TCP/UDP_PORT, TUN_IF из env)
set -euo pipefail
MESH_TCP_PORT="${MESH_TCP_PORT:-41001}"
MESH_UDP_PORT="${MESH_UDP_PORT:-41002}"
GOSSIP_PORT="${GOSSIP_PORT:-41003}"
TUN_IF="${TUN_IF:-synergy0}"

iptables -F INPUT
iptables -P INPUT DROP
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
iptables -A INPUT -p tcp --dport "$MESH_TCP_PORT" -j ACCEPT
iptables -A INPUT -p udp --dport "$MESH_UDP_PORT" -j ACCEPT
iptables -A INPUT -p tcp --dport "$GOSSIP_PORT" -j ACCEPT
iptables -A INPUT -p udp --dport "$GOSSIP_PORT" -j ACCEPT
iptables -A INPUT -i "$TUN_IF" -j ACCEPT 2>/dev/null || true

iptables -F OUTPUT
iptables -P OUTPUT DROP
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --dport "$MESH_TCP_PORT" -j ACCEPT
iptables -A OUTPUT -p udp --dport "$MESH_UDP_PORT" -j ACCEPT
iptables -A OUTPUT -p tcp --dport "$GOSSIP_PORT" -j ACCEPT
iptables -A OUTPUT -p udp --dport "$GOSSIP_PORT" -j ACCEPT
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
iptables -A OUTPUT -o "$TUN_IF" -j ACCEPT 2>/dev/null || true

if command -v netfilter-persistent >/dev/null; then
  netfilter-persistent save
fi
echo "FAIL-CLOSED FW UP (in/out default DROP)"
iptables -L INPUT -n --line-numbers | head -12
