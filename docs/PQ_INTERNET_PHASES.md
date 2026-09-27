# PQ-Internet: закрытие фаз 1–3 (справочная реализация, v0.2.0+)

Статус: логика протокола реализована в `std`-only ядре, покрыта тестами
(`cargo test`: 360 passed). Ниже — что где лежит и что осталось
интеграционной работой на узлах.

## Фаза 1 — PQ-транспорт

| Задача | Где | Статус |
|---|---|---|
| Дейтаграммный фрейм `SYD1` (seq + cumulative/SACK, commitment) | `src/datagram.rs` | ✅ + тесты roundtrip/tamper |
| Ретрансмит-очередь с RTO и окном inflight | `src/datagram.rs::RetransmitQueue` | ✅ + тесты ack/RTO/window |
| Session resumption + 0-RTT exporter, replay-guard | `src/session_resume.rs` | ✅ + тесты expiry/replay/binding |
| Rendezvous через relay + hole-punch cookies (`punch_id` order-independent) | `src/rendezvous.rs` | ✅ + тесты |
| Plaintext MVP-адаптеры (`runtime/synergynet_ref/*`, `stage_rpc_v1.py`) | — | ⚠️ помечены legacy: использовать только за `MeshTunnelPolicy::secure_default`; шифрованный путь — `transport_record.rs` + `mesh_transport.rs` |

Осталось на узлах: открыть UDP-порт mesh (см. `deploy/two-node/`), прогнать
`three_node_tcp_relay`-тест поверх UDP-сокетов после интеграции `datagram.rs`
в сокетный слой.

## Фаза 2 — сеть

| Задача | Где | Статус |
|---|---|---|
| Kademlia-маршрутизация поверх `MeshAddress` (256 k-buckets, K=20, XOR-distance) | `src/dht.rs` | ✅ + тесты ordering/eviction |
| Gossip для `MeshLinkAdvertisement` (dedup, TTL, детерминированный fanout) | `src/gossip.rs` | ✅ + тесты |
| PQ-DNS: namehash + подписанные записи + монотонный реестр | `src/pq_dns.rs` | ✅ + тесты monotonic/expiry |
| Подписи записей | существующий `AuthorizationEnvelope` (ML-DSA-87 + SLH-DSA) | ✅ переиспользован |

Осталось: провязать `PeerDirectory` snapshots -> `dht.rs` insert,
`MeshLinkStateDb` update <- `gossip.rs` fanout (проводка, не криптография).

## Фаза 3 — защита всего трафика

| Задача | Где | Статус |
|---|---|---|
| Double-ratchet на flow (HKDF-SHA256, skipped-keys window 16, fail-closed дубликаты) | `src/double_ratchet.rs` | ✅ + тесты in-order/out-of-order/rekey |
| PQ-rekey hook (свежий ML-KEM secret -> chain) | `src/double_ratchet.rs::pq_rekey` | ✅ + тест |
| TUN-абстракция | `src/mesh_tunnel.rs` (`MemoryTunnelDevice`, `MeshTunnelPolicy::secure_default{fail_closed}`) | ✅ существует |
| Реальный TUN-драйвер (wintun/tun/utun) | — | ❌ вне `std`-ядра: ставится на узлах |
| Kill-switch на уровне ОС | `deploy/two-node/firewall-failclosed.sh`, `firewall-failclosed-windows.ps1` | ✅ скрипты |

## Проводка (turnkey-интеграция)

| Связка | Где | Статус |
|---|---|---|
| `NodeSetSnapshot` -> DHT (`index_snapshot_into_dht`, expired скипаются) | `src/pq_internet.rs` | ✅ + тесты |
| `MeshLinkAdvertisement` <-> gossip (канонические 132 байта, origin==from, replay -> `Ok(false)`) | `src/pq_internet.rs` | ✅ + тесты spoof/corrupt |
| gossip -> `MeshLinkStateDb::upsert` -> `route` end-to-end | `src/pq_internet.rs` | ✅ + тест |
| `SYD1` через реальные UDP-сокеты (send/recv/ACK/очередь) | `tests/pq_internet_udp.rs` | ✅ loopback-тест |

Осталось оператору на узлах: открыть UDP/TCP mesh-порты, заполнить
`deploy/two-node/node.env`, поставить TUN-драйвер, прогнать `smoke.sh`.

См. `deploy/two-node/`: `node.env.example`, `synergy-node.service`,
firewall-скрипты, `smoke.sh`. Порядок: build -> keys -> firewall ->
service -> smoke -> сверка `NodeSetSnapshot`.
