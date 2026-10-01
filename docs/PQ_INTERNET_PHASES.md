# PQ-Internet: компоненты фаз 1–3 и ограничения развёртывания

> **Коррекция статуса развёртывания (27.09.2026):** приведённые ниже
> компоненты — код/заготовки, а не доказательство защищённого сквозного
> трафика на серверах. Запущенный `deploy/mesh_keepalive.py` не вызывает
> ML-KEM/подписи/AEAD и передаёт случайные данные с бесключевым SHA256.
> TUN-интерфейс и правила firewall сами не маршрутизируют IP через PQ mesh.
> Реальный Stage RPC пока проверен только через временные SSH-forwarding
> каналы (не PQ). См. `docs/GEMMA_DISTRIBUTED_READINESS.md`.
> Инстансы пересозданы 29.09.2026: e2-1 `51.170.89.241`, e2-2 `129.151.138.7`.
> В коде есть функция проверки PQ-подписанного gossip-конверта, но
> запущенный keepalive-демон её не вызывает. Его пакеты нельзя считать
> аутентифицированными только из-за совпадения SHA256.

Статус: логика протокола реализована в `std`-only ядре, покрыта тестами.
`CRYPTO_PROFILE_VERSION = 2`: classical/Hybrid транспорт удалён, wire v1
НЕ совместим с v2.

## Удаление Hybrid (audit: классики в транспорте больше нет)

- Удалены: `ClassicalKexScheme`, `SecretBytes`, `CLASSICAL_SHARED_*`,
  `legacy_kex_*`, `classical_transcript_hash`, `TransportPolicy::Hybrid`.
- `HybridSharedSecret` переименован в `PqSharedSecret` (только ML-KEM-1024).
- Осталась единственная политика `TransportPolicy::PqOnly` (код 2).
- KDF: IKM только из ML-KEM секрета; KAT-значения обновлены под v2.

## Подписанный gossip

- `SignedGossipEnvelope` (`src/gossip.rs`): dual-подпись ML-DSA-87 +
  SLH-DSA-SHAKE-256s поверх `msg_id` в домене `GossipAdvertisement` (код 19).
- Неподписанный gossip релеями дропается; origin/keyset/policy проверяются.
- Silent-tamper даёт чужую запись: ловится сверкой `pq_authorization_root`.

## Stage-RPC fail-closed

- `StageRpcServer` / `PersistentContentServer` отказываются биндиться на
  не-loopback без `SYNERGY_ALLOW_PLAINTEXT_TRANSPORT=1`.
- `mvp_node.py --host 0.0.0.0` теперь падает fail-closed по умолчанию.
- Межмашинный stage-трафик — только через `transport_record`/`mesh_transport`.

## TUN + DROP

- `deploy/two-node/tunnel-up.sh`: kernel-TUN `synergy0` + адресация
  (насос TUN<->mesh — следующий шаг, API: `MemoryTunnelDevice`).
- `deploy/two-node/firewall-iptables.sh`: INPUT/OUTPUT default-DROP,
  разрешены lo/established/SSH/mesh/DNS/80/443/TUN. Сохранение через
  netfilter-persistent.

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

## Третий узел (Windows, DESKTOP-C8GUE41)

- Код той же ветки, `cargo test` зелёный локально.
- Mesh-точка: `mesh_ping.py listen 41002`, пинги до e2-1/e2-2 отсюда: OK.
- Топология честно outbound-only: входящие с интернета не доходят
  (WARP-egress + NAT), e2<->e2 полный mesh между собой.
- Firewall: `deploy/windows-node/firewall-windows-node.ps1`
  (Standard: inbound-hardening + mesh; Strict: outbound DROP —
  только осознанно). Требует elevated PowerShell.
- TUN-драйвера на Windows нет из коробки (нужен wintun);
  сквозное шифрование всего трафика здесь даёт WARP (WireGuard) +
  PQ-слой mesh поверх.

## Full mesh через NAT (`deploy/mesh_keepalive.py`)

- Постоянные двунаправленные SYD1-flow: каждый узел слушает UDP и диалит
  пиров; keepalive ~20с с джиттером держит NAT-маппинг — обратные пакеты
  идут по нему. Входящие порты нужны только публичным узлам.
- Кадры фиксированного размера со случайной нагрузкой (сокрытие паттернов;
  commitment SHA256). Шифрование контента — слой transport_record/mesh_transport.
- WARP держать в режиме «1.1.1.1» (только DNS): WireGuard-туннель
  классический и не пропускает входящие; mesh-UDP идёт напрямую под PQ.
