# PQ IP Gateway — развёрнут и проверен (home ↔ e2-2)

`deploy/pq_ip_gateway.py` — универсальный TCP-поверх-PQ шлюз без TUN-драйверов.
Приложения подключаются к локальному порту как к обычному TCP-сокету;
полезная нагрузка шифруется и уходит UDP-дейтаграммами удалённому шлюзу.

## Криптография (NIST FIPS, pqcrypto 1.0.0 + cryptography)

- **ML-DSA-87** (FIPS 204): взаимная аутентификация, pinned ключи, контекст `SYNERGY/PQ-IP-GATEWAY/V1`
- **ML-KEM-1024** (FIPS 203): эфемерный shared secret на каждое соединение
- **ChaCha20-Poly1305**: AEAD записей, nonce = direction(4B) + counter(8B), строгий порядок
- **HKDF-SHA256**: ключи из ML-KEM secret + transcript salt
- **Chain-ratchet**: ротация каждые 65536 записей направления
- Replay/tamper/wrong-key отклоняются (покрыто тестами)

## Развёртывание (28.09.2026)

| Узел | Роль | Слушает | Цель |
|------|------|---------|------|
| home | client | 127.0.0.1:17801 | e2-2:44200 |
| e2-2 (51.170.93.115) | server | 0.0.0.0:44200 | 127.0.0.1:7701 (stage1) |

- Идентичности: `pq-stage-keys/home.json`, `e2-2.json`, публичные ключи обменены по scp
- Firewall: TCP 44200 открыт только с home IP (OCI security list + iptables)
- Проверки: stage1 через шлюз → token 135 MATCH; неверный peer key → `ValueError`

## Ограничения

- Один TCP-поток на соединение; не IP/TUN для всего трафика
- `pqcrypto` — reference без формального аудита
- e2-1 недоступен по SSH с 28.09 (баннер не отвечает, инстанс перезапускается)
