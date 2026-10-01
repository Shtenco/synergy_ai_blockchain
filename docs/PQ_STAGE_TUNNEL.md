# PQ Stage RPC Tunnel — развёрнут и проверен

## Статус: РАБОТАЕТ (27.09.2026)

`deploy/pq_stage_tunnel.py` — потоковый TCP-туннель с взаимной PQ-аутентификацией для Stage RPC.

### Криптография (NIST FIPS, библиотека pqcrypto 1.0.0)

- **ML-DSA-87** (FIPS 204): взаимная аутентификация узлов, контекст `SYNERGY/STAGE-PQ-TCP/V1`
- **ML-KEM-1024** (FIPS 203): эфемерный сеансовый ключ на каждое соединение (encaps/decaps)
- **ChaCha20-Poly1305**: AEAD для каждой записи, nonce = direction(4B) + counter(8B)
- **HKDF-SHA256**: вывод ключей из ML-KEM shared secret + transcript salt
- **Chain-ratchet**: ротация ключей каждые 65536 записей (forward secrecy прошлого)
- **Pinned peer keys**: публичные ключи ML-DSA передаются вне канала (scp), не принимаются из handshake

### Развёртывание

| Узел | Роль | Слушает | Цель |
|------|------|---------|------|
| home (188.130.156.212) | client | 127.0.0.1:17700, 17701 | e2-1:44100, e2-2:44100 |
| e2-1 (51.170.89.241) | server | 0.0.0.0:44100 | 127.0.0.1:7700 (stage0) |
| e2-2 (129.151.138.7) | server | 0.0.0.0:44100 | 127.0.0.1:7701 (stage1) |

- e2: systemd `synergy-pq-stage.service`, автозапуск, `ProtectSystem=strict`, `NoNewPrivileges`
- home: фоновые процессы (PID 13208, 14552)
- Firewall: 44100 открыт только с 188.130.156.212/32 (OCI security list + iptables)

### Проверки

1. **Локальные юнит-тесты** (`tests/test_pq_stage_tunnel.py`): 3 passed
   - шифрованный roundtrip + replay-защита по counter
   - отклонение неверного pinned server key
   - ограничение размера записи
2. **Локальный сквозной**: PQ client → PQ server → Turbo API → `{"ok": true}`
3. **Межузловой сквозной**: stage0@e2-1 → stage1@e2-2 → verifier `MATCH` → Gemma ответ

### Ограничения (честно)

- Защищает **один TCP-поток Stage RPC** за раз, не IP/TUN-туннель для всего трафика
- Gemma исполняется **только на home** (3.46 ГБ GGUF); e2 не вмещают даже один тензор (1.93 ГБ > 954 МБ RAM)
- `pqcrypto` — reference implementation без формального аудита
- Составная схема (ML-DSA + ML-KEM + ChaCha20) не является стандартизованным TLS-профилем
- MIDAS не участвует в Stage RPC (нет доступа к guest OS)

### Следующие шаги

1. Исполняемое распределение Gemma: tensor-parallel runtime или переквантование тензоров ≤512 МБ
2. IP/TUN-туннель поверх PQ-канала (весь трафик, не только Stage RPC)
3. Подключение MIDAS как воркера (нужен доступ к guest OS + установка runtime)
