<!-- SCIENTIFIC-PROFILE-2026:START -->
<div align="center">
<img src="assets/readme/research-architecture.svg" width="100%" alt="SYNERGY PQ-EVM / NEXUS CONSENSUS architecture"/>

**[Новое научно-техническое досье / Scientific Profile](docs/SCIENTIFIC_PROFILE_2026.md)**
</div>

Дополнение раскрывает алгоритмы, математическую модель, исследовательскую ценность и воспроизводимость. Весь предыдущий README сохранён без сокращений.

---
<!-- SCIENTIFIC-PROFILE-2026:END -->

# SYNERGY AI Blockchain — PQ-EVM + NEXUS

Experimental consensus/execution core for the SYNERGY post-quantum EVM architecture.

## v1 implemented in this branch

- EVM-compatible system-precompile surface;
- native PQ authorization policies: `ONLINE`, `MAX`, `PQ_ONLY`;
- ML-DSA-87 and SLH-DSA-SHAKE-256s verifier precompile ABIs;
- deterministic fixed-point NEXUS graph kernel callable from every EVM context;
- frozen model-root / activation-block consensus model;
- Bitcoin / Ethereum / Solana legacy-identity migration binding;
- native Solidity `PQSmartAccount` facade;
- fail-closed security and migration invariants.

## NEXUS provenance

The current consensus profile points to NEXUS V18 research in `Shtenco/synergy_agi_olga`.
The reported V18 source checkpoint SHA-256 is:

`74433965c8193b6f75b42c197a4394bb14e37f2ef0ea0c7eb8b826e46c65c4e4`

The PyTorch checkpoint itself is **not** executed inside consensus. Production activation requires a deterministic quantized integer artifact, canonical test vectors and a frozen model root.

## Cryptographic rule

SYNERGY does not invent replacements for standardized PQ cryptography. Production nodes must use reviewed standards-conformant implementations for ML-DSA / SLH-DSA / ML-KEM. The repository defines consensus policy, deterministic execution interfaces and migration rules.

## Repository map

- `src/pq.rs` — hybrid/PQ authorization policies;
- `src/nexus.rs` — deterministic Q16.16 NEXUS consensus reference kernel;
- `src/consensus.rs` — reserved precompiles, gas and activation model;
- `src/migration.rs` — BTC/ETH/SOL → independent PQ identity binding;
- `contracts/` — Solidity ABI/facades for the PQ-EVM;
- `docs/ARCHITECTURE.md` — full architecture;
- `docs/SECURITY.md` — threat model and non-negotiable invariants.

## Local verification

The Rust reference core intentionally has no external dependencies:

```bash
cargo test
```

## Status

Research / integration branch. Not audited. Do not use it to custody real assets until the production PQ provider, EVM-client integration, cross-client vectors, light clients, bridge proofs and independent cryptographic audit are complete.


<!-- SYNERGY-FEDERATION-PASSPORT:START -->
---

##  SYNERGY federation passport

**Домен:**  Blockchain / trust authority  
**Архитектурный родитель:** [`synergy_system`](https://github.com/Shtenco/synergy_system)  
**Архитектурный корень:** [`synergy_system`](https://github.com/Shtenco/synergy_system)

```mermaid
flowchart LR
    SYS[ synergy_system] --> P[synergy_system]
    P --> THIS[synergy_ai_blockchain]
    THIS --> E[ Evidence / outputs]
```

Эта диаграмма фиксирует место в документационной федерации. Реальная code/runtime dependency должна подтверждаться отдельными артефактами.

### Навигация

- [ Атлас всех 75 репозиториев](https://github.com/Shtenco/synergy_system/blob/main/docs/SYNERGY_REPOSITORY_ATLAS.md)
- [ Машиночитаемый registry](https://github.com/Shtenco/synergy_system/blob/main/registry/SYNERGY_REPOSITORIES.json)
- [ SYNERGY SYSTEM](https://github.com/Shtenco/synergy_system)

### Evidence rule

`GREEN` присваивается только воспроизводимым утверждениям. Исследовательский код, диаграмма или заявленная метрика без проверяемого artifact trail остаются `R&D/CANDIDATE`.

<!-- SYNERGY-FEDERATION-PASSPORT:END -->


---

#  Реальная evidence-карта `main`

В отличие от многих архитектурных узлов федерации, `synergy_ai_blockchain` уже содержит большой исполняемый и доказательный слой на `main`: Rust workspace, Solidity contracts, node runtime, deployment manifests, PQ test vectors, smoke/adversarial tests и сохранённые evidence bundles.

## Фактические группы артефактов

| Группа | Примеры из `main` |
|---|---|
| Rust core | `Cargo.toml`, `src/*.rs` |
| PQ crypto | `src/pq.rs`, `src/pq_reference.rs`, `src/pq_rpc.rs` |
| EVM | `src/evm_compat.rs`, `contracts/*.sol` |
| NEXUS | `src/nexus.rs`, `src/inference.rs`, `models/nexus_v16/`, `models/nexus_v18/` |
| Network / mesh | `src/mesh_*`, `src/peer_discovery.rs`, `src/network.rs` |
| Agent fabric | `node-runtime/crates/agent-fabric/`, `src/agent_*` |
| Economic layer | `src/syna_emission.rs`, `src/syna_reward.rs`, `src/syna_state.rs` |
| Deployment | `deploy/mvp-3host/`, `deploy/mvp-4host/` |
| PQ vectors | `tests/vectors/ml-dsa-87-*`, `ml-kem-1024-*`, `slh-dsa-*` |
| Evidence | `evidence/GREENFULL_LOCAL.json`, `evidence/MVP_EVIDENCE_BUNDLE.json`, `evidence/p4_fullgreen/` |

```mermaid
flowchart TB
    SRC[ Rust / Solidity source] --> TEST[ Tests / vectors]
    TEST --> BUILD[ Build / clippy / docs]
    BUILD --> RUNTIME[ MVP runtime]
    RUNTIME --> EVID[ Evidence bundles]
    EVID --> CLAIM[ Bounded claims]
```

## Что означает GREEN здесь

Файлы вроде `evidence/p4_fullgreen/P4_FULLGREEN.json` являются **локальными evidence checkpoints конкретного набора проверок**. Они не превращают автоматически весь проект в production-ready или independently audited.

Нужно различать:

```text
local reproducible GREEN
      !=
independent cryptographic audit
      !=
multi-client consensus safety
      !=
production custody readiness
```

## Наиболее важные evidence anchors

- `docs/M2_REAL_PQ_CRYPTO_EVIDENCE.md`;
- `docs/PQ_TEST_VECTOR_PROVENANCE.md`;
- `tests/pq_acvp.rs`;
- `tests/vectors/M2_FIXTURE_MANIFEST.json`;
- `evidence/GREENFULL_LOCAL.json`;
- `evidence/MVP_EVIDENCE_BUNDLE.json`;
- `evidence/p4_fullgreen/P4_FULLGREEN.json`;
- `evidence/p6_pq_mesh/P6_STATUS.json`;
- `evidence/p7_agent_fabric/P7_STATUS.json`.

Это уже делает репозиторий одним из наиболее evidence-rich узлов всей федерации, но сильные security claims по-прежнему должны оставаться bounded конкретным тестом и окружением.
