# SYNERGY Cross-Repository MVP Audit — 2026-09-24

## Executive conclusion

Owner-level GitHub inventory contains **72 repositories** under `Shtenco`.

A full default-branch tree inventory was performed across all 72 repositories, followed by active-branch inspection of the repositories materially relevant to the Post-Quantum AI Blockchain MVP.

The central conclusion is:

> The MVP is not 90% complete by strict end-to-end acceptance criteria, but a very large fraction of the required engineering already exists as reusable components, prototypes, executed local evidence, tests, deployment gates and research runtimes across other SYNERGY repositories.

The project should therefore switch from a "build every milestone from scratch" plan to an **integration/distillation plan**.

The highest-value existing sources are:

- `Shtenco/synergy_ai_blockchain` — PQ/consensus/current foundation plus earlier economic testnet generations;
- `Shtenco/synergynet` — real TCP content transport, persistent content service/store and static peer relay generations;
- `Shtenco/synergy_agi_olga` — real five-process TCP model-shard inference, collective inference, Byzantine-aware aggregation and distributed model manifests;
- `Shtenco/synergy_meta_os` — node admission, capability isolation, deployment/bootstrap and external three-host gates;
- `Shtenco/synergy_turbo_linux` — host orchestration, CAS storage, MetaRAM/CAS bridge and runtime substrate;
- `Shtenco/synergy_pay_system` — settlement, idempotency, double-entry ledger, provider registry and live-readiness controls;
- `Shtenco/synergy_gguf_compress` — V1-V5 GGUF compression/runtime line including native factor execution, packed-Q4 and global activation-aware budget optimization;
- `Shtenco/synegy_ai_compress` — lossless/compression research and storage codec candidates;
- `Shtenco/synergy_qr_compress` — content/container/temporal compression and exact round-trip tests;
- `Shtenco/synergy_2chain_qe` — tested Solidity monetary/bridge/AMM/treasury primitives;
- `Shtenco/synergy_blochain_budget`, `synergy_graph_print_money`, `synergy_ai_financial_system` — accounting, Merkle/proof, conservation and economic simulation components.

The correct strategy is to **import, normalize and connect** these generations into the canonical `synergy_ai_blockchain` MVP branch rather than recreate them.

---

## Audit scope

### Repository count

GitHub owner-affiliation enumeration returned exactly **72 repositories**.

The initial generic repository endpoint exposed only 50 in the first page/window; the owner-affiliation endpoint revealed the complete owner-level inventory.

### Method

For all 72 repositories:

1. enumerate repository metadata;
2. inspect recursive default-branch Git tree;
3. identify source, tests, CI, Docker/deployment, network, inference, storage, economic and blockchain surfaces;
4. separate MVP-relevant repositories from trading/science/application repositories.

For the critical repositories, the audit additionally inspected active feature branches, because several canonical implementations are **not on `main`**.

This matters especially for:

- `synergynet`;
- `synergy_ai_blockchain`;
- `synergy_meta_os`;
- `synergy_agi_olga`;
- `synergy_gguf_compress`;
- `synergy_gllm_nexus`;
- `synergy_pay_system`;
- `synegy_ai_compress`.

---

# 1. Full repository inventory classification

## A. Directly relevant to the PQ AI blockchain MVP

### Canonical blockchain / consensus / economic-testnet family

- `synergy_ai_blockchain`
- `synergychain`
- `synergy_metachain`
- `synergy_2chain_qe`
- `synergy_qe`
- `synergy_usds`
- `synergy_blochain_budget`
- `synergy_graph_print_money`
- `print_money_synergychain`
- `synergy_chain_print_money`

### Network / node / host runtime

- `synergynet`
- `synergy_meta_os`
- `synergy_turbo_linux`
- `synergy_shttps`
- `synergy_motherboard_xpu_xml`

### NEXUS / distributed AI

- `synergy_agi_olga`
- `synergy_agi_nexus`
- `synergy_gllm_nexus`
- `synergy_nexus_science_agent`
- `synergy_ai_language`
- `synergy_ai_coder`
- `synergy_ai_company`

### Storage / compression / model runtime

- `synergy_gguf_compress`
- `synegy_ai_compress`
- `synergy_qr_compress`

### Payments / economics / accounting

- `synergy_pay_system`
- `synergy_ai_financial_system`
- `synergy_financial_os`
- `synergy_eurasian`

### System federation / orchestration

- `synergy_system`
- `synergy_project`
- `synergy_agi_autopilot`

## B. Potentially reusable engineering patterns but not on the MVP critical path

The enterprise trading service repositories contain Docker, API, auth, metrics, resilience, adapters and deployment tests that may be reused as service-operational patterns:

- `synergy-adaptive-engine`
- `synergy-ai-investment-committee`
- `synergy-market-graph`
- `synergy-market-maker`
- `synergy-marketvision`
- `synergy-midas-institutional`
- `synergy-quantlab`
- `synergy-relative-value`
- `synergy-riskguard`
- `synergy-trademux`

Application/UI/product repositories may later provide wallet/control-plane surfaces but are not blockers for the first MVP:

- `sinergy-super-app`
- `sinergy_app`
- `synergy_app`
- `synergy_apps`
- `synergy_app_family`
- `synergy_messenger`

## C. Not required for the PQ AI blockchain MVP

Trading research, unrelated science, public sites and special research repos are not on the MVP critical path:

- `3D_bars_market_structure`
- `binary_quantum_theory`
- `cashero`
- `cold_nuclear`
- `computer_vision_trading_metatrader_5`
- `cross_forex_arbitrage_trading_metatrader_5`
- `dlp_solver`
- `epstein_network`
- `global_liquidity_dataminer`
- `midas_lite`
- `multi_threaded_trading_robot_with_machine_learning_python`
- `quantum-trading_metatrader5`
- `swap_arbitrage_metatrader_5`
- `synergy_crypto_pump`
- `synergy_midas_ai`
- `synergy_midas_ai_trading_system`
- `synergy_ai_trade_terminal`
- `synergy_algotrading_graph_system`
- `synergy_matrix_sota`
- `synergy_agi_trader`
- `shtenco.github.io`
- `shtencoauantai.github.io`
- `synergychain.github.io`
- `shhts`

They should not distract the first MVP integration effort.

---

# 2. M3 audit — PQ P2P / DHT

## Existing reusable implementation

Repository:

`Shtenco/synergynet`

Important generations:

- `feat/three-node-content-mesh-lab-v1-20260821`
- `feat/real-tcp-content-transport-v2-20260821`
- `feat/persistent-store-codec-v3-20260821`
- `feat/persistent-content-service-v1-20260821`
- `feat/static-peer-relay-service-v1-20260821`
- `feat/shttps-transport-bridge-v1`
- later Autopilot transport generations.

### Real TCP content transport

`src/synergynet/tcp_transport.py` already implements an actual bounded TCP server/client protocol.

Implemented operations:

```
HAS
PUT
GET_RAW
```

Properties already implemented:

- real TCP sockets;
- bounded request/header sizes;
- bounded payload sizes;
- deterministic SHA-256 chunk identity;
- content-defined chunking;
- cache-hit probing before transfer;
- raw/zlib representation;
- decode + size + SHA-256 verification before storage;
- exact object reconstruction and hash verification;
- transfer byte accounting.

The source explicitly avoids unsafe filesystem/shell/dynamic-deserialization surfaces.

### Persistent content service

`src/synergynet/persistent_service_v1.py`

Adds:

- persistent directory-backed content storage;
- bounded JSON-line protocol;
- exact request shape validation;
- protocol/status endpoint;
- pluggable codec registry;
- digest verification before commit;
- explicit `execution_authority=NONE`.

### Static peer relay

`src/synergynet/static_relay_v1.py`

Already implements:

- bounded peer directory;
- unique peer IDs;
- allowlisted peer endpoints;
- source -> relay -> destination chunk transfer;
- independent source hash verification;
- destination commit verification;
- request and response digests;
- exact schema checks;
- no payment/accounting/execution authority escalation.

Tests exist for:

- TCP transport;
- three-node lab;
- persistent store;
- persistent service;
- static peer relay;
- build readiness.

## What M3 does NOT yet have

The branch itself accurately records:

```
pq_transport = NOT_IMPLEMENTED
quic = NOT_PERFORMED
production_verified = false
```

Still missing for the current M3 acceptance gate:

- automatic peer discovery;
- Kademlia-style DHT;
- dynamic provider records;
- persistent stable PQ node identity;
- live ML-KEM/ML-DSA authenticated session using the current M2 crypto core;
- session transcript/replay/rekey integration;
- wrong-key/wrong-node/downgrade attack tests over live sockets;
- NAT/bootstrap strategy;
- peer scoring / bans;
- non-static routing.

## M3 verdict

**Do not build transport, content service or basic relay from scratch.**

M3 should be assembled by combining:

```
current synergy_ai_blockchain M2 PQ transport primitives
+
synergynet TCP/persistent service/static relay
+
new DHT/discovery/provider-record layer
```

The remaining engineering is primarily **integration + DHT + live PQ sessions**, not a fresh network implementation.

---

# 3. M4 audit — model-shard network

## Existing distributed model manifest

Repository:

`Shtenco/synergy_agi_olga`

Generation:

`nexus-v16-distributed-weight-fusion`

Artifact:

`results_v16/NEXUS_V16_DISTRIBUTED_MODEL_MANIFEST.json`

It already defines a real distributed model manifest with:

- logical model identity;
- total logical parameters;
- five physical model shards;
- per-shard file name;
- per-shard SHA-256;
- per-shard parameter count;
- fusion component hashes.

Five physical expert checkpoints are identified independently.

## Existing content-addressed storage

Reusable sources:

- `synergynet` persistent content store;
- `synergy_turbo_linux/meta_os_v30/meta_storage/shared_cas.py`;
- `synegy_ai_compress`;
- `synergy_qr_compress`;
- `synergy_gguf_compress`.

`SharedCAS` already uses plaintext SHA-256 as immutable CID and verifies decoded content against the CID.

## Existing compression/runtime line

`synergy_gguf_compress` active branches implement:

- adaptive low-rank compression;
- Q4/Q8;
- sparse residual correction;
- native-factor GGUF execution;
- packed-Q4 runtime representation;
- patched llama.cpp integration;
- direct C++ packed-Q4 CPU kernel;
- reproducible distillation/evidence reports;
- activation-aware global byte-budget optimization (V5);
- Pareto output.

## Missing M4 integration

Still required:

- canonical conversion of NEXUS/GGUF manifests to the `model_shard.rs` model-root schema;
- DHT provider advertisement by shard root;
- fresh-node lookup from model root only;
- provider availability/expiry records;
- retry/failover between shard providers;
- shard fetch through authenticated SynergyNet session;
- corrupt-provider negative test;
- exact chain commitment of the selected model root/version.

## M4 verdict

The hard parts of:

- model manifesting;
- physical sharding;
- content identity;
- persistent content storage;
- compression;

already exist separately.

M4 is now primarily a **network-distribution integration milestone**.

---

# 4. M5 audit — real distributed inference

## Strong existing evidence: real five-process TCP shard inference

Repository:

`Shtenco/synergy_agi_olga`

Generation:

`nexus-v16-distributed-weight-fusion`

File:

`nexus_v16/verify_five_node_rpc.py`

This is not merely a struct or simulation.

It:

1. spawns five separate OS processes;
2. loads a different model checkpoint into each process;
3. opens five TCP listeners;
4. serializes inference requests over TCP;
5. executes each shard/model in the remote process;
6. returns numerical scores;
7. compares remote results to local references;
8. records process IDs, ports, request counts and checkpoint hashes.

The source classifies itself as:

`REAL FIVE-PROCESS TCP SHARD INFERENCE ON ONE HOST`

and explicitly states that external deployment would replace loopback addresses with host addresses and authenticated transport.

## Existing distributed collective inference

Generation:

`nexus-v14-collective-inference`

The workflow already executes:

- five independent proposal workers;
- heterogeneous GitHub-hosted Ubuntu/Windows/macOS runners;
- multiple model families;
- signed proposals;
- three independent review workers;
- Byzantine-aware aggregation;
- tamper-evident ledger;
- artifacts and observability.

This is batch/artifact mediated, not an always-on socket mesh, but it proves orchestration concepts.

## Existing Byzantine-aware aggregation

`nexus_collective/consensus.py`

Already contains:

- signature verification;
- quorum;
- weighted reputation;
- independent peer review;
- evidence/logic/utility weighting;
- objection penalties;
- offline/fallback penalties;
- deterministic aggregate;
- updated reputation;
- result ledger hash.

## Missing M5 acceptance

The strict MVP M5 still needs:

- external independent hosts rather than 5 loopback processes;
- current PQ-authenticated network rather than raw local TCP;
- a real autoregressive LLM/transformer stage pipeline;
- activation tensor transfer between sequential model stages;
- chain-native job scheduling and result commitment;
- timeout/retry through the canonical network;
- TTFT;
- tokens/sec;
- activation bytes;
- stage latency;
- network latency;
- end-to-end latency;
- retry/failover metrics.

## M5 verdict

M5 is **substantially pre-implemented as an execution proof**, but not yet integrated into the canonical chain/network.

We should port the V16 five-process harness as the first canonical M5 acceptance harness instead of starting from zero.

---

# 5. M6 audit — Byzantine verification / slashing

## Existing reusable verification logic

Sources:

- current `synergy_ai_blockchain/src/verification.rs`;
- `synergy_agi_olga/nexus_collective/consensus.py`;
- `synergynet/research/legacy_distillation_v1/verification_network_v2.py`;
- current worker/verifier identity and authorization registry;
- current funding/payment/slashing-oriented state primitives.

Already represented:

- independent reviews;
- invalid signature rejection;
- quorum;
- reputation weighting;
- disagreement/objections;
- Byzantine penalties;
- canonical evidence hashes;
- duplicate/replay-resistant structures in current blockchain core.

## Missing integrated M6 gate

Need one deliberate bad worker in the canonical distributed inference pipeline:

```
malicious worker output
-> independent verifier
-> canonical mismatch evidence
-> finality rejection
-> slash worker bond exactly once
-> pay correct workers
```

The principal missing element is the **cross-plane binding** between inference verification evidence and economic slashing.

## M6 verdict

Verification mechanics exist; the missing work is canonicalization and economic integration.

---

# 6. M7 audit — KV/cache failover

## Existing reusable pieces

Current blockchain branch already contains:

- `src/kv_cache.rs`;
- KV leases;
- replica receipts;
- sequence/version ideas.

`synergy_turbo_linux` adds:

- immutable SharedCAS;
- MetaRAM -> CAS eviction/page-in;
- generation-aware cold page references.

Earlier economic testnet generations additionally demonstrate persistent recovery/replay rejection patterns.

## Missing M7 acceptance

No audited repository currently proves:

```
autoregressive generation
-> replicated KV checkpoint
-> active inference worker dies
-> different inference worker loads checkpoint
-> generation continues
```

This remains a genuine integration/runtime milestone.

## M7 verdict

The persistence and receipt primitives exist, but **distributed autoregressive KV handoff is still real new work**.

---

# 7. M8 audit — closed economic loop

## Existing payment system is much more mature than assumed

Repository:

`Shtenco/synergy_pay_system`

Important implemented components include:

### Settlement engine

- idempotency key handling;
- route selection;
- compliance state;
- fund reservation event;
- multi-leg provider execution;
- settlement status machine;
- failure state;
- ledger posting.

### Double-entry ledger

- per-asset zero-sum invariant;
- idempotent journal references;
- thread-safe updates;
- balances;
- transfer helper.

### Provider registry

- provider status;
- asset-pair capability;
- jurisdiction;
- max notional;
- legal/contract evidence requirements.

### Live-readiness control plane

Evidence schemas include:

- credential backends;
- HSM/MPC;
- legal basis;
- KYB;
- settlement accounts;
- fee tiers;
- rails;
- prefunding;
- sanctions/PEP screening;
- audit evidence;
- bridge evidence;
- provider health;
- disaster recovery.

Active branches additionally include:

- full payment-router MVP;
- global settlement;
- omnichain token/DEX/bridge;
- fee-aware settlement;
- reversal/refund;
- PQ migration adapters.

## Existing Solidity economy

`synergy_2chain_qe` contains an extensive Foundry/Solidity codebase with:

- BridgeCore;
- InternalAMM;
- TreasuryDistributor;
- synthetic/canonical token logic;
- health factors;
- caps;
- emergency stop;
- mint/burn/lock/unlock flows;
- tests.

Other economic repos add:

- Merkle/proof/accounting;
- token-conservation experiments;
- treasury policies;
- economic-cycle simulations.

## Missing M8 integration

The MVP does not need the entire QE macro system.

It needs a narrow compute-market adapter:

```
funded inference reservation
-> compute receipt
-> storage receipt
-> verifier receipt
-> canonical payout split
-> one-shot consume
-> worker/verifier/storage rewards
-> slash dishonest worker
-> accounting root
```

## M8 verdict

Generic payment/accounting machinery is already strong.

The remaining work is to build a **compute/storage/verifier settlement adapter**, not a new financial system.

---

# 8. M9 audit — heterogeneous runtime

## Existing runtime/orchestration

`synergy_meta_os/runtime/orchestrator.py` already defines node profiles such as:

- NEXUS_COMPUTE;
- P2P_RELAY;
- CONTENT_CACHE;
- BLOCKCHAIN_PEER;
- BLOCKCHAIN_VALIDATOR;
- METAPAY_GATEWAY;
- FULL_SYNERGY_NODE.

It enforces capability ceilings, artifact hashes, resource limits, attestation for privileged roles and staged update/rollback.

## Existing host substrate

`synergy_turbo_linux` already contains:

- remote SSH orchestration (инстансы пересозданы 29.09.2026: e2-1 `51.170.89.241`, e2-2 `129.151.138.7`);
- KVM/libvirt provisioning work;
- benchmark workflow;
- memory/storage experimentation;
- CAS integration.

## Existing compressed model runtime

`synergy_gguf_compress` active V1-V5 branches provide substantial quantized-model runtime research and implementation.

## Existing heterogeneous compute orchestration proof

NEXUS V14 executes inference/review workers on Linux, Windows and macOS runners.

## Missing M9 acceptance

Still required:

- canonical worker capability advertisement;
- at least one real CPU backend;
- at least one real GPU backend;
- scheduler routing stages by capabilities;
- same model/job protocol across CPU/GPU workers;
- real GGUF/quantized execution inside the distributed inference pipeline;
- backend-independent commitment policy where required;
- GPU packed-Q4/fused runtime work remains incomplete in GGUF roadmap.

## M9 verdict

The runtime pieces are strong, but heterogeneous execution needs one canonical integration.

---

# 9. M10 audit — reproducible testnet

This milestone is much further advanced than the previous roadmap suggested.

## Existing real local three-node checkpoint network

Branch:

`synergy_ai_blockchain/feat/economic-testnet-loopback-3node-evidence-v1-20260828`

File:

`testnet/economic_testnet_loopback_v1.py`

Executed evidence records:

- three independent Python processes;
- three TCP servers;
- two canonical checkpoints per node;
- six accepted checkpoint deliveries;
- all three nodes converge to the exact same head.

The repository explicitly recorded the claim:

`LOCAL_3_NODE_TCP_PROPAGATION_VERIFIED_NOT_PERSISTENT_TESTNET`

## Existing persistent restart / partition / replay evidence

Branch:

`feat/economic-testnet-persistent-restart-evidence-v1-20260828`

File:

`testnet/economic_testnet_persistent_restart_v1.py`

The executed scenario already proves:

1. all three nodes persist C1;
2. C2 reaches only node-1 and node-2;
3. all nodes are restarted in fresh processes;
4. recovered heads are exactly C2/C2/C1;
5. replay of C1 to node-1 is rejected;
6. node-3 catches up to C2;
7. all nodes append C3;
8. a second fresh-process restart recovers one common C3 head.

Persistence uses:

- canonical JSON;
- flush;
- fsync;
- atomic replace;
- full chain re-verification on recovery.

Canonical evidence root is recorded in the historical branch documentation.

## Existing external deployment gate

Repository:

`synergy_meta_os`

Branch:

`feat/external-three-host-requirements-v1-20260905`

File:

`src/synergy_meta_os/economic_testnet_external_deployment_gate_v1.py`

The gate already requires:

- exactly three nodes;
- three distinct persistent external hosts;
- unique host fingerprints;
- persistent durable state per node;
- fresh-process restart evidence per node;
- non-loopback cross-host checkpoint propagation transcript;
- artifact/deployment/result roots;
- transport endpoint roots.

The gate deliberately remains blocked until those real external-host inputs exist.

This is strong evidence that an earlier project generation had already reached the same conceptual next step.

## Missing M10 integrated MVP

The historical testnet proves checkpoint transport/recovery but does **not** yet integrate:

- current M2 PQ identities/sessions;
- DHT;
- model publish/fetch;
- distributed LLM job;
- verifier decision;
- KV failover;
- compute settlement;
- slash;
- final canonical all-plane state.

## M10 verdict

Do not recreate genesis/persistence/restart/3-node loopback infrastructure from scratch.

Import it and evolve it into the current canonical testnet.

---

# 10. New MVP readiness matrix after the 72-repository audit

Legend:

- **FOUNDATION COMPLETE** — canonical source foundations exist;
- **REUSABLE EXECUTED PROTOTYPE** — real code/evidence exists elsewhere and should be imported;
- **PARTIAL** — meaningful pieces exist but acceptance integration is missing;
- **NEW INTEGRATION REQUIRED** — no complete end-to-end proof found.

| Milestone | Revised state | Existing assets | Remaining acceptance blocker |
|---|---|---|---|
| M2 PQ core | FOUNDATION COMPLETE / executable certification blocked | current branch | working Rust/Solidity runner + Cargo.lock + frozen evidence |
| M3 PQ P2P/DHT | PARTIAL / strong reuse | real TCP, persistent service, static relay, 3-node labs | live PQ handshake + DHT/discovery/provider records |
| M4 model network | PARTIAL / strong reuse | V16 model manifest, CAS, content service, compression | provider discovery + fresh-node shard retrieval |
| M5 distributed inference | REUSABLE EXECUTED PROTOTYPE | five-process TCP model inference + multi-runner collective inference | external hosts + PQ + real LLM stage/activation pipeline + metrics |
| M6 Byzantine verification | PARTIAL / strong reuse | signed reviews, Byzantine aggregate, verification state | bad-worker proof -> canonical rejection -> one-shot slash |
| M7 KV failover | PARTIAL | KV receipts, CAS, persistence patterns | live autoregressive KV replication and resume |
| M8 economics | PARTIAL / strong reuse | payment router, ledger, settlements, Solidity economy | compute/storage/verifier settlement adapter |
| M9 heterogeneous runtime | PARTIAL / strong reuse | Meta-OS, Turbo, GGUF V1-V5, heterogeneous runners | same real job across CPU/GPU workers |
| M10 testnet | REUSABLE EXECUTED PROTOTYPE | 3-node TCP, persistent restart, partition/catchup/replay rejection, external-host gate | integrated external 3-host PQ AI economic testnet |

---

# 11. The "90%" question

A strict statement that "90% of the MVP is already complete" is **not supportable yet**, because the missing work is concentrated in the highest-value integration gates.

However, the audit supports a different and much more useful statement:

> Most major subsystems required by the MVP already have at least one concrete implementation lineage somewhere in the 72-repository SYNERGY estate.

The largest remaining problem is **not absence of code**.

It is:

```
fragmentation
+
branch divergence
+
different schemas
+
historical generations
+
lack of one canonical end-to-end runtime
```

Therefore the project's shortest route to MVP is now **federation/distillation**, not greenfield implementation.

---

# 12. Canonical import queue

## M3 import queue

From:

`Shtenco/synergynet@feat/static-peer-relay-service-v1-20260821`

Import/adapt:

- `src/synergynet/tcp_transport.py`
- `src/synergynet/storage_v3.py`
- `src/synergynet/persistent_service_v1.py`
- `src/synergynet/static_relay_v1.py`
- corresponding tests.

Destination conceptually:

`synergy_ai_blockchain/network_runtime/`

Do not directly copy Python semantics into consensus. Use them as executable reference/runtime services around the Rust protocol core.

Add new:

- PQ session adapter;
- DHT;
- bootstrap;
- peer discovery;
- signed provider records.

## M4 import queue

From:

`synergy_agi_olga@nexus-v16-distributed-weight-fusion`

Import/adapt:

- distributed model manifest;
- shard hashes;
- RPC shard model boundary.

From:

- `synergynet` persistent store;
- `synergy_turbo_linux` SharedCAS;
- `synergy_gguf_compress` V4/V5 manifests.

Build one canonical `ModelManifestV1`.

## M5 import queue

From:

`synergy_agi_olga@nexus-v16-distributed-weight-fusion`

Port:

- five-process worker harness;
- per-worker model ownership;
- request/response RPC tests.

Replace:

- loopback-only raw transport
with
- canonical M3 PQ transport.

Then replace score-only model with the first small autoregressive model stage pipeline.

## M6 import queue

Use concepts/code from:

- `nexus_collective/consensus.py`;
- current `verification.rs`;
- verification-network research.

Canonicalize only deterministic evidence and chain-safe decisions.

## M7 import queue

Combine:

- current `kv_cache.rs`;
- `synergy_turbo_linux` SharedCAS;
- historical persistent restart/recovery harness.

Add live KV checkpoint serialization and cross-worker resume.

## M8 import queue

Use:

- current blockchain funding/payment state;
- `synergy_pay_system` ledger/settlement/idempotency patterns;
- only narrowly required token/treasury parts from `synergy_2chain_qe`.

Do not import the full macro-QE system before MVP.

## M9 import queue

Use:

- current `scheduling.rs`;
- Meta-OS capability profile;
- Turbo host runtime;
- GGUF V4/V5 runtime.

Add canonical worker capabilities and CPU/GPU integration.

## M10 import queue

Port historical:

- `economic_testnet_loopback_v1.py`;
- `economic_testnet_persistent_restart_v1.py`;
- external three-host deployment gate.

Then extend the same testnet harness with:

- PQ network;
- DHT;
- model distribution;
- inference;
- verification;
- payment/slashing.

---

# 13. What must NOT be rewritten

The following functionality already has useful implementation and should not be recreated merely to satisfy a new milestone label:

- basic TCP content transfer;
- content-defined chunking;
- SHA-256 content identity;
- persistent content service;
- persistent content-addressed store;
- static peer relay;
- basic 3-node local process harness;
- canonical checkpoint persistence/recovery;
- partition/catch-up test pattern;
- replay rejection pattern;
- external three-host admission contract;
- distributed model manifest idea;
- multi-process model-worker RPC harness;
- signed collective inference messages;
- Byzantine-aware aggregate/reputation prototype;
- append-only inference ledger;
- double-entry ledger;
- settlement idempotency pattern;
- provider/readiness registry pattern;
- generic Meta-OS service capability isolation;
- artifact hash verification;
- staged update/rollback;
- GGUF adaptive compression/runtime work;
- CAS implementation.

The task is to **select the best generation, normalize interfaces, and integrate it**.

---

# 14. Revised critical path

The old path implied a largely greenfield sequence:

```
M3 -> M4 -> M5 -> M6 -> M7 -> M8 -> M9 -> M10
```

The audit changes it to:

```
                ┌─ synergynet transport/store/relay ─────────┐
                │                                            │
M2 GREEN ─> CANONICAL INTEGRATION BRANCH                     │
                │                                            │
                ├─ NEXUS V16 five-process inference ─────────┤
                ├─ NEXUS collective verification ────────────┤
                ├─ Meta-OS node/deployment gates ────────────┤
                ├─ old economic 3-node/persistence testnet ──┤
                ├─ MetaPay settlement/ledger ────────────────┤
                ├─ Turbo SharedCAS ───────────────────────────┤
                └─ GGUF V4/V5 runtime ───────────────────────┘
                                   │
                                   ▼
                      ONE 3-HOST PQ AI TESTNET
                                   │
                                   ▼
                                  MVP
```

This is a materially shorter engineering route.

---

# 15. Recommended next implementation milestone: M3-M5 DISTILLATION SPRINT

Instead of treating M3, M4 and M5 as three independent greenfield projects, create one integration sprint:

## Phase A — canonical runtime extraction

Bring in:

- SynergyNet persistent TCP service;
- static relay;
- V16 distributed model manifest;
- V16 worker RPC harness.

Do not yet change semantics.

Goal: reproduce historical tests under one integration tree.

## Phase B — replace static transport identity with current M2 PQ identity

Wire current:

- ML-KEM transport;
- ML-DSA/SLH authorization profile;
- transcript commitment;
- replay state;
- rekey ceiling.

into the existing content/worker sockets.

## Phase C — add DHT/discovery

Only this part needs a genuinely new M3 networking layer.

Keep static directory as deterministic bootstrap/fallback test fixture.

## Phase D — model-root distribution

Bind:

`model_root -> shard roots -> provider records -> persistent store`.

## Phase E — inference

Run V16-style multi-process workers through the canonical network.

Then swap the model payload to a small real autoregressive LLM stage pipeline.

This converts M3/M4/M5 from three large rebuilds into one integration sequence.

---

# 16. Immediate blockers that remain real

Despite the amount of reusable code, these blockers are not solved by repository archaeology:

1. M2 executable Rust/Solidity runner remains unavailable.
2. No audited active DHT/Kademlia implementation was found in the inspected SYNERGY estate.
3. SynergyNet PQ transport is explicitly marked not implemented in its TCP-v2 generation.
4. Existing multi-process NEXUS RPC is loopback/same-host.
5. Existing economic testnet external-host gate explicitly remains blocked awaiting three real persistent external hosts.
6. No complete autoregressive distributed-KV failover demo was found.
7. No single integrated demo currently connects PQ network + model distribution + inference + verifier + settlement + slash.

These are the true remaining engineering targets.

---

# Final audit decision

The earlier roadmap was too pessimistic about how much needed to be newly built.

The repository estate already contains substantial prior generations for nearly every MVP plane.

The correct project strategy from this point is:

```
STOP recreating subsystems
START canonical cross-repo distillation
PRESERVE executed evidence
PORT only proven generations
ADD only missing integration layers
MAKE one end-to-end three-host runtime
```

The highest-priority integration sequence is:

```
M2 executable evidence
-> import SynergyNet persistent transport/relay
-> attach current PQ sessions
-> add DHT/provider discovery
-> import NEXUS V16 distributed worker harness
-> bind model manifests/shards
-> execute real small LLM over 3 hosts
-> attach verification/slashing
-> attach compute settlement
-> reuse persistent/restart testnet harness
-> final reproducible MVP demo
```
