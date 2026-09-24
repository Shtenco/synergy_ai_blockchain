# MVP CANONICAL INTEGRATION PLAN — 2026-09-24

## Goal

Deliver one reproducible three-host SYNERGY MVP run that proves, in one execution lineage:

1. PQ-authenticated peer sessions;
2. peer/provider discovery;
3. model publication and shard retrieval;
4. distributed inference;
5. verification of worker output;
6. KV replication/failover evidence;
7. storage evidence;
8. settlement/reward/slash accounting;
9. one canonical final checkpoint binding all plane roots.

No subsystem is to be rebuilt if an executable prior generation already exists.

## Canonical integration branch

`feat/mvp-canonical-integration-20260924`

Base:

`feat/distributed-ai-foundation-v1-20260922`

## Architecture rule

Consensus-safe Rust remains authoritative for identities, commitments, authorization, replay protection, scheduling, verification and settlement state.

Python/C++ runtimes are workers/adapters only. They may execute transport/storage/model compute, but they do not acquire consensus or treasury authority.

## Critical path

### Gate 0 — M2 executable certification

Required before release GREEN:

- Cargo.lock;
- cargo fmt --check;
- cargo check --all-targets;
- cargo clippy --all-targets -- -D warnings;
- cargo test --all-targets;
- cargo test --all-targets --features reference-pq;
- Solidity 0.8.26 compile/test;
- SBOM/provenance evidence.

This remains a runner/infrastructure blocker, not a source-design blocker.

### Gate 1 — canonical MVP checkpoint

Implemented in `src/mvp.rs`.

The checkpoint binds:

- model root;
- network/session root;
- provider/discovery root;
- inference root;
- verification root;
- KV root;
- storage root;
- settlement root;
- scheduler root;
- participating node-set root.

This is the cross-plane spine that prevents a demo from accidentally combining evidence from unrelated runs.

### Gate 2 — SynergyNet extraction

Source generation:

`Shtenco/synergynet@feat/static-peer-relay-service-v1-20260821`

Reuse:

- persistent content store;
- persistent content service;
- static relay;
- bounded TCP framing;
- tests.

Do not port economic authority into the network service.

### Gate 3 — PQ session adapter

Replace raw/untrusted worker transport with the current Rust M2 contract:

- TransportPeerIdentity;
- TransportTranscript;
- PQ-only handshake authorization;
- ML-KEM shared secret establishment;
- directional session keys;
- replay guard;
- record sequence;
- rekey policy.

Static peers remain as deterministic bootstrap fixtures.

### Gate 4 — discovery/provider layer

This is the principal genuinely new M3 work.

Minimum MVP implementation:

- bootstrap peer set;
- signed node/provider record;
- model/shard provider record;
- TTL/expiry;
- deterministic record commitment;
- lookup by model/shard root;
- duplicate/stale/bad-signature rejection.

A full production Kademlia implementation is not required before the first MVP if a bounded DHT-compatible routing table and provider lookup prove the required three-host behavior. The protocol surface must permit later Kademlia replacement without changing model or consensus commitments.

### Gate 5 — model distribution

Sources:

- current `model_shard.rs`;
- NEXUS V16 distributed manifest;
- SynergyNet content service;
- Turbo SharedCAS;
- GGUF V4/V5 manifest conventions.

Acceptance:

fresh node receives only model root -> discovers provider -> downloads shard(s) -> verifies bytes -> reconstructs manifest -> commits exact model root.

### Gate 6 — distributed inference

Source:

`Shtenco/synergy_agi_olga@nexus-v16-distributed-weight-fusion`

Reuse the five-process RPC execution shape, but narrow MVP to three hosts.

First acceptance model may be deliberately small. The requirement is real transformer/autoregressive execution, not benchmark prestige.

Evidence per stage:

- worker ID;
- model/shard root;
- input commitment;
- output commitment;
- start/end monotonic timestamps;
- input/output bytes;
- retry count;
- backend/capability root.

### Gate 7 — verifier/slash path

Use current `verification.rs` plus NEXUS Byzantine review logic as reference.

Mandatory adversarial scenario:

- one worker returns deliberately corrupted output;
- verifier rejects exact output commitment;
- invalid result cannot finalize;
- dishonest worker slash is consumed once;
- honest worker reward remains payable;
- replay of slash/reward receipt is rejected.

### Gate 8 — KV failover

Use current `kv_cache.rs` and SharedCAS/persistence patterns.

Acceptance scenario:

- generation starts on worker A;
- KV snapshot is replicated to worker B;
- A is terminated;
- B loads exact KV root;
- generation continues;
- final token sequence commitment matches uninterrupted reference within deterministic policy.

### Gate 9 — compute settlement

Reuse current funding/payment primitives and patterns from `synergy_pay_system`.

MVP settlement scope only:

- job funding reservation;
- worker reward;
- storage reward;
- verifier reward;
- slash;
- refund/release;
- one-shot consumption;
- accounting root.

Do not import unrelated macro-QE mechanisms into the MVP path.

### Gate 10 — three-host testnet

Reuse historical:

- 3-process checkpoint propagation;
- persistence/restart;
- partition/catch-up;
- replay rejection;
- Meta-OS three-host gate.

Replace loopback assumptions with three persistent external hosts.

Final demo must execute:

```
host A publishes model
-> host B discovers/fetches a shard
-> host C participates in inference/verification
-> one staged worker failure
-> KV recovery
-> one deliberate Byzantine result
-> slash
-> valid result settlement
-> all three nodes converge to one MvpCheckpoint root
```

## Definition of MVP GREEN

MVP is GREEN only when one evidence directory contains all of:

- exact source commit;
- exact dependency lock;
- build/test logs;
- node fingerprints;
- PQ session transcripts/commitments;
- provider records;
- model manifest + shard hashes;
- inference stage receipts;
- verifier receipts;
- KV replication/failover receipts;
- storage receipts;
- funding/settlement/slash receipts;
- restart/catch-up transcript;
- final identical checkpoint root from all three hosts;
- reproducibility command/script.

## What is intentionally deferred beyond MVP

- large public permissionless DHT;
- NAT traversal at Internet scale;
- production token economics;
- production governance;
- arbitrary model sizes;
- large-validator BFT deployment;
- mobile inference optimization;
- CUDA/Metal/Vulkan optimization beyond the backend needed for one heterogeneous proof;
- public mainnet launch.

These are post-MVP scale/product milestones, not blockers for proving the system architecture.
