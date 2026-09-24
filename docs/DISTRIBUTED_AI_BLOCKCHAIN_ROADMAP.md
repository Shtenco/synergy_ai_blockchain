# SYNERGY Post-Quantum Distributed AI Blockchain — master hardening roadmap

Date: 2026-09-22

This document is the canonical engineering roadmap for turning the existing PQ-EVM / NEXUS research branch into a reproducible distributed-AI blockchain stack.

## Baseline recovered from existing branches

The starting point is `feat/pq-evm-nexus-v1`, not an empty rewrite. It already contains:

- fail-closed hybrid/PQ authorization policy interfaces;
- ML-DSA-87 / SLH-DSA verification precompile surfaces;
- an ML-KEM-1024 provider boundary for transport;
- deterministic NEXUS consensus/reference execution;
- validator, payment, storage, service-plane and Autopilot primitives;
- EVM-facing Solidity interfaces;
- CI running `cargo test --all-targets`.

Several older branches also contain 3-node economic-testnet evidence and AI-node commitment experiments. Those are inputs to later integration gates, not automatic production authority.

## Engineering rule

A subsystem becomes green only when all of these exist:

1. executable implementation;
2. adversarial/unit tests;
3. integration evidence;
4. reproducible artifact identity;
5. explicit failure and downgrade behavior;
6. no claim stronger than the evidence.

## Milestones

### M0 — canonical ancestry and authority boundaries

Status: IN PROGRESS / mostly recovered.

- keep `synergy_ai_blockchain` as consensus/protocol authority;
- keep NEXUS model research in NEXUS repositories;
- keep compression implementation in AI-compress repositories;
- import interfaces and immutable evidence, not copied marketing claims;
- preserve provenance of old testnet and Autopilot branches.

Exit gate: one documented ancestry map and no duplicated authority.

### M1 — distributed inference protocol primitives

Status: THIS BRANCH.

Implement consensus-safe data structures and invariants for:

- model manifests and immutable model-shard lineage;
- inference jobs and deterministic execution plans;
- stage assignment and stage receipts;
- replicated proof-of-inference verification;
- heterogeneous/locality-aware scheduling;
- distributed KV-cache leases/commitments.

Exit gate: all protocol invariants covered by Rust tests and CI green.

### M2 — real post-quantum reference provider

Replace interface-only PQ crypto in tests/reference client with standards-conformant implementations:

- ML-KEM-1024 (FIPS 203);
- ML-DSA-87 (FIPS 204);
- SLH-DSA-SHAKE-256s (FIPS 205);
- known-answer / serialization / corruption / downgrade tests;
- zeroization and key-domain separation.

Reference libraries are never declared production-audited merely because tests pass.

Exit gate: real sign/verify and encapsulate/decapsulate round trips plus negative vectors in CI.

### M3 — PQ P2P transport and discovery

Build the real node network:

- libp2p QUIC + TCP fallback;
- Kademlia DHT for peer/model-shard discovery;
- Gossipsub for advertisements and job metadata;
- request-response streams for shard/activation traffic;
- transcript-bound hybrid classical + ML-KEM session derivation;
- replay protection, rekey, anti-downgrade and peer identity binding.

Exit gate: 3 independent local nodes reconnect after restart and maintain authenticated PQ-bound sessions.

### M4 — model shard network

Connect `ModelShardOutput` to real model storage:

- GGUF/Safetensors/OmegaStore tensor boundaries;
- content-addressed shard IDs;
- Merkle roots;
- Gabriel/GRAAL random-access storage adapters;
- replication / erasure placement;
- availability challenges;
- version lineage without duplicating unchanged model data.

Exit gate: publish, discover, retrieve and byte-verify a sharded real model through multiple nodes.

### M5 — first real distributed LLM executor

Start small and measurable:

- 3-node pipeline on loopback/LAN;
- explicit stage boundaries;
- activation transport;
- timeout/retry;
- deterministic job state;
- metrics: TTFT, tokens/s, bytes transferred/token, stage latency.

Then add locality-aware micro-clusters and expert parallelism. WAN per-layer token hopping is not an accepted production design.

Exit gate: one open model generates identical bounded test outputs under a frozen configuration across repeated 3-node runs.

### M6 — proof-of-inference, challenge and slashing

Phase 1:

- deterministic commitments;
- random replication;
- quorum comparison;
- challenge window;
- independent recomputation;
- stake reservation and slashing evidence.

Phase 2 research:

- TEE attestation;
- interactive/fraud proofs;
- zkML where proof cost is justified.

Exit gate: Byzantine worker simulation cannot finalize a mismatching result without producing slashable evidence.

### M7 — distributed KV cache

- session/sequence ownership;
- range commitments;
- expiry and bounded leases;
- replication;
- failover;
- no raw KV content in consensus state.

Exit gate: worker loss during decode can recover from another authorized KV replica within a bounded window.

### M8 — inference economics

Bind existing payment primitives to execution:

- pre-funded job reservation;
- per-stage metering;
- result finalization;
- challenge reserve;
- provider payment;
- verifier reward;
- slash distribution;
- no payment for unverified or expired work.

Exit gate: every unit paid is traceable to a finalized job/stage receipt.

### M9 — heterogeneous mobile / desktop / GPU scheduling

Nodes advertise measured capabilities. Roles differ by hardware:

- mobile/edge: retrieval, cache, small experts, validation samples, speculative work;
- desktop: medium experts, storage, orchestration;
- GPU nodes: large experts, prefill, decode, large batches.

Exit gate: scheduler never assigns a job exceeding declared hard resource constraints and measurably reduces cross-network transfer versus naive placement.

### M10 — production hardening

- fuzz/property testing;
- cross-client vectors;
- chaos testing;
- persistent restart tests;
- protocol version negotiation;
- DoS/resource limits;
- key rotation/recovery;
- reproducible builds;
- external cryptographic/security audit;
- testnet before any asset custody.

## Current maturity after ancestry correction

| Subsystem | Current evidence | Target milestone |
|---|---|---|
| NEXUS research/model routing | substantial code/artifacts | M5/M9 integration |
| compression/model storage | substantial code | M4 |
| random-access compression | implemented in compression line | M4 |
| hot/cold model architecture | strong R&D specification | M4/M5 |
| AI node/Autopilot | protocol primitives + older evidence branches | M5/M9 |
| blockchain economic experiments | substantial separate code/evidence | M8 |
| canonical AI blockchain | real PQ-EVM branch, not yet integrated network | M1-M5 |
| PQ authorization | policy/precompile interfaces | M2 |
| PQ transport | ML-KEM provider boundary only | M2-M3 |
| P2P/DHT | not canonical yet | M3 |
| model-shard network | storage commitments exist; model lineage missing | M1/M4 |
| distributed LLM executor | not canonical yet | M5 |
| proof-of-inference | verifier precompile address exists; protocol missing | M1/M6 |
| distributed KV cache | protocol missing | M1/M7 |
| inference payments | payment primitives exist, executor binding missing | M8 |
| slashing | executor binding missing | M6/M8 |
| model lineage / Weight-UTXO idea | concept only | M1/M4 |
| zkML | research-only future lane | M6 |
| heterogeneous scheduling | protocol missing | M1/M9 |

## Non-negotiable architecture boundary

Heavy LLM inference is off-consensus. The canonical chain commits model/job/result/payment/verification state. Validators do not fetch arbitrary model weights or perform unbounded network inference while executing blocks.

This separation is required for deterministic consensus, bounded resource usage and realistic latency.
