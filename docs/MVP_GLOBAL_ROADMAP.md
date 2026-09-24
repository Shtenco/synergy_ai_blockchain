# SYNERGY Post-Quantum AI Blockchain — MVP Global Roadmap

Current state: M2 source hardening complete; executable M2 evidence pending a working toolchain/runner.

The architectural principle remains:

NEXUS runtime -> distributed inference fabric -> model/data network -> PQ P2P trust -> SYNERGY chain

LLM inference stays outside consensus. Workers execute inference; the chain commits identity, model/job/result commitments, verification outcomes, payment/funding state, slashing/economic state and provenance.

## M2 — PQ crypto / authorization / execution evidence

Goal: finish executable evidence only.

Required GREEN gate:
- committed Cargo.lock;
- frozen/locked dependency resolution;
- dependency duplicate audit;
- SPDX/SBOM from the actual resolved graph;
- cargo fmt --check;
- cargo check core;
- cargo check reference-pq;
- clippy -D warnings;
- cargo test --all-targets;
- cargo test --all-targets --features reference-pq;
- doctests + release PQ tests;
- pinned solc 0.8.26 compile for all consensus contracts.

No M3 merge before this gate is truly executable PASS.

## M3 — Post-quantum P2P / DHT

Goal: turn authenticated transport primitives into a real multi-node network.

Deliverables:
- node identity registry and stable node IDs;
- PQ-authenticated peer handshake;
- peer discovery;
- Kademlia-style DHT/routing table;
- signed provider records;
- model-shard/provider advertisements;
- replay-resistant session establishment;
- transport rekey in live connections;
- NAT-friendly dialing/bootstrap strategy;
- peer scoring and abuse limits;
- deterministic protocol version negotiation;
- network partition/reconnect handling.

M3 acceptance:
- at least 3 independent processes discover each other from bootstrap;
- PQ-authenticated sessions form without static peer lists after bootstrap;
- DHT put/get/provider lookup works;
- malicious wrong-key/wrong-node/replay/downgrade peers are rejected;
- node restart/reconnect does not create duplicate identity or replay state.

## M4 — Model-shard network

Goal: distribute model artifacts instead of assuming local monolithic weights.

Deliverables:
- immutable model manifest;
- model root and shard roots;
- shard placement/provider records in DHT;
- shard fetch protocol;
- availability proofs;
- cache policy;
- dedup/archive integration;
- integrity verification before execution;
- model version activation and rollback controls.

M4 acceptance:
- a model manifest can be published by root;
- a fresh node can discover and retrieve required shards from the network;
- corrupt shard/provider is detected and rejected;
- missing provider causes deterministic retry/failover;
- exact model root used by inference is committed to chain state.

## M5 — Real 3-node distributed inference

Goal: prove that the project is an AI blockchain, not only a blockchain with AI data structures.

Minimum topology:
- node A: input / stage 0;
- node B: intermediate model stage;
- node C: final stage / output.

Deliverables:
- real model execution, not mocks;
- stage assignments;
- authenticated stage receipts;
- activation transfer between workers;
- deterministic job/result commitments;
- timeout/retry;
- result aggregation;
- chain finalization of the job.

Mandatory measurements:
- TTFT;
- tokens/sec;
- bytes of activations transferred;
- stage latency;
- end-to-end latency;
- network overhead;
- per-node compute time;
- retry/failover cost.

M5 acceptance:
- same real inference job runs end-to-end across 3 separate processes/nodes;
- result commitment reaches canonical chain state;
- measurable metrics are emitted;
- one worker can be restarted and the system either recovers or fails deterministically;
- PQ negative tests still pass under distributed execution.

## M6 — Byzantine verification / slashing

Goal: make dishonest AI workers economically unsafe.

Deliverables:
- independent verification challenges;
- verifier selection;
- mismatch/counterexample evidence;
- duplicate-verifier prevention;
- quorum/finality rules;
- fraud/incorrect-result proof path;
- slashable worker bond;
- dispute state machine;
- false accusation protection.

M6 acceptance:
- one deliberately malicious worker returns a bad result;
- independent verifier path detects it;
- bad result is not finalized as valid;
- slash/economic penalty is applied exactly once;
- correct workers are paid;
- replayed or duplicate verification evidence is rejected.

## M7 — KV/cache failover and long-running inference resilience

Goal: distributed generation must survive worker loss.

Deliverables:
- KV/cache ownership metadata;
- replica receipts;
- checkpointing;
- replica selection;
- failover/reconstruction;
- bounded stale-cache policy;
- sequence/version protection;
- migration of active generation state between workers.

M7 acceptance:
- generation starts on one worker;
- active worker is killed;
- another worker resumes from replicated state;
- token stream continues or restarts from a deterministic checkpoint;
- stale/forged KV replica receipt is rejected.

## M8 — Economics / payments / resource market

Goal: close the economic loop for compute, storage and verification.

Deliverables:
- worker pricing;
- storage pricing;
- verifier rewards;
- funded payment intents;
- settlement lanes;
- one-shot funding consumption;
- provider/worker bonds;
- slashing;
- fee accounting;
- reward caps;
- accounting roots;
- economic finality.

M8 acceptance:
- a user funds an inference job;
- compute/storage/verifier providers are paid from canonical funded state;
- overpayment/double-spend/double-consume fails;
- bad worker loses bond;
- accounting root matches all realized payouts;
- economic settlement is independently reproducible from receipts.

## M9 — Heterogeneous runtime

Goal: remove dependence on one hardware/backend.

Deliverables:
- CPU backend;
- at least one GPU backend;
- heterogeneous worker capability manifest;
- scheduler capability matching;
- quantized/GGUF path;
- NEXUS deterministic consensus kernel separated from nondeterministic LLM inference;
- optional DeepCompress/model compression integration only where it preserves verifiable roots.

M9 acceptance:
- same network runs mixed worker types;
- scheduler sends work only to compatible nodes;
- result/model commitments remain backend-independent where required;
- deterministic consensus functions remain bit-exact.

## M10 — MVP hardening / testnet

Goal: produce a demoable, externally reproducible MVP.

Deliverables:
- reproducible builds;
- persistent chain database;
- genesis/config format;
- 3+ node testnet launcher;
- bootstrap nodes;
- wallet/account tooling;
- transaction CLI/API;
- inference job CLI/API;
- model publish/fetch CLI/API;
- metrics/observability;
- structured logs;
- state snapshot/recovery;
- chaos tests;
- load tests;
- security regression corpus;
- CI evidence bundle;
- deployment documentation.

Final MVP demo must prove, end-to-end:

1. three nodes start from clean state;
2. PQ identities and authenticated networking establish;
3. peers discover each other through the network layer;
4. a model is published/discovered by commitment;
5. a funded inference job is submitted;
6. work is distributed across multiple workers;
7. real inference executes;
8. verification decides the result;
9. one malicious/failing worker is handled;
10. storage/KV failover is exercised;
11. payment/reward/slashing state settles;
12. canonical chain finality contains the job/result/economic commitments;
13. metrics report TTFT, tokens/sec, activation bytes and stage latency;
14. the same demo can be reproduced from documented commands.

## MVP scope discipline

Not required before the first MVP:
- global production-scale DHT;
- thousands of validators;
- mainnet economics;
- every payment rail;
- every AI model/runtime;
- full DAO ecosystem;
- QE/macro monetary system;
- mobile wallet ecosystem;
- global bridge network.

Those are post-MVP expansion tracks.

The shortest correct MVP path is:

M2 executable GREEN
-> M3 real PQ network
-> M4 real model distribution
-> M5 real 3-node inference
-> M6 Byzantine verification/slashing
-> M7 KV failover
-> M8 closed economic loop
-> M9 heterogeneous runtime
-> M10 reproducible public testnet/demo
