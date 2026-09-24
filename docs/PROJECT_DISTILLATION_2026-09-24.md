# SYNERGY Post-Quantum AI Blockchain — Project Distillation

Date: 2026-09-24

This file distills the previous development thread into one continuation point.

## 1. Original project objective

The target is not merely a post-quantum signature library. The intended stack is:

```
NEXUS runtime
    ->
distributed AI inference fabric
    ->
model / storage network
    ->
post-quantum authenticated P2P trust
    ->
SYNERGY chain
    ->
payments / verification / slashing / finality
```

Heavy LLM inference must remain off-consensus. Consensus commits bounded identities, commitments, verification outcomes, economics and finality. Workers execute model stages outside block execution.

## 2. Completed architectural foundation

M0 architecture is effectively complete.

M1 distributed-AI foundation exists at source level:
- immutable model-shard lineage;
- Weight-UTXO-style transition primitives;
- distributed inference jobs;
- ordered execution plans;
- stage receipts;
- replication-first verification primitives;
- KV-cache leases and replica receipts;
- heterogeneous scheduler primitives;
- payment, storage, cognitive, governance and service-plane state machinery;
- EVM/PQ boundary contracts.

## 3. M2 post-quantum security line

The previous work intentionally concentrated on making the PQ security boundary fail closed before starting networking.

Completed source-level milestones:

```
M2.1   real providers                          COMPLETE
M2.2   domain separation                       COMPLETE
M2.3   anti-downgrade                          COMPLETE
M2.4   dual-PQ authorization                   COMPLETE
M2.5   MAX three-lane authorization            COMPLETE
M2.6   ML-KEM ACVP fixtures                    COMPLETE
M2.7   ML-DSA ACVP fixtures                    COMPLETE
M2.8   SLH-DSA FIPS 205 ACVP fixture           COMPLETE
M2.9   Wycheproof malformed KEM negatives      COMPLETE
M2.10  provenance / source hardening           COMPLETE
M2.11  executable cargo/solc certification     BLOCKED
M2.12  GREEN                                   NOT ALLOWED YET
```

Reference providers are pinned around:
- ML-KEM-1024;
- ML-DSA-87;
- SLH-DSA-SHAKE-256s.

The authorization model includes:
- canonical chain/domain/policy/epoch/nonce/expiry/payload binding;
- FIPS context-aware verification;
- strict PQ_ONLY and MAX authorization shapes;
- replay-state protection;
- rotating keyset vs stable identity separation;
- opaque key handles;
- fallible RNG paths;
- structural key/signature/ciphertext length rejection;
- zeroize-on-drop secret material;
- bounded transport records;
- transcript commitments;
- message/time based rekey ceilings.

Privileged state coverage was expanded to transactions, validators, migrations, model/governance activation, service-plane checkpoints, Autopilot execution, payments, settlement lanes, storage proofs and cognitive evidence.

Cross-plane state hardening includes:
- canonical funding reservation identity;
- funded settlement -> service finality binding;
- exact storage proof -> archive receipt binding;
- conflict rejection for same-subject service finality;
- canonical replay subjects;
- one-shot terminal state transitions;
- Rust/Solidity FIPS-context parity fixtures;
- strict PQ Solidity account boundary;
- deterministic NEXUS score facade.

## 4. M2 evidence already present

The branch contains:
- ACVP subsets for ML-KEM, ML-DSA and SLH-DSA;
- Wycheproof negative subset;
- fixture manifest;
- static M2 security guard;
- Cargo lock verification script;
- Cargo metadata -> SPDX generator;
- pinned Rust 1.85 workflow gate;
- pinned/hash-verified solc 0.8.26 gate;
- reproducibility evidence hashing;
- dependency duplicate audit commands;
- artifact upload definitions.

The intended executable M2 gate is:

```
cargo fmt --all -- --check
cargo check --frozen --all-targets
cargo check --frozen --all-targets --features reference-pq
cargo clippy --frozen --all-targets --features reference-pq -- -D warnings -D clippy::all
cargo test --frozen --all-targets
cargo test --frozen --all-targets --features reference-pq
cargo test --frozen --doc --features reference-pq
cargo test --frozen --release --lib --features reference-pq
pinned solc 0.8.26 compile
resolved dependency/SBOM/duplicate audit
```

## 5. Current blocker

M2 is source-complete but not executable-certified.

The current branch head before this distillation was:
`286b36e70877f977e16e4db0527f5d7ca24f9ff8`.

GitHub Actions run #1189 / `35967798927` failed before any workflow step.

Both original jobs exposed:
`steps=null`
and
`logs_url=null`.

A rerun of failed jobs was requested on 2026-09-24 and accepted by GitHub. The replacement jobs failed identically before first step.

The current local execution container also lacks:
- cargo;
- rustc;
- rustup;
- solc;
- forge.

Outbound DNS/network for direct git clone is unavailable.

Cargo.lock is not committed.

Therefore a real M2 GREEN cannot be claimed yet.

## 6. Scope decision

Do not keep expanding M2 architecture.

The source hardening line is frozen because additional structs/guards now have sharply diminishing value. The next useful work after executable certification is live multi-process networking.

## 7. Critical path to MVP

```
M2 executable GREEN
    ->
M3 PQ P2P / DHT
    ->
M4 model-shard network
    ->
M5 real three-node distributed inference
    ->
M6 Byzantine verification + slashing
    ->
M7 KV/cache failover
    ->
M8 closed compute/storage/verifier economics
    ->
M9 heterogeneous CPU/GPU runtime
    ->
M10 reproducible testnet/demo
    ->
MVP
```

## 8. M3 — next engineering milestone

Goal: turn authenticated transport primitives into a real network.

Required:
- stable node IDs;
- node identity registry;
- PQ-authenticated handshake;
- bootstrap discovery;
- Kademlia-style routing/DHT;
- signed provider records;
- live rekey;
- peer scoring;
- replay/downgrade/wrong-key rejection;
- partition/reconnect handling;
- deterministic protocol negotiation.

Acceptance:

```
Node A
Node B
Node C
   ->
bootstrap
   ->
PQ handshake
   ->
peer discovery
   ->
DHT routing
   ->
put/get/provider lookup
   ->
restart/reconnect
   ->
PASS
```

Do not count mocks or a single-process simulation as M3 completion.

## 9. M4 — model-shard network

A model must stop being assumed to exist as one local file.

Required:
- immutable model manifest;
- model root;
- shard roots;
- provider records;
- shard retrieval protocol;
- integrity verification;
- availability/failover;
- caching and dedup integration;
- model-version activation.

Acceptance:
a fresh node that knows only a model root can find providers, retrieve required shards, reject corruption and build a valid execution plan.

## 10. M5 — first real AI-blockchain proof

This is the milestone where the project stops being merely a blockchain with AI-oriented state structures.

Minimum topology:

```
User input
  ->
Node A: stage 0
  ->
activation transfer
  ->
Node B: intermediate stage
  ->
activation transfer
  ->
Node C: final stage
  ->
result commitment
  ->
SYNERGY chain
```

Must use a real model, not mocks.

Mandatory metrics:
- TTFT;
- tokens/sec;
- activation bytes;
- network latency;
- stage latency;
- per-node compute time;
- end-to-end latency;
- retry/failover cost.

## 11. M6 — Byzantine AI verification

A deliberately dishonest worker must be detected.

Required:
- independent verifier selection;
- verification challenges;
- mismatch/counterexample evidence;
- verifier uniqueness;
- quorum/finality rules;
- slashable bonds;
- one-shot slashing;
- false-accusation protection.

Acceptance:
a wrong result is rejected, a bad worker is slashed once, correct workers are paid and replayed evidence fails.

## 12. M7 — KV/cache resilience

Long-running generation must survive worker loss.

Required:
- checkpointed KV state;
- replica receipts;
- version/sequence protection;
- reconstruction/failover;
- migration of active inference state.

Acceptance:
kill an active worker and resume from a valid replicated checkpoint or fail deterministically from a known boundary.

## 13. M8 — closed economic loop

A funded inference job must pay actual providers.

Recipients:
- compute worker;
- storage provider;
- verifier;
- network/service fee lanes.

Must reject:
- double funding;
- double consumption;
- double settlement;
- duplicate slash;
- reward overflow.

Acceptance:
canonical funded state fully reproduces realized payouts and penalties.

## 14. M9 — heterogeneous runtime

Minimum:
- CPU worker;
- GPU worker;
- quantized/GGUF execution path;
- capability-aware scheduler.

NEXUS/GGUF/DeepCompress work belongs here as runtime optimization, not consensus dependency.

Consensus-critical roots must remain reproducible and backend-independent where required.

## 15. M10 — reproducible MVP testnet

Required:
- genesis;
- persistent database;
- 3+ node launcher;
- bootstrap;
- account/wallet tooling;
- PQ transactions;
- model publish/fetch;
- inference submit;
- distributed execution;
- verification;
- storage;
- funding;
- settlement;
- slashing;
- metrics;
- restart/recovery;
- reproducible build and README commands.

## 16. Final MVP demo

A successful public MVP demonstration should prove all of the following in one run:

1. Start 3–5 clean SYNERGY nodes.
2. Establish PQ-authenticated connections.
3. Form the DHT automatically.
4. Publish a small real model by commitment.
5. Distribute model shards.
6. Fund and submit an inference job.
7. Schedule model stages across multiple workers.
8. Execute the real model.
9. Intentionally fail or corrupt one worker.
10. Detect or recover from the failure.
11. Pay correct workers/providers/verifiers.
12. Slash a dishonest worker exactly once.
13. Commit canonical job/model/result/verification/storage/economic roots.
14. Report TTFT, tokens/sec, activation traffic, stage latency, rewards and slashes.
15. Reproduce the complete demo from documented commands.

## 17. Explicit post-MVP scope

Do not block the first MVP on:
- thousands of validators;
- global mainnet scale;
- full DAO;
- all EVM/Bitcoin/Lightning bridges;
- every payment rail;
- mobile wallet ecosystem;
- QE/macroeconomic issuance core;
- full world agent economy;
- 70B-on-phone execution.

Those are later expansion tracks.

## 18. Immediate continuation rule

The immediate engineering sequence is:

1. obtain a real executable Rust/Solidity runner;
2. generate and commit the exact Cargo.lock;
3. pass every frozen M2 gate and retain artifacts;
4. mark M2 GREEN only from real evidence;
5. immediately start M3 with three independent processes;
6. avoid reopening M2 architecture unless executable tests uncover a concrete defect.

That is the shortest honest path from the current repository state to a demonstrable post-quantum AI-blockchain MVP.
