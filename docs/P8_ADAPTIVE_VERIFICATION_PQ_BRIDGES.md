# P8 — Adaptive Verification + Post-Quantum Omnichain Bridges

## Scope

P8 has two linked goals:

1. reduce Proof-of-Useful-Inference verification cost without removing the existing strict full-recompute path;
2. make BTC and Ethereum-family bridge claims proof-driven and PQ-authorized on the SYNERGY side.

## Adaptive verification

The old strict verifier requires at least two independent full recomputations.

P8 adds a preferred adaptive path:

1. worker commits to an ordered execution shard set;
2. the canonical shard-set root is stored as the execution trace root;
3. each independent verifier receives deterministic sample indices derived from the challenge sample seed, challenge id, job id and verifier identity;
4. verifier recomputes only those shards;
5. the sample bundle is PQ-authorized in its own authorization domain;
6. if every required independent verifier matches the deterministic samples, the result may be reward-eligible under the adaptive policy;
7. any mismatch, insufficient verifier quorum or strict policy escalates to the existing full-recompute verifier;
8. only FullMatch is accepted after escalation.

The strict P7 verifier is not removed.

### Security boundary

Sampling is probabilistic fraud detection, not an absolute proof that every unsampled computation was correct.

For jobs that require deterministic full assurance, set strict_full_recompute=true.

A later zkML/STARK execution-proof layer can reduce this residual sampling assumption further.

## Bitcoin bridge

P8 adds a Bitcoin SPV verifier that checks:

- canonical 80-byte Bitcoin block headers;
- double-SHA256 block hash;
- compact target / PoW threshold;
- connected header ancestry;
- required confirmation count;
- transaction Merkle inclusion.

A verified BTC source proof is then bound into a SYNERGY PQ bridge claim.

Production hardening still requires trusted checkpoint / cumulative-work and Bitcoin difficulty-transition policy so a bridge cannot select an arbitrary low-work fork.

## Ethereum L1 / L2 / L3 bridge

P8 adds a local Ethereum proof engine:

- Keccak-256 implementation;
- canonical RLP parsing;
- Merkle-Patricia trie inclusion verification;
- EIP-1186-style account proof verification;
- storage proof verification.

The recursive settlement proof supports:

- Ethereum L1: finalized L1 state root;
- Ethereum L2: child state root proven from its L1 settlement contract storage;
- Ethereum L3: L3 state root proven in L2 settlement storage, whose L2 state root is in turn proven on L1.

Maximum initial recursive depth is two settlement hops: L1 -> L2 -> L3.

RPC is only a proof-data source. It is not treated as finality.

### Ethereum finality boundary

The current bridge core accepts a VerifiedEvmStateAnchor containing a finalized block/state root plus finality proof commitment.

Before production mainnet deployment this must be connected to an embedded Ethereum consensus light-client or an equivalently strong finalized-header verifier. A bare RPC finalized flag must not be considered sufficient.

## PQ authorization

Successful source-chain proof verification does not itself mint or unlock assets.

Every bridge claim is bound to:

- source proof root;
- source asset root;
- destination SYNERGY account;
- exact amount;
- unique claim id.

The claim is then authorized under AuthorizationDomain::BridgeProof using PQ-only authorization and consumed through replay state. Claim ids are one-shot.

## Implementation files

- src/adaptive_verification.rs
- src/bitcoin_bridge.rs
- src/ethereum_proof.rs
- src/pq_bridge.rs
- src/agent_reward.rs
- src/pq.rs
- src/lib_v2.rs

## Required GREEN gates

- cargo fmt --check
- cargo check --frozen --all-targets
- cargo test --frozen --all-targets
- cargo clippy --frozen --all-targets -- -D warnings
- cargo test --frozen --all-targets --features reference-pq
- BTC known-answer SPV tests
- Ethereum Keccak known-answer tests
- Ethereum MPT proof fixtures from real eth_getProof responses
- adaptive clean-sample test
- mismatch -> full-recompute escalation test
- strict-mode full-recompute test
- PQ authorization/replay tests for sample bundles
- PQ authorization/replay tests for bridge claims
- real BTC testnet proof
- real Ethereum finalized-state proof
- real L2 settlement-root proof
- real L3 settlement-root proof
