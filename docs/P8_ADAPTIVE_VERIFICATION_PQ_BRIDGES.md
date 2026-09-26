# P8 — Adaptive Verification + Post-Quantum Omnichain Bridges

## Scope

P8 reduces Proof-of-Useful-Inference verification cost while preserving strict full recomputation, and hardens BTC / Ethereum-family bridge claims so source-chain proofs are locally verified and SYNERGY-side authorization is post-quantum.

## Adaptive verification

- deterministic shard sampling from challenge seed + verifier identity;
- canonical shard-set root bound to worker execution_trace_root;
- PQ-authorized verifier bundles with replay protection;
- clean sampled MATCH can authorize the adaptive reward path;
- mismatch, insufficient quorum or strict policy escalates to the existing full-recompute verifier;
- strict_full_recompute remains available for deterministic full assurance.

Sampling is probabilistic fraud detection. A future zkML/STARK layer can reduce this residual assumption.

## Bitcoin mainnet bridge

Implemented:
- 80-byte header parsing;
- double-SHA256;
- compact target and PoW verification;
- parent-hash continuity;
- 2016-block retarget validation;
- target-timespan clamp;
- median-time-past;
- cumulative post-checkpoint chainwork;
- best-chain adoption / competing-tip rejection;
- transaction Merkle inclusion;
- confirmation count on the adopted best proved chain.

The protocol checkpoint is pinned to Bitcoin Core mainnet policy at height 966143, including minimum chainwork and assumevalid hash.

A BitcoinVerifiedTxProof can only be produced through BitcoinMainnetChainState::verify_tx_and_adopt.

## Ethereum consensus light client

The bridge does not trust an RPC-provided finalized state root.

Implemented:
- weak-subjectivity bootstrap policy;
- mainnet genesis validators root;
- Altair/Bellatrix/Capella/Deneb/Electra/Fulu fork versions;
- 512-member sync committee validation;
- >2/3 participation threshold;
- BLS12-381 aggregate verification with blst;
- finality Merkle branch verification;
- current/next sync committee rotation;
- SSZ BeaconBlockHeader roots;
- execution payload commitment proof;
- finalized execution state-root extraction;
- sealed EthereumFinalizedExecutionAnchor creation only from verified light-client state.

## Ethereum L1 / L2 / L3 settlement

The Ethereum proof engine includes Keccak-256, canonical RLP, MPT inclusion, account/storage proofs and EVM block-header state-root extraction.

Recursive settlement supports L1, L1→L2 and L1→L2→L3.

Typed settlement adapters:

### DirectStateRoot
Only for contracts that explicitly commit the child execution state root.

### OpStackOutputRootV0
Verifies:
outputRoot = keccak256(version || stateRoot || messagePasserStorageRoot || blockHash)

The parent storage proof must commit the resulting output root.

### ArbitrumNitroConfirmedAssertion
Verifies Nitro assertion inputs, binds GlobalState.blockHash to the supplied L2 header RLP, extracts the child stateRoot from that header, recomputes the assertion hash, and requires the parent-chain proved commitment to match it.

Every settlement-scheme preimage has its own canonical commitment, preventing type confusion.

### Trusted settlement profile registry

L2/L3 claimants cannot freely choose a settlement contract, storage slot or adapter. Each supported parent/child chain pair is defined by a consensus-configured EvmSettlementProfile containing:
- parent and child chain IDs;
- settlement contract address;
- commitment storage slot;
- expected proved contract codeHash;
- allowed settlement adapter kind;
- profile version.

The canonical EvmSettlementProfileRegistry root is bound by PqBridgeValidationContext. A proof is rejected if its registry root differs from the configured root or if the proved account codeHash differs from the profile. The registry can contain multiple approved networks while each recursive proof consumes only the profile for its actual hops.

## PQ authorization

Every external→SYNERGY claim binds:
- exact source proof;
- settlement scheme and parameters;
- source asset root;
- destination account;
- amount;
- unique claim id;
- bridge direction.

AuthorizationDomain::BridgeProof uses PQ-only authorization and one-shot replay consumption.

## External-chain cryptographic boundary

Bitcoin and Ethereum L1 do not natively verify ML-DSA / SLH-DSA transactions today.

Therefore inbound external→SYNERGY can be proof-driven and PQ-authorized on SYNERGY. Outbound SYNERGY→BTC/ETH cannot honestly be called end-to-end native PQ unless the destination chain verifies a PQ proof/signature, for example via a dedicated zk/PQ verifier contract. Bridging does not make Bitcoin or Ethereum themselves post-quantum.

## Remaining GREEN gates

Before PR #29 may be marked GREEN:
- cargo fmt --all -- --check
- cargo check --all-targets
- cargo test --all-targets
- cargo clippy --all-targets -- -D warnings
- cargo test --all-targets --features reference-pq
- live Ethereum finalized light-client fixture
- live eth_getProof fixture against that finalized state
- live OP Stack settlement fixture
- live Arbitrum Nitro / Orbit confirmed-assertion fixture
- final Windows regression when DESKTOP-C8GUE41 returns

GitHub-hosted portable jobs are currently failing before checkout with zero job steps and zero artifacts; this is treated as infrastructure failure, not as a code GREEN or code failure.
