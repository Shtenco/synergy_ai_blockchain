# PROTOCOL CONVERGENCE CHECKPOINT P3

Branch: `feat/protocol-convergence-pi-pq-evm-syna-v1-20260925`
PR: #24
Status: SOURCE HARDENED / PHYSICAL EXECUTION PENDING

## What is now implemented

### PI-PQ
- `src/pi_pq.rs`
- explicit fail-closed experimental lane;
- immutable provenance/spec/vector/input/output commitments;
- cannot authorize consensus;
- cannot authorize assets;
- cannot authorize SYNA mint.

The exact historical PI primitive has not been re-invented.

Legacy inventory identifies the strongest current source candidate:

`SYNERGY_ORCH/l1/hash16d.py` (~9.4 KB, 5 historical copies)

with adjacent historical L1 lineage:
- `ledger.py`
- `node.py`
- `qe_engine.py`
- `sinergy_dex.py`

The migration inventory maps this lineage to `synergy_ai_blockchain`, but the actual source is not yet present in the current canonical repository tree. Recovery remains required before PI-PQ can advance.

## Ethereum / EVM

Existing historical branch:
`feat/sinergy-l1-base-qe-v1-20260904`

contains:
- PQSmartAccount;
- IPQVerifier;
- Base/SINERGY cross-domain messenger;
- Base relayer;
- QE/economic adapters.

Important classification:

The historical Base <-> SINERGY bridge is a **trusted-relayer V1**, not a trustless final bridge.

Its own documentation already defines the stronger upgrade path:
source finality proof
-> lock/burn/message-event verification
-> replay guard
-> destination execution.

Therefore Protocol Convergence V1 preserves trusted relayer only as a transitional compatibility adapter.

Production bridge authority requires `EvmBridgeProofReceipt` or a future stronger light-client/proof implementation. An RPC response alone is not finality.

## SYNA historical lineage

Historical `synergy_ai_financial_system` branches contain:
- Polygon fork/preflight work;
- treasury and graph policy contracts;
- liquidity growth experiments;
- tax/burn token mechanics;
- two-chain solvency experiments;
- anti-MEV and solver-auction research.

Useful pieces are economic research inputs, not automatic mint authority.

Canonical V1 rule:

`NO FINALIZED VERIFIED USEFUL INFERENCE -> NO SYNA INFERENCE MINT`

## Canonical SYNA pipeline

Exact verifier receipts
-> canonical aggregate recomputation
-> MATCH verdict
-> compute settlement root
-> finalized checkpoint root
-> deterministic reward policy
-> one-shot reward claim
-> bounded supply transition
-> post-mint supply-state root.

Current code:
- `src/syna_reward.rs`
- `src/syna_emission.rs`

Security improvements in P3:
- removed duplicate SYNA implementation;
- removed duplicate PI/EVM module exports;
- mint path recomputes verifier aggregate from exact receipt set;
- reward amount is derived by policy, not selected by AI/model/caller;
- mismatch cannot mint worker reward;
- inconclusive cannot mint worker reward;
- claim is one-shot;
- supply is capped by job/epoch/global policy;
- supply update is transactional with claim consumption;
- every successful mint exposes deterministic `supply_state_root`.

## Security blockers

### Physical execution
GitHub Actions continues to fail before job execution:
- rust-core: no steps/no logs;
- solidity-core: no steps/no logs.

Physical runner:
`DESKTOP-C8GUE41`
is currently offline.

Therefore P3 is NOT marked GREEN yet.

### Existing tracked key
`Shtenco/synergy_usds` contains a tracked file named:
`base-mainnet-deployer.key`

Treat the corresponding key as compromised:
- revoke roles;
- move assets/authority;
- rotate deployer/admin keys;
- never reuse it for SYNA/PQ-EVM/bridge deployment.

## Next executable gate P4

On physical runner:

1. `cargo fmt --check`
2. `cargo check --all-targets`
3. `cargo test --all-targets`
4. `cargo test --all-targets --features reference-pq`
5. execute Solidity compile gate;
6. verify new PI-PQ fail-closed tests;
7. verify EVM compatibility tests;
8. verify SYNA canonical-receipt mint tests;
9. verify mismatch/inconclusive no-mint;
10. verify double-mint rejection;
11. verify epoch/global supply caps;
12. verify post-mint supply-state root.

Only after P4 passes should PR #24 be merged and the protocol profile pinned into the rest of the SYNERGY repository federation.

## Cross-repository rollout after merge

Do not copy consensus code into every repository.

Each participating repository must consume a pinned adapter manifest:

- `synergynet`: transport/discovery adapter;
- `synergy_agi_olga`: inference worker adapter;
- `synergy_gllm_nexus`: model/research adapter;
- `synergy_pay_system`: settlement adapter;
- `synergy_ai_financial_system`: legacy SYNA/tokenomic adapter;
- `synergy_2chain_qe`: EVM/L2 economic test adapter;
- `synergychain`: wallet/product/node UI adapter;
- `synergy_system`: federation authority map.

Consensus, cryptographic policy, reward authorization and SYNA issuance authority remain only in `synergy_ai_blockchain`.
