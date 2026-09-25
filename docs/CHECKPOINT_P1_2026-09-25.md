# PROTOCOL CONVERGENCE CHECKPOINT P1

Branch: `feat/protocol-convergence-pi-pq-evm-syna-v1-20260925`

## Completed
- frozen convergence architecture for PI-PQ + PQ-EVM + SYNA;
- standard ML-KEM / ML-DSA / SLH-DSA lane remains authoritative;
- added fail-closed PI-PQ evidence interface without inventing the missing historical primitive;
- PI lane cannot authorize consensus, assets or SYNA mint;
- added canonical SYNA Proof-of-Useful-Inference reward claim;
- reward claim binds chain/epoch/job/worker/model/inference/verifier/settlement/checkpoint;
- MATCH required for worker reward;
- one-shot claim state rejects double mint;
- mismatch cannot mint worker reward.

## Open P1 blocker
Exact historical PI-based primitive source/provenance has not yet been recovered from the inspected default branches and known PQ/EVM branches.

## Next gate P2
- recover PI source from deeper history/artifacts/other repositories;
- hash-pin source + specification + vectors;
- add Ethereum transaction/receipt/log/gas compatibility fixtures;
- add ETH L1 proof adapter;
- add Base/EVM-L2 trust-model adapter;
- add deterministic SYNA emission-policy caps and supply accounting;
- execute cargo test on a real runner and attach evidence.

Claim boundary: PI-PQ remains experimental/non-authoritative until exact source recovery and cryptanalysis.
