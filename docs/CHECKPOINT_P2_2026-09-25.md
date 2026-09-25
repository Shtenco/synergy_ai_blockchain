# PROTOCOL CONVERGENCE CHECKPOINT P2

Branch: `feat/protocol-convergence-pi-pq-evm-syna-v1-20260925`

Status: CODE COMPLETE / EXECUTION PENDING

## Added after P1
- Ethereum/EVM compatibility profile;
- explicit L1 / optimistic rollup / zk rollup / validium / sidechain classes;
- chain-id and settlement-chain binding;
- bridge-contract commitment;
- finalized proof receipt requirement;
- explicit rejection of legacy downgrade for PQ-only accounts;
- deterministic SYNA emission policy;
- per-job emission cap;
- per-epoch emission cap;
- optional global max supply;
- forward-only emission epochs;
- useful-work threshold and bounded reward derivation.

## Security invariants
- RPC response alone is never bridge finality;
- PQ authorization is additive, never downgraded by EVM compatibility;
- useful inference establishes reward eligibility, not arbitrary reward quantity;
- AI output never chooses its own unbounded emission;
- PI-PQ remains non-authoritative until source recovery/audit.

## Evidence state
- GitHub Actions attempted but runner jobs terminated before any step (`steps=[]`);
- physical Rust runner DESKTOP-C8GUE41 currently offline;
- therefore no GREEN claim for P2 yet.

## Next gate P3
- executable cargo test evidence;
- exact historical PI source recovery;
- Ethereum canonical transaction/receipt/log fixture vectors;
- ETH L1 proof verifier adapter;
- Base L2 adapter and trust-model manifest;
- bind SynaEmissionPolicy amount to SynaRewardClaim consumption;
- supply state commitment into final checkpoint.
