# PROTOCOL CONVERGENCE CHECKPOINT P4 — SOURCE HARDENED

Branch: `feat/protocol-convergence-pi-pq-evm-syna-v1-20260925`
Canonical PR: #24
Execution status: PHYSICAL RUNNER REQUIRED / NOT GREEN YET

## Canonical code now present

### Standard PQ production lane
Remains unchanged:
- ML-KEM-1024
- ML-DSA-87
- SLH-DSA-SHAKE-256s
- dual-PQ authorization
- anti-downgrade / replay / context binding

### PI-PQ research lane
`src/pi_pq.rs`
- fail-closed;
- evidence/provenance commitments only;
- cannot authorize consensus/assets/SYNA;
- exact historical PI source is still required.

Strongest legacy source candidate remains:
`SYNERGY_ORCH/l1/hash16d.py`

The inventory proves historical copies existed, but current GitHub/Drive search has not recovered the raw source. No substitute algorithm is invented.

### Ethereum / EVM compatibility
`src/evm_compat.rs`
now separates:
1. declared EVM compatibility profile;
2. hash-pinned executable compatibility evidence;
3. finalized bridge proof receipt;
4. one-shot bridge replay state.

A verified compatibility root requires non-zero commitments for:
- transaction vectors;
- receipts/logs vectors;
- gas vectors;
- JSON-RPC vectors;
- ABI vectors;
- precompile registry;
- client matrix.

Boolean claims alone are not sufficient evidence.

Network policies:
- `protocol/evm/ethereum-mainnet-v1.json`
- `protocol/evm/base-mainnet-v1.json`

Ethereum chain id: 1.
Base chain id: 8453.
Base settlement chain: Ethereum 1.

Historical trusted relayer remains transitional only.
Production bridge policy is proof-required and replay-protected.

### SYNA Proof-of-Useful-Inference
Canonical modules:
- `src/syna_reward.rs`
- `src/syna_emission.rs`
- `src/syna_state.rs`

Pipeline:

exact verifier receipts
-> canonical aggregate recomputation
-> MATCH
-> compute settlement
-> finalized inference checkpoint
-> deterministic emission policy
-> one-shot reward claim
-> bounded supply transition
-> native worker balance transition
-> supply-state + mint-transition commitments.

Security properties:
- caller cannot fabricate aggregate counters;
- mismatch cannot mint worker reward;
- inconclusive cannot mint worker reward;
- model/caller cannot choose arbitrary reward;
- per-job cap;
- per-epoch cap;
- optional global supply cap;
- backward epoch rejected;
- double claim rejected;
- partial state update avoided by transactional preflight;
- worker account and total supply transition are checked independently;
- every accepted transition has a deterministic root.

## Cross-repository rollout staged

Draft adapter PRs:
- synergynet #20
- synergy_agi_olga #28
- synergy_gllm_nexus #5
- synergy_pay_system #22
- synergy_ai_financial_system #24
- synergy_2chain_qe #2
- synergychain #23
- synergy_system #51

Adapters point to canonical PR #24 / branch until physical GREEN.
They MUST be pinned to the immutable merge SHA only after canonical merge.

## Current execution blocker

Latest GitHub Actions attempts continue to fail before workflow execution.
Both rust-core and solidity-core return no steps and no job logs.

Physical runner `DESKTOP-C8GUE41` is offline.

Therefore this checkpoint is SOURCE HARDENED, not GREEN.

## Required physical gate before merge

```bash
cargo fmt --check
cargo check --all-targets
cargo test --all-targets
cargo test --all-targets --features reference-pq
```

Then Solidity compile/security gate and explicit validation of:
- PI fail-closed tests;
- EVM evidence-root tests;
- EVM bridge finality test;
- EVM bridge replay rejection;
- SYNA canonical receipt recomputation;
- MATCH mint;
- MISMATCH no mint;
- INCONCLUSIVE no mint;
- reward self-selection rejection;
- double-mint rejection;
- epoch/global supply caps;
- native account transition;
- supply-state root.

Only after real PASS may PR #24 merge.
