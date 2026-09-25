# SYNERGY Protocol Convergence V1

Status: active integration specification
Canonical authority repository: `Shtenco/synergy_ai_blockchain`
Branch: `feat/protocol-convergence-pi-pq-evm-syna-v1-20260925`

## 1. Purpose

This specification converges three previously separate SYNERGY lines into one protocol:

1. post-quantum cryptography and SYNERGY's proprietary PI-based research algorithm;
2. a post-quantum EVM execution layer interoperable with Ethereum L1 and EVM L2 networks;
3. SYNA issuance/reward for cryptographically verified useful AI inference.

The convergence rule is: one canonical protocol authority, many repository adapters. No repository may silently fork consensus, issuance, signature policy, settlement truth, or inference-verification semantics.

## 2. Existing canonical baseline

The current `main` already contains:

- standard PQ production lane based on ML-KEM / ML-DSA / SLH-DSA;
- dual-PQ authorization and anti-downgrade policy;
- PQSmartAccount and EVM-facing verifier interfaces;
- post-quantum transport/session commitments;
- distributed inference commitments;
- verifier receipts and aggregation;
- malicious-worker detection;
- slashing;
- compute settlement;
- checkpoint finalization;
- local four-node failover evidence.

These remain non-negotiable security foundations.

## 3. Cryptographic lanes

### 3.1 Standard production lane

The production trust root remains standards-based:

- ML-KEM-1024 for key establishment;
- ML-DSA-87 for signatures;
- SLH-DSA-SHAKE-256s for independent signature diversity;
- SHA-2/SHA-3/HKDF/ChaCha20-Poly1305 where already defined by the protocol profile.

No proprietary primitive may silently replace this lane.

### 3.2 SYNERGY PI-PQ lane

The proprietary PI-based algorithm is introduced initially as:

`EXPERIMENTAL / NON-AUTHORITATIVE / FAIL-CLOSED`

Until its exact source and historical provenance are recovered and independently analyzed, it may only be used for:

- additional commitment material;
- domain-separated challenge generation;
- experimental identity/evidence binding;
- optional third-lane verification experiments;
- benchmark and cryptanalysis fixtures.

It MUST NOT by itself authorize:

- asset transfer;
- validator action;
- treasury action;
- bridge mint/burn;
- SYNA issuance;
- consensus finalization.

Promotion to an authoritative cryptographic lane requires all of:

1. exact source recovery and immutable source hash;
2. written primitive specification;
3. deterministic reference implementation;
4. known-answer tests;
5. structural attack analysis;
6. collision/preimage/signature/KEM security claims stated precisely;
7. external cryptographic review;
8. side-channel analysis where relevant;
9. cross-language test vectors;
10. explicit migration and downgrade rules.

## 4. PQ-EVM and Ethereum compatibility

SYNERGY must be EVM-compatible without reducing its PQ security policy.

Compatibility target is split into three surfaces.

### 4.1 Ethereum transaction/execution compatibility

Required:

- canonical chain-id semantics;
- Ethereum-compatible address/account model where exposed;
- transaction envelope adapters;
- ABI compatibility;
- receipts/logs/events parity;
- deterministic gas accounting;
- revert/return-data semantics;
- precompile registry and collision policy;
- JSON-RPC compatibility surface;
- contract deployment/call parity tests.

PQ authorization is additive. Legacy Ethereum authorization must never automatically downgrade a PQ-only SYNERGY account.

### 4.2 Ethereum L1 interoperability

Required bridge proof path:

`ETH L1 event/state proof -> verified bridge adapter -> SYNERGY canonical receipt -> PQ finalization`

No mint based only on an RPC response.

Required gates:

- finalized block policy;
- chain-id binding;
- proof-of-origin;
- replay protection;
- deposit uniqueness;
- withdrawal uniqueness;
- bounded reorg policy;
- explicit bridge accounting;
- emergency halt.

### 4.3 EVM L2 interoperability

Each L2 adapter must declare its trust model explicitly.

At minimum:

- rollup/validium/sidechain class;
- canonical L1 settlement chain;
- finality source;
- message bridge contract identity;
- proof/challenge assumptions;
- sequencer dependence;
- withdrawal delay/finality.

Base-derived code in `synergy_2chain_qe` is reusable for EVM/fork/bridge testing, but does not by itself prove generic ETH-L2 interoperability.

## 5. SYNA: Proof of Useful Inference

SYNA is not specified as wasteful hash mining.

The canonical issuance event is a finalized useful-inference proof.

Pipeline:

`InferenceJob`
-> funded/reserved execution
-> worker execution
-> output commitment
-> independent verifier receipts
-> aggregate verdict
-> optional failover/recompute
-> settlement
-> checkpoint finalization
-> SYNA reward authorization
-> mint

### 5.1 Required mint invariant

`NO FINALIZED VERIFIED INFERENCE -> NO SYNA INFERENCE MINT`

A valid reward claim must bind at least:

- chain id;
- protocol epoch;
- job id;
- model root;
- execution-plan root;
- input commitment;
- output commitment;
- verifier-set root;
- settlement root;
- final checkpoint root;
- worker identity;
- useful-work accounting;
- reward-policy version;
- unique reward nonce/claim id.

### 5.2 Verdict rules

MATCH:
- worker may receive SYNA reward;
- verifier/storage rewards may be paid according to policy;
- no slash.

MISMATCH:
- dishonest worker receives zero inference reward;
- slash may be consumed once;
- verifier/failover participants may be rewarded only under explicit policy.

INCONCLUSIVE:
- no worker inference mint;
- no slash unless a separate provable offense exists.

### 5.3 Anti-double-mint

A reward claim is one-shot.

The chain must reject reuse of:

- job id;
- finalized checkpoint reward claim;
- settlement root;
- reward nonce;
- slash evidence.

### 5.4 Emission policy separation

Proof of useful inference proves eligibility, not arbitrary emission size.

Emission rate must be a separately versioned deterministic policy with:

- per-job cap;
- per-epoch cap;
- global supply cap or explicit uncapped monetary constitution;
- difficulty/usefulness weighting rules;
- verifier quorum requirements;
- anti-Sybil controls;
- self-dealing rules;
- governance upgrade delay.

No AI model may choose its own reward.

## 6. Cross-repository authority map

### `synergy_ai_blockchain`
Canonical authority:
- consensus;
- PQ policy;
- PI-PQ experiment interface;
- EVM/PQ execution profile;
- inference proof commitments;
- slashing;
- final checkpoint;
- SYNA mint authorization.

### `synergynet`
Adapter authority:
- transport/discovery/routing only;
- carries authenticated inference and bridge messages;
- never mints SYNA and never grants validator authority.

### `synergy_agi_olga` / `synergy_gllm_nexus`
Compute/research:
- model execution;
- stage plans;
- model manifests;
- inference evidence generation;
- no direct mint authority.

### `synergy_pay_system`
Financial settlement:
- payment/ledger/idempotency patterns;
- settlement receipts;
- external payment truth;
- no independent SYNA consensus mint.

### `synergy_2chain_qe`
Reusable EVM/bridge economic lab:
- Foundry;
- Base fork;
- bridge/mint/burn/treasury mechanics;
- EVM/L2 adapter test material;
- no canonical consensus authority.

### `synergychain`
Product/application integration:
- node UI/business/autopilot surfaces;
- wallet/user experience;
- no cryptographic or issuance fork.

### `synergy_system`
Federation/architecture authority:
- repository map;
- ownership contracts;
- must reference this protocol profile as the canonical blockchain authority.

## 7. Rollout order

### Gate P1 — recover PI algorithm
- locate exact source in repository history/branches/artifacts;
- hash-pin it;
- write spec and vectors;
- classify what primitive it actually is;
- keep non-authoritative.

### Gate P2 — Ethereum compatibility harness
- ETH transaction/receipt/log/gas vectors;
- JSON-RPC compatibility tests;
- L1 proof adapter;
- Base L2 adapter;
- cross-client fixtures.

### Gate P3 — SYNA useful-inference reward
- canonical reward claim type;
- one-shot claim state;
- deterministic reward-policy interface;
- MATCH/MISMATCH/INCONCLUSIVE tests;
- slash/reward interaction tests;
- supply/accounting invariants.

### Gate P4 — federation adapters
Propagate only interfaces/manifests to participating repositories.

No bulk copy of consensus code into all repositories.

### Gate P5 — multi-host testnet
On distinct machines:

PQ handshake
-> discovery
-> model distribution
-> inference
-> malicious worker
-> verifier detection
-> failover
-> KV resume
-> settlement
-> SYNA reward claim
-> mint
-> common checkpoint
-> ETH L1/L2 bridge roundtrip test.

## 8. Security blockers discovered during audit

A repository currently contains a tracked file named `base-mainnet-deployer.key`.

Its secret contents are intentionally not reproduced here.

Before any real bridge/L1/L2/SYNA deployment:

- treat that key as compromised;
- move assets/authority away from it;
- revoke any roles;
- rotate deployer/admin credentials;
- purge future usage;
- use secret storage / hardware-backed signing where possible.

Deleting the file from the latest commit is not sufficient to make the old key secret again.

## 9. Definition of done

Protocol Convergence V1 is GREEN only when:

- PI implementation provenance is recovered and classified;
- standard PQ lane remains mandatory and executable;
- ETH-compatible execution vectors pass;
- at least one ETH L1 proof path passes;
- at least one EVM L2 adapter passes;
- verified inference deterministically authorizes a one-shot SYNA reward;
- dishonest/inconclusive inference cannot mint worker rewards;
- double mint and double slash are rejected;
- all participating repositories consume one pinned protocol profile;
- four physical hosts reproduce the full flow.
