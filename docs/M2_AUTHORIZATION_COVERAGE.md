# M2 Privileged Authorization Coverage

Branch: `feat/distributed-ai-foundation-v1-20260922`

This document records the source-level authorization boundary for every privileged
domain currently present in `AuthorizationDomain`.

| Domain | State transition | Required policy | Identity binding | Replay / state binding |
|---|---|---|---|---|
| `Transaction` | EVM transaction authorization | caller-required `Online`, `Max` or `PqOnly` | `sender_account == authorization.keyset_commitment()` | chain, nonce, authorization epoch, exclusive expiry, max future horizon |
| `ValidatorVote` | consensus vote | `Max` in hybrid transition, `PqOnly` in native PQ mode | `validator_id` is stable commitment to ML-DSA + SLH-DSA public keys; evidence keys must match registered identity | chain, epoch, nonce, expiry, expected validator ID |
| `BridgeMigration` | legacy identity -> native PQ account | `PqOnly` plus independent legacy ownership proof | `pq_identity_commitment == authorization.keyset_commitment()`; `synergy_account_id == pq_identity_commitment` | chain, epoch, nonce, expiry, legacy proof |
| `ModelUpgrade` | model lineage/state upgrade | `Max` | expected authority keyset commitment | chain, epoch, nonce, expiry, activation epoch, lineage parent/index closure |
| `InferenceReceipt` | off-consensus AI worker receipt accepted by protocol | `PqOnly` | expected worker ID + expected worker keyset commitment | chain, epoch, nonce, expiry, assignment/worker/shard/input binding |
| `Governance` | privileged governance action | `Max` | expected governance authority keyset commitment | chain, epoch, nonce, expiry, proposal ID, governance state root, activation epoch |
| `VerificationReceipt` | independent AI verifier receipt | `PqOnly` | expected verifier ID + expected verifier keyset commitment | challenge ID, chain, epoch, nonce, expiry, verifier receipt payload |
| `ConsensusActivation` | activate consensus implementation/model/gas schedule | `Max` | expected consensus authority keyset commitment | chain, epoch, nonce, expiry, expected activation block, mandatory future activation delay, full activation commitment |
| `ServicePlaneCheckpoint` | commit canonical payment/storage/cognitive/autopilot/finality roots | `Max` | expected service-plane authority keyset commitment | chain, authorization epoch, nonce, expiry, exact next service-plane epoch, all canonical roots |
| `AutopilotExecution` | execute a value-bearing AI-prepared call | `Max` | owner account equals authorization keyset commitment | chain, reservation epoch, nonce, expiry, reservation root, policy root, proposal/call commitment |
| `PaymentIntent` | authorize payer payment intent | caller/account-required policy | payer account equals authorization keyset commitment | chain, epoch, nonce, expiry, amount, fee, rails, corridor, compliance commitment |
| `SettlementBatch` | authorize execution-lane settlement batch | `PqOnly` | expected lane authority keyset commitment | chain, epoch, nonce, expiry, lane ID, sequence, accounting/availability/finality commitments |
| `StorageProof` | storage provider proof receipt | `PqOnly` | expected provider ID + expected provider keyset commitment | chain, storage epoch, nonce, expiry, object/challenge/proof/served-byte commitment |
| `CognitiveEvidence` | CognitiveNode AI/symbolic evidence | `PqOnly` | node manifest PQ identity equals authorization keyset commitment | chain, epoch, nonce, expiry, request/node/model/input/output/proof/price/policy bindings |

## Keyset identity primitive

`authorization_keyset_commitment(policy, ordered_public_keys)` derives the
canonical identity root without requiring signature bytes. The same commitment
can therefore be registered before the first authorization proof is produced.

The commitment binds:

- crypto profile version;
- authorization policy;
- ordered algorithm suite;
- exact serialized public-key lengths;
- exact public-key bytes.

`HybridAuthorization::keyset_commitment()` delegates to the same primitive after
the proof structure has passed fail-closed validation.

## AI verification aggregation

`VerificationAggregate::validate_receipts` binds aggregate counters and
`receipt_root` to the canonical ordered receipt set.

Verifier IDs must be strictly ordered and unique. Each receipt must independently
validate against the challenge. Counts are recomputed with checked arithmetic;
caller-supplied aggregate counters are not trusted.

## M2 execution boundary

All entries above are source/test-definition evidence only until the pinned Rust
toolchain actually executes:

```text
cargo fmt --all -- --check
cargo check --frozen --all-targets
cargo check --frozen --all-targets --features reference-pq
cargo clippy --frozen --all-targets --features reference-pq -- -D warnings -D clippy::all
cargo test --frozen --all-targets
cargo test --frozen --all-targets --features reference-pq
cargo test --frozen --doc --features reference-pq
cargo test --frozen --release --lib --features reference-pq
```

M2 must remain YELLOW until real runner logs exist and the exact generated
`Cargo.lock` is committed and revalidated with `--frozen`.
