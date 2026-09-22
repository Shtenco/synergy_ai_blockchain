# M2 — Real Post-Quantum Crypto Evidence Ledger

Date: 2026-09-22  
Branch: `feat/distributed-ai-foundation-v1-20260922`

## Objective

M2 is complete only when the protocol uses real standards-conformant post-quantum primitives through explicit provider boundaries and produces executable positive/negative evidence.

Target standards:

- FIPS 203 — ML-KEM-1024
- FIPS 204 — ML-DSA-87
- FIPS 205 — SLH-DSA-SHAKE-256s

The project does not implement these algorithms from scratch.

## Selected reference implementations

Pinned Rust dependencies behind Cargo feature `reference-pq`:

- `ml-kem = 0.3.2`
- `ml-dsa = 0.1.1`
- `slh-dsa = 0.1.0`

The reference provider is an integration/testing dependency, not an assertion of independent cryptographic audit.

Upstream references:

- https://docs.rs/ml-kem/0.3.2/ml_kem/
- https://docs.rs/ml-dsa/0.1.1/ml_dsa/
- https://docs.rs/slh-dsa/0.1.0/slh_dsa/

## Implemented in this branch

### 1. Real ML-KEM-1024 adapter

`src/pq_reference.rs` implements `MlKem1024Provider` using RustCrypto ML-KEM.

Properties:

- real ML-KEM-1024 key generation;
- validated public-key import through `EncapsulationKey::new`;
- real encapsulation and decapsulation;
- preferred 64-byte decapsulation-key seed representation;
- secret seeds stay behind opaque local handles;
- corrupted ciphertext test expects implicit rejection to produce a different shared secret;
- wrong handles and invalid public-key lengths fail closed.

The protocol-facing trait still accepts only a secret-key handle, not raw private key bytes.

### 2. Real ML-DSA-87 verification

`ReferencePqSignatureVerifier` parses an encoded ML-DSA-87 public key and signature and invokes the standards-based verification path.

Tests include:

- real generated key;
- real sign/verify;
- modified message rejection;
- modified signature rejection.

### 3. Real SLH-DSA-SHAKE-256s verification

The same provider parses SLH-DSA-SHAKE-256s public keys/signatures and invokes the verification implementation.

Tests include:

- real generated key;
- real sign/verify;
- modified message rejection.

### 4. Authorization domain separation

`src/pq.rs` now defines a canonical signed envelope containing:

- protocol prefix/version;
- chain ID;
- authorization domain;
- authorization policy;
- epoch;
- nonce;
- expiry;
- payload commitment.

A signature from one domain/policy cannot be reused as the same canonical message under another domain/policy.

### 5. Anti-downgrade authorization structure

Hybrid authorization now fails closed unless:

- evidence count exactly matches the selected policy;
- every required scheme appears exactly once;
- no extra scheme is present;
- no duplicate scheme is present;
- public key bytes are non-empty;
- signature bytes are non-empty.

### 6. Scheme-routed verifier

`SchemeRoutedVerifier` explicitly sends:

- secp256k1 / Ed25519 → classical backend;
- ML-DSA-87 / SLH-DSA-SHAKE-256s → PQ backend.

The implementation does not use an ambiguous `backend_a || backend_b` fallback.

### 7. Real dual-PQ authorization test

The reference-provider tests create one real ML-DSA-87 signature and one real SLH-DSA-SHAKE-256s signature over the exact same canonical `PQ_ONLY` authorization message.

The test also attempts verification against an `ONLINE` canonical message and requires failure.

### 8. MAX three-lane anti-downgrade test

The reference test suite now constructs a `MAX` authorization containing:

- a separately routed classical secp256k1 test lane;
- a real ML-DSA-87 signature;
- a real SLH-DSA-SHAKE-256s signature.

The authorization succeeds only when all three lanes validate. Corrupting only the classical lane must make the entire authorization fail. The PQ verifier is not permitted to satisfy the classical lane.

### 9. External-vector provenance pinned

`docs/PQ_TEST_VECTOR_PROVENANCE.md` records reproducible provenance for the external evidence gate:

- NIST ACVP commit `65370b861b96efd30dfe0daae607bde26a78a5c8` for ML-KEM / ML-DSA vector lineage used by the selected RustCrypto suites;
- SPHINCS+ commit `eccdc43a99e194f52d5ef0e4030ef4dd1e31828b` for the documented SLH-DSA KAT lineage;
- exact target parameter sets and import rules.

The external evidence is now stronger than provenance-only preparation:

- ML-KEM-1024 ACVP deterministic encapsulation fixture is wired to exact ciphertext/shared-key assertions;
- ML-DSA-87 ACVP valid/invalid verification cases are wired to the real verifier;
- SLH-DSA-SHAKE-256s FIPS 205 ACVP `tgId=36`, valid `tcId=491` and invalid `tcId=492`, are wired to the real verifier;
- a pinned Wycheproof ML-KEM-1024 negative subset rejects 1567-byte and 1569-byte ciphertexts at the provider boundary.

These are executable tests in source. They are **not yet execution evidence** until Rust actually runs them.

### 10. FIPS 204/205 cryptographic context separation

The protocol now has a second, cryptographic domain-separation layer in addition to the canonical signed message.

`AuthorizationEnvelope::fips_signature_context(policy)` derives a bounded context from:

- protocol/version prefix `SYNERGY/PQ-FIPS-CONTEXT/V1`;
- chain ID;
- authorization domain;
- authorization policy.

Epoch, nonce, expiry and payload commitment remain in the canonical message, so the FIPS context is a stable protocol namespace rather than a per-signature transcript.

A separate `ContextSignatureVerifier` boundary ensures:

- ML-DSA-87 uses FIPS 204 `verify_with_context`;
- SLH-DSA-SHAKE-256s uses FIPS 205 `try_verify_with_context`;
- context length greater than 255 bytes fails closed;
- Secp256k1 / Ed25519 lanes are not reinterpreted as having FIPS context semantics;
- scheme routing still prevents a PQ backend from satisfying a classical lane.

Reference-provider tests now require correct-context acceptance, wrong-context rejection, tampered-message rejection, 256-byte-context rejection, and a dual-PQ `PQ_ONLY` authorization where both PQ lanes share the exact derived context. Changing domain or policy changes the context and must invalidate the authorization.

Implementation/test-definition commits:
- `db4c8b79fbc22c03b7e843890814e1f93b469588`
- `c08296bd8c1c1ffd628daecf2047321936a9d77d`
- `2de22b4fbcf6efca67da559beda790ea0c5ec318`
- `ee87ec4f3c27f69e57e2ac7c8629fa40085b4b61`

This closes M2.10b at implementation/test-definition level. It is not execution evidence until the Rust test commands actually run.

## CI gate

The workflow now contains two intended test passes:

```text
cargo test --all-targets
cargo test --all-targets --features reference-pq
```

### Current infrastructure status

As of 2026-09-22, the latest post-vector commit `fb3b3e86fa281f542be0d79fe6a7ae9437821c31` triggered workflow run `35764263197`. The sole job `rust-core` concluded `failure`, but GitHub returned no executed steps and no job log blob. Therefore this is still an infrastructure scheduling failure, not a Rust test failure.

GitHub Actions runs for this branch terminate before any step starts:

- runner_id = 0
- runner_name = empty
- steps = []
- conclusion = failure after only a few seconds

Therefore this branch does **not** claim executable CI success yet.

A local fallback was attempted, but the working container has no Rust toolchain and external DNS/package installation is unavailable.

This is tracked as an infrastructure validation blocker, not proof of a source-code failure.

Explicit runner-image experiment:

- workflow changed from `ubuntu-latest` to `ubuntu-24.04`;
- run `35767666405` still completed `failure`;
- job `rust-core` still exposed no executed steps and no log URL.

Therefore the blocker is not currently attributable to the floating `ubuntu-latest` alias.

## Dependency provenance boundary

`docs/M2_DEPENDENCY_PROVENANCE.md` now records:

- exact direct crate pins and feature selection;
- `rust-version = 1.85`;
- the source repositories used by the reference crypto line;
- the explicit prohibition on fabricating a `Cargo.lock`;
- the exact commands required to generate the lockfile, inspect locked metadata and run locked tests.

This closes direct dependency provenance at source level, but transitive resolution/SBOM remain blocked until Cargo executes.

## Still required before M2 can become GREEN

- executable Rust compilation on Rust >= 1.85;
- all default-feature tests green;
- all `reference-pq` tests green;
- official/traceable known-answer vectors committed or reproducibly fetched in CI;
- ~~ML-KEM negative/Wycheproof vector subset~~ — committed and wired to tests; execution pending;
- ~~ML-DSA known-answer and invalid-signature vector subset~~ — committed and wired to tests; execution pending;
- ~~SLH-DSA ACVP/KAT subset~~ — FIPS 205 valid/invalid subset committed and wired to tests; execution pending;
- ~~explicit context/domain separation tests~~ — implementation and real-provider tests committed; execution pending;
- dependency lockfile committed;
- SBOM/dependency provenance record;
- secret-key zeroization evidence for production-selected backend;
- independent cryptographic review before real asset custody.

## M2 maturity

Current state: **YELLOW / implemented, executable evidence blocked by runner infrastructure.**

M3 must not be declared complete or production-ready until this gate is resolved.


## Static release-tag compatibility audit

The context-separation implementation was re-audited against the exact upstream release tags selected in `Cargo.toml`, rather than against moving `master` APIs:

- `ml-dsa/v0.1.1` → commit `f75d5b829948988f18d9463f286805fb9410bcdd`;
- `slh-dsa/v0.1.0` → commit `81526ad2de17bf58295d97d796ff35bc991ab1b7`;
- `ml-kem/v0.3.2` → commit `440768245bba59784b504269cb3087a6c21af45c`.

This audit found one real source-level compatibility defect before executable CI could report it: ML-DSA 0.1.1 exposes context-aware deterministic signing on `ExpandedSigningKey::sign_deterministic`, while `SigningKey`'s ordinary `Signer` implementation supports only an empty context. The tests were corrected in commit `74ea0f80b3678ee3aa756789e3af96acf5a86fa2` to use:

```text
SigningKey
  -> expanded_key()
  -> sign_deterministic(message, context)
```

Exact-tag inspection also confirmed the currently used ML-KEM 0.3.2 APIs (`EncapsulationKey::new`, `encapsulate_deterministic`, `DecapsulationKey::from_seed`) and SLH-DSA 0.1.0 context APIs (`try_sign_with_context`, `try_verify_with_context`).

This reduces known compile risk but is still not a substitute for `cargo test`.

## Lockfile bootstrap gate

Workflow commit `320e777c35d100d6433796e6b58e3fc83998935b` changes CI so the first actually assigned hosted runner will:

1. use an existing committed `Cargo.lock`, or generate a bootstrap lockfile with `cargo generate-lockfile` when absent;
2. emit `cargo metadata --locked --format-version 1` to `m2-cargo-metadata.json`;
3. run `cargo test --locked --all-targets`;
4. run `cargo test --locked --all-targets --features reference-pq`;
5. upload `Cargo.lock` and locked metadata as a workflow artifact even when later tests fail.

A generated artifact does **not** itself close M2.10c. The exact Cargo-produced lockfile must be committed to the branch, followed by a later run that succeeds using that committed lockfile.

Workflow run `35771551276` (run #175) was queued from this commit. Its result must be treated as pending until real job steps and logs exist.
