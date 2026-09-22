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


## Cross-repository hosted-runner diagnosis

The zero-step failure pattern is not isolated to `synergy_ai_blockchain`.

Observed on the same GitHub account:

- `Shtenco/synergychain`, run `34547147861`, 2026-09-11: GitHub-hosted jobs actually executed `Set up job`, `actions/checkout@v4`, Foundry setup and test steps. One job completed successfully, proving hosted runners were provisioned for this account at that time.
- `Shtenco/synergychain`, run `34956850725`, 2026-09-15: both jobs concluded failure with `steps=[]`.
- `Shtenco/synergy_midas_ai_trading_system`, run `35453264669`, 2026-09-19: job concluded failure with `steps=[]`.
- `Shtenco/synergy_ai_blockchain`, runs including `35767770906` and `35771551276`, 2026-09-22: job concludes failure with `steps=[]`, no downloadable log blob, and zero billable Ubuntu milliseconds.

For run `35767770906`, the Actions timing API reports:

```text
UBUNTU total_ms = 0
job duration_ms = 0
workflow run_duration_ms = 4000
```

This evidence strongly localizes the current blocker above repository source/test execution: the GitHub-hosted VM is not being provisioned. Changing `ubuntu-latest` to `ubuntu-24.04` did not change the failure mode.

Therefore M2.11 remains an infrastructure blocker. No source-code failure should be inferred from these zero-step runs.


## Secret-key zeroization hardening

ML-KEM handle storage was hardened in commit `869cd817cbe2b29d86eba8706ecef3bba90f4cf0`: the provider stores `MlKem1024DecapsulationKey` directly instead of a raw seed array. Because the pinned `ml-kem/v0.3.2` dependency is compiled with `zeroize`, its own `Drop` implementation clears the sensitive decapsulation components.

Commit `8a39fed2d52edeab8a419f4ef24fc5c33c29c146` adds a local lifecycle test requiring key removal to revoke the opaque handle and make subsequent decapsulation fail closed.

This partially advances the remaining zeroization gate. It does **not** close production key custody for every algorithm: SLH-DSA 0.1.0 signing keys do not carry an equivalent zeroize-on-drop guarantee, and the current provider does not retain SLH private keys.


## Locked dependency graph and SPDX preparation

M2.10d now has an executable generation path without fabricating transitive data.

Commits:

- `4feeddfa8b301cd7b3fe7f615597676afefa7658` — standard-library SPDX 2.3 generator from Cargo metadata;
- `26ddbadc653d6fc5c3fd4e7974498ccb18c7e009` — reproducible timestamp/namespace derivation using `SOURCE_DATE_EPOCH` and metadata SHA-256;
- `e65880ed11a3399605a9350ef7f831d5b24990ca` — CI emits locked metadata, locked dependency tree and SPDX artifact.

When a runner is actually provisioned, CI will produce:

```text
Cargo.lock
m2-cargo-metadata.json
m2-cargo-tree.txt
m2-spdx.json
```

The SPDX document is generated only from `cargo metadata --locked`; no package or dependency edge is invented by source code. Its document namespace is bound to the SHA-256 of the exact metadata input, while its creation time is derived from the git commit timestamp through `SOURCE_DATE_EPOCH`.

This closes the **generator/preparation** side of M2.10d. The actual locked graph and SBOM remain pending until Cargo executes.

Workflow run `35781369356` (run #210) again failed with `steps=[]`; therefore none of these generation steps executed.


## Opaque signing custody and handle hardening

M2 signing custody now uses an opaque-handle boundary.

Commits:

- `5338e1e4d6414609f4869fde5ebca4f678ddf82f` — introduces `ContextSignatureSigner`, `PqSigningKeyHandle` and envelope-derived signing;
- `0cdd27fddb34aa7a70e841ee1519d2f997d62ab7` — adds zeroizing in-memory ML-DSA-87 signer;
- `c91b55cf6931569052e10f4ccb382983878b7fb5` / `c8c41ca894ce0996847fd3a5542d14ad7217afc4` — bind the public key to the same opaque handle instead of accepting caller-supplied public-key bytes;
- `fd983e1523ffb03664b10a5ab1ce5b29e751b836` — replaces restart-repeating counter handles with nonzero random 256-bit capability IDs and collision checks;
- `23350f08f90e6e05ed0a1fa0693182a6a5209a91` — tests nonzero/unique live handles.

The reference signer supports ML-DSA-87 only. It intentionally rejects SLH-DSA signing because the pinned stable `slh-dsa 0.1.0` lacks a signing-key zeroize-on-drop guarantee.

ML-DSA signing-key lifecycle is therefore **complete at source level** for the reference provider, pending executable Rust confirmation.

SLH-DSA verification remains implemented and ACVP-backed, while production signing custody remains blocked on either:

- a reviewed zeroizing stable SLH backend;
- an HSM/OS-keystore/remote-signer provider implementing the same opaque-handle interface;
- or an explicitly reviewed dependency upgrade once Cargo execution is available.


## Static pre-Cargo hardening pass

The M2 source-level audit was extended beyond vector correctness.

### Fallible RNG and panic-free provider boundary

Commit `a6f0600ee76206dcd2db3c534150b71dadd49966` removes infallible system-RNG paths from production PQ key generation:

- ML-KEM decapsulation-key generation uses `try_generate()`;
- ML-DSA signing-key generation uses `try_generate()`;
- opaque capability IDs use `try_fill_bytes()`;
- provider generation returns `Option` on RNG failure.

Commit `0aa4a4d259a507d662cf347cc46fbb2d3a44ba2d` bounds capability-ID allocation to 32 attempts. Commit `5fe87ef74de50f7578fb6332d92b58cead9db08a` fixes zero-ID retry semantics so a zero draw is retried rather than terminating immediately.

### Exact serialized-size fail-closed gates

Commit `e6f9616d4317a3cd8ab20029fde587802d5664c9` rejects wrong-size objects before upstream parsing:

- ML-KEM-1024 public key: 1568 bytes;
- ML-KEM-1024 ciphertext: 1568 bytes;
- ML-DSA-87 public key: 2592 bytes;
- ML-DSA-87 signature: 4627 bytes;
- SLH-DSA-SHAKE-256s public key: 64 bytes;
- SLH-DSA-SHAKE-256s signature: 29792 bytes.

### Nominal opaque capability types

Commits `16dd6990cc2676595979a21cebd52e52deec7915` and `b7d771f691639cbabd64ef5cfa2ebfd2a793030f` make the ML-KEM provider expose an associated secret-handle type backed by an opaque nominal `MlKemSecretHandle`.

Commits `e0a0513c36ba70b94fd3e7a31487f59865ac269f`, `295376cecebe21f0dcd3dcd8940acccc22eecb46` and `2271ddb3f3f10088bfc8af3daa1ea2b4e860b354` do the same for signing handles. Opaque handles intentionally do not implement `Debug`; test assertions were adjusted in `31e73289bff9f56f8adb0817e5fe34736aa26cad` so capability values are not required to be format-printable.

### Transaction-path anti-downgrade and replay binding

A later audit found that `PqEvmTransaction::validate` still called the legacy no-context authorization aggregator. Commit `ac916abf32c6683a390fe7ca7f4a541816b749dc` changes the actual transaction path to FIPS-context verification and adds a matching transaction signing helper.

Commit `5b10d7803679910a61fe7894eb05fc704df96f53` makes transaction validation state-aware:

- transaction chain ID must equal the expected chain;
- transaction nonce must equal the state-provided expected nonce;
- calldata bound remains enforced;
- cryptographic verification then uses the transaction canonical preimage plus FIPS context.

Commit `cd24e5758cfd09ca03d2c8a0aa2a26e694e44215` compiles the no-context authorization aggregator only under `#[cfg(test)]`. Production code therefore cannot call that aggregate downgrade path.

### Generic envelope replay/expiry enforcement

Commit `d8ad638a8055c052c68fc0728ed1df68ab0dcfc8` adds `AuthorizationValidationContext` and requires public envelope verification to check:

- expected chain ID;
- expected epoch;
- expected nonce;
- current time against `expires_at`.

The fields are therefore both signed and state-validated.

### Automated static guard

`scripts/m2_static_guard.py` was added in commit `bc92b8552352e150c97dfd96a631eb10140e0eb3` and wired before Rust setup in commit `71765ddbffc3f2632a25ada932d2443f03ca85c8`.

It guards dependency pins, Rust 1.85, context anti-downgrade, nominal handles, serialized sizes, fallible RNG, bounded handle generation, transaction state validation and generic envelope replay/expiry validation.

Workflow run `35795271723` (run #262) still failed with `steps=[]`, so even this Python-only post-checkout guard did not execute. The hosted-runner blocker therefore remains above checkout and source execution.
