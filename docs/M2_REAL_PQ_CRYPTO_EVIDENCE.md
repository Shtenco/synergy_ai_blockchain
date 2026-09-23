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


## Transaction, transport and shared-secret hardening

The static M2 pass found and closed additional protocol-level gaps after the initial cryptographic provider work.

### Expected domain/policy are now state-bound

Commits `8cda4e509481896be2a1430c9861543b08ea0099` and `a51eb5142f3c8bb97b5f6b1cbd3ccf0c6bf02af9` require the verifier/caller to state the expected authorization domain and policy. A cryptographically valid signature from another action domain or a weaker/different policy cannot be accepted merely because its own signed fields are internally self-consistent.

### ML-KEM encapsulation RNG is fail-closed

Exact `kem 0.3` source review showed that the convenience `Encapsulate::encapsulate()` path uses `UnwrapErr(SysRng)`, which can panic on system RNG failure.

Commit `1e3e00169be48d3f0726a6496b5725341b7375bb` removes that production path. The reference provider now obtains 32 bytes through fallible `OsRng::try_fill_bytes`, converts them to ML-KEM `B32`, and invokes the exact-version `encapsulate_deterministic` implementation.

### PQ evidence sizes are rejected before provider dispatch

Commit `157c47784a5c80b6e0bcf68b0d19108c4463bdf5` moves ML-DSA/SLH serialization sizes into the protocol layer and makes `HybridAuthorization::validate_structure` reject malformed PQ key/signature lengths before cryptographic parsing.

### Hardened transport boundary

Commit `7452b4c22dd09c49e08efd5ff6aeef4dab7910eb` adds protocol constants and transport validation for:

- ML-KEM-1024 public key: 1568 bytes;
- ML-KEM-1024 ciphertext: 1568 bytes;
- ML-KEM shared secret: 32 bytes;
- nonzero transcript hash;
- nonempty classical KEX material when `TransportPolicy::Hybrid` is selected.

Commit `98cd3799266faffb449fe57fc14e39fdbfccc6c0` makes rekey policy fail closed and caps a configured policy at:

- `2^20` messages;
- 300 seconds.

Zero limits or limits above those maxima are invalid, and `should_rekey` returns true for an invalid policy rather than silently disabling rotation.

### Typed zeroizing shared-secret boundary

The initial transport hardening zeroized secret vectors from `HybridSharedSecret::drop`. A further audit identified that plain public `Vec<u8>` fields remained too easy to copy or mutate before drop.

Commits `84b6722bed0257a7aff3f2a329f24929449abd78` and `923d529d7e883b820243950e0265c5e9b71865a9` replace the ML-KEM shared secret with a nominal fixed-size `MlKemSharedSecret([u8; 32])` and the variable-length classical secret with a nominal `SecretBytes(Vec<u8>)`.

Both secret wrappers:

- keep their storage private;
- do not implement `Clone`;
- use redacted `Debug`;
- zeroize their backing memory on drop.

`MlKem1024Provider::encapsulate` and `decapsulate` now return `MlKemSharedSecret` instead of a raw `Vec<u8>`.

This closes the transport shared-secret lifecycle at source level, pending executable Rust confirmation.

### Runner remains the execution gate

The latest explicitly inspected workflow in this audit line, run `35795271723` (#262), still concluded failure with `steps=[]`. No source checkout, Python guard, Rust toolchain, Cargo resolver, compilation or tests executed.

Therefore all items above are source/test-definition evidence only. M2 remains YELLOW.


## M2 static pre-Cargo audit: current result

The static audit uncovered and corrected several defects before a Rust runner became available:

- duplicate `MAX_CLASSICAL_PUBLIC_KEY_BYTES` / `MAX_CLASSICAL_SIGNATURE_BYTES` definitions that would have been a guaranteed Rust compile error;
- stale ML-KEM tests using ordinary equality after secret-bearing types intentionally lost `PartialEq/Eq`;
- transaction authorization lacked explicit authorization epoch and expiry fields;
- the static guard itself truncated production-provider inspection at an early helper-level `#[cfg(test)]`;
- the guard temporarily contained contradictory legacy-KEX limits and premature `PASS` output;
- raw ML-KEM shared-secret temporaries could have skipped explicit zeroization on an early wrapper-conversion return path;
- `HybridSharedSecret.transcript_hash` was mutable from outside the module after transcript derivation.

All of those issues have been corrected at source level.

An equivalent connector-side evaluation of the corrected production-boundary checks confirmed the previously failing fallible-keygen/RNG invariants after the guard boundary fix. This is useful source-level evidence, but it is **not** a substitute for Rust compilation.

Latest GitHub Actions run checked during this pass: `35796955251` (run #359). Its sole `rust-core` job again completed with `failure`, `steps=null` and `logs_url=null`, so no repository command executed.


## Static pre-Cargo audit continuation

Additional source-level defects and hardening completed in this pass:

- transaction authorization now signs and validates `authorization_epoch` and `authorization_expires_at`, closing the gap between generic envelope replay protection and the actual transaction path;
- classical authorization evidence is bounded before backend verification;
- classical transport public-key and shared-secret material is bounded;
- ML-KEM temporary raw shared-secret buffers are explicitly zeroized on every return path;
- the transport transcript is canonical, SHA-256 committed and policy-bound;
- the derived transcript commitment is private/read-only after `HybridSharedSecret` construction;
- duplicate classical-evidence constants that would have prevented Rust compilation were removed;
- tests were repaired after secret-bearing types intentionally lost ordinary `PartialEq/Eq`;
- static-guard production slicing was corrected to use the actual `#[cfg(test)] mod tests` boundary;
- contradictory transport-size assertions and premature `PASS` markers in the static guard were removed.

A connector-side evaluation of the corrected critical invariants found the previously reported four failures were all caused by the old guard slicing bug; after commit `cfc2b89527199b8fd09012e29574ea1225af10f3`, fallible KEM key generation, fallible RustCrypto key generation, fallible capability RNG and bounded allocation attempts are all present in the production section.

The static sanity sweep also found no repeated top-level constant/type definitions after the duplicate-cap fix. Repeated method names observed in different `impl` blocks are valid Rust and not symbol conflicts.

### Hosted-runner rerun evidence

Workflow run `35796955251` was manually rerun after the source hardening. The rerun created job `106979201432`, which again completed with:

```text
conclusion = failure
steps = null
logs_url = null
```

Therefore even an explicit job rerun fails before runner provisioning. This further supports classifying M2.11 as an external GitHub Actions execution blocker rather than a repository test failure.


## M2 transport-cryptography hardening continuation

The M2 transport boundary now additionally includes:

- explicit `CRYPTO_PROFILE_VERSION` binding across authorization, FIPS context, transactions and transport transcripts;
- canonical ordered signature-suite binding;
- exact Secp256k1/Ed25519/PQ evidence encodings and structural prefilters;
- exact MAX-policy authorization byte budget (`37,173` bytes);
- explicit classical KEX registry (X25519 / compressed Secp256k1) and algorithm identifiers;
- explicit ML-KEM and HKDF algorithm codes;
- transcript-bound rekey policy;
- transcript-bound ML-KEM recipient role;
- network-id / epoch / fresh session-id transcript anti-replay context;
- one-shot `TransportReplayGuard` session consumption;
- validation-before-replay-consumption ordering, preventing malformed local input from burning a session ID;
- exact 32-byte classical shared-secret boundary;
- canonical HKDF-SHA256 transport session-key derivation;
- opaque zeroizing `TransportSessionKey`;
- independent transcript/HKDF known-answer vectors.

The external capability handles for ML-KEM and ML-DSA are now non-Copy **and non-Clone**.
Providers store separate internal capability identifiers which also zeroize on drop.

The HKDF implementation has one explicit residual memory-hardening limitation:
upstream RustCrypto HKDF/HMAC internal PRK state does not provide zeroize-on-drop.
SYNERGY minimizes its lifetime and never stores it persistently, but M2 must not claim that
library-internal PRK memory is guaranteed to be wiped.


## Privileged-domain identity and state binding

The M2 source boundary now enforces every currently defined `AuthorizationDomain`
through a concrete state-aware path:

- `Transaction`: sender account equals canonical authorization keyset commitment;
- `ValidatorVote`: validator ID is a stable commitment to ML-DSA + SLH-DSA identity keys; PQ-only validator mode forbids retained legacy key material;
- `BridgeMigration`: legacy ownership proof plus PQ-only authorization; target PQ identity equals the authorization keyset commitment and the target account ID equals that PQ identity;
- `ModelUpgrade`: MAX authorization from the registered authority keyset, expected activation epoch, and closed parent/index lineage;
- `InferenceReceipt`: PQ-only worker authorization from the registered worker keyset, bound to the stage assignment;
- `Governance`: MAX authorization from the registered governance authority keyset, bound to proposal ID, governance state root and activation epoch.

`authorization_keyset_commitment` can derive the same identity root directly
from ordered public keys without signature bytes, allowing keysets to be
registered before an authorization proof exists.

AI verification aggregation is also hardened: `VerificationAggregate::validate_receipts`
requires a canonical strictly ordered unique verifier-receipt set and recomputes
the receipt root and verdict counters rather than trusting aggregate metadata.

The detailed matrix is committed in `docs/M2_AUTHORIZATION_COVERAGE.md`.

### Latest runner evidence

At branch head before this documentation commit, workflow run `35835746225`
(run #565) again produced one `rust-core` job, id `107098658051`, with:

```text
status = completed
conclusion = failure
steps = null
logs_url = null
```

No repository step executed. M2 therefore remains YELLOW and no compilation or
test PASS is claimed.


## Consensus and service-plane privileged-state closure

The authorization registry now also covers two consensus-critical state transitions that previously had structural validation but no cryptographic authority gate:

- `AuthorizationDomain::ConsensusActivation` (protocol code 8): `ConsensusActivationAuthorization` requires `AuthPolicy::Max`, the expected authority keyset, expected activation block, and state-aware chain/epoch/nonce/expiry validation. Its payload commitment binds the model manifest hash, implementation hash and every gas-schedule field.
- `AuthorizationDomain::ServicePlaneCheckpoint` (protocol code 9): `ServicePlaneCheckpointAuthorization` requires `AuthPolicy::Max`, the expected authority keyset, expected service-plane epoch, and state-aware chain/authorization-epoch/nonce/expiry validation. Its payload commitment binds every canonical payment/storage/cognitive/autopilot/data-availability/finality root.

Old authorization-domain codes 1–7 were left unchanged. The protocol-code uniqueness test and static guard include the new domains.

This expands the M2 source-level privileged-state matrix from AI/transaction/governance paths to protocol activation and canonical service-plane state. It remains pending executable Rust confirmation.


## Extended privileged-state and determinism hardening

The M2 source boundary now covers additional existing protocol state transitions rather than limiting PQ authorization to the cryptographic helper layer.

New authorization domains and enforcement paths added during this pass:

- `ConsensusActivation` (code 8): MAX authority, implementation/model/gas-schedule commitment, future activation delay.
- `ServicePlaneCheckpoint` (code 9): MAX authority, exact next service-plane epoch, all canonical service roots.
- `AutopilotExecution` (code 10): MAX owner authority, budget reservation/policy/call commitment, exclusive expiry.
- `PaymentIntent` (code 11): payer identity equals authorization keyset; economic fields/rails/compliance bound.
- `SettlementBatch` (code 12): PQ-only lane authority, exact monotonic lane sequence, accounting/availability/finality bound.
- `StorageProof` (code 13): PQ-only registered provider keyset over object/challenge/proof/served bytes.
- `CognitiveEvidence` (code 14): PQ-only CognitiveNode keyset over request/model/input/output/proof/price/policy evidence.

Additional deterministic arithmetic/source fixes:

- consensus gas sizing now uses checked `usize -> u64` conversions;
- canonical network length prefixes are fallible;
- canonical transaction signing preimages are fallible and unavailable for oversized calldata;
- inference stage counts are protocol-bounded and stage indexes use checked conversion;
- model-lineage vector lengths use checked `usize -> u64` conversion;
- storage and service-plane ratios fail closed instead of truncating or saturating overflow.

Autopilot delegated-policy validation now rejects invalid windows, duplicate capabilities, zero commitments, per-action limits above epoch limits, and proposals that outlive their policy.

All items remain source/test-definition evidence until a real Rust runner executes the frozen Cargo gates.


## Replay-state, minimal feature surface and profile registry hardening

Additional M2 source-level controls added in the latest pass:

- `AuthorizationReplayState` now provides a canonical stateful `verify_and_consume` path. It validates chain/domain/policy/epoch/nonce/expiry through the existing envelope verifier and advances the nonce only after successful authorization. Nonce overflow fails closed; epoch rotation is forward-only.
- `slh-dsa = =0.1.0` now disables default features and explicitly enables only `alloc`.
- `rand = =0.8.5` now disables default features and explicitly enables only `getrandom`; `std` / `std_rng` are not part of the allowed reference-provider feature surface.
- the locked-feature verifier requires those exact resolved feature sets and rejects unexpected crypto features.
- `AutopilotBudgetReservation` now contains an explicit `owner_account`; the MAX-authorized execution path requires reservation owner, expected owner and authorization keyset commitment to be identical, and the owner is included in the signed execution commitment.
- `AuthScheme::Ed25519` remains protocol code 2 for append-only registry stability but is explicitly inactive in crypto profile v1. No active policy may silently start using it under profile v1.
- the stable local reference signer remains ML-DSA-only. SLH signing custody is external-provider/HSM-only until a reviewed stable zeroizing SLH backend is executable-tested.

These are source/test-definition controls only; executable Cargo evidence remains blocked by zero-step GitHub Actions runner provisioning.
