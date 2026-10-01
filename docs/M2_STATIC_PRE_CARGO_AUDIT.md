# M2 static pre-Cargo audit

Status: source-level audit only. This document does not claim compilation or test success.

## Scope

This audit covers the pinned post-quantum reference stack before a working Cargo runner is available:

- `ml-kem = 0.3.2`
- `ml-dsa = 0.1.1`
- `slh-dsa = 0.1.0`
- `rand = 0.8.5`
- crate MSRV: Rust `1.85`

## Exact direct-crate MSRV

| crate | pinned version | upstream rust-version |
| --- | ---: | ---: |
| synergy-pq-evm-core | 0.2.0 | 1.85 |
| ml-kem | 0.3.2 | 1.85 |
| ml-dsa | 0.1.1 | 1.85 |
| slh-dsa | 0.1.0 | 1.75 |

The minimum direct-crate ceiling is therefore Rust 1.85. CI explicitly installs Rust 1.85.0 before lock resolution, check and test execution.

## Expected dependency-generation splits

The reference feature intentionally combines two RustCrypto generations.

Expected duplicate families:

- `rand_core 0.6.x`: stable SLH-DSA 0.1.0 and `rand 0.8.5`;
- `rand_core 0.10.x`: ML-KEM 0.3.2 / ML-DSA 0.1.1 stack;
- `signature 2.3.0-pre.x`: SLH-DSA 0.1.0;
- `signature 3.x`: ML-DSA 0.1.1;
- `hybrid-array 0.2.0-rc.x`: SLH-DSA 0.1.0;
- `hybrid-array 0.4.x`: ML-KEM / ML-DSA.

These duplicates are not by themselves defects. They become actionable only if values or trait objects cross generation boundaries.

The current provider avoids those crossings:

- SLH key generation/tests use `rand 0.8.5` / `rand_core 0.6`;
- ML-KEM/ML-DSA key generation uses each crate's own fallible `Generate::try_generate()` path;
- a `rand 0.8` RNG is not passed into ML-KEM/ML-DSA `rand_core 0.10` traits.

Expected unification:

- ML-KEM 0.3.2 and ML-DSA 0.1.1 both require `module-lattice 0.2.3`; a second module-lattice generation would require review.
- Both use the 0.4 generation of `hybrid-array`; exact patch selection remains a lockfile concern.

CI captures `cargo tree --locked --duplicates` so the actual resolver result can be compared with this expectation.

## Production panic-path audit

The production portion of `src/pq_reference.rs` is guarded against local panic-style control flow.

Forbidden before the `#[cfg(test)]` boundary:

- `.unwrap(`
- `.expect(`
- `panic!(`
- `debug_assert!(`
- infallible `.fill_bytes(`

Key generation is now fallible:

- ML-KEM uses `MlKem1024DecapsulationKey::try_generate().ok()?`;
- ML-DSA uses `SigningKey::<MlDsa87>::try_generate().ok()?`;
- capability IDs use `try_fill_bytes(...).ok()?`.

Opaque-handle allocation attempts are bounded to 32 iterations instead of an unbounded collision/repeated-zero loop.

## Opaque capability typing

ML-KEM:

- `MlKem1024Provider` has an associated `SecretHandle` type;
- `MlKemSecretHandle` is a nominal newtype with private bytes;
- arbitrary byte slices cannot be passed as a reference-provider secret handle.

ML-DSA signing:

- `PqSigningKeyHandle` is a nominal newtype with private bytes;
- it intentionally does not implement `Debug`;
- the provider derives the public key from the same stored private-key object referenced by the handle.

This prevents accidental KEM/signing handle interchange and reduces capability leakage through formatting.

## Exact serialized-size gates

Before upstream parsing, the provider rejects wrong lengths:

| primitive | object | bytes |
| --- | --- | ---: |
| ML-KEM-1024 | encapsulation key | 1568 |
| ML-KEM-1024 | ciphertext | 1568 |
| ML-DSA-87 | verifying key | 2592 |
| ML-DSA-87 | signature | 4627 |
| SLH-DSA-SHAKE-256s | verifying key | 64 |
| SLH-DSA-SHAKE-256s | signature | 29792 |

The upstream parsers remain authoritative for semantic validation after the length gate.

## Context and downgrade invariants

The public authorization path is `verify_envelope_authorization`.

It derives both:

- the canonical signed message;
- the FIPS 204/205 context;

from the same `AuthorizationEnvelope + AuthPolicy`.

Raw helpers remain crate-internal:

- `verify_authorization`;
- `verify_authorization_with_context`.

The no-Cargo guard checks these visibility and naming invariants to detect accidental API downgrade.

## Automated no-Cargo guard

`scripts/m2_static_guard.py` checks:

- exact direct dependency pins;
- Rust 1.85 declaration;
- envelope-bound verifier presence;
- raw verifier crate visibility;
- nominal KEM/signing handles;
- exact serialization size gates;
- absence of production panic-style patterns;
- fallible key generation;
- fallible RNG;
- bounded handle generation.

The guard can pass without Cargo, but it is not compilation evidence.

## Remaining pre-GREEN requirements

Still mandatory:

1. Cargo-generated `Cargo.lock`;
2. `cargo metadata --locked`;
3. `cargo tree --locked` and duplicate review;
4. reproducible SPDX output;
5. Rust 1.85 `cargo check --locked --all-targets`;
6. Rust 1.85 `cargo check --locked --all-targets --features reference-pq`;
7. `cargo test --locked --all-targets`;
8. `cargo test --locked --all-targets --features reference-pq`.

M2 remains YELLOW until those execution gates pass.


## Additional protocol-boundary findings

The continued static audit found that cryptographic correctness alone did not yet guarantee correct protocol use.

Closed in this pass:

- actual transaction validation previously used the no-context aggregate verifier; it now uses FIPS context;
- transaction validation now requires expected chain ID, expected nonce and caller-required authorization policy;
- generic authorization verification now requires expected chain/domain/policy/epoch/nonce and checks expiry against current time;
- no-context aggregate verification is compiled only for tests;
- PQ key/signature lengths are rejected structurally before provider dispatch;
- ML-KEM convenience encapsulation using upstream `UnwrapErr(SysRng)` was replaced with a fallible randomness path;
- KEM and signing handles are nominal capabilities rather than byte aliases;
- transport identity/shared-secret lengths and transcript presence are checked;
- rekey policy is bounded and invalid configurations fail closed;
- ML-KEM/classical transport secrets are nominal zeroizing non-Clone wrappers.

These changes reduce the remaining M2 uncertainty primarily to executable dependency resolution, compilation and runtime tests. Инстансы пересозданы 29.09.2026: e2-1 `51.170.89.241`, e2-2 `129.151.138.7`.


## Latest cross-plane hardening pass

Additional source-level invariants closed before executable Cargo/Solidity runners are available:

- payment finality now commits a funded-settlement root, not a bare settlement-batch root;
- funded settlement binds the exact authorized batch root, funding-consumption root, item count and funding-receipt count;
- transport record nonce issuance enforces both message-count and time-based rekey limits;
- transport replay-state commitment stores the exact transcript hash for every consumed session ID;
- storage dedup catalog roots must advance whenever new unique bytes are introduced;
- erasure placement must match the source archive's erasure policy;
- storage provider bid duration may not exceed the remaining archive lifetime;
- compression savings fail closed when archival transformation expands data;
- cognitive reward arithmetic rejects over-cap totals rather than silently clipping them;
- Solidity PQ verifier ABI is context-aware and size-strict;
- the native PQ smart account is strict dual-PQ with expiry/epoch binding and no deployment-time single-PQ downgrade;
- NEXUS Solidity profile v1 exposes only the implemented Score mode;
- CI now contains a separate Solidity compilation job pinned to solc 0.8.26
  (`commit.8a97fa7a`) with SHA-256
  `d5f23436f443edb85d8e76906d12f0a86ce0490e7663a9e608efeb7a93f149ef`.

Latest checked GitHub Actions run #1096 (run id 35908721491) parsed both
`rust-core` and `solidity-core`, but both jobs failed before their first step
with `steps=null` and `logs_url=null`. This is still runner provisioning
failure, not repository execution evidence.

M2 remains YELLOW.
