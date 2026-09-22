# M2 Dependency Provenance and Reproducibility Boundary

Date: 2026-09-22
Branch: `feat/distributed-ai-foundation-v1-20260922`

## Purpose

This document records the dependency boundary for the M2 post-quantum reference provider without pretending that unresolved transitive dependencies are already reproducible.

## Toolchain floor

`Cargo.toml` declares:

```toml
rust-version = "1.85"
```

This matches the minimum Rust requirement exposed by the selected RustCrypto ML-DSA generation and prevents CI from silently compiling the same source with an older unsupported compiler.

## Direct dependency pins

The post-quantum reference provider is feature-gated by `reference-pq`.

Exact direct versions:

| Crate | Version | Role | Enabled features / policy |
|---|---:|---|---|
| `ml-kem` | `0.3.2` | FIPS 203 ML-KEM-1024 | `default-features = false`, `getrandom`, `zeroize` |
| `ml-dsa` | `0.1.1` | FIPS 204 ML-DSA-87 | `default-features = false`, `alloc`, `getrandom`, `zeroize` |
| `slh-dsa` | `0.1.0` | FIPS 205 SLH-DSA-SHAKE-256s | exact version |
| `rand` | `0.8.5` | reference-test entropy plumbing | exact version |
| `hex` | `0.4.3` | test fixture decoding | dev dependency |
| `serde` | `1.0.228` | fixture decoding | dev dependency, `derive` |
| `serde_json` | `1.0.145` | fixture decoding | dev dependency |

All version requirements use exact `=` pins in `Cargo.toml`.

## Source provenance

Primary upstream repositories and exact release tags:

- ML-KEM: `RustCrypto/KEMs`, tag `ml-kem/v0.3.2`, commit `440768245bba59784b504269cb3087a6c21af45c`
- ML-DSA: `RustCrypto/signatures`, tag `ml-dsa/v0.1.1`, commit `f75d5b829948988f18d9463f286805fb9410bcdd`
- SLH-DSA: `RustCrypto/signatures`, tag `slh-dsa/v0.1.0`, commit `81526ad2de17bf58295d97d796ff35bc991ab1b7`
- external validation vectors: `usnistgov/ACVP-Server`, `C2SP/wycheproof`

External vector source commits and blob SHAs are recorded separately in
`docs/PQ_TEST_VECTOR_PROVENANCE.md`.

## What is reproducible now

Source-level reproducibility currently includes:

- exact direct crate versions;
- exact Cargo feature selection;
- exact Rust minimum version;
- exact external-vector source commits/blob SHAs;
- deterministic committed fixture contents;
- explicit two-command CI test gate.

## What is NOT yet reproducible

There is currently no generated `Cargo.lock`.

Therefore the project does **not** yet claim exact transitive dependency resolution or a complete software bill of materials.

The following remain blocked until Cargo runs successfully:

1. `cargo generate-lockfile`;
2. commit the resulting `Cargo.lock` without hand-editing;
3. verify `cargo metadata --locked --format-version 1`;
4. capture the full resolved dependency graph;
5. generate a machine-readable SBOM from the locked graph;
6. run both required test commands using the committed lockfile.

## Required executable gate

The exact sequence for M2.10c/M2.10d/M2.11 is:

```bash
cargo generate-lockfile
git diff -- Cargo.lock

cargo metadata --locked --format-version 1

cargo test --locked --all-targets
cargo test --locked --all-targets --features reference-pq
```

Only after those commands execute successfully should the lockfile-derived dependency graph be described as reproducible.

## Integrity rule

A manually fabricated `Cargo.lock`, manually invented checksums, or a hand-written transitive SBOM is explicitly forbidden as M2 evidence.

Current state:

```text
direct dependency provenance    GREEN at source level
Cargo.lock                      BLOCKED on executable Cargo
transitive resolution           BLOCKED on Cargo.lock
SBOM                            BLOCKED on locked resolution
M2 overall                      YELLOW
```


## Secret-key lifecycle evidence

### ML-KEM-1024

The provider no longer stores a raw 64-byte seed in its handle map. Commit `869cd817cbe2b29d86eba8706ecef3bba90f4cf0` stores the pinned crate's `ml_kem_1024::DecapsulationKey` directly.

At upstream tag `ml-kem/v0.3.2`, commit `440768245bba59784b504269cb3087a6c21af45c`, `DecapsulationKey<P>` implements a `Drop` path under the enabled `zeroize` feature which zeroizes:

- the PKE decryption key;
- seed component `d` when present;
- implicit-rejection secret `z`.

The local lifecycle test added in commit `8a39fed2d52edeab8a419f4ef24fc5c33c29c146` requires `remove_key(handle)` to revoke the opaque handle and makes subsequent decapsulation fail closed.

This is source-level zeroization/lifecycle evidence. It is still pending executable Rust confirmation.

### ML-DSA-87

The selected `ml-dsa = 0.1.1` dependency enables its `zeroize` feature. Upstream `SigningKey` has a zeroizing drop path for the seed and its expanded signing key. SYNERGY currently uses signing keys only inside reference tests; production signing-key custody is not yet implemented in the provider.

### SLH-DSA-SHAKE-256s

Pinned `slh-dsa = 0.1.0` does not expose an equivalent `zeroize` feature/drop guarantee for `SigningKey`. The current SYNERGY reference provider verifies SLH-DSA signatures and does not retain SLH private keys; tests generate ephemeral signing keys.

Therefore full production SLH signing-key zeroization remains an explicit hardening item. It must not be claimed complete merely because verification is correct.


## Opaque signing-key custody boundary

Commit `5338e1e4d6414609f4869fde5ebca4f678ddf82f` adds `ContextSignatureSigner` and `PqSigningKeyHandle`. Protocol-facing signing code receives only:

- an opaque 32-byte handle;
- a public key;
- the resulting signature.

Raw private-key bytes are not part of the protocol API.

Commit `0cdd27fddb34aa7a70e841ee1519d2f997d62ab7` adds `ReferencePqSigner` for ML-DSA-87. It stores `ml_dsa::SigningKey<MlDsa87>` inside the provider and signs the envelope-derived FIPS context through `ExpandedSigningKey::sign_deterministic`.

At exact upstream tag `ml-dsa/v0.1.1`, commit `f75d5b829948988f18d9463f286805fb9410bcdd`, the enabled `zeroize` feature provides:

- `Drop` for `SigningKey`, zeroizing its seed;
- `Drop` for `ExpandedSigningKey`, zeroizing `rho`, `K`, `tr`, `s1`, `s2`, `t0` and their NTT forms;
- `ZeroizeOnDrop` markers for both key types.

Therefore ML-DSA signing-key lifecycle is now closed at source level for the reference in-memory provider, pending executable tests.

The same reference signer intentionally refuses `SLH-DSA-SHAKE-256s`. Stable `slh-dsa/v0.1.0` lacks a zeroize-on-drop signing-key guarantee. A newer `slh-dsa/v0.2.0-rc.5` has such support, but M2 does not silently upgrade a pinned stable cryptographic dependency to a release candidate without executable Cargo compatibility testing. Production SLH signing remains delegated to a future zeroizing keystore/HSM/provider boundary.


## Locked SBOM generation path

The branch now includes `scripts/m2_spdx_from_cargo_metadata.py`, a dependency-free SPDX 2.3 JSON generator.

Inputs are deliberately restricted to the real locked resolver output:

```bash
cargo metadata --locked --format-version 1 > m2-cargo-metadata.json
cargo tree --locked --edges normal,build,dev > m2-cargo-tree.txt
SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)" \
  python3 scripts/m2_spdx_from_cargo_metadata.py \
    m2-cargo-metadata.json \
    m2-spdx.json
```

The generator enumerates Cargo-resolved packages and `DEPENDS_ON` relationships. It cannot close M2.10d in the absence of a real `Cargo.lock` and successful `cargo metadata --locked`.


## Expected feature/dependency duplication before lock resolution

Static upstream-manifest review predicts the following legitimate multi-generation families under `reference-pq`:

- `rand_core 0.6.x`: SLH-DSA 0.1.0 and rand 0.8.5;
- `rand_core 0.10.x`: ML-KEM 0.3.2 / ML-DSA 0.1.1 stack;
- `signature 2.3.0-pre.x`: SLH-DSA 0.1.0;
- `signature 3.x`: ML-DSA 0.1.1;
- `hybrid-array 0.2.0-rc.x`: SLH-DSA 0.1.0;
- `hybrid-array 0.4.x`: ML-KEM / ML-DSA.

The provider deliberately does not pass RNGs or signature trait objects across these generation boundaries.

ML-KEM 0.3.2 and ML-DSA 0.1.1 both require `module-lattice 0.2.3`; unexpected duplication of that family should be reviewed after lock generation.

CI commit `0d80cf83b4b05604a04044db04a3e6c72b4e2fce` captures `cargo tree --locked --duplicates` and pins execution to Rust 1.85.0. Commit `f90ad93b3a2b527d4d91f592508be1e20230e9f8` adds formatting, compile and Clippy diagnostic gates before the mandatory tests.


## Transport shared-secret zeroization

The core now directly pins `zeroize = 1.8.1` (RustCrypto/utils tag `zeroize-v1.8.1`, commit `7050a8402b44344023cd8d27fe6e0e4055d6bdde`).

That exact release has MSRV Rust 1.60 and, with its default/`alloc` support, implements `Zeroize` for `Vec<Z>`. Its implementation clears initialized elements, clears the vector length and zeroizes spare capacity.

`HybridSharedSecret` uses that primitive in its `Drop` implementation for both post-quantum and classical shared-secret vectors. The type no longer derives `Clone` or raw `Debug`; its custom debug output redacts both secret fields.
