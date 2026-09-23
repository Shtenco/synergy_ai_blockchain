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


## Canonical transport transcript dependency

The transport transcript commitment directly pins:

- `sha2 = 0.10.9`;
- upstream repository: `RustCrypto/hashes`;
- tag: `sha2-v0.10.9`;
- commit: `82c36a428f8d6f05f3bfccdedb243e9d1f85359d`.

The dependency is used without default features for SHA-256 transcript commitment. It shares the stable SHA-2/digest generation already present in the SLH-DSA dependency family rather than introducing a novel hash construction.

`TransportTranscript::commitment` domain-separates `SYNERGY/PQ-TRANSPORT/V1`, binds transport policy, initiator/responder role order, both node identities and advertised KEX keys, ML-KEM ciphertext and the optional classical transcript commitment. `HybridSharedSecret` can only be constructed from a validated transcript and retains the bound transport policy.


## Static pre-Cargo audit additions

The pre-Cargo audit now also pins the transport transcript hash primitive:

- SHA-256: `RustCrypto/hashes`, tag `sha2-v0.10.9`, commit `82c36a428f8d6f05f3bfccdedb243e9d1f85359d`.

The crate uses the exact dependency:

```text
sha2 = =0.10.9
```

The M2 static guard now checks the following before any Cargo step can run:

- exact direct dependency pins and Rust 1.85 MSRV;
- no public no-context PQ authorization downgrade path;
- nominal non-Copy zeroizing capability handles;
- exact ML-KEM / ML-DSA / SLH-DSA serialized sizes;
- fallible OS randomness and bounded handle-allocation attempts;
- transaction chain / nonce / authorization epoch / expiry / policy binding;
- typed zeroizing transport secrets with redacted Debug;
- canonical SHA-256 transport transcript commitment;
- transport policy binding and rekey limits;
- classical authorization / transport byte caps;
- immutable transcript commitment after derivation.

A bug in the guard itself was found during this audit: it originally split `pq_reference.rs` at the first `#[cfg(test)]` attribute, which occurred on a small helper before the production provider. Commit `cfc2b89527199b8fd09012e29574ea1225af10f3` changes the boundary to the actual `#[cfg(test)] mod tests` module, so the entire production provider is now inspected.


## HKDF transport combiner provenance and memory boundary

The transport combiner now pins:

- `hkdf = 0.12.4`;
- upstream repository: `RustCrypto/KDFs`;
- tag: `hkdf-v0.12.4`;
- commit: `1ac16e8b9d4ee7a67613c9396c6cc1327652eaba`.

The exact `hmac 0.12.1` implementation used by this HKDF line was also inspected at
`RustCrypto/MACs`, tag `hmac-v0.12.1`, commit
`46797e3b44973a30edb9d7f3a3ebb41810061d90`.

Important memory-hardening limitation: neither `hkdf 0.12.4` nor `hmac 0.12.1`
implements `Zeroize` / zeroize-on-drop for the internal HKDF PRK/HMAC state.
Stable `hkdf 0.13.0` was inspected as well and does not add that guarantee.

SYNERGY therefore does **not** claim zeroization of the library-internal PRK state.
Instead the implementation:

- keeps the HKDF object as a function-local one-shot value;
- performs one Expand operation only;
- explicitly drops the HKDF object immediately after Expand;
- explicitly zeroizes the assembled IKM buffer;
- explicitly zeroizes the HKDF info buffer;
- returns only an opaque `TransportSessionKey` whose 32-byte output zeroizes on drop;
- never stores or exposes an HKDF/PRK object in protocol state.

This is a deliberate residual-risk boundary. Replacing RFC5869 with a custom KDF merely
to obtain explicit memory wiping is prohibited without an independently reviewed construction.

The canonical combiner is domain-separated by
`SYNERGY/PQ-TRANSPORT/KDF\0`, crypto-profile version, transport policy,
ML-KEM algorithm code, KDF algorithm code, and the canonical transcript commitment.

An independently calculated known-answer vector is committed in the network tests:

```text
transcript SHA-256
7cedd002de19f032b45bdde3d99eef89eb9b12b30bbfbcf9e66740c060b297e8

HKDF-SHA256 session key
c1bfa4aaaf544e95235f01fbdb40f392eb8d4869183f221713d05f2da8568890
```

These vectors bind the canonical byte layout and KDF output, pending executable Cargo confirmation.


## SLH-DSA signing custody policy

As of the current upstream tag set, the newest stable RustCrypto SLH-DSA tag remains `slh-dsa/v0.1.0`. The `0.2.0` line is still release-candidate only (through `v0.2.0-rc.5`).

M2 therefore keeps `slh-dsa = =0.1.0` pinned with only the explicit `alloc` feature and does **not** introduce local SLH signing-key custody. The production section of `ReferencePqSigner` creates and stores only `ml_dsa::SigningKey<MlDsa87>`; no `SigningKey<Shake256s>` or SLH key-generation path exists.

SLH-DSA remains fully available for verification/FIPS-205 evidence. Production SLH signing must be supplied by a separate provider implementing the opaque `ContextSignatureSigner` interface (for example HSM/OS keystore/remote signer) until a reviewed stable zeroizing backend can be tested with executable Cargo.


## Crypto profile v1 reserved algorithm policy

`AuthScheme::Ed25519` retains protocol code `2` for append-only registry stability, but it is explicitly inactive in `CRYPTO_PROFILE_VERSION = 1`. No `AuthPolicy` includes it.

Activating Ed25519 in a future authorization policy requires an explicit crypto-profile revision plus executable compatibility/vector evidence; it must not be enabled by silently changing the policy-to-suite mapping under profile v1.


## Resolved-graph SPDX determinism

The SPDX 2.3 generator no longer derives its document namespace from raw `cargo metadata` bytes, because root package IDs can contain machine-specific absolute checkout paths. The namespace is now bound to `Cargo.lock` plus a canonical package/edge graph.

The generator also emits only package IDs present in the active `resolve.nodes` graph. Disabled optional dependencies are excluded. This keeps the core SBOM and `reference-pq` SBOM semantically distinct and feature-accurate.

Registry package download locations are rendered as deterministic crates.io package URLs while the exact Cargo source string remains preserved as an annotation.
