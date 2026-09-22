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

Primary upstream repositories:

- ML-KEM: `RustCrypto/KEMs`
- ML-DSA: `RustCrypto/signatures`
- SLH-DSA: `RustCrypto/signatures`
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
