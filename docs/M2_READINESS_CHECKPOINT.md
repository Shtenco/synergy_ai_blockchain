# M2 readiness checkpoint — pre-runner hardening complete

Status: YELLOW / source-level complete, executable evidence blocked.

Current scope intentionally stops before M3.

## Source-level M2 closure

The M2 implementation now includes:

- FIPS-203/204/205-aligned PQ provider boundaries and ACVP/Wycheproof fixtures;
- domain-separated authorization envelopes and FIPS signature contexts;
- anti-downgrade crypto-profile binding;
- dual-PQ authorization and exact algorithm registry/profile rules;
- stable-identity replay subjects separated from current rotating keyset commitments;
- nonce-consuming public authorization APIs with stateless low-level verification kept crate-internal;
- replay-state commitments suitable for rollback detection;
- transaction current-keyset binding in addition to stable account identity;
- authenticated hybrid transport transcript binding, peer-role binding, transcript-bound replay state, directional traffic keys, bounded record nonces and time/message rekey enforcement;
- one-shot Autopilot execution leases and authenticated one-shot terminal transitions;
- one-shot payment funding reservations with canonical reservation identity;
- funded-settlement finality: bare settlement roots are not canonical payment finality;
- archive/dedup/erasure/provider-bid lifecycle validation;
- storage proofs bound to the exact unexpired ArchiveReceipt;
- deterministic scheduler, cognitive settlement/reward validation and non-clipping accounting;
- canonical chain-bound service finality with conflict detection;
- Rust/Solidity PQ authorization-context parity fixtures;
- context-aware, exact-size Solidity PQ verifier boundary;
- strict dual-PQ PQSmartAccount with bounded calldata/returndata/gas, nonce consumption semantics and reentrancy protection;
- Score-only NEXUS consensus facade for crypto profile v1;
- static M2 guard covering the above invariants;
- pinned dependency/action/compiler provenance definitions and deterministic evidence/SBOM generation scripts.

## Explicitly not claimed

The following are NOT complete because no executable runner has started:

- Cargo.lock generation;
- resolved dependency graph and duplicate-version proof;
- actual SPDX/SBOM generated from a resolved Cargo graph;
- cargo fmt;
- cargo check core;
- cargo check --features reference-pq;
- clippy -D warnings;
- cargo test --all-targets;
- cargo test --all-targets --features reference-pq;
- doctests/release PQ tests;
- actual solc 0.8.26 compilation.

## Infrastructure blocker

Latest workflow run at this checkpoint failed before any job step executed.

Both jobs reported no executable steps/logs:
- rust-core: steps=null, logs_url=null
- solidity-core: steps=null, logs_url=null

Cargo.lock is still absent.

Therefore M2.12 GREEN remains prohibited.

## Acceptance rule

M2 may move from YELLOW to GREEN only after a real runner produces, at minimum:

1. a committed Cargo.lock;
2. locked/frozen dependency verification and SPDX/SBOM output;
3. successful Rust fmt/check/clippy/tests for core and reference-pq;
4. successful pinned solc 0.8.26 compile of all consensus Solidity contracts;
5. retained evidence hashes/artifacts from that same executable dependency state.

Until those conditions are met, the correct status is:

M2 source hardening: COMPLETE
M2 executable evidence: BLOCKED BY RUNNER
M2 GREEN: FORBIDDEN
M3: NOT STARTED
