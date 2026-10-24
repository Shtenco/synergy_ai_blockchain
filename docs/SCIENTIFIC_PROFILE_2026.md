# SYNERGY AI Blockchain — deterministic PQ-EVM scientific profile

## Research hypothesis

This project examines whether post-quantum authorization and tightly controlled deterministic graph intelligence can coexist with EVM-style consensus. The essential innovation is **reproducibility under consensus**: model identity, fixed-point arithmetic, activation rules, gas bounds and cryptographic authority must be identical for all validating nodes.

Implementation spans authorization policies and post-quantum verification boundaries, reserved precompiles, a frozen model-root profile for NEXUS, migration identity bindings, network/inference/storage subsystems and tests with ML-DSA, SLH-DSA and ML-KEM reference vectors. The PyTorch checkpoint is a provenance source, not a neural binary executed directly in consensus.

## Fixed-point model

The [NEXUS kernel](../src/nexus.rs) defines Q16.16 arithmetic with scale Q=65536. An ideal fixed-point product follows

$$
\operatorname{qmul}(a,b)\approx\operatorname{round}\left(\frac{ab}{65536}\right).
$$

The exact rounding, truncation and saturation policies must be taken from the Rust implementation. Frozen profile parameters include 16 graph nodes, 3 layers, up to 512 inputs, 64 outputs and a mandatory nonzero quantized model root. This bounds both semantic changes and memory/compute costs.

## Gas and resource accounting

The [consensus module](../src/consensus.rs) meters an operation with a separately charged fixed cost, input/output byte lengths, graph nodes, edges and layers:

$$
G=G_0+g_{\mathrm{in}}B_{\mathrm{in}}+g_{\mathrm{out}}B_{\mathrm{out}}+g_nN+g_eE+g_lL.
$$

Default rates in source: base 25,000; input byte 8; output byte 16; node 250; edge 40; layer 5,000. Test important properties: nonnegative cost, overflow protection, deterministic out-of-gas behavior and monotonicity under additional work.

## Engineering components

| Source | Role |
|---|---|
| src/pq.rs; src/pq_reference.rs | Hybrid/PQ authorization and verification boundaries |
| src/consensus.rs | Precompile reservations, activation and gas policy |
| src/nexus.rs | Quantized model manifest and deterministic inference |
| src/migration.rs | Cross-identity binding to an independent PQ identity |
| src/network.rs; src/mesh_transport.rs | Peer communications |
| src/inference.rs; src/model_shard.rs | Distributed model processing |
| tests/vectors/ | Test vectors and repeatable cryptographic checks |

## Novel application directions

A bounded cognition precompile could support verifiable scores, reproducible model policies and machine-checkable assistive computation. The authority design must never equate generated advice with spending permission. Separately, model-root activation by governance creates a reproducible transition between inference revisions.

## Experimental validation

Run the repository Rust tests, record toolchain and hash, verify cryptographic test vectors, replay fixed-point outputs with two independent implementations, test root activation, and compare gas accounting for edge cases. Deployment claims require external integration, PQ library verification and cross-client replay. A successful reference test alone is not an audited public network.
