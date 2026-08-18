# Security invariants

## Cryptographic boundary

1. Consensus never implements home-grown ML-KEM/ML-DSA/SLH-DSA mathematics.
2. Production clients bind to reviewed standards-conformant implementations and official known-answer tests.
3. `MAX` authorization is fail-closed: every mandatory signature lane must verify.
4. A legacy private key is never hashed/converted into a PQ private key.
5. Bitcoin spending keys are never reused for application ECDH, KEM, NEXUS or KDF input.

## NEXUS boundary

NEXUS is not a signing key, oracle of legal truth, or privileged root user.

Consensus NEXUS execution must be:

- integer/fixed-point only;
- bit deterministic across CPU architectures;
- bounded in memory, time, input and output;
- charged by a consensus gas schedule;
- pinned to a model root and implementation hash;
- free of network/filesystem/time/random dependencies;
- unable to mutate state except through ordinary caller contract logic.

AI output must never replace exact checks for signature verification, arithmetic invariants, balance conservation, bridge reserve proofs or consensus validity.

## Migration boundary

Migration from BTC/ETH/SOL requires:

- source-chain ownership proof;
- proof of possession of the new independent PQ key;
- chain/domain/nonce/expiry binding;
- source-chain finality policy;
- replay protection;
- auditable lock/burn proof before mint/unlock.

Canonical bridge invariant:

`minted_on_synergy <= finalized_locked_or_burned_on_source - finalized_withdrawals`

## Model supply chain

A model upgrade is consensus code. Treat it like a hard fork:

- source checkpoint hash;
- quantized artifact hash/root;
- deterministic exporter version;
- canonical vectors;
- reproducible build;
- independent client agreement;
- activation block;
- rollback/incident plan.

Validators must never fetch weights during transaction execution.

## What v1 does not yet prove

- the full NEXUS V18 PyTorch checkpoint has not yet been losslessly converted to the consensus fixed-point representation;
- no production ML-DSA/SLH-DSA provider is vendored in this repository yet;
- no geth/reth/revm fork is included yet;
- no production BTC/ETH/SOL light client is included yet;
- the reserved precompile addresses are SYNERGY-local and are not claims about Ethereum mainnet.

These are explicit next integration gates, not hidden assumptions.
