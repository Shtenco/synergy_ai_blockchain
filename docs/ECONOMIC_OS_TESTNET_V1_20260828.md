# SYNERGY Economic OS Evidence Testnet v1

This generation turns the closed Economic OS protocol DAG and its non-signing blockchain commitment into an executable **non-production checkpoint testnet protocol**.

It is not a mainnet, not a validator-consensus claim and not evidence that a live network is currently running.

## Genesis

Genesis digest: `cfba3627eb65d933ed1dec416bfe1c28ecf586312028efc7e629859f315678b2`.

Pinned roots:

- EconomicCycle v1: `83f9c3ee0c168ca50212ebaa1e64c58c08eb87fd040a8b5f214ee4987242f3f1`;
- Economic blockchain commitment v1: `9ffd71e7f535ff91cd4cedfb229ac0b43972bc8a2e82f8dce269b7440a9e65a8`;
- compute trust context: `608b0ca91e905cb0345d345af9e1246489236a8e672a07fb60ea4cfb8691d397`.

Genesis state is `READY_NOT_EXECUTED` and `live_network_claim=false`.

## Checkpoints

`synergy.economic-testnet-checkpoint/v1` is an append-only SHA-256 hash chain.

The first checkpoint must extend the exact genesis digest. Each subsequent checkpoint must extend the exact preceding checkpoint. Every checkpoint must preserve the three pinned roots above. Optional typed `FINANCIAL_OS` and `METAPAY` roots are accepted only as real 64-hex artifact digests; Git commit IDs or prose placeholders are not accepted as economic evidence roots.

Checkpoint state is intentionally:

- `TESTNET_CHECKPOINT_CANDIDATE`;
- `CANDIDATE_NOT_FINAL`;
- `UNSIGNED`;
- `NOT_SUBMITTED`;
- `consensus_claim=NONE`.

A fresh outer hash cannot convert a candidate into SIGNED/FINAL or substitute one of the pinned roots because verification performs canonical checkpoint reconstruction.

## Authority

The testnet protocol has no Financial OS, MetaPay, accounting, signing or payment authority. It transports/content-addresses evidence only.

## Execution boundary

The included in-process `CheckpointLedgerV1` and regressions prove deterministic protocol behavior. They do **not** constitute a persistent multi-node testnet execution. Promotion from `READY_NOT_EXECUTED` requires a separate executed testnet evidence generation with runner identity, host/runtime facts, checkpoint transcript, process/network evidence and clean teardown or continuing-live status.
