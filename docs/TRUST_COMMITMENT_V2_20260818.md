# SINERGY Trust Commitment V2 — 2026-08-18

## Status

Research / federation hardening candidate. This document does not promote the trust layer to production and does not change the historical `commitment.envelope/v1` primitive.

## Non-destructive rule

`sinergy_ai_blockchain.commitment` remains the historical v1 implementation and is not modified by this v2 work. The new implementation lives under `sinergy_ai_blockchain.v2` so provenance, old tests and old consumers remain reproducible.

## Why v2 exists

The v1 serializer is deterministic by key order, but it accepts any JSON number that Python's `json` module accepts. That is insufficient for cross-language financial commitments because JavaScript and Python do not share an unlimited exact numeric domain.

V2 therefore binds commitments to the federation profile `sinergy.canonical-json/v1`:

- JSON numeric primitives are allowed only for discrete integers in the JavaScript safe-integer range;
- money, ratios, prices and fractional economics must already be normalized decimal strings by the authoritative domain producer;
- Python `float` and `Decimal` objects are rejected from hashable payloads;
- object keys are recursively sorted, UTF-8 is preserved and no whitespace is emitted;
- the generic hash layer never rewrites a decimal string.

## Typed domain binding

Every v2 envelope is checked against the closed `schema_policy.py` allowlist before it can produce a commitment digest. A payload declared as `PROJECT_PROPOSAL` cannot carry `project.screening/v1`, and a new project commitment cannot use the preserved legacy `project.proposal/v1`; it must use `project.proposal/v2`.

`from_payload()` additionally requires the payload's own top-level `schema` field to equal the declared `payload_schema`.

## Canonical time

`as_of` must be timezone-aware and is normalized to one UTC RFC3339 representation ending in `Z`. Two offsets representing the same instant therefore commit to the same timestamp bytes.

## Authority boundary

A commitment proves only that exact bytes were committed under an allowed schema/domain combination and envelope context. It does **not** mean:

- accounting recognition;
- project approval;
- credit approval;
- payment authorization;
- QE authorization;
- AI execution authorization;
- legal or regulatory approval.

Financial truth remains owned by Financial OS. Settlement truth remains owned by MetaPay/reconciliation. Project screening remains non-authorizing. AI remains proposal-only.

## Cross-repository conformance

The branch mirrors, without modifying, two authoritative fixtures from `Shtenco/synergy_financial_os`:

- `canonical_json_v1_unicode_safe_integer.json`;
- `financial_snapshot_v2_canonical.json`.

The trust-layer tests require byte-compatible canonical serialization and a fixed payload digest for the FinancialSnapshot fixture. This makes divergence between Financial OS and the blockchain trust layer observable before any on-chain implementation exists.

## V1 preservation

V1 is intentionally not deleted, rewritten or silently reinterpreted. If a future migration is performed, it must be explicit and versioned. New canonical federation commitments should target v2 only after its tests have actually executed successfully in CI.
