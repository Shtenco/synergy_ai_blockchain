# SINERGY Capital + Economic Cycle Typed Commitment Domains — 2026-08-18

## Purpose

This additive trust-policy extension allows the v2 commitment layer to preserve exact bytes for two new Financial OS contracts without giving the blockchain financial authority.

New closed bindings:

```text
CAPITAL_AUTHORIZATION -> capital.authorization/v1
ECONOMIC_CYCLE_TRACE  -> economic.cycle-trace/v1
```

The existing `PROJECT_EVIDENCE -> project.evidence/v1` binding remains unchanged.

## Type safety

`capital.authorization/v1` cannot be committed under `PROJECT_SCREENING`, and `project.screening/v1` cannot be committed under `CAPITAL_AUTHORIZATION`.

The v2 envelope additionally requires the payload's own top-level `schema` field to match the declared payload schema, so allowlist membership alone cannot hide a type-confused payload.

## Authority boundary

A blockchain commitment to a capital authorization proves only that exact authorization bytes existed under the declared trust context. The authorization's economic validity comes from Financial OS and its human/multisig evidence. The commitment does not itself approve or execute capital funding.

A commitment to an economic cycle trace proves only the exact provenance object. `TRACE_COMPLETE` and its commitment do not prove project profitability or distributable profit.

## Cross-repository fixture

The branch mirrors the same canonical `capital.authorization/v1` fixture used by Financial OS and MetaPay:

`1bf53290d288e2117ce9c339227669673658eed2c95d72dc2657236b11ae2140`

The trust test verifies that the v2 commitment can bind those exact bytes only in the correct logical domain.

## Non-destructive evolution

This work is stacked above trust commitment v2. Commitment v1, commitment v2 primitives, existing domain mappings and historical trust tests are preserved. Only the closed schema-policy allowlist is extended for the newly introduced schemas.
