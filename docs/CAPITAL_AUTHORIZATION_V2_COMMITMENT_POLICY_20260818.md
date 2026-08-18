# SINERGY CapitalAuthorization V2 Trust Policy — 2026-08-18

This additive layer preserves v1 commitment support while adding the destination-bound Financial OS v2 schemas:

```text
CAPITAL_AUTHORIZATION -> capital.authorization/v1, capital.authorization/v2
ECONOMIC_CYCLE_TRACE  -> economic.cycle-trace/v1, economic.cycle-trace/v2
```

V1 remains available as historical/provenance compatibility. V2 is the hardened candidate that binds exact funding source, destination, idempotency key and approver-policy digest.

The blockchain does not decide which authorization should be issued and does not execute it. It proves typed bytes under a domain-separated commitment.

The branch mirrors the Financial OS v2 fixtures for exact byte conformance. Type confusion remains fail-closed: CapitalAuthorization v2 cannot be committed as ProjectScreening, and the payload's own top-level schema must match the declared payload schema.

No v1 trust primitive or prior commitment domain is removed.
