# CommitmentEnvelope v3 — federation trust policy

This generation is additive. Commitment v1/v2 code, fixtures and branches remain intact.

## Why v3 exists

A review of the v2 capital/cycle draft found a real inconsistency: its tests expected newer schema generations while the immutable legacy `schema_policy.py` still allowed only v1 for those domains. Rather than silently changing the meaning of v2, v3 makes the schema-policy generation explicit in the commitment bytes.

Every v3 commitment contains:

- `schema_version = commitment.envelope/v3`;
- `canonical_profile = sinergy.canonical-json/v1`;
- `policy_profile = sinergy.commitment-schema-policy/v3`;
- logical domain + network/verifier context;
- exact payload schema and digest;
- subject/sequence/time;
- signer policy and optional previous/metadata digests.

## Latest-by-default

The policy preserves older schema generations for provenance verification, but new `from_payload()` commitments require the latest schema for a domain unless the caller explicitly opts into `require_latest_schema=False`.

Current latest federation bindings include:

- `SETTLEMENT_RECEIPT -> settlement.receipt/v2`;
- `CAPITAL_AUTHORIZATION -> capital.authorization/v2`;
- `ECONOMIC_CYCLE_TRACE -> economic.cycle-trace/v3`.

## Non-authority

A v3 commitment proves exact typed bytes under an explicit policy generation. It does **not**:

- approve capital;
- execute a payment;
- validate project economics;
- recognize revenue or profit;
- mutate Financial OS accounting.

MetaPay remains settlement authority and Financial OS remains accounting/profit authority.
