# CommitmentEnvelope v4 — external finalization of non-circular accounting traces

This generation is additive. Commitment v1-v3 and their policy profiles remain immutable.

V4 extends the federation trust policy to RevenueRecognition v2 and makes EconomicCycleTrace v5 the latest trace schema. Trace v5 deliberately contains no commitment to itself; it ends at FinancialSnapshot with `trust_finalization = EXTERNAL_COMMITMENT_REQUIRED`.

Only after the trace bytes are complete does CommitmentEnvelope v4 commit them from outside the trace.

For the canonical Trace v5:

- semantic trace digest: `0182bbf05b7dc11690adf899bd6e3b353df47b3e2146c3629669693167dacfca`;
- SHA-256 of the full Trace v5 payload bytes under canonical JSON: `67933a4e517d4a3fbdb42776dfd4183809db139046e35da6d348fa2a408c57a9`;
- CommitmentEnvelope v4 digest: `b8a1737da1bc6a8b435f7d3a05f34d997ea229561e33a9003f0c0ccac7c184c4`.

V4 policy profile is `sinergy.commitment-schema-policy/v4`. Latest creation is fail-closed; older trace generations remain available only through explicit provenance opt-in.

Trust still proves typed exact bytes only. It does not approve capital, settle payments, recognize revenue, create ledger entries or compute NAV/profit.
