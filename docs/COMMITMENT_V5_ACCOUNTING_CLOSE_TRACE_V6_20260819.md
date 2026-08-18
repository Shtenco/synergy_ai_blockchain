# CommitmentEnvelope v5 — AccountingClose / Trace v6 trust finalization

Commitment v5 is an additive trust generation. Commitment v1-v4 and their policy profiles remain immutable provenance.

## Immutable policy v5

`sinergy.commitment-schema-policy/v5` promotes:

- `LEDGER_EVENT -> ledger.event/v2`;
- `ACCOUNTING_CLOSE -> accounting.close/v2`;
- `LEDGER_INCLUSION_PROOF -> ledger.inclusion-proof/v2`;
- `ECONOMIC_CYCLE_TRACE -> economic.cycle-trace/v6`.

Prior schema generations remain readable only as explicit provenance. `from_payload()` requires the latest schema by default.

## Non-circular finalization

Financial OS first completes Trace v6 through AccountingClose v2 and LedgerInclusionProof v2. Only afterwards does the blockchain create an external commitment over the exact completed trace bytes.

The latest Trace v6 is rejected before commitment unless:

- `complete == true`;
- `status == TRACE_COMPLETE`;
- `trust_finalization == EXTERNAL_COMMITMENT_REQUIRED`;
- an `ACCOUNTING_CLOSE` phase exists;
- a `LEDGER_INCLUSION_PROOF` phase exists.

The blockchain does not recalculate accounting, recognize revenue or post ledger events. It proves exact bytes under a typed immutable policy generation.

## Canonical vector

- Trace v6 semantic digest: `566b1570f55b4327270e94fbbc0fec61a3c5618b327dc432ac9b366e6a2657c2`
- full Trace v6 payload hash: `9bbb649e33eaa830191fc288faf680af0985fee45b3bfde9ab1ab3de08fa1643`
- CommitmentEnvelope v5 digest: `9a3398ecdd6367356c5e2179d490e615f9940ad2ff500bcf59a0f2e921c216d1`

These hashes deliberately have different meanings: the first is the Financial OS semantic trace-body digest, the second identifies the full serialized trace artifact including that digest, and the third identifies the external typed trust envelope.
