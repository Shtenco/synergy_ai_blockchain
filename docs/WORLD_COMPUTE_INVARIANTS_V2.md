# SYNERGY WORLD COMPUTE — invariant ledger v2

This document is a cross-repository contract for the integrated PQ-EVM, Meta Pay, archival storage, NEXUS/CognitiveNode and Autopilot planes. A service may scale horizontally only while these invariants remain true.

## I1 — AI output is never transaction authority

`NEXUS/Autopilot proposal != cryptographic authorization`.

A value-bearing action must end in an independently verified wallet/HSM/MPC/PQ-account signature. Raw private keys, seeds and signing authority do not enter the AI context.

## I2 — budget reservation precedes value-bearing Autopilot signing

A signer accepts a value-bearing Autopilot call only if it is bound to an active reservation:

`policy -> grant/company budget -> reserve -> proposal -> budget-bound call -> external PQ signature -> execution receipt -> commit/release`.

The signed call value must not exceed the reservation. Realized value must not exceed the signed call.

## I3 — source funding reservation precedes parallel payment-lane execution

Corridor lanes may execute independently, but the same payer/source-asset balance may not exist as independent spendable copies in different lanes.

`payer+asset funding shard -> RESERVED -> corridor lane -> CONSUMED | RELEASED`.

A final settled payment needs a matching consumed-funding receipt. External bank/CBDC/processor adapters must bind the rail's real hold/reservation; an internal simulation is not evidence of an external hold.

## I4 — heterogeneous assets are never added as one monetary scalar

`1000 KZT + 25 USD != 1025 money`.

Settlement hierarchy carries deterministic per-asset totals and roots. Conversion to a reporting/base/NAV currency is a separate oracle/valuation operation with explicit price/time/source commitments.

## I5 — canonical chain commits bounded roots, not the world's bulk data

Hot work executes in horizontally scalable service planes. PQ-EVM consumes bounded epoch commitments for payments, funding, accounting, availability, storage, cognitive work, Autopilot policy/budget and finality.

Bulk receipts/data remain in the data-availability/archival plane and are referenced by commitments.

## I6 — storage savings are measured, never protocol constants

For an object/corpus:

`SavingFactor = CompressionFactor * DedupFactor * PriceAdvantage / ErasureOverhead`.

Compression, dedup and physical placement are evidenced by actual byte counts/roots. Incompressible data may expand. No `10x/100x/1000x` constant is encoded as a promise.

## I7 — private dedup is not a public plaintext membership oracle

Public/explicit-opt-in objects may use a public content-addressed dedup domain. Tenant-private dedup uses a tenant-secret keyed commitment (HMAC/domain commitment); the secret never belongs on-chain.

This does not by itself hide object size/access timing and is not a substitute for encryption, padding or access-control policy.

## I8 — cognitive quorum counts independent implementations/evidence, not identities

`same checkpoint x 100 node ids != 100 independent cognitive nodes`.

Independent cognitive contribution is gated by model/lineage/implementation/evidence commitments and measured residual capability/error correlation. Duplicate checkpoints cannot increase independent quorum or diversity reward.

## I9 — constructive DEV oracle scaling is not realized intelligence proof

If admitted specialist `k` solves at least

`q_k >= c*k^(alpha-1), 0<alpha<1`

of the DEV cases unresolved immediately before its admission, then

`E_n <= E_1 * product_{k=2..n}(1-c*k^(alpha-1))`

and rigorously

`E_n <= E_1 * exp[-(c/alpha)*((n+1)^alpha-2^alpha)]`.

This is a conditional DEV **oracle coverage** bound. It is not by itself a claim about realized collective accuracy or open-domain AGI.

## I10 — SEALED evidence cannot influence portfolio/order/weights/thresholds

The strict NEXUS scaling protocol is two-phase:

`DEV inference -> DEV quality/admission/governor -> PRESEAL -> SEALED inference -> frozen scoring`.

PRESEAL commits:

- selected node order;
- model/lineage/implementation roots;
- DEV Governor weights;
- observable routing/category policy;
- aggregation thresholds;
- node budgets;
- SEALED suite bytes SHA without using its labels;
- exact scorer/validator/workflow hashes.

After PRESEAL there is no node replacement, reweighting or threshold tuning. SEALED provenance/coverage failure invalidates the experiment.

## I11 — model-family selection pays for complexity

Stretched-exponential error decay is not selected by raw `R^2` alone. Power/exponential/stretched candidates estimate a finite error floor and are compared with complexity-penalized AICc plus BIC agreement. Finite observed zero-error samples use an explicit finite-sample correction only for model fitting; the empirical zero remains reported as observed.

## I12 — Authority remains above foreign consensus

Foreign teacher unanimity, high trust weight or large node count cannot override deterministic verified Authority invariants. An Authority override violation is a hard no-claim / no-finalization condition.

## I13 — external economic value is not created by internal marks

Internal token marks, minting, QE/QT or pool revaluation do not by themselves create canonical external NAV. External-value accounting recognizes realized external assets/cashflows and explicit liabilities. This invariant applies to financial modules even when AI chooses routing/policy.

## I14 — performance claims use the slowest end-to-end stage

World-payment TPS, storage throughput or cognitive service capacity is not inferred from a single microbenchmark. Sustainable rate is bounded by the slowest required stage, including funding/budget reservation, compliance, external rails, data availability, PQ verification, consensus/finality and recovery/reconciliation paths.

## Cross-repository mapping

- `Shtenco/agi_olga`: R7.5/Blind strict evidence protocol, node provenance, small-world routing, Trust Governor.
- `Shtenco/synergy_pay_system`: payment lanes, asset-aware hierarchy, funding reservation plane, external-rail adapters.
- `Shtenco/ai_compress`: exact codec evidence, scoped private/public dedup, storage economics.
- `Shtenco/synergychain`: people/company Autopilot, delegation, company budget, budget-bound signer handoff.
- `Shtenco/synergy_ai_blockchain`: PQ authorization, canonical service-plane roots and typed commitments binding the planes together.

A change that violates any invariant above is a protocol regression even if a local benchmark improves.
