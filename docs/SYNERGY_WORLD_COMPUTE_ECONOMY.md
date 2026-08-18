# SYNERGY World Compute Economy — architecture note

Status: research / implementation scaffold. No world-scale throughput, universal intelligence scaling, or fixed storage-saving factor is claimed until the corresponding frozen benchmarks are passed.

## 1. One canonical chain, several parallel service planes

SYNERGY must not execute every payment, archive byte and AI reasoning step as one serial EVM stream. The canonical PQ-EVM commits bounded roots from horizontally scaled planes:

```text
PAYMENT LANES ───── region/global settlement root ─┐
ARCHIVISTS ──────── catalog/availability root ─────┤
COGNITIVE NODES ─── registry/evidence root ────────┼─> ServicePlaneRoots -> PQ-EVM finality
AUTOPILOTS ──────── policy/company-graph root ─────┤
DATA AVAILABILITY ─ proof root ────────────────────┘
```

The execution/data planes may scale independently. Canonical consensus verifies bounded commitments, protocol invariants and finality.

## 2. NEXUS R7.5 scaling contract

Adding node count alone is not intelligence scaling. V15/V16 already demonstrated that correlated nodes can be equal to or worse than one model. R7.5 therefore treats a new CognitiveNode as useful only when it adds residual capability and is sufficiently independent.

For remaining oracle error `E_n`, if the next admitted node solves a fraction `q_n` of the still-unresolved DEV cases and

```text
q_n >= c * n^(alpha - 1),  0 < alpha < 1,
```

then

```text
E_n <= E_1 * exp(-(c/alpha) * (n^alpha - 1)).
```

This is only a constructive DEV oracle-coverage bound. A frozen node portfolio/order must reproduce the effect on precommitted SEALED TEST, and the realized Trust Governor must convert oracle diversity into collective accuracy without Authority violations.

Each evidence-bearing node commits:

- operational `node_id` and PQ identity;
- `model_root`;
- `lineage_root`;
- `implementation_root`;
- role commitment;
- frozen benchmark root and evidence root.

The same checkpoint under many node IDs does not count as many independent nodes.

## 3. Cognitive market

A CognitiveNode is an economic service, not a validator/signing authority by default.

```text
request -> specialist -> evidence -> verifier/governor -> deterministic receipt -> reward/slash
```

Reward is separated into:

1. verified base work payment;
2. realized-utility bonus;
3. diversity bonus tied to newly solved residual cases and low positive error correlation.

Self-reported confidence alone never creates a reward.

## 4. Meta Pay world-scale settlement

Payment execution is partitioned by deterministic lanes (jurisdictions/assets/epoch), then recursively aggregated:

```text
PaymentIntent
  -> lane
  -> SettlementBatchCommitment
  -> RegionSettlementCommitment
  -> GlobalSettlementCheckpoint
  -> payment_global_checkpoint_root
```

This architecture keeps millions of receipts/provider records off canonical EVM state while preserving accounting, availability and finality commitments. Capacity must be benchmarked separately at ingress, compliance, external settlement, data availability, PQ verification and consensus.

## 5. Archival storage market

Storage savings are derived from evidence, never protocol constants.

```text
raw bytes
  -> verified lossless codec
  -> archive bytes
  -> scoped content-addressed dedup
  -> unique archive bytes
  -> erasure placement
  -> physical stored bytes
  -> recurring proof-of-storage
```

Public/explicitly opted-in data may use a shared dedup domain. Private tenant data is domain separated to avoid cross-tenant presence leakage.

The end-to-end monetary saving factor is approximately:

```text
SavingFactor = CompressionFactor * DedupFactor * PriceAdvantage / ErasureOverhead
```

Every factor must come from measured byte counts or actual market prices. Incompressible inputs may expand; such expansion must be recorded honestly.

## 6. Personal and company Autopilot

Autopilot is a capability-safe blockchain service node. AI planning is not signing authority.

```text
observe -> NEXUS/evidence -> simulation -> policy -> proposal
       -> external PQ wallet/HSM/MPC authorization -> execution -> receipt -> feedback
```

A company may be represented as a graph of delegated departmental autopilots. A child grant can only narrow its parent:

- capabilities are a subset;
- targets are a subset or remain constrained by the parent;
- validity time is contained by the parent;
- value per action cannot increase;
- an epoch budget limits cumulative delegated spend;
- optional human-approval thresholds may be stricter than the parent policy.

No model upgrade silently inherits unrestricted authority.

## 7. Canonical epoch commitment

`ServicePlaneRoots` binds the epoch to:

- payment global checkpoint root;
- storage catalog root;
- CognitiveNode registry root;
- cognitive evidence root;
- Autopilot policy/company graph root;
- data-availability root;
- service finality root.

A companion capacity envelope records aggregate counts/bytes represented by those roots without placing bulk data into consensus state.

## 8. Required proof gates

Before claims are promoted:

1. **NEXUS** — at least 8 genuinely distinct frozen nodes and >=6 node-budget points, frozen DEV selection, precommitted SEALED TEST, no Authority violations.
2. **Meta Pay** — measured end-to-end throughput including compliance/external rails/DA/PQ/finality, not only an in-process router benchmark.
3. **Storage** — corpus-specific exact round-trip, compression/dedup/erasure byte accounting, random-access/availability tests and actual provider pricing.
4. **Autopilot** — capability non-escalation, cumulative budget accounting, execution simulation, external cryptographic authorization and reconciliation receipts.
5. **PQ-EVM** — bit-exact cross-client execution vectors and production post-quantum provider integration before mainnet activation.

The design goal is a horizontally scaled economic computer. The evidence boundary is intentionally stricter than the architecture ambition.
