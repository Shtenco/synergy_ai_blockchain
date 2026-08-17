# SINERGY trust layer — federation commitment flow

Status: **additive draft integration note**. Existing commitment hashing and historical blockchain experiments remain unchanged.

## Purpose

The trust layer anchors **identity of typed state**, not business authorization.

A valid commitment means:

```text
these exact canonical bytes
+ this payload schema
+ this logical domain
+ this network/verifier context
```

were bound together.

It does not transform the payload's economic semantics.

## End-to-end reference flow

### 1. Domain producer creates a canonical object

Examples:

```text
synergy_financial_os
  -> financial.snapshot/v2
  -> project.screening/v1

synergy_matrix_sota
  -> maturity.snapshot/v1

synergy_pay_system
  -> settlement.receipt/v1

agi_olga
  -> ai.policy-proposal/v2
```

Each object is content-addressed under its own canonical rules.

### 2. Consumer verifies but does not reinterpret

Example `synergychain` control plane:

```text
financial.snapshot/v2
  -> verify exact shape + digest
  -> display values
  -> DO NOT recompute HardNAV/P&L/LCR

project.screening/v1
  -> verify exact shape + digest
  -> display REVIEWABLE / NO_ACTION
  -> DO NOT convert REVIEWABLE into APPROVED/FUNDED
```

### 3. Trust layer validates schema/domain binding

`schema_policy.py` enforces examples such as:

```text
FINANCIAL_SNAPSHOT <-> financial.snapshot/v2
PROJECT_SCREENING  <-> project.screening/v1
AI_POLICY_PROPOSAL <-> ai.policy-proposal/v2
```

A valid digest cannot be reused under an incompatible semantic type.

### 4. Commitment envelope adds trust-domain separation

The existing commitment layer binds the content digest to its logical domain,
network domain and verifier context.

This protects against cross-domain replay/reinterpretation.

### 5. Authenticity/authorization remains a separate layer

Future production commitments may require:

- HSM/MPC-backed signing;
- signer policy/version;
- legal-entity authority;
- quorum/multisig;
- timestamp/finality rules;
- revocation/rotation policy.

None of these are inferred merely from a SHA-256 digest.

## Critical semantic examples

### Financial snapshot

A committed `financial.snapshot/v2` means the exact published Financial OS state was anchored.

It does **not** mean every asset has been independently audited by the blockchain layer.

### Project screening

A committed:

```text
status = REVIEWABLE
```

means only that the exact screening result was anchored.

It does not mean:

```text
APPROVED
FUNDED
QE_AUTHORIZED
INVESTMENT_RECOMMENDED
```

The trust layer must never upgrade the meaning of the source object.

### AI policy proposal

A committed `ai.policy-proposal/v2` remains:

```text
authorization = NONE
```

Anchoring an AI proposal does not authorize its actions.

## Safe trust equation

```text
CommitmentAuthority(payload)
<= SemanticAuthority(payload)
```

The commitment may prove identity/authenticity/finality of a payload, but cannot grant a stronger economic meaning than the payload schema itself allows.

## Legacy preservation

Older payload schemas, contracts and commitment experiments stay preserved for provenance. The closed schema/domain policy applies to new canonical federation commitments and does not destructively rewrite historical artifacts.
