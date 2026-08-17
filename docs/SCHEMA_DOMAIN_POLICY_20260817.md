# SINERGY trust layer — schema/domain commitment policy

Status: **additive draft hardening layer**. Existing commitment hashing/domain separation remains untouched.

## Problem

A SHA-256 digest proves byte identity, not semantic type. The same digest must not be accepted under two incompatible meanings such as:

```text
financial.snapshot/v2
```

and

```text
ai.policy-proposal/v2
```

Without an explicit type policy, a verifier can accidentally or maliciously reinterpret a valid digest as a different class of financial object.

## Canonical draft rule

Every commitment carries a logical domain. Each domain has a closed payload-schema allowlist:

| Logical domain | Allowed payload schema |
|---|---|
| `FINANCIAL_SNAPSHOT` | `financial.snapshot/v2` |
| `MATURITY_SNAPSHOT` | `maturity.snapshot/v1` |
| `SETTLEMENT_RECEIPT` | `settlement.receipt/v1` |
| `LEDGER_EVENT` | `ledger.event/v1` |
| `PROJECT_EVIDENCE` | `project.evidence/v1` |
| `PROJECT_SCREENING` | `project.screening/v1` |
| `AI_POLICY_PROPOSAL` | `ai.policy-proposal/v2` |

Unknown domains and mismatched pairs fail closed.

## Legacy preservation

Superseded schemas such as `ai.policy-proposal/v1` remain preserved in their source repositories and central schema registry for provenance. Preservation does **not** imply that a superseded draft is accepted for new canonical trust-layer commitments.

## Separation from authorization

A valid commitment means only:

```text
these bytes + this schema + this logical domain
were bound under this commitment context
```

It does not mean:

- the payload is economically correct;
- a project is funded;
- an AI proposal is authorized;
- a payment is legally final;
- a financial snapshot passed every external audit.

Those meanings belong to their own domain policies and evidence gates.

## Implementation

- `sinergy_ai_blockchain/schema_policy.py`
- `tests/test_schema_policy.py`

Runner verification remains pending until GitHub Actions executes the branch tests.
