# SINERGY AI Blockchain

**Trust, state-commitment and proof layer for the SINERGY repository federation.**

This repository is intentionally narrow. The blockchain is not the whole economy and is not the canonical financial accounting engine.

## Role

Preferred responsibilities:

- snapshot and ledger-root commitments;
- ownership/token state where on-chain representation is appropriate;
- governance decisions and timelocked policy commitments;
- settlement/finality references;
- evidence/proof registries;
- oracle/attestation references;
- cross-chain message verification;
- AI policy-proposal attestations where useful;
- reproducible contract/interface specifications.

## Non-responsibilities

This repository should not become the place where:

- browser-side token prices define HardNAV;
- private banking/provider credentials are stored;
- the complete off-chain canonical ledger is duplicated unnecessarily;
- raw OLGA/NEXUS output is granted direct financial authority;
- a blockchain transaction is assumed to prove real-economy profit without accounting evidence.

## Trust architecture

```text
canonical ledger / settlement / project evidence
        |
        v
versioned canonical object
        |
        v
canonical serialization + digest
        |
        v
approved signature / attestation
        |
        v
on-chain commitment / registry
```

The on-chain commitment proves what object/digest was committed at a point in time. It does not by itself prove that every off-chain economic claim inside that object is true; truth still depends on the evidence and accounting processes that produced it.

## Preferred commitment types

- `FinancialSnapshotCommitment`;
- `LedgerRootCommitment`;
- `SettlementCommitment`;
- `ProjectEvidenceCommitment`;
- `PolicyDecisionCommitment`;
- `AIPolicyProposalCommitment`;
- `SchemaRegistry` / version registry.

## Security principles

- least authority;
- explicit chain/network binding;
- replay protection;
- deterministic domain separation for signed messages;
- timelock/multisig/guardian controls for privileged state;
- pause/emergency behavior where appropriate;
- no secrets in source control;
- contract and bridge allowlists with explicit version/codehash binding where needed;
- independent audit/fork testing before production deployment.

## Cross-repository boundary

- `synergy_financial_os` owns canonical accounting constitution and financial schemas;
- `ai_financial_system` preserves historical smart-contract/DeFi research;
- `synergy_pay_system` owns payment execution and settlement reconciliation;
- `synergychain` consumes signed state in the portal/control plane;
- `agi_olga` emits bounded proposals, not privileged transactions;
- `synergy_eurasian` provides real-economy project/evidence objects.

## Legacy integration rule

Existing smart-contract generations in `ai_financial_system`, `synergy_pay_system`, `usds`, `cashero` and other repositories remain in place. This repository should reference or adapt verified contracts instead of deleting source history and pretending they originated here.

## Initial build order

1. Define domain-separated commitment formats.
2. Add schema/version registry interfaces.
3. Add snapshot commitment reference contract.
4. Add deterministic verification tests.
5. Add governance/timelock integration.
6. Add settlement/evidence commitment adapters.
7. Only then evaluate cross-chain production deployment.

## Claims boundary

A trust-layer implementation can prove integrity, ordering, signatures and on-chain state. It cannot create external reserve assets, legal rights, licensed settlement access or guaranteed economic returns by itself.
