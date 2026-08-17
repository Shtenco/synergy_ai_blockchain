# Commitment formats

## Principle

On-chain commitments use canonical, versioned and domain-separated messages. A digest without a schema/version and domain is insufficient for long-lived cross-repository interoperability.

## Reference envelope

```text
CommitmentEnvelope
  domain
  schema
  subject_id
  sequence
  as_of
  payload_digest
  previous_commitment
  signer_policy
  metadata_digest
```

## Domains

Initial logical domains may include:

```text
SINERGY:FINANCIAL_SNAPSHOT
SINERGY:LEDGER_ROOT
SINERGY:SETTLEMENT
SINERGY:PROJECT_EVIDENCE
SINERGY:POLICY_DECISION
SINERGY:AI_POLICY_PROPOSAL
```

Production encodings must bind chain/network and contract version to prevent cross-domain or cross-chain replay.

## Payload digest

The payload digest is computed from a canonical serialization owned by the originating schema repository. The blockchain layer must not invent a different financial or payment serialization silently.

## Sequence and history

Where the source object is sequential, commitments should link sequence and/or previous digest so consumers can detect rollback or skipped history according to policy.

## Privacy

Sensitive source payloads need not be published on-chain. Store the minimum commitment and retain protected source evidence in the authorized system. Avoid including personal data, provider credentials or confidential commercial data in public commitment metadata.
