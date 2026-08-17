# Commitment formats

## Principle

On-chain or cross-system commitments use canonical, versioned and domain-separated messages. A digest without schema, logical domain, network domain and verifier context is insufficient for long-lived interoperability.

## Reference envelope

```text
CommitmentEnvelope
  domain
  network_domain
  verifier_id
  schema
  subject_id
  sequence
  as_of
  payload_digest
  previous_commitment
  signer_policy
  metadata_digest
```

Examples of `network_domain`:

```text
offchain:reference
eip155:8453
eip155:137
```

`verifier_id` identifies the intended verification context, such as a contract address/version, code hash or named off-chain policy. Production bindings should use an unambiguous identifier appropriate to the network.

## Logical domains

Initial logical domains may include:

```text
SINERGY:FINANCIAL_SNAPSHOT
SINERGY:LEDGER_ROOT
SINERGY:SETTLEMENT
SINERGY:PROJECT_EVIDENCE
SINERGY:POLICY_DECISION
SINERGY:AI_POLICY_PROPOSAL
```

The same payload committed under a different logical domain, network or verifier must produce a different commitment digest.

## Payload digest

The payload digest is computed from a canonical serialization owned by the originating schema repository. The blockchain layer must not invent a different financial or payment serialization silently.

Reference process:

```text
versioned payload
 -> canonical serialization
 -> payload_digest
 -> CommitmentEnvelope
 -> canonical envelope serialization
 -> commitment_digest
 -> optional signature / on-chain registry
```

## Sequence and history

Where the source object is sequential, commitments should link sequence and/or previous digest so consumers can detect rollback or skipped history according to policy.

A history link proves the claimed sequence relation between commitments. It does not prove the external truth of the economic evidence referenced by the payload.

## Privacy

Sensitive source payloads need not be published on-chain. Store the minimum commitment and retain protected source evidence in the authorized system. Avoid including personal data, provider credentials or confidential commercial data in public commitment metadata.

## Key boundary

This format specification contains no signing keys, seed phrases or custody material. Key generation, HSM/MPC policy, signer quorum and rotation belong to a separately audited security layer.
