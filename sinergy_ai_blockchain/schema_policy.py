from __future__ import annotations

from dataclasses import dataclass


class CommitmentPolicyError(ValueError):
    """Raised when a trust-layer commitment violates a closed schema/domain policy."""


DOMAIN_SCHEMA_POLICY: dict[str, frozenset[str]] = {
    "FINANCIAL_SNAPSHOT": frozenset({"financial.snapshot/v2"}),
    "MATURITY_SNAPSHOT": frozenset({"maturity.snapshot/v1"}),
    "SETTLEMENT_RECEIPT": frozenset({"settlement.receipt/v1"}),
    "LEDGER_EVENT": frozenset({"ledger.event/v1"}),
    "PROJECT_EVIDENCE": frozenset({"project.evidence/v1"}),
    "PROJECT_SCREENING": frozenset({"project.screening/v1"}),
    "AI_POLICY_PROPOSAL": frozenset({"ai.policy-proposal/v2"}),
}


@dataclass(frozen=True)
class CommitmentSchemaBinding:
    logical_domain: str
    payload_schema: str

    def __post_init__(self) -> None:
        domain = self.logical_domain.upper().strip()
        schema = self.payload_schema.strip()
        if domain not in DOMAIN_SCHEMA_POLICY:
            raise CommitmentPolicyError(f"unsupported logical_domain: {domain or '<empty>'}")
        if schema not in DOMAIN_SCHEMA_POLICY[domain]:
            allowed = ", ".join(sorted(DOMAIN_SCHEMA_POLICY[domain]))
            raise CommitmentPolicyError(
                f"payload schema {schema or '<empty>'} is not allowed for {domain}; allowed: {allowed}"
            )
        object.__setattr__(self, "logical_domain", domain)
        object.__setattr__(self, "payload_schema", schema)


def validate_commitment_schema_binding(
    logical_domain: str,
    payload_schema: str,
) -> CommitmentSchemaBinding:
    """Return a normalized binding or fail closed on schema/domain type confusion."""

    return CommitmentSchemaBinding(logical_domain, payload_schema)


def allowed_payload_schemas(logical_domain: str) -> tuple[str, ...]:
    domain = logical_domain.upper().strip()
    try:
        allowed = DOMAIN_SCHEMA_POLICY[domain]
    except KeyError as exc:
        raise CommitmentPolicyError(
            f"unsupported logical_domain: {domain or '<empty>'}"
        ) from exc
    return tuple(sorted(allowed))
