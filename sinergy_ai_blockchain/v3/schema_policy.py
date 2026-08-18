from __future__ import annotations

from dataclasses import dataclass


POLICY_PROFILE = "sinergy.commitment-schema-policy/v3"

DOMAIN_SCHEMA_POLICY_V3: dict[str, frozenset[str]] = {
    "FINANCIAL_SNAPSHOT": frozenset({"financial.snapshot/v2"}),
    "MATURITY_SNAPSHOT": frozenset({"maturity.snapshot/v1"}),
    "SETTLEMENT_RECEIPT": frozenset({"settlement.receipt/v1", "settlement.receipt/v2"}),
    "LEDGER_EVENT": frozenset({"ledger.event/v1"}),
    "PROJECT_PROPOSAL": frozenset({"project.proposal/v2"}),
    "PROJECT_EVIDENCE": frozenset({"project.evidence/v1"}),
    "PROJECT_SCREENING": frozenset({"project.screening/v1"}),
    "CAPITAL_AUTHORIZATION": frozenset({"capital.authorization/v1", "capital.authorization/v2"}),
    "ECONOMIC_CYCLE_TRACE": frozenset({
        "economic.cycle-trace/v1",
        "economic.cycle-trace/v2",
        "economic.cycle-trace/v3",
    }),
    "AI_POLICY_PROPOSAL": frozenset({"ai.policy-proposal/v2"}),
}

LATEST_SCHEMA_BY_DOMAIN: dict[str, str] = {
    "FINANCIAL_SNAPSHOT": "financial.snapshot/v2",
    "MATURITY_SNAPSHOT": "maturity.snapshot/v1",
    "SETTLEMENT_RECEIPT": "settlement.receipt/v2",
    "LEDGER_EVENT": "ledger.event/v1",
    "PROJECT_PROPOSAL": "project.proposal/v2",
    "PROJECT_EVIDENCE": "project.evidence/v1",
    "PROJECT_SCREENING": "project.screening/v1",
    "CAPITAL_AUTHORIZATION": "capital.authorization/v2",
    "ECONOMIC_CYCLE_TRACE": "economic.cycle-trace/v3",
    "AI_POLICY_PROPOSAL": "ai.policy-proposal/v2",
}


class CommitmentPolicyV3Error(ValueError):
    pass


@dataclass(frozen=True)
class CommitmentSchemaBindingV3:
    logical_domain: str
    payload_schema: str
    policy_profile: str = POLICY_PROFILE

    def __post_init__(self) -> None:
        domain = self.logical_domain.upper().strip()
        schema = self.payload_schema.strip()
        if self.policy_profile != POLICY_PROFILE:
            raise CommitmentPolicyV3Error("unsupported commitment policy profile")
        if domain not in DOMAIN_SCHEMA_POLICY_V3:
            raise CommitmentPolicyV3Error(f"unsupported logical_domain: {domain or '<empty>'}")
        if schema not in DOMAIN_SCHEMA_POLICY_V3[domain]:
            allowed = ", ".join(sorted(DOMAIN_SCHEMA_POLICY_V3[domain]))
            raise CommitmentPolicyV3Error(
                f"payload schema {schema or '<empty>'} is not allowed for {domain}; allowed: {allowed}"
            )
        object.__setattr__(self, "logical_domain", domain)
        object.__setattr__(self, "payload_schema", schema)

    @property
    def latest_for_domain(self) -> bool:
        return LATEST_SCHEMA_BY_DOMAIN[self.logical_domain] == self.payload_schema


def validate_commitment_schema_binding_v3(
    logical_domain: str,
    payload_schema: str,
    *,
    require_latest: bool = False,
) -> CommitmentSchemaBindingV3:
    binding = CommitmentSchemaBindingV3(logical_domain, payload_schema)
    if require_latest and not binding.latest_for_domain:
        raise CommitmentPolicyV3Error(
            f"{binding.payload_schema} is provenance-compatible but not latest for {binding.logical_domain}; "
            f"latest={LATEST_SCHEMA_BY_DOMAIN[binding.logical_domain]}"
        )
    return binding


def allowed_payload_schemas_v3(logical_domain: str) -> tuple[str, ...]:
    domain = logical_domain.upper().strip()
    if domain not in DOMAIN_SCHEMA_POLICY_V3:
        raise CommitmentPolicyV3Error(f"unsupported logical_domain: {domain or '<empty>'}")
    return tuple(sorted(DOMAIN_SCHEMA_POLICY_V3[domain]))
