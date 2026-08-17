import pytest

from sinergy_ai_blockchain.schema_policy import (
    CommitmentPolicyError,
    DOMAIN_SCHEMA_POLICY,
    allowed_payload_schemas,
    validate_commitment_schema_binding,
)


def test_every_trust_domain_has_an_explicit_nonempty_schema_allowlist() -> None:
    assert DOMAIN_SCHEMA_POLICY
    assert all(allowed for allowed in DOMAIN_SCHEMA_POLICY.values())


@pytest.mark.parametrize(
    ("domain", "schema"),
    [
        ("FINANCIAL_SNAPSHOT", "financial.snapshot/v2"),
        ("MATURITY_SNAPSHOT", "maturity.snapshot/v1"),
        ("SETTLEMENT_RECEIPT", "settlement.receipt/v1"),
        ("LEDGER_EVENT", "ledger.event/v1"),
        ("PROJECT_PROPOSAL", "project.proposal/v2"),
        ("PROJECT_EVIDENCE", "project.evidence/v1"),
        ("PROJECT_SCREENING", "project.screening/v1"),
        ("AI_POLICY_PROPOSAL", "ai.policy-proposal/v2"),
    ],
)
def test_canonical_domain_schema_pairs_are_accepted(domain: str, schema: str) -> None:
    binding = validate_commitment_schema_binding(domain.lower(), schema)
    assert binding.logical_domain == domain
    assert binding.payload_schema == schema


def test_financial_snapshot_cannot_be_reinterpreted_as_ai_proposal() -> None:
    with pytest.raises(CommitmentPolicyError):
        validate_commitment_schema_binding(
            "FINANCIAL_SNAPSHOT",
            "ai.policy-proposal/v2",
        )


def test_ai_proposal_cannot_be_reinterpreted_as_financial_snapshot() -> None:
    with pytest.raises(CommitmentPolicyError):
        validate_commitment_schema_binding(
            "AI_POLICY_PROPOSAL",
            "financial.snapshot/v2",
        )


def test_old_ai_proposal_v1_is_preserved_but_not_commitment_canonical() -> None:
    with pytest.raises(CommitmentPolicyError):
        validate_commitment_schema_binding(
            "AI_POLICY_PROPOSAL",
            "ai.policy-proposal/v1",
        )
    assert allowed_payload_schemas("AI_POLICY_PROPOSAL") == (
        "ai.policy-proposal/v2",
    )


def test_old_project_proposal_v1_is_preserved_but_not_commitment_canonical() -> None:
    with pytest.raises(CommitmentPolicyError):
        validate_commitment_schema_binding(
            "PROJECT_PROPOSAL",
            "project.proposal/v1",
        )
    assert allowed_payload_schemas("PROJECT_PROPOSAL") == (
        "project.proposal/v2",
    )


def test_project_proposal_cannot_be_reinterpreted_as_screening_result() -> None:
    with pytest.raises(CommitmentPolicyError):
        validate_commitment_schema_binding(
            "PROJECT_SCREENING",
            "project.proposal/v2",
        )
    with pytest.raises(CommitmentPolicyError):
        validate_commitment_schema_binding(
            "PROJECT_PROPOSAL",
            "project.screening/v1",
        )


def test_unknown_domain_fails_closed() -> None:
    with pytest.raises(CommitmentPolicyError):
        validate_commitment_schema_binding("MYSTERY_DOMAIN", "financial.snapshot/v2")
