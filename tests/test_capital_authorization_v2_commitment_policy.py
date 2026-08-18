import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sinergy_ai_blockchain import CommitmentPolicyError, allowed_payload_schemas, validate_commitment_schema_binding
from sinergy_ai_blockchain.v2 import CommitmentEnvelopeV2, CommitmentV2InvariantError


ROOT = Path(__file__).resolve().parents[1]
AUTH_FIXTURE = ROOT / "fixtures/conformance/capital_authorization_v2_canonical.json"
TRACE_FIXTURE = ROOT / "fixtures/conformance/economic_cycle_trace_v2_complete.json"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_capital_domain_preserves_v1_and_adds_v2_side_by_side() -> None:
    assert allowed_payload_schemas("CAPITAL_AUTHORIZATION") == (
        "capital.authorization/v1",
        "capital.authorization/v2",
    )


def test_cycle_trace_domain_preserves_v1_and_adds_v2_side_by_side() -> None:
    assert allowed_payload_schemas("ECONOMIC_CYCLE_TRACE") == (
        "economic.cycle-trace/v1",
        "economic.cycle-trace/v2",
    )


def test_exact_capital_authorization_v2_bytes_commit_under_capital_domain() -> None:
    payload = _load(AUTH_FIXTURE)
    envelope = CommitmentEnvelopeV2.from_payload(
        logical_domain="CAPITAL_AUTHORIZATION",
        network_domain="offchain:reference",
        verifier_id="financial-os-capital-authorization-v2",
        payload_schema="capital.authorization/v2",
        subject_id="project-001",
        sequence=42,
        as_of=datetime(2026, 8, 18, 19, 0, tzinfo=UTC),
        payload=payload,
        signer_policy="research-no-signature-v2",
    )
    assert envelope.verify_payload(payload) == envelope.payload_digest
    assert envelope.domain == "SINERGY:CAPITAL_AUTHORIZATION"


def test_exact_cycle_trace_v2_bytes_commit_under_cycle_domain() -> None:
    payload = _load(TRACE_FIXTURE)
    envelope = CommitmentEnvelopeV2.from_payload(
        logical_domain="ECONOMIC_CYCLE_TRACE",
        network_domain="offchain:reference",
        verifier_id="financial-os-cycle-trace-v2",
        payload_schema="economic.cycle-trace/v2",
        subject_id="cycle-002",
        sequence=2,
        as_of=datetime(2026, 8, 18, 18, 0, tzinfo=UTC),
        payload=payload,
        signer_policy="research-no-signature-v2",
    )
    assert envelope.verify_payload(payload) == envelope.payload_digest


def test_v2_authorization_still_cannot_be_committed_as_project_screening() -> None:
    with pytest.raises(CommitmentPolicyError):
        validate_commitment_schema_binding("PROJECT_SCREENING", "capital.authorization/v2")


def test_payload_top_level_schema_forgery_is_rejected_for_v2() -> None:
    payload = _load(AUTH_FIXTURE)
    payload["schema"] = "capital.authorization/v1"
    with pytest.raises(CommitmentV2InvariantError):
        CommitmentEnvelopeV2.from_payload(
            logical_domain="CAPITAL_AUTHORIZATION",
            network_domain="offchain:reference",
            verifier_id="financial-os-capital-authorization-v2",
            payload_schema="capital.authorization/v2",
            subject_id="project-001",
            sequence=42,
            as_of=datetime(2026, 8, 18, 19, 0, tzinfo=UTC),
            payload=payload,
            signer_policy="research-no-signature-v2",
        )
