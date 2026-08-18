import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sinergy_ai_blockchain import CommitmentPolicyError, validate_commitment_schema_binding
from sinergy_ai_blockchain.v2 import CommitmentEnvelopeV2, CommitmentV2InvariantError


ROOT = Path(__file__).resolve().parents[1]
AUTH_FIXTURE = ROOT / "fixtures/conformance/capital_authorization_v1_canonical.json"


def _authorization() -> dict:
    return json.loads(AUTH_FIXTURE.read_text(encoding="utf-8"))


def test_capital_authorization_has_its_own_closed_commitment_domain() -> None:
    binding = validate_commitment_schema_binding(
        "CAPITAL_AUTHORIZATION", "capital.authorization/v1"
    )
    assert binding.logical_domain == "CAPITAL_AUTHORIZATION"
    assert binding.payload_schema == "capital.authorization/v1"


def test_economic_cycle_trace_has_its_own_closed_commitment_domain() -> None:
    binding = validate_commitment_schema_binding(
        "ECONOMIC_CYCLE_TRACE", "economic.cycle-trace/v1"
    )
    assert binding.logical_domain == "ECONOMIC_CYCLE_TRACE"
    assert binding.payload_schema == "economic.cycle-trace/v1"


def test_capital_authorization_cannot_be_reinterpreted_as_screening() -> None:
    with pytest.raises(CommitmentPolicyError):
        validate_commitment_schema_binding(
            "PROJECT_SCREENING", "capital.authorization/v1"
        )
    with pytest.raises(CommitmentPolicyError):
        validate_commitment_schema_binding(
            "CAPITAL_AUTHORIZATION", "project.screening/v1"
        )


def test_commitment_v2_can_bind_exact_financial_os_authorization_fixture() -> None:
    payload = _authorization()
    envelope = CommitmentEnvelopeV2.from_payload(
        logical_domain="CAPITAL_AUTHORIZATION",
        network_domain="offchain:reference",
        verifier_id="financial-os-capital-authorization-v1",
        payload_schema="capital.authorization/v1",
        subject_id="project-001",
        sequence=42,
        as_of=datetime(2026, 8, 18, 19, 0, tzinfo=UTC),
        payload=payload,
        signer_policy="research-no-signature-v2",
    )
    assert envelope.domain == "SINERGY:CAPITAL_AUTHORIZATION"
    assert envelope.verify_payload(payload) == envelope.payload_digest
    assert len(envelope.commitment_digest) == 64


def test_payload_schema_field_still_cannot_be_forged_after_allowlist_match() -> None:
    payload = _authorization()
    payload["schema"] = "project.screening/v1"
    with pytest.raises(CommitmentV2InvariantError):
        CommitmentEnvelopeV2.from_payload(
            logical_domain="CAPITAL_AUTHORIZATION",
            network_domain="offchain:reference",
            verifier_id="financial-os-capital-authorization-v1",
            payload_schema="capital.authorization/v1",
            subject_id="project-001",
            sequence=42,
            as_of=datetime(2026, 8, 18, 19, 0, tzinfo=UTC),
            payload=payload,
            signer_policy="research-no-signature-v2",
        )


def test_cycle_trace_commitment_remains_provenance_not_authorization() -> None:
    payload = {
        "schema": "economic.cycle-trace/v1",
        "cycle_id": "cycle-001",
        "authority": "PROVENANCE_ONLY",
        "profit_recognition": "NOT_PERFORMED",
        "execution_authority": "NONE",
    }
    envelope = CommitmentEnvelopeV2.from_payload(
        logical_domain="ECONOMIC_CYCLE_TRACE",
        network_domain="offchain:reference",
        verifier_id="financial-os-cycle-trace-v1",
        payload_schema="economic.cycle-trace/v1",
        subject_id="cycle-001",
        sequence=1,
        as_of=datetime(2026, 8, 18, 20, 0, tzinfo=UTC),
        payload=payload,
        signer_policy="research-no-signature-v2",
    )
    assert envelope.domain == "SINERGY:ECONOMIC_CYCLE_TRACE"
