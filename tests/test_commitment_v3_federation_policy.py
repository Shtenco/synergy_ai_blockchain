from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import jsonschema
import pytest

from sinergy_ai_blockchain.v3 import (
    POLICY_PROFILE,
    CommitmentEnvelopeV3,
    CommitmentPolicyV3Error,
    CommitmentV3InvariantError,
    allowed_payload_schemas_v3,
    validate_commitment_schema_binding_v3,
)


ROOT = Path(__file__).resolve().parents[1]
FUNDING = ROOT / "fixtures/conformance/settlement_receipt_v2_funding.json"
REVENUE = ROOT / "fixtures/conformance/settlement_receipt_v2_revenue.json"
TRACE = ROOT / "fixtures/conformance/economic_cycle_trace_v3_complete.json"
SCHEMA = ROOT / "schemas/commitment_envelope_v3.schema.json"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _envelope(domain: str, schema: str, payload: dict, subject: str) -> CommitmentEnvelopeV3:
    return CommitmentEnvelopeV3.from_payload(
        logical_domain=domain,
        network_domain="offchain:reference",
        verifier_id="sinergy-federation-v3",
        payload_schema=schema,
        subject_id=subject,
        sequence=3,
        as_of=datetime(2026, 8, 19, 12, 0, tzinfo=UTC),
        payload=payload,
        signer_policy="research-no-signature-v3",
    )


def test_v3_policy_preserves_provenance_generations_and_marks_latest() -> None:
    assert allowed_payload_schemas_v3("SETTLEMENT_RECEIPT") == (
        "settlement.receipt/v1",
        "settlement.receipt/v2",
    )
    assert allowed_payload_schemas_v3("ECONOMIC_CYCLE_TRACE") == (
        "economic.cycle-trace/v1",
        "economic.cycle-trace/v2",
        "economic.cycle-trace/v3",
    )
    assert validate_commitment_schema_binding_v3(
        "SETTLEMENT_RECEIPT", "settlement.receipt/v2", require_latest=True
    ).latest_for_domain is True
    with pytest.raises(CommitmentPolicyV3Error):
        validate_commitment_schema_binding_v3(
            "SETTLEMENT_RECEIPT", "settlement.receipt/v1", require_latest=True
        )


def test_exact_funding_and_revenue_receipt_bytes_commit_under_settlement_domain() -> None:
    for path in (FUNDING, REVENUE):
        payload = _load(path)
        envelope = _envelope(
            "SETTLEMENT_RECEIPT",
            "settlement.receipt/v2",
            payload,
            payload["settlement_id"],
        )
        assert envelope.verify_payload(payload) == envelope.payload_digest
        assert envelope.policy_profile == POLICY_PROFILE
        assert envelope.domain == "SINERGY:SETTLEMENT_RECEIPT"


def test_exact_trace_v3_bytes_commit_under_trace_domain() -> None:
    payload = _load(TRACE)
    envelope = _envelope(
        "ECONOMIC_CYCLE_TRACE",
        "economic.cycle-trace/v3",
        payload,
        payload["cycle_id"],
    )
    assert envelope.verify_payload(payload) == envelope.payload_digest
    assert envelope.domain == "SINERGY:ECONOMIC_CYCLE_TRACE"


def test_latest_creation_rejects_old_receipt_generation_by_default() -> None:
    legacy = {"schema": "settlement.receipt/v1", "example": "provenance-only"}
    with pytest.raises(CommitmentV3InvariantError, match="not latest"):
        CommitmentEnvelopeV3.from_payload(
            logical_domain="SETTLEMENT_RECEIPT",
            network_domain="offchain:reference",
            verifier_id="legacy-check",
            payload_schema="settlement.receipt/v1",
            subject_id="legacy-settlement",
            sequence=1,
            as_of=datetime(2026, 8, 18, 12, 0, tzinfo=UTC),
            payload=legacy,
            signer_policy="research-no-signature-v3",
        )
    envelope = CommitmentEnvelopeV3.from_payload(
        logical_domain="SETTLEMENT_RECEIPT",
        network_domain="offchain:reference",
        verifier_id="legacy-check",
        payload_schema="settlement.receipt/v1",
        subject_id="legacy-settlement",
        sequence=1,
        as_of=datetime(2026, 8, 18, 12, 0, tzinfo=UTC),
        payload=legacy,
        signer_policy="research-no-signature-v3",
        require_latest_schema=False,
    )
    assert envelope.verify_payload(legacy) == envelope.payload_digest


def test_receipt_and_trace_type_confusion_remains_fail_closed() -> None:
    receipt = _load(FUNDING)
    trace = _load(TRACE)
    with pytest.raises(CommitmentPolicyV3Error):
        validate_commitment_schema_binding_v3(
            "CAPITAL_AUTHORIZATION", "settlement.receipt/v2"
        )
    with pytest.raises(CommitmentPolicyV3Error):
        validate_commitment_schema_binding_v3(
            "SETTLEMENT_RECEIPT", "economic.cycle-trace/v3"
        )
    with pytest.raises(CommitmentV3InvariantError):
        CommitmentEnvelopeV3.from_payload(
            logical_domain="SETTLEMENT_RECEIPT",
            network_domain="offchain:reference",
            verifier_id="type-confusion",
            payload_schema="settlement.receipt/v2",
            subject_id="cycle-003",
            sequence=3,
            as_of=datetime(2026, 8, 19, 12, 0, tzinfo=UTC),
            payload=trace,
            signer_policy="research-no-signature-v3",
        )
    assert receipt["schema"] != trace["schema"]


def test_envelope_v3_schema_requires_policy_profile() -> None:
    payload = _load(FUNDING)
    envelope = _envelope(
        "SETTLEMENT_RECEIPT", "settlement.receipt/v2", payload, payload["settlement_id"]
    )
    schema = _load(SCHEMA)
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(envelope.to_canonical_dict())
    broken = envelope.to_canonical_dict()
    broken.pop("policy_profile")
    assert list(jsonschema.Draft202012Validator(schema).iter_errors(broken))
