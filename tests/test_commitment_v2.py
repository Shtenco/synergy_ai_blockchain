import json
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

import pytest

from sinergy_ai_blockchain.v2 import (
    CanonicalJsonV2Error,
    CommitmentEnvelopeV2,
    CommitmentV2InvariantError,
    canonical_json_digest,
    canonical_json_text,
)


ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT_FIXTURE = ROOT / "fixtures/conformance/financial_snapshot_v2_canonical.json"
JSON_FIXTURE = ROOT / "fixtures/conformance/canonical_json_v1_unicode_safe_integer.json"
EXPECTED_SNAPSHOT_PAYLOAD_DIGEST = (
    "d2d2c4ce2c6c6d4efdf60c1fe84593065830631917c98c945e34a5529e1e29d4"
)
EXPECTED_ENVELOPE_DIGEST = (
    "2f9fa67eb2bba94706fbb92f783ec8da563e4ce4e1bc9b48539584735547c038"
)


def _snapshot() -> dict:
    return json.loads(SNAPSHOT_FIXTURE.read_text(encoding="utf-8"))


def _envelope(payload: dict | None = None, **changes) -> CommitmentEnvelopeV2:
    snapshot = _snapshot() if payload is None else payload
    kwargs = {
        "logical_domain": "FINANCIAL_SNAPSHOT",
        "network_domain": "offchain:reference",
        "verifier_id": "financial-os-reference-v2",
        "payload_schema": "financial.snapshot/v2",
        "subject_id": "consolidated-sinergy",
        "sequence": 10,
        "as_of": datetime(2026, 8, 17, 12, 0, tzinfo=UTC),
        "payload": snapshot,
        "signer_policy": "research-no-signature-v2",
    }
    kwargs.update(changes)
    return CommitmentEnvelopeV2.from_payload(**kwargs)


def test_shared_canonical_json_vector_matches_financial_os_exactly() -> None:
    vector = json.loads(JSON_FIXTURE.read_text(encoding="utf-8"))
    assert canonical_json_text(vector["payload"]) == vector["canonical_json"]


def test_financial_snapshot_fixture_has_fixed_cross_repo_payload_digest() -> None:
    assert canonical_json_digest(_snapshot()) == EXPECTED_SNAPSHOT_PAYLOAD_DIGEST


def test_envelope_v2_has_fixed_digest_for_shared_financial_snapshot() -> None:
    envelope = _envelope()
    assert envelope.payload_digest == EXPECTED_SNAPSHOT_PAYLOAD_DIGEST
    assert envelope.commitment_digest == EXPECTED_ENVELOPE_DIGEST
    assert envelope.domain == "SINERGY:FINANCIAL_SNAPSHOT"
    assert envelope.to_canonical_dict()["canonical_profile"] == "sinergy.canonical-json/v1"


def test_equivalent_timestamp_offsets_produce_identical_commitment() -> None:
    utc_envelope = _envelope()
    offset_envelope = _envelope(
        as_of=datetime(2026, 8, 17, 17, 0, tzinfo=timezone(timedelta(hours=5)))
    )
    assert utc_envelope.to_canonical_dict()["as_of"] == "2026-08-17T12:00:00Z"
    assert utc_envelope.commitment_digest == offset_envelope.commitment_digest


def test_payload_schema_field_must_match_declared_schema() -> None:
    payload = _snapshot()
    payload["schema"] = "project.screening/v1"
    with pytest.raises(CommitmentV2InvariantError):
        _envelope(payload=payload)


def test_domain_schema_allowlist_is_enforced_in_envelope_v2() -> None:
    with pytest.raises(CommitmentV2InvariantError):
        _envelope(payload_schema="ai.policy-proposal/v2")


def test_project_proposal_v1_is_preserved_but_not_new_commitment_canonical() -> None:
    with pytest.raises(CommitmentV2InvariantError):
        CommitmentEnvelopeV2.from_payload(
            logical_domain="PROJECT_PROPOSAL",
            network_domain="offchain:reference",
            verifier_id="project-reference-v2",
            payload_schema="project.proposal/v1",
            subject_id="project-1",
            sequence=1,
            as_of=datetime(2026, 8, 17, 12, 0, tzinfo=UTC),
            payload={"schema": "project.proposal/v1"},
            signer_policy="research-no-signature-v2",
        )


@pytest.mark.parametrize("bad", [0.1, float("inf"), float("-inf"), float("nan")])
def test_fractional_or_nonfinite_json_numbers_are_rejected(bad: float) -> None:
    payload = _snapshot()
    payload["hard_nav"] = bad
    with pytest.raises((CanonicalJsonV2Error, CommitmentV2InvariantError)):
        CommitmentEnvelopeV2.from_payload(
            logical_domain="FINANCIAL_SNAPSHOT",
            network_domain="offchain:reference",
            verifier_id="financial-os-reference-v2",
            payload_schema="financial.snapshot/v2",
            subject_id="consolidated-sinergy",
            sequence=10,
            as_of=datetime(2026, 8, 17, 12, 0, tzinfo=UTC),
            payload=payload,
            signer_policy="research-no-signature-v2",
        )


def test_decimal_object_is_rejected_before_hashing() -> None:
    payload = _snapshot()
    payload["hard_nav"] = Decimal("100")
    with pytest.raises(CommitmentV2InvariantError):
        _envelope(payload=payload)


@pytest.mark.parametrize("bad_sequence", [True, -1, 9_007_199_254_740_992])
def test_sequence_is_cross_language_safe_integer(bad_sequence) -> None:
    with pytest.raises(CommitmentV2InvariantError):
        _envelope(sequence=bad_sequence)


def test_naive_timestamp_is_rejected() -> None:
    with pytest.raises(CommitmentV2InvariantError):
        _envelope(as_of=datetime(2026, 8, 17, 12, 0))


def test_payload_tamper_breaks_verification_even_when_envelope_is_unchanged() -> None:
    payload = _snapshot()
    envelope = _envelope(payload=payload)
    tampered = dict(payload)
    tampered["hard_nav"] = "101"
    with pytest.raises(CommitmentV2InvariantError):
        envelope.verify_payload(tampered)
