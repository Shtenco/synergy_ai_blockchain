from datetime import UTC, datetime

import pytest

from sinergy_ai_blockchain import (
    CommitmentEnvelope,
    CommitmentInvariantError,
    payload_digest,
)


NOW = datetime(2026, 8, 17, 12, 0, tzinfo=UTC)
PAYLOAD = {"schema": "financial.snapshot/v1", "sequence": 7, "hard_nav": "100"}
PAYLOAD_DIGEST = payload_digest(PAYLOAD)


def _envelope(**overrides) -> CommitmentEnvelope:
    kwargs = {
        "domain": "SINERGY:FINANCIAL_SNAPSHOT",
        "network_domain": "offchain:reference",
        "verifier_id": "financial-os-reference-v1",
        "payload_schema": "financial.snapshot/v1",
        "subject_id": "consolidated-sinergy",
        "sequence": 7,
        "as_of": NOW,
        "payload_digest": PAYLOAD_DIGEST,
        "signer_policy": "research-no-signature-v1",
    }
    kwargs.update(overrides)
    return CommitmentEnvelope(**kwargs)


def test_payload_digest_is_canonical_for_key_order() -> None:
    assert payload_digest({"b": 2, "a": 1}) == payload_digest({"a": 1, "b": 2})


def test_commitment_is_deterministic() -> None:
    assert _envelope().commitment_digest == _envelope().commitment_digest


def test_logical_domain_changes_commitment() -> None:
    assert _envelope().commitment_digest != _envelope(
        domain="SINERGY:LEDGER_ROOT"
    ).commitment_digest


def test_network_domain_changes_commitment() -> None:
    assert _envelope().commitment_digest != _envelope(
        network_domain="eip155:8453"
    ).commitment_digest


def test_verifier_changes_commitment() -> None:
    assert _envelope().commitment_digest != _envelope(
        verifier_id="0x0000000000000000000000000000000000000001:v1"
    ).commitment_digest


def test_payload_schema_is_distinct_from_envelope_schema_version() -> None:
    payload = _envelope().to_canonical_dict()
    assert payload["schema_version"] == "commitment.envelope/v1"
    assert payload["payload_schema"] == "financial.snapshot/v1"


def test_invalid_payload_digest_is_rejected() -> None:
    with pytest.raises(CommitmentInvariantError):
        _envelope(payload_digest="bad")


def test_naive_timestamp_is_rejected() -> None:
    with pytest.raises(CommitmentInvariantError):
        _envelope(as_of=datetime(2026, 8, 17, 12, 0))


def test_non_sinergy_domain_is_rejected() -> None:
    with pytest.raises(CommitmentInvariantError):
        _envelope(domain="FINANCIAL_SNAPSHOT")
