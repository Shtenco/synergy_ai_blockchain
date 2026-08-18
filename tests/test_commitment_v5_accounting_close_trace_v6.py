from __future__ import annotations

import copy
import json
from datetime import UTC, datetime
from pathlib import Path

import jsonschema
import pytest

from sinergy_ai_blockchain.v2.canonical_json import canonical_json_digest
from sinergy_ai_blockchain.v5 import (
    CommitmentEnvelopeV5,
    CommitmentPolicyV5Error,
    CommitmentV5InvariantError,
    allowed_payload_schemas_v5,
    validate_commitment_schema_binding_v5,
)


ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "fixtures/conformance"


def load(name: str) -> dict:
    return json.loads((FIX / name).read_text(encoding="utf-8"))


def test_v5_policy_preserves_old_generations_but_promotes_accounting_bridge_v2() -> None:
    assert allowed_payload_schemas_v5("LEDGER_EVENT") == (
        "ledger.event/v1", "ledger.event/v2"
    )
    assert allowed_payload_schemas_v5("ACCOUNTING_CLOSE") == (
        "accounting.close/v1", "accounting.close/v2"
    )
    assert allowed_payload_schemas_v5("LEDGER_INCLUSION_PROOF") == (
        "ledger.inclusion-proof/v1", "ledger.inclusion-proof/v2"
    )
    assert "economic.cycle-trace/v5" in allowed_payload_schemas_v5("ECONOMIC_CYCLE_TRACE")
    assert validate_commitment_schema_binding_v5(
        "ECONOMIC_CYCLE_TRACE", "economic.cycle-trace/v6", require_latest=True
    ).latest_for_domain is True
    with pytest.raises(CommitmentPolicyV5Error):
        validate_commitment_schema_binding_v5(
            "ECONOMIC_CYCLE_TRACE", "economic.cycle-trace/v5", require_latest=True
        )


def test_exact_financial_os_v2_v6_bytes_commit_under_separate_domains() -> None:
    cases = (
        ("LEDGER_EVENT", "ledger.event/v2", "ledger_event_v2_recognized_revenue.json", "revenue-event-001"),
        ("ACCOUNTING_CLOSE", "accounting.close/v2", "accounting_close_v2_cycle_003.json", "close-cycle-003-v2"),
        ("LEDGER_INCLUSION_PROOF", "ledger.inclusion-proof/v2", "ledger_inclusion_proof_v2_cycle_003.json", "revenue-event-001"),
    )
    for domain, schema, filename, subject in cases:
        payload = load(filename)
        envelope = CommitmentEnvelopeV5.from_payload(
            logical_domain=domain,
            network_domain="offchain:reference",
            verifier_id="sinergy-federation-v5",
            payload_schema=schema,
            subject_id=subject,
            sequence=1,
            as_of=datetime(2026, 8, 19, 12, tzinfo=UTC),
            payload=payload,
            signer_policy="research-no-signature-v5",
        )
        assert envelope.verify_payload(payload) == canonical_json_digest(payload)


def test_trace_v6_is_finalized_only_after_complete_close_and_inclusion_phases() -> None:
    payload = load("economic_cycle_trace_v6_complete.json")
    envelope = CommitmentEnvelopeV5.from_payload(
        logical_domain="ECONOMIC_CYCLE_TRACE",
        network_domain="offchain:reference",
        verifier_id="sinergy-federation-v5",
        payload_schema="economic.cycle-trace/v6",
        subject_id="cycle-006",
        sequence=6,
        as_of=datetime(2026, 8, 19, 12, tzinfo=UTC),
        payload=payload,
        signer_policy="research-no-signature-v5",
    )
    assert envelope.payload_digest == "9bbb649e33eaa830191fc288faf680af0985fee45b3bfde9ab1ab3de08fa1643"
    assert envelope.commitment_digest == "9a3398ecdd6367356c5e2179d490e615f9940ad2ff500bcf59a0f2e921c216d1"
    assert envelope.to_canonical_dict() == load("commitment_envelope_v5_trace_v6.json")

    schema = json.loads((ROOT / "schemas/commitment_envelope_v5.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(envelope.to_canonical_dict())

    incomplete = copy.deepcopy(payload)
    incomplete["complete"] = False
    incomplete["status"] = "TRACE_PARTIAL"
    incomplete["references"] = [
        item for item in incomplete["references"]
        if item["phase"] != "LEDGER_INCLUSION_PROOF"
    ]
    with pytest.raises(CommitmentV5InvariantError):
        CommitmentEnvelopeV5.from_payload(
            logical_domain="ECONOMIC_CYCLE_TRACE",
            network_domain="offchain:reference",
            verifier_id="sinergy-federation-v5",
            payload_schema="economic.cycle-trace/v6",
            subject_id="cycle-006-incomplete",
            sequence=6,
            as_of=datetime(2026, 8, 19, 12, tzinfo=UTC),
            payload=incomplete,
            signer_policy="research-no-signature-v5",
        )


def test_old_trace_v5_requires_explicit_provenance_opt_in() -> None:
    payload = {
        "schema": "economic.cycle-trace/v5",
        "cycle_id": "historical-cycle",
        "complete": True,
        "status": "TRACE_COMPLETE",
        "references": [],
        "trust_finalization": "EXTERNAL_COMMITMENT_REQUIRED",
    }
    with pytest.raises(CommitmentV5InvariantError):
        CommitmentEnvelopeV5.from_payload(
            logical_domain="ECONOMIC_CYCLE_TRACE",
            network_domain="offchain:reference",
            verifier_id="historical-v5",
            payload_schema="economic.cycle-trace/v5",
            subject_id="historical-cycle",
            sequence=5,
            as_of=datetime(2026, 8, 19, 12, tzinfo=UTC),
            payload=payload,
            signer_policy="research-no-signature-v5",
        )
    envelope = CommitmentEnvelopeV5.from_payload(
        logical_domain="ECONOMIC_CYCLE_TRACE",
        network_domain="offchain:reference",
        verifier_id="historical-v5",
        payload_schema="economic.cycle-trace/v5",
        subject_id="historical-cycle",
        sequence=5,
        as_of=datetime(2026, 8, 19, 12, tzinfo=UTC),
        payload=payload,
        signer_policy="research-no-signature-v5",
        require_latest_schema=False,
    )
    assert envelope.verify_payload(payload) == envelope.payload_digest


def test_type_confusion_remains_fail_closed() -> None:
    payload = load("accounting_close_v2_cycle_003.json")
    with pytest.raises(CommitmentV5InvariantError):
        CommitmentEnvelopeV5.from_payload(
            logical_domain="LEDGER_EVENT",
            network_domain="offchain:reference",
            verifier_id="sinergy-federation-v5",
            payload_schema="accounting.close/v2",
            subject_id="close-cycle-003-v2",
            sequence=1,
            as_of=datetime(2026, 8, 19, 12, tzinfo=UTC),
            payload=payload,
            signer_policy="research-no-signature-v5",
        )
