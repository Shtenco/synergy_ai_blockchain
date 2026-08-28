from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "economic_testnet_execution_evidence_v1",
    ROOT / "testnet" / "economic_testnet_execution_evidence_v1.py",
)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = MOD
SPEC.loader.exec_module(MOD)


def fresh_hash(payload):
    body = dict(payload)
    body.pop("evidence_digest", None)
    body["evidence_digest"] = MOD.digest(body)
    return body


def test_canonical_local_execution_evidence_verifies():
    evidence = MOD.load_execution_evidence(ROOT)
    verified = MOD.verify_execution_evidence(evidence)
    assert verified["evidence_digest"] == MOD.EXPECTED_EVIDENCE_DIGEST
    assert verified["execution_status"] == "LOCAL_PROTOCOL_EXECUTION_VERIFIED_NOT_NETWORK_TESTNET"
    assert verified["network_testnet_status"] == "NOT_EXECUTED"
    assert verified["live_network_claim"] is False
    assert verified["checkpoint_digests"] == list(MOD.EXPECTED_CHECKPOINTS)


def test_fresh_hash_cannot_promote_local_replay_to_network_testnet():
    evidence = MOD.load_execution_evidence(ROOT)
    evidence["network_testnet_status"] = "EXECUTED"
    evidence["live_network_claim"] = True
    evidence = fresh_hash(evidence)
    with pytest.raises(MOD.EconomicTestnetExecutionEvidenceV1Error):
        MOD.verify_execution_evidence(evidence)


def test_fresh_hash_cannot_replace_checkpoint_chain():
    evidence = MOD.load_execution_evidence(ROOT)
    evidence["checkpoint_digests"][1] = "0" * 64
    evidence = fresh_hash(evidence)
    with pytest.raises(MOD.EconomicTestnetExecutionEvidenceV1Error):
        MOD.verify_execution_evidence(evidence)


def test_fresh_hash_cannot_escalate_authority():
    evidence = MOD.load_execution_evidence(ROOT)
    evidence["execution_authority"] = "LOCAL_RUNNER"
    evidence = fresh_hash(evidence)
    with pytest.raises(MOD.EconomicTestnetExecutionEvidenceV1Error):
        MOD.verify_execution_evidence(evidence)


def test_local_execution_does_not_remove_persistent_multi_node_blocker():
    evidence = MOD.verify_execution_evidence(MOD.load_execution_evidence(ROOT))
    assert evidence["remaining_blockers"] == [
        "PERSISTENT_MULTI_NODE_TESTNET_EXECUTION_NOT_CAPTURED"
    ]
    assert evidence["multi_node_claim"] is False
    assert evidence["persistent_runner_claim"] is False
