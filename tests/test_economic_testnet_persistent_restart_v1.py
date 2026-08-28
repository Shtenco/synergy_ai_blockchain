from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "economic_testnet_persistent_restart_v1",
    ROOT / "testnet" / "economic_testnet_persistent_restart_v1.py",
)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = MOD
SPEC.loader.exec_module(MOD)


def test_persistent_restart_partition_replay_and_catchup(tmp_path):
    result = MOD.run_persistent_restart_selftest(tmp_path)
    assert result["node_count"] == 3
    assert result["restart_count"] == 2
    assert result["replay_rejected"] is True
    assert result["node3_catchup_verified"] is True
    assert result["second_restart_all_nodes_same_final_head"] is True
    assert result["checkpoint_digests"] == [
        "69897b297fde6a25a9c123fe1c21b5ea31f2da2dc463edfc1c7a2364812ca8ab",
        "3742319fa196294a16f9bd80fc502cbd25c06040b569b9080dfeb2893100dedd",
        "92c74a6181af9676c4e6805665db3d6466cde5b5a7cecc1850e500ec9a627ae8",
    ]
    assert result["first_restart_heads"] == [
        result["checkpoint_digests"][1],
        result["checkpoint_digests"][1],
        result["checkpoint_digests"][0],
    ]
    assert result["final_head_digest"] == result["checkpoint_digests"][2]
    assert result["transcript_digest"] == "fd29843c4934246938bdd8d71d32c716d589e2e6756df444e72d1e0d1bb791d8"


def test_store_tamper_is_detected_on_fresh_recovery(tmp_path):
    result = MOD.run_persistent_restart_selftest(tmp_path)
    path = tmp_path / "node-1.json"
    state = json.loads(path.read_text(encoding="utf-8"))
    state["checkpoints"][0]["sequence"] = 9
    path.write_text(json.dumps(state, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    with pytest.raises(Exception):
        MOD.PersistentCheckpointStoreV1(path)


def test_recovered_store_cannot_reaccept_checkpoint_one(tmp_path):
    result = MOD.run_persistent_restart_selftest(tmp_path)
    protocol = MOD._load_protocol()
    roots = MOD.canonical_roots(protocol)
    genesis = protocol.load_genesis()
    c1 = protocol.build_checkpoint(
        genesis=genesis,
        sequence=1,
        previous_checkpoint_digest=genesis["genesis_digest"],
        evidence_roots=roots,
        observed_at="2026-08-28T10:20:00Z",
    )
    store = MOD.PersistentCheckpointStoreV1(tmp_path / "node-1.json")
    with pytest.raises(Exception):
        store.append(c1)


def test_evidence_file_remains_non_external_non_final():
    evidence = json.loads((ROOT / "registry" / "economic_testnet_persistent_restart_execution_evidence_v1.json").read_text(encoding="utf-8"))
    body = dict(evidence)
    supplied = body.pop("evidence_digest")
    protocol = MOD._load_protocol()
    assert protocol.digest(body) == supplied == "7c533e6ebb3b3177ef9191d1951c930ddd9d6f49541b0fa3982924f2dce86680"
    assert evidence["execution_status"] == "LOCAL_DISK_PERSISTENCE_RESTART_RECOVERY_VERIFIED_NOT_EXTERNAL_HOST_TESTNET"
    assert evidence["external_host_claim"] is False
    assert evidence["public_network_claim"] is False
    assert evidence["consensus_claim"] == "NONE"
    assert evidence["finality_claim"] == "CANDIDATE_NOT_FINAL"
    assert evidence["signing_status"] == "UNSIGNED"
    assert evidence["submission_status"] == "NOT_SUBMITTED"
    assert evidence["remaining_blockers"] == ["EXTERNAL_HOST_MULTI_NODE_DEPLOYMENT_EXECUTION_NOT_CAPTURED"]
