from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "economic_testnet_loopback_v1",
    ROOT / "testnet" / "economic_testnet_loopback_v1.py",
)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = MOD
SPEC.loader.exec_module(MOD)


def test_three_process_tcp_loopback_converges_to_exact_head():
    result = MOD.run_three_node_loopback_selftest()
    assert result["node_count"] == 3
    assert result["accepted_delivery_count"] == 6
    assert result["rejected_delivery_count"] == 0
    assert result["evidence_set_digest"] == "c804516869743b9215cc7c46749412209fa929ee941a259a726bfd1c97c9a1a0"
    assert result["checkpoint_digests"] == [
        "69897b297fde6a25a9c123fe1c21b5ea31f2da2dc463edfc1c7a2364812ca8ab",
        "3742319fa196294a16f9bd80fc502cbd25c06040b569b9080dfeb2893100dedd",
    ]
    assert result["final_head_digest"] == result["checkpoint_digests"][1]
    assert result["all_nodes_same_final_head"] is True
    assert result["transcript_digest"] == "8371c650c0cae249a077519701d33077ded70a7698bf4d43fc5a73f1a29edcf8"


def test_recorded_loopback_evidence_remains_non_persistent_and_non_consensus():
    evidence = json.loads((ROOT / "registry" / "economic_testnet_loopback_execution_evidence_v1.json").read_text(encoding="utf-8"))
    body = dict(evidence)
    claimed = body.pop("evidence_digest")
    protocol = MOD._load_protocol()
    assert protocol.digest(body) == claimed == "6f80d6cfdbce8eb0b2410c7e440f260eaf6199da8e5b64ce48c365c68be684d5"
    assert evidence["execution_status"] == "LOCAL_3_NODE_TCP_PROPAGATION_VERIFIED_NOT_PERSISTENT_TESTNET"
    assert evidence["persistent_network_testnet_status"] == "NOT_EXECUTED"
    assert evidence["external_host_claim"] is False
    assert evidence["persistent_runner_claim"] is False
    assert evidence["consensus_claim"] == "NONE"
    assert evidence["remaining_blockers"] == ["PERSISTENT_EXTERNAL_HOST_MULTI_NODE_TESTNET_EXECUTION_NOT_CAPTURED"]
    for field in (
        "accounting_authority", "financial_authority", "payment_authority",
        "signing_authority", "blockchain_submission_authority", "execution_authority",
    ):
        assert evidence[field] == "NONE"
