from __future__ import annotations

import importlib.util
from datetime import UTC, datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "economic_testnet_v1",
    ROOT / "testnet" / "economic_testnet_v1.py",
)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MOD)


def roots():
    return [
        {
            "root_type": "ECONOMIC_CYCLE",
            "digest": MOD.PINNED_ECONOMIC_CYCLE,
            "source_repository": "Shtenco/synergy_system",
            "schema_id": "synergy.economic-cycle/v1",
        },
        {
            "root_type": "ECONOMIC_BLOCKCHAIN_COMMITMENT",
            "digest": MOD.PINNED_ECONOMIC_COMMITMENT,
            "source_repository": "Shtenco/synergy_ai_blockchain",
            "schema_id": "synergy.ai-blockchain-economic-evidence-commitment/v1",
        },
        {
            "root_type": "COMPUTE_TRUST_CONTEXT",
            "digest": MOD.PINNED_COMPUTE_CONTEXT,
            "source_repository": "Shtenco/synergy_ai_blockchain",
            "schema_id": "synergy.ai-blockchain-node-preproduction-commitment/v3",
        },
    ]


def at(minute):
    return datetime(2026, 8, 28, 10, minute, tzinfo=UTC)


def test_genesis_is_ready_but_not_executed_or_live():
    g = MOD.verify_genesis(MOD.load_genesis(ROOT))
    assert g["genesis_digest"] == MOD.EXPECTED_GENESIS_DIGEST
    assert g["execution_status"] == "READY_NOT_EXECUTED"
    assert g["live_network_claim"] is False
    assert g["signing_authority"] == "NONE"
    assert g["blockchain_submission_authority"] == "NONE"


def test_two_checkpoint_append_only_hash_chain_selftest():
    g = MOD.load_genesis(ROOT)
    ledger = MOD.CheckpointLedgerV1(g)
    c1 = MOD.build_checkpoint(
        genesis=g,
        sequence=1,
        previous_checkpoint_digest=ledger.head_digest,
        evidence_roots=roots(),
        observed_at=at(20),
    )
    d1 = ledger.append(c1)
    assert d1 == c1["checkpoint_digest"]
    c2 = MOD.build_checkpoint(
        genesis=g,
        sequence=2,
        previous_checkpoint_digest=ledger.head_digest,
        evidence_roots=roots(),
        observed_at=at(21),
    )
    d2 = ledger.append(c2)
    assert d2 != d1
    assert c2["previous_checkpoint_digest"] == d1
    assert len(ledger.checkpoints) == 2


def test_economic_commitment_root_substitution_fails():
    g = MOD.load_genesis(ROOT)
    bad = roots()
    bad[1] = {**bad[1], "digest": "0" * 64}
    with pytest.raises(MOD.EconomicTestnetV1Error, match="ECONOMIC_BLOCKCHAIN_COMMITMENT"):
        MOD.build_checkpoint(
            genesis=g, sequence=1, previous_checkpoint_digest=g["genesis_digest"],
            evidence_roots=bad, observed_at=at(20),
        )


def test_first_checkpoint_cannot_skip_or_replace_genesis():
    g = MOD.load_genesis(ROOT)
    with pytest.raises(MOD.EconomicTestnetV1Error, match="extend genesis"):
        MOD.build_checkpoint(
            genesis=g, sequence=1, previous_checkpoint_digest="f" * 64,
            evidence_roots=roots(), observed_at=at(20),
        )


def test_fresh_hash_cannot_turn_candidate_into_signed_final_checkpoint():
    g = MOD.load_genesis(ROOT)
    c = MOD.build_checkpoint(
        genesis=g, sequence=1, previous_checkpoint_digest=g["genesis_digest"],
        evidence_roots=roots(), observed_at=at(20),
    )
    c["signing_status"] = "SIGNED"
    c["finality_status"] = "FINAL"
    body = dict(c); body.pop("checkpoint_digest")
    c["checkpoint_digest"] = MOD.digest(body)
    with pytest.raises(MOD.EconomicTestnetV1Error, match="reconstruction"):
        MOD.verify_checkpoint(
            c, genesis=g, expected_sequence=1,
            expected_previous_digest=g["genesis_digest"],
        )


def test_checkpoint_replay_at_wrong_sequence_is_rejected():
    g = MOD.load_genesis(ROOT)
    c = MOD.build_checkpoint(
        genesis=g, sequence=1, previous_checkpoint_digest=g["genesis_digest"],
        evidence_roots=roots(), observed_at=at(20),
    )
    with pytest.raises(MOD.EconomicTestnetV1Error, match="position"):
        MOD.verify_checkpoint(
            c, genesis=g, expected_sequence=2,
            expected_previous_digest=c["checkpoint_digest"],
        )


def test_dynamic_metapay_root_requires_real_hex64_artifact_digest():
    g = MOD.load_genesis(ROOT)
    extended = roots() + [{
        "root_type": "METAPAY",
        "digest": "not-a-git-commit-or-artifact-root",
        "source_repository": "Shtenco/synergy_pay_system",
        "schema_id": "distribution.utilization/v3",
    }]
    with pytest.raises(MOD.EconomicTestnetV1Error, match="hex64"):
        MOD.build_checkpoint(
            genesis=g, sequence=1, previous_checkpoint_digest=g["genesis_digest"],
            evidence_roots=extended, observed_at=at(20),
        )
