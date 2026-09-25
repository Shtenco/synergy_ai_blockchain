from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "economic_commitment_verifier",
    ROOT / "verify" / "verify_economic_os_e2e_commitment_v1.py",
)
MOD = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MOD)


def load():
    return json.loads((ROOT / "registry" / "economic_os_e2e_commitment_v1.json").read_text(encoding="utf-8"))


def rehash(value):
    body = dict(value)
    body.pop("commitment_digest", None)
    value["commitment_digest"] = hashlib.sha256(
        json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return value


def test_canonical_commitment_passes():
    assert MOD.verify(load()) == MOD.EXPECTED_DIGEST


@pytest.mark.parametrize(
    "field,value",
    [
        ("economic_cycle_digest", "0" * 64),
        ("financial_os_terminal_commit", "1" * 40),
        ("metapay_terminal_commit", "2" * 40),
        ("protocol_status", "E2E_LIVE_EXECUTED"),
        ("live_execution_claim", True),
        ("testnet_status", "EXECUTED"),
        ("submission_status", "SUBMITTED"),
        ("signing_authority", "AI"),
        ("blockchain_submission_authority", "AI"),
        ("financial_authority", "AI"),
        ("payment_authority", "AI"),
        ("accounting_authority", "AI"),
        ("execution_authority", "AI"),
    ],
)
def test_fresh_hash_cannot_promote_or_substitute(field, value):
    item = load()
    item[field] = value
    rehash(item)
    with pytest.raises(MOD.EconomicCommitmentV1Error):
        MOD.verify(item)
