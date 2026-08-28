from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

SCHEMA = "synergy.economic-testnet-execution-evidence/v1"
EXPECTED_EVIDENCE_DIGEST = "a841d4a662feca85ad459ce2da157279d7a754280dfb75aa1ef025f92c7f1268"
EXPECTED_SOURCE_COMMIT = "af12f7e4e09ad77d8c8c90a45611846115526147"
EXPECTED_GENESIS = "cfba3627eb65d933ed1dec416bfe1c28ecf586312028efc7e629859f315678b2"
EXPECTED_CYCLE = "83f9c3ee0c168ca50212ebaa1e64c58c08eb87fd040a8b5f214ee4987242f3f1"
EXPECTED_COMMITMENT = "9ffd71e7f535ff91cd4cedfb229ac0b43972bc8a2e82f8dce269b7440a9e65a8"
EXPECTED_COMPUTE_CONTEXT = "608b0ca91e905cb0345d345af9e1246489236a8e672a07fb60ea4cfb8691d397"
EXPECTED_EVIDENCE_SET = "c804516869743b9215cc7c46749412209fa929ee941a259a726bfd1c97c9a1a0"
EXPECTED_CHECKPOINTS = (
    "69897b297fde6a25a9c123fe1c21b5ea31f2da2dc463edfc1c7a2364812ca8ab",
    "3742319fa196294a16f9bd80fc502cbd25c06040b569b9080dfeb2893100dedd",
)
HEX = frozenset("0123456789abcdef")


class EconomicTestnetExecutionEvidenceV1Error(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def hex64(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise EconomicTestnetExecutionEvidenceV1Error(f"{name} must be hex64")
    value = value.lower()
    if len(value) != 64 or any(ch not in HEX for ch in value):
        raise EconomicTestnetExecutionEvidenceV1Error(f"{name} must be hex64")
    return value


def canonical_time(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise EconomicTestnetExecutionEvidenceV1Error(f"{name} must be canonical UTC Z text")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    result = parsed.isoformat().replace("+00:00", "Z")
    if result != value:
        raise EconomicTestnetExecutionEvidenceV1Error(f"{name} must be canonical UTC Z text")
    return result


def verify_execution_evidence(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or value.get("schema") != SCHEMA:
        raise EconomicTestnetExecutionEvidenceV1Error("unsupported execution evidence schema")
    item = dict(value)
    claimed = hex64(item.pop("evidence_digest", None), "evidence_digest")
    if digest(item) != claimed:
        raise EconomicTestnetExecutionEvidenceV1Error("execution evidence digest mismatch")

    exact = {
        "network_id": "synergy-economic-testnet-v1",
        "source_repository": "Shtenco/synergy_ai_blockchain",
        "source_branch": "feat/economic-os-testnet-v1-20260828",
        "source_commit": EXPECTED_SOURCE_COMMIT,
        "genesis_digest": EXPECTED_GENESIS,
        "economic_cycle_digest": EXPECTED_CYCLE,
        "economic_commitment_digest": EXPECTED_COMMITMENT,
        "compute_trust_context_digest": EXPECTED_COMPUTE_CONTEXT,
        "runner_class": "EPHEMERAL_LOCAL_PYTHON_SANDBOX",
        "runtime": "CPython 3.13.5",
        "platform": "Linux x86_64",
        "network_mode": "IN_PROCESS_NO_EXTERNAL_NETWORK",
        "persistence": "EPHEMERAL",
        "node_count": 1,
        "checkpoint_count": 2,
        "evidence_set_digest": EXPECTED_EVIDENCE_SET,
        "execution_status": "LOCAL_PROTOCOL_EXECUTION_VERIFIED_NOT_NETWORK_TESTNET",
        "network_testnet_status": "NOT_EXECUTED",
        "live_network_claim": False,
        "multi_node_claim": False,
        "persistent_runner_claim": False,
        "consensus_claim": "NONE",
        "signing_status": "UNSIGNED",
        "submission_status": "NOT_SUBMITTED",
        "accounting_authority": "NONE",
        "financial_authority": "NONE",
        "payment_authority": "NONE",
        "signing_authority": "NONE",
        "blockchain_submission_authority": "NONE",
        "execution_authority": "NONE",
    }
    for field, expected in exact.items():
        if item.get(field) != expected:
            raise EconomicTestnetExecutionEvidenceV1Error(f"execution evidence mismatch: {field}")

    checkpoints = item.get("checkpoint_digests")
    if checkpoints != list(EXPECTED_CHECKPOINTS):
        raise EconomicTestnetExecutionEvidenceV1Error("checkpoint digest set mismatch")
    if item.get("first_checkpoint_previous_digest") != EXPECTED_GENESIS:
        raise EconomicTestnetExecutionEvidenceV1Error("checkpoint #1 does not extend genesis")
    if item.get("second_checkpoint_previous_digest") != EXPECTED_CHECKPOINTS[0]:
        raise EconomicTestnetExecutionEvidenceV1Error("checkpoint #2 does not extend checkpoint #1")
    if item.get("remaining_blockers") != ["PERSISTENT_MULTI_NODE_TESTNET_EXECUTION_NOT_CAPTURED"]:
        raise EconomicTestnetExecutionEvidenceV1Error("remaining blocker set mismatch")
    canonical_time(item.get("executed_at"), "executed_at")
    if claimed != EXPECTED_EVIDENCE_DIGEST:
        raise EconomicTestnetExecutionEvidenceV1Error("unexpected canonical execution evidence root")
    item["evidence_digest"] = claimed
    return item


def load_execution_evidence(root: Path | None = None) -> dict[str, Any]:
    repo_root = root or Path(__file__).resolve().parents[1]
    path = repo_root / "registry" / "economic_testnet_local_execution_evidence_v1.json"
    return json.loads(path.read_text(encoding="utf-8"))
