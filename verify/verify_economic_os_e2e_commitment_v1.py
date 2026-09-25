from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

EXPECTED_DIGEST = "9ffd71e7f535ff91cd4cedfb229ac0b43972bc8a2e82f8dce269b7440a9e65a8"
EXPECTED = {
    "schema": "synergy.ai-blockchain-economic-evidence-commitment/v1",
    "commitment_id": "SYNERGY_ECONOMIC_OS_E2E_COMMITMENT_V1_20260828",
    "economic_cycle_schema": "synergy.economic-cycle/v1",
    "economic_cycle_digest": "83f9c3ee0c168ca50212ebaa1e64c58c08eb87fd040a8b5f214ee4987242f3f1",
    "economic_cycle_source_repository": "Shtenco/synergy_system",
    "economic_cycle_source_commit": "43760304d0f0c43e737cbe3bb717dd0f15eaa953",
    "financial_os_repository": "Shtenco/synergy_financial_os",
    "financial_os_terminal_commit": "d21ce6b5bd91422c45f938b2d4ec641974106944",
    "metapay_repository": "Shtenco/synergy_pay_system",
    "metapay_terminal_commit": "a4b7b2876915e7f70089947a5b40f3cff81458d9",
    "compute_trust_context_commitment_digest": "608b0ca91e905cb0345d345af9e1246489236a8e672a07fb60ea4cfb8691d397",
    "protocol_status": "E2E_PROTOCOL_DAG_CLOSED_NOT_LIVE_EXECUTED",
    "canonical_merge_status": "STACKED_PR_CANDIDATE_NOT_MERGED",
    "live_execution_claim": False,
    "testnet_status": "NOT_EXECUTED",
    "commitment_scope": "PROVENANCE_ONLY",
    "submission_status": "NOT_SUBMITTED_CANDIDATE_ONLY",
    "signing_authority": "NONE",
    "blockchain_submission_authority": "NONE",
    "financial_authority": "NONE",
    "payment_authority": "NONE",
    "accounting_authority": "NONE",
    "execution_authority": "NONE",
    "generated_at": "2026-08-28T10:05:00Z",
}


class EconomicCommitmentV1Error(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify(value: dict[str, Any]) -> str:
    if not isinstance(value, dict):
        raise EconomicCommitmentV1Error("economic commitment must be object")
    payload = dict(value)
    claimed = payload.pop("commitment_digest", None)
    actual = hashlib.sha256(canonical(payload)).hexdigest()
    if claimed != EXPECTED_DIGEST or actual != EXPECTED_DIGEST:
        raise EconomicCommitmentV1Error("economic commitment digest mismatch")
    if payload != EXPECTED:
        raise EconomicCommitmentV1Error("economic commitment identity/lineage/state/authority mismatch")
    return actual


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    value = json.loads((root / "registry" / "economic_os_e2e_commitment_v1.json").read_text(encoding="utf-8"))
    digest = verify(value)
    print(json.dumps({"status": "PASS", "commitment_digest": digest}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
