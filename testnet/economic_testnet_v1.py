from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable, Mapping

GENESIS_SCHEMA = "synergy.economic-testnet-genesis/v1"
CHECKPOINT_SCHEMA = "synergy.economic-testnet-checkpoint/v1"
EXPECTED_GENESIS_DIGEST = "cfba3627eb65d933ed1dec416bfe1c28ecf586312028efc7e629859f315678b2"
PINNED_ECONOMIC_COMMITMENT = "9ffd71e7f535ff91cd4cedfb229ac0b43972bc8a2e82f8dce269b7440a9e65a8"
PINNED_ECONOMIC_CYCLE = "83f9c3ee0c168ca50212ebaa1e64c58c08eb87fd040a8b5f214ee4987242f3f1"
PINNED_COMPUTE_CONTEXT = "608b0ca91e905cb0345d345af9e1246489236a8e672a07fb60ea4cfb8691d397"
HEX = frozenset("0123456789abcdef")
REQUIRED_PINNED_ROOTS = {
    "ECONOMIC_BLOCKCHAIN_COMMITMENT": PINNED_ECONOMIC_COMMITMENT,
    "ECONOMIC_CYCLE": PINNED_ECONOMIC_CYCLE,
    "COMPUTE_TRUST_CONTEXT": PINNED_COMPUTE_CONTEXT,
}


class EconomicTestnetV1Error(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def hex64(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise EconomicTestnetV1Error(f"{name} must be hex64")
    normalized = value.lower()
    if len(normalized) != 64 or any(ch not in HEX for ch in normalized):
        raise EconomicTestnetV1Error(f"{name} must be hex64")
    return normalized


def canonical_time(value: Any, name: str) -> str:
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise EconomicTestnetV1Error(f"{name} must be timezone-aware")
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if not isinstance(value, str) or not value.endswith("Z"):
        raise EconomicTestnetV1Error(f"{name} must be canonical UTC Z text")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    canonical_value = parsed.isoformat().replace("+00:00", "Z")
    if canonical_value != value:
        raise EconomicTestnetV1Error(f"{name} must be canonical UTC Z text")
    return canonical_value


def verify_genesis(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or value.get("schema") != GENESIS_SCHEMA:
        raise EconomicTestnetV1Error("unsupported economic testnet genesis schema")
    item = dict(value)
    claimed = hex64(item.pop("genesis_digest", None), "genesis_digest")
    actual = digest(item)
    if claimed != EXPECTED_GENESIS_DIGEST or actual != EXPECTED_GENESIS_DIGEST:
        raise EconomicTestnetV1Error("genesis digest mismatch")
    if item.get("network_id") != "synergy-economic-testnet-v1":
        raise EconomicTestnetV1Error("network id mismatch")
    if item.get("network_scope") != "NON_PRODUCTION_EVIDENCE_TESTNET":
        raise EconomicTestnetV1Error("testnet scope escalation")
    if item.get("economic_commitment_schema") != "synergy.ai-blockchain-economic-evidence-commitment/v1":
        raise EconomicTestnetV1Error("economic commitment schema mismatch")
    if item.get("economic_commitment_digest") != PINNED_ECONOMIC_COMMITMENT:
        raise EconomicTestnetV1Error("economic commitment root mismatch")
    if item.get("economic_cycle_digest") != PINNED_ECONOMIC_CYCLE:
        raise EconomicTestnetV1Error("economic cycle root mismatch")
    if item.get("compute_trust_context_commitment_digest") != PINNED_COMPUTE_CONTEXT:
        raise EconomicTestnetV1Error("compute context root mismatch")
    if item.get("checkpoint_schema") != CHECKPOINT_SCHEMA:
        raise EconomicTestnetV1Error("checkpoint schema mismatch")
    if item.get("checkpoint_validation") != "HASH_CHAIN_AND_PINNED_EVIDENCE_ONLY_NO_CONSENSUS_CLAIM":
        raise EconomicTestnetV1Error("checkpoint validation/consensus claim mismatch")
    if item.get("signing_mode") != "UNSIGNED_TESTNET_CANDIDATES_ONLY":
        raise EconomicTestnetV1Error("signing mode escalation")
    if item.get("execution_status") != "READY_NOT_EXECUTED" or item.get("live_network_claim") is not False:
        raise EconomicTestnetV1Error("genesis cannot claim executed/live testnet")
    allowed = item.get("allowed_evidence_root_types")
    expected_allowed = [
        "ECONOMIC_CYCLE",
        "ECONOMIC_BLOCKCHAIN_COMMITMENT",
        "FINANCIAL_OS",
        "METAPAY",
        "COMPUTE_TRUST_CONTEXT",
    ]
    if allowed != expected_allowed:
        raise EconomicTestnetV1Error("allowed evidence root types mismatch")
    for authority in (
        "accounting_authority", "financial_authority", "payment_authority",
        "signing_authority", "blockchain_submission_authority", "execution_authority",
    ):
        if item.get(authority) != "NONE":
            raise EconomicTestnetV1Error(f"{authority} escalation")
    canonical_time(item.get("generated_at"), "generated_at")
    item["genesis_digest"] = claimed
    return item


def normalize_evidence_root(raw: Mapping[str, Any], *, allowed_types: set[str]) -> dict[str, str]:
    if not isinstance(raw, Mapping):
        raise EconomicTestnetV1Error("evidence root must be object")
    root_type = raw.get("root_type")
    if root_type not in allowed_types:
        raise EconomicTestnetV1Error("unsupported evidence root type")
    source_repository = raw.get("source_repository")
    schema_id = raw.get("schema_id")
    if not isinstance(source_repository, str) or not source_repository.strip():
        raise EconomicTestnetV1Error("source_repository required")
    if not isinstance(schema_id, str) or not schema_id.strip():
        raise EconomicTestnetV1Error("schema_id required")
    return {
        "root_type": root_type,
        "digest": hex64(raw.get("digest"), "evidence root digest"),
        "source_repository": source_repository.strip(),
        "schema_id": schema_id.strip(),
    }


def build_checkpoint(
    *,
    genesis: Mapping[str, Any],
    sequence: int,
    previous_checkpoint_digest: str,
    evidence_roots: Iterable[Mapping[str, Any]],
    observed_at: datetime | str,
) -> dict[str, Any]:
    g = verify_genesis(genesis)
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        raise EconomicTestnetV1Error("checkpoint sequence must be positive integer")
    previous = hex64(previous_checkpoint_digest, "previous_checkpoint_digest")
    if sequence == 1 and previous != g["genesis_digest"]:
        raise EconomicTestnetV1Error("first checkpoint must extend genesis digest")
    allowed = set(g["allowed_evidence_root_types"])
    roots = [normalize_evidence_root(raw, allowed_types=allowed) for raw in evidence_roots]
    roots.sort(key=lambda x: (x["root_type"], x["source_repository"], x["schema_id"], x["digest"]))
    if not roots:
        raise EconomicTestnetV1Error("checkpoint requires evidence roots")
    identities = [(x["root_type"], x["digest"], x["source_repository"], x["schema_id"]) for x in roots]
    if len(identities) != len(set(identities)):
        raise EconomicTestnetV1Error("duplicate evidence root")
    by_type: dict[str, list[str]] = {}
    for root in roots:
        by_type.setdefault(root["root_type"], []).append(root["digest"])
    for root_type, expected in REQUIRED_PINNED_ROOTS.items():
        if by_type.get(root_type) != [expected]:
            raise EconomicTestnetV1Error(f"checkpoint must pin exact {root_type}")
    roots_digest = digest(roots)
    body: dict[str, Any] = {
        "schema": CHECKPOINT_SCHEMA,
        "network_id": g["network_id"],
        "sequence": sequence,
        "genesis_digest": g["genesis_digest"],
        "previous_checkpoint_digest": previous,
        "evidence_roots": roots,
        "evidence_set_digest": roots_digest,
        "observed_at": canonical_time(observed_at, "observed_at"),
        "status": "TESTNET_CHECKPOINT_CANDIDATE",
        "finality_status": "CANDIDATE_NOT_FINAL",
        "signing_status": "UNSIGNED",
        "submission_status": "NOT_SUBMITTED",
        "consensus_claim": "NONE",
        "accounting_authority": "NONE",
        "financial_authority": "NONE",
        "payment_authority": "NONE",
        "execution_authority": "NONE",
    }
    body["checkpoint_digest"] = digest(body)
    return body


def verify_checkpoint(
    checkpoint: Mapping[str, Any],
    *,
    genesis: Mapping[str, Any],
    expected_sequence: int,
    expected_previous_digest: str,
) -> dict[str, Any]:
    g = verify_genesis(genesis)
    if not isinstance(checkpoint, Mapping) or checkpoint.get("schema") != CHECKPOINT_SCHEMA:
        raise EconomicTestnetV1Error("unsupported checkpoint schema")
    item = dict(checkpoint)
    claimed = hex64(item.pop("checkpoint_digest", None), "checkpoint_digest")
    if digest(item) != claimed:
        raise EconomicTestnetV1Error("checkpoint digest mismatch")
    if item.get("network_id") != g["network_id"] or item.get("genesis_digest") != g["genesis_digest"]:
        raise EconomicTestnetV1Error("checkpoint/genesis lineage mismatch")
    if item.get("sequence") != expected_sequence or item.get("previous_checkpoint_digest") != hex64(expected_previous_digest, "expected_previous_digest"):
        raise EconomicTestnetV1Error("checkpoint hash-chain position mismatch")
    rebuilt = build_checkpoint(
        genesis=g,
        sequence=expected_sequence,
        previous_checkpoint_digest=expected_previous_digest,
        evidence_roots=item.get("evidence_roots") or (),
        observed_at=item.get("observed_at"),
    )
    if rebuilt != checkpoint:
        raise EconomicTestnetV1Error("checkpoint canonical reconstruction mismatch")
    item["checkpoint_digest"] = claimed
    return item


@dataclass
class CheckpointLedgerV1:
    genesis: Mapping[str, Any]

    def __post_init__(self) -> None:
        self.genesis = verify_genesis(self.genesis)
        self._checkpoints: list[dict[str, Any]] = []

    @property
    def next_sequence(self) -> int:
        return len(self._checkpoints) + 1

    @property
    def head_digest(self) -> str:
        return self.genesis["genesis_digest"] if not self._checkpoints else self._checkpoints[-1]["checkpoint_digest"]

    def append(self, checkpoint: Mapping[str, Any]) -> str:
        verified = verify_checkpoint(
            checkpoint,
            genesis=self.genesis,
            expected_sequence=self.next_sequence,
            expected_previous_digest=self.head_digest,
        )
        self._checkpoints.append(dict(verified))
        return verified["checkpoint_digest"]

    @property
    def checkpoints(self) -> tuple[dict[str, Any], ...]:
        return tuple(dict(x) for x in self._checkpoints)


def load_genesis(root: Path | None = None) -> dict[str, Any]:
    repo_root = root or Path(__file__).resolve().parents[1]
    return json.loads((repo_root / "registry" / "economic_testnet_genesis_v1.json").read_text(encoding="utf-8"))
