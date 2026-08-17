from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any


class CommitmentInvariantError(ValueError):
    """Raised when a commitment envelope is structurally unsafe or ambiguous."""


def canonical_json_bytes(payload: Any) -> bytes:
    """Serialize JSON-compatible data deterministically for hashing.

    Callers are responsible for converting Decimal, datetime and domain objects
    into their schema-defined JSON representation before this function is used.
    """

    try:
        text = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise CommitmentInvariantError("payload is not canonical JSON-compatible") from exc
    return text.encode("utf-8")


def payload_digest(payload: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _require_text(value: str, field_name: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise CommitmentInvariantError(f"{field_name} is required")
    return normalized


def _require_hex64(value: str, field_name: str) -> str:
    normalized = value.lower().strip()
    if len(normalized) != 64 or any(char not in "0123456789abcdef" for char in normalized):
        raise CommitmentInvariantError(f"{field_name} must be a 64-character hex digest")
    return normalized


@dataclass(frozen=True)
class CommitmentEnvelope:
    domain: str
    network_domain: str
    verifier_id: str
    schema: str
    subject_id: str
    sequence: int
    as_of: datetime
    payload_digest: str
    signer_policy: str
    previous_commitment: str | None = None
    metadata_digest: str | None = None

    def __post_init__(self) -> None:
        domain = _require_text(self.domain, "domain")
        if not domain.startswith("SINERGY:"):
            raise CommitmentInvariantError("domain must use the SINERGY: namespace")
        network_domain = _require_text(self.network_domain, "network_domain")
        verifier_id = _require_text(self.verifier_id, "verifier_id")
        schema = _require_text(self.schema, "schema")
        subject_id = _require_text(self.subject_id, "subject_id")
        signer_policy = _require_text(self.signer_policy, "signer_policy")
        if self.sequence < 0:
            raise CommitmentInvariantError("sequence must be non-negative")
        if self.as_of.tzinfo is None or self.as_of.utcoffset() is None:
            raise CommitmentInvariantError("as_of must be timezone-aware")

        object.__setattr__(self, "domain", domain)
        object.__setattr__(self, "network_domain", network_domain)
        object.__setattr__(self, "verifier_id", verifier_id)
        object.__setattr__(self, "schema", schema)
        object.__setattr__(self, "subject_id", subject_id)
        object.__setattr__(self, "signer_policy", signer_policy)
        object.__setattr__(
            self,
            "payload_digest",
            _require_hex64(self.payload_digest, "payload_digest"),
        )
        if self.previous_commitment is not None:
            object.__setattr__(
                self,
                "previous_commitment",
                _require_hex64(self.previous_commitment, "previous_commitment"),
            )
        if self.metadata_digest is not None:
            object.__setattr__(
                self,
                "metadata_digest",
                _require_hex64(self.metadata_digest, "metadata_digest"),
            )

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "network_domain": self.network_domain,
            "verifier_id": self.verifier_id,
            "schema": self.schema,
            "subject_id": self.subject_id,
            "sequence": self.sequence,
            "as_of": self.as_of.isoformat(),
            "payload_digest": self.payload_digest,
            "previous_commitment": self.previous_commitment,
            "signer_policy": self.signer_policy,
            "metadata_digest": self.metadata_digest,
        }

    @property
    def commitment_digest(self) -> str:
        return payload_digest(self.to_canonical_dict())
