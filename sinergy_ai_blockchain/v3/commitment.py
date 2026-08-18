from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Mapping

from ..v2.canonical_json import MAX_SAFE_JSON_INTEGER, CanonicalJsonV2Error, canonical_json_digest
from .schema_policy import POLICY_PROFILE, CommitmentPolicyV3Error, validate_commitment_schema_binding_v3


COMMITMENT_ENVELOPE_SCHEMA_V3 = "commitment.envelope/v3"
CANONICAL_JSON_PROFILE = "sinergy.canonical-json/v1"


class CommitmentV3InvariantError(ValueError):
    pass


def _text(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CommitmentV3InvariantError(f"{field_name} is required")
    return value.strip()


def _hex64(value: Any, field_name: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    result = _text(value, field_name).lower()
    if len(result) != 64 or any(c not in "0123456789abcdef" for c in result):
        raise CommitmentV3InvariantError(f"{field_name} must be a 64-character hex digest")
    return result


def _sequence(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CommitmentV3InvariantError("sequence must be an integer")
    if value < 0 or value > MAX_SAFE_JSON_INTEGER:
        raise CommitmentV3InvariantError("sequence must be a non-negative safe integer")
    return value


def canonical_rfc3339_utc_v3(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise CommitmentV3InvariantError("as_of must be timezone-aware datetime")
    utc_value = value.astimezone(UTC)
    timespec = "microseconds" if utc_value.microsecond else "seconds"
    return utc_value.isoformat(timespec=timespec).replace("+00:00", "Z")


@dataclass(frozen=True)
class CommitmentEnvelopeV3:
    logical_domain: str
    network_domain: str
    verifier_id: str
    payload_schema: str
    subject_id: str
    sequence: int
    as_of: datetime
    payload_digest: str
    signer_policy: str
    previous_commitment: str | None = None
    metadata_digest: str | None = None
    policy_profile: str = POLICY_PROFILE

    def __post_init__(self) -> None:
        if self.policy_profile != POLICY_PROFILE:
            raise CommitmentV3InvariantError("unsupported policy_profile")
        try:
            binding = validate_commitment_schema_binding_v3(
                self.logical_domain,
                self.payload_schema,
            )
        except CommitmentPolicyV3Error as exc:
            raise CommitmentV3InvariantError(str(exc)) from exc
        object.__setattr__(self, "logical_domain", binding.logical_domain)
        object.__setattr__(self, "payload_schema", binding.payload_schema)
        object.__setattr__(self, "network_domain", _text(self.network_domain, "network_domain"))
        object.__setattr__(self, "verifier_id", _text(self.verifier_id, "verifier_id"))
        object.__setattr__(self, "subject_id", _text(self.subject_id, "subject_id"))
        object.__setattr__(self, "sequence", _sequence(self.sequence))
        canonical_rfc3339_utc_v3(self.as_of)
        object.__setattr__(self, "payload_digest", _hex64(self.payload_digest, "payload_digest"))
        object.__setattr__(self, "signer_policy", _text(self.signer_policy, "signer_policy"))
        if self.previous_commitment is not None:
            object.__setattr__(self, "previous_commitment", _hex64(self.previous_commitment, "previous_commitment"))
        if self.metadata_digest is not None:
            object.__setattr__(self, "metadata_digest", _hex64(self.metadata_digest, "metadata_digest"))

    @property
    def domain(self) -> str:
        return f"SINERGY:{self.logical_domain}"

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "schema_version": COMMITMENT_ENVELOPE_SCHEMA_V3,
            "canonical_profile": CANONICAL_JSON_PROFILE,
            "policy_profile": self.policy_profile,
            "domain": self.domain,
            "network_domain": self.network_domain,
            "verifier_id": self.verifier_id,
            "payload_schema": self.payload_schema,
            "subject_id": self.subject_id,
            "sequence": self.sequence,
            "as_of": canonical_rfc3339_utc_v3(self.as_of),
            "payload_digest": self.payload_digest,
            "previous_commitment": self.previous_commitment,
            "signer_policy": self.signer_policy,
            "metadata_digest": self.metadata_digest,
        }

    @property
    def commitment_digest(self) -> str:
        try:
            return canonical_json_digest(self.to_canonical_dict())
        except CanonicalJsonV2Error as exc:
            raise CommitmentV3InvariantError(str(exc)) from exc

    def verify_payload(self, payload: Mapping[str, Any]) -> str:
        if not isinstance(payload, Mapping):
            raise CommitmentV3InvariantError("payload must be a JSON object")
        if payload.get("schema") != self.payload_schema:
            raise CommitmentV3InvariantError("payload schema field does not match payload_schema")
        try:
            digest = canonical_json_digest(dict(payload))
        except CanonicalJsonV2Error as exc:
            raise CommitmentV3InvariantError(str(exc)) from exc
        if digest != self.payload_digest:
            raise CommitmentV3InvariantError(
                f"payload digest mismatch: expected={self.payload_digest} got={digest}"
            )
        return digest

    @classmethod
    def from_payload(
        cls,
        *,
        logical_domain: str,
        network_domain: str,
        verifier_id: str,
        payload_schema: str,
        subject_id: str,
        sequence: int,
        as_of: datetime,
        payload: Mapping[str, Any],
        signer_policy: str,
        previous_commitment: str | None = None,
        metadata_digest: str | None = None,
        require_latest_schema: bool = True,
    ) -> "CommitmentEnvelopeV3":
        if not isinstance(payload, Mapping):
            raise CommitmentV3InvariantError("payload must be a JSON object")
        if payload.get("schema") != payload_schema:
            raise CommitmentV3InvariantError("payload schema field does not match requested payload_schema")
        try:
            validate_commitment_schema_binding_v3(
                logical_domain,
                payload_schema,
                require_latest=require_latest_schema,
            )
        except CommitmentPolicyV3Error as exc:
            raise CommitmentV3InvariantError(str(exc)) from exc
        try:
            digest = canonical_json_digest(dict(payload))
        except CanonicalJsonV2Error as exc:
            raise CommitmentV3InvariantError(str(exc)) from exc
        envelope = cls(
            logical_domain=logical_domain,
            network_domain=network_domain,
            verifier_id=verifier_id,
            payload_schema=payload_schema,
            subject_id=subject_id,
            sequence=sequence,
            as_of=as_of,
            payload_digest=digest,
            signer_policy=signer_policy,
            previous_commitment=previous_commitment,
            metadata_digest=metadata_digest,
        )
        envelope.verify_payload(payload)
        return envelope
