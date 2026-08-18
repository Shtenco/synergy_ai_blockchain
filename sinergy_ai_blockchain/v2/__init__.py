"""SINERGY trust commitment v2 primitives.

This namespace is intentionally additive. The historical v1 commitment module
remains unchanged for provenance and compatibility research.
"""

from .canonical_json import (
    MAX_SAFE_JSON_INTEGER,
    CanonicalJsonV2Error,
    assert_canonical_json_profile,
    canonical_json_bytes,
    canonical_json_digest,
    canonical_json_text,
)
from .commitment import (
    COMMITMENT_ENVELOPE_SCHEMA_V2,
    CANONICAL_JSON_PROFILE,
    CommitmentEnvelopeV2,
    CommitmentV2InvariantError,
    canonical_rfc3339_utc,
)

__all__ = [
    "MAX_SAFE_JSON_INTEGER",
    "CanonicalJsonV2Error",
    "assert_canonical_json_profile",
    "canonical_json_bytes",
    "canonical_json_digest",
    "canonical_json_text",
    "COMMITMENT_ENVELOPE_SCHEMA_V2",
    "CANONICAL_JSON_PROFILE",
    "CommitmentEnvelopeV2",
    "CommitmentV2InvariantError",
    "canonical_rfc3339_utc",
]
