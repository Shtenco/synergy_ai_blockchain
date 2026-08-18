from __future__ import annotations

import hashlib
import json
from decimal import Decimal
from typing import Any, Mapping, Sequence


MAX_SAFE_JSON_INTEGER = 9_007_199_254_740_991


class CanonicalJsonV2Error(ValueError):
    """Raised when a payload violates sinergy.canonical-json/v1."""


def assert_canonical_json_profile(value: Any, path: str = "$") -> None:
    """Require the SINERGY cross-language canonical JSON primitive profile.

    Fractions, money and ratios must already be normalized decimal strings by
    the domain producer. JSON numeric primitives are reserved for discrete safe
    integers only. This function never rewrites strings while hashing.
    """

    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_JSON_INTEGER:
            raise CanonicalJsonV2Error(
                f"{path} integer exceeds cross-language safe range"
            )
        return
    if isinstance(value, float):
        raise CanonicalJsonV2Error(
            f"{path} contains float; canonical JSON requires decimal strings"
        )
    if isinstance(value, Decimal):
        raise CanonicalJsonV2Error(
            f"{path} contains Decimal object; canonical JSON requires decimal strings"
        )
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalJsonV2Error(
                    f"{path} contains non-string JSON object key"
                )
            assert_canonical_json_profile(item, f"{path}.{key}")
        return
    if isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray)
    ):
        for index, item in enumerate(value):
            assert_canonical_json_profile(item, f"{path}[{index}]")
        return
    raise CanonicalJsonV2Error(
        f"{path} contains non-JSON value of type {type(value).__name__}"
    )


def canonical_json_text(payload: Any) -> str:
    assert_canonical_json_profile(payload)
    try:
        return json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise CanonicalJsonV2Error("payload must be canonical JSON") from exc


def canonical_json_bytes(payload: Any) -> bytes:
    return canonical_json_text(payload).encode("utf-8")


def canonical_json_digest(payload: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
