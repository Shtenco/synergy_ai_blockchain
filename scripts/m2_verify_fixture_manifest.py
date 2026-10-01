#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tests/vectors/M2_FIXTURE_MANIFEST.json"

def git_blob_sha1(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()

def main() -> int:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if manifest.get("schema") != "synergy-m2-fixture-manifest-v1":
        raise SystemExit("M2 fixture manifest schema mismatch")

    fixtures = manifest.get("fixtures")
    if not isinstance(fixtures, list) or not fixtures:
        raise SystemExit("M2 fixture manifest is empty")

    seen = set()
    for entry in fixtures:
        path = entry.get("path")
        expected = entry.get("git_blob_sha1")
        expected_sha256 = entry.get("sha256")
        if (
            not isinstance(path, str)
            or not isinstance(expected, str)
            or not isinstance(expected_sha256, str)
            or len(expected_sha256) != 64
        ):
            raise SystemExit("M2 fixture manifest entry malformed")
        if path in seen:
            raise SystemExit(f"duplicate fixture path in manifest: {path}")
        seen.add(path)

        file_path = ROOT / path
        if not file_path.is_file():
            raise SystemExit(f"fixture missing: {path}")

        data = file_path.read_bytes()
        actual = git_blob_sha1(data)
        if actual != expected:
            raise SystemExit(
                f"fixture blob mismatch: {path}: expected {expected}, got {actual}"
            )
        actual_sha256 = hashlib.sha256(data).hexdigest()
        if actual_sha256 != expected_sha256:
            raise SystemExit(
                f"fixture SHA-256 mismatch: {path}: expected {expected_sha256}, got {actual_sha256}"
            )

    expected_vector_paths = {
        "tests/vectors/ml-kem-1024-acvp-subset.json",
        "tests/vectors/ml-dsa-87-acvp-subset.json",
        "tests/vectors/slh-dsa-shake-256s-acvp-subset.json",
        "tests/vectors/ml-kem-1024-wycheproof-negative-subset.json",
    }
    expected_auxiliary_paths = {
        "tests/fixtures/evm_fips_context_v1.hex",
        "tests/fixtures/evm_fips_context_v2.hex",
        "tests/fixtures/evm_authorization_envelope_v1.hex",
        "tests/fixtures/evm_authorization_envelope_v2.hex",
    }
    expected_paths = expected_vector_paths | expected_auxiliary_paths
    if seen != expected_paths:
        raise SystemExit(
            f"fixture manifest coverage mismatch: expected {sorted(expected_paths)}, got {sorted(seen)}"
        )

    vectors_dir = ROOT / "tests/vectors"
    actual_json_paths = {
        str(path.relative_to(ROOT)).replace("\\", "/")
        for path in vectors_dir.glob("*.json")
        if path.name != MANIFEST.name
    }
    if actual_json_paths != expected_vector_paths:
        raise SystemExit(
            "unexpected/unmanifested JSON fixture inventory: "
            f"expected {sorted(expected_vector_paths)}, got {sorted(actual_json_paths)}"
        )

    fixtures_dir = ROOT / "tests/fixtures"
    actual_auxiliary_paths = {
        str(path.relative_to(ROOT)).replace("\\", "/")
        for path in fixtures_dir.glob("*")
        if path.is_file()
    }
    if actual_auxiliary_paths != expected_auxiliary_paths:
        raise SystemExit(
            "unexpected/unmanifested auxiliary fixture inventory: "
            f"expected {sorted(expected_auxiliary_paths)}, got {sorted(actual_auxiliary_paths)}"
        )

    print(f"M2 fixture manifest: PASS ({len(fixtures)} fixtures, SHA-1+SHA-256)")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
