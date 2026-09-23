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
        if not isinstance(path, str) or not isinstance(expected, str):
            raise SystemExit("M2 fixture manifest entry malformed")
        if path in seen:
            raise SystemExit(f"duplicate fixture path in manifest: {path}")
        seen.add(path)

        file_path = ROOT / path
        if not file_path.is_file():
            raise SystemExit(f"fixture missing: {path}")

        actual = git_blob_sha1(file_path.read_bytes())
        if actual != expected:
            raise SystemExit(
                f"fixture blob mismatch: {path}: expected {expected}, got {actual}"
            )

    expected_paths = {
        "tests/vectors/ml-kem-1024-acvp-subset.json",
        "tests/vectors/ml-dsa-87-acvp-subset.json",
        "tests/vectors/slh-dsa-shake-256s-acvp-subset.json",
        "tests/vectors/ml-kem-1024-wycheproof-negative-subset.json",
    }
    if seen != expected_paths:
        raise SystemExit(
            f"fixture manifest coverage mismatch: expected {sorted(expected_paths)}, got {sorted(seen)}"
        )

    print(f"M2 fixture manifest: PASS ({len(fixtures)} fixtures)")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
