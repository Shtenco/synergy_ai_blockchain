#!/usr/bin/env python3
import json
import re
import sys
import tomllib
from pathlib import Path

EXPECTED_CRYPTO = {
    "ml-kem": "0.3.2",
    "ml-dsa": "0.1.1",
    "slh-dsa": "0.1.0",
    "zeroize": "1.8.1",
    "sha2": "0.10.9",
    "hkdf": "0.12.4",
}

HEX64 = re.compile(r"^[0-9a-f]{64}$")
ALLOWED_REGISTRIES = {
    "registry+https://github.com/rust-lang/crates.io-index",
    "registry+https://index.crates.io/",
}

def fail(message: str) -> None:
    raise SystemExit(f"M2 lock policy failed: {message}")

def main() -> int:
    if len(sys.argv) != 3:
        print(
            "usage: m2_verify_lock.py <Cargo.lock> <reference-pq-metadata.json>",
            file=sys.stderr,
        )
        return 2

    lock_path = Path(sys.argv[1])
    metadata_path = Path(sys.argv[2])

    if not lock_path.is_file():
        fail("Cargo.lock is missing")
    if not metadata_path.is_file():
        fail("locked cargo metadata is missing")

    lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    lock_version = int(lock.get("version", 0))
    if lock_version < 3:
        fail(f"unsupported old Cargo.lock format version {lock_version}")

    packages = lock.get("package", [])
    if not packages:
        fail("Cargo.lock contains no packages")

    seen = set()
    crypto_versions = {name: set() for name in EXPECTED_CRYPTO}

    for pkg in packages:
        name = pkg.get("name")
        version = pkg.get("version")
        source = pkg.get("source")
        checksum = pkg.get("checksum")
        if not isinstance(name, str) or not isinstance(version, str):
            fail("lock package missing name/version")

        key = (name, version, source or "")
        if key in seen:
            fail(f"duplicate lock package tuple: {key}")
        seen.add(key)

        if isinstance(source, str):
            if source.startswith("git+"):
                fail(f"git dependency forbidden in M2 locked graph: {name} {version}")
            if source.startswith("registry+"):
                if source not in ALLOWED_REGISTRIES:
                    fail(f"non-crates.io registry forbidden in M2 graph: {source}")
                if not isinstance(checksum, str) or not HEX64.fullmatch(checksum):
                    fail(f"registry package lacks a 64-hex checksum: {name} {version}")

        if name in crypto_versions:
            crypto_versions[name].add(version)

    for name, expected in EXPECTED_CRYPTO.items():
        versions = crypto_versions[name]
        if expected not in versions:
            fail(f"required crypto package {name}={expected} not present; found {sorted(versions)}")
        unexpected = sorted(v for v in versions if v != expected)
        if unexpected:
            fail(f"unexpected additional {name} versions in lock: {unexpected}")

    metadata_bytes = metadata_path.read_bytes()
    metadata = json.loads(metadata_bytes.decode("utf-8"))
    meta_packages = metadata.get("packages", [])
    resolve = metadata.get("resolve") or {}
    root = resolve.get("root")
    if not root:
        fail("cargo metadata has no resolved root")

    root_pkg = next((p for p in meta_packages if p.get("id") == root), None)
    if not root_pkg or root_pkg.get("name") != "synergy-pq-evm-core":
        fail("locked metadata root is not synergy-pq-evm-core")

    declared_features = root_pkg.get("features") or {}
    allowed_root_features = {"default", "reference-pq"}
    unexpected_root_features = sorted(set(declared_features) - allowed_root_features)
    if unexpected_root_features:
        fail(f"unexpected crate features are not covered by M2 CI: {unexpected_root_features}")
    if declared_features.get("default") not in ([], None):
        fail("default feature set must remain empty for consensus core")
    if "reference-pq" not in declared_features:
        fail("reference-pq feature declaration missing")

    nodes = resolve.get("nodes", [])
    node_by_id = {node.get("id"): node for node in nodes}
    root_node = node_by_id.get(root)
    if not root_node or "reference-pq" not in set(root_node.get("features", [])):
        fail("metadata was not resolved with reference-pq enabled")

    required_features = {
        ("ml-kem", "0.3.2"): {"getrandom", "zeroize"},
        ("ml-dsa", "0.1.1"): {"alloc", "getrandom", "zeroize"},
        ("slh-dsa", "0.1.0"): {"alloc"},
        ("hkdf", "0.12.4"): set(),
    }
    allowed_features = {
        ("ml-kem", "0.3.2"): {"getrandom", "zeroize"},
        ("ml-dsa", "0.1.1"): {"alloc", "getrandom", "zeroize"},
        ("slh-dsa", "0.1.0"): {"alloc", "default"},
        ("hkdf", "0.12.4"): set(),
    }
    package_by_id = {pkg.get("id"): pkg for pkg in meta_packages}
    observed_feature_targets = set()
    for node in nodes:
        pkg = package_by_id.get(node.get("id"))
        if not pkg:
            continue
        key = (pkg.get("name"), pkg.get("version"))
        expected = required_features.get(key)
        if expected is None:
            continue
        observed = set(node.get("features", []))
        missing = sorted(expected - observed)
        if missing:
            fail(f"required features missing for {key[0]} {key[1]}: {missing}")
        unexpected = sorted(observed - allowed_features[key])
        if unexpected:
            fail(f"unexpected features enabled for {key[0]} {key[1]}: {unexpected}")
        observed_feature_targets.add(key)

    missing_targets = sorted(set(required_features) - observed_feature_targets)
    if missing_targets:
        fail(f"reference-pq metadata is missing required crypto nodes: {missing_targets}")

    for pkg in meta_packages:
        source = pkg.get("source")
        name = pkg.get("name", "<unknown>")
        version = pkg.get("version", "<unknown>")
        if isinstance(source, str) and source.startswith("git+"):
            fail(f"git source forbidden by metadata policy: {name} {version}")
        if isinstance(source, str) and source.startswith("registry+") and source not in ALLOWED_REGISTRIES:
            fail(f"non-crates.io metadata registry forbidden: {source}")
        if source is None and name != "synergy-pq-evm-core":
            fail(f"unexpected local/path package in locked graph: {name} {version}")

    lock_pairs = {(p.get("name"), p.get("version")) for p in packages}
    for pkg in meta_packages:
        name = pkg.get("name")
        version = pkg.get("version")
        if name == "synergy-pq-evm-core":
            continue
        if (name, version) not in lock_pairs:
            fail(f"metadata package absent from lock: {name} {version}")

    print(
        "M2 lock policy: PASS "
        f"(lock v{lock_version}, packages={len(packages)}, metadata_packages={len(meta_packages)})"
    )
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
