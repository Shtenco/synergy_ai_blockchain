"""Inventory/verify physical GGUF storage splits without claiming layer execution.

The splitting tool is llama-gguf-split. This manifest records byte-level
provenance. `model_root` and `ordered_shard_root` are candidate commitments;
they are NOT automatically registered with chain consensus.

Usage:
  python scripts/gemma_storage_shards.py create MODEL.gguf SPLITS_DIR MANIFEST.json
  python scripts/gemma_storage_shards.py verify MODEL.gguf SPLITS_DIR MANIFEST.json
"""

import hashlib
import json
from pathlib import Path
import sys

DOMAIN = b"SYNERGY/GGUF-ORDERED-STORAGE-SHARDS/V1\0"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inventory(model: Path, folder: Path) -> dict:
    prefix = model.stem + ".gguf-"
    files = sorted(p for p in folder.glob(prefix + "*-of-*.gguf") if p.is_file())
    if not files:
        raise ValueError("no llama-gguf-split outputs found")
    count = len(files)
    expected_suffixes = [f"{i:05d}-of-{count:05d}.gguf" for i in range(1, count + 1)]
    if [p.name[len(prefix):] for p in files] != expected_suffixes:
        raise ValueError("incomplete or noncanonical split sequence")
    shards = [{"index": i, "name": p.name, "bytes": p.stat().st_size,
               "sha256": sha256(p)} for i, p in enumerate(files)]
    if any(item["bytes"] == 0 for item in shards):
        raise ValueError("empty shard")
    ordered = hashlib.sha256(DOMAIN + len(shards).to_bytes(4, "big") + b"".join(
        item["index"].to_bytes(4, "big") + item["bytes"].to_bytes(8, "big")
        + bytes.fromhex(item["sha256"]) for item in shards)).hexdigest()
    return {"schema": "synergy.gguf-storage-splits/v1",
            "executable_layer_stages": False,
            "model_file": model.name, "model_bytes": model.stat().st_size,
            "model_sha256": sha256(model), "shard_count": count,
            "ordered_shard_root": ordered, "shards": shards}


def main():
    if len(sys.argv) != 5 or sys.argv[1] not in ("create", "verify"):
        raise SystemExit(__doc__)
    mode, model, folder, manifest = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4])
    actual = inventory(model, folder)
    if mode == "create":
        manifest.write_text(json.dumps(actual, indent=2) + "\n", encoding="utf-8")
    elif json.loads(manifest.read_text(encoding="utf-8")) != actual:
        raise SystemExit("shard manifest mismatch")
    print(f"{mode} OK: {actual['shard_count']} physical shards; root={actual['ordered_shard_root']}")


if __name__ == "__main__":
    main()
