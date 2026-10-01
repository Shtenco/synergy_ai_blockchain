"""Create or verify independently loadable contiguous-layer GGUF stages.

Usage:
  python -m scripts.llama_layer_shards create MODEL.gguf OUTPUT_DIR MANIFEST.json [STAGES]
  python -m scripts.llama_layer_shards verify MODEL.gguf OUTPUT_DIR MANIFEST.json [STAGES]
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

from gguf import GGUFReader, GGUFValueType, GGUFWriter

from runtime.gguf_v3 import GGUFFile


DOMAIN = b"SYNERGY/EXECUTABLE-LLAMA-LAYER-SHARDS/V1\0"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def layer_ranges(block_count: int, stage_count: int) -> list[tuple[int, int]]:
    if not 1 <= stage_count <= block_count:
        raise ValueError("stage count must be between 1 and block count")
    return [
        (i * block_count // stage_count, (i + 1) * block_count // stage_count)
        for i in range(stage_count)
    ]


def tensor_names(all_names: set[str], start: int, end: int, block_count: int) -> set[str]:
    names = {
        name for name in all_names
        if any(name.startswith(f"blk.{layer}.") for layer in range(start, end))
    }
    if start == 0:
        names.add("token_embd.weight")
    if end == block_count:
        names.add("output_norm.weight")
        names.add("output.weight" if "output.weight" in all_names else "token_embd.weight")
    missing = names - all_names
    if missing:
        raise ValueError(f"source model is missing required tensors: {sorted(missing)}")
    return names


def _copy_metadata(reader: GGUFReader, writer: GGUFWriter) -> None:
    for key, field in reader.fields.items():
        if key.startswith("GGUF.") or key == "general.architecture":
            continue
        value_type = field.types[0]
        subtype = field.types[1] if value_type == GGUFValueType.ARRAY else None
        writer.add_key_value(key, field.contents(), value_type, subtype)


def create_shard(source: Path, destination: Path, selected: set[str]) -> None:
    reader = GGUFReader(source)
    writer = GGUFWriter(destination, "llama")
    try:
        _copy_metadata(reader, writer)
        found = set()
        for tensor in reader.tensors:
            if tensor.name not in selected:
                continue
            writer.add_tensor(
                tensor.name,
                tensor.data,
                raw_dtype=tensor.tensor_type,
            )
            found.add(tensor.name)
        if found != selected:
            raise ValueError(f"tensor selection mismatch: {sorted(selected - found)}")
        writer.write_header_to_file()
        writer.write_kv_data_to_file()
        writer.write_tensors_to_file(progress=False)
    finally:
        writer.close()


def inventory(model: Path, folder: Path, stage_count: int) -> dict:
    model_hash = sha256(model)
    with GGUFFile(model, metadata_filter=lambda key: not key.startswith("tokenizer.")) as source:
        block_count = int(source.metadata["llama.block_count"])
        all_names = set(source.tensors)
    stages = []
    for index, (start, end) in enumerate(layer_ranges(block_count, stage_count)):
        selected = tensor_names(all_names, start, end, block_count)
        path = folder / f"stage-{index:02d}-layers-{start:02d}-{end:02d}.gguf"
        if not path.is_file():
            raise ValueError(f"missing stage shard {path}")
        with GGUFFile(path, metadata_filter=lambda key: not key.startswith("tokenizer.")) as shard:
            actual_names = set(shard.tensors)
            if actual_names != selected:
                raise ValueError(f"stage {index} tensor set mismatch")
            if int(shard.metadata["llama.block_count"]) != block_count:
                raise ValueError(f"stage {index} block_count mismatch")
        stages.append({
            "index": index,
            "role": "first" if start == 0 else "final" if end == block_count else "middle",
            "layer_start": start,
            "layer_end": end,
            "file": path.name,
            "bytes": path.stat().st_size,
            "sha256": sha256(path),
            "tensor_count": len(selected),
            "tensors": sorted(selected),
        })
    commitment = hashlib.sha256(DOMAIN + bytes.fromhex(model_hash) + b"".join(
        stage["index"].to_bytes(4, "big")
        + stage["layer_start"].to_bytes(4, "big")
        + stage["layer_end"].to_bytes(4, "big")
        + stage["bytes"].to_bytes(8, "big")
        + bytes.fromhex(stage["sha256"])
        for stage in stages
    )).hexdigest()
    return {
        "schema": "synergy.executable-llama-layer-shards/v1",
        "executable_layer_stages": True,
        "model_file": model.name,
        "model_bytes": model.stat().st_size,
        "model_sha256": model_hash,
        "block_count": block_count,
        "stage_count": stage_count,
        "stage_root": commitment,
        "stages": stages,
    }


def canonical_json(value: dict) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"


def main() -> None:
    if len(sys.argv) not in (5, 6) or sys.argv[1] not in ("create", "verify"):
        raise SystemExit(__doc__)
    mode = sys.argv[1]
    model, folder, manifest = map(Path, sys.argv[2:5])
    stage_count = int(sys.argv[5]) if len(sys.argv) == 6 else 4
    if mode == "create":
        folder.mkdir(parents=True, exist_ok=True)
        with GGUFFile(model, metadata_filter=lambda key: not key.startswith("tokenizer.")) as source:
            block_count = int(source.metadata["llama.block_count"])
            all_names = set(source.tensors)
        for index, (start, end) in enumerate(layer_ranges(block_count, stage_count)):
            destination = folder / f"stage-{index:02d}-layers-{start:02d}-{end:02d}.gguf"
            create_shard(model, destination, tensor_names(all_names, start, end, block_count))
        actual = inventory(model, folder, stage_count)
        manifest.parent.mkdir(parents=True, exist_ok=True)
        manifest.write_text(canonical_json(actual), encoding="ascii")
    else:
        actual = inventory(model, folder, stage_count)
        if manifest.read_text(encoding="ascii") != canonical_json(actual):
            raise SystemExit("layer shard manifest mismatch")
    print(f"{mode} OK: {stage_count} executable stages; root={actual['stage_root']}")


if __name__ == "__main__":
    main()
