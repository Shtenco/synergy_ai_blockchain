from __future__ import annotations

from dataclasses import dataclass
import hashlib
import math
from pathlib import Path
import time
from typing import Sequence

import numpy as np

from .gguf_v3 import GGUFFile
from .llama_mmap_v1 import (
    ACTIVATIONS,
    LOGITS,
    TOKENS,
    LlamaConfig,
    LlamaMmapStage,
    decode_payload,
    encode_activations,
    encode_logits,
    encode_tokens,
)
from .llama_tokenizer_v1 import LlamaBpeTokenizer


@dataclass(frozen=True)
class PipelineResult:
    token_ids: list[int]
    text: str
    elapsed_seconds: float
    tokens_per_second: float


class LlamaPipeline:
    def __init__(
        self,
        model_path: str | Path,
        *,
        stage_layers: int = 7,
        stage_paths: Sequence[str | Path] | None = None,
        max_context: int = 512,
        chunk_rows: int = 32,
    ):
        self.model_path = Path(model_path)
        self.max_context = max_context
        self.stage_layers = stage_layers
        with GGUFFile(self.model_path, metadata_filter=lambda k: not k.startswith("tokenizer.")) as g:
            self.config = LlamaConfig.from_metadata(g.metadata)
        self.tokenizer = LlamaBpeTokenizer(self.model_path)
        model_root = _sha256_file(self.model_path)
        self.stages: list[LlamaMmapStage] = []
        paths = [Path(path) for path in stage_paths] if stage_paths is not None else None
        expected_stages = (self.config.block_count + stage_layers - 1) // stage_layers
        if paths is not None and len(paths) != expected_stages:
            raise ValueError(f"expected {expected_stages} stage paths, got {len(paths)}")
        layer = 0
        stage_index = 0
        while layer < self.config.block_count:
            end = min(layer + stage_layers, self.config.block_count)
            self.stages.append(
                LlamaMmapStage(
                    paths[stage_index] if paths is not None else self.model_path,
                    layer,
                    end,
                    max_context=max_context,
                    chunk_rows=chunk_rows,
                    model_root=model_root,
                )
            )
            layer = end
            stage_index += 1

    def reset(self) -> None:
        for stage in self.stages:
            stage.reset()

    def close(self) -> None:
        for stage in self.stages:
            stage.close()

    def __enter__(self) -> "LlamaPipeline":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def generate(
        self,
        prompt: str,
        *,
        max_new_tokens: int = 32,
        temperature: float = 0.0,
        seed: int = 1,
    ) -> PipelineResult:
        rng = np.random.default_rng(seed)
        input_ids = self.tokenizer.encode(prompt)
        if len(input_ids) + max(0, max_new_tokens - 1) > self.max_context:
            raise ValueError(f"prompt exceeds max_context={self.max_context}")
        if max_new_tokens < 0:
            raise ValueError("max_new_tokens must be non-negative")
        if not math.isfinite(temperature) or temperature < 0:
            raise ValueError("temperature must be finite and non-negative")
        self.reset()
        generated: list[int] = []
        start = time.perf_counter()
        pending = input_ids
        position = 0
        for _ in range(max_new_tokens):
            payload = encode_tokens(pending, position)
            for stage in self.stages:
                payload = stage.run(payload)
            kind, _, logits, top = decode_payload(payload)
            if kind != LOGITS:
                raise RuntimeError("pipeline did not produce logits")
            if temperature > 0:
                probs = _softmax(logits[0] / temperature)
                next_id = int(rng.choice(len(probs), p=probs))
            else:
                next_id = int(top)
            if next_id in self.tokenizer.eog_token_ids:
                break
            generated.append(next_id)
            position += len(pending)
            pending = [next_id]
        elapsed = time.perf_counter() - start
        text = self.tokenizer.decode(generated)
        return PipelineResult(
            token_ids=generated,
            text=text,
            elapsed_seconds=elapsed,
            tokens_per_second=len(generated) / elapsed if elapsed > 0 else 0.0,
        )


def _softmax(x: np.ndarray) -> np.ndarray:
    x = x - x.max()
    e = np.exp(x)
    return e / e.sum()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
