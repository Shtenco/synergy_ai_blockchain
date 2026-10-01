from __future__ import annotations

from dataclasses import dataclass
import hashlib
import math
from pathlib import Path
import struct

import numpy as np

from .gguf_v3 import GGUFError, GGUFFile, MappedTensor


class LlamaRuntimeError(ValueError):
    pass


_FRAME = struct.Struct("<4sBBHIII")
_MAGIC = b"SL32"
_VERSION = 1
TOKENS = 1
ACTIVATIONS = 2
LOGITS = 3


@dataclass(frozen=True)
class LlamaConfig:
    context_length: int
    embedding_length: int
    block_count: int
    feed_forward_length: int
    head_count: int
    head_count_kv: int
    rope_dimension_count: int
    rope_freq_base: float
    rms_epsilon: float
    rope_scaling_type: str
    rope_scaling_factor: float
    rope_original_context: int
    rope_low_freq_factor: float
    rope_high_freq_factor: float

    @classmethod
    def from_metadata(cls, m: dict[str, object]) -> "LlamaConfig":
        if m.get("general.architecture") != "llama":
            raise LlamaRuntimeError("GGUF architecture must be llama")

        def integer(key: str, default: int | None = None) -> int:
            value = m.get(key, default)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise LlamaRuntimeError(f"missing or invalid {key}")
            return value

        def number(key: str, default: float) -> float:
            value = m.get(key, default)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
                raise LlamaRuntimeError(f"invalid {key}")
            return float(value)

        heads = integer("llama.attention.head_count")
        embedding = integer("llama.embedding_length")
        kv_heads = integer("llama.attention.head_count_kv", heads)
        rope_dim = integer("llama.rope.dimension_count", embedding // heads)
        if embedding % heads or heads % kv_heads or rope_dim % 2 or rope_dim > embedding // heads:
            raise LlamaRuntimeError("incompatible Llama attention dimensions")
        scaling_type = m.get("llama.rope.scaling.type", "none")
        if scaling_type not in ("none", "linear", "llama3"):
            raise LlamaRuntimeError(f"unsupported RoPE scaling {scaling_type!r}")
        context = integer("llama.context_length")
        return cls(
            context, embedding, integer("llama.block_count"), integer("llama.feed_forward_length"),
            heads, kv_heads, rope_dim, number("llama.rope.freq_base", 10000.0),
            number("llama.attention.layer_norm_rms_epsilon", 1e-5), str(scaling_type),
            number("llama.rope.scaling.factor", 1.0),
            integer("llama.rope.scaling.original_context_length", context),
            number("llama.rope.scaling.low_freq_factor", 1.0),
            number("llama.rope.scaling.high_freq_factor", 4.0),
        )


def encode_tokens(token_ids: list[int] | np.ndarray, position: int) -> bytes:
    tokens = np.asarray(token_ids, dtype="<u4")
    if tokens.ndim != 1 or not len(tokens):
        raise LlamaRuntimeError("at least one token ID is required")
    return _FRAME.pack(_MAGIC, _VERSION, TOKENS, 0, position, len(tokens), 1) + tokens.tobytes()


def encode_activations(hidden: np.ndarray, position: int) -> bytes:
    x = np.asarray(hidden, dtype="<f4")
    if x.ndim == 1:
        x = x[None, :]
    if x.ndim != 2 or not x.shape[0] or not x.shape[1]:
        raise LlamaRuntimeError("activations must be [tokens, embedding]")
    return _FRAME.pack(_MAGIC, _VERSION, ACTIVATIONS, 0, position, x.shape[0], x.shape[1]) + x.tobytes()


def decode_payload(payload: bytes) -> tuple[int, int, np.ndarray, int | None]:
    if len(payload) < _FRAME.size:
        raise LlamaRuntimeError("stage payload is truncated")
    magic, version, kind, flags, position, rows, cols = _FRAME.unpack_from(payload)
    if magic != _MAGIC or version != _VERSION or flags != 0 or not rows or not cols:
        raise LlamaRuntimeError("invalid stage payload header")
    body = payload[_FRAME.size:]
    if kind == TOKENS:
        if cols != 1 or len(body) != rows * 4:
            raise LlamaRuntimeError("invalid token payload")
        return kind, position, np.frombuffer(body, dtype="<u4").copy(), None
    if kind in (ACTIVATIONS, LOGITS):
        extra = 4 if kind == LOGITS else 0
        if len(body) != rows * cols * 4 + extra:
            raise LlamaRuntimeError("invalid float payload")
        values = np.frombuffer(body, dtype="<f4", count=rows * cols).copy().reshape(rows, cols)
        top = struct.unpack_from("<I", body, rows * cols * 4)[0] if kind == LOGITS else None
        return kind, position, values, top
    raise LlamaRuntimeError("unknown stage payload kind")


def encode_logits(logits: np.ndarray, position: int) -> bytes:
    values = np.asarray(logits, dtype="<f4").reshape(1, -1)
    top = int(np.argmax(values[0]))
    return (_FRAME.pack(_MAGIC, _VERSION, LOGITS, 0, position, 1, values.shape[1])
            + values.tobytes() + struct.pack("<I", top))


class LayerKvCache:
    def __init__(self, max_context: int, kv_heads: int, head_dim: int):
        self.k = np.empty((max_context, kv_heads, head_dim), dtype=np.float32)
        self.v = np.empty_like(self.k)


class LlamaMmapStage:
    """StageBackend-compatible contiguous-layer Llama executor.

    Calls are incremental and stateful. A pipeline sends the same position and
    token count through each stage in order. reset() starts a new sequence.
    """

    def __init__(
        self,
        model_path: str | Path,
        layer_start: int,
        layer_end: int,
        *,
        max_context: int = 512,
        chunk_rows: int = 32,
        model_root: str | None = None,
        shard_root: str | None = None,
        capability_root: str | None = None,
    ):
        self.model_path = Path(model_path)
        self.gguf = GGUFFile(self.model_path, metadata_filter=lambda key: not key.startswith("tokenizer."))
        self.config = LlamaConfig.from_metadata(self.gguf.metadata)
        if not 0 <= layer_start < layer_end <= self.config.block_count:
            raise LlamaRuntimeError("invalid contiguous layer range")
        if not 0 < max_context <= self.config.context_length or chunk_rows <= 0:
            raise LlamaRuntimeError("invalid runtime memory limits")
        self.layer_start, self.layer_end = layer_start, layer_end
        self.max_context, self.chunk_rows, self.position = max_context, chunk_rows, 0
        self._validate_tensors()
        head_dim = self.config.embedding_length // self.config.head_count
        self.cache = {
            layer: LayerKvCache(max_context, self.config.head_count_kv, head_dim)
            for layer in range(layer_start, layer_end)
        }
        self.model_root = model_root or _sha256_file(self.model_path)
        span = f"{layer_start}:{layer_end}".encode()
        self.shard_root = shard_root or hashlib.sha256(
            b"SYNERGY/GGUF-MMAP/STAGE/V1\0" + self.model_root.encode("ascii") + span
        ).hexdigest()
        self.capability_root = capability_root or hashlib.sha256(b"numpy-mmap-q4k-q6k/v1\0" + span).hexdigest()

    def _validate_tensors(self) -> None:
        d = self.config.embedding_length
        head_dim = d // self.config.head_count
        kv_width = self.config.head_count_kv * head_dim
        ff = self.config.feed_forward_length
        expected: dict[str, tuple[int, ...]] = {}
        if self.layer_start == 0:
            embedding = self.gguf.tensor("token_embd.weight")
            if len(embedding.shape) != 2 or embedding.shape[1] != d:
                raise LlamaRuntimeError("token_embd.weight shape mismatch")
        for i in range(self.layer_start, self.layer_end):
            prefix = f"blk.{i}."
            expected.update({
                prefix + "attn_norm.weight": (d,),
                prefix + "attn_q.weight": (d, d),
                prefix + "attn_k.weight": (kv_width, d),
                prefix + "attn_v.weight": (kv_width, d),
                prefix + "attn_output.weight": (d, d),
                prefix + "ffn_norm.weight": (d,),
                prefix + "ffn_gate.weight": (ff, d),
                prefix + "ffn_up.weight": (ff, d),
                prefix + "ffn_down.weight": (d, ff),
            })
        if self.layer_end == self.config.block_count:
            expected["output_norm.weight"] = (d,)
            if "output.weight" in self.gguf.tensors:
                output = self.gguf.tensor("output.weight")
                if len(output.shape) != 2 or output.shape[1] != d:
                    raise LlamaRuntimeError("output.weight shape mismatch")
            elif "token_embd.weight" not in self.gguf.tensors:
                raise LlamaRuntimeError("missing output.weight and token_embd.weight")
        for name, shape in expected.items():
            if self.gguf.tensor(name).shape != shape:
                raise LlamaRuntimeError(f"{name} shape mismatch")

    def reset(self) -> None:
        self.position = 0

    def close(self) -> None:
        self.gguf.close()

    def run(self, payload: bytes) -> bytes:
        kind, position, values, _ = decode_payload(payload)
        if position != self.position:
            raise LlamaRuntimeError(f"expected position {self.position}, got {position}")
        if self.layer_start == 0:
            if kind != TOKENS:
                raise LlamaRuntimeError("first stage requires token IDs")
            embedding = self.gguf.tensor("token_embd.weight")
            vocab, width = embedding.shape
            if width != self.config.embedding_length or np.any(values >= vocab):
                raise LlamaRuntimeError("token ID outside vocabulary")
            hidden = embedding.gather(values.astype(np.int64))
        else:
            if kind != ACTIVATIONS or values.shape[1] != self.config.embedding_length:
                raise LlamaRuntimeError("middle stage requires matching activations")
            hidden = values
        if self.position + len(hidden) > self.max_context:
            raise LlamaRuntimeError("stage context limit exceeded")
        hidden = self._run_layers(hidden, position)
        self.position += len(hidden)
        if self.layer_end != self.config.block_count:
            return encode_activations(hidden, position)
        normed = _rms_norm(hidden[-1], self.gguf.tensor("output_norm.weight").vector(), self.config.rms_epsilon)
        output_name = "output.weight" if "output.weight" in self.gguf.tensors else "token_embd.weight"
        logits = self.gguf.tensor(output_name).matvec(
            normed, chunk_rows=self.chunk_rows, quantize_input=True
        )
        return encode_logits(logits, position)

    def _run_layers(self, hidden: np.ndarray, position: int) -> np.ndarray:
        n_tokens = len(hidden)
        for layer in range(self.layer_start, self.layer_end):
            prefix = f"blk.{layer}."
            n = _rms_norm_batch(hidden, self.gguf.tensor(prefix + "attn_norm.weight").vector(), self.config.rms_epsilon)
            head_dim = self.config.embedding_length // self.config.head_count
            q = self._mv_batch(prefix + "attn_q.weight", n).reshape(n_tokens, self.config.head_count, head_dim)
            k = self._mv_batch(prefix + "attn_k.weight", n).reshape(n_tokens, self.config.head_count_kv, head_dim)
            v = self._mv_batch(prefix + "attn_v.weight", n).reshape(n_tokens, self.config.head_count_kv, head_dim)
            q = _rope_batch(q, position, self.config)
            k = _rope_batch(k, position, self.config)
            cache = self.cache[layer]
            cache.k[position:position + n_tokens] = k
            cache.v[position:position + n_tokens] = v
            groups = self.config.head_count // self.config.head_count_kv
            kv_index = np.arange(self.config.head_count) // groups
            keys = cache.k[:position + n_tokens, kv_index].transpose(1, 0, 2)
            vals = cache.v[:position + n_tokens, kv_index].transpose(1, 0, 2)
            scores = np.einsum("thd,hsd->hts", q, keys, optimize=False) / np.float32(math.sqrt(head_dim))
            query_positions = np.arange(position, position + n_tokens)
            key_positions = np.arange(position + n_tokens)
            scores = np.where(
                key_positions[None, None, :] <= query_positions[None, :, None],
                scores,
                -np.inf,
            )
            scores -= scores.max(axis=2, keepdims=True)
            attention = np.exp(scores, dtype=np.float32)
            attention /= attention.sum(axis=2, keepdims=True)
            mixed = np.einsum("hts,hsd->thd", attention, vals, optimize=False).reshape(n_tokens, -1)
            hidden = hidden + self._mv_batch(prefix + "attn_output.weight", mixed)
            n = _rms_norm_batch(hidden, self.gguf.tensor(prefix + "ffn_norm.weight").vector(), self.config.rms_epsilon)
            gate = self._mv_batch(prefix + "ffn_gate.weight", n)
            up = self._mv_batch(prefix + "ffn_up.weight", n)
            with np.errstate(over="ignore"):
                silu_gate = gate / (np.float32(1.0) + np.exp(-gate, dtype=np.float32))
            hidden = (hidden + self._mv_batch(prefix + "ffn_down.weight", silu_gate * up)).astype(np.float32)
        return hidden

    def _mv_batch(self, name: str, x: np.ndarray) -> np.ndarray:
        return self.gguf.tensor(name).matmul(
            x, chunk_rows=self.chunk_rows, quantize_input=True
        )


class LlamaFirstStage(LlamaMmapStage):
    def __init__(self, model_path: str | Path, layer_end: int, **kwargs):
        super().__init__(model_path, 0, layer_end, **kwargs)


class LlamaMiddleStage(LlamaMmapStage):
    pass


class LlamaFinalStage(LlamaMmapStage):
    def __init__(self, model_path: str | Path, layer_start: int, **kwargs):
        with GGUFFile(model_path, metadata_filter=lambda key: not key.startswith("tokenizer.")) as gguf:
            end = int(gguf.metadata["llama.block_count"])
        super().__init__(model_path, layer_start, end, **kwargs)


def _rms_norm(x: np.ndarray, weight: np.ndarray, epsilon: float) -> np.ndarray:
    if x.shape != weight.shape:
        raise LlamaRuntimeError("RMSNorm dimension mismatch")
    scale = np.float32(1.0) / np.sqrt(np.mean(x * x, dtype=np.float32) + np.float32(epsilon))
    return (x * scale * weight).astype(np.float32)


def _rms_norm_batch(x: np.ndarray, weight: np.ndarray, epsilon: float) -> np.ndarray:
    scale = np.float32(1.0) / np.sqrt(np.mean(x * x, axis=1, dtype=np.float32, keepdims=True) + np.float32(epsilon))
    return (x * scale * weight).astype(np.float32)


def _rope(x: np.ndarray, position: int, config: LlamaConfig) -> np.ndarray:
    rotary = config.rope_dimension_count
    frequency = config.rope_freq_base ** (-np.arange(0, rotary, 2, dtype=np.float32) / np.float32(rotary))
    if config.rope_scaling_type == "linear":
        frequency /= np.float32(config.rope_scaling_factor)
    elif config.rope_scaling_type == "llama3":
        wavelength = np.float32(2.0 * math.pi) / frequency
        low = config.rope_original_context / config.rope_low_freq_factor
        high = config.rope_original_context / config.rope_high_freq_factor
        scaled = frequency / np.float32(config.rope_scaling_factor)
        smooth = (config.rope_original_context / wavelength - config.rope_low_freq_factor) / (
            config.rope_high_freq_factor - config.rope_low_freq_factor
        )
        medium = (np.float32(1.0) - smooth) * scaled + smooth * frequency
        frequency = np.where(wavelength > low, scaled, np.where(wavelength < high, frequency, medium))
    angle = np.float32(position) * frequency
    cos, sin = np.cos(angle, dtype=np.float32), np.sin(angle, dtype=np.float32)
    out = x.copy()
    pairs = x[:, :rotary].reshape(x.shape[0], rotary // 2, 2)
    rotated = out[:, :rotary].reshape(out.shape[0], rotary // 2, 2)
    rotated[:, :, 0] = pairs[:, :, 0] * cos - pairs[:, :, 1] * sin
    rotated[:, :, 1] = pairs[:, :, 0] * sin + pairs[:, :, 1] * cos
    return out


def _rope_batch(x: np.ndarray, position: int, config: LlamaConfig) -> np.ndarray:
    rotary = config.rope_dimension_count
    frequency = config.rope_freq_base ** (-np.arange(0, rotary, 2, dtype=np.float32) / np.float32(rotary))
    if config.rope_scaling_type == "linear":
        frequency /= np.float32(config.rope_scaling_factor)
    elif config.rope_scaling_type == "llama3":
        wavelength = np.float32(2.0 * math.pi) / frequency
        low = config.rope_original_context / config.rope_low_freq_factor
        high = config.rope_original_context / config.rope_high_freq_factor
        scaled = frequency / np.float32(config.rope_scaling_factor)
        smooth = (config.rope_original_context / wavelength - config.rope_low_freq_factor) / (
            config.rope_high_freq_factor - config.rope_low_freq_factor
        )
        medium = (np.float32(1.0) - smooth) * scaled + smooth * frequency
        frequency = np.where(wavelength > low, scaled, np.where(wavelength < high, frequency, medium))
    n_tokens = x.shape[0]
    positions = np.arange(position, position + n_tokens, dtype=np.float32)
    angle = positions[:, None] * frequency[None, :]
    cos, sin = np.cos(angle, dtype=np.float32), np.sin(angle, dtype=np.float32)
    out = x.copy()
    pairs = x[:, :, :rotary].reshape(x.shape[0], x.shape[1], rotary // 2, 2)
    rotated = out[:, :, :rotary].reshape(out.shape[0], out.shape[1], rotary // 2, 2)
    rotated[:, :, :, 0] = pairs[:, :, :, 0] * cos[:, None, :] - pairs[:, :, :, 1] * sin[:, None, :]
    rotated[:, :, :, 1] = pairs[:, :, :, 0] * sin[:, None, :] + pairs[:, :, :, 1] * cos[:, None, :]
    return out


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(8 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()
