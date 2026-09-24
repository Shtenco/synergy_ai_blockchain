from __future__ import annotations

from dataclasses import dataclass
import io
import json
import math
import numpy as np

FORMAT = "synergy.mini-transformer-activation/v1"


class TransformerError(ValueError):
    pass


@dataclass(frozen=True)
class MiniTransformerConfig:
    vocab_size: int = 256
    d_model: int = 64
    n_heads: int = 4
    d_ff: int = 128
    max_seq: int = 128
    seed: int = 20260924

    def validate(self) -> None:
        if self.vocab_size <= 1 or self.d_model <= 0 or self.n_heads <= 0 or self.d_ff <= 0 or self.max_seq <= 0:
            raise TransformerError("invalid transformer dimensions")
        if self.d_model % self.n_heads != 0:
            raise TransformerError("d_model must divide n_heads")


def _rms_norm(x: np.ndarray, eps: float = 1e-6) -> np.ndarray:
    scale = np.sqrt(np.mean(np.square(x), axis=-1, keepdims=True) + eps)
    return x / scale


def _softmax(x: np.ndarray) -> np.ndarray:
    z = x - np.max(x, axis=-1, keepdims=True)
    ez = np.exp(z)
    return ez / np.sum(ez, axis=-1, keepdims=True)


@dataclass
class TransformerBlock:
    wq: np.ndarray
    wk: np.ndarray
    wv: np.ndarray
    wo: np.ndarray
    w1: np.ndarray
    w2: np.ndarray
    n_heads: int

    def forward(self, x: np.ndarray) -> np.ndarray:
        if x.ndim != 2:
            raise TransformerError("block input must be [seq,d_model]")
        seq, d_model = x.shape
        head_dim = d_model // self.n_heads
        n = _rms_norm(x)
        q = (n @ self.wq).reshape(seq, self.n_heads, head_dim).transpose(1, 0, 2)
        k = (n @ self.wk).reshape(seq, self.n_heads, head_dim).transpose(1, 0, 2)
        v = (n @ self.wv).reshape(seq, self.n_heads, head_dim).transpose(1, 0, 2)
        scores = (q @ k.transpose(0, 2, 1)) / math.sqrt(head_dim)
        causal = np.triu(np.ones((seq, seq), dtype=bool), k=1)
        scores = np.where(causal[None, :, :], -1e30, scores)
        attn = _softmax(scores)
        mixed = (attn @ v).transpose(1, 0, 2).reshape(seq, d_model)
        x = x + mixed @ self.wo
        n2 = _rms_norm(x)
        hidden = np.maximum(0.0, n2 @ self.w1)
        return x + hidden @ self.w2


@dataclass
class MiniTransformerWeights:
    token_embedding: np.ndarray
    positional_embedding: np.ndarray
    block0: TransformerBlock
    block1: TransformerBlock
    lm_head: np.ndarray

    @classmethod
    def deterministic(cls, config: MiniTransformerConfig) -> "MiniTransformerWeights":
        config.validate()
        rng = np.random.default_rng(config.seed)

        def m(a: int, b: int) -> np.ndarray:
            return (rng.standard_normal((a, b), dtype=np.float32) / math.sqrt(a)).astype(np.float32)

        def block() -> TransformerBlock:
            d = config.d_model
            return TransformerBlock(m(d,d),m(d,d),m(d,d),m(d,d),m(d,config.d_ff),m(config.d_ff,d),config.n_heads)

        return cls(
            token_embedding=m(config.vocab_size, config.d_model),
            positional_embedding=m(config.max_seq, config.d_model),
            block0=block(),
            block1=block(),
            lm_head=m(config.d_model, config.vocab_size),
        )


def encode_bytes(prompt: bytes, config: MiniTransformerConfig) -> np.ndarray:
    if not prompt:
        raise TransformerError("prompt required")
    data = np.frombuffer(bytes(prompt[:config.max_seq]), dtype=np.uint8).astype(np.int64)
    return data


def _save_activation(tokens: np.ndarray, hidden: np.ndarray) -> bytes:
    meta = json.dumps({"format":FORMAT,"tokens":tokens.tolist()}, separators=(",",":"), sort_keys=True).encode()
    if len(meta) > 16 * 1024:
        raise TransformerError("activation metadata too large")
    buf = io.BytesIO()
    np.save(buf, hidden.astype(np.float32), allow_pickle=False)
    body = buf.getvalue()
    return len(meta).to_bytes(4, "big") + meta + body


def _load_activation(payload: bytes) -> tuple[np.ndarray, np.ndarray]:
    if len(payload) < 4:
        raise TransformerError("activation frame too short")
    n = int.from_bytes(payload[:4], "big")
    if n <= 0 or n > 16 * 1024 or 4 + n > len(payload):
        raise TransformerError("invalid activation metadata length")
    meta = json.loads(payload[4:4+n].decode())
    if meta.get("format") != FORMAT or not isinstance(meta.get("tokens"), list):
        raise TransformerError("activation format mismatch")
    tokens = np.asarray(meta["tokens"], dtype=np.int64)
    hidden = np.load(io.BytesIO(payload[4+n:]), allow_pickle=False)
    if hidden.dtype != np.float32 or hidden.ndim != 2 or hidden.shape[0] != len(tokens):
        raise TransformerError("activation tensor mismatch")
    return tokens, hidden


class MiniTransformerStage0:
    def __init__(self, config: MiniTransformerConfig | None = None):
        self.config = config or MiniTransformerConfig()
        self.weights = MiniTransformerWeights.deterministic(self.config)
        self.model_root = _root("model", self.config)
        self.shard_root = _root("stage0", self.config)
        self.capability_root = _root("numpy-cpu-stage0", self.config)

    def run(self, payload: bytes) -> bytes:
        tokens = encode_bytes(payload, self.config)
        pos = np.arange(len(tokens))
        hidden = self.weights.token_embedding[tokens] + self.weights.positional_embedding[pos]
        hidden = self.weights.block0.forward(hidden)
        return _save_activation(tokens, hidden)


class MiniTransformerStage1:
    def __init__(self, config: MiniTransformerConfig | None = None):
        self.config = config or MiniTransformerConfig()
        self.weights = MiniTransformerWeights.deterministic(self.config)
        self.model_root = _root("model", self.config)
        self.shard_root = _root("stage1", self.config)
        self.capability_root = _root("numpy-cpu-stage1", self.config)

    def run(self, payload: bytes) -> bytes:
        tokens, hidden = _load_activation(payload)
        if hidden.shape[1] != self.config.d_model or len(tokens) > self.config.max_seq:
            raise TransformerError("activation dimensions outside config")
        hidden = self.weights.block1.forward(hidden)
        logits = _rms_norm(hidden)[-1] @ self.weights.lm_head
        token = int(np.argmax(logits))
        return bytes([token])


def _root(label: str, config: MiniTransformerConfig) -> str:
    import hashlib
    body = json.dumps({
        "label":label,
        "vocab_size":config.vocab_size,
        "d_model":config.d_model,
        "n_heads":config.n_heads,
        "d_ff":config.d_ff,
        "max_seq":config.max_seq,
        "seed":config.seed,
    },sort_keys=True,separators=(",",":")).encode()
    return hashlib.sha256(b"SYNERGY/MINI-TRANSFORMER/V1\0"+body).hexdigest()


def reference_next_token(prompt: bytes, config: MiniTransformerConfig | None = None) -> int:
    cfg = config or MiniTransformerConfig()
    return MiniTransformerStage1(cfg).run(MiniTransformerStage0(cfg).run(prompt))[0]
