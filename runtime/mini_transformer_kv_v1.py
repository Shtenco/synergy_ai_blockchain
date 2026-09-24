from __future__ import annotations

from dataclasses import dataclass
import io
import json
import math
import numpy as np

from .mini_transformer_v1 import MiniTransformerConfig, MiniTransformerWeights, TransformerError, _rms_norm, _softmax


@dataclass
class BlockKvState:
    k: np.ndarray
    v: np.ndarray

    @classmethod
    def empty(cls, heads: int, head_dim: int) -> "BlockKvState":
        return cls(
            np.empty((heads, 0, head_dim), dtype=np.float32),
            np.empty((heads, 0, head_dim), dtype=np.float32),
        )


class IncrementalBlock:
    def __init__(self, block):
        self.block = block

    def step(self, x: np.ndarray, state: BlockKvState) -> tuple[np.ndarray, BlockKvState]:
        if x.ndim != 1:
            raise TransformerError("incremental block expects [d_model]")
        d_model = x.shape[0]
        heads = self.block.n_heads
        head_dim = d_model // heads
        n = _rms_norm(x[None, :])[0]
        q = (n @ self.block.wq).reshape(heads, head_dim)
        k_new = (n @ self.block.wk).reshape(heads, 1, head_dim)
        v_new = (n @ self.block.wv).reshape(heads, 1, head_dim)
        k = np.concatenate([state.k, k_new], axis=1)
        v = np.concatenate([state.v, v_new], axis=1)
        scores = np.einsum("hd,hsd->hs", q, k) / math.sqrt(head_dim)
        attn = _softmax(scores)
        mixed = np.einsum("hs,hsd->hd", attn, v).reshape(d_model)
        y = x + mixed @ self.block.wo
        n2 = _rms_norm(y[None, :])[0]
        hidden = np.maximum(0.0, n2 @ self.block.w1)
        y = y + hidden @ self.block.w2
        return y.astype(np.float32), BlockKvState(k.astype(np.float32), v.astype(np.float32))


@dataclass
class Stage0KvState:
    position: int
    block: BlockKvState


@dataclass
class Stage1KvState:
    position: int
    block: BlockKvState


class IncrementalStage0:
    def __init__(self, config: MiniTransformerConfig | None = None):
        self.config = config or MiniTransformerConfig()
        self.weights = MiniTransformerWeights.deterministic(self.config)
        hd = self.config.d_model // self.config.n_heads
        self.state = Stage0KvState(0, BlockKvState.empty(self.config.n_heads, hd))
        self.block = IncrementalBlock(self.weights.block0)

    def step(self, token_id: int) -> np.ndarray:
        if not 0 <= token_id < self.config.vocab_size:
            raise TransformerError("token out of range")
        if self.state.position >= self.config.max_seq:
            raise TransformerError("sequence limit reached")
        x = (
            self.weights.token_embedding[token_id]
            + self.weights.positional_embedding[self.state.position]
        ).astype(np.float32)
        y, block_state = self.block.step(x, self.state.block)
        self.state = Stage0KvState(self.state.position + 1, block_state)
        return y

    def snapshot(self) -> bytes:
        buf = io.BytesIO()
        np.savez(
            buf,
            position=np.asarray([self.state.position], dtype=np.int64),
            k=self.state.block.k,
            v=self.state.block.v,
        )
        return buf.getvalue()

    def restore(self, payload: bytes) -> None:
        data = np.load(io.BytesIO(payload), allow_pickle=False)
        position = int(data["position"][0])
        k = np.asarray(data["k"], dtype=np.float32)
        v = np.asarray(data["v"], dtype=np.float32)
        hd = self.config.d_model // self.config.n_heads
        if k.shape != (self.config.n_heads, position, hd) or v.shape != k.shape:
            raise TransformerError("stage0 KV shape mismatch")
        if not 0 <= position <= self.config.max_seq:
            raise TransformerError("stage0 KV position invalid")
        self.state = Stage0KvState(position, BlockKvState(k.copy(), v.copy()))


class IncrementalStage1:
    def __init__(self, config: MiniTransformerConfig | None = None):
        self.config = config or MiniTransformerConfig()
        self.weights = MiniTransformerWeights.deterministic(self.config)
        hd = self.config.d_model // self.config.n_heads
        self.state = Stage1KvState(0, BlockKvState.empty(self.config.n_heads, hd))
        self.block = IncrementalBlock(self.weights.block1)

    def step(self, activation: np.ndarray) -> int:
        if self.state.position >= self.config.max_seq:
            raise TransformerError("sequence limit reached")
        if activation.shape != (self.config.d_model,):
            raise TransformerError("stage1 activation shape mismatch")
        y, block_state = self.block.step(activation.astype(np.float32), self.state.block)
        self.state = Stage1KvState(self.state.position + 1, block_state)
        logits = _rms_norm(y[None, :])[0] @ self.weights.lm_head
        return int(np.argmax(logits))

    def snapshot(self) -> bytes:
        buf = io.BytesIO()
        np.savez(
            buf,
            position=np.asarray([self.state.position], dtype=np.int64),
            k=self.state.block.k,
            v=self.state.block.v,
        )
        return buf.getvalue()

    def restore(self, payload: bytes) -> None:
        data = np.load(io.BytesIO(payload), allow_pickle=False)
        position = int(data["position"][0])
        k = np.asarray(data["k"], dtype=np.float32)
        v = np.asarray(data["v"], dtype=np.float32)
        hd = self.config.d_model // self.config.n_heads
        if k.shape != (self.config.n_heads, position, hd) or v.shape != k.shape:
            raise TransformerError("stage1 KV shape mismatch")
        if not 0 <= position <= self.config.max_seq:
            raise TransformerError("stage1 KV position invalid")
        self.state = Stage1KvState(position, BlockKvState(k.copy(), v.copy()))


def prefill(stage0: IncrementalStage0, stage1: IncrementalStage1, prompt: bytes) -> int:
    last = 0
    for token in prompt[: stage0.config.max_seq]:
        last = stage1.step(stage0.step(int(token)))
    return last


def generate_one(stage0: IncrementalStage0, stage1: IncrementalStage1, token: int) -> int:
    return stage1.step(stage0.step(token))
