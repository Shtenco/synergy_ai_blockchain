from __future__ import annotations

from dataclasses import dataclass
import mmap
from pathlib import Path
import struct
from typing import Any, Callable

import numpy as np


class GGUFError(ValueError):
    pass


F32 = 0
F16 = 1
Q4_K = 12
Q6_K = 14

# (values per block, bytes per block). These are the on-disk ggml layouts.
_TYPE_LAYOUT = {F32: (1, 4), F16: (1, 2), Q4_K: (256, 144), Q6_K: (256, 210)}
_SCALARS = {
    0: "<B", 1: "<b", 2: "<H", 3: "<h", 4: "<I", 5: "<i",
    6: "<f", 7: "<?", 10: "<Q", 11: "<q", 12: "<d",
}


@dataclass(frozen=True)
class TensorInfo:
    name: str
    dimensions: tuple[int, ...]  # GGML order: fastest-changing dimension first.
    ggml_type: int
    offset: int
    nbytes: int

    @property
    def shape(self) -> tuple[int, ...]:
        return tuple(reversed(self.dimensions))


class _Reader:
    def __init__(self, data: mmap.mmap):
        self.data = data
        self.pos = 0

    def take(self, n: int) -> memoryview:
        if n < 0 or self.pos + n > len(self.data):
            raise GGUFError("truncated GGUF")
        out = memoryview(self.data)[self.pos:self.pos + n]
        self.pos += n
        return out

    def unpack(self, fmt: str) -> Any:
        n = struct.calcsize(fmt)
        return struct.unpack(fmt, self.take(n))[0]

    def string(self, *, max_bytes: int = 1 << 28) -> str:
        n = self.unpack("<Q")
        if n > max_bytes:
            raise GGUFError("GGUF string is too large")
        try:
            return bytes(self.take(n)).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise GGUFError("invalid GGUF UTF-8") from exc

    def value(self, kind: int, *, depth: int = 0, retain: bool = True) -> Any:
        if depth > 4:
            raise GGUFError("metadata arrays nested too deeply")
        if kind in _SCALARS:
            return self.unpack(_SCALARS[kind])
        if kind == 8:
            value = self.string()
            return value if retain else None
        if kind == 9:
            element_kind = self.unpack("<I")
            count = self.unpack("<Q")
            if count > 10_000_000:
                raise GGUFError("metadata array is too large")
            if retain:
                return [self.value(element_kind, depth=depth + 1) for _ in range(count)]
            for _ in range(count):
                self.value(element_kind, depth=depth + 1, retain=False)
            return None
        raise GGUFError(f"unsupported GGUF metadata type {kind}")


class GGUFFile:
    """Read-only GGUF v3 index backed by one mmap.

    metadata_filter can discard large tokenizer arrays after parsing. It does not
    alter validation or offsets and is useful on memory-constrained workers.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        metadata_filter: Callable[[str], bool] | None = None,
    ):
        self.path = Path(path)
        self._file = self.path.open("rb")
        try:
            self._mmap = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)
            self.metadata, pending, header_end = self._parse(metadata_filter)
            alignment = self.metadata.get("general.alignment", 32)
            if isinstance(alignment, bool) or not isinstance(alignment, int) or alignment < 8 or alignment & (alignment - 1):
                raise GGUFError("invalid general.alignment")
            self.data_offset = (header_end + alignment - 1) // alignment * alignment
            tensors: dict[str, TensorInfo] = {}
            for name, dims, ggml_type, relative in pending:
                if name in tensors:
                    raise GGUFError(f"duplicate tensor {name!r}")
                if relative % alignment:
                    raise GGUFError(f"tensor {name!r} offset is not aligned")
                if ggml_type not in _TYPE_LAYOUT:
                    # Index unknown types so model validation can report their names.
                    nbytes = -1
                else:
                    block, block_bytes = _TYPE_LAYOUT[ggml_type]
                    count = _product(dims)
                    if dims[0] % block:
                        raise GGUFError(f"tensor {name!r} is not block aligned")
                    nbytes = count // block * block_bytes
                    if self.data_offset + relative + nbytes > len(self._mmap):
                        raise GGUFError(f"tensor {name!r} extends past EOF")
                tensors[name] = TensorInfo(name, dims, ggml_type, self.data_offset + relative, nbytes)
            self.tensors = tensors
        except Exception:
            if hasattr(self, "_mmap"):
                self._mmap.close()
            self._file.close()
            raise

    def _parse(self, keep: Callable[[str], bool] | None):
        r = _Reader(self._mmap)
        if bytes(r.take(4)) != b"GGUF" or r.unpack("<I") != 3:
            raise GGUFError("expected little-endian GGUF v3")
        tensor_count = r.unpack("<Q")
        metadata_count = r.unpack("<Q")
        if tensor_count > 1_000_000 or metadata_count > 1_000_000:
            raise GGUFError("unreasonable GGUF table size")
        metadata: dict[str, Any] = {}
        seen_metadata: set[str] = set()
        for _ in range(metadata_count):
            key = r.string(max_bytes=65535)
            kind = r.unpack("<I")
            retain = keep is None or keep(key)
            value = r.value(kind, retain=retain)
            if key in seen_metadata:
                raise GGUFError(f"duplicate metadata key {key!r}")
            seen_metadata.add(key)
            if retain:
                metadata[key] = value
        pending = []
        for _ in range(tensor_count):
            name = r.string(max_bytes=64)
            rank = r.unpack("<I")
            if not 1 <= rank <= 4:
                raise GGUFError("invalid tensor rank")
            dims = tuple(r.unpack("<Q") for _ in range(rank))
            if any(d == 0 for d in dims):
                raise GGUFError("zero tensor dimension")
            pending.append((name, dims, r.unpack("<I"), r.unpack("<Q")))
        return metadata, pending, r.pos

    def tensor(self, name: str) -> "MappedTensor":
        try:
            info = self.tensors[name]
        except KeyError as exc:
            raise GGUFError(f"missing tensor {name!r}") from exc
        if info.ggml_type not in _TYPE_LAYOUT:
            raise GGUFError(f"tensor {name!r} uses unsupported ggml type {info.ggml_type}")
        return MappedTensor(self._mmap, info)

    def close(self) -> None:
        self._mmap.close()
        self._file.close()

    def __enter__(self) -> "GGUFFile":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


class MappedTensor:
    def __init__(self, data: mmap.mmap, info: TensorInfo):
        self._data = data
        self.info = info

    @property
    def shape(self) -> tuple[int, ...]:
        return self.info.shape

    def rows(self, start: int, stop: int) -> np.ndarray:
        """Materialize a bounded range from a rank-2 tensor as float32."""
        if len(self.info.dimensions) != 2:
            raise GGUFError(f"tensor {self.info.name!r} is not a matrix")
        cols, total_rows = self.info.dimensions
        if not 0 <= start <= stop <= total_rows:
            raise GGUFError("row range outside tensor")
        return self._decode(start * cols, (stop - start) * cols).reshape(stop - start, cols)

    def gather(self, indices: np.ndarray) -> np.ndarray:
        """Materialize specific rows from a rank-2 tensor as float32."""
        if len(self.info.dimensions) != 2:
            raise GGUFError(f"tensor {self.info.name!r} is not a matrix")
        cols, total_rows = self.info.dimensions
        indices = np.asarray(indices, dtype=np.int64)
        if np.any(indices < 0) or np.any(indices >= total_rows):
            raise GGUFError("gather index outside tensor")
        out = np.empty((len(indices), cols), dtype=np.float32)
        for i, idx in enumerate(indices):
            out[i] = self._decode(int(idx) * cols, cols)
        return out

    def vector(self) -> np.ndarray:
        if len(self.info.dimensions) != 1:
            raise GGUFError(f"tensor {self.info.name!r} is not a vector")
        return self._decode(0, self.info.dimensions[0])

    def matvec(
        self, vector: np.ndarray, *, chunk_rows: int = 32, quantize_input: bool = False
    ) -> np.ndarray:
        if len(self.info.dimensions) != 2:
            raise GGUFError(f"tensor {self.info.name!r} is not a matrix")
        cols, rows = self.info.dimensions
        x = np.asarray(vector, dtype=np.float32)
        if x.shape != (cols,) or chunk_rows <= 0:
            raise GGUFError("matvec dimension mismatch")
        if quantize_input and self.info.ggml_type in (Q4_K, Q6_K):
            return self._quantized_matmul(x[None, :], chunk_rows)[0]
        out = np.empty(rows, dtype=np.float32)
        for first in range(0, rows, chunk_rows):
            last = min(rows, first + chunk_rows)
            out[first:last] = self.rows(first, last) @ x
        return out

    def matmul(
        self, matrix: np.ndarray, *, chunk_rows: int = 32, quantize_input: bool = False
    ) -> np.ndarray:
        if len(self.info.dimensions) != 2:
            raise GGUFError(f"tensor {self.info.name!r} is not a matrix")
        cols, rows = self.info.dimensions
        x = np.asarray(matrix, dtype=np.float32)
        if x.ndim != 2 or x.shape[1] != cols or chunk_rows <= 0:
            raise GGUFError("matmul dimension mismatch")
        if quantize_input and self.info.ggml_type in (Q4_K, Q6_K):
            return self._quantized_matmul(x, chunk_rows)
        out = np.empty((x.shape[0], rows), dtype=np.float32)
        for first in range(0, rows, chunk_rows):
            last = min(rows, first + chunk_rows)
            out[:, first:last] = x @ self.rows(first, last).T
        return out

    def _quantized_matmul(self, matrix: np.ndarray, chunk_rows: int) -> np.ndarray:
        """Match GGML K-quant matmul by quantizing each input row to Q8_K."""
        cols, rows = self.info.dimensions
        if cols % 256:
            raise GGUFError("K-quant matrix width must be divisible by 256")
        xq, xd, xsum = _quantize_q8_k(matrix)
        block_bytes = _TYPE_LAYOUT[self.info.ggml_type][1]
        blocks_per_row = cols // 256
        row_bytes = blocks_per_row * block_bytes
        out = np.empty((matrix.shape[0], rows), dtype=np.float32)
        for first in range(0, rows, chunk_rows):
            last = min(rows, first + chunk_rows)
            raw = np.frombuffer(
                self._data,
                dtype=np.uint8,
                count=(last - first) * row_bytes,
                offset=self.info.offset + first * row_bytes,
            ).reshape(last - first, blocks_per_row, block_bytes)
            if self.info.ggml_type == Q4_K:
                out[:, first:last] = _dot_q4_k_q8_k(raw, xq, xd, xsum)
            else:
                out[:, first:last] = _dot_q6_k_q8_k(raw, xq, xd)
        return out

    def _decode(self, element_start: int, count: int) -> np.ndarray:
        kind = self.info.ggml_type
        block, block_bytes = _TYPE_LAYOUT[kind]
        if element_start % block or count % block:
            raise GGUFError("quantized slice is not block aligned")
        offset = self.info.offset + element_start // block * block_bytes
        if kind in (F32, F16):
            dtype = "<f4" if kind == F32 else "<f2"
            return np.frombuffer(self._data, dtype=dtype, count=count, offset=offset).astype(np.float32, copy=True)
        raw = np.frombuffer(self._data, dtype=np.uint8, count=count // block * block_bytes, offset=offset)
        blocks = raw.reshape(-1, block_bytes)
        return dequantize_q4_k(blocks).reshape(-1) if kind == Q4_K else dequantize_q6_k(blocks).reshape(-1)


def dequantize_q4_k(blocks: bytes | bytearray | memoryview | np.ndarray) -> np.ndarray:
    """Exact block_q4_K expansion from llama.cpp's reference kernel."""
    b = np.frombuffer(blocks, dtype=np.uint8) if not isinstance(blocks, np.ndarray) else np.asarray(blocks, dtype=np.uint8)
    if b.size % 144:
        raise GGUFError("Q4_K data must contain complete 144-byte blocks")
    b = b.reshape(-1, 144)
    d = b[:, 0:2].copy().view("<f2").astype(np.float32).reshape(-1)
    dmin = b[:, 2:4].copy().view("<f2").astype(np.float32).reshape(-1)
    packed = b[:, 4:16]
    scales = np.empty((len(b), 8), dtype=np.uint8)
    mins = np.empty_like(scales)
    scales[:, :4] = packed[:, :4] & 63
    mins[:, :4] = packed[:, 4:8] & 63
    scales[:, 4:] = (packed[:, 8:12] & 15) | ((packed[:, :4] >> 6) << 4)
    mins[:, 4:] = (packed[:, 8:12] >> 4) | ((packed[:, 4:8] >> 6) << 4)
    q = b[:, 16:].reshape(-1, 4, 32)
    values = np.empty((len(b), 8, 32), dtype=np.float32)
    values[:, 0::2] = q & 15
    values[:, 1::2] = q >> 4
    values *= (d[:, None, None] * scales[:, :, None]).astype(np.float32)
    values -= (dmin[:, None, None] * mins[:, :, None]).astype(np.float32)
    return values.reshape(-1, 256)


def dequantize_q6_k(blocks: bytes | bytearray | memoryview | np.ndarray) -> np.ndarray:
    """Exact block_q6_K expansion from llama.cpp's reference kernel."""
    b = np.frombuffer(blocks, dtype=np.uint8) if not isinstance(blocks, np.ndarray) else np.asarray(blocks, dtype=np.uint8)
    if b.size % 210:
        raise GGUFError("Q6_K data must contain complete 210-byte blocks")
    b = b.reshape(-1, 210)
    ql = b[:, :128].reshape(-1, 2, 64)
    qh = b[:, 128:192].reshape(-1, 2, 32)
    scales = b[:, 192:208].view(np.int8).reshape(-1, 2, 8)
    d = b[:, 208:210].copy().view("<f2").astype(np.float32).reshape(-1)
    out = np.empty((len(b), 2, 128), dtype=np.float32)
    for half in range(2):
        lo, hi, sc = ql[:, half], qh[:, half], scales[:, half]
        quant = np.empty((len(b), 4, 32), dtype=np.int8)
        quant[:, 0] = ((lo[:, :32] & 15) | ((hi & 3) << 4)).astype(np.int8) - 32
        quant[:, 1] = ((lo[:, 32:] & 15) | (((hi >> 2) & 3) << 4)).astype(np.int8) - 32
        quant[:, 2] = ((lo[:, :32] >> 4) | (((hi >> 4) & 3) << 4)).astype(np.int8) - 32
        quant[:, 3] = ((lo[:, 32:] >> 4) | (((hi >> 6) & 3) << 4)).astype(np.int8) - 32
        scale_index = np.array([[0, 1], [2, 3], [4, 5], [6, 7]])
        expanded_scales = np.repeat(sc[:, scale_index], 16, axis=2)
        out[:, half] = (d[:, None, None] * expanded_scales * quant).reshape(len(b), 128)
    return out.reshape(-1, 256)


def _quantize_q8_k(matrix: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    blocks = np.asarray(matrix, dtype=np.float32).reshape(matrix.shape[0], -1, 256)
    maximum_indices = np.argmax(np.abs(blocks), axis=2)
    maximum = np.take_along_axis(blocks, maximum_indices[:, :, None], axis=2)[:, :, 0]
    inverse_scale = np.divide(
        np.float32(-127.0), maximum, out=np.zeros_like(maximum), where=maximum != 0
    )
    quants = np.rint(blocks * inverse_scale[:, :, None])
    quants = np.minimum(quants, np.float32(127.0)).astype(np.int8)
    scale = np.divide(
        np.float32(1.0), inverse_scale, out=np.zeros_like(inverse_scale), where=inverse_scale != 0
    )
    sums = quants.astype(np.int16).reshape(*quants.shape[:2], 16, 16).sum(axis=3, dtype=np.int16)
    return quants, scale, sums


def _q4_k_scales(raw: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    packed = raw[:, :, 4:16]
    scales = np.empty((*raw.shape[:2], 8), dtype=np.uint8)
    mins = np.empty_like(scales)
    scales[:, :, :4] = packed[:, :, :4] & 63
    mins[:, :, :4] = packed[:, :, 4:8] & 63
    scales[:, :, 4:] = (packed[:, :, 8:12] & 15) | ((packed[:, :, :4] >> 6) << 4)
    mins[:, :, 4:] = (packed[:, :, 8:12] >> 4) | ((packed[:, :, 4:8] >> 6) << 4)
    return scales, mins


def _dot_q4_k_q8_k(
    raw: np.ndarray, xq: np.ndarray, xd: np.ndarray, xsum: np.ndarray
) -> np.ndarray:
    weight_scale = raw[:, :, 0:2].copy().view("<f2").astype(np.float32)[:, :, 0]
    weight_min = raw[:, :, 2:4].copy().view("<f2").astype(np.float32)[:, :, 0]
    scales, mins = _q4_k_scales(raw)
    packed = raw[:, :, 16:].reshape(*raw.shape[:2], 4, 32)
    quants = np.empty((*raw.shape[:2], 8, 32), dtype=np.uint8)
    quants[:, :, 0::2] = packed & 15
    quants[:, :, 1::2] = packed >> 4
    input_groups = xq.reshape(*xq.shape[:2], 8, 32)
    products = np.einsum(
        "rbgk,tbgk->trbg",
        quants.astype(np.int32),
        input_groups.astype(np.int32),
        dtype=np.int32,
        optimize=False,
    )
    main = np.einsum("rbg,trbg->trb", scales.astype(np.int32), products, optimize=False)
    input_sums = xsum.reshape(*xsum.shape[:2], 8, 2).sum(axis=3, dtype=np.int32)
    minimum = np.einsum("rbg,tbg->trb", mins.astype(np.int32), input_sums, optimize=False)
    block_values = xd[:, None, :] * (
        weight_scale[None, :, :] * main - weight_min[None, :, :] * minimum
    )
    return block_values.sum(axis=2, dtype=np.float32)


def _dot_q6_k_q8_k(raw: np.ndarray, xq: np.ndarray, xd: np.ndarray) -> np.ndarray:
    ql = raw[:, :, :128].reshape(*raw.shape[:2], 2, 64)
    qh = raw[:, :, 128:192].reshape(*raw.shape[:2], 2, 32)
    scales = raw[:, :, 192:208].view(np.int8)
    weight_scale = raw[:, :, 208:210].copy().view("<f2").astype(np.float32)[:, :, 0]
    quants = np.empty((*raw.shape[:2], 2, 4, 32), dtype=np.int8)
    quants[:, :, :, 0, :] = ((ql[:, :, :, :32] & 15) | ((qh & 3) << 4)).astype(np.int8) - 32
    quants[:, :, :, 1, :] = ((ql[:, :, :, 32:] & 15) | (((qh >> 2) & 3) << 4)).astype(np.int8) - 32
    quants[:, :, :, 2, :] = ((ql[:, :, :, :32] >> 4) | (((qh >> 4) & 3) << 4)).astype(np.int8) - 32
    quants[:, :, :, 3, :] = ((ql[:, :, :, 32:] >> 4) | (((qh >> 6) & 3) << 4)).astype(np.int8) - 32
    quant_groups = quants.reshape(*raw.shape[:2], 16, 16)
    input_groups = xq.reshape(*xq.shape[:2], 16, 16)
    products = np.einsum(
        "rbgk,tbgk->trbg",
        quant_groups.astype(np.int32),
        input_groups.astype(np.int32),
        dtype=np.int32,
        optimize=False,
    )
    weighted = np.einsum("rbg,trbg->trb", scales.astype(np.int32), products, optimize=False)
    return (xd[:, None, :] * weight_scale[None, :, :] * weighted).sum(axis=2, dtype=np.float32)


def _product(values: tuple[int, ...]) -> int:
    result = 1
    for value in values:
        result *= value
        if result > 2**63 - 1:
            raise GGUFError("tensor is too large")
    return result
