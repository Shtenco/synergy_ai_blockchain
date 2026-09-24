from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import tempfile
import zlib


class StorageInvariantError(ValueError):
    pass


@dataclass(frozen=True)
class EncodedChunk:
    digest: str
    raw_size: int
    codec: str
    payload: bytes


class Codec:
    codec_id: str

    def encode(self, raw: bytes) -> bytes:
        raise NotImplementedError

    def decode(self, payload: bytes) -> bytes:
        raise NotImplementedError


class RawCodec(Codec):
    codec_id = "raw"

    def encode(self, raw: bytes) -> bytes:
        return bytes(raw)

    def decode(self, payload: bytes) -> bytes:
        return bytes(payload)


class ZlibCodec(Codec):
    codec_id = "zlib-9"

    def encode(self, raw: bytes) -> bytes:
        return zlib.compress(bytes(raw), level=9)

    def decode(self, payload: bytes) -> bytes:
        return zlib.decompress(payload)


class CodecRegistry:
    def __init__(self, codecs: tuple[Codec, ...] = (RawCodec(), ZlibCodec())):
        by_id = {codec.codec_id: codec for codec in codecs}
        if len(by_id) != len(codecs) or not by_id:
            raise StorageInvariantError("codec ids must be unique and non-empty")
        self._codecs = by_id

    def get(self, codec_id: str) -> Codec:
        try:
            return self._codecs[codec_id]
        except KeyError as exc:
            raise StorageInvariantError("unknown codec") from exc

    def encode_best(self, raw: bytes) -> EncodedChunk:
        raw = bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        candidates: list[tuple[int, str, bytes]] = []
        for codec_id, codec in sorted(self._codecs.items()):
            payload = codec.encode(raw)
            if codec.decode(payload) != raw:
                raise StorageInvariantError(f"codec round-trip failed: {codec_id}")
            candidates.append((len(payload), codec_id, payload))
        _, codec_id, payload = min(candidates, key=lambda item: (item[0], item[1]))
        return EncodedChunk(digest=digest, raw_size=len(raw), codec=codec_id, payload=payload)


class DirectoryChunkStore:
    """Durable content-addressed raw-byte store."""

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        if not self.root.is_dir():
            raise StorageInvariantError("store root must be a directory")

    @staticmethod
    def _digest(raw: bytes) -> str:
        return hashlib.sha256(raw).hexdigest()

    @staticmethod
    def _validate_digest(digest: str) -> str:
        if not isinstance(digest, str) or len(digest) != 64 or digest.lower() != digest:
            raise StorageInvariantError("digest must be lowercase sha256 hex")
        try:
            int(digest, 16)
        except ValueError as exc:
            raise StorageInvariantError("digest must be lowercase sha256 hex") from exc
        return digest

    def _path(self, digest: str) -> Path:
        digest = self._validate_digest(digest)
        return self.root / digest[:2] / digest[2:]

    def has(self, digest: str) -> bool:
        return self._path(digest).is_file()

    def put(self, raw: bytes) -> str:
        raw = bytes(raw)
        digest = self._digest(raw)
        target = self._path(digest)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.is_file():
            if self.get(digest) != raw:
                raise StorageInvariantError("existing content digest collision/corruption")
            return digest
        fd, tmp_name = tempfile.mkstemp(prefix=".chunk-", dir=target.parent)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, target)
        finally:
            try:
                os.unlink(tmp_name)
            except FileNotFoundError:
                pass
        return digest

    def get(self, digest: str) -> bytes:
        path = self._path(digest)
        try:
            raw = path.read_bytes()
        except FileNotFoundError as exc:
            raise StorageInvariantError("chunk not found") from exc
        if self._digest(raw) != digest:
            raise StorageInvariantError("stored chunk hash mismatch")
        return raw
