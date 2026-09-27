from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import socket
import socketserver
import threading
import time
from typing import Protocol, Any, BinaryIO

_MAX_HEADER = 16 * 1024
_MAX_PAYLOAD = 64 * 1024 * 1024
_PROTOCOL = "synergy.stage-rpc/v1"

#: Opt-in env var for non-loopback PLAINTEXT binds. Cross-machine stage
#: traffic must use the PQ mesh transport (transport_record/mesh_transport);
#: these Python adapters are a loopback-only dev harness otherwise.
PLAINTEXT_OPT_IN_ENV = "SYNERGY_ALLOW_PLAINTEXT_TRANSPORT"
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


def _require_loopback_or_opt_in(host: str, what: str) -> None:
    import os

    if host in _LOOPBACK_HOSTS:
        return
    if os.environ.get(PLAINTEXT_OPT_IN_ENV) == "1":
        return
    raise StageRpcError(
        f"{what}: non-loopback plaintext bind {host!r} refused; "
        f"cross-machine traffic must use the PQ mesh transport "
        f"(set {PLAINTEXT_OPT_IN_ENV}=1 only for isolated lab nets)"
    )


class StageRpcError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    def check(x: Any) -> None:
        if x is None or isinstance(x, (str, bool)):
            return
        if isinstance(x, int) and not isinstance(x, bool):
            if abs(x) > 2**53 - 1:
                raise StageRpcError("unsafe integer")
            return
        if isinstance(x, float):
            raise StageRpcError("floats forbidden in control plane")
        if isinstance(x, list):
            for y in x:
                check(y)
            return
        if isinstance(x, dict):
            if any(not isinstance(k, str) for k in x):
                raise StageRpcError("object keys must be strings")
            for y in x.values():
                check(y)
            return
        raise StageRpcError("unsupported control value")
    check(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _line(value: dict[str, Any]) -> bytes:
    return _canonical(value) + b"\n"


def _read_line(reader: BinaryIO) -> dict[str, Any]:
    raw = reader.readline(_MAX_HEADER + 1)
    if not raw or len(raw) > _MAX_HEADER or not raw.endswith(b"\n"):
        raise StageRpcError("invalid header frame")
    try:
        obj = json.loads(raw.decode())
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StageRpcError("invalid header JSON") from exc
    if not isinstance(obj, dict):
        raise StageRpcError("header must be object")
    _canonical(obj)
    return obj


def _hex64(value: object, name: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise StageRpcError(f"{name} must be lowercase hex64")
    return value


def _size(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not (0 <= value <= _MAX_PAYLOAD):
        raise StageRpcError(f"invalid {name}")
    return value


class StageBackend(Protocol):
    model_root: str
    shard_root: str
    capability_root: str

    def run(self, payload: bytes) -> bytes: ...


@dataclass
class HashReferenceBackend:
    """Deterministic smoke backend. Not an LLM claim."""

    model_root: str
    shard_root: str
    capability_root: str

    def run(self, payload: bytes) -> bytes:
        return hashlib.sha256(b"SYNERGY/STAGE-REFERENCE/V1\0" + payload).digest()


class _State:
    def __init__(self, backend: StageBackend):
        self.backend = backend
        self.lock = threading.Lock()


class _Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        state: _State = self.server.state  # type: ignore[attr-defined]
        try:
            request = _read_line(self.rfile)
            expected = {
                "protocol", "request_id", "job_id", "stage_index", "worker_id",
                "model_root", "shard_root", "input_commitment", "payload_bytes",
                "session_root",
            }
            if set(request) != expected or request["protocol"] != _PROTOCOL:
                raise StageRpcError("unexpected request shape")
            request_id = _hex64(request["request_id"], "request_id")
            job_id = _hex64(request["job_id"], "job_id")
            worker_id = _hex64(request["worker_id"], "worker_id")
            model_root = _hex64(request["model_root"], "model_root")
            shard_root = _hex64(request["shard_root"], "shard_root")
            session_root = _hex64(request["session_root"], "session_root")
            input_commitment = _hex64(request["input_commitment"], "input_commitment")
            stage_index = request["stage_index"]
            if isinstance(stage_index, bool) or not isinstance(stage_index, int) or not (0 <= stage_index <= 2**32 - 1):
                raise StageRpcError("invalid stage_index")
            payload_bytes = _size(request["payload_bytes"], "payload_bytes")
            payload = self.rfile.read(payload_bytes)
            if len(payload) != payload_bytes:
                raise StageRpcError("truncated stage payload")
            if hashlib.sha256(payload).hexdigest() != input_commitment:
                raise StageRpcError("input commitment mismatch")
            if model_root != state.backend.model_root or shard_root != state.backend.shard_root:
                raise StageRpcError("worker model/shard mismatch")

            started_ns = time.monotonic_ns()
            with state.lock:
                output = bytes(state.backend.run(payload))
            finished_ns = time.monotonic_ns()
            if len(output) > _MAX_PAYLOAD:
                raise StageRpcError("backend output too large")

            output_commitment = hashlib.sha256(output).hexdigest()
            trace = {
                "protocol": _PROTOCOL,
                "request_id": request_id,
                "job_id": job_id,
                "stage_index": stage_index,
                "worker_id": worker_id,
                "model_root": model_root,
                "shard_root": shard_root,
                "input_commitment": input_commitment,
                "output_commitment": output_commitment,
                "session_root": session_root,
                "capability_root": _hex64(state.backend.capability_root, "capability_root"),
                "input_bytes": len(payload),
                "output_bytes": len(output),
                "elapsed_micros": max(1, (finished_ns - started_ns) // 1000),
                "execution_authority": "NONE",
                "payment_authority": "NONE",
            }
            trace_root = hashlib.sha256(_canonical(trace)).hexdigest()
            response = {
                **trace,
                "trace_root": trace_root,
            }
            self.wfile.write(_line(response))
            self.wfile.write(output)
            self.wfile.flush()
        except (StageRpcError, OSError, ValueError):
            self.wfile.write(_line({
                "protocol": _PROTOCOL,
                "ok": False,
                "error": "INVALID_REQUEST",
                "execution_authority": "NONE",
                "payment_authority": "NONE",
            }))
            self.wfile.flush()


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    def __init__(self, address: tuple[str, int], backend: StageBackend):
        self.state = _State(backend)
        super().__init__(address, _Handler)


class StageRpcServer:
    def __init__(self, backend: StageBackend, host: str = "127.0.0.1", port: int = 0):
        _require_loopback_or_opt_in(host, "StageRpcServer")
        self._server = _Server((host, port), backend)
        self._thread: threading.Thread | None = None

    @property
    def address(self) -> tuple[str, int]:
        host, port = self._server.server_address[:2]
        return str(host), int(port)

    def start(self) -> "StageRpcServer":
        if self._thread is not None:
            raise StageRpcError("server already started")
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None

    def __enter__(self) -> "StageRpcServer":
        return self.start()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


class StageRpcClient:
    def __init__(self, address: tuple[str, int], timeout: float = 10.0):
        self.address = address
        self.timeout = timeout

    def run(
        self,
        *,
        request_id: str,
        job_id: str,
        stage_index: int,
        worker_id: str,
        model_root: str,
        shard_root: str,
        session_root: str,
        payload: bytes,
    ) -> tuple[dict[str, Any], bytes]:
        payload = bytes(payload)
        request = {
            "protocol": _PROTOCOL,
            "request_id": _hex64(request_id, "request_id"),
            "job_id": _hex64(job_id, "job_id"),
            "stage_index": stage_index,
            "worker_id": _hex64(worker_id, "worker_id"),
            "model_root": _hex64(model_root, "model_root"),
            "shard_root": _hex64(shard_root, "shard_root"),
            "input_commitment": hashlib.sha256(payload).hexdigest(),
            "payload_bytes": len(payload),
            "session_root": _hex64(session_root, "session_root"),
        }
        with socket.create_connection(self.address, timeout=self.timeout) as sock:
            reader = sock.makefile("rb")
            sock.sendall(_line(request))
            sock.sendall(payload)
            response = _read_line(reader)
            if response.get("ok") is False:
                raise StageRpcError(response.get("error", "stage RPC failed"))
            out_size = _size(response["output_bytes"], "output_bytes")
            output = reader.read(out_size)
            if len(output) != out_size or hashlib.sha256(output).hexdigest() != response["output_commitment"]:
                raise StageRpcError("stage output integrity failure")
            claimed = response["trace_root"]
            body = dict(response)
            body.pop("trace_root")
            if hashlib.sha256(_canonical(body)).hexdigest() != claimed:
                raise StageRpcError("trace root mismatch")
            return response, output
