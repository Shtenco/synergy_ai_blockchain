from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import socket
import socketserver
import threading
from typing import BinaryIO, Any

from .storage_v3 import CodecRegistry, DirectoryChunkStore, StorageInvariantError


class PersistentServiceError(ValueError):
    pass


_MAX_HEADER_BYTES = 16 * 1024
_MAX_PAYLOAD_BYTES = 32 * 1024 * 1024
_SERVICE_SCHEMA = "synergynet.content-service/v1"
_PROTOCOL = "synergynet.content-wire/v1"
_ALLOWED_OPS = {"HAS", "PUT", "GET_RAW", "STATUS"}


def _canonical_json(value: Any) -> bytes:
    def check(item: Any) -> None:
        if item is None or isinstance(item, (str, bool)): return
        if isinstance(item, int) and not isinstance(item, bool):
            if abs(item) > 2**53 - 1: raise PersistentServiceError("unsafe integer")
            return
        if isinstance(item, float): raise PersistentServiceError("floats are forbidden in content-service protocol")
        if isinstance(item, list):
            for child in item: check(child)
            return
        if isinstance(item, dict):
            if any(not isinstance(key, str) for key in item): raise PersistentServiceError("object keys must be strings")
            for child in item.values(): check(child)
            return
        raise PersistentServiceError("unsupported protocol value")
    check(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _json_line(value: dict[str, Any]) -> bytes: return _canonical_json(value) + b"\n"


def _read_json_line(reader: BinaryIO) -> dict[str, Any]:
    line = reader.readline(_MAX_HEADER_BYTES + 1)
    if not line or len(line) > _MAX_HEADER_BYTES or not line.endswith(b"\n"): raise PersistentServiceError("invalid frame header")
    try: value = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc: raise PersistentServiceError("invalid JSON header") from exc
    if not isinstance(value, dict): raise PersistentServiceError("frame header must be an object")
    _canonical_json(value); return value


def _digest(value: object) -> str:
    if not isinstance(value, str) or len(value) != 64 or value.lower() != value: raise PersistentServiceError("digest must be lowercase sha256 hex")
    if any(ch not in "0123456789abcdef" for ch in value): raise PersistentServiceError("digest must be lowercase sha256 hex")
    return value


def _size(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not (0 <= value <= _MAX_PAYLOAD_BYTES): raise PersistentServiceError(f"invalid {name}")
    return value


def _exact_shape(payload: dict[str, Any], expected: set[str]) -> None:
    if set(payload) != expected: raise PersistentServiceError("unexpected request shape")


@dataclass(frozen=True)
class ServiceStatus:
    schema: str
    protocol: str
    store_kind: str
    execution_authority: str
    def to_dict(self) -> dict[str, str]:
        return {"schema": self.schema, "protocol": self.protocol, "store_kind": self.store_kind, "execution_authority": self.execution_authority}


class _State:
    def __init__(self, store: DirectoryChunkStore, codecs: CodecRegistry):
        self.store=store; self.codecs=codecs; self.lock=threading.Lock()


class _Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        state: _State = self.server.state
        while True:
            try: request = _read_json_line(self.rfile)
            except PersistentServiceError:
                self._reply({"ok":False,"error":"INVALID_FRAME","execution_authority":"NONE"}); return
            op=request.get("op")
            if op not in _ALLOWED_OPS:
                self._reply({"ok":False,"error":"UNKNOWN_OP","execution_authority":"NONE"}); return
            try:
                if op=="STATUS":
                    _exact_shape(request,{"op"})
                    self._reply({"ok":True,**ServiceStatus(_SERVICE_SCHEMA,_PROTOCOL,"DIRECTORY_SHA256_RAW_BYTES","NONE").to_dict()}); continue
                if op=="HAS":
                    _exact_shape(request,{"op","digest"}); digest=_digest(request["digest"])
                    with state.lock: present=state.store.has(digest)
                    self._reply({"ok":True,"present":present,"execution_authority":"NONE"}); continue
                if op=="PUT":
                    _exact_shape(request,{"op","digest","raw_size","payload_size","codec"})
                    digest=_digest(request["digest"]); raw_size=_size(request["raw_size"],"raw_size"); payload_size=_size(request["payload_size"],"payload_size")
                    codec_id=request["codec"]
                    if not isinstance(codec_id,str) or not codec_id: raise PersistentServiceError("invalid codec")
                    payload=self.rfile.read(payload_size)
                    if len(payload)!=payload_size: raise PersistentServiceError("truncated payload")
                    try: raw=state.codecs.get(codec_id).decode(payload)
                    except Exception as exc: raise PersistentServiceError("codec decode failed") from exc
                    if len(raw)!=raw_size or hashlib.sha256(raw).hexdigest()!=digest: raise PersistentServiceError("decoded content mismatch")
                    with state.lock: stored=state.store.put(raw)
                    if stored!=digest: raise PersistentServiceError("store digest mismatch")
                    self._reply({"ok":True,"digest":digest,"execution_authority":"NONE"}); continue
                if op=="GET_RAW":
                    _exact_shape(request,{"op","digest"}); digest=_digest(request["digest"])
                    with state.lock: raw=state.store.get(digest)
                    self.wfile.write(_json_line({"ok":True,"digest":digest,"raw_size":len(raw),"execution_authority":"NONE"})); self.wfile.write(raw); self.wfile.flush(); continue
            except (PersistentServiceError,StorageInvariantError,KeyError,TypeError,ValueError):
                self._reply({"ok":False,"error":"INVALID_REQUEST","execution_authority":"NONE"}); return
    def _reply(self,payload:dict[str,Any])->None:
        self.wfile.write(_json_line(payload)); self.wfile.flush()


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address=True; daemon_threads=True
    def __init__(self,address:tuple[str,int],state:_State): self.state=state; super().__init__(address,_Handler)


class PersistentContentServer:
    def __init__(self,*,store_root:str|Path,host:str="127.0.0.1",port:int=0,codecs:CodecRegistry|None=None):
        if not isinstance(host,str) or not host: raise PersistentServiceError("host is required")
        if isinstance(port,bool) or not isinstance(port,int) or not (0<=port<=65535): raise PersistentServiceError("invalid port")
        self._server=_Server((host,port),_State(DirectoryChunkStore(store_root),codecs or CodecRegistry())); self._thread=None
    @property
    def address(self):
        host,port=self._server.server_address[:2]; return str(host),int(port)
    @property
    def store(self): return self._server.state.store
    def start(self):
        if self._thread is not None: raise PersistentServiceError("server already started")
        self._thread=threading.Thread(target=self._server.serve_forever,daemon=True); self._thread.start(); return self
    def close(self):
        self._server.shutdown(); self._server.server_close()
        if self._thread is not None: self._thread.join(timeout=2); self._thread=None
    def __enter__(self): return self.start()
    def __exit__(self,exc_type,exc,tb): self.close()


class PersistentContentClient:
    def __init__(self,address:tuple[str,int],timeout:float=5.0): self.address=address; self.timeout=timeout
    def status(self):
        with socket.create_connection(self.address,timeout=self.timeout) as sock:
            reader=sock.makefile("rb"); sock.sendall(_json_line({"op":"STATUS"})); return _read_json_line(reader)
    def has(self,digest:str)->bool:
        with socket.create_connection(self.address,timeout=self.timeout) as sock:
            reader=sock.makefile("rb"); sock.sendall(_json_line({"op":"HAS","digest":_digest(digest)})); response=_read_json_line(reader)
            if not response.get("ok"): raise PersistentServiceError("HAS failed")
            return bool(response["present"])
    def put(self,raw:bytes,*,codec_id:str="raw")->str:
        raw=bytes(raw); digest=hashlib.sha256(raw).hexdigest(); codec=CodecRegistry().get(codec_id); payload=codec.encode(raw)
        with socket.create_connection(self.address,timeout=self.timeout) as sock:
            reader=sock.makefile("rb"); sock.sendall(_json_line({"op":"PUT","digest":digest,"raw_size":len(raw),"payload_size":len(payload),"codec":codec_id})); sock.sendall(payload); response=_read_json_line(reader)
            if not response.get("ok") or response.get("digest")!=digest: raise PersistentServiceError("PUT failed")
        return digest
    def get_raw(self,digest:str)->bytes:
        digest=_digest(digest)
        with socket.create_connection(self.address,timeout=self.timeout) as sock:
            reader=sock.makefile("rb"); sock.sendall(_json_line({"op":"GET_RAW","digest":digest})); response=_read_json_line(reader)
            if not response.get("ok") or response.get("digest")!=digest: raise PersistentServiceError("GET_RAW failed")
            raw_size=_size(response["raw_size"],"raw_size"); raw=reader.read(raw_size)
            if len(raw)!=raw_size or hashlib.sha256(raw).hexdigest()!=digest: raise PersistentServiceError("GET_RAW integrity failure")
            return raw


def main(argv=None):
    parser=argparse.ArgumentParser(); parser.add_argument("--store",required=True); parser.add_argument("--host",default="127.0.0.1"); parser.add_argument("--port",type=int,default=7791)
    args=parser.parse_args(argv)
    with PersistentContentServer(store_root=args.store,host=args.host,port=args.port):
        try: threading.Event().wait()
        except KeyboardInterrupt: return 0
    return 0
