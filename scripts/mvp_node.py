from __future__ import annotations

import argparse
import json
import signal
import threading
from pathlib import Path

from runtime.synergynet_ref import PersistentContentServer
from runtime.stage_rpc_v1 import StageRpcServer
from runtime.mini_transformer_v1 import MiniTransformerConfig, MiniTransformerStage0, MiniTransformerStage1
from runtime.llama_cpp_backend_v1 import LlamaCppSingleTokenBackend


def _wait() -> None:
    stop = threading.Event()
    def handler(*_):
        stop.set()
    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)
    stop.wait()


def main() -> int:
    p = argparse.ArgumentParser(description="SYNERGY MVP node role launcher")
    p.add_argument("--role", required=True, choices=["provider","stage0","stage1","trained-worker"])
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--store")
    p.add_argument("--llama-cli")
    p.add_argument("--gguf")
    p.add_argument("--model-root")
    p.add_argument("--shard-root")
    p.add_argument("--capability-root")
    args = p.parse_args()

    if args.role == "provider":
        if not args.store:
            raise SystemExit("--store required for provider")
        with PersistentContentServer(store_root=args.store, host=args.host, port=args.port) as server:
            print(json.dumps({"role":"provider","address":server.address,"status":"READY"}, sort_keys=True), flush=True)
            _wait()
        return 0

    cfg = MiniTransformerConfig()
    if args.role == "stage0":
        backend = MiniTransformerStage0(cfg)
    elif args.role == "stage1":
        backend = MiniTransformerStage1(cfg)
    else:
        required = [args.llama_cli,args.gguf,args.model_root,args.shard_root,args.capability_root]
        if any(x is None for x in required):
            raise SystemExit("trained-worker requires --llama-cli --gguf --model-root --shard-root --capability-root")
        backend = LlamaCppSingleTokenBackend(
            llama_cli=args.llama_cli,
            model_path=args.gguf,
            model_root=args.model_root,
            shard_root=args.shard_root,
            capability_root=args.capability_root,
        )

    with StageRpcServer(backend, host=args.host, port=args.port) as server:
        print(json.dumps({
            "role":args.role,
            "address":server.address,
            "model_root":backend.model_root,
            "shard_root":backend.shard_root,
            "capability_root":backend.capability_root,
            "status":"READY",
        }, sort_keys=True), flush=True)
        _wait()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
