from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess

class LlamaCppBackendError(RuntimeError):
    pass

class LlamaCppSingleTokenBackend:
    """Optional trained-model backend for canonical Stage RPC.

    It invokes a pinned/externally supplied llama.cpp `llama-cli` binary against
    a local GGUF model. The network/RPC contract is unchanged from the reference
    backend. This adapter intentionally does not download binaries or models.
    """

    def __init__(
        self,
        *,
        llama_cli: str | Path,
        model_path: str | Path,
        model_root: str,
        shard_root: str,
        capability_root: str,
        context_size: int = 512,
        seed: int = 1,
        timeout_seconds: int = 120,
    ):
        self.llama_cli = Path(llama_cli)
        self.model_path = Path(model_path)
        self.model_root = model_root
        self.shard_root = shard_root
        self.capability_root = capability_root
        self.context_size = int(context_size)
        self.seed = int(seed)
        self.timeout_seconds = int(timeout_seconds)
        if not self.llama_cli.is_file() or not os.access(self.llama_cli, os.X_OK):
            raise LlamaCppBackendError("llama-cli executable required")
        if not self.model_path.is_file():
            raise LlamaCppBackendError("local GGUF model required")
        if self.context_size <= 0 or self.timeout_seconds <= 0:
            raise LlamaCppBackendError("invalid llama.cpp runtime limits")

    def run(self, payload: bytes) -> bytes:
        try:
            prompt = payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise LlamaCppBackendError("trained backend expects UTF-8 prompt bytes") from exc
        if not prompt:
            raise LlamaCppBackendError("prompt required")

        cmd = [
            str(self.llama_cli),
            "-m", str(self.model_path),
            "-p", prompt,
            "-n", "1",
            "--temp", "0",
            "--seed", str(self.seed),
            "-c", str(self.context_size),
            "--no-display-prompt",
            "--simple-io",
        ]
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=self.timeout_seconds,
            check=False,
        )
        if proc.returncode != 0:
            tail = proc.stderr[-4096:].decode("utf-8", errors="replace")
            raise LlamaCppBackendError(f"llama.cpp failed: {tail}")
        output = proc.stdout
        if not output:
            raise LlamaCppBackendError("llama.cpp returned empty output")
        return bytes(output)

    def artifact_evidence(self) -> dict[str, str | int]:
        return {
            "backend": "llama.cpp/llama-cli",
            "llama_cli_sha256": hashlib.sha256(self.llama_cli.read_bytes()).hexdigest(),
            "gguf_sha256": hashlib.sha256(self.model_path.read_bytes()).hexdigest(),
            "model_root": self.model_root,
            "shard_root": self.shard_root,
            "capability_root": self.capability_root,
            "context_size": self.context_size,
            "seed": self.seed,
        }
