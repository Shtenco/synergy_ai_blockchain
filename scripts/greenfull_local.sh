#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

LLAMA_CLI="${LLAMA_CLI:-llama-cli}"
MODEL_DIR="${MODEL_DIR:-models/qwen35_08b}"
MODEL_FILE="$MODEL_DIR/Qwen_Qwen3.5-0.8B-Q4_K_M.gguf"
EXPECTED_SHA="fb044e93939a70469c905781334f5de1e6c8b608ced6cbc8c9249bd4127d9526"

mkdir -p evidence "$MODEL_DIR"

echo "[1/8] Fetch + verify Qwen3.5-0.8B"
python3 scripts/mvp_fetch_qwen35_08b.py --dir "$MODEL_DIR"

echo "[2/8] Verify GGUF SHA"
ACTUAL_SHA="$(sha256sum "$MODEL_FILE" | awk '{print $1}')"
test "$ACTUAL_SHA" = "$EXPECTED_SHA"

echo "[3/8] Verify llama.cpp availability"
command -v "$LLAMA_CLI" >/dev/null
LLAMA_BIN="$(command -v "$LLAMA_CLI")"
LLAMA_SHA="$(sha256sum "$LLAMA_BIN" | awk '{print $1}')"

echo "[4/8] Run trained-model deterministic inference"
python3 scripts/mvp_fetch_qwen35_08b.py   --dir "$MODEL_DIR"   --llama-cli "$LLAMA_BIN"   --prompt "Reply with exactly: SYNERGY_QWEN_OK"

echo "[5/8] Run local MVP runtime proofs"
PYTHONPATH=. python3 scripts/mvp_synergynet_smoke.py
PYTHONPATH=. python3 scripts/mvp_stage_rpc_smoke.py
PYTHONPATH=. python3 scripts/mvp_vertical_slice_smoke.py
PYTHONPATH=. python3 scripts/mvp_real_transformer_smoke.py
PYTHONPATH=. python3 scripts/mvp_transformer_kv_resume.py
PYTHONPATH=. python3 scripts/mvp_adversarial_transformer.py

echo "[6/8] Run Rust/Solidity certification"
cargo generate-lockfile
cargo fmt --all -- --check
cargo check --frozen --all-targets
cargo check --frozen --all-targets --features reference-pq
cargo clippy --frozen --all-targets --features reference-pq -- -D warnings -D clippy::all
cargo test --frozen --all-targets
cargo test --frozen --all-targets --features reference-pq
cargo test --frozen --doc --features reference-pq
cargo test --frozen --release --lib --features reference-pq

echo "[7/8] Record trained artifact evidence"
python3 - <<PY
import hashlib, json
from pathlib import Path
p=Path("$MODEL_FILE")
e={
 "schema":"synergy.qwen35-greenfull-artifact/v1",
 "model_file":str(p),
 "gguf_sha256":"$ACTUAL_SHA",
 "gguf_bytes":p.stat().st_size,
 "llama_cli":"$LLAMA_BIN",
 "llama_cli_sha256":"$LLAMA_SHA",
}
raw=json.dumps(e,sort_keys=True,separators=(",",":")).encode()
e["evidence_root"]=hashlib.sha256(raw).hexdigest()
Path("evidence/qwen35_greenfull_artifact.json").write_text(json.dumps(e,indent=2,sort_keys=True))
print(json.dumps(e,indent=2,sort_keys=True))
PY

echo "[8/8] Bundle evidence"
python3 scripts/mvp_bundle_evidence.py

echo
echo "LOCAL SOFTWARE GREEN: PASS"
echo "NOTE: GREENFULL still additionally requires the 3-host external run and live dual-PQ signer evidence."
