#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

OUT="evidence/p4_fullgreen"
LOGS="$OUT/logs"
mkdir -p "$LOGS"

SOLC_BIN="${SOLC_BIN:-solc}"
EXPECTED_SOLC="0.8.26"

run_gate() {
  local name="$1"
  shift
  echo
  echo "===== P4 GATE: $name ====="
  "$@" 2>&1 | tee "$LOGS/$name.log"
}

echo "P4 FULLGREEN certification"
echo "commit=$(git rev-parse HEAD)"
echo "utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

command -v cargo >/dev/null
command -v rustc >/dev/null
command -v rustfmt >/dev/null
command -v python3 >/dev/null
command -v "$SOLC_BIN" >/dev/null

git ls-files --error-unmatch Cargo.lock >/dev/null
git diff --exit-code -- Cargo.lock

{
  echo "commit=$(git rev-parse HEAD)"
  echo "rustc=$(rustc --version)"
  echo "cargo=$(cargo --version)"
  echo "rustfmt=$(rustfmt --version)"
  echo "python=$(python3 --version 2>&1)"
  echo "solc=$($SOLC_BIN --version | tr '\n' ' ')"
} | tee "$OUT/environment.txt"

"$SOLC_BIN" --version | grep -F "$EXPECTED_SOLC" >/dev/null

run_gate 01_fixture_manifest python3 scripts/m2_verify_fixture_manifest.py
run_gate 02_static_security python3 scripts/m2_static_guard.py
run_gate 03_fmt cargo fmt --all -- --check
run_gate 04_check_core cargo check --frozen --all-targets
run_gate 05_check_reference_pq cargo check --frozen --all-targets --features reference-pq
run_gate 06_clippy cargo clippy --frozen --all-targets --features reference-pq -- -D warnings -D clippy::all
run_gate 07_test_core cargo test --frozen --all-targets
run_gate 08_test_reference_pq cargo test --frozen --all-targets --features reference-pq
run_gate 09_doctest cargo test --frozen --doc --features reference-pq
run_gate 10_release_reference_pq cargo test --frozen --release --lib --features reference-pq

# P4-specific regression gates. These are intentionally repeated as named
# evidence even though the full suite above already executes them.
run_gate 11_inference cargo test --frozen inference::tests
run_gate 12_pi_pq cargo test --frozen pi_pq::tests
run_gate 13_evm_compat cargo test --frozen evm_compat::tests
run_gate 14_syna_emission cargo test --frozen syna_emission::tests
run_gate 15_syna_reward cargo test --frozen syna_reward::tests
run_gate 16_syna_state cargo test --frozen syna_state::tests

rm -rf "$OUT/solc"
mkdir -p "$OUT/solc"
run_gate 17_solidity "$SOLC_BIN"   --base-path .   --include-path .   --bin   --abi   --metadata-hash none   --overwrite   --output-dir "$OUT/solc"   contracts/IPQVerifier.sol   contracts/PQSmartAccount.sol   contracts/INexusAI.sol

find "$OUT/solc" -type f -print0 | sort -z | xargs -0 sha256sum > "$OUT/solidity_sha256.txt"

python3 - <<'PY'
import hashlib
import json
import subprocess
from pathlib import Path

out = Path("evidence/p4_fullgreen")
logs = out / "logs"

def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

commit = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
log_files = sorted(logs.glob("*.log"))
manifest = {
    "schema": "synergy.p4-fullgreen/v1",
    "git_commit": commit,
    "status": "PASS",
    "scope": [
        "production-pq",
        "pi-pq-fail-closed-shell",
        "pq-evm-l1-l2-compatibility",
        "bridge-replay-protection",
        "syna-proof-of-useful-inference",
    ],
    "gates": {p.stem: {"sha256": sha256(p), "bytes": p.stat().st_size} for p in log_files},
    "environment_sha256": sha256(out / "environment.txt"),
    "solidity_manifest_sha256": sha256(out / "solidity_sha256.txt"),
}
raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
manifest["evidence_root"] = hashlib.sha256(raw).hexdigest()
(out / "P4_FULLGREEN.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
print(json.dumps(manifest, indent=2, sort_keys=True))
PY

echo
echo "P4 FULLGREEN: PASS"
echo "evidence=$OUT/P4_FULLGREEN.json"
