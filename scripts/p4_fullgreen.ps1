$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$Root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $Root
$Out = Join-Path $Root "evidence\p4_fullgreen"
$Logs = Join-Path $Out "logs"
New-Item -ItemType Directory -Force -Path $Logs | Out-Null
$Solc = if ($env:SOLC_BIN) { $env:SOLC_BIN } else { "solc" }

function Run-Gate {
  param([string]$Name,[string]$Exe,[string[]]$CommandArgs)
  Write-Host ""
  Write-Host "===== P4 GATE: $Name ====="
  $Log = Join-Path $Logs "$Name.log"
  & $Exe @CommandArgs 2>&1 | Tee-Object -FilePath $Log
  if ($LASTEXITCODE -ne 0) { throw "P4 gate failed: $Name (exit $LASTEXITCODE)" }
}

foreach ($cmd in @("cargo","rustc","rustfmt","python","git",$Solc)) {
  if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) { throw "Required command not found: $cmd" }
}

git ls-files --error-unmatch Cargo.lock | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Cargo.lock is not tracked" }
git diff --exit-code -- Cargo.lock
if ($LASTEXITCODE -ne 0) { throw "Cargo.lock is modified" }

$Commit = (git rev-parse HEAD).Trim()
$EnvLines = @(
  "commit=$Commit",
  "rustc=$(rustc --version)",
  "cargo=$(cargo --version)",
  "rustfmt=$(rustfmt --version)",
  "python=$(python --version 2>&1)",
  "solc=$((& $Solc --version) -join ' ')"
)
$EnvLines | Set-Content -Encoding UTF8 (Join-Path $Out "environment.txt")
if (((& $Solc --version) -join "`n") -notmatch "0\.8\.26") { throw "solc 0.8.26 required" }

Run-Gate "01_fixture_manifest" "python" @("scripts/m2_verify_fixture_manifest.py")
Run-Gate "02_static_security" "python" @("scripts/m2_static_guard.py")
Run-Gate "03_fmt" "cargo" @("fmt","--all","--","--check")
Run-Gate "04_check_core" "cargo" @("check","--frozen","--all-targets")
Run-Gate "05_check_reference_pq" "cargo" @("check","--frozen","--all-targets","--features","reference-pq")
Run-Gate "06_clippy" "cargo" @("clippy","--frozen","--all-targets","--features","reference-pq","--","-D","warnings","-D","clippy::all")
Run-Gate "07_test_core" "cargo" @("test","--frozen","--all-targets")
Run-Gate "08_test_reference_pq" "cargo" @("test","--frozen","--all-targets","--features","reference-pq")
Run-Gate "09_doctest" "cargo" @("test","--frozen","--doc","--features","reference-pq")
Run-Gate "10_release_reference_pq" "cargo" @("test","--frozen","--release","--lib","--features","reference-pq")
Run-Gate "11_inference" "cargo" @("test","--frozen","inference::tests")
Run-Gate "12_peer_discovery" "cargo" @("test","--frozen","peer_discovery::tests")
Run-Gate "13_pi_pq" "cargo" @("test","--frozen","pi_pq::tests")
Run-Gate "14_evm_compat" "cargo" @("test","--frozen","evm_compat::tests")
Run-Gate "15_syna_emission" "cargo" @("test","--frozen","syna_emission::tests")
Run-Gate "16_syna_reward" "cargo" @("test","--frozen","syna_reward::tests")
Run-Gate "17_syna_state" "cargo" @("test","--frozen","syna_state::tests")

$SolcOut = Join-Path $Out "solc"
if (Test-Path $SolcOut) { Remove-Item -Recurse -Force $SolcOut }
New-Item -ItemType Directory -Force -Path $SolcOut | Out-Null
$SolArgs = @("--base-path",".","--include-path",".","--bin","--abi","--metadata-hash","none","--overwrite","--output-dir",$SolcOut,"contracts/IPQVerifier.sol","contracts/PQSmartAccount.sol","contracts/INexusAI.sol")
Run-Gate "18_solidity" $Solc $SolArgs

$SolidityManifest = Join-Path $Out "solidity_sha256.txt"
Get-ChildItem -File -Recurse $SolcOut | Sort-Object FullName | ForEach-Object {
  $Hash = (Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLowerInvariant()
  "$Hash  $($_.FullName.Substring($Root.Path.Length + 1))"
} | Set-Content -Encoding UTF8 $SolidityManifest

$Py = @'
import hashlib, json, pathlib, subprocess
out = pathlib.Path("evidence/p4_fullgreen")
logs = out / "logs"
def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            h.update(chunk)
    return h.hexdigest()
commit = subprocess.check_output(["git","rev-parse","HEAD"], text=True).strip()
files = sorted(logs.glob("*.log"))
manifest = {
  "schema":"synergy.p4-fullgreen/v1",
  "git_commit":commit,
  "status":"PASS",
  "scope":["production-pq","pi-pq-fail-closed-shell","pq-evm-l1-l2-compatibility","bridge-replay-protection","syna-proof-of-useful-inference"],
  "gates":{p.stem:{"sha256":sha256(p),"bytes":p.stat().st_size} for p in files},
  "environment_sha256":sha256(out/"environment.txt"),
  "solidity_manifest_sha256":sha256(out/"solidity_sha256.txt"),
}
raw = json.dumps(manifest, sort_keys=True, separators=(",",":")).encode()
manifest["evidence_root"] = hashlib.sha256(raw).hexdigest()
(out/"P4_FULLGREEN.json").write_text(json.dumps(manifest, indent=2, sort_keys=True)+"\n")
print(json.dumps(manifest, indent=2, sort_keys=True))
'@
$Py | python -
if ($LASTEXITCODE -ne 0) { throw "P4 evidence bundle generation failed" }

Write-Host ""
Write-Host "P4 FULLGREEN: PASS"
Write-Host "evidence=evidence/p4_fullgreen/P4_FULLGREEN.json"
