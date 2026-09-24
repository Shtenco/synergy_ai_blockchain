# Executable Evidence — DESKTOP-C8GUE41 — 2026-09-24

Physical runner:
- device: DESKTOP-C8GUE41
- OS: Windows
- Rust: rustc/cargo 1.85.0
- llama.cpp: b11149-d2e54583c
- Solidity compiler: 0.8.26+commit.8a97fa7a.Windows.msvc

## Confirmed physical PASS

### Runtime / AI
- SynergyNet relay smoke: PASS
- Stage RPC smoke: PASS
- Vertical slice provider -> relay -> stage RPC -> verifier: PASS
- Real two-stage causal Transformer distributed-vs-local equivalence: PASS
- Transformer KV snapshot/restore/failover: PASS
- Exact resumed token equals uninterrupted token: PASS
- Malicious Transformer worker produces canonical mismatch evidence: PASS

Evidence roots observed on runner:
- real Transformer: c15835907a855b49810656030ddd45f844afb7299b3c2b918299e96c1744217c
- KV resume: eeefb91715ffd6abc187d759091b8201eb97cba6e913b7dfd520f1db13fe7f2a
- malicious worker: 397674841ae3053a23df576a6867157d802f037281a68ca09527cd2a29b80562

KV proof:
- uninterrupted_next_token = 24
- resumed_next_token = 24
- exact_resume_equivalence = true

### Trained Qwen
Artifact:
- Qwen_Qwen3.5-0.8B-Q4_K_M.gguf
- size: 579,615,840 bytes
- SHA-256: fb044e93939a70469c905781334f5de1e6c8b608ced6cbc8c9249bd4127d9526

Physical llama.cpp execution:
- build: b11149-d2e54583c
- model loaded: PASS
- exit code: 0
- observed prompt speed: ~12.2 tok/s
- observed generation speed: ~7.1 tok/s

### Rust / PQ
- Cargo.lock generated locally
- Cargo.lock SHA-256 observed during run: e065e45b2fb4ed8f96136472fa67aa62607fc3ae093dc3dc6cfd387f2b300799
- cargo fmt --all -- --check: PASS
- cargo check --all-targets: PASS
- cargo check --locked --all-targets --features reference-pq: PASS
- cargo clippy --locked --all-targets --features reference-pq -- -D warnings -D clippy::all: PASS
- cargo test --locked --all-targets: PASS

The full reference-PQ test suite started 256 tests. All ordinary/PQ/network/transport/verification tests observed in output were PASS. Six expensive SLH-DSA/dual-PQ tests remained running in debug profile when the Remote Desktop Commander tunnel disconnected. They were consuming CPU, not reporting failures.

### Solidity
- solc 0.8.26 exact version: PASS
- contracts IPQVerifier.sol, INexusAI.sol, PQSmartAccount.sol compile: PASS
- compiler exit code: 0
- ABI/bin artifacts produced under evidence/solc on runner

## Remaining before executable GREEN

1. reconnect DESKTOP-C8GUE41 remote tunnel;
2. collect final summary of the six long-running SLH-DSA/dual-PQ tests;
3. run/confirm doctest and release reference-PQ tests;
4. bundle evidence;
5. commit canonical Cargo.lock;
6. only then mark executable M2 GREEN / local software GREEN.

The external 3-host/4-node topology is a separate deployment acceptance gate and must not be conflated with local software GREEN.
