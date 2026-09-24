# MVP Software Closure Checkpoint — 2026-09-24

Branch:

`feat/mvp-canonical-integration-20260924`

PR:

`#22`

## Software planes now present

### PQ/session plane
- M2 PQ identities and authorization;
- transport transcript;
- deterministic hello wire contract;
- ML-KEM session-secret boundary;
- directional HKDF keys;
- bounded record nonces/rekey limits;
- ChaCha20-Poly1305 record AEAD;
- transcript/application AAD;
- framed encrypted TCP record I/O;
- replay/gap/wrong-AAD rejection.

### Discovery/network plane
- dynamic node records;
- provider records;
- TTL;
- replay/downgrade rejection;
- deterministic node/provider roots;
- imported persistent SynergyNet content service;
- static relay/bootstrap fixture.

### Model plane
- imported NEXUS V16 five-shard manifest;
- deterministic ordered shard root;
- persistent content-addressed storage;
- trained GGUF adapter;
- canonical historical Qwen2.5-0.5B artifact identity.

### Inference plane
- hardened bounded Stage RPC;
- exact input/output commitments;
- trace roots;
- real two-stage causal Transformer reference runtime;
- activation transfer;
- trained llama.cpp/GGUF backend adapter.

### KV/failover plane
- real incremental attention K/V tensors;
- KV snapshot serialization;
- exact KV root;
- restore on replacement worker;
- resumed next-token equivalence with uninterrupted execution.

### Byzantine plane
- verifier challenges/receipts;
- aggregate built from canonical ordered unique receipt set;
- deliberate malicious Transformer worker harness;
- mismatch blocks match finalization.

### Economics plane
- one-shot slash;
- slash consumed atomically during mismatch finalization;
- slash replay rejected;
- compute/storage/verifier/protocol/refund conservation;
- honest worker reward / dishonest worker no-reward policies.

### Finality plane
- one `MvpCheckpoint` binds all plane roots;
- finalization recomputes verifier aggregate from actual receipts;
- verification root must equal canonical receipt root;
- settlement must bind the same verifier set;
- adversarial checkpoint can be followed by an honest checkpoint with exact chain extension.

### Deployment/evidence plane
- 3-host inventory schema;
- unique/non-loopback host validator;
- role launcher;
- systemd template;
- evidence bundle generator;
- external-host acceptance checklist.

## What is not honestly GREEN yet

### 1. Executable Rust/Solidity certification
GitHub Actions run #1292 still fails before checkout:
- rust-core: `steps=null`, `logs_url=null`;
- solidity-core: `steps=null`, `logs_url=null`.

Therefore no Cargo.lock/test/Solidity evidence has been produced by this branch.

### 2. Live dual-PQ signing backend
The protocol requires PQ-only peer authorization. The current reference signer intentionally supports zeroizing ML-DSA signing but leaves SLH-DSA signing verification-only because the pinned backend does not meet the desired signing-key zeroization boundary.

MVP must therefore use either:
- reviewed zeroizing SLH-DSA signing backend; or
- OS/HSM/keystore signer implementing the existing `ContextSignatureSigner` boundary.

The protocol must not be downgraded to bypass this.

### 3. Actual trained-model deployment file
Historical evidence fixes the canonical first demo artifact as Qwen2.5-0.5B-Instruct-Q4_K_M, SHA-256 `74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db`, size `491400032` bytes. The deployment machine must possess and hash-verify that actual file.

### 4. Three real external hosts
The repository now contains the deployment pack, but three persistent external machines have not been supplied/executed in this environment.

## Honest current classification

```
MVP architecture:             COMPLETE
MVP canonical software path:  SOURCE-COMPLETE / HIGH READINESS
real transformer path:        COMPLETE (reference)
trained model adapter:        COMPLETE
PQ encrypted record plane:    COMPLETE at source level
KV exact resume:              COMPLETE at reference-runtime level
Byzantine/slash path:         COMPLETE at source/test level
3-host deploy pack:           COMPLETE
Rust/Solidity executable:     BLOCKED BY RUNNER
dual-PQ live signing:         EXTERNAL BACKEND REQUIRED
trained GGUF physical file:   EXTERNAL ARTIFACT REQUIRED
3-host evidence:              EXTERNAL HOSTS REQUIRED
MVP GREEN:                    NOT YET CLAIMED
```

The remaining path is execution/infrastructure, not another architecture rewrite.
