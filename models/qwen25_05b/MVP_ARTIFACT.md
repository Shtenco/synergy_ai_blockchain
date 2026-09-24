# Canonical trained-model artifact for the first MVP demo

Historical NEXUS R2 evidence identifies the exact trained model/runtime pair already used successfully in this project family:

- model: `Qwen2.5-0.5B-Instruct-Q4_K_M`
- exact size: `491400032` bytes
- exact SHA-256: `74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db`
- runtime: official `llama.cpp b10221`
- historical executable entrypoint: `llama-completion --jinja --single-turn`

Historical NEXUS R2 audit also records that this pair was physically connected and exercised.

For the new PQ-AI blockchain MVP, a host may use this artifact only if the local file hash and exact byte size match the values above. A same-name file with a different digest is a different model artifact and must receive a new model root.

The current repository adapter is:

`runtime/llama_cpp_backend_v1.py`

Before a trained-model run is accepted, evidence must include:

1. llama.cpp executable SHA-256;
2. GGUF SHA-256;
3. GGUF byte size;
4. model root;
5. stage/shard root;
6. capability root;
7. deterministic inference parameters;
8. Stage RPC trace root;
9. verifier result.

The exact GGUF binary was not directly discoverable as a standalone Google Drive file during the 2026-09-24 integration pass; the artifact identity is preserved from the historical R2 evidence and must be matched against the actual deployment file.
