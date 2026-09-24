# Trained GGUF backend

`runtime/llama_cpp_backend_v1.py` is the trained-model substitution for the deterministic NumPy Transformer backend.

It deliberately does not download a model or a runtime. An MVP host must be provisioned with:

- a pinned executable `llama-cli` from llama.cpp;
- a local trained Qwen/Llama-compatible GGUF;
- the expected model/shard/capability roots.

The adapter executes deterministic one-token inference (`temperature=0`, fixed seed), returns the bytes through the same bounded Stage RPC contract and records SHA-256 for both the executable and GGUF artifact.

This allows the public demo to replace the reference Transformer without modifying network, verification, settlement or checkpoint commitments.

The existing two-stage NumPy Transformer remains the exact distributed activation-transfer proof. A later llama.cpp split-execution backend may replace both stages without changing the evidence schema.
