# Real Transformer MVP backend v1

The first canonical distributed model backend is a deliberately tiny deterministic **real causal Transformer** implemented with NumPy only. It contains byte-token embeddings, positional embeddings, causal multi-head self-attention, pre-norm residual blocks, MLP layers and an LM head. Stage 0 emits serialized hidden activations; Stage 1 consumes them and emits next-token logits/argmax.

It is intentionally untrained and therefore makes **no language-quality claim**. Its purpose is to prove real transformer mathematics, activation transfer and exact distributed-vs-local equivalence through the canonical Stage RPC contract without depending on external model downloads or `llama.cpp`.

Next backend substitution: Qwen/Llama GGUF via the existing `synergy_gguf_compress` V4/V5 runtime line, using the same RPC/evidence contracts.
