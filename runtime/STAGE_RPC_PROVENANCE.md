# Stage RPC v1

This runtime is a hardened rewrite of the execution shape proven by `Shtenco/synergy_agi_olga@nexus-v16-distributed-weight-fusion/nexus_v16/verify_five_node_rpc.py`.

Unlike the historical harness it does **not** use pickle or arbitrary Python object deserialization. The control plane is bounded canonical JSON; payloads are raw bytes with SHA-256 input/output commitments. The reference hash backend is only a smoke backend and makes no LLM-performance claim. A real model backend must implement the same `StageBackend` interface.
