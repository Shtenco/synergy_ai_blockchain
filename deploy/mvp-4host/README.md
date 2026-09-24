# SYNERGY MVP 4-host topology

The fourth node is a permanent independent verifier/failover worker.

Roles:
- Node A — model/content provider.
- Node B — transformer stage 0 worker.
- Node C — primary stage 1 worker.
- Node D — independent stage 1 verifier + failover replica.

Acceptance scenario:
1. A distributes the exact model shard to B/C/D.
2. B computes stage 0 and emits committed activations.
3. C computes the primary stage 1 result.
4. D independently recomputes stage 1.
5. A C/D mismatch blocks primary finalization.
6. If C is malicious/unavailable, D becomes the stage 1 failover.
7. D output must equal the deterministic/reference result.
8. Verification/slash/settlement then feeds the canonical MvpCheckpoint.

Local proof:
```
PYTHONPATH=. python scripts/mvp_four_node_smoke.py
```

Expected evidence:
`evidence/mvp_four_node_smoke.json`

The local proof uses four distinct TCP endpoints on one physical machine.
It proves role separation, content replication, independent verification and
failover behavior, but it does not by itself prove four distinct external hosts.

External GREENFULL-4 requires four distinct persistent machines with unique
node identities and PQ-authenticated sessions.
