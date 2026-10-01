# SYNERGY MVP 3-host deployment pack

This directory is the deployment boundary for the first real external MVP.

## Required topology

- **Host A** — persistent content/model provider.
- **Host B** — transformer stage 0 worker + KV primary/replica participant.
  e2-1 `51.170.89.241`, e2-2 `129.151.138.7` (пересозданы 29.09.2026).
- **Host C** — transformer stage 1 worker/verifier + KV failover target.

All three hosts must be distinct persistent machines. Loopback aliases or three processes on one host do not satisfy the MVP external-host gate.

## Bootstrap

On every host:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r runtime/requirements-mvp.txt
```

Host A:

```bash
PYTHONPATH=. python3 scripts/mvp_node.py   --role provider   --host 0.0.0.0   --port 7791   --store /var/lib/synergy/provider
```

Host B:

```bash
PYTHONPATH=. python3 scripts/mvp_node.py   --role stage0   --host 0.0.0.0   --port 7801
```

Host C:

```bash
PYTHONPATH=. python3 scripts/mvp_node.py   --role stage1   --host 0.0.0.0   --port 7802
```

For the trained public demo, replace one reference worker with:

```bash
PYTHONPATH=. python3 scripts/mvp_node.py   --role trained-worker   --host 0.0.0.0   --port 7802   --llama-cli /opt/llama.cpp/llama-cli   --gguf /opt/models/model.gguf   --model-root <64hex>   --shard-root <64hex>   --capability-root <64hex>
```

## Security boundary

The Python workers are execution runtimes only. Production-accepted traffic must be wrapped by the Rust PQ transport/session layer before evidence is canonicalized.

The Rust layer now includes:

- ML-KEM/session transcript binding;
- directional transport keys;
- ChaCha20-Poly1305 encrypted records;
- direction/sequence nonces;
- transcript/application AAD;
- replay rejection;
- rekey limits.

## External MVP acceptance

A run is accepted only if evidence proves:

1. three unique persistent host fingerprints;
2. authenticated PQ session roots between required peers;
3. model/shard provider lookup;
4. exact shard hash on destination;
5. stage0 activation transfer B -> C;
6. next-token output;
7. verifier receipts;
8. one deliberate malicious-worker mismatch;
9. slash consumed exactly once;
10. KV snapshot copied to a different host and resumed after primary termination;
11. valid worker settlement;
12. restart and catch-up;
13. identical final `MvpCheckpoint` root on all three hosts.

No local-only run may be relabeled as external MVP GREEN.
