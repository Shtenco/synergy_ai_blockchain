# MVP Vertical Slice #1

This smoke harness intentionally proves the narrowest useful runtime path before a real LLM backend is attached:

```
node A content provider
  -> persistent content store
  -> relay
  -> node B content store
  -> bounded stage RPC
  -> deterministic verifier recompute
  -> evidence root
```

Run:

```bash
PYTHONPATH=. python3 scripts/mvp_vertical_slice_smoke.py
```

Output:

`evidence/mvp_vertical_slice_smoke.json`

The hash reference backend is only a transport/integrity test. It is not counted as M5 distributed LLM completion. The next runtime substitution is a real small transformer backend using the exact same stage-RPC protocol and commitment fields.
