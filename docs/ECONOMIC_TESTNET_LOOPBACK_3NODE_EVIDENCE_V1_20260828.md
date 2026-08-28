# Economic Testnet 3-Node TCP Loopback Evidence v1 — 2026-08-28

This additive generation advances the Economic OS testnet execution path from a single in-process deterministic replay to actual checkpoint serialization across three independent local Python processes using TCP loopback.

It remains explicitly **non-persistent** and **non-external-host**. It is not evidence of a public or production testnet, consensus, finality, signing or blockchain submission.

## Executed facts

- runner class: `EPHEMERAL_LOCAL_MULTI_PROCESS_TCP_LOOPBACK`
- runtime: CPython 3.13.5
- platform: Linux x86_64
- transport: TCP on `127.0.0.1`
- processes/nodes: 3
- checkpoints per node: 2
- checkpoint deliveries: 6 accepted / 0 rejected
- persistence: EPHEMERAL

All three nodes independently verified the exact checkpoint chain and converged to the same final head.

Evidence set:
`c804516869743b9215cc7c46749412209fa929ee941a259a726bfd1c97c9a1a0`

Checkpoint #1:
`69897b297fde6a25a9c123fe1c21b5ea31f2da2dc463edfc1c7a2364812ca8ab`

Checkpoint #2 / common final head:
`3742319fa196294a16f9bd80fc502cbd25c06040b569b9080dfeb2893100dedd`

Six-ack transcript digest:
`8371c650c0cae249a077519701d33077ded70a7698bf4d43fc5a73f1a29edcf8`

Canonical loopback execution evidence root:
`6f80d6cfdbce8eb0b2410c7e440f260eaf6199da8e5b64ce48c365c68be684d5`

## Claim boundary

Positive claim:
`LOCAL_3_NODE_TCP_PROPAGATION_VERIFIED_NOT_PERSISTENT_TESTNET`

Still not claimed:
- external-host testnet;
- persistent runner;
- consensus;
- finality beyond candidate status;
- signing;
- submission;
- accounting, financial, payment or execution authority.

The remaining testnet execution blocker is narrowed to:
`PERSISTENT_EXTERNAL_HOST_MULTI_NODE_TESTNET_EXECUTION_NOT_CAPTURED`.

The repository also includes a reproducible `economic_testnet_loopback_v1.py` harness for three-process TCP replay of the same pinned genesis/checkpoint protocol. Its purpose is reproducibility and adversarial testing; it does not create consensus or production authority.
