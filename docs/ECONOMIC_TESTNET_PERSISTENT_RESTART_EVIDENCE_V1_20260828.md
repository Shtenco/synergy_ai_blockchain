# Economic Testnet Local Persistence / Restart Evidence v1 — 2026-08-28

This additive generation advances the already verified three-process TCP loopback checkpoint protocol with local durable state, fresh-process recovery, partition/catch-up behavior and replay rejection.

It still does **not** prove an external-host or public testnet, consensus, finality, signing or blockchain submission.

## Exact parent evidence

Three-process TCP loopback execution root:

`6f80d6cfdbce8eb0b2410c7e440f260eaf6199da8e5b64ce48c365c68be684d5`

## Executed scenario

1. node-1, node-2 and node-3 persist checkpoint #1;
2. checkpoint #2 is delivered only to node-1/node-2, deliberately withholding it from node-3;
3. all three node states are recovered in fresh Python processes;
4. recovered heads are exactly `C2 / C2 / C1`;
5. replay of checkpoint #1 against recovered node-1 is rejected;
6. node-3 reconnects and accepts checkpoint #2;
7. all nodes accept checkpoint #3;
8. all three states are recovered again in fresh processes and converge to exact checkpoint #3.

Checkpoint roots:

- C1 `69897b297fde6a25a9c123fe1c21b5ea31f2da2dc463edfc1c7a2364812ca8ab`
- C2 `3742319fa196294a16f9bd80fc502cbd25c06040b569b9080dfeb2893100dedd`
- C3 `92c74a6181af9676c4e6805665db3d6466cde5b5a7cecc1850e500ec9a627ae8`

Deterministic transcript root:

`fd29843c4934246938bdd8d71d32c716d589e2e6756df444e72d1e0d1bb791d8`

Canonical execution evidence root:

`7c533e6ebb3b3177ef9191d1951c930ddd9d6f49541b0fa3982924f2dce86680`

## Persistence boundary

The reference store writes a canonical JSON checkpoint sequence to a temporary file, flushes + fsyncs it and atomically replaces the prior state file. Recovery re-verifies every stored checkpoint against the exact genesis, sequence and previous checkpoint digest before accepting the recovered state.

Therefore a corrupt/tampered persisted checkpoint sequence fails closed on restart.

## Claim boundary

Positive claim only:

`LOCAL_DISK_PERSISTENCE_RESTART_RECOVERY_VERIFIED_NOT_EXTERNAL_HOST_TESTNET`

Still not claimed:

- external-host multi-node deployment;
- public network;
- consensus;
- finality beyond candidate state;
- signing;
- blockchain submission;
- financial/accounting/payment/execution authority.

The remaining testnet deployment blocker is narrowed to:

`EXTERNAL_HOST_MULTI_NODE_DEPLOYMENT_EXECUTION_NOT_CAPTURED`
