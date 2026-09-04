# SINERGY L1 G0 runnable PQ devnet

This directory turns the existing PQ-EVM consensus model into a runnable single-host integration node without pretending that the temporary backend is native post-quantum consensus.

## Network profile

- chain id: `8453001`
- public/integration RPC: `http://127.0.0.1:9545`
- private EVM backend RPC: `http://127.0.0.1:9546`
- public state-changing `eth_sendRawTransaction`: blocked
- accepted write path: `synergy_sendPqRawTransaction`
- default PQ replay DB: `~/.synergy-l1/pq_gateway.sqlite3`
- persistent EVM state: `~/.synergy-l1/anvil-state.json`

The backend is intentionally bound only to localhost. Do not expose port 9546.

## Cryptography

The gateway pins `pqcrypto==1.0.0` and verifies:

- ML-DSA-87 / FIPS 204;
- SLH-DSA-SHAKE-256s / FIPS 205 for `hybrid_max` and `pq_only` envelopes.

`hybrid_online` requires the normal EVM raw transaction authorization plus an ML-DSA-87 envelope.

`hybrid_max` requires the normal EVM raw transaction authorization plus ML-DSA-87 and SLH-DSA-SHAKE-256s.

`pq_only` treats the dual-PQ envelope as the external authorization identity, although the G0 private EVM backend still consumes a conventional raw EVM transaction. Native reserved-address PQ precompiles are a later generation and are not claimed by G0.

## Start

Install Foundry (`anvil`) and Python 3, then set a private devnet mnemonic:

```bash
export SYNERGY_DEVNET_MNEMONIC='...private mnemonic...'
chmod +x node/run-devnet.sh
node/run-devnet.sh
```

Never use Anvil's public default mnemonic for a persistent or remotely reachable node.

Health check:

```bash
curl -s http://127.0.0.1:9545 \
  -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"synergy_health","params":[]}'
```

Chain profile:

```bash
curl -s http://127.0.0.1:9545 \
  -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"synergy_chainProfile","params":[]}'
```

## PQ envelope flow

1. Build and sign an EVM raw transaction for chain id `8453001`.
2. Generate or load the ML-DSA-87 key pair. For `pq_only`/`hybrid_max`, also load SLH-DSA-SHAKE-256s.
3. Ask `synergy_getPqNonce` for the next replay nonce.
4. Choose a short `expires_at` Unix timestamp (maximum TTL is 600 seconds by default).
5. Call `synergy_buildPqPreimage` with the raw transaction, ML-DSA public key, nonce, expiry and policy.
6. Sign the returned preimage bytes with the required PQ keys.
7. Submit all fields through `synergy_sendPqRawTransaction`.
8. The gateway verifies PQ signatures and replay state and only then forwards the raw transaction to the private EVM backend.

## Security boundary

G0 is suitable for:

- deploying and testing the SINERGY-side messenger and QE controller;
- exercising a trusted relayer against a Base fork;
- validating PQ admission, replay protection and persistent EVM state;
- local integration with the existing PQ-EVM/NEXUS library.

G0 is **not** sufficient for custody of production value because Anvil is a development EVM backend and block production is not native PQ consensus.

The production path is to replace the backend/gateway split with native `revm/reth` integration of the reserved PQ precompiles at `0x0900` and `0x0901`, then connect multi-validator PQ transport/consensus.
