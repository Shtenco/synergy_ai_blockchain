# Base Mainnet <-> SINERGY L1 trusted relayer V1

This relayer connects the two `TrustedRelayerCrossDomainMessenger` contracts. It does not use Base's OP Stack L1CrossDomainMessenger because that contract belongs to the Ethereum Mainnet <-> Base corridor, not Base -> arbitrary SINERGY L1.

## Directional security

### Base -> SINERGY

1. Watch `SentMessage` on the configured Base messenger.
2. Wait `BASE_CONFIRMATIONS`.
3. Build `sourceEventId = keccak256(sourceChainId, blockHash, txHash, logIndex)`.
4. Build the SINERGY `relayMessage` transaction.
5. Sign the underlying devnet EVM transaction with the dedicated SINERGY relayer ECDSA key.
6. Wrap it in `hybrid_max` using ML-DSA-87 + SLH-DSA-SHAKE-256s.
7. Submit through `synergy_sendPqRawTransaction` on port 9545.

### SINERGY -> Base

1. Watch `SentMessage` on SINERGY.
2. Wait `SINERGY_CONFIRMATIONS`.
3. Derive the same source-event identity format.
4. Submit `relayMessage` to Base from a **dedicated relayer key**, not the deployer key.

The destination messenger rejects the same sourceEventId twice and exposes `xDomainMessageSender()` while the target call is executing.

## Environment

Never put private keys in the repository.

```bash
export BASE_RPC_URL='https://...'
export SINERGY_RPC_URL='http://127.0.0.1:9545'
export BASE_SINERGY_MESSENGER='0x...'
export SINERGY_BASE_MESSENGER='0x...'

export BASE_RELAYER_PRIVATE_KEY='0x...DEDICATED RELAYER KEY...'
export SINERGY_RELAYER_ECDSA_PRIVATE_KEY='0x...DEVNET BACKEND RELAYER KEY...'

export SINERGY_RELAYER_ML_DSA_87_PUBLIC_KEY_FILE="$HOME/.synergy-l1/keys/relayer.ml_dsa_87.pub"
export SINERGY_RELAYER_ML_DSA_87_SECRET_KEY_FILE="$HOME/.synergy-l1/keys/relayer.ml_dsa_87.key"
export SINERGY_RELAYER_SLH_DSA_PUBLIC_KEY_FILE="$HOME/.synergy-l1/keys/relayer.slh_dsa_shake_256s.pub"
export SINERGY_RELAYER_SLH_DSA_SECRET_KEY_FILE="$HOME/.synergy-l1/keys/relayer.slh_dsa_shake_256s.key"

export BASE_CONFIRMATIONS=20
export SINERGY_CONFIRMATIONS=2
export RELAYER_POLL_SECONDS=2
```

Generate fresh PQ keys locally:

```bash
python node/generate_pq_relayer_keys.py "$HOME/.synergy-l1/keys"
```

Install/run:

```bash
python3 -m venv ~/.synergy-l1/relayer-venv
~/.synergy-l1/relayer-venv/bin/pip install -r relayer/requirements.txt
~/.synergy-l1/relayer-venv/bin/python relayer/base_sinergy_relayer.py
```

## Important operational rule

The Base messenger's `trustedRelayer` must equal the EOA derived from `BASE_RELAYER_PRIVATE_KEY`. The SINERGY messenger's `trustedRelayer` must equal the EOA derived from `SINERGY_RELAYER_ECDSA_PRIVATE_KEY`.

The relayer validates both at startup/use time and refuses to submit from a mismatched account.

## Upgrade path

This is deliberately a trusted relayer. The existing `synergy_metachain` bridge pipeline already defines the stronger future boundary: source finality proof + lock/burn/message-event verification + replay guard. When the real Ethereum/Base light-client verifier is available, that proof path should replace relayer trust without changing the application-level cross-domain sender checks.
