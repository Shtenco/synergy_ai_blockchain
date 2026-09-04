# SINERGY L1 + Base Messenger + QE Printing Press V1

Status: integration/devnet architecture. No Base Mainnet deployment is performed by this branch.

## Objective

Build the smallest runnable SINERGY L1 surface needed for the economic experiment:

1. EVM-compatible SINERGY L1, chain id `8453001`, RPC `127.0.0.1:9545`;
2. post-quantum transaction admission using ML-DSA-87 and, for `PqOnly`, SLH-DSA-SHAKE-256s;
3. an `ICrossDomainMessenger`-style trusted-relayer corridor between Base Mainnet (`8453`) and SINERGY L1 (`8453001`);
4. the existing QE economic machine: internal QE price impulse -> external Base DEX execution -> QT/debt closure -> canonical NAV settlement;
5. fail-closed accounting: internal marked value, QE debt and flash principal are never canonical profit.

## Important Base correction

The OP Stack Base `L1CrossDomainMessenger` is an Ethereum Mainnet contract for the Ethereum <-> Base corridor. It is not a universal Base Mainnet -> arbitrary SINERGY L1 transport.

On Base Mainnet the canonical OP Stack messenger predeploy is `L2CrossDomainMessenger` at `0x4200000000000000000000000000000000000007`, and that messenger is paired with Base's Ethereum-side portal/messenger system.

Therefore SINERGY keeps the `ICrossDomainMessenger` developer model (`sendMessage`, `relayMessage`, `xDomainMessageSender`) but deploys its own `TrustedRelayerCrossDomainMessenger` on Base and on SINERGY L1.

## Architecture

```text
                         BASE MAINNET / 8453

   Canonical USDC/WETH vault
              |
              v
      BaseQEExternalExecutor
              |
       best real DEX route
   UniV3 / Aerodrome / Pancake
              |
              v
   Base TrustedRelayerMessenger
              ^
              |  relayer: event + confirmations + replay id
              v
  SINERGY TrustedRelayerMessenger
              |
              v
       SinergyQEController
              |
              v
       Internal QE Pool
              |
       PQ-EVM / NEXUS policy

                         SINERGY L1 / 8453001
```

## Why the messenger is separate from the asset reserve

For the first generation, canonical Base USDC/WETH remains in the Base execution vault. The cross-domain corridor transports authenticated intents and settlement receipts, not flash-loan principal.

This is materially safer than bridging the same asset for every QE cycle. The L1 controls the monetary state; Base holds and executes canonical external inventory.

A later asset bridge can be added independently after the messaging and accounting invariants are proven.

## QE economic cycle

The economic lineage is inherited from `Shtenco/synergychain` V11/V12:

```text
QE -> price gradient -> external executable DEX route -> QT -> settlement -> canonical NAV
```

The live-intent form is:

1. read an executable external Base quote / venue set;
2. set a bounded internal QE price deviation;
3. create a signed `QEIntent` containing direction, principal cap, slippage/deadline and minimum canonical gain;
4. relay the intent to Base;
5. Base executor trades only through allowlisted, codehash-pinned DEX adapters;
6. repay any temporary financing on Base;
7. compute Base canonical NAV after all fees and protocol-owned LP losses;
8. relay the settlement receipt to SINERGY L1;
9. close the QE debt with QT and return the internal price to neutral;
10. only the canonical Base NAV delta is eligible for reserve growth.

## Accounting invariants

For every completed cycle:

```text
QE_DEBT_END = 0
FLASH_DEBT_END = 0            # if flash is used on Base
EXECUTOR_RESIDUAL = 0         # except explicitly owned inventory
MESSAGE_REPLAY = false
CANONICAL_NAV_AFTER >= CANONICAL_NAV_BEFORE + min_gain
```

Canonical NAV is Base-native settlement value (for the initial corridor, native USDC plus executable USDC liquidation value of canonical WETH).

The following are explicitly excluded from canonical profit:

- minted internal tokens;
- internal QE debt;
- marginal mark-to-market revaluation of protocol-issued supply;
- flash principal;
- transfers between protocol-owned vaults;
- executor PnL that is offset by protocol-owned LP/reserve loss.

## Relation to the old pump model

The old four-contract V11 harness is preserved conceptually:

- `InternalMintedPool`
- `BaseExternalPool`
- `USDCBridgePump`
- `ETHBridgePump`

In V1 L1 integration, the two pumps become a cross-domain control/settlement path around a Base canonical execution vault. The internal QE gradient can determine the external trade direction and size, but the system reports success only when consolidated external NAV actually rises.

## Security model for V1

The first bridge is intentionally `trusted-relayer`, not trustless.

The relayer may relay only an event emitted by the configured remote messenger. Both messenger contracts enforce:

- fixed remote chain id;
- fixed trusted relayer;
- replay id consumption;
- target non-zero;
- bounded message size;
- `xDomainMessageSender()` exposure during the target call.

Every economic target MUST additionally check:

```solidity
msg.sender == localMessenger
localMessenger.xDomainMessageSender() == configuredRemoteEconomicContract
```

The trusted relayer remains a trust assumption until the metachain Ethereum/Base light-client path is connected.

## Post-quantum boundary

The existing consensus core already reserves:

- `0x0900` ML-DSA-87 verification;
- `0x0901` SLH-DSA-SHAKE-256s verification;
- `0x0910` deterministic NEXUS inference;
- `0x0911` NEXUS proof verification.

The first runnable devnet uses a private EVM backend plus a fail-closed public PQ RPC admission gateway. Direct state-changing backend RPC methods are not exposed. This gives a practical hybrid-PQ node for integration while native `revm/reth` precompile integration is developed.

It MUST NOT be described as a production-grade PQ consensus network until the native precompiles, validator consensus, peer transport and external-host multi-node evidence are complete.

## Generation plan

### G0 - runnable single-node devnet

- chain id 8453001;
- persistent EVM state;
- public RPC 9545 through PQ admission gateway;
- private backend RPC 9546 bound to localhost;
- ML-DSA-87 + SLH-DSA-SHAKE-256s envelope verification;
- replay-safe PQ nonces.

### G1 - messenger corridor on local Base fork

- deploy `TrustedRelayerCrossDomainMessenger` on both sides;
- deploy `SinergyQEController` on SINERGY;
- deploy Base executor/adapter against a Base fork;
- relay one full intent and settlement in both directions.

### G2 - economic acceptance

A test passes only if a full cycle closes every debt/residual and records canonical Base NAV correctly. A QE=0 control is retained for causal research attribution.

### G3 - Base Mainnet micro-live

Only after G0-G2 are green:

- rotate all previously exposed deployer/relayer credentials;
- deploy only new messenger/executor contracts;
- use a strict per-transaction notional cap;
- no OP Stack L3 deployment;
- no unbounded approvals;
- no assumption of guaranteed QE profit.

### G4 - native PQ L1

Replace the devnet admission proxy with native `revm/reth` integration of the reserved PQ/NEXUS precompiles and multi-validator PQ transport/consensus.
