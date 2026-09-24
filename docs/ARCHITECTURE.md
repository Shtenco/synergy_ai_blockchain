# SYNERGY PQ-EVM + NEXUS architecture v1

## Goal

Preserve ordinary EVM bytecode/ABI semantics while adding two consensus-native capabilities:

1. post-quantum account/transaction authorization;
2. deterministic NEXUS inference callable from every EVM execution context.

The design does **not** claim that Ethereum, Bitcoin or Solana become post-quantum by bridging into SYNERGY. Legacy-chain ownership is used only to authorize migration; after migration the SYNERGY account uses independently generated PQ keys.

## Existing project reuse

- `Shtenco/agi_olga`: NEXUS provenance/model research. V18 reports checkpoint SHA-256 `74433965c8193b6f75b42c197a4394bb14e37f2ef0ea0c7eb8b826e46c65c4e4` and an internal small-world graph reasoner.
- `Shtenco/synergy_pay_system`: existing omnichain catalog, EVM contracts, bridge meta-router, settlement, HSM/MPC and readiness controls.
- `Shtenco/synergychain`: product/Growth OS and OLGA AGI surface.
- `Shtenco/synergy_ai_blockchain`: this consensus/execution repository.

## Execution layers

```text
Legacy chains / wallets
 BTC secp256k1 | ETH secp256k1 | SOL Ed25519
          | ownership proof only
          v
+------------------------------------------+
| SYNERGY migration / light-client layer   |
+------------------------------------------+
          |
          v
+------------------------------------------+
| Native PQ account layer                  |
| ML-DSA-87 [+ SLH-DSA-SHAKE-256s]         |
+------------------------------------------+
          |
          v
+------------------------------------------+
| EVM-compatible execution                 |
| bytecode / ABI / storage / logs / RPC    |
+------------------+-----------------------+
                   |
        +----------+-----------+
        |                      |
        v                      v
 PQ verify precompiles      NEXUS precompile
 0x0900 / 0x0901           0x0910
                               |
                               v
                       fixed-point graph AI
```

## PQ cryptography

Mandatory production profile:

- ML-DSA-87 for native PQ signatures;
- SLH-DSA-SHAKE-256s as an independent hash-based signature lane for MAX/cold policy;
- ML-KEM-1024 for wallet/session key establishment outside consensus transaction verification;
- existing secp256k1/Ed25519 only for legacy compatibility and migration proofs.

No PQ private key is derived from a Bitcoin/Ethereum/Solana private key.

## EVM compatibility

The EVM does not need new opcodes for ordinary applications. Consensus clients expose reserved system precompiles. Solidity contracts can `STATICCALL` them through the included interfaces.

A native SYNERGY typed transaction may carry PQ authorization outside EVM execution. Existing Ethereum tooling can still interact through account-abstraction/smart-account facades and standard ABI calls.

## NEXUS in every EVM

"NEXUS in every EVM" means every contract execution can call the same deterministic system precompile. It does **not** mean one mutable LLM process per contract.

Consensus rules:

- no HTTP/OpenRouter/network call during block execution;
- no PyTorch runtime in consensus;
- no floating point;
- quantized integer/fixed-point weights only;
- frozen model artifact root in chain configuration;
- model upgrade activates at a declared block height;
- validators execute bit-identical kernels;
- bounded input/output dimensions;
- deterministic gas schedule;
- NEXUS cannot directly authorize asset transfers.

The initial Rust reference kernel implements the NEXUS small-world graph brick in Q16.16. Full V18 activation requires export/quantization of the verified checkpoint into a frozen consensus artifact and cross-client test vectors.

## Model upgrade lifecycle

1. freeze source checkpoint and training evidence;
2. export deterministic integer graph/weights;
3. generate manifest and model Merkle/root hash;
4. produce canonical inference test vectors;
5. reproduce bit-exact outputs on at least two independent clients;
6. governance schedules `(model_root, implementation_hash, gas_schedule, activation_block)`;
7. validators preinstall artifacts before activation;
8. activation occurs without runtime downloads.

## AI safety boundary

NEXUS is a deterministic computation primitive, not consensus authority. Contracts may use it for scoring, policy recommendations, anomaly classification or proof assistance, but signatures, balances, state transition validity and consensus finality remain explicit deterministic protocol rules.
