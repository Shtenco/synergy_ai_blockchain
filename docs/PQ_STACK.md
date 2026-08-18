# Full-chain post-quantum stack

A blockchain is not post-quantum merely because one wallet can verify a PQ signature. SYNERGY PQ-EVM treats every cryptographic boundary separately.

## Layer 1 — user/account authorization

- native: ML-DSA-87;
- MAX/cold: ML-DSA-87 AND SLH-DSA-SHAKE-256s;
- transition/EVM compatibility: secp256k1 AND ML-DSA-87;
- no OR downgrade.

## Layer 2 — validator consensus authorization

Migration epoch:

`legacy_validator_signature AND ML-DSA-87`

Final PQ epoch:

`ML-DSA-87`

Validator PQ keys are generated independently from old BLS/ECC/EdDSA keys.

Because ML-DSA signatures are substantially larger than legacy ECC signatures, consensus networking and block/vote encoding must be benchmarked before selecting validator-set size and quorum cadence.

## Layer 3 — P2P/session establishment

- ML-KEM-1024 mandatory PQ KEM;
- optional classical KEX in transition mode;
- transcript-bound robust combiner/KDF in the networking client;
- periodic fresh KEM rekey for post-compromise recovery;
- no private KEM material inside EVM state.

## Layer 4 — EVM application compatibility

Keep normal EVM bytecode, ABI, storage semantics and Keccak opcodes for application compatibility. Add chain-local system precompiles rather than changing every contract.

Where stronger consensus commitments are desired, the block protocol may additionally carry a wider PQ security commitment/root without changing Solidity's `keccak256` semantics. This requires a separately specified state commitment design and proof format before activation.

## Layer 5 — NEXUS AI

Every EVM context can call the same deterministic NEXUS precompile.

Two execution profiles are planned:

1. `NEXUS_NATIVE_FIXED`: validators execute a frozen quantized integer model bit-for-bit;
2. `NEXUS_PROVED`: off-chain inference produces a proof and validators verify the proof through the `NEXUS_PROOF_VERIFY` precompile.

The second profile is the scale path for larger future NEXUS models. Neither profile gives AI signing authority.

## Layer 6 — bridge and migration

BTC/ETH/SOL legacy signatures prove source ownership only. Assets become PQ-native only after finalized lock/burn evidence and mint under an independently generated PQ account.

Reserve invariant:

`minted <= finalized_locked - finalized_withdrawals`

## Layer 7 — governance and administration

Treasury, bridge admin, validator registry, model-upgrade and emergency keys must migrate to the same PQ/hybrid policies. A PQ user layer with classical governance is not sufficient.

## Layer 8 — wallet at rest

Wallet storage should use a reviewed memory-hard password KDF where a passphrase exists, authenticated encryption, hardware-backed storage where available, explicit recovery and independent PQ key material.

The experimental pi/time-ratchet research may be added as a domain-separated supplemental ratchet, but system security must not depend on secrecy or unpredictability of pi.

## Migration sequence

1. ship dual classical+PQ identities;
2. require hybrid authorization for high-value/admin operations;
3. enable PQ-native smart accounts;
4. migrate validator and P2P keys;
5. enable BTC/ETH/SOL migration corridors;
6. freeze and activate deterministic NEXUS model root;
7. enforce PQ-only new accounts/validators at a declared fork height;
8. retain legacy verification only for explicitly bounded migration proofs.
