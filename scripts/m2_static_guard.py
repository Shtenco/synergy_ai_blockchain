#!/usr/bin/env python3
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]

def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"M2 static guard failed: {message}")

cargo = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
pq = (ROOT / "src/pq.rs").read_text(encoding="utf-8")
pq_ref = (ROOT / "src/pq_reference.rs").read_text(encoding="utf-8")
network = (ROOT / "src/network.rs").read_text(encoding="utf-8")
tx = (ROOT / "src/tx.rs").read_text(encoding="utf-8")
workflow = (ROOT / ".github/workflows/pq-evm-ci.yml").read_text(encoding="utf-8")
toolchain = (ROOT / "rust-toolchain.toml").read_text(encoding="utf-8")
lock_policy = (ROOT / "scripts/m2_verify_lock.py").read_text(encoding="utf-8")

# Reproducibility / MSRV invariants.
require('rust-version = "1.85"' in cargo, "crate rust-version must stay pinned to 1.85")
for exact in (
    'ml-kem = { version = "=0.3.2"',
    'ml-dsa = { version = "=0.1.1"',
    'slh-dsa = { version = "=0.1.0"',
    'rand = { version = "=0.8.5"',
    'zeroize = { version = "=1.8.1"',
    'sha2 = { version = "=0.10.9"',
    'hex = "=0.4.3"',
    'serde = { version = "=1.0.228"',
    'serde_json = "=1.0.145"',
):
    require(exact in cargo, f"missing exact dependency pin: {exact}")

# Context anti-downgrade invariants.
require("pub fn verify_envelope_authorization" in pq, "envelope-bound verifier missing")
require(
    '#[cfg(test)]\npub(crate) fn verify_authorization<' in pq,
    "no-context authorization helper must exist only in test builds",
)
require(
    "pub(crate) fn verify_authorization_with_context<" in pq,
    "raw context verifier must remain crate-internal",
)
require("pub struct PqSigningKeyHandle([u8; 32]);" in pq, "signing handle must remain nominal")
require("pub type PqSigningKeyHandle = [u8; 32];" not in pq, "signing handle regressed to type alias")
require("type SecretHandle;" in network, "ML-KEM provider must have associated secret-handle type")
require(
    "pub struct MlKemSecretHandle([u8; 32]);" in pq_ref,
    "ML-KEM handle must remain nominal",
)
require(
    "pub type MlKemSecretHandle = [u8; 32];" not in pq_ref,
    "ML-KEM handle regressed to type alias",
)

# Exact serialization gates.
for gate in (
    "ML_KEM_1024_PUBLIC_KEY_BYTES: usize = 1568",
    "ML_KEM_1024_CIPHERTEXT_BYTES: usize = 1568",
    "ML_KEM_SHARED_SECRET_BYTES: usize = 32",
):
    require(gate in network, f"missing network ML-KEM size invariant: {gate}")

for gate in (
    "ML_DSA_87_PUBLIC_KEY_BYTES: usize = 2592",
    "ML_DSA_87_SIGNATURE_BYTES: usize = 4627",
    "SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES: usize = 64",
    "SLH_DSA_SHAKE_256S_SIGNATURE_BYTES: usize = 29792",
):
    require(gate in pq, f"missing protocol PQ serialized-size gate: {gate}")

# Production provider must fail closed instead of panicking on local conditions.
prod = pq_ref.split("\n#[cfg(test)]\nmod tests", 1)[0]
for forbidden in (".unwrap(", ".expect(", "panic!(", "debug_assert!(", ".fill_bytes("):
    require(forbidden not in prod, f"production pq_reference contains forbidden pattern {forbidden}")

require("try_generate_keypair" in prod, "fallible ML-KEM key generation missing")
require("::try_generate().ok()?" in prod, "fallible RustCrypto key generation missing")
require(".try_fill_bytes(" in prod, "fallible capability RNG missing")
require("for _ in 0..32" in prod, "capability allocation attempts must remain bounded")

# Actual transaction path must be state-aware and FIPS-context aware.
require(
    "pub struct TxValidationContext" in tx,
    "state-aware transaction validation context missing",
)
require(
    "expected_chain_id" in tx
    and "expected_nonce" in tx
    and "expected_authorization_epoch" in tx
    and "authorization_expires_at" in tx
    and "AuthorizationEpochMismatch" in tx
    and "AuthorizationExpired" in tx,
    "transaction chain/nonce/epoch/expiry replay guards missing",
)
require(
    "verify_authorization_with_context(" in tx,
    "transaction validation must use FIPS context verifier",
)
require(
    "verify_authorization(verifier" not in tx,
    "transaction validation regressed to no-context verifier",
)


# Generic envelope replay/expiry state must be enforced, not merely signed.
require(
    "pub struct AuthorizationValidationContext" in pq,
    "authorization state validation context missing",
)
require(
    "validate_in_context" in pq
    and "authorization chain mismatch" in pq
    and "authorization epoch mismatch" in pq
    and "authorization nonce mismatch" in pq
    and "authorization expired" in pq,
    "authorization chain/epoch/nonce/expiry checks missing",
)


require(
    "expected_domain" in pq and "expected_policy" in pq,
    "generic authorization verifier must enforce expected domain and policy",
)
require(
    "required_policy" in tx and "PolicyMismatch" in tx,
    "transaction verifier must enforce caller-required policy",
)


require(
    "expected_public_key_bytes" in pq and "expected_signature_bytes" in pq,
    "HybridAuthorization must enforce protocol PQ evidence sizes",
)


require(
    "validate_for_policy" in network
    and "transcript_hash == [0u8; 32]" in network
    and "pub struct MlKemSharedSecret([u8; ML_KEM_SHARED_SECRET_BYTES]);" in network
    and "MlKemSharedSecret::try_from_slice" in network,
    "transport ML-KEM/transcript validation regressed",
)
require(
    ".encapsulate()" not in pq_ref.split("\n#[cfg(test)]\nmod tests", 1)[0]
    and "encapsulate_deterministic" in pq_ref,
    "production ML-KEM encapsulation must remain fallible and deterministic-from-randomness",
)


require(
    'pub struct MlKemSharedSecret([u8; ML_KEM_SHARED_SECRET_BYTES]);' in network
    and 'impl Drop for MlKemSharedSecret' in network
    and 'self.0.zeroize();' in network,
    "ML-KEM shared secret must remain opaque and zeroize on drop",
)
require(
    'pub struct SecretBytes(Vec<u8>);' in network
    and 'impl Drop for SecretBytes' in network,
    "classical secret bytes must remain opaque and zeroize on drop",
)
require(
    'pub struct HybridSharedSecret' in network
    and '#[derive(PartialEq, Eq)]\npub struct HybridSharedSecret' not in network
    and 'pq_shared: MlKemSharedSecret' in network
    and 'classical_shared: Option<SecretBytes>' in network,
    "HybridSharedSecret must contain typed secret wrappers and remain non-Clone",
)
require(
    'field("pq_shared", &"<redacted>")' in network
    and 'field("classical_shared", &"<redacted>")' in network
    and 'MlKemSharedSecret(<redacted>)' in network
    and 'SecretBytes(<redacted>)' in network,
    "HybridSharedSecret Debug must remain redacted",
)


require(
    "MAX_REKEY_MESSAGES: u64 = 1 << 20" in network
    and "MAX_REKEY_SECONDS: u64 = 300" in network
    and "pub fn should_rekey" in network
    and "self.validate().is_err()" in network,
    "transport rekey policy must remain bounded and fail closed",
)
require(
    "Option<(Vec<u8>, MlKemSharedSecret)>" in network
    and "Option<MlKemSharedSecret>" in network,
    "ML-KEM provider must return typed zeroizing shared secrets",
)

require(
    '#[derive(PartialEq, Eq)]\npub struct MlKemSharedSecret' not in network
    and '#[derive(PartialEq, Eq)]\npub struct SecretBytes' not in network,
    "secret-bearing transport types must not expose ordinary equality",
)
require(
    'zeroize::Zeroize::zeroize(&mut randomness_bytes);' in pq_ref
    and 'zeroize::Zeroize::zeroize(&mut randomness);' in pq_ref
    and 'zeroize::Zeroize::zeroize(&mut shared);' in pq_ref,
    "ML-KEM entropy/shared temporary copies must be explicitly zeroized",
)


require(
    '#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]\npub struct PqSigningKeyHandle' not in pq
    and 'impl Drop for PqSigningKeyHandle' in pq
    and 'zeroize::Zeroize::zeroize(&mut self.0);' in pq,
    "signing capability handles must remain non-Copy and zeroizing",
)
require(
    '#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]\npub struct MlKemSecretHandle' not in pq_ref
    and 'impl Drop for MlKemSecretHandle' in pq_ref,
    "ML-KEM capability handles must remain non-Copy and zeroizing",
)

require(
    "SECP256K1_PUBLIC_KEY_BYTES: usize = 33" in pq
    and "SECP256K1_SIGNATURE_BYTES: usize = 65" in pq
    and "ED25519_PUBLIC_KEY_BYTES: usize = 32" in pq
    and "ED25519_SIGNATURE_BYTES: usize = 64" in pq
    and "MAX_AUTHORIZATION_EVIDENCE_BYTES: usize = 40_000" in pq,
    "canonical classical authorization encodings missing or changed",
)



require(
    'pub struct TransportTranscript' in network
    and 'TRANSPORT_TRANSCRIPT_DOMAIN' in network
    and 'pub fn commitment(&self) -> Option<[u8; 32]>' in network
    and 'Sha256::new()' in network,
    "canonical transport transcript commitment missing",
)
require(
    'policy: TransportPolicy' in network
    and 'secret.policy() != policy' in network,
    "established shared secret must remain bound to transport policy",
)
require(
    "pub enum ClassicalKexScheme" in network
    and "X25519_PUBLIC_KEY_BYTES: usize = 32" in network
    and "SECP256K1_KEX_PUBLIC_KEY_BYTES: usize = 33" in network
    and "classical KEX public key length mismatch" in network
    and "PQ-only transport forbids classical KEX material" in network
    and "CLASSICAL_SHARED_SECRET_BYTES: usize = 32" in network,
    "explicit classical KEX registry or exact transport bounds missing",
)

require(
    "transcript_hash: [u8; 32]" in network
    and "pub transcript_hash: [u8; 32]" not in network
    and "pub fn transcript_hash(&self) -> &[u8; 32]" in network
    and "if transcript_hash == [0u8; 32]" in network,
    "transport transcript commitment must be immutable and fail closed",
)

require(
    "context.now >= self.expires_at" in pq
    and "context.now >= self.authorization_expires_at" in tx,
    "authorization expiry must be exclusive at the expiry instant",
)


require(
    'CRYPTO_PROFILE_VERSION: u16 = 1' in pq
    and 'CRYPTO_PROFILE_VERSION.to_be_bytes()' in pq
    and 'crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes()' in network,
    "crypto profile version must remain bound into authorization and transport domains",
)

require(
    'channel = "1.85.0"' in toolchain
    and 'components = ["rustfmt", "clippy"]' in toolchain,
    "repository Rust toolchain pin missing or changed",
)

require(
    'actions/checkout@11d5960a326750d5838078e36cf38b85af677262' in workflow
    and 'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02' in workflow
    and 'actions/checkout@v4' not in workflow
    and 'actions/upload-artifact@v4' not in workflow
    and 'timeout-minutes: 45' in workflow,
    "GitHub Actions supply-chain pins missing or mutable",
)

require(
    'git dependency forbidden in M2 locked graph' in lock_policy
    and 'registry package lacks a 64-hex checksum' in lock_policy
    and '"ml-kem": "0.3.2"' in lock_policy
    and '"ml-dsa": "0.1.1"' in lock_policy
    and '"slh-dsa": "0.1.0"' in lock_policy,
    "locked supply-chain verification policy missing",
)

require(
    "max_future_seconds" in pq
    and "authorization expiry exceeds policy horizon" in pq
    and "max_authorization_future_seconds" in tx,
    "authorization lifetime horizon policy missing",
)

require(
    "authorization evidence order is noncanonical" in pq
    and "append_policy_suite" in pq
    and "scheme.protocol_code()" in pq,
    "ordered authorization algorithm suite binding missing",
)

require(
    "MAX_TX_CALLDATA_BYTES: usize = 1_048_576" in tx
    and "context.max_calldata_bytes > MAX_TX_CALLDATA_BYTES" in tx,
    "transaction protocol calldata ceiling missing",
)


require(
    "secp256k1 public key must use compressed encoding" in pq
    and "secp256k1 signature recovery id must be canonical" in pq
    and "authorization evidence must not be all-zero" in pq,
    "canonical classical evidence prefilter missing",
)

require(
    "ML_KEM_1024_PROTOCOL_CODE: u8 = 1" in network
    and "hasher.update([ML_KEM_1024_PROTOCOL_CODE])" in network,
    "transport ML-KEM algorithm code binding missing",
)

require(
    "CRYPTO_PROFILE_VERSION.to_be_bytes()" in tx
    and "AuthorizationDomain::Transaction.protocol_code()" in tx
    and "self.authorization.policy.required_schemes()" in tx,
    "classical transaction preimage lacks crypto profile or suite binding",
)

require(
    "[profile.release]" in cargo
    and "overflow-checks = true" in cargo,
    "release profile must retain overflow checks for consensus determinism",
)

require(
    "CLASSICAL_SHARED_SECRET_BYTES: usize = 32" in network
    and "secret.len() != CLASSICAL_SHARED_SECRET_BYTES" in network
    and "shared.len() == CLASSICAL_SHARED_SECRET_BYTES" in network,
    "classical shared-secret length must remain exact",
)

require(
    "persist-credentials: false" in workflow
    and "-D warnings -D clippy::all" in workflow
    and "cargo test --locked --doc --features reference-pq" in workflow
    and "cargo test --locked --release --lib --features reference-pq" in workflow,
    "hardened executable CI gates missing",
)


require(
    "#![forbid(unsafe_code)]" in (ROOT / "src/lib_v2.rs").read_text(encoding="utf-8"),
    "crate must continue to forbid unsafe code",
)

require(
    "#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]\npub struct PqSigningKeyHandle" not in pq
    and "#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]\npub struct MlKemSecretHandle" not in pq_ref
    and "struct InternalCapabilityId([u8; 32]);" in pq_ref
    and "impl Drop for InternalCapabilityId" in pq_ref,
    "capability handles or internal IDs regressed to clonable/non-zeroizing form",
)

require(
    "ML-KEM-1024 public key must not be all-zero" in network
    and "classical KEX public key must not be all-zero" in network
    and "secp256k1 KEX public key must use compressed encoding" in network,
    "transport advertised-key structural prefilter missing",
)

require(
    "m2-cargo-metadata-core.json" in workflow
    and "m2-cargo-metadata-reference-pq.json" in workflow
    and "m2-spdx-core.json" in workflow
    and "m2-spdx-reference-pq.json" in workflow
    and "--features reference-pq > m2-cargo-metadata-reference-pq.json" in workflow,
    "core/reference-pq resolved evidence must remain separated",
)

require(
    "unexpected features enabled for" in lock_policy
    and '("ml-kem", "0.3.2"): {"getrandom", "zeroize"}' in lock_policy
    and '("ml-dsa", "0.1.1"): {"alloc", "getrandom", "zeroize"}' in lock_policy
    and '("slh-dsa", "0.1.0"): {"alloc", "default"}' in lock_policy,
    "critical crypto feature allowlist missing",
)

print("M2 static guard: PASS")
