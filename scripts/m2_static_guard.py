#!/usr/bin/env python3
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]

def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"M2 static guard failed: {message}")

cargo = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
pq = (ROOT / "src/pq.rs").read_text(encoding="utf-8")
lib_v2 = (ROOT / "src/lib_v2.rs").read_text(encoding="utf-8")
pq_sol = (ROOT / "contracts/IPQVerifier.sol").read_text(encoding="utf-8")
smart_account_sol = (ROOT / "contracts/PQSmartAccount.sol").read_text(encoding="utf-8")
nexus_sol = (ROOT / "contracts/INexusAI.sol").read_text(encoding="utf-8")
pq_ref = (ROOT / "src/pq_reference.rs").read_text(encoding="utf-8")
network = (ROOT / "src/network.rs").read_text(encoding="utf-8")
tx = (ROOT / "src/tx.rs").read_text(encoding="utf-8")
workflow = (ROOT / ".github/workflows/pq-evm-ci.yml").read_text(encoding="utf-8")
toolchain = (ROOT / "rust-toolchain.toml").read_text(encoding="utf-8")
lock_policy = (ROOT / "scripts/m2_verify_lock.py").read_text(encoding="utf-8")
fixture_manifest = (ROOT / "tests/vectors/M2_FIXTURE_MANIFEST.json").read_text(encoding="utf-8")
fixture_verifier = (ROOT / "scripts/m2_verify_fixture_manifest.py").read_text(encoding="utf-8")
spdx_generator = (ROOT / "scripts/m2_spdx_from_cargo_metadata.py").read_text(encoding="utf-8")
validator = (ROOT / "src/validator.rs").read_text(encoding="utf-8")
migration = (ROOT / "src/migration.rs").read_text(encoding="utf-8")
model_shard = (ROOT / "src/model_shard.rs").read_text(encoding="utf-8")
inference = (ROOT / "src/inference.rs").read_text(encoding="utf-8")
governance = (ROOT / "src/governance.rs").read_text(encoding="utf-8")
verification = (ROOT / "src/verification.rs").read_text(encoding="utf-8")
consensus = (ROOT / "src/consensus.rs").read_text(encoding="utf-8")
service_planes = (ROOT / "src/service_planes.rs").read_text(encoding="utf-8")
autopilot = (ROOT / "src/autopilot.rs").read_text(encoding="utf-8")
autopilot_budget = (ROOT / "src/autopilot_budget.rs").read_text(encoding="utf-8")
autopilot_execution_lease = (ROOT / "src/autopilot_execution_lease.rs").read_text(encoding="utf-8")
payments = (ROOT / "src/payments.rs").read_text(encoding="utf-8")
payment_funding = (ROOT / "src/payment_funding.rs").read_text(encoding="utf-8")
storage = (ROOT / "src/storage.rs").read_text(encoding="utf-8")
cognitive = (ROOT / "src/cognitive.rs").read_text(encoding="utf-8")
cognitive_registry = (ROOT / "src/cognitive_registry.rs").read_text(encoding="utf-8")
nexus = (ROOT / "src/nexus.rs").read_text(encoding="utf-8")
kv_cache = (ROOT / "src/kv_cache.rs").read_text(encoding="utf-8")

# Reproducibility / MSRV invariants.
require('rust-version = "1.85"' in cargo, "crate rust-version must stay pinned to 1.85")
for exact in (
    'ml-kem = { version = "=0.3.2"',
    'ml-dsa = { version = "=0.1.1"',
    'slh-dsa = { version = "=0.1.0"',
    'rand = { version = "=0.8.5"',
    'zeroize = { version = "=1.8.1"',
    'sha2 = { version = "=0.10.9"',
    'hkdf = { version = "=0.12.4"',
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
    and "MAX_AUTHORIZATION_EVIDENCE_BYTES: usize =" in pq
    and "SLH_DSA_SHAKE_256S_SIGNATURE_BYTES;" in pq,
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
    and "cargo test --frozen --doc --features reference-pq" in workflow
    and "cargo test --frozen --release --lib --features reference-pq" in workflow,
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
    and '("slh-dsa", "0.1.0"): {"alloc"}' in lock_policy
    and '("rand", "0.8.5"): {"getrandom"}' in lock_policy,
    "critical crypto feature allowlist missing",
)

require(
    "assert_eq!(MAX_AUTHORIZATION_EVIDENCE_BYTES, 37_173);" in pq,
    "authorization byte budget must equal the exact MAX-policy suite size",
)


require(
    "pub rekey_policy: RekeyPolicy" in network
    and "self.rekey_policy.validate()?" in network
    and "hasher.update(self.rekey_policy.max_messages.to_be_bytes())" in network
    and "hasher.update(self.rekey_policy.max_seconds.to_be_bytes())" in network
    and "pub fn should_rekey(&self, messages_since_rekey: u64, seconds_since_rekey: u64)" in network,
    "transport transcript must bind and enforce rekey policy",
)


require(
    "pub enum TransportRole" in network
    and "pub ml_kem_recipient: TransportRole" in network
    and "hasher.update([self.ml_kem_recipient.protocol_code()])" in network
    and "hybrid transport peers must agree on classical KEX scheme" in network
    and "transport peers must use distinct ML-KEM public keys" in network
    and "hybrid transport peers must use distinct classical KEX public keys" in network,
    "transport role/KEX agreement binding missing",
)


require(
    "pub struct TransportValidationContext" in network
    and "pub network_id: [u8; 32]" in network
    and "pub epoch: u64" in network
    and "pub session_id: [u8; 32]" in network
    and "transport network mismatch" in network
    and "transport epoch mismatch" in network
    and "transport session mismatch" in network
    and "commitment_in_context" in network,
    "transport network/epoch/session anti-replay binding missing",
)

require(
    "transcript.commitment_in_context(validation)?" in network,
    "shared secret construction must require state-aware transcript validation",
)


require(
    "pub trait TransportReplayGuard" in network
    and "pub fn establish_shared_secret" in network
    and "pub(crate) fn from_transcript" in network
    and "replay_guard.consume_session" in network,
    "one-shot transport replay guard boundary missing",
)


require(
    "pub struct TransportSessionKey([u8; TRANSPORT_SESSION_KEY_BYTES]);" in network
    and "impl Drop for TransportSessionKey" in network
    and "TransportSessionKey(<redacted>)" in network
    and "pub fn derive_transport_session_key" in network
    and "Hkdf::<Sha256>::new(Some(secret.transcript_hash()), &ikm)" in network
    and "ikm.zeroize();" in network,
    "transcript-bound zeroizing HKDF transport session key missing",
)

require(
    '"hkdf": "0.12.4"' in lock_policy
    and '("hkdf", "0.12.4"): set()' in lock_policy,
    "HKDF exact lock/feature policy missing",
)


require(
    "pub struct InMemoryTransportReplayGuard" in network
    and "MAX_TRANSPORT_SESSIONS_PER_EPOCH: usize = 65_536" in network
    and "consumed: BTreeSet<[u8; 32]>" in network
    and "if new_epoch <= self.epoch" in network
    and "self.consumed.len() >= MAX_TRANSPORT_SESSIONS_PER_EPOCH" in network,
    "bounded monotonic reference replay guard missing",
)


require(
    "ALLOWED_REGISTRIES" in lock_policy
    and "non-crates.io registry forbidden in M2 graph" in lock_policy
    and "unexpected local/path package in locked graph" in lock_policy,
    "locked dependency source allowlist missing",
)

require(
    "cargo fetch --locked" in workflow
    and 'CARGO_NET_OFFLINE=true' in workflow
    and "cargo check --frozen --all-targets" in workflow
    and "cargo test --frozen --all-targets --features reference-pq" in workflow
    and "cargo test --frozen --release --lib --features reference-pq" in workflow,
    "post-fetch offline/frozen Cargo gates missing",
)

require(
    "m2-build-environment.txt" in workflow
    and "m2-evidence-sha256.txt" in workflow
    and "sha256sum" in workflow
    and "git_commit=$(git rev-parse HEAD)" in workflow,
    "tamper-evident M2 evidence manifest missing",
)

require(
    "7cedd002de19f032b45bdde3d99eef89eb9b12b30bbfbcf9e66740c060b297e8" in network
    and "c1bfa4aaaf544e95235f01fbdb40f392eb8d4869183f221713d05f2da8568890" in network
    and "f1a8e0660f99db442f1e56becc05a1ae6e4dd18d14ede6233eefce9e5009ba16" in pq
    and "fb28450c0d70acfa64a0c5c04e963eb6bcf20661105431f6d244691162c0f8d5" in pq,
    "independent authorization/transport known-answer vectors missing",
)

require(
    "let expand_result = hkdf.expand(&info, &mut output);" in network
    and "drop(hkdf);" in network,
    "HKDF state lifetime must remain one-shot and explicitly minimized",
)


require(
    "verify_envelope_authorization" in validator
    and "AuthorizationDomain::ValidatorVote" in validator
    and "expected_policy: policy.authorization_policy()" in validator
    and "PQ-only validator forbids legacy public key material" in validator,
    "validator votes must remain state-aware PQ-authorized and PQ-only identities classical-free",
)

require(
    "verify_envelope_authorization" in migration
    and "AuthorizationDomain::BridgeMigration" in migration
    and "binding.authorization.policy != AuthPolicy::PqOnly" in migration
    and "legacy.verify_legacy_ownership" in migration,
    "bridge migration must require legacy ownership plus state-aware dual-PQ authorization",
)

require(
    "verify_envelope_authorization" in model_shard
    and "AuthorizationDomain::ModelUpgrade" in model_shard
    and "upgrade.authorization.policy != AuthPolicy::Max" in model_shard
    and "duplicate created shard index" in model_shard
    and "created shard parent was not consumed by transition" in model_shard,
    "model lineage upgrades must remain MAX-authorized and lineage-closed",
)


require(
    "verify_envelope_authorization" in inference
    and "AuthorizationDomain::InferenceReceipt" in inference
    and "authorized.authorization.policy != AuthPolicy::PqOnly" in inference
    and "expected_worker_id" in inference
    and "authorization_commitment" in inference,
    "inference receipts must remain state-aware PQ-only authorized",
)


require(
    "verify_envelope_authorization" in governance
    and "AuthorizationDomain::Governance" in governance
    and "authorized.authorization.policy != AuthPolicy::Max" in governance
    and "expected_governance_state_root" in governance
    and "expected_proposal_id" in governance,
    "governance actions must remain state-root-bound MAX-authorized transitions",
)


require(
    "pub fn keyset_commitment(&self) -> Option<[u8; 32]>" in pq
    and "SYNERGY/PQ-AUTH-KEYSET/V1" in pq,
    "canonical authorization keyset identity commitment missing",
)

require(
    "self.authorization.primary_account_identity_commitment() != Some(self.sender_account)" in tx,
    "transaction sender account must remain bound to stable primary PQ identity",
)

require(
    "binding.authorization.keyset_commitment()" in migration
    and "Some(binding.binding.pq_identity_commitment)" in migration
    and "binding.authorization.primary_account_identity_commitment()" in migration
    and "Some(binding.binding.synergy_account_id)" in migration,
    "migration must bind stable account identity separately from full PQ authority keyset",
)

require(
    "expected_worker_keyset_commitment" in inference
    and "authorized.authorization.keyset_commitment()" in inference,
    "inference worker identity must remain bound to registered keyset",
)

require(
    "expected_authority_keyset_commitment" in governance
    and "authorized.authorization.keyset_commitment()" in governance
    and "expected_activation_epoch" in governance,
    "governance authority/activation state binding missing",
)

require(
    "expected_authority_keyset_commitment" in model_shard
    and "upgrade.authorization.keyset_commitment()" in model_shard
    and "expected_activation_epoch" in model_shard
    and "created shard parent was not consumed by transition" in model_shard,
    "model upgrade authority/activation/lineage binding missing",
)

require(
    "pub fn pq_identity_commitment(&self) -> Option<[u8; 32]>" in validator
    and "validator id does not match PQ identity commitment" in validator
    and "PQ-only validator forbids legacy public key material" in validator,
    "validator ID must remain stable PQ-key identity commitment",
)


require(
    "pub fn authorization_keyset_commitment<'a, I>" in pq
    and "IntoIterator<Item = (AuthScheme, &'a [u8])>" in pq
    and "authorization_keyset_commitment(" in pq,
    "signature-independent allocation-free keyset registration primitive missing",
)


require(
    "canonical_receipt_set" in verification
    and "verifier receipts must be strictly ordered and unique" in verification
    and "verification aggregate does not match canonical receipt set" in verification
    and "pub fn validate_receipts" in verification,
    "AI verification aggregate must remain bound to canonical unique verifier receipts",
)


require(
    "AuthorizationDomain::VerificationReceipt" in verification
    and "verify_envelope_authorization" in verification
    and "authorized.authorization.policy != AuthPolicy::PqOnly" in verification
    and "expected_verifier_keyset_commitment" in verification
    and "pub fn verify_verifier_receipt" in verification,
    "verifier receipts must remain state-aware PQ-only authorized",
)


require(
    "VerificationReceipt" in pq
    and "Self::VerificationReceipt => 7" in pq,
    "verification receipt authorization domain code missing or changed",
)


require(
    "SECP256K1_HALF_ORDER" in pq
    and "is_canonical_secp256k1_signature" in pq
    and "secp256k1 signature must use canonical low-S encoding" in pq,
    "secp256k1 low-S canonicality gate missing",
)

require(
    "synergy-m2-fixture-manifest-v1" in fixture_manifest
    and "git_blob_sha1" in fixture_manifest
    and "M2 fixture manifest: PASS" in fixture_verifier
    and "python3 scripts/m2_verify_fixture_manifest.py" in workflow,
    "tamper-evident local PQ fixture gate missing",
)

require(
    "unexpected crate features are not covered by M2 CI" in lock_policy
    and "default feature set must remain empty for consensus core" in lock_policy,
    "Cargo feature-surface policy missing",
)

require(
    "Cargo.lock" in spdx_generator
    and '"checksums"' in spdx_generator
    and "Cargo.lock source" in spdx_generator,
    "SPDX output must remain bound to locked package checksums/sources",
)


require(
    "pub fn primary_account_identity_commitment(" in pq
    and "SYNERGY/PQ-PRIMARY-ACCOUNT/V1" in pq
    and "primary_account_identity_is_stable_across_authorization_policies" in pq,
    "policy-independent stable account identity primitive missing",
)


require(
    "AuthorizationDomain::ConsensusActivation" in consensus
    and "authorized.authorization.policy != AuthPolicy::Max" in consensus
    and "expected_activation_block" in consensus
    and "expected_authority_keyset_commitment" in consensus
    and "authorization_commitment" in consensus,
    "consensus activation must remain MAX-authorized and authority-bound",
)

require(
    "AuthorizationDomain::ServicePlaneCheckpoint" in service_planes
    and "authorized.authorization.policy != AuthPolicy::Max" in service_planes
    and "expected_service_plane_epoch" in service_planes
    and "expected_authority_keyset_commitment" in service_planes
    and "authorization_commitment" in service_planes,
    "service-plane checkpoints must remain MAX-authorized and authority-bound",
)

require(
    "Self::ConsensusActivation => 8" in pq
    and "Self::ServicePlaneCheckpoint => 9" in pq,
    "consensus/service authorization domain codes missing or changed",
)


require(
    "current_block" in consensus
    and "min_activation_delay_blocks" in consensus
    and "checked_add(validation.min_activation_delay_blocks)" in consensus
    and "validation.min_activation_delay_blocks == 0" in consensus,
    "consensus activation must reject retroactive/zero-delay activation",
)

require(
    "current_service_plane_epoch" in service_planes
    and "checked_add(1)" in service_planes
    and "validation.expected_service_plane_epoch != next_epoch" in service_planes,
    "service-plane checkpoint epochs must remain strictly monotonic",
)


require(
    "AuthorizationDomain::AutopilotExecution" in autopilot_budget
    and "authorized.authorization.policy != AuthPolicy::Max" in autopilot_budget
    and "expected_owner_account" in autopilot_budget
    and "expected_reservation_root" in autopilot_budget
    and "expected_policy_root" in autopilot_budget
    and "now >= self.expires_at" in autopilot_budget,
    "Autopilot value-bearing execution must remain MAX-authorized and expiry-bound",
)

require(
    "Self::AutopilotExecution => 10" in pq,
    "Autopilot authorization domain code missing or changed",
)


require(
    "AuthorizationDomain::PaymentIntent" in payments
    and "authorized.authorization.keyset_commitment() != Some(authorized.intent.payer)" in payments
    and "required_policy" in payments
    and "authorization_commitment" in payments,
    "payment intents must remain payer-keyset-bound and state-aware",
)

require(
    "AuthorizationDomain::SettlementBatch" in payments
    and "authorized.authorization.policy != AuthPolicy::PqOnly" in payments
    and "expected_lane_authority_keyset_commitment" in payments
    and "expected_sequence" in payments,
    "settlement batches must remain PQ-authorized by registered lane authority",
)

require(
    "validate_against_intent" in payment_funding
    and "funding reservation payment intent root mismatch" in payment_funding
    and "funding reservation amount/intention mismatch" in payment_funding,
    "funding reservations must remain bound to canonical payment intent",
)

require(
    "Self::PaymentIntent => 11" in pq
    and "Self::SettlementBatch => 12" in pq,
    "payment authorization domain codes missing or changed",
)


require(
    "pub fn validate_against_intent(" in payment_funding
    and "reservation.validate_against_intent(intent, now)?" in payment_funding
    and "self.validate_against(reservation)" in payment_funding,
    "funding consumption must recheck canonical payment intent and expiry",
)


require(
    "AuthorizationDomain::StorageProof" in storage
    and "authorized.authorization.policy != AuthPolicy::PqOnly" in storage
    and "expected_provider_keyset_commitment" in storage
    and "expected_provider_id" in storage
    and "authorization_commitment" in storage,
    "storage proofs must remain PQ-authorized by registered provider keysets",
)

require(
    "AuthorizationDomain::CognitiveEvidence" in cognitive
    and "authorized.authorization.policy != AuthPolicy::PqOnly" in cognitive
    and "node.pq_identity_commitment" in cognitive
    and "authorized.authorization.keyset_commitment()" in cognitive
    and "authorization_commitment" in cognitive,
    "CognitiveNode evidence must remain PQ-authorized by registered node identity",
)

require(
    "Self::StorageProof => 13" in pq
    and "Self::CognitiveEvidence => 14" in pq,
    "storage/cognitive authorization domain codes missing or changed",
)


require(
    "pub(crate) fn validate_against(" in payment_funding
    and "pub fn validate_against_intent(" in payment_funding,
    "reservation-only funding consumption validator must remain crate-internal",
)

for name, source in (
    ("payments", payments),
    ("payment_funding", payment_funding),
    ("storage", storage),
    ("cognitive", cognitive),
    ("service_planes", service_planes),
    ("autopilot_budget", autopilot_budget),
):
    require(
        source.startswith("//!"),
        f"{name} inner module docs must precede all Rust items",
    )


require(
    "u64::try_from(input_bytes).ok()?" in consensus
    and "u64::try_from(output_bytes).ok()?" in consensus
    and "u64::try_from(nodes).ok()?" in consensus,
    "consensus gas accounting must use checked architecture-safe size conversion",
)

require(
    "pub fn archive_to_raw_bps(&self) -> Option<u64>" in storage
    and "pub fn unique_to_logical_bps(&self) -> Option<u64>" in storage
    and "u64::try_from(ratio).ok()" in storage,
    "storage ratio conversion must remain fail-closed and non-truncating",
)

require(
    "u64::try_from(self.consumed_shards.len()).ok()?" in model_shard
    and "u64::try_from(self.created_shards.len()).ok()?" in model_shard,
    "model lineage vector lengths must remain architecture-safe in canonical serialization",
)


require(
    "fn put_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) -> Option<()>" in network
    and "u64::try_from(bytes.len()).ok()?" in network,
    "transport transcript length prefixes must remain fallible and architecture-safe",
)

require(
    "MAX_INFERENCE_STAGES: usize = 65_536" in inference
    and "self.stages.len() > MAX_INFERENCE_STAGES" in inference
    and "u32::try_from(i)" in inference,
    "inference execution plans must remain bounded with checked stage indexes",
)

require(
    "pub fn signing_preimage(&self) -> Option<Vec<u8>>" in tx
    and "u64::try_from(field.len()).ok()?" in tx
    and "u8::try_from(schemes.len()).ok()?" in tx
    and "self.data.len() > MAX_TX_CALLDATA_BYTES" in tx,
    "canonical transaction encoding must remain fallible and protocol-bounded",
)


require(
    "current_sequence" in payments
    and "checked_add(1)" in payments
    and "validation.expected_sequence != next_sequence" in payments,
    "settlement lane sequence must remain strictly monotonic",
)

require(
    "pub fn validate(&self) -> Result<(), &'static str>" in autopilot
    and "Autopilot policy contains duplicate capability" in autopilot
    and "Autopilot per-action limit exceeds epoch limit" in autopilot
    and "now < self.valid_until" in autopilot
    and "proposal outlives Autopilot policy" in autopilot,
    "Autopilot delegated policy semantics must remain fail closed",
)

require(
    "checked_mul(10_000)?" in service_planes
    and "u64::try_from(value).ok()" in service_planes,
    "service-plane capacity ratio must remain checked and non-saturating",
)


require(
    'slh-dsa = { version = "=0.1.0", optional = true, default-features = false, features = ["alloc"] }' in cargo
    and 'rand = { version = "=0.8.5", optional = true, default-features = false, features = ["getrandom"] }' in cargo,
    "SLH-DSA/rand feature surface must remain explicit and minimal",
)


require(
    "pub owner_account: [u8; 32]" in autopilot_budget
    and "reservation.owner_account != validation.expected_owner_account" in autopilot_budget
    and "authorized.authorization.keyset_commitment() != Some(reservation.owner_account)" in autopilot_budget
    and "hasher.update(reservation.owner_account)" in autopilot_budget,
    "Autopilot budget reservation ownership must remain keyset-bound",
)


require(
    "pub struct AuthorizationReplayState" in pq
    and "pub fn verify_and_consume" in pq
    and "self.next_nonce.checked_add(1)" in pq
    and "self.next_nonce = advanced_nonce" in pq
    and "pub fn rotate_epoch" in pq
    and "if new_epoch <= self.epoch" in pq,
    "authorization replay state must consume nonce exactly once and rotate epoch forward only",
)


reference_prod = pq_ref.split("\n#[cfg(test)]\nmod tests", 1)[0]
require(
    "SigningKey::<MlDsa87>::try_generate().ok()?" in reference_prod
    and "if scheme != AuthScheme::MlDsa87" in reference_prod
    and "SigningKey<Shake256s>" not in reference_prod
    and "SigningKey::<Shake256s>" not in reference_prod,
    "reference signer must remain ML-DSA-only; stable SLH signing is external-provider-only",
)


require(
    "pub const fn active_in_crypto_profile_v1" in pq
    and "Self::Secp256k1 | Self::MlDsa87 | Self::SlhDsaShake256s" in pq
    and "crypto_profile_v1_keeps_ed25519_reserved_but_inactive" in pq,
    "Ed25519 must remain reserved/inactive in crypto profile v1",
)


require(
    "MAX_AUTHORIZATION_LIFETIME_SECONDS: u64 = 86_400" in pq
    and "max_lifetime_seconds" in pq
    and "authorization lifetime policy exceeds protocol ceiling" in pq
    and "AuthorizationDomain::Transaction.max_lifetime_seconds()" in tx,
    "authorization lifetime must remain bounded by protocol, not caller policy",
)


for name, source, stateless, consuming in (
    ("governance", governance, "verify_governance_action", "verify_governance_action_and_consume"),
    ("consensus", consensus, "verify_consensus_activation", "verify_consensus_activation_and_consume"),
    ("service_planes", service_planes, "verify_service_plane_checkpoint", "verify_service_plane_checkpoint_and_consume"),
    ("autopilot_budget", autopilot_budget, "verify_autopilot_execution", "verify_autopilot_execution_and_consume"),
    ("payments-intent", payments, "verify_payment_intent", "verify_payment_intent_and_consume"),
    ("payments-settlement", payments, "verify_settlement_batch", "verify_settlement_batch_and_consume"),
    ("storage", storage, "verify_storage_proof", "verify_storage_proof_and_consume"),
    ("cognitive", cognitive, "verify_cognitive_evidence", "verify_cognitive_evidence_and_consume"),
    ("inference", inference, "verify_inference_receipt", "verify_inference_receipt_and_consume"),
    ("verification", verification, "verify_verifier_receipt", "verify_verifier_receipt_and_consume"),
    ("model_shard", model_shard, "verify_model_upgrade", "verify_model_upgrade_and_consume"),
    ("migration", migration, "verify_binding", "verify_binding_and_consume"),
    ("validator", validator, "verify_validator_vote", "verify_validator_vote_and_consume"),
):
    if name == "autopilot_budget":
        require(
            f"pub(crate) fn {stateless}" in source
            and f"pub(crate) fn {consuming}" in source
            and "replay.consume_verified" in source,
            "Autopilot raw consuming verifier must remain crate-internal behind execution lease",
        )
    else:
        require(
            f"pub(crate) fn {stateless}" in source
            and f"pub fn {consuming}" in source
            and "replay.consume_verified" in source,
            f"{name} privileged API must expose replay-consuming verification only",
        )


require(
    "Committed Cargo.lock gate" in workflow
    and "git ls-files --error-unmatch Cargo.lock" in workflow
    and "git diff --exit-code -- Cargo.lock" in workflow,
    "CI must fail closed when Cargo.lock is generated but not committed",
)

require(
    "rustup=$(rustup --version" in workflow
    and "m2-build-environment.txt" in workflow,
    "reproducibility evidence must record rustup bootstrap version",
)

require(
    "pub fn validate(&self) -> Result<(), NexusError>" in nexus
    and "self.nodes == 0" in nexus
    and "request.mode != NexusMode::Score" in nexus
    and "NexusError::UnsupportedMode" in nexus
    and "fn qadd_saturating" in nexus
    and ".expect(" not in nexus.split("\n#[cfg(test)]\nmod tests", 1)[0],
    "NEXUS v1 must reject invalid manifests/modes and keep production arithmetic panic-free",
)

require(
    "u64::try_from(self.legacy_identifier.len()).ok()?" in migration
    and "u64::try_from(self.ml_dsa87_public_key.len()).ok()?" in validator
    and "u64::try_from(self.slh_dsa_shake256s_public_key.len()).ok()?" in validator
    and "u64::try_from(receipts.len())" in verification,
    "canonical privileged serialization must remain architecture-safe",
)


require(
    "graph_sha256 = hashlib.sha256(lock_bytes + b\"\\0\" + canonical_graph).hexdigest()" in spdx_generator
    and "resolved_ids = {node.get(\"id\") for node in nodes if node.get(\"id\")}" in spdx_generator
    and "unresolved/disabled package leaked into SBOM" in spdx_generator
    and "https://crates.io/api/v1/crates/" in spdx_generator,
    "SPDX generation must be path-independent and resolved-graph-only",
)


require(
    '"sha256"' in fixture_manifest
    and "hashlib.sha256(data).hexdigest()" in fixture_verifier
    and "unexpected/unmanifested JSON fixture inventory" in fixture_verifier,
    "PQ fixture manifest must verify SHA-256 and complete JSON inventory",
)

require(
    "ml_kem_rejects_correct_length_noncanonical_public_key" in pq_ref
    and "public_key[0] = 0xff" in pq_ref
    and "public_key[1] = (public_key[1] & 0xf0) | 0x0f" in pq_ref,
    "ML-KEM regression must reject correct-length noncanonical modulus encoding",
)


require(
    "Self::KvReplicaReceipt => 15" in pq
    and "MAX_KV_REPLICAS: usize = 32" in kv_cache
    and "pub(crate) fn verify_kv_replica_receipt" in kv_cache
    and "pub fn verify_kv_replica_receipt_and_consume" in kv_cache
    and "AuthorizationDomain::KvReplicaReceipt" in kv_cache
    and "expected_worker_keyset_commitment" in kv_cache
    and "replay.consume_verified" in kv_cache,
    "KV-cache replica evidence must remain PQ-authorized, bounded and replay-consuming",
)


require(
    "pub(crate) fn independent_prefix_count" in cognitive_registry
    and "pub fn independent_registered_count" in cognitive_registry
    and "ordered.sort_by_key(|(node, _)| node.node_id)" in cognitive_registry
    and "duplicate cognitive node id" in cognitive_registry,
    "economic cognitive quorum must validate registry state and canonicalize ordering",
)

require(
    "cognitive node validity window invalid" in cognitive
    and "self.valid_until_epoch < self.valid_from_epoch" in cognitive,
    "CognitiveNode manifest validity window must remain explicit and fail closed",
)

require(
    "kv lease expiry required" in kv_cache
    and "self.expires_at == 0" in kv_cache,
    "KV-cache leases must require nonzero expiry",
)


require(
    "pub fn commitment(&self) -> [u8; 32]" in pq
    and 'SYNERGY/PQ-REPLAY-STATE/V1\\0' in pq
    and "hasher.update(self.next_nonce.to_be_bytes())" in pq,
    "replay state must expose a canonical rollback-detectable commitment",
)

for stateless, consuming in (
    ("verify_governance_action", "verify_governance_action_and_consume"),
    ("verify_consensus_activation", "verify_consensus_activation_and_consume"),
    ("verify_service_plane_checkpoint", "verify_service_plane_checkpoint_and_consume"),
    ("verify_payment_intent", "verify_payment_intent_and_consume"),
    ("verify_settlement_batch", "verify_settlement_batch_and_consume"),
    ("verify_storage_proof", "verify_storage_proof_and_consume"),
    ("verify_cognitive_evidence", "verify_cognitive_evidence_and_consume"),
    ("verify_inference_receipt", "verify_inference_receipt_and_consume"),
    ("verify_verifier_receipt", "verify_verifier_receipt_and_consume"),
    ("verify_model_upgrade", "verify_model_upgrade_and_consume"),
    ("verify_binding", "verify_binding_and_consume"),
    ("verify_validator_vote", "verify_validator_vote_and_consume"),
    ("verify_kv_replica_receipt", "verify_kv_replica_receipt_and_consume"),
):
    require(
        consuming in lib_v2
        and f"pub use {stateless}" not in lib_v2
        and f" {stateless}," not in lib_v2,
        f"public crate surface must export consuming API only for {stateless}",
    )

require(
    "authorize_and_lock_autopilot_execution" in lib_v2
    and "verify_autopilot_execution_and_consume" not in lib_v2
    and "pub(crate) fn verify_autopilot_execution_and_consume" in autopilot_budget,
    "Autopilot public crate surface must expose lease-enforced authorization only",
)


require(
    "subject_commitment: [u8; 32]" in pq
    and "pub fn new_for_subject(" in pq
    and "pub(crate) fn consume_verified_for_subject(" in pq
    and "pub(crate) fn verify_and_consume_for_subject<" in pq
    and "hasher.update(self.subject_commitment)" in pq,
    "production replay state must remain authority-subject-bound",
)

require(
    "pub fn new(" not in pq
    and "pub fn consume_verified(" not in pq
    and "pub fn verify_and_consume<" not in pq,
    "unbound replay constructor/consume APIs must not be public in production",
)

for name, source in (
    ("governance", governance),
    ("consensus", consensus),
    ("service_planes", service_planes),
    ("autopilot_budget", autopilot_budget),
    ("payments", payments),
    ("storage", storage),
    ("cognitive", cognitive),
    ("inference", inference),
    ("verification", verification),
    ("model_shard", model_shard),
    ("migration", migration),
    ("validator", validator),
    ("kv_cache", kv_cache),
):
    require(
        "replay.consume_verified_for_subject" in source,
        f"{name} consuming verifier must bind replay state to authority subject",
    )

require(
    "pub(crate) fn validate<V: ContextSignatureVerifier>" in tx
    and "pub fn validate_and_consume<V: ContextSignatureVerifier>" in tx
    and "replay.consume_verified_for_subject" in tx
    and "self.sender_account" in tx,
    "transaction public validation must consume subject-bound replay state",
)


require(
    "pub fn consume_verified_for_subject(" not in pq
    and "pub fn verify_and_consume_for_subject<" not in pq,
    "generic replay consume/verify helpers must not be public",
)

for name, source in (
    ("validator", validator),
    ("transaction", tx),
):
    require(
        "AuthorizationReplayState" in source,
        f"{name} replay type import missing",
    )


require(
    "pub fn infer_reference_metered(" in nexus
    and "pub(crate) fn infer_reference(" in nexus
    and "NexusError::OutOfGas" in nexus
    and "if gas_used > gas_budget" in nexus
    and "self.nodes != 16" in nexus
    and "self.layers != 3" in nexus
    and "self.max_input_values != 512" in nexus
    and "self.max_output_values != 64" in nexus
    and "self.source_checkpoint_sha256_hex != Self::V18_SOURCE_CHECKPOINT" in nexus,
    "NEXUS v1 must remain exact-profile and gas-metered before execution",
)

require(
    "infer_reference_metered" in lib_v2
    and "NexusError" in lib_v2,
    "public crate surface must expose the metered NEXUS API",
)

require(
    "provenance implementation root mismatch" in cognitive_registry
    and "provenance role commitment mismatch" in cognitive_registry
    and "canonical_role_commitment" in cognitive_registry
    and "self.implementation_root != node.software_commitment" in cognitive_registry,
    "cognitive provenance must remain bound to operational role and implementation",
)


require(
    "expected_payer_keyset_commitment" in payments
    and "primary_account_identity_commitment()" in payments
    and "Some(authorized.intent.payer)" in payments
    and "Some(validation.expected_payer_keyset_commitment)" in payments,
    "payment payer identity must remain stable-account-bound with separate current keyset",
)

require(
    "expected_owner_keyset_commitment" in autopilot_budget
    and "primary_account_identity_commitment()" in autopilot_budget
    and "Some(reservation.owner_account)" in autopilot_budget
    and "Some(validation.expected_owner_keyset_commitment)" in autopilot_budget,
    "Autopilot owner identity must remain stable-account-bound with separate current keyset",
)

require(
    "binding.binding.synergy_account_id" in migration
    and "replay.consume_verified_for_subject" in migration,
    "bridge migration replay subject must remain the stable target account identity",
)

require(
    "funding reservation payer account mismatch" in payment_funding
    and "self.payer_account_root != intent.payer" in payment_funding,
    "funding reservation must remain bound to the exact payer account",
)


require(
    "pub mod autopilot_execution_lease;" in lib_v2
    and "AutopilotExecutionLease" in lib_v2
    and "AutopilotLeaseTerminalReceipt" in lib_v2
    and "new execution lease must be locked" in autopilot_execution_lease
    and "terminal receipt cannot remain execution-locked" in autopilot_execution_lease,
    "Autopilot one-time execution lease must remain compiled and fail closed",
)


require(
    "pub fn finalize_once(" in autopilot_execution_lease
    and "execution lease already terminal" in autopilot_execution_lease
    and "terminal receipt lease mismatch" in autopilot_execution_lease
    and "AUTOPILOT_LEASE_TERMINAL_DOMAIN" in autopilot_execution_lease
    and "pub fn commitment(&self) -> Option<[u8; 32]>" in autopilot_execution_lease,
    "Autopilot execution lease must remain one-shot with canonical terminal commitment",
)


require(
    "bytes memory message" in pq_sol
    and "bytes memory context" in pq_sol
    and "ML_DSA_87_PUBLIC_KEY_BYTES = 2592" in pq_sol
    and "ML_DSA_87_SIGNATURE_BYTES = 4627" in pq_sol
    and "SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES = 64" in pq_sol
    and "SLH_DSA_SHAKE_256S_SIGNATURE_BYTES = 29792" in pq_sol
    and "MAX_FIPS_CONTEXT_BYTES = 255" in pq_sol
    and "abi.encode(publicKey, message, context, signature)" in pq_sol,
    "Solidity PQ precompile boundary must remain context-aware and size-strict",
)

require(
    "requireDualPQ" not in smart_account_sol
    and "AUTH_POLICY_PQ_ONLY = 3" in smart_account_sol
    and "AUTHORIZATION_EPOCH = 1" in smart_account_sol
    and "MAX_AUTHORIZATION_LIFETIME_SECONDS = 86_400" in smart_account_sol
    and "_hasNonZeroByte(mlDsa87PublicKey_)" in smart_account_sol
    and "_hasNonZeroByte(slhDsaPublicKey_)" in smart_account_sol
    and "mlDsaSignature.length != 4627" in smart_account_sol
    and "slhDsaSignature.length != 29792" in smart_account_sol
    and "block.timestamp >= validUntil" in smart_account_sol
    and "validUntil - block.timestamp > MAX_AUTHORIZATION_LIFETIME_SECONDS" in smart_account_sol
    and "PQVerify.mlDsa87" in smart_account_sol
    and "PQVerify.slhDsa256s" in smart_account_sol,
    "PQSmartAccount must remain strict dual-PQ, size-bound and expiry-bound",
)

require(
    "function inferScore(" in nexus_sol
    and "enum Mode" not in nexus_sol
    and "Policy" not in nexus_sol
    and "ProofAssist" not in nexus_sol
    and "abi.encode(modelRoot, uint8(0), inputQ16, maxOutputs)" in nexus_sol,
    "Solidity NEXUS v1 facade must expose Score-only consensus mode",
)


require(
    "Self::TransportHandshake => 16" in pq
    and "AuthorizationDomain::TransportHandshake.protocol_code()" in pq,
    "transport handshake authorization domain code missing or outside registry test",
)

require(
    "pub fn establish_authenticated_shared_secret" in network
    and "pub(crate) fn establish_shared_secret" in network
    and "AuthorizationDomain::TransportHandshake" in network
    and "authorized.authorization.policy != AuthPolicy::PqOnly" in network
    and "TransportRole::Initiator" in network
    and "TransportRole::Responder" in network
    and "consume_verified_for_subject" in network
    and "let mut next_initiator = initiator_replay.clone()" in network
    and "let mut next_responder = responder_replay.clone()" in network,
    "transport establishment must authenticate both peers and atomically consume auth replay state",
)

require(
    "establish_authenticated_shared_secret" in lib_v2
    and "establish_shared_secret," not in lib_v2,
    "public crate surface must not expose unauthenticated transport establishment",
)

require(
    "transport_handshake_rejects_role_swap" in network
    and "transport_session_replay_failure_does_not_burn_peer_auth_nonces" in network,
    "transport handshake role and replay atomicity regressions missing",
)


require(
    "pub(crate) fn verify_authorization" in pq
    and "pub(crate) fn verify_authorization_with_context" in pq
    and "pub(crate) fn verify_envelope_authorization" in pq
    and "verify_envelope_authorization," not in lib_v2,
    "stateless low-level authorization verification must remain crate-internal",
)


require(
    "expected_keyset_commitment == [0u8; 32]" in network
    and "initiator_validation.expected_keyset_commitment" in network
    and "responder_validation.expected_keyset_commitment" in network
    and "== responder_validation.expected_keyset_commitment" in network,
    "transport peers must use distinct nonzero registered authentication keysets",
)

require(
    "pub fn commitment(&self) -> Option<[u8; 32]>" in network
    and 'SYNERGY/TRANSPORT-REPLAY-STATE/V1\\0' in network
    and "for session_id in &self.consumed" in network
    and "network_id == [0u8; 32] || epoch == 0" in network,
    "transport replay state must remain persistently commit-able and reject zero epoch",
)


require(
    "pub fn authorize_and_lock_autopilot_execution" in autopilot_execution_lease
    and "pub fn canonical_root(" in autopilot_execution_lease
    and "execution lease root mismatch" in autopilot_execution_lease
    and "execution lease call root mismatch" in autopilot_execution_lease
    and "verify_autopilot_execution_and_consume(" in autopilot_execution_lease
    and "authorize_and_lock_autopilot_execution" in lib_v2
    and "verify_autopilot_execution_and_consume" not in lib_v2,
    "Autopilot public execution path must require canonical one-time lease before nonce consumption",
)


require(
    "enum TransportDirection" in network
    and "InitiatorToResponder => 1" in network
    and "ResponderToInitiator => 2" in network
    and "info.push(direction.protocol_code())" in network
    and "pub fn derive_directional_transport_session_keys" in network
    and "pub struct TransportSessionKeys" in network,
    "transport KDF must derive independent directional traffic keys",
)

require(
    "derive_directional_transport_session_keys" in lib_v2
    and "derive_transport_session_key," not in lib_v2
    and "TransportSessionKeys" in lib_v2,
    "public crate surface must expose direction-separated transport keys only",
)


require(
    "TRANSPORT_RECORD_NONCE_BYTES: usize = 12" in network
    and "pub struct TransportRecordSequence" in network
    and "if self.next_sequence >= self.max_messages" in network
    and "self.next_sequence.checked_add(1)?" in network
    and "nonce[1] = self.direction.protocol_code()" in network,
    "transport record nonce sequence must remain directional, bounded and non-wrapping",
)

require(
    "TransportRecordSequence" in lib_v2
    and "TRANSPORT_RECORD_NONCE_BYTES" in lib_v2,
    "public crate surface must expose bounded transport record sequencing",
)


require(
    "expected_authorization_keyset_commitment" in tx
    and "self.authorization.keyset_commitment()" in tx
    and "primary_account_identity_commitment() != Some(self.sender_account)" in tx
    and "transaction_rejects_unregistered_secondary_pq_keyset" in tx,
    "transaction authorization must bind stable account identity and registered current keyset",
)


require(
    "Self::AutopilotLeaseTerminal => 17" in pq
    and "AuthorizationDomain::AutopilotLeaseTerminal.protocol_code()" in pq,
    "Autopilot lease terminal authorization domain missing from append-only registry",
)

require(
    "pub(crate) fn finalize_once(" in autopilot_execution_lease
    and "pub fn finalize_autopilot_lease_and_consume" in autopilot_execution_lease
    and "AuthorizationDomain::AutopilotLeaseTerminal" in autopilot_execution_lease
    and "authorized.authorization.policy != AuthPolicy::Max" in autopilot_execution_lease
    and "receipt.success" in autopilot_execution_lease
    and "let mut next_lease = lease.clone()" in autopilot_execution_lease
    and "let mut next_replay = replay.clone()" in autopilot_execution_lease,
    "Autopilot lease terminal transition must remain MAX-authorized and atomic",
)

require(
    "pub fn commitment_against(" in autopilot_budget
    and 'SYNERGY/AUTOPILOT-REALIZED-EXECUTION/V1\\0' in autopilot_budget,
    "Autopilot realized execution receipts must remain canonically committed",
)

require(
    "finalize_autopilot_lease_and_consume" in lib_v2
    and "AutopilotLeaseTerminalAuthorization" in lib_v2,
    "public crate surface must expose authenticated lease terminal transition",
)

print("M2 static guard: PASS")
