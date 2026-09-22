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

# Reproducibility / MSRV invariants.
require('rust-version = "1.85"' in cargo, "crate rust-version must stay pinned to 1.85")
for exact in (
    'ml-kem = { version = "=0.3.2"',
    'ml-dsa = { version = "=0.1.1"',
    'slh-dsa = { version = "=0.1.0"',
    'rand = { version = "=0.8.5"',
    'hex = "=0.4.3"',
    'serde = { version = "=1.0.228"',
    'serde_json = "=1.0.145"',
):
    require(exact in cargo, f"missing exact dependency pin: {exact}")

# Context anti-downgrade invariants.
require("pub fn verify_envelope_authorization" in pq, "envelope-bound verifier missing")
require("pub(crate) fn verify_authorization<" in pq, "raw verifier must remain crate-internal")
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
    "ML_DSA_87_PUBLIC_KEY_BYTES: usize = 2592",
    "ML_DSA_87_SIGNATURE_BYTES: usize = 4627",
    "SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES: usize = 64",
    "SLH_DSA_SHAKE_256S_SIGNATURE_BYTES: usize = 29792",
):
    require(gate in pq_ref, f"missing serialized-size gate: {gate}")

# Production provider must fail closed instead of panicking on local conditions.
prod = pq_ref.split("#[cfg(test)]", 1)[0]
for forbidden in (".unwrap(", ".expect(", "panic!(", "debug_assert!(", ".fill_bytes("):
    require(forbidden not in prod, f"production pq_reference contains forbidden pattern {forbidden}")

require("try_generate_keypair" in prod, "fallible ML-KEM key generation missing")
require("::try_generate().ok()?" in prod, "fallible RustCrypto key generation missing")
require(".try_fill_bytes(" in prod, "fallible capability RNG missing")
require("for _ in 0..32" in prod, "capability allocation attempts must remain bounded")

print("M2 static guard: PASS")
