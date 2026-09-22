//! Standards-based reference post-quantum provider.
//!
//! Enabled only with the `reference-pq` Cargo feature. This module integrates
//! RustCrypto implementations of FIPS 203 ML-KEM-1024, FIPS 204 ML-DSA-87 and
//! FIPS 205 SLH-DSA-SHAKE-256s behind the protocol traits defined by this crate.
//!
//! This is a reference/integration provider, not a claim of independent audit.
//! Production deployments should place secret keys behind OS/hardware keystores
//! and keep the same opaque-handle boundary.

use crate::network::MlKem1024Provider;
use crate::pq::{AuthScheme, ContextSignatureVerifier, SignatureVerifier};
use std::collections::BTreeMap;

use ml_kem::{
    ml_kem_1024::{Ciphertext as MlKem1024Ciphertext, EncapsulationKey as MlKem1024EncapsulationKey},
    Decapsulate, Encapsulate, Kem, Key, KeyExport, MlKem1024, Seed as MlKemSeed,
};

/// Opaque local handle for one ML-KEM-1024 decapsulation key.
pub type MlKemSecretHandle = [u8; 32];

/// Reference ML-KEM provider.
///
/// Secret key material is stored internally as the preferred 64-byte ML-KEM
/// seed representation. Callers receive only an opaque handle.
#[derive(Default)]
pub struct ReferenceMlKem1024Provider {
    next_handle: u64,
    secrets: BTreeMap<MlKemSecretHandle, MlKemSeed>,
}

impl ReferenceMlKem1024Provider {
    pub fn new() -> Self {
        Self::default()
    }

    /// Generate a fresh ML-KEM-1024 keypair.
    ///
    /// Returns (opaque secret handle, serialized public encapsulation key).
    pub fn generate_keypair(&mut self) -> (MlKemSecretHandle, Vec<u8>) {
        let (dk, ek) = MlKem1024::generate_keypair();

        self.next_handle = self.next_handle.checked_add(1).expect("ML-KEM handle counter overflow");
        let mut handle = [0u8; 32];
        handle[..8].copy_from_slice(&self.next_handle.to_be_bytes());

        let seed = dk.to_bytes();
        let replaced = self.secrets.insert(handle, seed);
        debug_assert!(replaced.is_none());

        (handle, ek.to_bytes().as_ref().to_vec())
    }

    pub fn remove_key(&mut self, handle: &MlKemSecretHandle) -> bool {
        self.secrets.remove(handle).is_some()
    }

    pub fn contains_key(&self, handle: &MlKemSecretHandle) -> bool {
        self.secrets.contains_key(handle)
    }
}

impl MlKem1024Provider for ReferenceMlKem1024Provider {
    fn encapsulate(&self, public_key: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
        let encoded = Key::<MlKem1024EncapsulationKey>::try_from(public_key).ok()?;
        // EncapsulationKey::new performs the public-key validation required by
        // the ML-KEM implementation. Do not replace this with unchecked casting.
        let ek = MlKem1024EncapsulationKey::new(&encoded).ok()?;
        let (ciphertext, shared) = ek.encapsulate();
        Some((ciphertext.as_ref().to_vec(), shared.as_ref().to_vec()))
    }

    fn decapsulate(&self, secret_key_handle: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
        let handle: MlKemSecretHandle = secret_key_handle.try_into().ok()?;
        let seed = self.secrets.get(&handle)?;
        let dk = ml_kem::DecapsulationKey::<MlKem1024>::from_seed(seed.clone());
        let ciphertext = MlKem1024Ciphertext::try_from(ciphertext).ok()?;
        Some(dk.decapsulate(&ciphertext).as_ref().to_vec())
    }
}

/// Reference verifier for the two post-quantum signature lanes.
///
/// Classical Secp256k1/Ed25519 verification intentionally remains outside this
/// provider so hybrid policy cannot silently downgrade into a single backend.
#[derive(Debug, Default, Clone, Copy)]
pub struct ReferencePqSignatureVerifier;

impl SignatureVerifier for ReferencePqSignatureVerifier {
    fn verify(
        &self,
        scheme: AuthScheme,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        match scheme {
            AuthScheme::MlDsa87 => verify_ml_dsa_87(public_key, message, signature),
            AuthScheme::SlhDsaShake256s => verify_slh_dsa_shake_256s(public_key, message, signature),
            AuthScheme::Secp256k1 | AuthScheme::Ed25519 => false,
        }
    }
}

impl ContextSignatureVerifier for ReferencePqSignatureVerifier {
    fn verify_with_context(
        &self,
        scheme: AuthScheme,
        public_key: &[u8],
        message: &[u8],
        context: &[u8],
        signature: &[u8],
    ) -> bool {
        if context.len() > 255 {
            return false;
        }
        match scheme {
            AuthScheme::MlDsa87 => {
                verify_ml_dsa_87_with_context(public_key, message, context, signature)
            }
            AuthScheme::SlhDsaShake256s => {
                verify_slh_dsa_shake_256s_with_context(public_key, message, context, signature)
            }
            AuthScheme::Secp256k1 | AuthScheme::Ed25519 => false,
        }
    }
}

fn verify_ml_dsa_87(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    use ml_dsa::{MlDsa87, Signature, Verifier, VerifyingKey};

    let encoded_key = match ml_dsa::EncodedVerifyingKey::<MlDsa87>::try_from(public_key) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let verifying_key = VerifyingKey::<MlDsa87>::decode(&encoded_key);
    let signature = match Signature::<MlDsa87>::try_from(signature) {
        Ok(value) => value,
        Err(_) => return false,
    };
    verifying_key.verify(message, &signature).is_ok()
}

fn verify_ml_dsa_87_with_context(
    public_key: &[u8],
    message: &[u8],
    context: &[u8],
    signature: &[u8],
) -> bool {
    use ml_dsa::{MlDsa87, Signature, VerifyingKey};

    if context.len() > 255 {
        return false;
    }
    let encoded_key = match ml_dsa::EncodedVerifyingKey::<MlDsa87>::try_from(public_key) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let verifying_key = VerifyingKey::<MlDsa87>::decode(&encoded_key);
    let signature = match Signature::<MlDsa87>::try_from(signature) {
        Ok(value) => value,
        Err(_) => return false,
    };
    verifying_key.verify_with_context(message, context, &signature)
}

fn verify_slh_dsa_shake_256s(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    use slh_dsa::{Shake256s, Signature, VerifyingKey};
    use slh_dsa::signature::Verifier;

    let verifying_key = match VerifyingKey::<Shake256s>::try_from(public_key) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let signature = match Signature::<Shake256s>::try_from(signature) {
        Ok(value) => value,
        Err(_) => return false,
    };
    verifying_key.verify(message, &signature).is_ok()
}

fn verify_slh_dsa_shake_256s_with_context(
    public_key: &[u8],
    message: &[u8],
    context: &[u8],
    signature: &[u8],
) -> bool {
    use slh_dsa::{Shake256s, Signature, VerifyingKey};

    if context.len() > 255 {
        return false;
    }
    let verifying_key = match VerifyingKey::<Shake256s>::try_from(public_key) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let signature = match Signature::<Shake256s>::try_from(signature) {
        Ok(value) => value,
        Err(_) => return false,
    };
    verifying_key
        .try_verify_with_context(message, context, &signature)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::MlKem1024Provider;
    use crate::pq::{ContextSignatureVerifier, SignatureVerifier};

    #[test]
    fn ml_kem_1024_real_round_trip() {
        let mut provider = ReferenceMlKem1024Provider::new();
        let (handle, public_key) = provider.generate_keypair();
        assert!(provider.contains_key(&handle));

        let (ciphertext, sender_shared) = provider.encapsulate(&public_key).expect("encapsulation");
        let receiver_shared = provider.decapsulate(&handle, &ciphertext).expect("decapsulation");

        assert_eq!(sender_shared, receiver_shared);
        assert_eq!(sender_shared.len(), 32);
    }

    #[test]
    fn ml_kem_wrong_handle_fails_closed() {
        let mut provider = ReferenceMlKem1024Provider::new();
        let (_handle, public_key) = provider.generate_keypair();
        let (ciphertext, _) = provider.encapsulate(&public_key).expect("encapsulation");
        assert!(provider.decapsulate(&[99u8; 32], &ciphertext).is_none());
    }

    #[test]
    fn ml_kem_bad_public_key_length_is_rejected() {
        let provider = ReferenceMlKem1024Provider::new();
        assert!(provider.encapsulate(&[1u8; 31]).is_none());
    }

    #[test]
    fn ml_kem_corrupted_ciphertext_does_not_recover_original_secret() {
        let mut provider = ReferenceMlKem1024Provider::new();
        let (handle, public_key) = provider.generate_keypair();
        let (mut ciphertext, sender_shared) = provider.encapsulate(&public_key).expect("encapsulation");
        ciphertext[0] ^= 0x01;
        let receiver_shared = provider.decapsulate(&handle, &ciphertext).expect("implicit rejection");
        assert_ne!(sender_shared, receiver_shared);
    }

    #[test]
    fn ml_dsa_87_real_sign_verify_and_negative_message() {
        use ml_dsa::{Generate, Keypair, MlDsa87, SignatureEncoding, Signer, SigningKey};

        let signing_key = SigningKey::<MlDsa87>::generate();
        let public_key = signing_key.verifying_key().encode().to_vec();
        let message = b"SYNERGY/PQ/AUTH/v1";
        let signature = signing_key.sign(message).to_vec();

        let verifier = ReferencePqSignatureVerifier;
        assert!(verifier.verify(AuthScheme::MlDsa87, &public_key, message, &signature));
        assert!(!verifier.verify(AuthScheme::MlDsa87, &public_key, b"tampered", &signature));

        let mut corrupted = signature.clone();
        corrupted[corrupted.len() / 2] ^= 0x80;
        assert!(!verifier.verify(AuthScheme::MlDsa87, &public_key, message, &corrupted));
    }

    #[test]
    fn slh_dsa_shake_256s_real_sign_verify_and_negative_message() {
        use slh_dsa::{Shake256s, SigningKey};
        use slh_dsa::signature::{Keypair, Signer};

        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::<Shake256s>::new(&mut rng);
        let public_key = signing_key.verifying_key().to_vec();
        let message = b"SYNERGY/PQ/COLD/v1";
        let signature = signing_key.try_sign(message).expect("SLH-DSA sign").to_vec();

        let verifier = ReferencePqSignatureVerifier;
        assert!(verifier.verify(
            AuthScheme::SlhDsaShake256s,
            &public_key,
            message,
            &signature
        ));
        assert!(!verifier.verify(
            AuthScheme::SlhDsaShake256s,
            &public_key,
            b"tampered",
            &signature
        ));
    }

    #[test]
    fn ml_dsa_87_fips_context_is_cryptographically_enforced() {
        use ml_dsa::{Generate, Keypair, MlDsa87, SignatureEncoding, SigningKey};

        let signing_key = SigningKey::<MlDsa87>::generate();
        let public_key = signing_key.verifying_key().encode().to_vec();
        let message = b"SYNERGY/PQ/FIPS-CONTEXT/ML-DSA";
        let context = b"SYNERGY/context/A";
        let wrong_context = b"SYNERGY/context/B";
        let signature = signing_key
            .sign_deterministic(message, context)
            .expect("ML-DSA context sign")
            .to_vec();

        let verifier = ReferencePqSignatureVerifier;
        assert!(verifier.verify_with_context(
            AuthScheme::MlDsa87,
            &public_key,
            message,
            context,
            &signature,
        ));
        assert!(!verifier.verify_with_context(
            AuthScheme::MlDsa87,
            &public_key,
            message,
            wrong_context,
            &signature,
        ));
        assert!(!verifier.verify_with_context(
            AuthScheme::MlDsa87,
            &public_key,
            b"tampered",
            context,
            &signature,
        ));
        assert!(!verifier.verify_with_context(
            AuthScheme::MlDsa87,
            &public_key,
            message,
            &[0u8; 256],
            &signature,
        ));
    }

    #[test]
    fn slh_dsa_shake_256s_fips_context_is_cryptographically_enforced() {
        use slh_dsa::{Shake256s, SigningKey};
        use slh_dsa::signature::Keypair;

        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::<Shake256s>::new(&mut rng);
        let public_key = signing_key.verifying_key().to_vec();
        let message = b"SYNERGY/PQ/FIPS-CONTEXT/SLH-DSA";
        let context = b"SYNERGY/context/A";
        let wrong_context = b"SYNERGY/context/B";
        let signature = signing_key
            .try_sign_with_context(message, context, None)
            .expect("SLH-DSA context sign")
            .to_vec();

        let verifier = ReferencePqSignatureVerifier;
        assert!(verifier.verify_with_context(
            AuthScheme::SlhDsaShake256s,
            &public_key,
            message,
            context,
            &signature,
        ));
        assert!(!verifier.verify_with_context(
            AuthScheme::SlhDsaShake256s,
            &public_key,
            message,
            wrong_context,
            &signature,
        ));
        assert!(!verifier.verify_with_context(
            AuthScheme::SlhDsaShake256s,
            &public_key,
            b"tampered",
            context,
            &signature,
        ));
        assert!(!verifier.verify_with_context(
            AuthScheme::SlhDsaShake256s,
            &public_key,
            message,
            &[0u8; 256],
            &signature,
        ));
    }

    #[test]
    fn pq_only_authorization_requires_same_derived_fips_context_on_both_pq_lanes() {
        use crate::pq::{
            verify_authorization_with_context, AuthPolicy, AuthorizationDomain,
            AuthorizationEnvelope, HybridAuthorization, SignatureEvidence,
        };
        use ml_dsa::{
            Generate, Keypair as MlKeypair, MlDsa87, SignatureEncoding,
            SigningKey as MlSigningKey,
        };
        use slh_dsa::{Shake256s, SigningKey as SlhSigningKey};
        use slh_dsa::signature::Keypair as SlhKeypair;

        let envelope = AuthorizationEnvelope {
            chain_id: [0x31; 32],
            domain: AuthorizationDomain::InferenceReceipt,
            epoch: 77,
            nonce: 1234,
            expires_at: 9_999,
            payload_commitment: [0x62; 32],
        };
        let message = envelope.canonical_message(AuthPolicy::PqOnly).unwrap();
        let context = envelope.fips_signature_context(AuthPolicy::PqOnly).unwrap();

        let ml_sk = MlSigningKey::<MlDsa87>::generate();
        let ml_pk = ml_sk.verifying_key().encode().to_vec();
        let ml_sig = ml_sk
            .sign_deterministic(&message, &context)
            .expect("ML-DSA FIPS-context sign")
            .to_vec();

        let mut rng = rand::thread_rng();
        let slh_sk = SlhSigningKey::<Shake256s>::new(&mut rng);
        let slh_pk = slh_sk.verifying_key().to_vec();
        let slh_sig = slh_sk
            .try_sign_with_context(&message, &context, None)
            .expect("SLH-DSA FIPS-context sign")
            .to_vec();

        let auth = HybridAuthorization {
            policy: AuthPolicy::PqOnly,
            evidence: vec![
                SignatureEvidence {
                    scheme: AuthScheme::MlDsa87,
                    public_key: ml_pk,
                    signature: ml_sig,
                },
                SignatureEvidence {
                    scheme: AuthScheme::SlhDsaShake256s,
                    public_key: slh_pk,
                    signature: slh_sig,
                },
            ],
        };

        let verifier = ReferencePqSignatureVerifier;
        assert!(verify_authorization_with_context(
            &verifier,
            &auth,
            &message,
            &context,
        ));

        let mut wrong_domain = envelope.clone();
        wrong_domain.domain = AuthorizationDomain::Governance;
        let wrong_context = wrong_domain
            .fips_signature_context(AuthPolicy::PqOnly)
            .unwrap();
        assert!(!verify_authorization_with_context(
            &verifier,
            &auth,
            &message,
            &wrong_context,
        ));

        let wrong_policy_context = envelope
            .fips_signature_context(AuthPolicy::Max)
            .unwrap();
        assert!(!verify_authorization_with_context(
            &verifier,
            &auth,
            &message,
            &wrong_policy_context,
        ));
    }

    #[test]
    fn pq_only_authorization_verifies_two_independent_real_pq_lanes() {
        use crate::pq::{
            verify_authorization, AuthPolicy, AuthorizationDomain, AuthorizationEnvelope,
            HybridAuthorization, SignatureEvidence,
        };
        use ml_dsa::{Generate, Keypair as MlKeypair, MlDsa87, SignatureEncoding, Signer as MlSigner, SigningKey as MlSigningKey};
        use slh_dsa::{Shake256s, SigningKey as SlhSigningKey};
        use slh_dsa::signature::{Keypair as SlhKeypair, Signer as SlhSigner};

        let envelope = AuthorizationEnvelope {
            chain_id: [1; 32],
            domain: AuthorizationDomain::Transaction,
            epoch: 7,
            nonce: 42,
            expires_at: 999,
            payload_commitment: [2; 32],
        };
        let message = envelope.canonical_message(AuthPolicy::PqOnly).unwrap();

        let ml_sk = MlSigningKey::<MlDsa87>::generate();
        let ml_pk = ml_sk.verifying_key().encode().to_vec();
        let ml_sig = ml_sk.sign(&message).to_vec();

        let mut rng = rand::thread_rng();
        let slh_sk = SlhSigningKey::<Shake256s>::new(&mut rng);
        let slh_pk = slh_sk.verifying_key().to_vec();
        let slh_sig = slh_sk.try_sign(&message).expect("SLH-DSA sign").to_vec();

        let auth = HybridAuthorization {
            policy: AuthPolicy::PqOnly,
            evidence: vec![
                SignatureEvidence {
                    scheme: AuthScheme::MlDsa87,
                    public_key: ml_pk,
                    signature: ml_sig,
                },
                SignatureEvidence {
                    scheme: AuthScheme::SlhDsaShake256s,
                    public_key: slh_pk,
                    signature: slh_sig,
                },
            ],
        };

        assert!(verify_authorization(&ReferencePqSignatureVerifier, &auth, &message));

        let wrong_policy_message = envelope.canonical_message(AuthPolicy::Online).unwrap();
        assert!(!verify_authorization(
            &ReferencePqSignatureVerifier,
            &auth,
            &wrong_policy_message
        ));
    }

    #[test]
    fn max_authorization_requires_classical_and_both_real_pq_lanes() {
        use crate::pq::{
            verify_authorization, AuthPolicy, AuthorizationDomain, AuthorizationEnvelope,
            HybridAuthorization, SchemeRoutedVerifier, SignatureEvidence,
        };
        use ml_dsa::{
            Generate, Keypair as MlKeypair, MlDsa87, SignatureEncoding, Signer as MlSigner,
            SigningKey as MlSigningKey,
        };
        use slh_dsa::{Shake256s, SigningKey as SlhSigningKey};
        use slh_dsa::signature::{Keypair as SlhKeypair, Signer as SlhSigner};

        #[derive(Clone, Copy)]
        struct TestClassicalVerifier;

        impl SignatureVerifier for TestClassicalVerifier {
            fn verify(
                &self,
                scheme: AuthScheme,
                public_key: &[u8],
                message: &[u8],
                signature: &[u8],
            ) -> bool {
                scheme == AuthScheme::Secp256k1
                    && public_key == b"classical-key"
                    && signature == b"classical-signature"
                    && !message.is_empty()
            }
        }

        let envelope = AuthorizationEnvelope {
            chain_id: [0x11; 32],
            domain: AuthorizationDomain::Governance,
            epoch: 12,
            nonce: 99,
            expires_at: 1_000,
            payload_commitment: [0x22; 32],
        };
        let message = envelope.canonical_message(AuthPolicy::Max).unwrap();

        let ml_sk = MlSigningKey::<MlDsa87>::generate();
        let ml_pk = ml_sk.verifying_key().encode().to_vec();
        let ml_sig = ml_sk.sign(&message).to_vec();

        let mut rng = rand::thread_rng();
        let slh_sk = SlhSigningKey::<Shake256s>::new(&mut rng);
        let slh_pk = slh_sk.verifying_key().to_vec();
        let slh_sig = slh_sk.try_sign(&message).expect("SLH-DSA sign").to_vec();

        let verifier = SchemeRoutedVerifier {
            classical: TestClassicalVerifier,
            pq: ReferencePqSignatureVerifier,
        };

        let mut auth = HybridAuthorization {
            policy: AuthPolicy::Max,
            evidence: vec![
                SignatureEvidence {
                    scheme: AuthScheme::Secp256k1,
                    public_key: b"classical-key".to_vec(),
                    signature: b"classical-signature".to_vec(),
                },
                SignatureEvidence {
                    scheme: AuthScheme::MlDsa87,
                    public_key: ml_pk,
                    signature: ml_sig,
                },
                SignatureEvidence {
                    scheme: AuthScheme::SlhDsaShake256s,
                    public_key: slh_pk,
                    signature: slh_sig,
                },
            ],
        };

        assert!(verify_authorization(&verifier, &auth, &message));

        auth.evidence[0].signature = b"wrong-classical-signature".to_vec();
        assert!(!verify_authorization(&verifier, &auth, &message));
    }

    #[test]
    fn pq_verifier_never_claims_classical_lanes() {
        let verifier = ReferencePqSignatureVerifier;
        assert!(!verifier.verify(AuthScheme::Secp256k1, &[], b"x", &[]));
        assert!(!verifier.verify(AuthScheme::Ed25519, &[], b"x", &[]));
    }
}
