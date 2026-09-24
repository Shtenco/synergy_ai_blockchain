//! Standards-based reference post-quantum provider.
//!
//! Enabled only with the `reference-pq` Cargo feature. This module integrates
//! RustCrypto implementations of FIPS 203 ML-KEM-1024, FIPS 204 ML-DSA-87 and
//! FIPS 205 SLH-DSA-SHAKE-256s behind the protocol traits defined by this crate.
//!
//! This is a reference/integration provider, not a claim of independent audit.
//! Production deployments should place secret keys behind OS/hardware keystores
//! and keep the same opaque-handle boundary.

use crate::network::{
    MlKem1024Provider, MlKemSharedSecret, ML_KEM_1024_CIPHERTEXT_BYTES,
    ML_KEM_1024_PUBLIC_KEY_BYTES,
};
use crate::pq::{
    AuthScheme, ContextSignatureSigner, ContextSignatureVerifier, PqSigningKeyHandle,
    SignatureVerifier, ML_DSA_87_PUBLIC_KEY_BYTES, ML_DSA_87_SIGNATURE_BYTES,
    SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES, SLH_DSA_SHAKE_256S_SIGNATURE_BYTES,
};
use std::borrow::Borrow;
use std::collections::BTreeMap;

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct InternalCapabilityId([u8; 32]);

impl From<[u8; 32]> for InternalCapabilityId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl Borrow<[u8; 32]> for InternalCapabilityId {
    fn borrow(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for InternalCapabilityId {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

use ml_kem::{
    ml_kem_1024::{
        Ciphertext as MlKem1024Ciphertext, DecapsulationKey as MlKem1024DecapsulationKey,
        EncapsulationKey as MlKem1024EncapsulationKey,
    },
    Decapsulate, Generate, Key, KeyExport, B32,
};

/// Opaque local handle for one ML-KEM-1024 decapsulation key.
///
/// The bytes are intentionally private: protocol code can hold and return the
/// capability but cannot reinterpret it as arbitrary network/consensus bytes.
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MlKemSecretHandle([u8; 32]);

impl MlKemSecretHandle {
    fn from_random_bytes(bytes: [u8; 32]) -> Option<Self> {
        (bytes != [0u8; 32]).then_some(Self(bytes))
    }

    fn as_id_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[cfg(test)]
    fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

impl Drop for MlKemSecretHandle {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

/// Reference ML-KEM provider.
///
/// Secret key material is stored internally as the ML-KEM decapsulation-key
/// type itself. With the pinned `ml-kem` `zeroize` feature this type zeroizes
/// its private components on drop. Callers receive only an opaque handle.
#[derive(Default)]
pub struct ReferenceMlKem1024Provider {
    secrets: BTreeMap<InternalCapabilityId, MlKem1024DecapsulationKey>,
}

impl ReferenceMlKem1024Provider {
    pub fn new() -> Self {
        Self::default()
    }

    /// Generate a fresh ML-KEM-1024 keypair.
    ///
    /// Returns (opaque secret handle, serialized public encapsulation key).
    pub fn try_generate_keypair(&mut self) -> Option<(MlKemSecretHandle, Vec<u8>)> {
        let dk = MlKem1024DecapsulationKey::try_generate().ok()?;
        let ek = dk.encapsulation_key().clone();

        use rand::RngCore;

        let mut rng = rand::rngs::OsRng;
        let mut selected = None;
        for _ in 0..32 {
            let mut candidate = [0u8; 32];
            rng.try_fill_bytes(&mut candidate).ok()?;
            if let Some(candidate) = MlKemSecretHandle::from_random_bytes(candidate) {
                if !self.secrets.contains_key(candidate.as_id_bytes()) {
                    selected = Some(candidate);
                    break;
                }
            }
        }
        let handle = selected?;

        if self
            .secrets
            .insert(InternalCapabilityId::from(*handle.as_id_bytes()), dk)
            .is_some()
        {
            return None;
        }

        Some((handle, ek.to_bytes().as_slice().to_vec()))
    }

    pub fn remove_key(&mut self, handle: &MlKemSecretHandle) -> bool {
        self.secrets.remove(handle.as_id_bytes()).is_some()
    }

    pub fn contains_key(&self, handle: &MlKemSecretHandle) -> bool {
        self.secrets.contains_key(handle.as_id_bytes())
    }
}

impl MlKem1024Provider for ReferenceMlKem1024Provider {
    type SecretHandle = MlKemSecretHandle;

    fn encapsulate(&self, public_key: &[u8]) -> Option<(Vec<u8>, MlKemSharedSecret)> {
        if public_key.len() != ML_KEM_1024_PUBLIC_KEY_BYTES {
            return None;
        }
        let encoded = Key::<MlKem1024EncapsulationKey>::try_from(public_key).ok()?;
        // EncapsulationKey::new performs the public-key validation required by
        // the ML-KEM implementation. Do not replace this with unchecked casting.
        let ek = MlKem1024EncapsulationKey::new(&encoded).ok()?;

        use rand::RngCore;
        let mut randomness_bytes = [0u8; 32];
        rand::rngs::OsRng
            .try_fill_bytes(&mut randomness_bytes)
            .ok()?;
        let mut randomness = B32::try_from(randomness_bytes.as_slice()).ok()?;
        zeroize::Zeroize::zeroize(&mut randomness_bytes);

        let (ciphertext, mut shared) = ek.encapsulate_deterministic(&randomness);
        zeroize::Zeroize::zeroize(&mut randomness);

        let wrapped = MlKemSharedSecret::try_from_slice(shared.as_ref());
        zeroize::Zeroize::zeroize(&mut shared);
        wrapped.map(|wrapped| (ciphertext.as_slice().to_vec(), wrapped))
    }

    fn decapsulate(
        &self,
        secret_key_handle: &Self::SecretHandle,
        ciphertext: &[u8],
    ) -> Option<MlKemSharedSecret> {
        if ciphertext.len() != ML_KEM_1024_CIPHERTEXT_BYTES {
            return None;
        }
        let dk = self.secrets.get(secret_key_handle.as_id_bytes())?;
        let ciphertext = MlKem1024Ciphertext::try_from(ciphertext).ok()?;
        let mut shared = dk.decapsulate(&ciphertext);
        let wrapped = MlKemSharedSecret::try_from_slice(shared.as_ref());
        zeroize::Zeroize::zeroize(&mut shared);
        wrapped
    }
}

/// Reference dual-PQ signer with opaque key handles.
///
/// ML-DSA-87 uses RustCrypto's zeroizing signing-key type. SLH-DSA-SHAKE-256s
/// uses the pinned `fips205` backend whose private-key type derives
/// `Zeroize + ZeroizeOnDrop`. Protocol code receives only opaque handles.
struct SlhDsaSigningMaterial {
    secret: fips205::slh_dsa_shake_256s::PrivateKey,
    public_key: [u8; SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES],
}

#[derive(Default)]
pub struct ReferencePqSigner {
    ml_dsa_keys: BTreeMap<InternalCapabilityId, ml_dsa::SigningKey<ml_dsa::MlDsa87>>,
    slh_dsa_keys: BTreeMap<InternalCapabilityId, SlhDsaSigningMaterial>,
}

impl ReferencePqSigner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn contains_key(&self, handle: &PqSigningKeyHandle) -> bool {
        self.ml_dsa_keys.contains_key(handle.as_id_bytes())
            || self.slh_dsa_keys.contains_key(handle.as_id_bytes())
    }

    fn try_allocate_handle(&self) -> Option<PqSigningKeyHandle> {
        use rand::RngCore;

        let mut rng = rand::rngs::OsRng;
        for _ in 0..32 {
            let mut handle_bytes = [0u8; 32];
            rng.try_fill_bytes(&mut handle_bytes).ok()?;
            if let Some(handle) = PqSigningKeyHandle::from_random_bytes(handle_bytes) {
                if !self.ml_dsa_keys.contains_key(handle.as_id_bytes())
                    && !self.slh_dsa_keys.contains_key(handle.as_id_bytes())
                {
                    return Some(handle);
                }
            }
        }
        None
    }
}

impl ContextSignatureSigner for ReferencePqSigner {
    fn generate_keypair(&mut self, scheme: AuthScheme) -> Option<(PqSigningKeyHandle, Vec<u8>)> {
        match scheme {
            AuthScheme::MlDsa87 => {
                use ml_dsa::{Generate, Keypair, MlDsa87, SigningKey};

                let signing_key = SigningKey::<MlDsa87>::try_generate().ok()?;
                let public_key = signing_key.verifying_key().encode().to_vec();
                let handle = self.try_allocate_handle()?;
                if self
                    .ml_dsa_keys
                    .insert(
                        InternalCapabilityId::from(*handle.as_id_bytes()),
                        signing_key,
                    )
                    .is_some()
                {
                    return None;
                }
                Some((handle, public_key))
            }
            AuthScheme::SlhDsaShake256s => {
                use fips205::traits::SerDes;

                let (public_key, signing_key) = fips205::slh_dsa_shake_256s::try_keygen().ok()?;
                let public_key = public_key.into_bytes();
                let handle = self.try_allocate_handle()?;
                let material = SlhDsaSigningMaterial {
                    secret: signing_key,
                    public_key,
                };
                if self
                    .slh_dsa_keys
                    .insert(InternalCapabilityId::from(*handle.as_id_bytes()), material)
                    .is_some()
                {
                    return None;
                }
                Some((handle, public_key.to_vec()))
            }
            AuthScheme::Secp256k1 | AuthScheme::Ed25519 => None,
        }
    }

    fn public_key(
        &self,
        scheme: AuthScheme,
        secret_key_handle: &PqSigningKeyHandle,
    ) -> Option<Vec<u8>> {
        match scheme {
            AuthScheme::MlDsa87 => {
                use ml_dsa::Keypair;
                let signing_key = self.ml_dsa_keys.get(secret_key_handle.as_id_bytes())?;
                Some(signing_key.verifying_key().encode().to_vec())
            }
            AuthScheme::SlhDsaShake256s => self
                .slh_dsa_keys
                .get(secret_key_handle.as_id_bytes())
                .map(|material| material.public_key.to_vec()),
            AuthScheme::Secp256k1 | AuthScheme::Ed25519 => None,
        }
    }

    fn sign_with_context(
        &self,
        scheme: AuthScheme,
        secret_key_handle: &PqSigningKeyHandle,
        message: &[u8],
        context: &[u8],
    ) -> Option<Vec<u8>> {
        if context.len() > 255 {
            return None;
        }

        match scheme {
            AuthScheme::MlDsa87 => {
                use ml_dsa::SignatureEncoding;
                let signing_key = self.ml_dsa_keys.get(secret_key_handle.as_id_bytes())?;
                signing_key
                    .expanded_key()
                    .sign_deterministic(message, context)
                    .ok()
                    .map(|signature| signature.to_vec())
            }
            AuthScheme::SlhDsaShake256s => {
                use fips205::traits::Signer;
                let material = self.slh_dsa_keys.get(secret_key_handle.as_id_bytes())?;
                material
                    .secret
                    .try_sign(message, context, true)
                    .ok()
                    .map(|signature| signature.to_vec())
            }
            AuthScheme::Secp256k1 | AuthScheme::Ed25519 => None,
        }
    }

    fn remove_key(&mut self, scheme: AuthScheme, secret_key_handle: &PqSigningKeyHandle) -> bool {
        match scheme {
            AuthScheme::MlDsa87 => self
                .ml_dsa_keys
                .remove(secret_key_handle.as_id_bytes())
                .is_some(),
            AuthScheme::SlhDsaShake256s => self
                .slh_dsa_keys
                .remove(secret_key_handle.as_id_bytes())
                .is_some(),
            AuthScheme::Secp256k1 | AuthScheme::Ed25519 => false,
        }
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
            AuthScheme::SlhDsaShake256s => {
                verify_slh_dsa_shake_256s(public_key, message, signature)
            }
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

    if public_key.len() != ML_DSA_87_PUBLIC_KEY_BYTES
        || signature.len() != ML_DSA_87_SIGNATURE_BYTES
    {
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
    verifying_key.verify(message, &signature).is_ok()
}

fn verify_ml_dsa_87_with_context(
    public_key: &[u8],
    message: &[u8],
    context: &[u8],
    signature: &[u8],
) -> bool {
    use ml_dsa::{MlDsa87, Signature, VerifyingKey};

    if context.len() > 255
        || public_key.len() != ML_DSA_87_PUBLIC_KEY_BYTES
        || signature.len() != ML_DSA_87_SIGNATURE_BYTES
    {
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
    use slh_dsa::signature::Verifier;
    use slh_dsa::{Shake256s, Signature, VerifyingKey};

    if public_key.len() != SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES
        || signature.len() != SLH_DSA_SHAKE_256S_SIGNATURE_BYTES
    {
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
    verifying_key.verify(message, &signature).is_ok()
}

fn verify_slh_dsa_shake_256s_with_context(
    public_key: &[u8],
    message: &[u8],
    context: &[u8],
    signature: &[u8],
) -> bool {
    use slh_dsa::{Shake256s, Signature, VerifyingKey};

    if context.len() > 255
        || public_key.len() != SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES
        || signature.len() != SLH_DSA_SHAKE_256S_SIGNATURE_BYTES
    {
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
        let (handle, public_key) = provider
            .try_generate_keypair()
            .expect("ML-KEM key generation");
        assert!(provider.contains_key(&handle));

        let (ciphertext, sender_shared) = provider.encapsulate(&public_key).expect("encapsulation");
        let receiver_shared = provider
            .decapsulate(&handle, &ciphertext)
            .expect("decapsulation");

        assert_eq!(sender_shared.as_bytes(), receiver_shared.as_bytes());
        assert_eq!(sender_shared.as_bytes().len(), 32);
    }

    #[test]
    fn ml_kem_rejects_correct_length_noncanonical_public_key() {
        let mut provider = ReferenceMlKem1024Provider::new();
        let (_handle, mut public_key) = provider
            .try_generate_keypair()
            .expect("ML-KEM key generation");

        assert_eq!(public_key.len(), ML_KEM_1024_PUBLIC_KEY_BYTES);

        // ML-KEM encodes two coefficients into each 3-byte block using 12 bits
        // per coefficient. Force the first coefficient to 4095, which is above
        // q = 3329, while preserving the exact ML-KEM-1024 public-key length.
        public_key[0] = 0xff;
        public_key[1] = (public_key[1] & 0xf0) | 0x0f;

        assert!(provider.encapsulate(&public_key).is_none());
    }

    #[test]
    fn ml_kem_handles_are_nonzero_and_unique_while_live() {
        let mut provider = ReferenceMlKem1024Provider::new();
        let (h1, _) = provider
            .try_generate_keypair()
            .expect("ML-KEM key generation");
        let (h2, _) = provider
            .try_generate_keypair()
            .expect("ML-KEM key generation");

        assert!(!h1.is_zero());
        assert!(!h2.is_zero());
        assert!(h1 != h2);
        assert!(provider.contains_key(&h1));
        assert!(provider.contains_key(&h2));
    }

    #[test]
    fn ml_kem_remove_key_revokes_handle_and_drops_private_key() {
        let mut provider = ReferenceMlKem1024Provider::new();
        let (handle, public_key) = provider
            .try_generate_keypair()
            .expect("ML-KEM key generation");
        let (ciphertext, _) = provider.encapsulate(&public_key).expect("encapsulation");

        assert!(provider.contains_key(&handle));
        assert!(provider.remove_key(&handle));
        assert!(!provider.contains_key(&handle));
        assert!(provider.decapsulate(&handle, &ciphertext).is_none());
        assert!(!provider.remove_key(&handle));
    }

    #[test]
    fn ml_kem_wrong_handle_fails_closed() {
        let mut provider = ReferenceMlKem1024Provider::new();
        let (_correct_handle, public_key) = provider
            .try_generate_keypair()
            .expect("ML-KEM key generation");
        let (wrong_handle, _) = provider
            .try_generate_keypair()
            .expect("second ML-KEM key generation");
        let (ciphertext, sender_shared) = provider.encapsulate(&public_key).expect("encapsulation");
        let wrong_shared = provider
            .decapsulate(&wrong_handle, &ciphertext)
            .expect("ML-KEM implicit rejection");
        assert_ne!(wrong_shared.as_bytes(), sender_shared.as_bytes());
    }

    #[test]
    fn ml_kem_bad_public_key_length_is_rejected() {
        let provider = ReferenceMlKem1024Provider::new();
        assert!(provider.encapsulate(&[1u8; 31]).is_none());
    }

    #[test]
    fn ml_kem_corrupted_ciphertext_does_not_recover_original_secret() {
        let mut provider = ReferenceMlKem1024Provider::new();
        let (handle, public_key) = provider
            .try_generate_keypair()
            .expect("ML-KEM key generation");
        let (mut ciphertext, sender_shared) =
            provider.encapsulate(&public_key).expect("encapsulation");
        ciphertext[0] ^= 0x01;
        let receiver_shared = provider
            .decapsulate(&handle, &ciphertext)
            .expect("implicit rejection");
        assert_ne!(sender_shared.as_bytes(), receiver_shared.as_bytes());
    }

    #[test]
    fn serialized_size_guards_fail_closed_before_crypto_parsing() {
        let mut kem = ReferenceMlKem1024Provider::new();
        let (handle, public_key) = kem.try_generate_keypair().expect("ML-KEM key generation");
        let (ciphertext, _) = kem.encapsulate(&public_key).expect("encapsulation");

        assert_eq!(public_key.len(), ML_KEM_1024_PUBLIC_KEY_BYTES);
        assert_eq!(ciphertext.len(), ML_KEM_1024_CIPHERTEXT_BYTES);
        assert!(kem
            .encapsulate(&public_key[..public_key.len() - 1])
            .is_none());
        assert!(kem
            .decapsulate(&handle, &ciphertext[..ciphertext.len() - 1])
            .is_none());

        let verifier = ReferencePqSignatureVerifier;
        assert!(!verifier.verify(
            AuthScheme::MlDsa87,
            &[0u8; ML_DSA_87_PUBLIC_KEY_BYTES - 1],
            b"m",
            &[0u8; ML_DSA_87_SIGNATURE_BYTES],
        ));
        assert!(!verifier.verify(
            AuthScheme::MlDsa87,
            &[0u8; ML_DSA_87_PUBLIC_KEY_BYTES],
            b"m",
            &[0u8; ML_DSA_87_SIGNATURE_BYTES + 1],
        ));
        assert!(!verifier.verify(
            AuthScheme::SlhDsaShake256s,
            &[0u8; SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES + 1],
            b"m",
            &[0u8; SLH_DSA_SHAKE_256S_SIGNATURE_BYTES],
        ));
        assert!(!verifier.verify(
            AuthScheme::SlhDsaShake256s,
            &[0u8; SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES],
            b"m",
            &[0u8; SLH_DSA_SHAKE_256S_SIGNATURE_BYTES - 1],
        ));
    }

    #[test]
    fn ml_dsa_signing_handles_are_nonzero_and_unique_while_live() {
        use crate::pq::ContextSignatureSigner;

        let mut signer = ReferencePqSigner::new();
        let (h1, _) = signer.generate_keypair(AuthScheme::MlDsa87).expect("key 1");
        let (h2, _) = signer.generate_keypair(AuthScheme::MlDsa87).expect("key 2");

        assert!(!h1.is_zero());
        assert!(!h2.is_zero());
        assert!(h1 != h2);
        assert!(signer.contains_key(&h1));
        assert!(signer.contains_key(&h2));
    }

    #[test]
    fn ml_dsa_reference_signer_uses_opaque_handle_and_context() {
        use crate::pq::{
            sign_envelope_evidence, AuthPolicy, AuthorizationDomain, AuthorizationEnvelope,
            ContextSignatureSigner,
        };

        let envelope = AuthorizationEnvelope {
            chain_id: [0x81; 32],
            domain: AuthorizationDomain::ValidatorVote,
            epoch: 3,
            nonce: 7,
            expires_at: 10_000,
            payload_commitment: [0x82; 32],
        };

        let mut signer = ReferencePqSigner::new();
        let (handle, _public_key) = signer
            .generate_keypair(AuthScheme::MlDsa87)
            .expect("ML-DSA keypair");
        assert!(signer.contains_key(&handle));

        let evidence = sign_envelope_evidence(
            &signer,
            AuthScheme::MlDsa87,
            &handle,
            AuthPolicy::PqOnly,
            &envelope,
        )
        .expect("ML-DSA envelope evidence");

        let message = envelope.canonical_message(AuthPolicy::PqOnly).unwrap();
        let context = envelope.fips_signature_context(AuthPolicy::PqOnly).unwrap();
        let verifier = ReferencePqSignatureVerifier;
        assert!(verifier.verify_with_context(
            AuthScheme::MlDsa87,
            &evidence.public_key,
            &message,
            &context,
            &evidence.signature,
        ));

        let mut wrong_domain = envelope.clone();
        wrong_domain.domain = AuthorizationDomain::Governance;
        let wrong_context = wrong_domain
            .fips_signature_context(AuthPolicy::PqOnly)
            .unwrap();
        assert!(!verifier.verify_with_context(
            AuthScheme::MlDsa87,
            &evidence.public_key,
            &message,
            &wrong_context,
            &evidence.signature,
        ));

        assert!(signer.remove_key(AuthScheme::MlDsa87, &handle));
        assert!(!signer.contains_key(&handle));
        assert!(sign_envelope_evidence(
            &signer,
            AuthScheme::MlDsa87,
            &handle,
            AuthPolicy::PqOnly,
            &envelope,
        )
        .is_none());
    }

    #[test]
    fn slh_reference_signer_is_zeroizing_and_cross_verifies() {
        use crate::pq::ContextSignatureSigner;

        let mut signer = ReferencePqSigner::new();
        let (handle, public_key) = signer
            .generate_keypair(AuthScheme::SlhDsaShake256s)
            .expect("SLH-DSA keypair");
        assert!(signer.contains_key(&handle));

        let message = b"SYNERGY/PQ/SLH-LIVE/v1";
        let context = b"SYNERGY/context/live-signer";
        let signature = signer
            .sign_with_context(AuthScheme::SlhDsaShake256s, &handle, message, context)
            .expect("SLH-DSA context signature");

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
            b"tampered",
            context,
            &signature,
        ));

        assert!(signer.remove_key(AuthScheme::SlhDsaShake256s, &handle));
        assert!(!signer.contains_key(&handle));
        assert!(signer
            .sign_with_context(AuthScheme::SlhDsaShake256s, &handle, message, context,)
            .is_none());
        assert!(signer.generate_keypair(AuthScheme::Secp256k1).is_none());
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
        let corruption_index = corrupted.len() / 2;
        corrupted[corruption_index] ^= 0x80;
        assert!(!verifier.verify(AuthScheme::MlDsa87, &public_key, message, &corrupted));
    }

    #[test]
    fn slh_dsa_shake_256s_real_sign_verify_and_negative_message() {
        use slh_dsa::signature::{Keypair, Signer};
        use slh_dsa::{Shake256s, SigningKey};

        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::<Shake256s>::new(&mut rng);
        let public_key = signing_key.verifying_key().to_vec();
        let message = b"SYNERGY/PQ/COLD/v1";
        let signature = signing_key
            .try_sign(message)
            .expect("SLH-DSA sign")
            .to_vec();

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
            .expanded_key()
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
        use slh_dsa::signature::Keypair;
        use slh_dsa::{Shake256s, SigningKey};

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
            Generate, Keypair as MlKeypair, MlDsa87, SignatureEncoding, SigningKey as MlSigningKey,
        };
        use slh_dsa::signature::Keypair as SlhKeypair;
        use slh_dsa::{Shake256s, SigningKey as SlhSigningKey};

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
            .expanded_key()
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
            &verifier, &auth, &message, &context,
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

        let wrong_policy_context = envelope.fips_signature_context(AuthPolicy::Max).unwrap();
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
            verify_authorization_with_context, AuthPolicy, AuthorizationDomain,
            AuthorizationEnvelope, HybridAuthorization, SignatureEvidence,
        };
        use ml_dsa::{
            Generate, Keypair as MlKeypair, MlDsa87, SignatureEncoding, SigningKey as MlSigningKey,
        };
        use slh_dsa::signature::Keypair as SlhKeypair;
        use slh_dsa::{Shake256s, SigningKey as SlhSigningKey};

        let envelope = AuthorizationEnvelope {
            chain_id: [1; 32],
            domain: AuthorizationDomain::Transaction,
            epoch: 7,
            nonce: 42,
            expires_at: 999,
            payload_commitment: [2; 32],
        };
        let message = envelope.canonical_message(AuthPolicy::PqOnly).unwrap();
        let context = envelope.fips_signature_context(AuthPolicy::PqOnly).unwrap();

        let ml_sk = MlSigningKey::<MlDsa87>::generate();
        let ml_pk = ml_sk.verifying_key().encode().to_vec();
        let ml_sig = ml_sk
            .expanded_key()
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

        assert!(verify_authorization_with_context(
            &ReferencePqSignatureVerifier,
            &auth,
            &message,
            &context,
        ));

        let wrong_policy_message = envelope.canonical_message(AuthPolicy::Online).unwrap();
        assert!(!verify_authorization_with_context(
            &ReferencePqSignatureVerifier,
            &auth,
            &wrong_policy_message,
            &context,
        ));
    }

    #[test]
    fn max_authorization_requires_classical_and_both_real_pq_lanes() {
        use crate::pq::{
            verify_authorization_with_context, AuthPolicy, AuthorizationDomain,
            AuthorizationEnvelope, HybridAuthorization, SchemeRoutedVerifier, SignatureEvidence,
        };
        use ml_dsa::{
            Generate, Keypair as MlKeypair, MlDsa87, SignatureEncoding, SigningKey as MlSigningKey,
        };
        use slh_dsa::signature::Keypair as SlhKeypair;
        use slh_dsa::{Shake256s, SigningKey as SlhSigningKey};

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
                    && public_key.len()
                        == AuthScheme::Secp256k1.expected_public_key_bytes().unwrap()
                    && public_key.first() == Some(&0x02)
                    && signature.len() == AuthScheme::Secp256k1.expected_signature_bytes().unwrap()
                    && signature[31] == 1
                    && signature[63] == 1
                    && signature[64] == 0
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
        let context = envelope.fips_signature_context(AuthPolicy::Max).unwrap();

        let ml_sk = MlSigningKey::<MlDsa87>::generate();
        let ml_pk = ml_sk.verifying_key().encode().to_vec();
        let ml_sig = ml_sk
            .expanded_key()
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

        let verifier = SchemeRoutedVerifier {
            classical: TestClassicalVerifier,
            pq: ReferencePqSignatureVerifier,
        };

        let mut classical_public_key =
            vec![1; AuthScheme::Secp256k1.expected_public_key_bytes().unwrap()];
        classical_public_key[0] = 0x02;
        let mut classical_signature =
            vec![0; AuthScheme::Secp256k1.expected_signature_bytes().unwrap()];
        classical_signature[31] = 1;
        classical_signature[63] = 1;
        classical_signature[64] = 0;

        let mut auth = HybridAuthorization {
            policy: AuthPolicy::Max,
            evidence: vec![
                SignatureEvidence {
                    scheme: AuthScheme::Secp256k1,
                    public_key: classical_public_key,
                    signature: classical_signature,
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

        assert!(verify_authorization_with_context(
            &verifier, &auth, &message, &context,
        ));

        auth.evidence[0].signature[31] = 2;
        assert!(!verify_authorization_with_context(
            &verifier, &auth, &message, &context,
        ));
    }

    #[test]
    fn pq_verifier_never_claims_classical_lanes() {
        let verifier = ReferencePqSignatureVerifier;
        assert!(!verifier.verify(AuthScheme::Secp256k1, &[], b"x", &[]));
        assert!(!verifier.verify(AuthScheme::Ed25519, &[], b"x", &[]));
    }
}
