use ml_dsa::{
    EncodedSignature, Generate, Keypair, MlDsa65, Signature, Signer, SigningKey, Verifier,
};

/// Real FIPS-204 ML-DSA-65 signer for Secure Event Fabric integration.
///
/// This reference provider keeps the private key in process memory. Production
/// deployment must replace key generation/storage with the project key-management
/// or HSM boundary; the event fabric itself must never own treasury/validator keys.
pub struct MlDsa65EventSigner {
    key_id: String,
    signer_repo: String,
    signing_key: SigningKey<MlDsa65>,
}

impl MlDsa65EventSigner {
    pub const ALGORITHM: &'static str = "ML-DSA-65";

    pub fn generate(key_id: impl Into<String>, signer_repo: impl Into<String>) -> Self {
        Self {
            key_id: key_id.into(),
            signer_repo: signer_repo.into(),
            signing_key: SigningKey::<MlDsa65>::generate(),
        }
    }

    pub fn algorithm(&self) -> &'static str {
        Self::ALGORITHM
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn signer_repo(&self) -> &str {
        &self.signer_repo
    }

    pub fn sign(&self, message: &[u8]) -> EncodedSignature<MlDsa65> {
        let signature: Signature<MlDsa65> = self.signing_key.sign(message);
        signature.encode()
    }

    pub fn verify(&self, message: &[u8], encoded: &EncodedSignature<MlDsa65>) -> bool {
        let Some(signature) = Signature::<MlDsa65>::decode(encoded) else {
            return false;
        };
        self.signing_key
            .verifying_key()
            .verify(message, &signature)
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_ml_dsa_65_signs_and_verifies_event_bytes() {
        let signer = MlDsa65EventSigner::generate(
            "midas-event-key-1",
            "Shtenco/midas_ai",
        );
        let message = br#"{"event_id":"event-1","payload_hash":"abc"}"#;
        let signature = signer.sign(message);

        assert_eq!(signer.algorithm(), "ML-DSA-65");
        assert_eq!(signer.key_id(), "midas-event-key-1");
        assert_eq!(signer.signer_repo(), "Shtenco/midas_ai");
        assert!(signer.verify(message, &signature));
        assert!(!signer.verify(b"tampered-event", &signature));
    }

    #[test]
    fn independent_keys_cannot_verify_each_others_signatures() {
        let first = MlDsa65EventSigner::generate("key-1", "Shtenco/midas_ai");
        let second = MlDsa65EventSigner::generate("key-2", "Shtenco/midas_ai");
        let message = b"canonical secure event bytes";
        let signature = first.sign(message);

        assert!(first.verify(message, &signature));
        assert!(!second.verify(message, &signature));
    }
}
