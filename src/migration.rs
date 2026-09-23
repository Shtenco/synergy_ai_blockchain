use sha2::{Digest, Sha256};

use crate::pq::{
    verify_envelope_authorization, AuthPolicy, AuthorizationDomain, AuthorizationEnvelope,
    AuthorizationReplayState, AuthorizationValidationContext, ContextSignatureVerifier, HybridAuthorization,
};

const MIGRATION_BINDING_DOMAIN: &[u8] = b"SYNERGY/BRIDGE-MIGRATION/V1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LegacyChain {
    Bitcoin,
    Ethereum,
    Solana,
    Other(u32),
}

impl LegacyChain {
    fn append_canonical(self, out: &mut Vec<u8>) {
        match self {
            Self::Bitcoin => out.push(1),
            Self::Ethereum => out.push(2),
            Self::Solana => out.push(3),
            Self::Other(code) => {
                out.push(255);
                out.extend_from_slice(&code.to_be_bytes());
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyIdentityBinding {
    pub source_chain: LegacyChain,
    /// Canonical raw address/public-key encoding for the source chain.
    pub legacy_identifier: Vec<u8>,
    /// Commitment to the independently generated target PQ identity/key set.
    pub pq_identity_commitment: [u8; 32],
    pub synergy_account_id: [u8; 32],
    pub nonce: u64,
    pub expires_at: u64,
}

impl LegacyIdentityBinding {
    pub fn validate(&self) -> Result<(), MigrationError> {
        if self.legacy_identifier.is_empty() {
            return Err(MigrationError::EmptyLegacyIdentifier);
        }
        if self.legacy_identifier.len() > 4_096 {
            return Err(MigrationError::LegacyIdentifierTooLarge);
        }
        if self.pq_identity_commitment == [0u8; 32] {
            return Err(MigrationError::EmptyPqIdentityCommitment);
        }
        if self.synergy_account_id == [0u8; 32] {
            return Err(MigrationError::EmptySynergyAccount);
        }
        if self.expires_at == 0 {
            return Err(MigrationError::Expired);
        }
        Ok(())
    }

    pub fn payload_commitment(&self) -> Option<[u8; 32]> {
        self.validate().ok()?;

        let mut encoded = Vec::with_capacity(
            MIGRATION_BINDING_DOMAIN.len() + self.legacy_identifier.len() + 80,
        );
        encoded.extend_from_slice(MIGRATION_BINDING_DOMAIN);
        self.source_chain.append_canonical(&mut encoded);
        let legacy_identifier_len =
            u64::try_from(self.legacy_identifier.len()).ok()?;
        encoded.extend_from_slice(&legacy_identifier_len.to_be_bytes());
        encoded.extend_from_slice(&self.legacy_identifier);
        encoded.extend_from_slice(&self.pq_identity_commitment);
        encoded.extend_from_slice(&self.synergy_account_id);

        let commitment: [u8; 32] = Sha256::digest(&encoded).into();
        Some(commitment)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationError {
    EmptyLegacyIdentifier,
    LegacyIdentifierTooLarge,
    EmptyPqIdentityCommitment,
    EmptySynergyAccount,
    Expired,
    PolicyMismatch,
    InvalidLegacyProof,
    InvalidPqAuthorization,
}

pub trait LegacyProofVerifier {
    fn verify_legacy_ownership(&self, binding: &LegacyIdentityBinding, proof: &[u8]) -> bool;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationAuthorization {
    pub chain_id: [u8; 32],
    pub epoch: u64,
    pub binding: LegacyIdentityBinding,
    pub authorization: HybridAuthorization,
}

impl MigrationAuthorization {
    pub fn envelope(&self) -> Option<AuthorizationEnvelope> {
        Some(AuthorizationEnvelope {
            chain_id: self.chain_id,
            domain: AuthorizationDomain::BridgeMigration,
            epoch: self.epoch,
            nonce: self.binding.nonce,
            expires_at: self.binding.expires_at,
            payload_commitment: self.binding.payload_commitment()?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MigrationValidationContext {
    pub expected_chain_id: [u8; 32],
    pub expected_epoch: u64,
    pub expected_nonce: u64,
    pub now: u64,
    pub max_future_seconds: u64,
}

pub(crate) fn verify_binding<L: LegacyProofVerifier, P: ContextSignatureVerifier>(
    binding: &MigrationAuthorization,
    legacy_proof: &[u8],
    legacy: &L,
    pq: &P,
    validation: &MigrationValidationContext,
) -> Result<(), MigrationError> {
    binding.binding.validate()?;

    if binding.authorization.policy != AuthPolicy::PqOnly {
        return Err(MigrationError::PolicyMismatch);
    }
    if binding.authorization.keyset_commitment()
        != Some(binding.binding.pq_identity_commitment)
        || binding.authorization.primary_account_identity_commitment()
            != Some(binding.binding.synergy_account_id)
    {
        return Err(MigrationError::InvalidPqAuthorization);
    }
    if !legacy.verify_legacy_ownership(&binding.binding, legacy_proof) {
        return Err(MigrationError::InvalidLegacyProof);
    }

    let envelope = binding
        .envelope()
        .ok_or(MigrationError::InvalidPqAuthorization)?;
    let auth_validation = AuthorizationValidationContext {
        expected_chain_id: validation.expected_chain_id,
        expected_domain: AuthorizationDomain::BridgeMigration,
        expected_policy: AuthPolicy::PqOnly,
        expected_epoch: validation.expected_epoch,
        expected_nonce: validation.expected_nonce,
        now: validation.now,
        max_future_seconds: validation.max_future_seconds,
    };

    if !verify_envelope_authorization(
        pq,
        &binding.authorization,
        &envelope,
        &auth_validation,
    ) {
        return Err(MigrationError::InvalidPqAuthorization);
    }

    Ok(())
}


pub fn verify_binding_and_consume<L: LegacyProofVerifier, P: ContextSignatureVerifier>(
    binding: &MigrationAuthorization,
    legacy_proof: &[u8],
    legacy: &L,
    pq: &P,
    validation: &MigrationValidationContext,
    replay: &mut AuthorizationReplayState,
) -> Result<(), MigrationError> {
    verify_binding(binding, legacy_proof, legacy, pq, validation)?;
    let envelope = binding
        .envelope()
        .ok_or(MigrationError::InvalidPqAuthorization)?;
    if !replay.consume_verified_for_subject(
        &binding.authorization,
        &envelope,
        binding.binding.pq_identity_commitment,
    ) {
        return Err(MigrationError::InvalidPqAuthorization);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pq::{
        AuthScheme, ContextSignatureVerifier, SignatureEvidence, ML_DSA_87_PUBLIC_KEY_BYTES,
        ML_DSA_87_SIGNATURE_BYTES, SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES,
        SLH_DSA_SHAKE_256S_SIGNATURE_BYTES,
    };

    struct LegacyOk;
    impl LegacyProofVerifier for LegacyOk {
        fn verify_legacy_ownership(&self, _binding: &LegacyIdentityBinding, proof: &[u8]) -> bool {
            proof == b"legacy-ok"
        }
    }

    #[derive(Clone)]
    struct ExpectedVerifier {
        message: Vec<u8>,
        context: Vec<u8>,
    }

    impl ContextSignatureVerifier for ExpectedVerifier {
        fn verify_with_context(
            &self,
            _scheme: AuthScheme,
            _public_key: &[u8],
            message: &[u8],
            context: &[u8],
            _signature: &[u8],
        ) -> bool {
            message == self.message && context == self.context
        }
    }

    fn authorization() -> MigrationAuthorization {
        let authorization = HybridAuthorization {
            policy: AuthPolicy::PqOnly,
            evidence: vec![
                    SignatureEvidence {
                        scheme: AuthScheme::MlDsa87,
                        public_key: vec![0x44; ML_DSA_87_PUBLIC_KEY_BYTES],
                        signature: vec![0x45; ML_DSA_87_SIGNATURE_BYTES],
                    },
                    SignatureEvidence {
                        scheme: AuthScheme::SlhDsaShake256s,
                        public_key: vec![0x46; SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES],
                        signature: vec![0x47; SLH_DSA_SHAKE_256S_SIGNATURE_BYTES],
                    },
            ],
        };
        let pq_identity_commitment = authorization
            .keyset_commitment()
            .expect("migration PQ identity commitment");
        let synergy_account_id = authorization
            .primary_account_identity_commitment()
            .expect("migration primary account identity");

        MigrationAuthorization {
            chain_id: [0x51; 32],
            epoch: 8,
            binding: LegacyIdentityBinding {
                source_chain: LegacyChain::Ethereum,
                legacy_identifier: vec![0x11; 20],
                pq_identity_commitment,
                synergy_account_id,
                nonce: 17,
                expires_at: 2_000,
            },
            authorization,
        }
    }

    fn validation() -> MigrationValidationContext {
        MigrationValidationContext {
            expected_chain_id: [0x51; 32],
            expected_epoch: 8,
            expected_nonce: 17,
            now: 1_900,
            max_future_seconds: 200,
        }
    }

    #[test]
    fn migration_requires_legacy_and_dual_pq_proof() {
        let binding = authorization();
        let envelope = binding.envelope().expect("migration envelope");
        let verifier = ExpectedVerifier {
            message: envelope
                .canonical_message(AuthPolicy::PqOnly)
                .expect("migration message"),
            context: envelope
                .fips_signature_context(AuthPolicy::PqOnly)
                .expect("migration context"),
        };

        assert_eq!(
            verify_binding(
                &binding,
                b"legacy-ok",
                &LegacyOk,
                &verifier,
                &validation(),
            ),
            Ok(())
        );
        assert_eq!(
            verify_binding(
                &binding,
                b"wrong",
                &LegacyOk,
                &verifier,
                &validation(),
            ),
            Err(MigrationError::InvalidLegacyProof)
        );
    }

    #[test]
    fn migration_rejects_replay_and_policy_downgrade() {
        let binding = authorization();
        let envelope = binding.envelope().expect("migration envelope");
        let verifier = ExpectedVerifier {
            message: envelope
                .canonical_message(AuthPolicy::PqOnly)
                .expect("migration message"),
            context: envelope
                .fips_signature_context(AuthPolicy::PqOnly)
                .expect("migration context"),
        };

        let mut bad_validation = validation();
        bad_validation.expected_nonce += 1;
        assert_eq!(
            verify_binding(
                &binding,
                b"legacy-ok",
                &LegacyOk,
                &verifier,
                &bad_validation,
            ),
            Err(MigrationError::InvalidPqAuthorization)
        );

        let mut downgraded = binding;
        downgraded.authorization.policy = AuthPolicy::Online;
        assert_eq!(
            verify_binding(
                &downgraded,
                b"legacy-ok",
                &LegacyOk,
                &verifier,
                &validation(),
            ),
            Err(MigrationError::PolicyMismatch)
        );
    }

    #[test]
    fn migration_consuming_api_accepts_nonce_once() {
        let binding = authorization();
        let envelope = binding.envelope().expect("migration envelope");
        let verifier = ExpectedVerifier {
            message: envelope
                .canonical_message(AuthPolicy::PqOnly)
                .expect("migration message"),
            context: envelope
                .fips_signature_context(AuthPolicy::PqOnly)
                .expect("migration context"),
        };
        let validation = validation();
        let mut replay = AuthorizationReplayState::new(
            binding.chain_id,
            AuthorizationDomain::BridgeMigration,
            AuthPolicy::PqOnly,
            binding.epoch,
            binding.binding.nonce,
        )
        .expect("migration replay state");

        assert_eq!(
            verify_binding_and_consume(
                &binding,
                b"legacy-ok",
                &LegacyOk,
                &verifier,
                &validation,
                &mut replay,
            ),
            Ok(())
        );
        assert_eq!(
            verify_binding_and_consume(
                &binding,
                b"legacy-ok",
                &LegacyOk,
                &verifier,
                &validation,
                &mut replay,
            ),
            Err(MigrationError::InvalidPqAuthorization)
        );
    }

    #[test]
    fn migration_rejects_pq_keyset_substitution() {
        let mut binding = authorization();
        let envelope = binding.envelope().expect("migration envelope");
        let verifier = ExpectedVerifier {
            message: envelope
                .canonical_message(AuthPolicy::PqOnly)
                .expect("migration message"),
            context: envelope
                .fips_signature_context(AuthPolicy::PqOnly)
                .expect("migration context"),
        };

        binding.authorization.evidence[0].public_key[0] ^= 1;
        assert_eq!(
            verify_binding(
                &binding,
                b"legacy-ok",
                &LegacyOk,
                &verifier,
                &validation(),
            ),
            Err(MigrationError::InvalidPqAuthorization)
        );
    }

    #[test]
    fn migration_payload_commitment_binds_old_and_new_identity() {
        let binding = authorization().binding;
        let base = binding.payload_commitment().expect("commitment");

        let mut changed = binding.clone();
        changed.synergy_account_id[0] ^= 1;
        assert_ne!(
            base,
            changed.payload_commitment().expect("changed account identity")
        );

        let mut changed = binding;
        changed.pq_identity_commitment[0] ^= 1;
        assert_ne!(
            base,
            changed.payload_commitment().expect("changed authority keyset")
        );
    }
}
