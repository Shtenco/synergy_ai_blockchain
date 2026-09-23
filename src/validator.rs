use sha2::{Digest, Sha256};

use crate::pq::{
    verify_envelope_authorization, AuthPolicy, AuthScheme, AuthorizationDomain,
    AuthorizationEnvelope, AuthorizationValidationContext, ContextSignatureVerifier,
    HybridAuthorization, CRYPTO_PROFILE_VERSION, ML_DSA_87_PUBLIC_KEY_BYTES,
    SECP256K1_PUBLIC_KEY_BYTES, SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValidatorPolicy {
    /// Migration mode: canonical Secp256k1 plus both independent PQ signature lanes.
    HybridTransition,
    /// Native post-quantum validator mode: ML-DSA + SLH-DSA, no classical lane.
    PqOnly,
}

impl ValidatorPolicy {
    pub const fn authorization_policy(self) -> AuthPolicy {
        match self {
            Self::HybridTransition => AuthPolicy::Max,
            Self::PqOnly => AuthPolicy::PqOnly,
        }
    }
}

const VALIDATOR_IDENTITY_DOMAIN: &[u8] = b"SYNERGY/VALIDATOR-IDENTITY/V1\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorIdentity {
    pub validator_id: [u8; 32],
    /// Canonical compressed Secp256k1 key used only during transition mode.
    pub legacy_public_key: Vec<u8>,
    pub ml_dsa87_public_key: Vec<u8>,
    pub slh_dsa_shake256s_public_key: Vec<u8>,
}

impl ValidatorIdentity {
    pub fn pq_identity_commitment(&self) -> Option<[u8; 32]> {
        if self.ml_dsa87_public_key.len() != ML_DSA_87_PUBLIC_KEY_BYTES
            || self.slh_dsa_shake256s_public_key.len() != SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES
            || self.ml_dsa87_public_key.iter().all(|byte| *byte == 0)
            || self
                .slh_dsa_shake256s_public_key
                .iter()
                .all(|byte| *byte == 0)
        {
            return None;
        }

        let mut hasher = Sha256::new();
        hasher.update(VALIDATOR_IDENTITY_DOMAIN);
        hasher.update(CRYPTO_PROFILE_VERSION.to_be_bytes());

        hasher.update([AuthScheme::MlDsa87.protocol_code()]);
        let ml_dsa_len = u64::try_from(self.ml_dsa87_public_key.len()).ok()?;
        hasher.update(ml_dsa_len.to_be_bytes());
        hasher.update(&self.ml_dsa87_public_key);

        hasher.update([AuthScheme::SlhDsaShake256s.protocol_code()]);
        let slh_dsa_len =
            u64::try_from(self.slh_dsa_shake256s_public_key.len()).ok()?;
        hasher.update(slh_dsa_len.to_be_bytes());
        hasher.update(&self.slh_dsa_shake256s_public_key);

        Some(hasher.finalize().into())
    }

    pub fn validate_for_policy(&self, policy: ValidatorPolicy) -> Result<(), &'static str> {
        if self.validator_id == [0u8; 32] {
            return Err("validator id required");
        }
        if self.pq_identity_commitment() != Some(self.validator_id) {
            return Err("validator id does not match PQ identity commitment");
        }
        if self.ml_dsa87_public_key.len() != ML_DSA_87_PUBLIC_KEY_BYTES
            || self.slh_dsa_shake256s_public_key.len() != SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES
        {
            return Err("validator PQ public key length mismatch");
        }
        if self.ml_dsa87_public_key.iter().all(|byte| *byte == 0)
            || self
                .slh_dsa_shake256s_public_key
                .iter()
                .all(|byte| *byte == 0)
        {
            return Err("validator PQ public keys must not be all-zero");
        }

        match policy {
            ValidatorPolicy::PqOnly => {
                if !self.legacy_public_key.is_empty() {
                    return Err("PQ-only validator forbids legacy public key material");
                }
                Ok(())
            }
            ValidatorPolicy::HybridTransition => {
                if self.legacy_public_key.len() != SECP256K1_PUBLIC_KEY_BYTES {
                    return Err("validator Secp256k1 public key length mismatch");
                }
                if !matches!(self.legacy_public_key.first(), Some(0x02 | 0x03)) {
                    return Err("validator Secp256k1 public key must be compressed");
                }
                Ok(())
            }
        }
    }

    fn matches_authorization(
        &self,
        policy: ValidatorPolicy,
        authorization: &HybridAuthorization,
    ) -> bool {
        if authorization.policy != policy.authorization_policy() {
            return false;
        }
        authorization.evidence.iter().all(|evidence| match evidence.scheme {
            AuthScheme::Secp256k1 => {
                matches!(policy, ValidatorPolicy::HybridTransition)
                    && evidence.public_key == self.legacy_public_key
            }
            AuthScheme::MlDsa87 => evidence.public_key == self.ml_dsa87_public_key,
            AuthScheme::SlhDsaShake256s => {
                evidence.public_key == self.slh_dsa_shake256s_public_key
            }
            AuthScheme::Ed25519 => false,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorVoteAuthorization {
    pub validator_id: [u8; 32],
    pub chain_id: [u8; 32],
    pub epoch: u64,
    pub nonce: u64,
    pub expires_at: u64,
    /// Commitment to the canonical consensus vote/block payload.
    pub vote_commitment: [u8; 32],
    pub authorization: HybridAuthorization,
}

impl ValidatorVoteAuthorization {
    pub fn envelope(&self) -> AuthorizationEnvelope {
        AuthorizationEnvelope {
            chain_id: self.chain_id,
            domain: AuthorizationDomain::ValidatorVote,
            epoch: self.epoch,
            nonce: self.nonce,
            expires_at: self.expires_at,
            payload_commitment: self.vote_commitment,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatorVoteValidationContext {
    pub expected_validator_id: [u8; 32],
    pub expected_chain_id: [u8; 32],
    pub expected_epoch: u64,
    pub expected_nonce: u64,
    pub now: u64,
    pub max_future_seconds: u64,
}

pub(crate) fn verify_validator_vote<V: ContextSignatureVerifier>(
    verifier: &V,
    policy: ValidatorPolicy,
    identity: &ValidatorIdentity,
    vote: &ValidatorVoteAuthorization,
    validation: &ValidatorVoteValidationContext,
) -> bool {
    if identity.validate_for_policy(policy).is_err()
        || identity.validator_id != validation.expected_validator_id
        || vote.validator_id != identity.validator_id
        || !identity.matches_authorization(policy, &vote.authorization)
    {
        return false;
    }

    let envelope = vote.envelope();
    let auth_validation = AuthorizationValidationContext {
        expected_chain_id: validation.expected_chain_id,
        expected_domain: AuthorizationDomain::ValidatorVote,
        expected_policy: policy.authorization_policy(),
        expected_epoch: validation.expected_epoch,
        expected_nonce: validation.expected_nonce,
        now: validation.now,
        max_future_seconds: validation.max_future_seconds,
    };

    verify_envelope_authorization(
        verifier,
        &vote.authorization,
        &envelope,
        &auth_validation,
    )
}


pub fn verify_validator_vote_and_consume<V: ContextSignatureVerifier>(
    verifier: &V,
    policy: ValidatorPolicy,
    identity: &ValidatorIdentity,
    vote: &ValidatorVoteAuthorization,
    validation: &ValidatorVoteValidationContext,
    replay: &mut AuthorizationReplayState,
) -> bool {
    if !verify_validator_vote(verifier, policy, identity, vote, validation) {
        return false;
    }
    let envelope = match Some(vote.envelope()) {
        Some(envelope) => envelope,
        None => return false,
    };
    replay.consume_verified(&vote.authorization, &envelope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pq::{
        ContextSignatureVerifier, SignatureEvidence, ML_DSA_87_SIGNATURE_BYTES,
        SECP256K1_SIGNATURE_BYTES, SLH_DSA_SHAKE_256S_SIGNATURE_BYTES,
    };

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

    fn identity_for(policy: ValidatorPolicy) -> ValidatorIdentity {
        let mut secp = vec![1u8; SECP256K1_PUBLIC_KEY_BYTES];
        secp[0] = 0x02;
        let mut identity = ValidatorIdentity {
            validator_id: [0u8; 32],
            legacy_public_key: if matches!(policy, ValidatorPolicy::HybridTransition) {
                secp
            } else {
                Vec::new()
            },
            ml_dsa87_public_key: vec![0x22; ML_DSA_87_PUBLIC_KEY_BYTES],
            slh_dsa_shake256s_public_key: vec![0x33; SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES],
        };
        identity.validator_id = identity
            .pq_identity_commitment()
            .expect("validator PQ identity commitment");
        identity
    }

    fn evidence(scheme: AuthScheme, public_key: Vec<u8>) -> SignatureEvidence {
        let mut signature = vec![
            0x44;
            match scheme {
                AuthScheme::Secp256k1 => SECP256K1_SIGNATURE_BYTES,
                AuthScheme::MlDsa87 => ML_DSA_87_SIGNATURE_BYTES,
                AuthScheme::SlhDsaShake256s => SLH_DSA_SHAKE_256S_SIGNATURE_BYTES,
                AuthScheme::Ed25519 => unreachable!(),
            }
        ];
        if scheme == AuthScheme::Secp256k1 {
            let last = signature.len() - 1;
            signature[last] = 0;
        }
        SignatureEvidence {
            scheme,
            public_key,
            signature,
        }
    }

    fn vote(policy: ValidatorPolicy) -> ValidatorVoteAuthorization {
        let identity = identity_for(policy);
        let evidence = match policy {
            ValidatorPolicy::HybridTransition => vec![
                evidence(AuthScheme::Secp256k1, identity.legacy_public_key.clone()),
                evidence(AuthScheme::MlDsa87, identity.ml_dsa87_public_key.clone()),
                evidence(
                    AuthScheme::SlhDsaShake256s,
                    identity.slh_dsa_shake256s_public_key.clone(),
                ),
            ],
            ValidatorPolicy::PqOnly => vec![
                evidence(AuthScheme::MlDsa87, identity.ml_dsa87_public_key.clone()),
                evidence(
                    AuthScheme::SlhDsaShake256s,
                    identity.slh_dsa_shake256s_public_key.clone(),
                ),
            ],
        };
        ValidatorVoteAuthorization {
            validator_id: identity.validator_id,
            chain_id: [0x55; 32],
            epoch: 9,
            nonce: 10,
            expires_at: 1_100,
            vote_commitment: [0x66; 32],
            authorization: HybridAuthorization {
                policy: policy.authorization_policy(),
                evidence,
            },
        }
    }

    fn validation() -> ValidatorVoteValidationContext {
        ValidatorVoteValidationContext {
            expected_validator_id: identity_for(ValidatorPolicy::PqOnly).validator_id,
            expected_chain_id: [0x55; 32],
            expected_epoch: 9,
            expected_nonce: 10,
            now: 1_000,
            max_future_seconds: 200,
        }
    }

    #[test]
    fn validator_id_is_stable_across_legacy_key_retirement() {
        let hybrid = identity_for(ValidatorPolicy::HybridTransition);
        let pq_only = identity_for(ValidatorPolicy::PqOnly);
        assert_eq!(hybrid.validator_id, pq_only.validator_id);
    }

    #[test]
    fn validator_id_rejects_pq_key_substitution() {
        let mut identity = identity_for(ValidatorPolicy::PqOnly);
        identity.ml_dsa87_public_key[0] ^= 1;
        assert!(identity.validate_for_policy(ValidatorPolicy::PqOnly).is_err());
    }

    #[test]
    fn pq_only_validator_identity_rejects_legacy_key_material() {
        let mut identity = identity_for(ValidatorPolicy::PqOnly);
        assert_eq!(identity.validate_for_policy(ValidatorPolicy::PqOnly), Ok(()));

        let mut legacy = vec![1u8; SECP256K1_PUBLIC_KEY_BYTES];
        legacy[0] = 0x02;
        identity.legacy_public_key = legacy;
        assert!(identity.validate_for_policy(ValidatorPolicy::PqOnly).is_err());
    }

    #[test]
    fn pq_only_vote_uses_state_aware_fips_authorization() {
        let identity = identity_for(ValidatorPolicy::PqOnly);
        let vote = vote(ValidatorPolicy::PqOnly);
        let envelope = vote.envelope();
        let verifier = ExpectedVerifier {
            message: envelope
                .canonical_message(vote.authorization.policy)
                .expect("canonical vote"),
            context: envelope
                .fips_signature_context(vote.authorization.policy)
                .expect("vote context"),
        };
        assert!(verify_validator_vote(
            &verifier,
            ValidatorPolicy::PqOnly,
            &identity,
            &vote,
            &validation(),
        ));
    }

    #[test]
    fn validator_vote_rejects_policy_downgrade_and_key_substitution() {
        let identity = identity_for(ValidatorPolicy::HybridTransition);
        let mut vote = vote(ValidatorPolicy::HybridTransition);
        let envelope = vote.envelope();
        let verifier = ExpectedVerifier {
            message: envelope
                .canonical_message(vote.authorization.policy)
                .expect("canonical vote"),
            context: envelope
                .fips_signature_context(vote.authorization.policy)
                .expect("vote context"),
        };

        assert!(verify_validator_vote(
            &verifier,
            ValidatorPolicy::HybridTransition,
            &identity,
            &vote,
            &validation(),
        ));

        vote.authorization.policy = AuthPolicy::Online;
        assert!(!verify_validator_vote(
            &verifier,
            ValidatorPolicy::HybridTransition,
            &identity,
            &vote,
            &validation(),
        ));

        let mut vote = vote(ValidatorPolicy::HybridTransition);
        vote.authorization.evidence[1].public_key[0] ^= 1;
        assert!(!verify_validator_vote(
            &verifier,
            ValidatorPolicy::HybridTransition,
            &identity,
            &vote,
            &validation(),
        ));
    }

    #[test]
    fn validator_vote_rejects_chain_epoch_nonce_and_expiry_replay() {
        let identity = identity_for(ValidatorPolicy::PqOnly);
        let vote = vote(ValidatorPolicy::PqOnly);
        let envelope = vote.envelope();
        let verifier = ExpectedVerifier {
            message: envelope
                .canonical_message(vote.authorization.policy)
                .expect("canonical vote"),
            context: envelope
                .fips_signature_context(vote.authorization.policy)
                .expect("vote context"),
        };

        let mut bad = validation();
        bad.expected_nonce += 1;
        assert!(!verify_validator_vote(
            &verifier,
            ValidatorPolicy::PqOnly,
            &identity,
            &vote,
            &bad,
        ));

        let mut bad = validation();
        bad.expected_epoch += 1;
        assert!(!verify_validator_vote(
            &verifier,
            ValidatorPolicy::PqOnly,
            &identity,
            &vote,
            &bad,
        ));

        let mut bad = validation();
        bad.now = vote.expires_at;
        assert!(!verify_validator_vote(
            &verifier,
            ValidatorPolicy::PqOnly,
            &identity,
            &vote,
            &bad,
        ));
    }
}
