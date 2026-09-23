use sha2::{Digest, Sha256};

use crate::pq::{
    verify_envelope_authorization, AuthPolicy, AuthorizationDomain, AuthorizationEnvelope,
    AuthorizationValidationContext, ContextSignatureVerifier, HybridAuthorization,
};

const GOVERNANCE_ACTION_DOMAIN: &[u8] = b"SYNERGY/GOVERNANCE-ACTION/V1\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovernanceAction {
    pub proposal_id: [u8; 32],
    pub action_commitment: [u8; 32],
    pub governance_state_root: [u8; 32],
    pub activation_epoch: u64,
}

impl GovernanceAction {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.proposal_id == [0u8; 32]
            || self.action_commitment == [0u8; 32]
            || self.governance_state_root == [0u8; 32]
        {
            return Err("governance commitments required");
        }
        if self.activation_epoch == 0 {
            return Err("governance activation epoch required");
        }
        Ok(())
    }

    pub fn authorization_commitment(&self) -> Option<[u8; 32]> {
        self.validate().ok()?;
        let mut hasher = Sha256::new();
        hasher.update(GOVERNANCE_ACTION_DOMAIN);
        hasher.update(self.proposal_id);
        hasher.update(self.action_commitment);
        hasher.update(self.governance_state_root);
        hasher.update(self.activation_epoch.to_be_bytes());
        Some(hasher.finalize().into())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovernanceAuthorization {
    pub chain_id: [u8; 32],
    pub epoch: u64,
    pub nonce: u64,
    pub expires_at: u64,
    pub action: GovernanceAction,
    pub authorization: HybridAuthorization,
}

impl GovernanceAuthorization {
    pub fn envelope(&self) -> Option<AuthorizationEnvelope> {
        Some(AuthorizationEnvelope {
            chain_id: self.chain_id,
            domain: AuthorizationDomain::Governance,
            epoch: self.epoch,
            nonce: self.nonce,
            expires_at: self.expires_at,
            payload_commitment: self.action.authorization_commitment()?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GovernanceValidationContext {
    pub expected_chain_id: [u8; 32],
    pub expected_epoch: u64,
    pub expected_nonce: u64,
    pub expected_proposal_id: [u8; 32],
    pub expected_governance_state_root: [u8; 32],
    pub expected_authority_keyset_commitment: [u8; 32],
    pub expected_activation_epoch: u64,
    pub now: u64,
    pub max_future_seconds: u64,
}

pub fn verify_governance_action<V: ContextSignatureVerifier>(
    verifier: &V,
    authorized: &GovernanceAuthorization,
    validation: &GovernanceValidationContext,
) -> bool {
    if authorized.authorization.policy != AuthPolicy::Max
        || authorized.action.validate().is_err()
        || authorized.action.proposal_id != validation.expected_proposal_id
        || authorized.action.governance_state_root != validation.expected_governance_state_root
        || authorized.action.activation_epoch != validation.expected_activation_epoch
        || authorized.authorization.keyset_commitment()
            != Some(validation.expected_authority_keyset_commitment)
    {
        return false;
    }

    let envelope = match authorized.envelope() {
        Some(envelope) => envelope,
        None => return false,
    };

    let auth_validation = AuthorizationValidationContext {
        expected_chain_id: validation.expected_chain_id,
        expected_domain: AuthorizationDomain::Governance,
        expected_policy: AuthPolicy::Max,
        expected_epoch: validation.expected_epoch,
        expected_nonce: validation.expected_nonce,
        now: validation.now,
        max_future_seconds: validation.max_future_seconds,
    };

    verify_envelope_authorization(
        verifier,
        &authorized.authorization,
        &envelope,
        &auth_validation,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pq::{
        AuthScheme, ContextSignatureVerifier, SignatureEvidence, ML_DSA_87_PUBLIC_KEY_BYTES,
        ML_DSA_87_SIGNATURE_BYTES, SECP256K1_PUBLIC_KEY_BYTES, SECP256K1_SIGNATURE_BYTES,
        SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES, SLH_DSA_SHAKE_256S_SIGNATURE_BYTES,
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

    fn max_authorization() -> HybridAuthorization {
        let mut secp_key = vec![1u8; SECP256K1_PUBLIC_KEY_BYTES];
        secp_key[0] = 0x02;
        let mut secp_sig = vec![2u8; SECP256K1_SIGNATURE_BYTES];
        secp_sig[SECP256K1_SIGNATURE_BYTES - 1] = 0;

        HybridAuthorization {
            policy: AuthPolicy::Max,
            evidence: vec![
                SignatureEvidence {
                    scheme: AuthScheme::Secp256k1,
                    public_key: secp_key,
                    signature: secp_sig,
                },
                SignatureEvidence {
                    scheme: AuthScheme::MlDsa87,
                    public_key: vec![3u8; ML_DSA_87_PUBLIC_KEY_BYTES],
                    signature: vec![4u8; ML_DSA_87_SIGNATURE_BYTES],
                },
                SignatureEvidence {
                    scheme: AuthScheme::SlhDsaShake256s,
                    public_key: vec![5u8; SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES],
                    signature: vec![6u8; SLH_DSA_SHAKE_256S_SIGNATURE_BYTES],
                },
            ],
        }
    }

    fn authorized() -> GovernanceAuthorization {
        GovernanceAuthorization {
            chain_id: [0x81; 32],
            epoch: 12,
            nonce: 13,
            expires_at: 1_100,
            action: GovernanceAction {
                proposal_id: [0x82; 32],
                action_commitment: [0x83; 32],
                governance_state_root: [0x84; 32],
                activation_epoch: 13,
            },
            authorization: max_authorization(),
        }
    }

    fn validation() -> GovernanceValidationContext {
        GovernanceValidationContext {
            expected_chain_id: [0x81; 32],
            expected_epoch: 12,
            expected_nonce: 13,
            expected_proposal_id: [0x82; 32],
            expected_governance_state_root: [0x84; 32],
            expected_authority_keyset_commitment: max_authorization()
                .keyset_commitment()
                .expect("governance authority keyset"),
            expected_activation_epoch: 13,
            now: 1_000,
            max_future_seconds: 200,
        }
    }

    #[test]
    fn governance_requires_max_state_aware_authorization() {
        let authorized = authorized();
        let envelope = authorized.envelope().expect("governance envelope");
        let verifier = ExpectedVerifier {
            message: envelope
                .canonical_message(AuthPolicy::Max)
                .expect("governance message"),
            context: envelope
                .fips_signature_context(AuthPolicy::Max)
                .expect("governance context"),
        };

        assert!(verify_governance_action(
            &verifier,
            &authorized,
            &validation(),
        ));

        let mut downgraded = authorized;
        downgraded.authorization.policy = AuthPolicy::Online;
        assert!(!verify_governance_action(
            &verifier,
            &downgraded,
            &validation(),
        ));
    }

    #[test]
    fn governance_rejects_unregistered_authority_keyset() {
        let authorized = authorized();
        let envelope = authorized.envelope().expect("governance envelope");
        let verifier = ExpectedVerifier {
            message: envelope
                .canonical_message(AuthPolicy::Max)
                .expect("governance message"),
            context: envelope
                .fips_signature_context(AuthPolicy::Max)
                .expect("governance context"),
        };

        let mut validation = validation();
        validation.expected_authority_keyset_commitment[0] ^= 1;
        assert!(!verify_governance_action(
            &verifier,
            &authorized,
            &validation,
        ));
    }

    #[test]
    fn governance_rejects_wrong_activation_epoch() {
        let authorized = authorized();
        let envelope = authorized.envelope().expect("governance envelope");
        let verifier = ExpectedVerifier {
            message: envelope
                .canonical_message(AuthPolicy::Max)
                .expect("governance message"),
            context: envelope
                .fips_signature_context(AuthPolicy::Max)
                .expect("governance context"),
        };

        let mut validation = validation();
        validation.expected_activation_epoch += 1;
        assert!(!verify_governance_action(
            &verifier,
            &authorized,
            &validation,
        ));
    }

    #[test]
    fn governance_rejects_stale_state_root_or_wrong_proposal() {
        let authorized = authorized();
        let envelope = authorized.envelope().expect("governance envelope");
        let verifier = ExpectedVerifier {
            message: envelope
                .canonical_message(AuthPolicy::Max)
                .expect("governance message"),
            context: envelope
                .fips_signature_context(AuthPolicy::Max)
                .expect("governance context"),
        };

        let mut stale = validation();
        stale.expected_governance_state_root = [0x85; 32];
        assert!(!verify_governance_action(&verifier, &authorized, &stale));

        let mut wrong = validation();
        wrong.expected_proposal_id = [0x86; 32];
        assert!(!verify_governance_action(&verifier, &authorized, &wrong));
    }
}
