//! Consensus-neutral canonical commitments for Autopilot budget lifecycle.
//!
//! AI planning is never signing authority. A value-bearing execution may be
//! authorized only after a budget reservation has already occupied both the
//! delegated grant and (when present) company-wide epoch envelope.

use sha2::{Digest, Sha256};

use crate::pq::{
    verify_envelope_authorization, AuthPolicy, AuthorizationDomain, AuthorizationEnvelope,
    AuthorizationReplayState, AuthorizationValidationContext, ContextSignatureVerifier,
    HybridAuthorization,
};

const AUTOPILOT_EXECUTION_DOMAIN: &[u8] = b"SYNERGY/AUTOPILOT-EXECUTION/V1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutopilotBudgetReservation {
    pub reservation_id: [u8; 32],
    pub owner_account: [u8; 32],
    pub reservation_root: [u8; 32],
    pub policy_root: [u8; 32],
    pub grant_root: [u8; 32],
    pub company_budget_root: Option<[u8; 32]>,
    pub company_graph_root: Option<[u8; 32]>,
    pub epoch: u64,
    pub reserved_value: u128,
    pub expires_at: u64,
}

impl AutopilotBudgetReservation {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.reservation_id == [0; 32]
            || self.owner_account == [0; 32]
            || self.reservation_root == [0; 32]
            || self.policy_root == [0; 32]
            || self.grant_root == [0; 32]
        {
            return Err("reservation/policy/grant commitments required");
        }
        if self.epoch == 0 || self.expires_at == 0 {
            return Err("reservation epoch/expiry required");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutopilotBudgetBoundCall {
    pub reservation_root: [u8; 32],
    pub policy_root: [u8; 32],
    pub proposal_root: [u8; 32],
    pub company_graph_root: Option<[u8; 32]>,
    pub target: [u8; 20],
    pub value: u128,
    pub calldata_hash: [u8; 32],
    pub expires_at: u64,
}

impl AutopilotBudgetBoundCall {
    pub fn validate_against(
        &self,
        reservation: &AutopilotBudgetReservation,
        now: u64,
    ) -> Result<(), &'static str> {
        reservation.validate()?;
        if self.reservation_root != reservation.reservation_root {
            return Err("budget reservation root mismatch");
        }
        if self.policy_root != reservation.policy_root {
            return Err("Autopilot policy root mismatch");
        }
        if self.proposal_root == [0; 32] || self.calldata_hash == [0; 32] {
            return Err("proposal/calldata commitment required");
        }
        if self.target == [0; 20] {
            return Err("zero execution target denied");
        }
        if self.value > reservation.reserved_value {
            return Err("execution value exceeds reserved value");
        }
        if now >= self.expires_at || now >= reservation.expires_at {
            return Err("Autopilot execution expired");
        }
        if let Some(expected) = reservation.company_graph_root {
            if self.company_graph_root != Some(expected) {
                return Err("company graph root mismatch");
            }
        }
        Ok(())
    }
}

impl AutopilotBudgetBoundCall {
    pub fn authorization_commitment(
        &self,
        reservation: &AutopilotBudgetReservation,
    ) -> Option<[u8; 32]> {
        self.validate_against(reservation, 0).ok()?;

        let mut hasher = Sha256::new();
        hasher.update(AUTOPILOT_EXECUTION_DOMAIN);
        hasher.update(reservation.reservation_id);
        hasher.update(reservation.owner_account);
        hasher.update(reservation.reservation_root);
        hasher.update(reservation.policy_root);
        hasher.update(reservation.grant_root);
        match reservation.company_budget_root {
            Some(root) => {
                hasher.update([1]);
                hasher.update(root);
            }
            None => hasher.update([0]),
        }
        match reservation.company_graph_root {
            Some(root) => {
                hasher.update([1]);
                hasher.update(root);
            }
            None => hasher.update([0]),
        }
        hasher.update(reservation.epoch.to_be_bytes());
        hasher.update(reservation.reserved_value.to_be_bytes());
        hasher.update(reservation.expires_at.to_be_bytes());

        hasher.update(self.reservation_root);
        hasher.update(self.policy_root);
        hasher.update(self.proposal_root);
        match self.company_graph_root {
            Some(root) => {
                hasher.update([1]);
                hasher.update(root);
            }
            None => hasher.update([0]),
        }
        hasher.update(self.target);
        hasher.update(self.value.to_be_bytes());
        hasher.update(self.calldata_hash);
        hasher.update(self.expires_at.to_be_bytes());

        Some(hasher.finalize().into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutopilotExecutionAuthorization {
    pub chain_id: [u8; 32],
    pub nonce: u64,
    pub authorization_expires_at: u64,
    pub call: AutopilotBudgetBoundCall,
    pub authorization: HybridAuthorization,
}

impl AutopilotExecutionAuthorization {
    pub fn envelope(
        &self,
        reservation: &AutopilotBudgetReservation,
    ) -> Option<AuthorizationEnvelope> {
        Some(AuthorizationEnvelope {
            chain_id: self.chain_id,
            domain: AuthorizationDomain::AutopilotExecution,
            epoch: reservation.epoch,
            nonce: self.nonce,
            expires_at: self.authorization_expires_at,
            payload_commitment: self.call.authorization_commitment(reservation)?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AutopilotExecutionValidationContext {
    pub expected_chain_id: [u8; 32],
    pub expected_nonce: u64,
    pub expected_owner_account: [u8; 32],
    pub expected_owner_keyset_commitment: [u8; 32],
    pub expected_reservation_root: [u8; 32],
    pub expected_policy_root: [u8; 32],
    pub now: u64,
    pub max_future_seconds: u64,
}

pub(crate) fn verify_autopilot_execution<V: ContextSignatureVerifier>(
    verifier: &V,
    reservation: &AutopilotBudgetReservation,
    authorized: &AutopilotExecutionAuthorization,
    validation: &AutopilotExecutionValidationContext,
) -> bool {
    if authorized.authorization.policy != AuthPolicy::Max
        || reservation.owner_account != validation.expected_owner_account
        || authorized
            .authorization
            .primary_account_identity_commitment()
            != Some(reservation.owner_account)
        || authorized.authorization.keyset_commitment()
            != Some(validation.expected_owner_keyset_commitment)
        || reservation.reservation_root != validation.expected_reservation_root
        || reservation.policy_root != validation.expected_policy_root
        || authorized
            .call
            .validate_against(reservation, validation.now)
            .is_err()
    {
        return false;
    }

    let envelope = match authorized.envelope(reservation) {
        Some(envelope) => envelope,
        None => return false,
    };

    let auth_validation = AuthorizationValidationContext {
        expected_chain_id: validation.expected_chain_id,
        expected_domain: AuthorizationDomain::AutopilotExecution,
        expected_policy: AuthPolicy::Max,
        expected_epoch: reservation.epoch,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutopilotRealizedExecutionReceipt {
    pub budget_bound_call_root: [u8; 32],
    pub reservation_root: [u8; 32],
    pub tx_hash: [u8; 32],
    pub realized_value: u128,
    pub success: bool,
}

impl AutopilotRealizedExecutionReceipt {
    pub fn validate_against(&self, call: &AutopilotBudgetBoundCall) -> Result<(), &'static str> {
        if self.budget_bound_call_root == [0; 32] || self.tx_hash == [0; 32] {
            return Err("execution and transaction commitments required");
        }
        if self.reservation_root != call.reservation_root {
            return Err("execution receipt reservation mismatch");
        }
        if self.realized_value > call.value {
            return Err("realized value exceeds signed call value");
        }
        Ok(())
    }

    pub fn commitment_against(&self, call: &AutopilotBudgetBoundCall) -> Option<[u8; 32]> {
        self.validate_against(call).ok()?;
        const DOMAIN: &[u8] = b"SYNERGY/AUTOPILOT-REALIZED-EXECUTION/V1\0";
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN);
        hasher.update(self.budget_bound_call_root);
        hasher.update(self.reservation_root);
        hasher.update(self.tx_hash);
        hasher.update(self.realized_value.to_be_bytes());
        hasher.update([u8::from(self.success)]);
        Some(hasher.finalize().into())
    }
}

pub(crate) fn verify_autopilot_execution_and_consume<V: ContextSignatureVerifier>(
    verifier: &V,
    reservation: &AutopilotBudgetReservation,
    authorized: &AutopilotExecutionAuthorization,
    validation: &AutopilotExecutionValidationContext,
    replay: &mut AuthorizationReplayState,
) -> bool {
    if !verify_autopilot_execution(verifier, reservation, authorized, validation) {
        return false;
    }
    let envelope = match authorized.envelope(reservation) {
        Some(envelope) => envelope,
        None => return false,
    };
    replay.consume_verified_for_subject(
        &authorized.authorization,
        &envelope,
        validation.expected_owner_account,
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

    fn reservation() -> AutopilotBudgetReservation {
        let owner_account = max_authorization()
            .primary_account_identity_commitment()
            .expect("owner account identity");
        AutopilotBudgetReservation {
            owner_account,
            reservation_id: [1; 32],
            reservation_root: [2; 32],
            policy_root: [3; 32],
            grant_root: [4; 32],
            company_budget_root: Some([5; 32]),
            company_graph_root: Some([6; 32]),
            epoch: 100,
            reserved_value: 1_000,
            expires_at: 200,
        }
    }

    fn call(value: u128) -> AutopilotBudgetBoundCall {
        AutopilotBudgetBoundCall {
            reservation_root: [2; 32],
            policy_root: [3; 32],
            proposal_root: [7; 32],
            company_graph_root: Some([6; 32]),
            target: [8; 20],
            value,
            calldata_hash: [9; 32],
            expires_at: 180,
        }
    }

    #[test]
    fn autopilot_execution_requires_max_owner_authorization() {
        let reservation = reservation();
        let authorization = max_authorization();
        let owner_account = authorization
            .primary_account_identity_commitment()
            .expect("owner account identity");
        let owner_keyset = authorization
            .keyset_commitment()
            .expect("owner keyset commitment");
        let authorized = AutopilotExecutionAuthorization {
            chain_id: [0xB1; 32],
            nonce: 9,
            authorization_expires_at: 170,
            call: call(700),
            authorization,
        };
        let envelope = authorized
            .envelope(&reservation)
            .expect("autopilot envelope");
        let verifier = ExpectedVerifier {
            message: envelope
                .canonical_message(AuthPolicy::Max)
                .expect("message"),
            context: envelope
                .fips_signature_context(AuthPolicy::Max)
                .expect("context"),
        };
        let validation = AutopilotExecutionValidationContext {
            expected_chain_id: [0xB1; 32],
            expected_nonce: 9,
            expected_owner_account: owner_account,
            expected_owner_keyset_commitment: owner_keyset,
            expected_reservation_root: reservation.reservation_root,
            expected_policy_root: reservation.policy_root,
            now: 120,
            max_future_seconds: 100,
        };

        assert!(verify_autopilot_execution(
            &verifier,
            &reservation,
            &authorized,
            &validation,
        ));

        let mut wrong_owner = validation;
        wrong_owner.expected_owner_account[0] ^= 1;
        assert!(!verify_autopilot_execution(
            &verifier,
            &reservation,
            &authorized,
            &wrong_owner,
        ));
    }

    #[test]
    fn autopilot_owner_identity_is_stable_across_secondary_key_rotation() {
        let auth = max_authorization();
        let owner = auth
            .primary_account_identity_commitment()
            .expect("owner account identity");

        let mut rotated = auth.clone();
        rotated.evidence[0].public_key[1] ^= 1;
        rotated.evidence[2].public_key[0] ^= 1;

        assert_eq!(rotated.primary_account_identity_commitment(), Some(owner));
        assert_ne!(auth.keyset_commitment(), rotated.keyset_commitment());
    }

    #[test]
    fn autopilot_execution_rejects_reservation_owned_by_different_account() {
        let mut reservation = reservation();
        let authorization = max_authorization();
        let owner_account = authorization
            .primary_account_identity_commitment()
            .expect("owner account identity");
        let owner_keyset = authorization
            .keyset_commitment()
            .expect("owner keyset commitment");
        reservation.owner_account[0] ^= 1;

        let authorized = AutopilotExecutionAuthorization {
            chain_id: [0xB1; 32],
            nonce: 9,
            authorization_expires_at: 170,
            call: call(100),
            authorization,
        };
        let envelope = authorized
            .envelope(&reservation)
            .expect("autopilot envelope");
        let verifier = ExpectedVerifier {
            message: envelope
                .canonical_message(AuthPolicy::Max)
                .expect("message"),
            context: envelope
                .fips_signature_context(AuthPolicy::Max)
                .expect("context"),
        };
        let validation = AutopilotExecutionValidationContext {
            expected_chain_id: [0xB1; 32],
            expected_nonce: 9,
            expected_owner_account: owner_account,
            expected_owner_keyset_commitment: owner_keyset,
            expected_reservation_root: reservation.reservation_root,
            expected_policy_root: reservation.policy_root,
            now: 120,
            max_future_seconds: 100,
        };

        assert!(!verify_autopilot_execution(
            &verifier,
            &reservation,
            &authorized,
            &validation,
        ));
    }

    #[test]
    fn autopilot_execution_expiry_is_exclusive() {
        let reservation = reservation();
        let authorization = max_authorization();
        let owner_account = authorization
            .primary_account_identity_commitment()
            .expect("owner account identity");
        let owner_keyset = authorization
            .keyset_commitment()
            .expect("owner keyset commitment");
        let authorized = AutopilotExecutionAuthorization {
            chain_id: [0xB1; 32],
            nonce: 9,
            authorization_expires_at: 180,
            call: call(100),
            authorization,
        };
        let envelope = authorized
            .envelope(&reservation)
            .expect("autopilot envelope");
        let verifier = ExpectedVerifier {
            message: envelope
                .canonical_message(AuthPolicy::Max)
                .expect("message"),
            context: envelope
                .fips_signature_context(AuthPolicy::Max)
                .expect("context"),
        };
        let validation = AutopilotExecutionValidationContext {
            expected_chain_id: [0xB1; 32],
            expected_nonce: 9,
            expected_owner_account: owner_account,
            expected_owner_keyset_commitment: owner_keyset,
            expected_reservation_root: reservation.reservation_root,
            expected_policy_root: reservation.policy_root,
            now: 180,
            max_future_seconds: 100,
        };

        assert!(!verify_autopilot_execution(
            &verifier,
            &reservation,
            &authorized,
            &validation,
        ));
    }

    #[test]
    fn call_cannot_exceed_reservation() {
        assert_eq!(call(999).validate_against(&reservation(), 120), Ok(()));
        assert_eq!(
            call(1_001).validate_against(&reservation(), 120),
            Err("execution value exceeds reserved value")
        );
    }

    #[test]
    fn company_graph_is_bound() {
        let mut c = call(100);
        c.company_graph_root = Some([99; 32]);
        assert_eq!(
            c.validate_against(&reservation(), 120),
            Err("company graph root mismatch")
        );
    }

    #[test]
    fn realized_value_cannot_exceed_signed_call() {
        let c = call(700);
        let receipt = AutopilotRealizedExecutionReceipt {
            budget_bound_call_root: [10; 32],
            reservation_root: [2; 32],
            tx_hash: [11; 32],
            realized_value: 701,
            success: true,
        };
        assert_eq!(
            receipt.validate_against(&c),
            Err("realized value exceeds signed call value")
        );
    }
}
