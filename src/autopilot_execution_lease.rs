//! One-time execution lease primitives for Autopilot anti-replay.

use sha2::{Digest, Sha256};

use crate::autopilot_budget::{
    verify_autopilot_execution_and_consume, AutopilotBudgetBoundCall, AutopilotBudgetReservation,
    AutopilotExecutionAuthorization, AutopilotExecutionValidationContext,
};
use crate::pq::{AuthorizationReplayState, ContextSignatureVerifier};

const AUTOPILOT_EXECUTION_LEASE_DOMAIN: &[u8] = b"SYNERGY/AUTOPILOT-EXECUTION-LEASE/V1\0";
const AUTOPILOT_LEASE_TERMINAL_DOMAIN: &[u8] = b"SYNERGY/AUTOPILOT-LEASE-TERMINAL/V1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutopilotExecutionLeaseStatus {
    ExecutionLocked,
    Settled,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutopilotExecutionLease {
    pub lease_root: [u8; 32],
    pub reservation_root: [u8; 32],
    pub budget_bound_call_root: [u8; 32],
    pub proposal_root: [u8; 32],
    pub status: AutopilotExecutionLeaseStatus,
}

impl AutopilotExecutionLease {
    pub fn canonical_root(
        reservation: &AutopilotBudgetReservation,
        call: &AutopilotBudgetBoundCall,
    ) -> Option<[u8; 32]> {
        let call_root = call.authorization_commitment(reservation)?;
        let mut hasher = Sha256::new();
        hasher.update(AUTOPILOT_EXECUTION_LEASE_DOMAIN);
        hasher.update(reservation.reservation_root);
        hasher.update(call_root);
        hasher.update(call.proposal_root);
        Some(hasher.finalize().into())
    }

    pub fn validate_new(
        &self,
        reservation: &AutopilotBudgetReservation,
        call: &AutopilotBudgetBoundCall,
        now: u64,
    ) -> Result<(), &'static str> {
        call.validate_against(reservation, now)?;
        let call_root = call
            .authorization_commitment(reservation)
            .ok_or("budget-bound call commitment unavailable")?;
        let expected_lease_root =
            Self::canonical_root(reservation, call).ok_or("execution lease root unavailable")?;

        if self.lease_root != expected_lease_root {
            return Err("execution lease root mismatch");
        }
        if self.budget_bound_call_root != call_root {
            return Err("execution lease call root mismatch");
        }
        if self.reservation_root != reservation.reservation_root {
            return Err("execution lease reservation mismatch");
        }
        if self.proposal_root != call.proposal_root {
            return Err("execution lease proposal mismatch");
        }
        if self.status != AutopilotExecutionLeaseStatus::ExecutionLocked {
            return Err("new execution lease must be locked");
        }
        Ok(())
    }
}

pub fn authorize_and_lock_autopilot_execution<V: ContextSignatureVerifier>(
    verifier: &V,
    reservation: &AutopilotBudgetReservation,
    authorized: &AutopilotExecutionAuthorization,
    validation: &AutopilotExecutionValidationContext,
    replay: &mut AuthorizationReplayState,
    lease: &AutopilotExecutionLease,
) -> bool {
    if lease
        .validate_new(reservation, &authorized.call, validation.now)
        .is_err()
    {
        return false;
    }

    verify_autopilot_execution_and_consume(
        verifier,
        reservation,
        authorized,
        validation,
        replay,
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutopilotLeaseTerminalReceipt {
    pub lease_root: [u8; 32],
    pub execution_receipt_root: Option<[u8; 32]>,
    pub reason_root: Option<[u8; 32]>,
    pub status: AutopilotExecutionLeaseStatus,
}

impl AutopilotLeaseTerminalReceipt {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.lease_root == [0; 32] {
            return Err("lease root required");
        }
        match self.status {
            AutopilotExecutionLeaseStatus::Settled => {
                if self.execution_receipt_root.is_none() || self.reason_root.is_some() {
                    return Err("settled lease requires execution receipt only");
                }
                if self.execution_receipt_root == Some([0; 32]) {
                    return Err("settled lease execution receipt root required");
                }
            }
            AutopilotExecutionLeaseStatus::Cancelled => {
                if self.reason_root.is_none() || self.execution_receipt_root.is_some() {
                    return Err("cancelled lease requires reason only");
                }
                if self.reason_root == Some([0; 32]) {
                    return Err("cancelled lease reason root required");
                }
            }
            AutopilotExecutionLeaseStatus::ExecutionLocked => {
                return Err("terminal receipt cannot remain execution-locked");
            }
        }
        Ok(())
    }

    pub fn commitment(&self) -> Option<[u8; 32]> {
        self.validate().ok()?;

        let mut hasher = Sha256::new();
        hasher.update(AUTOPILOT_LEASE_TERMINAL_DOMAIN);
        hasher.update(self.lease_root);
        hasher.update([match self.status {
            AutopilotExecutionLeaseStatus::ExecutionLocked => 0,
            AutopilotExecutionLeaseStatus::Settled => 1,
            AutopilotExecutionLeaseStatus::Cancelled => 2,
        }]);

        match self.execution_receipt_root {
            Some(root) => {
                hasher.update([1]);
                hasher.update(root);
            }
            None => hasher.update([0]),
        }
        match self.reason_root {
            Some(root) => {
                hasher.update([1]);
                hasher.update(root);
            }
            None => hasher.update([0]),
        }

        Some(hasher.finalize().into())
    }
}

impl AutopilotExecutionLease {
    pub fn finalize_once(
        &mut self,
        terminal: &AutopilotLeaseTerminalReceipt,
    ) -> Result<[u8; 32], &'static str> {
        if self.status != AutopilotExecutionLeaseStatus::ExecutionLocked {
            return Err("execution lease already terminal");
        }
        terminal.validate()?;
        if terminal.lease_root != self.lease_root {
            return Err("terminal receipt lease mismatch");
        }

        let commitment = terminal
            .commitment()
            .ok_or("terminal receipt commitment unavailable")?;
        self.status = terminal.status;
        Ok(commitment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::autopilot_budget::{
        AutopilotExecutionAuthorization, AutopilotExecutionValidationContext,
    };
    use crate::pq::{
        AuthPolicy, AuthScheme, AuthorizationDomain, ContextSignatureVerifier,
        HybridAuthorization, SignatureEvidence, ML_DSA_87_PUBLIC_KEY_BYTES,
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

    fn reservation_and_call() -> (AutopilotBudgetReservation, AutopilotBudgetBoundCall) {
        let authorization = max_authorization();
        let owner_account = authorization
            .primary_account_identity_commitment()
            .expect("owner account");
        let reservation = AutopilotBudgetReservation {
            reservation_id: [11; 32],
            owner_account,
            reservation_root: [12; 32],
            policy_root: [13; 32],
            grant_root: [14; 32],
            company_budget_root: Some([15; 32]),
            company_graph_root: Some([16; 32]),
            epoch: 7,
            reserved_value: 1_000,
            expires_at: 200,
        };
        let call = AutopilotBudgetBoundCall {
            reservation_root: reservation.reservation_root,
            policy_root: reservation.policy_root,
            proposal_root: [17; 32],
            company_graph_root: reservation.company_graph_root,
            target: [18; 20],
            value: 500,
            calldata_hash: [19; 32],
            expires_at: 180,
        };
        (reservation, call)
    }


    #[test]
    fn canonical_lease_root_binds_exact_signed_call() {
        let (reservation, call) = reservation_and_call();
        let root = AutopilotExecutionLease::canonical_root(&reservation, &call)
            .expect("canonical lease root");

        let mut changed_call = call.clone();
        changed_call.value += 1;
        assert_ne!(
            root,
            AutopilotExecutionLease::canonical_root(&reservation, &changed_call)
                .expect("changed lease root")
        );

        let call_root = call
            .authorization_commitment(&reservation)
            .expect("call root");
        let lease = AutopilotExecutionLease {
            lease_root: root,
            reservation_root: reservation.reservation_root,
            budget_bound_call_root: call_root,
            proposal_root: call.proposal_root,
            status: AutopilotExecutionLeaseStatus::ExecutionLocked,
        };
        assert_eq!(lease.validate_new(&reservation, &call, 100), Ok(()));
    }

    #[test]
    fn tampered_lease_does_not_consume_authorization_nonce() {
        let (reservation, call) = reservation_and_call();
        let authorization = max_authorization();
        let keyset = authorization
            .keyset_commitment()
            .expect("owner keyset commitment");
        let authorized = AutopilotExecutionAuthorization {
            chain_id: [0xB1; 32],
            nonce: 9,
            authorization_expires_at: 170,
            call: call.clone(),
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
            expected_owner_account: reservation.owner_account,
            expected_owner_keyset_commitment: keyset,
            expected_reservation_root: reservation.reservation_root,
            expected_policy_root: reservation.policy_root,
            now: 100,
            max_future_seconds: 100,
        };
        let mut replay = AuthorizationReplayState::new_for_subject(
            [0xB1; 32],
            AuthorizationDomain::AutopilotExecution,
            AuthPolicy::Max,
            reservation.owner_account,
            reservation.epoch,
            9,
        )
        .expect("replay state");

        let mut lease = AutopilotExecutionLease {
            lease_root: AutopilotExecutionLease::canonical_root(&reservation, &call)
                .expect("lease root"),
            reservation_root: reservation.reservation_root,
            budget_bound_call_root: call
                .authorization_commitment(&reservation)
                .expect("call root"),
            proposal_root: call.proposal_root,
            status: AutopilotExecutionLeaseStatus::ExecutionLocked,
        };
        lease.budget_bound_call_root[0] ^= 1;

        assert!(!authorize_and_lock_autopilot_execution(
            &verifier,
            &reservation,
            &authorized,
            &validation,
            &mut replay,
            &lease,
        ));
        assert_eq!(replay.next_nonce(), 9);
    }

    #[test]
    fn execution_lease_finalizes_exactly_once() {
        let mut lease = AutopilotExecutionLease {
            lease_root: [1; 32],
            reservation_root: [2; 32],
            budget_bound_call_root: [3; 32],
            proposal_root: [4; 32],
            status: AutopilotExecutionLeaseStatus::ExecutionLocked,
        };
        let settled = AutopilotLeaseTerminalReceipt {
            lease_root: lease.lease_root,
            execution_receipt_root: Some([5; 32]),
            reason_root: None,
            status: AutopilotExecutionLeaseStatus::Settled,
        };

        let commitment = lease
            .finalize_once(&settled)
            .expect("first terminal transition");
        assert_ne!(commitment, [0; 32]);
        assert_eq!(lease.status, AutopilotExecutionLeaseStatus::Settled);
        assert_eq!(
            lease.finalize_once(&settled),
            Err("execution lease already terminal")
        );
    }

    #[test]
    fn execution_lease_rejects_terminal_receipt_for_other_lease() {
        let mut lease = AutopilotExecutionLease {
            lease_root: [1; 32],
            reservation_root: [2; 32],
            budget_bound_call_root: [3; 32],
            proposal_root: [4; 32],
            status: AutopilotExecutionLeaseStatus::ExecutionLocked,
        };
        let terminal = AutopilotLeaseTerminalReceipt {
            lease_root: [9; 32],
            execution_receipt_root: None,
            reason_root: Some([8; 32]),
            status: AutopilotExecutionLeaseStatus::Cancelled,
        };

        assert_eq!(
            lease.finalize_once(&terminal),
            Err("terminal receipt lease mismatch")
        );
        assert_eq!(
            lease.status,
            AutopilotExecutionLeaseStatus::ExecutionLocked
        );
    }

    #[test]
    fn terminal_status_is_unambiguous() {
        let settled = AutopilotLeaseTerminalReceipt {
            lease_root: [1; 32],
            execution_receipt_root: Some([2; 32]),
            reason_root: None,
            status: AutopilotExecutionLeaseStatus::Settled,
        };
        assert_eq!(settled.validate(), Ok(()));

        let ambiguous = AutopilotLeaseTerminalReceipt {
            reason_root: Some([3; 32]),
            ..settled
        };
        assert_eq!(
            ambiguous.validate(),
            Err("settled lease requires execution receipt only")
        );
    }
}
