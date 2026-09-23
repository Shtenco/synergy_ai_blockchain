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
