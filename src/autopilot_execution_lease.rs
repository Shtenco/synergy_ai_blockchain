//! One-time execution lease primitives for Autopilot anti-replay.

use crate::autopilot_budget::{AutopilotBudgetBoundCall, AutopilotBudgetReservation};

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
    pub fn validate_new(
        &self,
        reservation: &AutopilotBudgetReservation,
        call: &AutopilotBudgetBoundCall,
        now: u64,
    ) -> Result<(), &'static str> {
        call.validate_against(reservation, now)?;
        if self.lease_root == [0; 32] || self.budget_bound_call_root == [0; 32] {
            return Err("execution lease/call root required");
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
            }
            AutopilotExecutionLeaseStatus::Cancelled => {
                if self.reason_root.is_none() || self.execution_receipt_root.is_some() {
                    return Err("cancelled lease requires reason only");
                }
            }
            AutopilotExecutionLeaseStatus::ExecutionLocked => {
                return Err("terminal receipt cannot remain execution-locked");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
