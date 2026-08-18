//! Consensus-neutral canonical commitments for Autopilot budget lifecycle.
//!
//! AI planning is never signing authority. A value-bearing execution may be
//! authorized only after a budget reservation has already occupied both the
//! delegated grant and (when present) company-wide epoch envelope.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutopilotBudgetReservation {
    pub reservation_id: [u8; 32],
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
        if now > self.expires_at || now > reservation.expires_at {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutopilotRealizedExecutionReceipt {
    pub budget_bound_call_root: [u8; 32],
    pub reservation_root: [u8; 32],
    pub tx_hash: [u8; 32],
    pub realized_value: u128,
    pub success: bool,
}

impl AutopilotRealizedExecutionReceipt {
    pub fn validate_against(
        &self,
        call: &AutopilotBudgetBoundCall,
    ) -> Result<(), &'static str> {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reservation() -> AutopilotBudgetReservation {
        AutopilotBudgetReservation {
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
