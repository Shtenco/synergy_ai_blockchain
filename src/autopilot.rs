//! Capability-safe AI Autopilot primitives.
//!
//! NEXUS/AI may propose, simulate and rank actions, but never obtains unilateral
//! spending/signing authority. Final execution remains bound to explicit account
//! policy, budget, expiry and PQ authorization.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutopilotCapability {
    ReadLedger,
    ReadMarket,
    QuotePayment,
    PreparePayment,
    PrepareSwap,
    PrepareTreasuryMove,
    PrepareContractCall,
    RequestHumanApproval,
    ScheduleWorkflow,
    SubmitEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalMode {
    HumanEveryAction,
    PolicyBoundBudget,
    CorporateQuorum,
    DeterministicRuleOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutopilotPolicy {
    pub policy_id: [u8; 32],
    pub owner_account: [u8; 32],
    pub policy_root: [u8; 32],
    pub max_value_per_action: u128,
    pub max_value_per_epoch: u128,
    pub valid_from: u64,
    pub valid_until: u64,
    pub approval_mode: ApprovalMode,
    pub allowed_capabilities: Vec<AutopilotCapability>,
}

impl AutopilotPolicy {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.policy_id == [0u8; 32]
            || self.owner_account == [0u8; 32]
            || self.policy_root == [0u8; 32]
        {
            return Err("Autopilot policy commitments required");
        }
        if self.valid_until <= self.valid_from {
            return Err("Autopilot policy validity window invalid");
        }
        if self.max_value_per_action == 0 || self.max_value_per_epoch == 0 {
            return Err("Autopilot policy value limits required");
        }
        if self.max_value_per_action > self.max_value_per_epoch {
            return Err("Autopilot per-action limit exceeds epoch limit");
        }
        if self.allowed_capabilities.is_empty() {
            return Err("Autopilot policy requires at least one capability");
        }
        for (index, capability) in self.allowed_capabilities.iter().enumerate() {
            if self.allowed_capabilities[..index].contains(capability) {
                return Err("Autopilot policy contains duplicate capability");
            }
        }
        Ok(())
    }

    pub fn allows(&self, capability: AutopilotCapability, value: u128, now: u64) -> bool {
        self.validate().is_ok()
            && now >= self.valid_from
            && now < self.valid_until
            && value <= self.max_value_per_action
            && self.allowed_capabilities.contains(&capability)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutopilotProposal {
    pub proposal_id: [u8; 32],
    pub policy_id: [u8; 32],
    pub nexus_model_root: [u8; 32],
    pub evidence_root: [u8; 32],
    pub simulation_state_root: [u8; 32],
    pub target: [u8; 20],
    pub value: u128,
    pub calldata_commitment: [u8; 32],
    pub expected_effect_commitment: [u8; 32],
    pub risk_commitment: [u8; 32],
    pub created_at: u64,
    pub expires_at: u64,
}

impl AutopilotProposal {
    pub fn validate_against(
        &self,
        policy: &AutopilotPolicy,
        capability: AutopilotCapability,
        now: u64,
    ) -> Result<(), &'static str> {
        if self.proposal_id == [0; 32] || self.policy_id != policy.policy_id {
            return Err("proposal/policy mismatch");
        }
        if self.nexus_model_root == [0; 32]
            || self.evidence_root == [0; 32]
            || self.simulation_state_root == [0; 32]
        {
            return Err("AI evidence commitments required");
        }
        if self.expires_at <= now || self.created_at > now {
            return Err("proposal outside time window");
        }
        if self.expires_at > policy.valid_until {
            return Err("proposal outlives Autopilot policy");
        }
        if !policy.allows(capability, self.value, now) {
            return Err("capability or budget denied");
        }
        Ok(())
    }
}

/// Execution receipts are produced only after a cryptographically authorized
/// account/organization executes an approved proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutopilotExecutionReceipt {
    pub proposal_id: [u8; 32],
    pub authorization_commitment: [u8; 32],
    pub transaction_commitment: [u8; 32],
    pub pre_state_root: [u8; 32],
    pub post_state_root: [u8; 32],
    pub realized_value_delta: i128,
    pub realized_cost: u128,
    pub success: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_rejects_invalid_window_duplicate_capability_and_zero_commitments() {
        let mut p = AutopilotPolicy {
            policy_id: [1; 32],
            owner_account: [2; 32],
            policy_root: [3; 32],
            max_value_per_action: 100,
            max_value_per_epoch: 1_000,
            valid_from: 1,
            valid_until: 100,
            approval_mode: ApprovalMode::PolicyBoundBudget,
            allowed_capabilities: vec![AutopilotCapability::PreparePayment],
        };
        assert_eq!(p.validate(), Ok(()));

        p.valid_until = p.valid_from;
        assert!(p.validate().is_err());

        p.valid_until = 100;
        p.allowed_capabilities
            .push(AutopilotCapability::PreparePayment);
        assert!(p.validate().is_err());

        p.allowed_capabilities.pop();
        p.owner_account = [0; 32];
        assert!(p.validate().is_err());
    }

    #[test]
    fn policy_expiry_is_exclusive() {
        let p = AutopilotPolicy {
            policy_id: [1; 32],
            owner_account: [2; 32],
            policy_root: [3; 32],
            max_value_per_action: 100,
            max_value_per_epoch: 1_000,
            valid_from: 1,
            valid_until: 100,
            approval_mode: ApprovalMode::PolicyBoundBudget,
            allowed_capabilities: vec![AutopilotCapability::PreparePayment],
        };
        assert!(p.allows(AutopilotCapability::PreparePayment, 1, 99));
        assert!(!p.allows(AutopilotCapability::PreparePayment, 1, 100));
    }

    #[test]
    fn policy_blocks_overspend() {
        let p = AutopilotPolicy {
            policy_id: [1; 32],
            owner_account: [2; 32],
            policy_root: [3; 32],
            max_value_per_action: 100,
            max_value_per_epoch: 1000,
            valid_from: 1,
            valid_until: 100,
            approval_mode: ApprovalMode::PolicyBoundBudget,
            allowed_capabilities: vec![AutopilotCapability::PreparePayment],
        };
        assert!(!p.allows(AutopilotCapability::PreparePayment, 101, 50));
        assert!(!p.allows(AutopilotCapability::PrepareSwap, 10, 50));
        assert!(p.allows(AutopilotCapability::PreparePayment, 100, 50));
    }
}
