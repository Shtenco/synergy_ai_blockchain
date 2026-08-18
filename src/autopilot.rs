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
    pub fn allows(&self, capability: AutopilotCapability, value: u128, now: u64) -> bool {
        now >= self.valid_from
            && now <= self.valid_until
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
