//! Deterministic reward policy for useful, complementary CognitiveNode work.
//!
//! The market must not pay merely for registering another model or emitting a
//! high self-confidence score. Rewards are derived from a verified work receipt
//! plus benchmark evidence that measures marginal residual coverage and error
//! correlation. All arithmetic is integer/fixed-point and consensus-safe.

use crate::cognitive::{CognitiveWorkReceipt, WorkVerdict};

const MICROS: u128 = 1_000_000;
const BPS: u128 = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CognitiveRewardPolicy {
    pub max_reward: u128,
    pub utility_bonus_bps: u32,
    pub diversity_bonus_bps: u32,
    pub max_positive_error_corr_micros: u32,
}

impl CognitiveRewardPolicy {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.max_reward == 0 {
            return Err("max reward required");
        }
        if self.utility_bonus_bps > 100_000 || self.diversity_bonus_bps > 100_000 {
            return Err("bonus bps exceeds hard cap");
        }
        if self.max_positive_error_corr_micros > 1_000_000 {
            return Err("correlation threshold out of range");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedMarginalContribution {
    /// Number of previously unresolved frozen cases solved by this node.
    pub newly_solved_cases: u64,
    /// Number of residual cases immediately before adding this node.
    pub residual_cases_before: u64,
    /// Mean positive pairwise error correlation with the admitted portfolio.
    pub mean_positive_error_corr_micros: u32,
    /// Commitment to the frozen benchmark/admission evidence that produced the metrics.
    pub contribution_evidence_root: [u8; 32],
}

impl VerifiedMarginalContribution {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.residual_cases_before == 0 {
            return Err("residual denominator required");
        }
        if self.newly_solved_cases > self.residual_cases_before {
            return Err("newly solved exceeds residual cases");
        }
        if self.mean_positive_error_corr_micros > 1_000_000 {
            return Err("correlation out of range");
        }
        if self.contribution_evidence_root == [0; 32] {
            return Err("contribution evidence root required");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CognitiveRewardBreakdown {
    pub base_reward: u128,
    pub utility_bonus: u128,
    pub diversity_bonus: u128,
    pub total_reward: u128,
    pub diversity_eligible: bool,
}

fn mul_div(a: u128, b: u128, denominator: u128) -> Result<u128, &'static str> {
    if denominator == 0 {
        return Err("division by zero");
    }
    a.checked_mul(b)
        .ok_or("reward multiplication overflow")
        .map(|x| x / denominator)
}

/// Compute an additional reward over the already policy-capped base payment.
///
/// `receipt.paid_amount` is treated as the verified base reward. Negative or zero
/// realized utility receives no utility bonus. Diversity bonus requires both
/// residual coverage and error correlation below policy threshold.
pub fn reward_breakdown(
    receipt: &CognitiveWorkReceipt,
    contribution: &VerifiedMarginalContribution,
    policy: &CognitiveRewardPolicy,
) -> Result<CognitiveRewardBreakdown, &'static str> {
    policy.validate()?;
    contribution.validate()?;

    if receipt.verdict != WorkVerdict::Accepted {
        return Ok(CognitiveRewardBreakdown {
            base_reward: 0,
            utility_bonus: 0,
            diversity_bonus: 0,
            total_reward: 0,
            diversity_eligible: false,
        });
    }

    let base = receipt.paid_amount.min(policy.max_reward);
    let positive_utility = receipt.realized_utility_micros.max(0) as u128;
    let utility_factor = positive_utility.min(MICROS);
    let utility_rate = u128::from(policy.utility_bonus_bps);
    let utility_bonus = mul_div(
        mul_div(base, utility_rate, BPS)?,
        utility_factor,
        MICROS,
    )?;

    let corr = u128::from(contribution.mean_positive_error_corr_micros);
    let diversity_eligible = contribution.newly_solved_cases > 0
        && contribution.mean_positive_error_corr_micros <= policy.max_positive_error_corr_micros;
    let diversity_bonus = if diversity_eligible {
        let residual_fraction = mul_div(
            u128::from(contribution.newly_solved_cases),
            MICROS,
            u128::from(contribution.residual_cases_before),
        )?;
        let independence = MICROS.saturating_sub(corr);
        let base_bonus = mul_div(base, u128::from(policy.diversity_bonus_bps), BPS)?;
        let by_residual = mul_div(base_bonus, residual_fraction, MICROS)?;
        mul_div(by_residual, independence, MICROS)?
    } else {
        0
    };

    let total = base
        .checked_add(utility_bonus)
        .and_then(|x| x.checked_add(diversity_bonus))
        .ok_or("reward addition overflow")?
        .min(policy.max_reward);

    Ok(CognitiveRewardBreakdown {
        base_reward: base,
        utility_bonus,
        diversity_bonus,
        total_reward: total,
        diversity_eligible,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt(utility: i64) -> CognitiveWorkReceipt {
        CognitiveWorkReceipt {
            request_id: [1; 32],
            node_id: [2; 32],
            evidence_commitment: [3; 32],
            verifier_commitment: [4; 32],
            authority_commitment: [5; 32],
            verdict: WorkVerdict::Accepted,
            paid_amount: 1_000,
            slash_amount: 0,
            realized_utility_micros: utility,
        }
    }

    fn policy() -> CognitiveRewardPolicy {
        CognitiveRewardPolicy {
            max_reward: 10_000,
            utility_bonus_bps: 2_000,
            diversity_bonus_bps: 5_000,
            max_positive_error_corr_micros: 600_000,
        }
    }

    #[test]
    fn complementary_node_gets_more_than_base() {
        let contribution = VerifiedMarginalContribution {
            newly_solved_cases: 20,
            residual_cases_before: 100,
            mean_positive_error_corr_micros: 100_000,
            contribution_evidence_root: [7; 32],
        };
        let r = reward_breakdown(&receipt(500_000), &contribution, &policy()).unwrap();
        assert_eq!(r.base_reward, 1_000);
        assert!(r.utility_bonus > 0);
        assert!(r.diversity_bonus > 0);
        assert!(r.total_reward > r.base_reward);
    }

    #[test]
    fn highly_correlated_node_gets_no_diversity_bonus() {
        let contribution = VerifiedMarginalContribution {
            newly_solved_cases: 20,
            residual_cases_before: 100,
            mean_positive_error_corr_micros: 900_000,
            contribution_evidence_root: [7; 32],
        };
        let r = reward_breakdown(&receipt(500_000), &contribution, &policy()).unwrap();
        assert!(!r.diversity_eligible);
        assert_eq!(r.diversity_bonus, 0);
    }
}
