//! Native SYNA mint state-transition receipt.
//!
//! The useful-inference reward module authorizes issuance. This module binds
//! that authorization to an explicit account/supply transition so a block can
//! commit who received the newly issued SYNA and which monetary state resulted.

use sha2::{Digest, Sha256};

use crate::{SynaMintAuthorization, SynaSupplyState};

pub const SYNA_MINT_TRANSITION_DOMAIN: &[u8] = b"SYNERGY/SYNA-MINT-TRANSITION/V1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SynaMintTransition {
    pub authorization_root: [u8; 32],
    pub claim_id: [u8; 32],
    pub worker_id: [u8; 32],
    pub amount: u128,
    pub epoch: u64,
    pub account_balance_before: u128,
    pub account_balance_after: u128,
    pub total_supply_before: u128,
    pub total_supply_after: u128,
    pub pre_supply_state_root: [u8; 32],
    pub supply_state_root: [u8; 32],
    pub checkpoint_root: [u8; 32],
}

impl SynaMintTransition {
    pub fn validate(
        &self,
        authorization: &SynaMintAuthorization,
        pre_supply: &SynaSupplyState,
        post_supply: &SynaSupplyState,
    ) -> Result<(), &'static str> {
        if self.authorization_root != authorization.commitment()
            || self.claim_id != authorization.claim_id()
            || self.worker_id != authorization.worker_id()
            || self.amount != authorization.amount()
            || self.epoch != authorization.epoch()
            || self.checkpoint_root != authorization.checkpoint_root()
            || self.pre_supply_state_root != authorization.pre_supply_state_root()
            || self.supply_state_root != authorization.supply_state_root()
            || self.amount == 0
        {
            return Err("SYNA mint transition authorization mismatch");
        }

        let expected_balance = self
            .account_balance_before
            .checked_add(self.amount)
            .ok_or("SYNA account balance overflow")?;
        let expected_supply = self
            .total_supply_before
            .checked_add(self.amount)
            .ok_or("SYNA total supply transition overflow")?;

        if self.account_balance_after != expected_balance
            || self.total_supply_after != expected_supply
            || pre_supply.total_supply != self.total_supply_before
            || pre_supply.commitment() != Some(self.pre_supply_state_root)
            || post_supply.total_supply != self.total_supply_after
            || post_supply.current_epoch != self.epoch
            || post_supply.commitment() != Some(self.supply_state_root)
        {
            return Err("invalid SYNA mint state transition");
        }
        Ok(())
    }

    pub fn commitment(
        &self,
        authorization: &SynaMintAuthorization,
        pre_supply: &SynaSupplyState,
        post_supply: &SynaSupplyState,
    ) -> Option<[u8; 32]> {
        self.validate(authorization, pre_supply, post_supply).ok()?;
        let mut h = Sha256::new();
        h.update(SYNA_MINT_TRANSITION_DOMAIN);
        h.update(self.authorization_root);
        h.update(self.claim_id);
        h.update(self.worker_id);
        h.update(self.amount.to_be_bytes());
        h.update(self.epoch.to_be_bytes());
        h.update(self.account_balance_before.to_be_bytes());
        h.update(self.account_balance_after.to_be_bytes());
        h.update(self.total_supply_before.to_be_bytes());
        h.update(self.total_supply_after.to_be_bytes());
        h.update(self.pre_supply_state_root);
        h.update(self.supply_state_root);
        h.update(self.checkpoint_root);
        Some(h.finalize().into())
    }
}

pub fn build_syna_mint_transition(
    authorization: &SynaMintAuthorization,
    account_balance_before: u128,
    pre_supply: &SynaSupplyState,
    post_supply: &SynaSupplyState,
) -> Result<SynaMintTransition, &'static str> {
    let total_supply_before = pre_supply.total_supply;
    let account_balance_after = account_balance_before
        .checked_add(authorization.amount())
        .ok_or("SYNA account balance overflow")?;
    let total_supply_after = total_supply_before
        .checked_add(authorization.amount())
        .ok_or("SYNA total supply transition overflow")?;

    let transition = SynaMintTransition {
        authorization_root: authorization.commitment(),
        claim_id: authorization.claim_id(),
        worker_id: authorization.worker_id(),
        amount: authorization.amount(),
        epoch: authorization.epoch(),
        account_balance_before,
        account_balance_after,
        total_supply_before,
        total_supply_after,
        pre_supply_state_root: authorization.pre_supply_state_root(),
        supply_state_root: authorization.supply_state_root(),
        checkpoint_root: authorization.checkpoint_root(),
    };
    transition.validate(authorization, pre_supply, post_supply)?;
    Ok(transition)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pre_supply() -> SynaSupplyState {
        SynaSupplyState {
            policy_version: 1,
            current_epoch: 7,
            total_supply: 1_000,
            epoch_emission: 0,
        }
    }

    fn post_supply() -> SynaSupplyState {
        SynaSupplyState {
            policy_version: 1,
            current_epoch: 7,
            total_supply: 1_010,
            epoch_emission: 10,
        }
    }

    fn authorization_with_worker(
        pre: &SynaSupplyState,
        post: &SynaSupplyState,
        worker_id: [u8; 32],
    ) -> SynaMintAuthorization {
        SynaMintAuthorization::test_only(
            worker_id,
            10,
            7,
            pre.commitment().unwrap(),
            post.commitment().unwrap(),
        )
    }

    fn authorization(pre: &SynaSupplyState, post: &SynaSupplyState) -> SynaMintAuthorization {
        authorization_with_worker(pre, post, [3; 32])
    }

    #[test]
    fn mint_transition_credits_exact_worker_and_supply() {
        let pre = pre_supply();
        let post = post_supply();
        let a = authorization(&pre, &post);
        let t = build_syna_mint_transition(&a, 25, &pre, &post).unwrap();
        assert_eq!(t.account_balance_after, 35);
        assert_eq!(t.total_supply_after, 1_010);
        assert!(t.commitment(&a, &pre, &post).is_some());
    }

    #[test]
    fn fabricated_balance_transition_is_rejected() {
        let pre = pre_supply();
        let post = post_supply();
        let a = authorization(&pre, &post);
        let mut t = build_syna_mint_transition(&a, 25, &pre, &post).unwrap();
        t.account_balance_after += 1;
        assert!(t.commitment(&a, &pre, &post).is_none());
    }

    #[test]
    fn fabricated_authorization_root_is_rejected() {
        let pre = pre_supply();
        let post = post_supply();
        let a = authorization(&pre, &post);
        let mut t = build_syna_mint_transition(&a, 25, &pre, &post).unwrap();
        t.authorization_root[0] ^= 1;
        assert!(t.validate(&a, &pre, &post).is_err());
    }

    #[test]
    fn fabricated_previous_supply_state_is_rejected() {
        let pre = pre_supply();
        let post = post_supply();
        let a = authorization(&pre, &post);
        let t = build_syna_mint_transition(&a, 25, &pre, &post).unwrap();

        let mut forged_pre = pre.clone();
        forged_pre.total_supply -= 1;
        assert!(t.validate(&a, &forged_pre, &post).is_err());
    }

    #[test]
    fn different_worker_authorization_is_rejected() {
        let pre = pre_supply();
        let post = post_supply();
        let a = authorization(&pre, &post);
        let t = build_syna_mint_transition(&a, 25, &pre, &post).unwrap();
        let wrong = authorization_with_worker(&pre, &post, [9; 32]);
        assert!(t.validate(&wrong, &pre, &post).is_err());
    }
}
