//! Deterministic SYNA emission policy.
//!
//! Proof of useful inference establishes eligibility; this policy bounds the
//! quantity. AI output never chooses its own reward amount.

use sha2::{Digest, Sha256};

pub const SYNA_SUPPLY_STATE_DOMAIN: &[u8] = b"SYNERGY/SYNA-SUPPLY-STATE/V1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SynaEmissionPolicy {
    pub version: u32,
    pub max_reward_per_job: u128,
    pub max_emission_per_epoch: u128,
    pub max_supply: Option<u128>,
    pub min_useful_work_units: u128,
}

impl SynaEmissionPolicy {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.version == 0
            || self.max_reward_per_job == 0
            || self.max_emission_per_epoch == 0
            || self.max_reward_per_job > self.max_emission_per_epoch
            || self.min_useful_work_units == 0
        {
            return Err("invalid SYNA emission policy");
        }
        if self
            .max_supply
            .is_some_and(|cap| cap == 0 || cap < self.max_emission_per_epoch)
        {
            return Err("invalid SYNA supply cap");
        }
        Ok(())
    }

    pub fn reward_for_useful_work(&self, useful_work_units: u128) -> Option<u128> {
        self.validate().ok()?;
        if useful_work_units < self.min_useful_work_units {
            return None;
        }
        let units = useful_work_units / self.min_useful_work_units;
        Some(units.min(self.max_reward_per_job))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SynaSupplyState {
    pub policy_version: u32,
    pub current_epoch: u64,
    pub total_supply: u128,
    pub epoch_emission: u128,
}

impl SynaSupplyState {
    pub fn commitment(&self) -> Option<[u8; 32]> {
        if self.policy_version == 0 || self.current_epoch == 0 {
            return None;
        }
        let mut h = Sha256::new();
        h.update(SYNA_SUPPLY_STATE_DOMAIN);
        h.update(self.policy_version.to_be_bytes());
        h.update(self.current_epoch.to_be_bytes());
        h.update(self.total_supply.to_be_bytes());
        h.update(self.epoch_emission.to_be_bytes());
        Some(h.finalize().into())
    }

    pub fn mint_bounded(
        &mut self,
        policy: &SynaEmissionPolicy,
        epoch: u64,
        amount: u128,
    ) -> Result<(), &'static str> {
        policy.validate()?;
        if amount == 0 || amount > policy.max_reward_per_job || epoch == 0 {
            return Err("invalid SYNA mint amount/epoch");
        }
        if self.policy_version != policy.version {
            return Err("SYNA policy version mismatch");
        }
        if epoch < self.current_epoch {
            return Err("SYNA epoch cannot move backward");
        }
        let base_epoch_emission = if epoch > self.current_epoch {
            0
        } else {
            self.epoch_emission
        };
        let next_epoch = base_epoch_emission
            .checked_add(amount)
            .ok_or("SYNA epoch emission overflow")?;
        if next_epoch > policy.max_emission_per_epoch {
            return Err("SYNA epoch cap exceeded");
        }
        let next_supply = self
            .total_supply
            .checked_add(amount)
            .ok_or("SYNA supply overflow")?;
        if policy.max_supply.is_some_and(|cap| next_supply > cap) {
            return Err("SYNA max supply exceeded");
        }
        self.current_epoch = epoch;
        self.epoch_emission = next_epoch;
        self.total_supply = next_supply;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> SynaEmissionPolicy {
        SynaEmissionPolicy {
            version: 1,
            max_reward_per_job: 100,
            max_emission_per_epoch: 1000,
            max_supply: Some(10_000),
            min_useful_work_units: 10,
        }
    }

    #[test]
    fn emission_is_bounded_by_job_epoch_and_supply() {
        let p = policy();
        let mut s = SynaSupplyState {
            policy_version: 1,
            current_epoch: 1,
            total_supply: 0,
            epoch_emission: 0,
        };
        assert!(s.mint_bounded(&p, 1, 100).is_ok());
        assert!(s.mint_bounded(&p, 1, 101).is_err());
        for _ in 0..9 {
            assert!(s.mint_bounded(&p, 1, 100).is_ok());
        }
        assert!(s.mint_bounded(&p, 1, 1).is_err());
        assert!(s.mint_bounded(&p, 2, 100).is_ok());
        assert!(s.commitment().is_some());
    }

    #[test]
    fn failed_future_epoch_mint_does_not_partially_advance_state() {
        let p = policy();
        let mut s = SynaSupplyState {
            policy_version: 1,
            current_epoch: 1,
            total_supply: 900,
            epoch_emission: 900,
        };
        let before = s.clone();

        assert!(s.mint_bounded(&p, 2, 101).is_err());
        assert_eq!(s, before);
    }

    #[test]
    fn global_supply_cap_is_enforced_without_partial_mutation() {
        let p = policy();
        let mut s = SynaSupplyState {
            policy_version: 1,
            current_epoch: 2,
            total_supply: 9_950,
            epoch_emission: 0,
        };
        let before = s.clone();

        assert!(s.mint_bounded(&p, 2, 100).is_err());
        assert_eq!(s, before);
    }

    #[test]
    fn epoch_cannot_move_backward_without_partial_mutation() {
        let p = policy();
        let mut s = SynaSupplyState {
            policy_version: 1,
            current_epoch: 3,
            total_supply: 100,
            epoch_emission: 10,
        };
        let before = s.clone();

        assert!(s.mint_bounded(&p, 2, 10).is_err());
        assert_eq!(s, before);
    }

    #[test]
    fn policy_version_mismatch_is_fail_closed() {
        let p = policy();
        let mut s = SynaSupplyState {
            policy_version: 2,
            current_epoch: 1,
            total_supply: 0,
            epoch_emission: 0,
        };
        let before = s.clone();

        assert!(s.mint_bounded(&p, 1, 10).is_err());
        assert_eq!(s, before);
    }

    #[test]
    fn model_cannot_self_select_unbounded_reward() {
        let p = policy();
        assert_eq!(p.reward_for_useful_work(5), None);
        assert_eq!(p.reward_for_useful_work(10), Some(1));
        assert_eq!(p.reward_for_useful_work(10_000), Some(100));
    }
}
