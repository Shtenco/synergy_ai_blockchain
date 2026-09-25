//! Deterministic SYNA emission policy.
//!
//! Proof of useful inference establishes eligibility; this policy bounds the
//! quantity. AI output never chooses its own reward amount.

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
        if let Some(cap) = self.max_supply {
            if cap == 0 || cap < self.max_emission_per_epoch {
                return Err("invalid SYNA supply cap");
            }
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
        if epoch > self.current_epoch {
            self.current_epoch = epoch;
            self.epoch_emission = 0;
        }
        let next_epoch = self
            .epoch_emission
            .checked_add(amount)
            .ok_or("SYNA epoch emission overflow")?;
        if next_epoch > policy.max_emission_per_epoch {
            return Err("SYNA epoch cap exceeded");
        }
        let next_supply = self
            .total_supply
            .checked_add(amount)
            .ok_or("SYNA supply overflow")?;
        if let Some(cap) = policy.max_supply {
            if next_supply > cap {
                return Err("SYNA max supply exceeded");
            }
        }
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
    }

    #[test]
    fn model_cannot_self_select_unbounded_reward() {
        let p = policy();
        assert_eq!(p.reward_for_useful_work(5), None);
        assert_eq!(p.reward_for_useful_work(10), Some(1));
        assert_eq!(p.reward_for_useful_work(10_000), Some(100));
    }
}
