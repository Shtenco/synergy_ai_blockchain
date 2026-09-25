use super::actions::{CbPolicy, EconomyActionError, TraderAction};
use super::constants::*;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Asset {
    Usdc = 0,
    Rubx = 1,
    Rubz = 2,
    Weth = 3,
    Syna = 4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EconomyError {
    Action(EconomyActionError),
    InvalidActor,
    InvalidAmount,
    InsufficientBalance,
    InsufficientCollateral,
    InsufficientFundInventory,
    Overflow,
}
impl From<EconomyActionError> for EconomyError {
    fn from(value: EconomyActionError) -> Self {
        Self::Action(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EconomyAccount {
    pub balances: [i128; 5],
    pub locked: [i128; 5],
    pub syna_debt: i128,
}
impl EconomyAccount {
    pub fn new(usdc: i128, weth: i128, syna: i128) -> Self {
        let mut balances = [0; 5];
        balances[Asset::Usdc as usize] = usdc;
        balances[Asset::Weth as usize] = weth;
        balances[Asset::Syna as usize] = syna;
        Self {
            balances,
            locked: [0; 5],
            syna_debt: 0,
        }
    }
    pub fn balance(&self, asset: Asset) -> i128 {
        self.balances[asset as usize]
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgenticEconomyState {
    pub agents: Vec<EconomyAccount>,
    pub cb: EconomyAccount,
    pub fund: EconomyAccount,
    pub hard_nav_micro: i128,
    pub collateral_nav_micro: i128,
    pub gross_tvl_micro: i128,
    pub net_external_capital_flow_micro: i128,
    pub realized_external_pnl_micro: i128,
    pub gas_paid_micro: i128,
    pub syna_supply_micro: i128,
    pub cb_mints: u8,
    pub block_height: u64,
    pub last_gas_execution_block: u64,
}

impl AgenticEconomyState {
    pub fn genesis(scale: i128) -> Result<Self, EconomyError> {
        if scale <= 0 {
            return Err(EconomyError::InvalidAmount);
        }
        let agents = (0..DQN_TRADERS)
            .map(|_| EconomyAccount::new(12 * MICRO * scale, 1_040 * scale, 5 * MICRO * scale))
            .collect();
        let cb = EconomyAccount::new(4_500_000 * scale, 900 * scale, 12 * MICRO * scale);
        let fund = EconomyAccount::new(MICRO * scale, 0, 30 * MICRO * scale);
        let hard = 100 * MICRO * scale;
        Ok(Self {
            agents,
            cb,
            fund,
            hard_nav_micro: hard,
            collateral_nav_micro: hard,
            gross_tvl_micro: hard,
            net_external_capital_flow_micro: 0,
            realized_external_pnl_micro: 0,
            gas_paid_micro: 0,
            syna_supply_micro: 72 * MICRO * scale,
            cb_mints: 0,
            block_height: 0,
            last_gas_execution_block: 0,
        })
    }

    pub fn capital_adjusted_wealth_micro(&self) -> i128 {
        self.hard_nav_micro - self.net_external_capital_flow_micro
    }

    pub fn transfer(
        &mut self,
        from: usize,
        to: usize,
        asset: Asset,
        amount: i128,
    ) -> Result<(), EconomyError> {
        if amount <= 0 || from == to {
            return Err(EconomyError::InvalidAmount);
        }
        if from >= self.agents.len() || to >= self.agents.len() {
            return Err(EconomyError::InvalidActor);
        }
        let i = asset as usize;
        if self.agents[from].balances[i] < amount {
            return Err(EconomyError::InsufficientBalance);
        }
        self.agents[from].balances[i] -= amount;
        self.agents[to].balances[i] = self.agents[to].balances[i]
            .checked_add(amount)
            .ok_or(EconomyError::Overflow)?;
        Ok(())
    }

    pub fn record_external_capital_flow(&mut self, amount: i128) -> Result<(), EconomyError> {
        self.hard_nav_micro = self
            .hard_nav_micro
            .checked_add(amount)
            .ok_or(EconomyError::Overflow)?;
        self.net_external_capital_flow_micro = self
            .net_external_capital_flow_micro
            .checked_add(amount)
            .ok_or(EconomyError::Overflow)?;
        Ok(())
    }

    pub fn record_external_pnl(&mut self, pnl: i128) -> Result<(), EconomyError> {
        self.hard_nav_micro = self
            .hard_nav_micro
            .checked_add(pnl)
            .ok_or(EconomyError::Overflow)?;
        self.realized_external_pnl_micro = self
            .realized_external_pnl_micro
            .checked_add(pnl)
            .ok_or(EconomyError::Overflow)?;
        Ok(())
    }

    pub fn record_collateral_lock(
        &mut self,
        unique: i128,
        gross: i128,
    ) -> Result<(), EconomyError> {
        if unique < 0 || gross < unique {
            return Err(EconomyError::InvalidAmount);
        }
        self.collateral_nav_micro = self
            .collateral_nav_micro
            .checked_add(unique)
            .ok_or(EconomyError::Overflow)?;
        self.gross_tvl_micro = self
            .gross_tvl_micro
            .checked_add(gross)
            .ok_or(EconomyError::Overflow)?;
        Ok(())
    }

    pub fn inventory_syna_mint(
        &mut self,
        actor: usize,
        syna: i128,
        collateral_usdc: i128,
    ) -> Result<(), EconomyError> {
        if actor >= self.agents.len() {
            return Err(EconomyError::InvalidActor);
        }
        if syna <= 0 || collateral_usdc <= 0 {
            return Err(EconomyError::InvalidAmount);
        }
        if self.fund.balance(Asset::Syna) < syna {
            return Err(EconomyError::InsufficientFundInventory);
        }
        if collateral_usdc * 10_000 < syna * AGENT_COLLATERAL_BPS as i128 {
            return Err(EconomyError::InsufficientCollateral);
        }
        if self.agents[actor].balance(Asset::Usdc) < collateral_usdc {
            return Err(EconomyError::InsufficientBalance);
        }
        self.agents[actor].balances[0] -= collateral_usdc;
        self.agents[actor].locked[0] += collateral_usdc;
        self.fund.balances[4] -= syna;
        self.agents[actor].balances[4] += syna;
        self.agents[actor].syna_debt += syna;
        self.record_collateral_lock(collateral_usdc, collateral_usdc)?;
        Ok(())
    }

    pub fn burn_syna(&mut self, actor: usize, amount: i128) -> Result<(), EconomyError> {
        if actor >= self.agents.len() {
            return Err(EconomyError::InvalidActor);
        }
        if amount <= 0 || self.agents[actor].balance(Asset::Syna) < amount {
            return Err(EconomyError::InsufficientBalance);
        }
        self.agents[actor].balances[4] -= amount;
        self.syna_supply_micro = self
            .syna_supply_micro
            .checked_sub(amount)
            .ok_or(EconomyError::Overflow)?;
        Ok(())
    }

    pub fn apply_cb_action(&mut self, action: u8) -> Result<CbPolicy, EconomyError> {
        let p = CbPolicy::decode(action)?;
        if p.syna_policy == 2 && self.cb_mints < CB_MINT_LIMIT {
            let mint = self
                .syna_supply_micro
                .checked_mul(CB_MINT_BPS as i128)
                .ok_or(EconomyError::Overflow)?
                / 10_000;
            self.cb.balances[4] = self.cb.balances[4]
                .checked_add(mint)
                .ok_or(EconomyError::Overflow)?;
            self.syna_supply_micro = self
                .syna_supply_micro
                .checked_add(mint)
                .ok_or(EconomyError::Overflow)?;
            self.cb_mints += 1;
        }
        Ok(p)
    }

    /// Synthetic deterministic action mix used only by the throughput benchmark.
    ///
    /// The authoritative DQN/economy runtime is pinned under
    /// reference/agentic_ai_economy_v8_1. Production economy results enter
    /// consensus through AgenticEconomyTransitionReceipt, not through this helper.
    pub fn apply_benchmark_action(&mut self, actor: usize, action: u8) -> Result<(), EconomyError> {
        let a = TraderAction::try_from(action)?;
        match a {
            TraderAction::Hold => {}
            TraderAction::SyntheticMint => self.inventory_syna_mint(actor, 2_500_000, 3_750_000)?,
            TraderAction::SyntheticBurn => self.burn_syna(actor, 500_000)?,
            _ => self.transfer(actor, (actor + 1) % self.agents.len(), Asset::Usdc, 1)?,
        }
        Ok(())
    }

    pub fn advance_block(&mut self) {
        self.block_height = self.block_height.saturating_add(1);
    }

    pub fn commitment(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"SYNERGY_AGENTIC_ECONOMY_V1");
        h.update(SYNERGY_CHAIN_ID.to_be_bytes());
        h.update(SOURCE_COMMIT.as_bytes());
        h.update(self.block_height.to_be_bytes());
        for v in [
            self.hard_nav_micro,
            self.collateral_nav_micro,
            self.gross_tvl_micro,
            self.net_external_capital_flow_micro,
            self.realized_external_pnl_micro,
            self.gas_paid_micro,
            self.syna_supply_micro,
        ] {
            h.update(v.to_be_bytes());
        }
        for a in &self.agents {
            for v in a.balances {
                h.update(v.to_be_bytes());
            }
        }
        h.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn action_spaces_are_closed() {
        for i in 0..32 {
            assert_eq!(TraderAction::try_from(i).unwrap() as u8, i);
        }
        assert!(TraderAction::try_from(32).is_err());
        assert!(CbPolicy::decode(89).is_ok());
        assert!(CbPolicy::decode(90).is_err());
    }
    #[test]
    fn internal_mint_does_not_create_hard_nav() {
        let mut s = AgenticEconomyState::genesis(1).unwrap();
        let h = s.hard_nav_micro;
        s.inventory_syna_mint(0, 2_500_000, 3_750_000).unwrap();
        assert_eq!(s.hard_nav_micro, h);
    }
    #[test]
    fn capital_flow_is_not_profit() {
        let mut s = AgenticEconomyState::genesis(1).unwrap();
        let w = s.capital_adjusted_wealth_micro();
        s.record_external_capital_flow(50_000_000).unwrap();
        assert_eq!(s.capital_adjusted_wealth_micro(), w);
    }
    #[test]
    fn rehypothecation_does_not_create_hard_nav() {
        let mut s = AgenticEconomyState::genesis(1).unwrap();
        let h = s.hard_nav_micro;
        s.record_collateral_lock(1_000_000, 5_000_000).unwrap();
        assert_eq!(s.hard_nav_micro, h);
        assert!(s.gross_tvl_micro > s.collateral_nav_micro);
    }
    #[test]
    fn cb_mint_is_capped() {
        let mut s = AgenticEconomyState::genesis(1).unwrap();
        for _ in 0..20 {
            s.apply_cb_action(89).unwrap();
        }
        assert_eq!(s.cb_mints, 5);
    }
    #[test]
    fn source_commit_is_bound() {
        let mut s = AgenticEconomyState::genesis(1).unwrap();
        let a = s.commitment();
        s.advance_block();
        assert_ne!(a, s.commitment());
        assert_eq!(SOURCE_COMMIT, "113ef7df80d465958dc75e63b4afcd358dd39aa3");
    }
}
