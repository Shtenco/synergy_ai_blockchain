use sha2::{Digest, Sha256};

use super::actions::{CbPolicy, TraderAction};
use super::constants::{EXACT_DQN_RUNTIME_SHA256, SOURCE_COMMIT, SYNERGY_CHAIN_ID};

pub const AGENTIC_ECONOMY_RECEIPT_DOMAIN: &[u8] = b"SYNERGY/AGENTIC-ECONOMY-TRANSITION/V1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EconomyAccountingSnapshot {
    pub hard_nav_micro: i128,
    pub collateral_nav_micro: i128,
    pub gross_tvl_micro: i128,
    pub net_external_capital_flow_micro: i128,
    pub realized_external_pnl_micro: i128,
    pub gas_paid_micro: i128,
    pub syna_supply_micro: i128,
}

impl EconomyAccountingSnapshot {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.hard_nav_micro < 0
            || self.collateral_nav_micro < 0
            || self.gross_tvl_micro < 0
            || self.gas_paid_micro < 0
            || self.syna_supply_micro < 0
        {
            return Err("negative economy accounting field");
        }
        if self.gross_tvl_micro < self.collateral_nav_micro {
            return Err("gross TVL cannot be below unique collateral NAV");
        }
        Ok(())
    }

    pub fn capital_adjusted_wealth_micro(&self) -> Option<i128> {
        self.hard_nav_micro
            .checked_sub(self.net_external_capital_flow_micro)
    }

    pub fn commitment(&self) -> Option<[u8; 32]> {
        self.validate().ok()?;
        let mut h = Sha256::new();
        h.update(b"SYNERGY/AGENTIC-ECONOMY-ACCOUNTING/V1\0");
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
        Some(h.finalize().into())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EconomyDecision {
    Trader { actor: u16, action: u8 },
    CentralBank { action: u8 },
}

impl EconomyDecision {
    pub fn validate(&self) -> Result<(), &'static str> {
        match *self {
            Self::Trader { actor, action } => {
                if actor >= 6 {
                    return Err("trader actor outside canonical DQN population");
                }
                TraderAction::try_from(action)
                    .map(|_| ())
                    .map_err(|_| "trader action outside canonical DQN action space")
            }
            Self::CentralBank { action } => CbPolicy::decode(action)
                .map(|_| ())
                .map_err(|_| "CB action outside canonical DQN action space"),
        }
    }

    fn update_hasher(&self, h: &mut Sha256) {
        match *self {
            Self::Trader { actor, action } => {
                h.update([0]);
                h.update(actor.to_be_bytes());
                h.update([action]);
            }
            Self::CentralBank { action } => {
                h.update([1]);
                h.update([action]);
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgenticEconomyTransitionReceipt {
    pub chain_id: u64,
    pub sequence: u64,
    pub source_block: u64,
    pub decision: EconomyDecision,
    pub executor_runtime_root: [u8; 32],
    pub model_checkpoint_root: [u8; 32],
    pub observation_root: [u8; 32],
    pub pre_state_root: [u8; 32],
    pub post_state_root: [u8; 32],
    pub action_log_root: [u8; 32],
    pub accounting: EconomyAccountingSnapshot,
}

impl AgenticEconomyTransitionReceipt {
    pub fn validate_static(&self) -> Result<(), &'static str> {
        if self.chain_id != SYNERGY_CHAIN_ID {
            return Err("wrong agentic economy chain id");
        }
        if self.sequence == 0 || self.source_block == 0 {
            return Err("zero economy sequence or source block");
        }
        self.decision.validate()?;
        if self.executor_runtime_root != EXACT_DQN_RUNTIME_SHA256 {
            return Err("wrong exact DQN runtime root");
        }
        if self.model_checkpoint_root == [0; 32]
            || self.observation_root == [0; 32]
            || self.pre_state_root == [0; 32]
            || self.post_state_root == [0; 32]
            || self.action_log_root == [0; 32]
            || self.pre_state_root == self.post_state_root
        {
            return Err("invalid zero/equal economy commitment root");
        }
        self.accounting.validate()
    }

    pub fn commitment(&self) -> Option<[u8; 32]> {
        self.validate_static().ok()?;
        let mut h = Sha256::new();
        h.update(AGENTIC_ECONOMY_RECEIPT_DOMAIN);
        h.update(SOURCE_COMMIT.as_bytes());
        h.update(self.chain_id.to_be_bytes());
        h.update(self.sequence.to_be_bytes());
        h.update(self.source_block.to_be_bytes());
        self.decision.update_hasher(&mut h);
        h.update(self.executor_runtime_root);
        h.update(self.model_checkpoint_root);
        h.update(self.observation_root);
        h.update(self.pre_state_root);
        h.update(self.post_state_root);
        h.update(self.action_log_root);
        h.update(self.accounting.commitment()?);
        Some(h.finalize().into())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgenticEconomyReplayState {
    pub next_sequence: u64,
    pub state_root: [u8; 32],
    pub last_source_block: u64,
}

impl AgenticEconomyReplayState {
    pub fn genesis(state_root: [u8; 32]) -> Result<Self, &'static str> {
        if state_root == [0; 32] {
            return Err("zero agentic economy genesis state");
        }
        Ok(Self {
            next_sequence: 1,
            state_root,
            last_source_block: 0,
        })
    }

    pub fn consume(
        &mut self,
        receipt: &AgenticEconomyTransitionReceipt,
    ) -> Result<[u8; 32], &'static str> {
        receipt.validate_static()?;
        if receipt.sequence != self.next_sequence {
            return Err("agentic economy sequence mismatch");
        }
        if receipt.pre_state_root != self.state_root {
            return Err("agentic economy pre-state mismatch");
        }
        if receipt.source_block <= self.last_source_block {
            return Err("agentic economy source block replay");
        }
        let root = receipt
            .commitment()
            .ok_or("invalid agentic economy receipt")?;
        let next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or("agentic economy sequence overflow")?;
        self.next_sequence = next_sequence;
        self.state_root = receipt.post_state_root;
        self.last_source_block = receipt.source_block;
        Ok(root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accounting() -> EconomyAccountingSnapshot {
        EconomyAccountingSnapshot {
            hard_nav_micro: 100_000_000,
            collateral_nav_micro: 120_000_000,
            gross_tvl_micro: 200_000_000,
            net_external_capital_flow_micro: 10_000_000,
            realized_external_pnl_micro: 2_000_000,
            gas_paid_micro: 1000,
            syna_supply_micro: 72_000_000,
        }
    }

    fn receipt(sequence: u64, block: u64, pre: u8, post: u8) -> AgenticEconomyTransitionReceipt {
        AgenticEconomyTransitionReceipt {
            chain_id: SYNERGY_CHAIN_ID,
            sequence,
            source_block: block,
            decision: EconomyDecision::Trader {
                actor: 2,
                action: 22,
            },
            executor_runtime_root: EXACT_DQN_RUNTIME_SHA256,
            model_checkpoint_root: [7; 32],
            observation_root: [8; 32],
            pre_state_root: [pre; 32],
            post_state_root: [post; 32],
            action_log_root: [9; 32],
            accounting: accounting(),
        }
    }

    #[test]
    fn receipt_binds_exact_source_and_all_transition_roots() {
        let r = receipt(1, 100, 1, 2);
        let a = r.commitment().unwrap();
        let mut changed = r.clone();
        changed.action_log_root[0] ^= 1;
        assert_ne!(a, changed.commitment().unwrap());
        assert_eq!(SOURCE_COMMIT, "113ef7df80d465958dc75e63b4afcd358dd39aa3");
    }

    #[test]
    fn wrong_runtime_is_rejected() {
        let mut r = receipt(1, 100, 1, 2);
        r.executor_runtime_root[0] ^= 1;
        assert!(r.validate_static().is_err());
    }

    #[test]
    fn replay_state_consumes_exact_sequence_once() {
        let mut s = AgenticEconomyReplayState::genesis([1; 32]).unwrap();
        let r = receipt(1, 100, 1, 2);
        assert!(s.consume(&r).is_ok());
        assert!(s.consume(&r).is_err());
    }

    #[test]
    fn disconnected_transition_is_rejected() {
        let mut s = AgenticEconomyReplayState::genesis([1; 32]).unwrap();
        let r = receipt(1, 100, 3, 4);
        assert!(s.consume(&r).is_err());
    }

    #[test]
    fn cb_and_trader_action_spaces_are_enforced() {
        let mut r = receipt(1, 100, 1, 2);
        r.decision = EconomyDecision::Trader {
            actor: 6,
            action: 1,
        };
        assert!(r.validate_static().is_err());
        r.decision = EconomyDecision::CentralBank { action: 90 };
        assert!(r.validate_static().is_err());
    }

    #[test]
    fn accounting_rejects_rehypothecation_as_unique_collateral() {
        let mut a = accounting();
        a.gross_tvl_micro = 100;
        a.collateral_nav_micro = 101;
        assert!(a.validate().is_err());
    }
}
