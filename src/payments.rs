//! Consensus-neutral primitives for globally sharded payment settlement.
//!
//! The design intentionally avoids forcing every retail payment through one
//! serial global execution lane. Edge/corridor lanes can execute independently
//! and commit bounded settlement batches to the canonical SYNERGY chain.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentRail {
    SynergyNative,
    Evm,
    Bitcoin,
    Lightning,
    Solana,
    Bank,
    Cbdc,
    Card,
    CashAgent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettlementState {
    Accepted,
    Reserved,
    Executed,
    Finalized,
    Reversed,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentIntent {
    pub intent_id: [u8; 32],
    pub payer: [u8; 32],
    pub payee: [u8; 32],
    pub asset_id: [u8; 32],
    pub amount: u128,
    pub max_fee: u128,
    pub source_rail: PaymentRail,
    pub destination_rail: PaymentRail,
    pub corridor_id: [u8; 16],
    pub compliance_commitment: [u8; 32],
    pub expires_at: u64,
}

impl PaymentIntent {
    pub fn validate(&self, now: u64) -> Result<(), &'static str> {
        if self.intent_id == [0; 32] {
            return Err("intent id required");
        }
        if self.payer == [0; 32] || self.payee == [0; 32] {
            return Err("payer/payee required");
        }
        if self.amount == 0 {
            return Err("amount must be positive");
        }
        if self.expires_at <= now {
            return Err("intent expired");
        }
        Ok(())
    }
}

/// A compact commitment produced by an execution lane/corridor.
///
/// Individual payment details may remain in the lane's availability layer; the
/// canonical chain commits the batch root, accounting totals and finality proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementBatch {
    pub lane_id: [u8; 16],
    pub sequence: u64,
    pub intents_root: [u8; 32],
    pub accounting_root: [u8; 32],
    pub availability_root: [u8; 32],
    pub item_count: u32,
    pub gross_amount: u128,
    pub total_fees: u128,
    pub finality_proof_commitment: [u8; 32],
}

impl SettlementBatch {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.lane_id == [0; 16] {
            return Err("lane id required");
        }
        if self.item_count == 0 {
            return Err("empty batch");
        }
        if self.intents_root == [0; 32]
            || self.accounting_root == [0; 32]
            || self.availability_root == [0; 32]
        {
            return Err("batch commitments required");
        }
        if self.total_fees > self.gross_amount {
            return Err("fees exceed gross amount");
        }
        Ok(())
    }
}

/// Stable partition key used by edge routers. It keeps hot corridors independent
/// while preserving deterministic settlement ordering within each lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PaymentLaneKey {
    pub jurisdiction: [u8; 2],
    pub asset_class: u16,
    pub corridor_bucket: u32,
    pub epoch: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_expired_intent() {
        let p = PaymentIntent {
            intent_id: [1; 32],
            payer: [2; 32],
            payee: [3; 32],
            asset_id: [4; 32],
            amount: 100,
            max_fee: 2,
            source_rail: PaymentRail::SynergyNative,
            destination_rail: PaymentRail::Bank,
            corridor_id: [5; 16],
            compliance_commitment: [6; 32],
            expires_at: 10,
        };
        assert!(p.validate(10).is_err());
    }

    #[test]
    fn rejects_fee_larger_than_batch_gross() {
        let batch = SettlementBatch {
            lane_id: [1; 16],
            sequence: 1,
            intents_root: [2; 32],
            accounting_root: [3; 32],
            availability_root: [4; 32],
            item_count: 5,
            gross_amount: 100,
            total_fees: 101,
            finality_proof_commitment: [5; 32],
        };
        assert!(batch.validate().is_err());
    }
}
