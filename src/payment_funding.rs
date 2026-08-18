//! Canonical funding commitments for horizontally sharded Meta Pay.
//!
//! Settlement lanes are partitioned by corridor, but spend authority is not.
//! A source `(payer, asset)` balance must be reserved exactly once before any
//! destination lane can consume it, preventing cross-lane double spending.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FundingStatus {
    Reserved,
    Consumed,
    Released,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentFundingReservation {
    pub reservation_id: [u8; 32],
    pub reservation_root: [u8; 32],
    pub payment_intent_root: [u8; 32],
    pub payer_account_root: [u8; 32],
    pub source_asset_root: [u8; 32],
    pub amount: u128,
    pub account_sequence: u64,
    pub funding_shard: u32,
    pub epoch: u64,
    pub status: FundingStatus,
}

impl PaymentFundingReservation {
    pub fn validate_reserved(&self) -> Result<(), &'static str> {
        if self.reservation_id == [0; 32]
            || self.reservation_root == [0; 32]
            || self.payment_intent_root == [0; 32]
            || self.payer_account_root == [0; 32]
            || self.source_asset_root == [0; 32]
        {
            return Err("funding commitments required");
        }
        if self.amount == 0 || self.account_sequence == 0 || self.epoch == 0 {
            return Err("funding amount/sequence/epoch required");
        }
        if self.status != FundingStatus::Reserved {
            return Err("funding reservation must be active");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentFundingConsumptionReceipt {
    pub reservation_root: [u8; 32],
    pub consumption_root: [u8; 32],
    pub payment_intent_root: [u8; 32],
    pub payer_account_root: [u8; 32],
    pub source_asset_root: [u8; 32],
    pub amount: u128,
    pub account_sequence: u64,
    pub funding_shard: u32,
    pub epoch: u64,
}

impl PaymentFundingConsumptionReceipt {
    pub fn validate_against(
        &self,
        reservation: &PaymentFundingReservation,
    ) -> Result<(), &'static str> {
        reservation.validate_reserved()?;
        if self.consumption_root == [0; 32] {
            return Err("funding consumption root required");
        }
        if self.reservation_root != reservation.reservation_root
            || self.payment_intent_root != reservation.payment_intent_root
            || self.payer_account_root != reservation.payer_account_root
            || self.source_asset_root != reservation.source_asset_root
            || self.amount != reservation.amount
            || self.account_sequence != reservation.account_sequence
            || self.funding_shard != reservation.funding_shard
            || self.epoch != reservation.epoch
        {
            return Err("funding consumption does not match reservation");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundedSettlementCommitment {
    pub settlement_batch_root: [u8; 32],
    pub funding_consumption_root: [u8; 32],
    pub settlement_item_count: u64,
    pub funding_receipt_count: u64,
}

impl FundedSettlementCommitment {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.settlement_batch_root == [0; 32] || self.funding_consumption_root == [0; 32] {
            return Err("settlement/funding roots required");
        }
        if self.settlement_item_count == 0 || self.settlement_item_count != self.funding_receipt_count {
            return Err("every settled item requires one funding receipt");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reservation() -> PaymentFundingReservation {
        PaymentFundingReservation {
            reservation_id: [1; 32],
            reservation_root: [2; 32],
            payment_intent_root: [3; 32],
            payer_account_root: [4; 32],
            source_asset_root: [5; 32],
            amount: 700,
            account_sequence: 9,
            funding_shard: 12,
            epoch: 7,
            status: FundingStatus::Reserved,
        }
    }

    #[test]
    fn consumption_must_match_source_reservation() {
        let r = reservation();
        let mut c = PaymentFundingConsumptionReceipt {
            reservation_root: [2; 32],
            consumption_root: [6; 32],
            payment_intent_root: [3; 32],
            payer_account_root: [4; 32],
            source_asset_root: [5; 32],
            amount: 700,
            account_sequence: 9,
            funding_shard: 12,
            epoch: 7,
        };
        assert_eq!(c.validate_against(&r), Ok(()));
        c.amount = 701;
        assert_eq!(
            c.validate_against(&r),
            Err("funding consumption does not match reservation")
        );
    }

    #[test]
    fn final_batch_requires_one_funding_receipt_per_payment() {
        let good = FundedSettlementCommitment {
            settlement_batch_root: [1; 32],
            funding_consumption_root: [2; 32],
            settlement_item_count: 10,
            funding_receipt_count: 10,
        };
        assert_eq!(good.validate(), Ok(()));
        let bad = FundedSettlementCommitment { funding_receipt_count: 9, ..good };
        assert_eq!(
            bad.validate(),
            Err("every settled item requires one funding receipt")
        );
    }
}
