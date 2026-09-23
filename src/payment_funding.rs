//! Canonical funding commitments for horizontally sharded Meta Pay.
//!
//! Settlement lanes are partitioned by corridor, but spend authority is not.
//! A source `(payer, asset)` balance must be reserved exactly once before any
//! destination lane can consume it, preventing cross-lane double spending.

use sha2::{Digest, Sha256};

use crate::payments::{PaymentIntent, SettlementBatchAuthorization};

const FUNDING_CONSUMPTION_DOMAIN: &[u8] = b"SYNERGY/PAYMENT-FUNDING-CONSUMPTION/V1\0";
const FUNDING_RELEASE_DOMAIN: &[u8] = b"SYNERGY/PAYMENT-FUNDING-RELEASE/V1\0";
const FUNDED_SETTLEMENT_DOMAIN: &[u8] = b"SYNERGY/FUNDED-SETTLEMENT/V1\0";


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
    pub fn validate_against_intent(
        &self,
        intent: &PaymentIntent,
        now: u64,
    ) -> Result<(), &'static str> {
        self.validate_reserved()?;
        intent.validate(now)?;

        let intent_root = intent
            .authorization_commitment()
            .ok_or("payment intent commitment required")?;
        if self.payment_intent_root != intent_root {
            return Err("funding reservation payment intent root mismatch");
        }
        if self.amount != intent.amount {
            return Err("funding reservation amount/intention mismatch");
        }
        if self.payer_account_root != intent.payer {
            return Err("funding reservation payer account mismatch");
        }
        Ok(())
    }
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
    pub fn canonical_root(
        reservation: &PaymentFundingReservation,
    ) -> Option<[u8; 32]> {
        reservation.validate_reserved().ok()?;
        let mut hasher = Sha256::new();
        hasher.update(FUNDING_CONSUMPTION_DOMAIN);
        hasher.update(reservation.reservation_root);
        hasher.update(reservation.payment_intent_root);
        hasher.update(reservation.payer_account_root);
        hasher.update(reservation.source_asset_root);
        hasher.update(reservation.amount.to_be_bytes());
        hasher.update(reservation.account_sequence.to_be_bytes());
        hasher.update(reservation.funding_shard.to_be_bytes());
        hasher.update(reservation.epoch.to_be_bytes());
        Some(hasher.finalize().into())
    }

    pub(crate) fn validate_against_intent(
        &self,
        reservation: &PaymentFundingReservation,
        intent: &PaymentIntent,
        now: u64,
    ) -> Result<(), &'static str> {
        reservation.validate_against_intent(intent, now)?;
        self.validate_against(reservation)
    }

    pub(crate) fn validate_against(
        &self,
        reservation: &PaymentFundingReservation,
    ) -> Result<(), &'static str> {
        reservation.validate_reserved()?;
        let expected_consumption_root =
            Self::canonical_root(reservation).ok_or("funding consumption root unavailable")?;
        if self.consumption_root != expected_consumption_root {
            return Err("funding consumption root mismatch");
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
pub struct PaymentFundingReleaseReceipt {
    pub reservation_root: [u8; 32],
    pub reason_root: [u8; 32],
    pub release_root: [u8; 32],
}

impl PaymentFundingReleaseReceipt {
    pub fn canonical_root(
        reservation: &PaymentFundingReservation,
        reason_root: [u8; 32],
    ) -> Option<[u8; 32]> {
        reservation.validate_reserved().ok()?;
        if reason_root == [0u8; 32] {
            return None;
        }
        let mut hasher = Sha256::new();
        hasher.update(FUNDING_RELEASE_DOMAIN);
        hasher.update(reservation.reservation_root);
        hasher.update(reservation.payment_intent_root);
        hasher.update(reservation.payer_account_root);
        hasher.update(reservation.source_asset_root);
        hasher.update(reservation.amount.to_be_bytes());
        hasher.update(reservation.account_sequence.to_be_bytes());
        hasher.update(reservation.funding_shard.to_be_bytes());
        hasher.update(reservation.epoch.to_be_bytes());
        hasher.update(reason_root);
        Some(hasher.finalize().into())
    }

    pub fn validate_against(
        &self,
        reservation: &PaymentFundingReservation,
    ) -> Result<(), &'static str> {
        if self.reservation_root != reservation.reservation_root || self.reason_root == [0u8; 32] {
            return Err("funding release does not match reservation");
        }
        let expected = Self::canonical_root(reservation, self.reason_root)
            .ok_or("funding release root unavailable")?;
        if self.release_root != expected {
            return Err("funding release root mismatch");
        }
        Ok(())
    }
}

impl PaymentFundingReservation {
    pub fn consume_once(
        &mut self,
        receipt: &PaymentFundingConsumptionReceipt,
        intent: &PaymentIntent,
        now: u64,
    ) -> Result<[u8; 32], &'static str> {
        receipt.validate_against_intent(self, intent, now)?;
        let root = receipt.consumption_root;
        self.status = FundingStatus::Consumed;
        Ok(root)
    }

    pub fn release_once(
        &mut self,
        receipt: &PaymentFundingReleaseReceipt,
    ) -> Result<[u8; 32], &'static str> {
        self.validate_reserved()?;
        receipt.validate_against(self)?;
        let root = receipt.release_root;
        self.status = FundingStatus::Released;
        Ok(root)
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

    pub fn validate_against_batch(
        &self,
        authorized: &SettlementBatchAuthorization,
    ) -> Result<(), &'static str> {
        self.validate()?;
        let expected_batch_root = authorized
            .batch
            .authorization_commitment()
            .ok_or("settlement batch commitment unavailable")?;
        if self.settlement_batch_root != expected_batch_root {
            return Err("funded settlement batch root mismatch");
        }
        if self.settlement_item_count != u64::from(authorized.batch.item_count) {
            return Err("funded settlement item count mismatch");
        }
        Ok(())
    }

    pub fn canonical_root(
        &self,
        authorized: &SettlementBatchAuthorization,
    ) -> Option<[u8; 32]> {
        self.validate_against_batch(authorized).ok()?;

        let mut hasher = Sha256::new();
        hasher.update(FUNDED_SETTLEMENT_DOMAIN);
        hasher.update(authorized.chain_id);
        hasher.update(authorized.epoch.to_be_bytes());
        hasher.update(self.settlement_batch_root);
        hasher.update(self.funding_consumption_root);
        hasher.update(self.settlement_item_count.to_be_bytes());
        hasher.update(self.funding_receipt_count.to_be_bytes());
        Some(hasher.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payments::{PaymentIntent, PaymentRail};

    fn intent() -> PaymentIntent {
        PaymentIntent {
            intent_id: [10; 32],
            payer: [11; 32],
            payee: [12; 32],
            asset_id: [13; 32],
            amount: 700,
            max_fee: 5,
            source_rail: PaymentRail::SynergyNative,
            destination_rail: PaymentRail::Bank,
            corridor_id: [14; 16],
            compliance_commitment: [15; 32],
            expires_at: 1_000,
        }
    }

    fn reservation() -> PaymentFundingReservation {
        let payment_intent_root = intent()
            .authorization_commitment()
            .expect("intent commitment");
        PaymentFundingReservation {
            reservation_id: [1; 32],
            reservation_root: [2; 32],
            payment_intent_root,
            payer_account_root: intent().payer,
            source_asset_root: [5; 32],
            amount: 700,
            account_sequence: 9,
            funding_shard: 12,
            epoch: 7,
            status: FundingStatus::Reserved,
        }
    }

    #[test]
    fn reservation_rejects_cross_account_funding_substitution() {
        let mut r = reservation();
        let intent = intent();
        r.payer_account_root[0] ^= 1;
        assert!(r.validate_against_intent(&intent, 100).is_err());
    }

    #[test]
    fn reservation_is_bound_to_exact_payment_intent() {
        let reservation = reservation();
        let intent = intent();
        assert_eq!(reservation.validate_against_intent(&intent, 100), Ok(()));

        let mut changed = intent.clone();
        changed.amount += 1;
        assert!(reservation.validate_against_intent(&changed, 100).is_err());
    }

    #[test]
    fn consumption_must_match_source_reservation() {
        let r = reservation();
        let mut c = PaymentFundingConsumptionReceipt {
            reservation_root: r.reservation_root,
            consumption_root: PaymentFundingConsumptionReceipt::canonical_root(&r)
                .expect("canonical consumption root"),
            payment_intent_root: r.payment_intent_root,
            payer_account_root: r.payer_account_root,
            source_asset_root: r.source_asset_root,
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
    fn funding_consumption_rechecks_intent_and_expiry() {
        let r = reservation();
        let intent = intent();
        let receipt = PaymentFundingConsumptionReceipt {
            reservation_root: r.reservation_root,
            consumption_root: PaymentFundingConsumptionReceipt::canonical_root(&r)
                .expect("canonical consumption root"),
            payment_intent_root: r.payment_intent_root,
            payer_account_root: r.payer_account_root,
            source_asset_root: r.source_asset_root,
            amount: r.amount,
            account_sequence: r.account_sequence,
            funding_shard: r.funding_shard,
            epoch: r.epoch,
        };

        assert_eq!(receipt.validate_against_intent(&r, &intent, 999), Ok(()));
        assert!(receipt.validate_against_intent(&r, &intent, 1_000).is_err());

        let mut changed = intent;
        changed.amount += 1;
        assert!(receipt.validate_against_intent(&r, &changed, 100).is_err());
    }

    #[test]
    fn funding_reservation_consumes_exactly_once() {
        let mut reservation = reservation();
        let intent = intent();
        let receipt = PaymentFundingConsumptionReceipt {
            reservation_root: reservation.reservation_root,
            consumption_root: PaymentFundingConsumptionReceipt::canonical_root(&reservation)
                .expect("canonical consumption root"),
            payment_intent_root: reservation.payment_intent_root,
            payer_account_root: reservation.payer_account_root,
            source_asset_root: reservation.source_asset_root,
            amount: reservation.amount,
            account_sequence: reservation.account_sequence,
            funding_shard: reservation.funding_shard,
            epoch: reservation.epoch,
        };

        assert!(reservation.consume_once(&receipt, &intent, 100).is_ok());
        assert_eq!(reservation.status, FundingStatus::Consumed);
        assert!(reservation.consume_once(&receipt, &intent, 100).is_err());
    }

    #[test]
    fn funding_reservation_releases_exactly_once() {
        let mut reservation = reservation();
        let reason_root = [0x77; 32];
        let receipt = PaymentFundingReleaseReceipt {
            reservation_root: reservation.reservation_root,
            reason_root,
            release_root: PaymentFundingReleaseReceipt::canonical_root(&reservation, reason_root)
                .expect("canonical release root"),
        };

        assert!(reservation.release_once(&receipt).is_ok());
        assert_eq!(reservation.status, FundingStatus::Released);
        assert!(reservation.release_once(&receipt).is_err());
    }

    #[test]
    fn funded_settlement_root_binds_exact_authorized_batch_and_funding() {
        use crate::pq::{AuthPolicy, AuthScheme, HybridAuthorization, SignatureEvidence,
            ML_DSA_87_PUBLIC_KEY_BYTES, ML_DSA_87_SIGNATURE_BYTES,
            SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES, SLH_DSA_SHAKE_256S_SIGNATURE_BYTES};

        let batch = SettlementBatchAuthorization {
            chain_id: [0xA1; 32],
            epoch: 7,
            nonce: 3,
            expires_at: 100,
            batch: crate::payments::SettlementBatch {
                lane_id: [0xA2; 16],
                sequence: 1,
                intents_root: [0xA3; 32],
                accounting_root: [0xA4; 32],
                availability_root: [0xA5; 32],
                item_count: 2,
                gross_amount: 200,
                total_fees: 2,
                finality_proof_commitment: [0xA6; 32],
            },
            authorization: HybridAuthorization {
                policy: AuthPolicy::PqOnly,
                evidence: vec![
                    SignatureEvidence {
                        scheme: AuthScheme::MlDsa87,
                        public_key: vec![1; ML_DSA_87_PUBLIC_KEY_BYTES],
                        signature: vec![2; ML_DSA_87_SIGNATURE_BYTES],
                    },
                    SignatureEvidence {
                        scheme: AuthScheme::SlhDsaShake256s,
                        public_key: vec![3; SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES],
                        signature: vec![4; SLH_DSA_SHAKE_256S_SIGNATURE_BYTES],
                    },
                ],
            },
        };
        let batch_root = batch.batch.authorization_commitment().expect("batch root");
        let funded = FundedSettlementCommitment {
            settlement_batch_root: batch_root,
            funding_consumption_root: [0xA7; 32],
            settlement_item_count: 2,
            funding_receipt_count: 2,
        };
        let root = funded.canonical_root(&batch).expect("funded settlement root");

        let mut changed = funded.clone();
        changed.funding_consumption_root[0] ^= 1;
        assert_ne!(
            root,
            changed.canonical_root(&batch).expect("changed funded root")
        );

        let mut wrong = funded.clone();
        wrong.settlement_batch_root[0] ^= 1;
        assert!(wrong.canonical_root(&batch).is_none());
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
