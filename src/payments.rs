//! Consensus-neutral primitives for globally sharded payment settlement.
//!
//! The design intentionally avoids forcing every retail payment through one
//! serial global execution lane. Edge/corridor lanes can execute independently
//! and commit bounded settlement batches to the canonical SYNERGY chain.

use sha2::{Digest, Sha256};

use crate::pq::{
    verify_envelope_authorization, AuthPolicy, AuthorizationDomain, AuthorizationEnvelope,
    AuthorizationReplayState, AuthorizationValidationContext, ContextSignatureVerifier, HybridAuthorization,
};

const PAYMENT_INTENT_DOMAIN: &[u8] = b"SYNERGY/PAYMENT-INTENT/V1\0";


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

impl PaymentRail {
    pub const fn protocol_code(self) -> u8 {
        match self {
            Self::SynergyNative => 1,
            Self::Evm => 2,
            Self::Bitcoin => 3,
            Self::Lightning => 4,
            Self::Solana => 5,
            Self::Bank => 6,
            Self::Cbdc => 7,
            Self::Card => 8,
            Self::CashAgent => 9,
        }
    }
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


impl PaymentIntent {
    pub fn authorization_commitment(&self) -> Option<[u8; 32]> {
        self.validate(0).ok()?;
        if self.asset_id == [0u8; 32]
            || self.corridor_id == [0u8; 16]
            || self.compliance_commitment == [0u8; 32]
        {
            return None;
        }

        let mut hasher = Sha256::new();
        hasher.update(PAYMENT_INTENT_DOMAIN);
        hasher.update(self.intent_id);
        hasher.update(self.payer);
        hasher.update(self.payee);
        hasher.update(self.asset_id);
        hasher.update(self.amount.to_be_bytes());
        hasher.update(self.max_fee.to_be_bytes());
        hasher.update([self.source_rail.protocol_code()]);
        hasher.update([self.destination_rail.protocol_code()]);
        hasher.update(self.corridor_id);
        hasher.update(self.compliance_commitment);
        hasher.update(self.expires_at.to_be_bytes());
        Some(hasher.finalize().into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentIntentAuthorization {
    pub chain_id: [u8; 32],
    pub epoch: u64,
    pub nonce: u64,
    pub intent: PaymentIntent,
    pub authorization: HybridAuthorization,
}

impl PaymentIntentAuthorization {
    pub fn envelope(&self) -> Option<AuthorizationEnvelope> {
        Some(AuthorizationEnvelope {
            chain_id: self.chain_id,
            domain: AuthorizationDomain::PaymentIntent,
            epoch: self.epoch,
            nonce: self.nonce,
            expires_at: self.intent.expires_at,
            payload_commitment: self.intent.authorization_commitment()?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaymentIntentValidationContext {
    pub expected_chain_id: [u8; 32],
    pub expected_epoch: u64,
    pub expected_nonce: u64,
    pub expected_payer: [u8; 32],
    pub expected_payer_keyset_commitment: [u8; 32],
    pub required_policy: AuthPolicy,
    pub now: u64,
    pub max_future_seconds: u64,
}

pub(crate) fn verify_payment_intent<V: ContextSignatureVerifier>(
    verifier: &V,
    authorized: &PaymentIntentAuthorization,
    validation: &PaymentIntentValidationContext,
) -> bool {
    if authorized.intent.payer != validation.expected_payer
        || authorized.intent.validate(validation.now).is_err()
        || authorized.authorization.policy != validation.required_policy
        || authorized.authorization.primary_account_identity_commitment()
            != Some(authorized.intent.payer)
        || authorized.authorization.keyset_commitment()
            != Some(validation.expected_payer_keyset_commitment)
    {
        return false;
    }

    let envelope = match authorized.envelope() {
        Some(envelope) => envelope,
        None => return false,
    };

    let auth_validation = AuthorizationValidationContext {
        expected_chain_id: validation.expected_chain_id,
        expected_domain: AuthorizationDomain::PaymentIntent,
        expected_policy: validation.required_policy,
        expected_epoch: validation.expected_epoch,
        expected_nonce: validation.expected_nonce,
        now: validation.now,
        max_future_seconds: validation.max_future_seconds,
    };

    verify_envelope_authorization(
        verifier,
        &authorized.authorization,
        &envelope,
        &auth_validation,
    )
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


impl SettlementBatch {
    pub fn authorization_commitment(&self) -> Option<[u8; 32]> {
        self.validate().ok()?;
        if self.finality_proof_commitment == [0u8; 32] {
            return None;
        }

        const DOMAIN: &[u8] = b"SYNERGY/SETTLEMENT-BATCH/V1\0";
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN);
        hasher.update(self.lane_id);
        hasher.update(self.sequence.to_be_bytes());
        hasher.update(self.intents_root);
        hasher.update(self.accounting_root);
        hasher.update(self.availability_root);
        hasher.update(self.item_count.to_be_bytes());
        hasher.update(self.gross_amount.to_be_bytes());
        hasher.update(self.total_fees.to_be_bytes());
        hasher.update(self.finality_proof_commitment);
        Some(hasher.finalize().into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementBatchAuthorization {
    pub chain_id: [u8; 32],
    pub epoch: u64,
    pub nonce: u64,
    pub expires_at: u64,
    pub batch: SettlementBatch,
    pub authorization: HybridAuthorization,
}

impl SettlementBatchAuthorization {
    pub fn envelope(&self) -> Option<AuthorizationEnvelope> {
        Some(AuthorizationEnvelope {
            chain_id: self.chain_id,
            domain: AuthorizationDomain::SettlementBatch,
            epoch: self.epoch,
            nonce: self.nonce,
            expires_at: self.expires_at,
            payload_commitment: self.batch.authorization_commitment()?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SettlementBatchValidationContext {
    pub expected_chain_id: [u8; 32],
    pub expected_epoch: u64,
    pub expected_nonce: u64,
    pub expected_lane_id: [u8; 16],
    pub current_sequence: u64,
    pub expected_sequence: u64,
    pub expected_lane_authority_keyset_commitment: [u8; 32],
    pub now: u64,
    pub max_future_seconds: u64,
}

pub(crate) fn verify_settlement_batch<V: ContextSignatureVerifier>(
    verifier: &V,
    authorized: &SettlementBatchAuthorization,
    validation: &SettlementBatchValidationContext,
) -> bool {
    let next_sequence = match validation.current_sequence.checked_add(1) {
        Some(sequence) => sequence,
        None => return false,
    };

    if authorized.authorization.policy != AuthPolicy::PqOnly
        || validation.expected_sequence != next_sequence
        || authorized.batch.lane_id != validation.expected_lane_id
        || authorized.batch.sequence != validation.expected_sequence
        || authorized.authorization.keyset_commitment()
            != Some(validation.expected_lane_authority_keyset_commitment)
        || authorized.batch.validate().is_err()
    {
        return false;
    }

    let envelope = match authorized.envelope() {
        Some(envelope) => envelope,
        None => return false,
    };

    let auth_validation = AuthorizationValidationContext {
        expected_chain_id: validation.expected_chain_id,
        expected_domain: AuthorizationDomain::SettlementBatch,
        expected_policy: AuthPolicy::PqOnly,
        expected_epoch: validation.expected_epoch,
        expected_nonce: validation.expected_nonce,
        now: validation.now,
        max_future_seconds: validation.max_future_seconds,
    };

    verify_envelope_authorization(
        verifier,
        &authorized.authorization,
        &envelope,
        &auth_validation,
    )
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


pub fn verify_payment_intent_and_consume<V: ContextSignatureVerifier>(
    verifier: &V,
    authorized: &PaymentIntentAuthorization,
    validation: &PaymentIntentValidationContext,
    replay: &mut AuthorizationReplayState,
) -> bool {
    if !verify_payment_intent(verifier, authorized, validation) {
        return false;
    }
    let envelope = match authorized.envelope() {
        Some(envelope) => envelope,
        None => return false,
    };
    replay.consume_verified_for_subject(
        &authorized.authorization,
        &envelope,
        validation.expected_payer,
    )
}


pub fn verify_settlement_batch_and_consume<V: ContextSignatureVerifier>(
    verifier: &V,
    authorized: &SettlementBatchAuthorization,
    validation: &SettlementBatchValidationContext,
    replay: &mut AuthorizationReplayState,
) -> bool {
    if !verify_settlement_batch(verifier, authorized, validation) {
        return false;
    }
    let envelope = match authorized.envelope() {
        Some(envelope) => envelope,
        None => return false,
    };
    replay.consume_verified_for_subject(
        &authorized.authorization,
        &envelope,
        validation.expected_lane_authority_keyset_commitment,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settlement_batch() -> SettlementBatch {
        SettlementBatch {
            lane_id: [1; 16],
            sequence: 7,
            intents_root: [2; 32],
            accounting_root: [3; 32],
            availability_root: [4; 32],
            item_count: 5,
            gross_amount: 100,
            total_fees: 2,
            finality_proof_commitment: [5; 32],
        }
    }

    use crate::pq::{
        AuthScheme, ContextSignatureVerifier, SignatureEvidence, ML_DSA_87_PUBLIC_KEY_BYTES,
        ML_DSA_87_SIGNATURE_BYTES, SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES,
        SLH_DSA_SHAKE_256S_SIGNATURE_BYTES,
    };

    #[derive(Clone)]
    struct ExpectedVerifier {
        message: Vec<u8>,
        context: Vec<u8>,
    }

    impl ContextSignatureVerifier for ExpectedVerifier {
        fn verify_with_context(
            &self,
            _scheme: AuthScheme,
            _public_key: &[u8],
            message: &[u8],
            context: &[u8],
            _signature: &[u8],
        ) -> bool {
            message == self.message && context == self.context
        }
    }

    fn pq_only_authorization() -> HybridAuthorization {
        HybridAuthorization {
            policy: AuthPolicy::PqOnly,
            evidence: vec![
                SignatureEvidence {
                    scheme: AuthScheme::MlDsa87,
                    public_key: vec![0x21; ML_DSA_87_PUBLIC_KEY_BYTES],
                    signature: vec![0x22; ML_DSA_87_SIGNATURE_BYTES],
                },
                SignatureEvidence {
                    scheme: AuthScheme::SlhDsaShake256s,
                    public_key: vec![0x23; SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES],
                    signature: vec![0x24; SLH_DSA_SHAKE_256S_SIGNATURE_BYTES],
                },
            ],
        }
    }

    fn intent_for(payer: [u8; 32]) -> PaymentIntent {
        PaymentIntent {
            intent_id: [1; 32],
            payer,
            payee: [3; 32],
            asset_id: [4; 32],
            amount: 100,
            max_fee: 2,
            source_rail: PaymentRail::SynergyNative,
            destination_rail: PaymentRail::Bank,
            corridor_id: [5; 16],
            compliance_commitment: [6; 32],
            expires_at: 100,
        }
    }

    #[test]
    fn payment_intent_requires_registered_payer_keyset() {
        let authorization = pq_only_authorization();
        let payer = authorization
            .primary_account_identity_commitment()
            .expect("payer account identity");
        let payer_keyset = authorization
            .keyset_commitment()
            .expect("payer keyset commitment");
        let authorized = PaymentIntentAuthorization {
            chain_id: [0xC1; 32],
            epoch: 7,
            nonce: 8,
            intent: intent_for(payer),
            authorization,
        };
        let envelope = authorized.envelope().expect("payment envelope");
        let verifier = ExpectedVerifier {
            message: envelope
                .canonical_message(AuthPolicy::PqOnly)
                .expect("message"),
            context: envelope
                .fips_signature_context(AuthPolicy::PqOnly)
                .expect("context"),
        };
        let validation = PaymentIntentValidationContext {
            expected_chain_id: [0xC1; 32],
            expected_epoch: 7,
            expected_nonce: 8,
            expected_payer: payer,
            expected_payer_keyset_commitment: payer_keyset,
            required_policy: AuthPolicy::PqOnly,
            now: 50,
            max_future_seconds: 60,
        };

        assert!(verify_payment_intent(&verifier, &authorized, &validation));

        let mut wrong = validation;
        wrong.expected_payer[0] ^= 1;
        assert!(!verify_payment_intent(&verifier, &authorized, &wrong));
    }

    #[test]
    fn payer_account_identity_is_stable_across_secondary_key_rotation() {
        let auth = pq_only_authorization();
        let account = auth
            .primary_account_identity_commitment()
            .expect("payer account identity");

        let mut rotated = auth.clone();
        rotated.evidence[1].public_key[0] ^= 1;

        assert_eq!(
            rotated.primary_account_identity_commitment(),
            Some(account)
        );
        assert_ne!(
            auth.keyset_commitment(),
            rotated.keyset_commitment()
        );
    }

    #[test]
    fn payment_intent_commitment_binds_amount_rails_and_compliance() {
        let authorization = pq_only_authorization();
        let payer = authorization
            .primary_account_identity_commitment()
            .expect("payer account identity");
        let base = intent_for(payer);
        let commitment = base.authorization_commitment().expect("commitment");

        let mut changed = base.clone();
        changed.amount += 1;
        assert_ne!(commitment, changed.authorization_commitment().expect("amount"));

        let mut changed = base.clone();
        changed.destination_rail = PaymentRail::Card;
        assert_ne!(commitment, changed.authorization_commitment().expect("rail"));

        let mut changed = base;
        changed.compliance_commitment[0] ^= 1;
        assert_ne!(commitment, changed.authorization_commitment().expect("compliance"));
    }

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
    fn settlement_batch_requires_registered_lane_authority() {
        let authorization = pq_only_authorization();
        let lane_authority = authorization
            .keyset_commitment()
            .expect("lane authority keyset");
        let authorized = SettlementBatchAuthorization {
            chain_id: [0xD1; 32],
            epoch: 9,
            nonce: 10,
            expires_at: 200,
            batch: settlement_batch(),
            authorization,
        };
        let envelope = authorized.envelope().expect("batch envelope");
        let verifier = ExpectedVerifier {
            message: envelope
                .canonical_message(AuthPolicy::PqOnly)
                .expect("message"),
            context: envelope
                .fips_signature_context(AuthPolicy::PqOnly)
                .expect("context"),
        };
        let validation = SettlementBatchValidationContext {
            expected_chain_id: [0xD1; 32],
            expected_epoch: 9,
            expected_nonce: 10,
            expected_lane_id: [1; 16],
            current_sequence: 6,
            expected_sequence: 7,
            expected_lane_authority_keyset_commitment: lane_authority,
            now: 100,
            max_future_seconds: 200,
        };

        assert!(verify_settlement_batch(
            &verifier,
            &authorized,
            &validation,
        ));

        let mut wrong = validation;
        wrong.expected_sequence = 8;
        assert!(!verify_settlement_batch(
            &verifier,
            &authorized,
            &wrong,
        ));
    }

    #[test]
    fn settlement_batch_requires_exact_next_lane_sequence() {
        let authorization = pq_only_authorization();
        let lane_authority = authorization
            .keyset_commitment()
            .expect("lane authority keyset");
        let authorized = SettlementBatchAuthorization {
            chain_id: [0xD1; 32],
            epoch: 9,
            nonce: 10,
            expires_at: 200,
            batch: settlement_batch(),
            authorization,
        };
        let envelope = authorized.envelope().expect("batch envelope");
        let verifier = ExpectedVerifier {
            message: envelope
                .canonical_message(AuthPolicy::PqOnly)
                .expect("message"),
            context: envelope
                .fips_signature_context(AuthPolicy::PqOnly)
                .expect("context"),
        };
        let mut validation = SettlementBatchValidationContext {
            expected_chain_id: [0xD1; 32],
            expected_epoch: 9,
            expected_nonce: 10,
            expected_lane_id: [1; 16],
            current_sequence: 5,
            expected_sequence: 7,
            expected_lane_authority_keyset_commitment: lane_authority,
            now: 100,
            max_future_seconds: 200,
        };

        assert!(!verify_settlement_batch(
            &verifier,
            &authorized,
            &validation,
        ));

        validation.current_sequence = 7;
        validation.expected_sequence = 7;
        assert!(!verify_settlement_batch(
            &verifier,
            &authorized,
            &validation,
        ));
    }

    #[test]
    fn settlement_batch_commitment_binds_finality_and_accounting() {
        let base = settlement_batch();
        let commitment = base.authorization_commitment().expect("batch commitment");

        let mut changed = base.clone();
        changed.accounting_root[0] ^= 1;
        assert_ne!(commitment, changed.authorization_commitment().expect("accounting"));

        let mut changed = base;
        changed.finality_proof_commitment[0] ^= 1;
        assert_ne!(commitment, changed.authorization_commitment().expect("finality"));
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
