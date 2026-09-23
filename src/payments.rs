use sha2::{Digest, Sha256};

use crate::pq::{
    verify_envelope_authorization, AuthPolicy, AuthorizationDomain, AuthorizationEnvelope,
    AuthorizationValidationContext, ContextSignatureVerifier, HybridAuthorization,
};

const PAYMENT_INTENT_DOMAIN: &[u8] = b"SYNERGY/PAYMENT-INTENT/V1\0";

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
    pub required_policy: AuthPolicy,
    pub now: u64,
    pub max_future_seconds: u64,
}

pub fn verify_payment_intent<V: ContextSignatureVerifier>(
    verifier: &V,
    authorized: &PaymentIntentAuthorization,
    validation: &PaymentIntentValidationContext,
) -> bool {
    if authorized.intent.payer != validation.expected_payer
        || authorized.intent.validate(validation.now).is_err()
        || authorized.authorization.policy != validation.required_policy
        || authorized.authorization.keyset_commitment() != Some(authorized.intent.payer)
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
    fn payment_intent_commitment_binds_amount_rails_and_compliance() {
        let authorization = pq_only_authorization();
        let payer = authorization
            .keyset_commitment()
            .expect("payer keyset commitment");
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
