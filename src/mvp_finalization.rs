//! Canonical MVP finalization gate.
//!
//! Finalization recomputes the verification aggregate from the exact canonical
//! verifier receipt set. A caller cannot finalize by supplying counters alone.

use crate::{
    aggregate_verifier_receipts, ComputeSettlement, MvpCheckpoint, VerificationChallenge,
    VerificationVerdict, VerifierReceipt, WorkerSlash,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MvpFinalizationInput {
    pub chain_id: [u8; 32],
    pub epoch: u64,
    pub sequence: u64,
    pub previous_checkpoint: [u8; 32],
    pub model_root: [u8; 32],
    pub network_root: [u8; 32],
    pub provider_root: [u8; 32],
    pub inference_root: [u8; 32],
    pub verification_root: [u8; 32],
    pub kv_root: [u8; 32],
    pub storage_root: [u8; 32],
    pub scheduler_root: [u8; 32],
    pub node_set_root: [u8; 32],
    pub funded_amount: u128,
}

pub fn finalize_mvp_checkpoint(
    input: &MvpFinalizationInput,
    challenge: &VerificationChallenge,
    receipts: &[VerifierReceipt],
    settlement: &ComputeSettlement,
    mut slash: Option<&mut WorkerSlash>,
) -> Result<MvpCheckpoint, &'static str> {
    challenge.validate()?;
    let aggregate = aggregate_verifier_receipts(challenge, receipts)?;

    if input.chain_id == [0; 32]
        || input.epoch == 0
        || input.sequence == 0
        || input.model_root == [0; 32]
        || input.network_root == [0; 32]
        || input.provider_root == [0; 32]
        || input.inference_root == [0; 32]
        || input.verification_root == [0; 32]
        || input.kv_root == [0; 32]
        || input.storage_root == [0; 32]
        || input.scheduler_root == [0; 32]
        || input.node_set_root == [0; 32]
        || input.funded_amount == 0
    {
        return Err("MVP finalization input incomplete");
    }

    if input.verification_root != aggregate.receipt_root {
        return Err("verification root does not match canonical receipt set");
    }

    if settlement.job_id != challenge.job_id
        || settlement.verifier_set_root != aggregate.receipt_root
    {
        return Err("settlement/verification mismatch");
    }

    let settlement_root = settlement
        .canonical_root(challenge, &aggregate, input.funded_amount)
        .ok_or("invalid compute settlement")?;

    match aggregate.final_verdict() {
        VerificationVerdict::Match => {
            if slash.is_some() || settlement.slash_root.is_some() {
                return Err("matching inference cannot include slash");
            }
        }
        VerificationVerdict::Mismatch => {
            let slash = slash.as_deref_mut().ok_or("mismatch requires slash")?;
            let slash_root = slash
                .consume_once(challenge, &aggregate)
                .map_err(|_| "invalid or already-consumed worker slash")?;
            if settlement.slash_root != Some(slash_root) {
                return Err("settlement slash root mismatch");
            }
        }
        VerificationVerdict::Inconclusive => {
            if slash.is_some() || settlement.slash_root.is_some() {
                return Err("inconclusive inference cannot slash");
            }
        }
    }

    let checkpoint = MvpCheckpoint {
        chain_id: input.chain_id,
        epoch: input.epoch,
        sequence: input.sequence,
        previous_checkpoint: input.previous_checkpoint,
        model_root: input.model_root,
        network_root: input.network_root,
        provider_root: input.provider_root,
        inference_root: input.inference_root,
        verification_root: aggregate.receipt_root,
        kv_root: input.kv_root,
        storage_root: input.storage_root,
        settlement_root,
        scheduler_root: input.scheduler_root,
        node_set_root: input.node_set_root,
    };
    checkpoint.validate()?;
    Ok(checkpoint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SlashState, VerificationVerdict};

    fn challenge() -> VerificationChallenge {
        VerificationChallenge {
            challenge_id: [1; 32],
            job_id: [2; 32],
            challenged_output_commitment: [3; 32],
            sample_seed_commitment: [4; 32],
            required_replications: 2,
            opened_at: 1,
            closes_at: 10,
        }
    }

    fn receipt(
        verifier: u8,
        verdict: VerificationVerdict,
        recomputed: [u8; 32],
    ) -> VerifierReceipt {
        VerifierReceipt {
            challenge_id: [1; 32],
            verifier_id: [verifier; 32],
            recomputed_output_commitment: recomputed,
            work_commitment: if verdict == VerificationVerdict::Inconclusive {
                [0; 32]
            } else {
                [9; 32]
            },
            trace_commitment: [10 + verifier; 32],
            signature_commitment: [20 + verifier; 32],
            verdict,
            completed_at: 5,
        }
    }

    fn base_input(verification_root: [u8; 32]) -> MvpFinalizationInput {
        MvpFinalizationInput {
            chain_id: [10; 32],
            epoch: 1,
            sequence: 1,
            previous_checkpoint: [0; 32],
            model_root: [11; 32],
            network_root: [12; 32],
            provider_root: [13; 32],
            inference_root: [14; 32],
            verification_root,
            kv_root: [16; 32],
            storage_root: [17; 32],
            scheduler_root: [18; 32],
            node_set_root: [19; 32],
            funded_amount: 100,
        }
    }

    #[test]
    fn match_finalizes_from_real_receipt_set_without_slash() {
        let c = challenge();
        let receipts = vec![
            receipt(
                5,
                VerificationVerdict::Match,
                c.challenged_output_commitment,
            ),
            receipt(
                6,
                VerificationVerdict::Match,
                c.challenged_output_commitment,
            ),
        ];
        let a = aggregate_verifier_receipts(&c, &receipts).unwrap();
        let s = ComputeSettlement {
            job_id: c.job_id,
            funding_root: [6; 32],
            worker_id: [7; 32],
            storage_provider_id: [8; 32],
            verifier_set_root: a.receipt_root,
            worker_reward: 60,
            storage_reward: 10,
            verifier_reward: 20,
            protocol_fee: 10,
            slash_root: None,
            refund_amount: 0,
        };
        let cp = finalize_mvp_checkpoint(&base_input(a.receipt_root), &c, &receipts, &s, None)
            .expect("checkpoint");
        assert!(cp.commitment().is_some());
    }

    #[test]
    fn mismatch_requires_exact_slash_root_from_same_receipts() {
        let c = challenge();
        let receipts = vec![
            receipt(
                5,
                VerificationVerdict::Match,
                c.challenged_output_commitment,
            ),
            receipt(6, VerificationVerdict::Mismatch, [99; 32]),
        ];
        let a = aggregate_verifier_receipts(&c, &receipts).unwrap();
        let mut slash = WorkerSlash {
            slash_id: [20; 32],
            job_id: c.job_id,
            worker_id: [7; 32],
            challenged_output_commitment: c.challenged_output_commitment,
            verification_receipt_root: a.receipt_root,
            amount: 25,
            epoch: 1,
            state: SlashState::Open,
        };
        let slash_root = slash.canonical_root(&c, &a).expect("slash root");
        let s = ComputeSettlement {
            job_id: c.job_id,
            funding_root: [6; 32],
            worker_id: [7; 32],
            storage_provider_id: [8; 32],
            verifier_set_root: a.receipt_root,
            worker_reward: 0,
            storage_reward: 10,
            verifier_reward: 20,
            protocol_fee: 10,
            slash_root: Some(slash_root),
            refund_amount: 60,
        };
        assert!(finalize_mvp_checkpoint(
            &base_input(a.receipt_root),
            &c,
            &receipts,
            &s,
            Some(&mut slash),
        )
        .is_ok());
        assert_eq!(slash.state, SlashState::Consumed);
        assert!(finalize_mvp_checkpoint(
            &base_input(a.receipt_root),
            &c,
            &receipts,
            &s,
            Some(&mut slash),
        )
        .is_err());
    }

    #[test]
    fn forged_verification_root_is_rejected() {
        let c = challenge();
        let receipts = vec![
            receipt(
                5,
                VerificationVerdict::Match,
                c.challenged_output_commitment,
            ),
            receipt(
                6,
                VerificationVerdict::Match,
                c.challenged_output_commitment,
            ),
        ];
        let a = aggregate_verifier_receipts(&c, &receipts).unwrap();
        let s = ComputeSettlement {
            job_id: c.job_id,
            funding_root: [6; 32],
            worker_id: [7; 32],
            storage_provider_id: [8; 32],
            verifier_set_root: a.receipt_root,
            worker_reward: 60,
            storage_reward: 10,
            verifier_reward: 20,
            protocol_fee: 10,
            slash_root: None,
            refund_amount: 0,
        };
        assert!(finalize_mvp_checkpoint(&base_input([88; 32]), &c, &receipts, &s, None,).is_err());
    }
}
