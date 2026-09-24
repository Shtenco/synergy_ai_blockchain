use synergy_pq_evm_core::{
    aggregate_verifier_receipts, finalize_mvp_checkpoint, ComputeSettlement, MvpFinalizationInput,
    SlashState, VerificationChallenge, VerificationVerdict, VerifierReceipt, WorkerSlash,
};

fn receipt(
    challenge_id: [u8; 32],
    verifier: u8,
    verdict: VerificationVerdict,
    recomputed: [u8; 32],
) -> VerifierReceipt {
    VerifierReceipt {
        challenge_id,
        verifier_id: [verifier; 32],
        recomputed_output_commitment: recomputed,
        trace_commitment: [40 + verifier; 32],
        signature_commitment: [60 + verifier; 32],
        verdict,
        completed_at: 5,
    }
}

fn input(
    sequence: u64,
    previous_checkpoint: [u8; 32],
    verification_root: [u8; 32],
    inference_root: [u8; 32],
) -> MvpFinalizationInput {
    MvpFinalizationInput {
        chain_id: [1; 32],
        epoch: 1,
        sequence,
        previous_checkpoint,
        model_root: [2; 32],
        network_root: [3; 32],
        provider_root: [4; 32],
        inference_root,
        verification_root,
        kv_root: [6; 32],
        storage_root: [7; 32],
        scheduler_root: [8; 32],
        node_set_root: [9; 32],
        funded_amount: 100,
    }
}

#[test]
fn bad_worker_is_slashed_once_then_honest_retry_extends_chain() {
    let bad = VerificationChallenge {
        challenge_id: [10; 32],
        job_id: [11; 32],
        challenged_output_commitment: [12; 32],
        sample_seed_commitment: [13; 32],
        required_replications: 2,
        opened_at: 1,
        closes_at: 10,
    };
    let bad_receipts = vec![
        receipt(bad.challenge_id, 21, VerificationVerdict::Mismatch, [14; 32]),
        receipt(bad.challenge_id, 22, VerificationVerdict::Mismatch, [14; 32]),
    ];
    let bad_aggregate = aggregate_verifier_receipts(&bad, &bad_receipts).unwrap();
    assert_eq!(bad_aggregate.final_verdict(), VerificationVerdict::Mismatch);

    let mut slash = WorkerSlash {
        slash_id: [15; 32],
        job_id: bad.job_id,
        worker_id: [16; 32],
        challenged_output_commitment: bad.challenged_output_commitment,
        verification_receipt_root: bad_aggregate.receipt_root,
        amount: 25,
        epoch: 1,
        state: SlashState::Open,
    };
    let slash_root = slash
        .canonical_root(&bad, &bad_aggregate)
        .expect("pre-finalization slash root");

    let bad_settlement = ComputeSettlement {
        job_id: bad.job_id,
        funding_root: [17; 32],
        worker_id: slash.worker_id,
        storage_provider_id: [18; 32],
        verifier_set_root: bad_aggregate.receipt_root,
        worker_reward: 0,
        storage_reward: 10,
        verifier_reward: 20,
        protocol_fee: 10,
        slash_root: Some(slash_root),
        refund_amount: 60,
    };

    let cp1 = finalize_mvp_checkpoint(
        &input(1, [0; 32], bad_aggregate.receipt_root, [19; 32]),
        &bad,
        &bad_receipts,
        &bad_settlement,
        Some(&mut slash),
    )
    .expect("mismatch checkpoint");
    assert_eq!(slash.state, SlashState::Consumed);

    // The same slash cannot be consumed again.
    assert!(finalize_mvp_checkpoint(
        &input(1, [0; 32], bad_aggregate.receipt_root, [19; 32]),
        &bad,
        &bad_receipts,
        &bad_settlement,
        Some(&mut slash),
    )
    .is_err());

    let cp1_root = cp1.commitment().expect("checkpoint 1 root");

    let good = VerificationChallenge {
        challenge_id: [20; 32],
        job_id: [21; 32],
        challenged_output_commitment: [22; 32],
        sample_seed_commitment: [23; 32],
        required_replications: 2,
        opened_at: 11,
        closes_at: 20,
    };
    let good_receipts = vec![
        receipt(
            good.challenge_id,
            31,
            VerificationVerdict::Match,
            good.challenged_output_commitment,
        ),
        receipt(
            good.challenge_id,
            32,
            VerificationVerdict::Match,
            good.challenged_output_commitment,
        ),
    ];
    let good_aggregate = aggregate_verifier_receipts(&good, &good_receipts).unwrap();
    assert_eq!(good_aggregate.final_verdict(), VerificationVerdict::Match);

    let good_settlement = ComputeSettlement {
        job_id: good.job_id,
        funding_root: [24; 32],
        worker_id: [25; 32],
        storage_provider_id: [26; 32],
        verifier_set_root: good_aggregate.receipt_root,
        worker_reward: 60,
        storage_reward: 10,
        verifier_reward: 20,
        protocol_fee: 10,
        slash_root: None,
        refund_amount: 0,
    };

    let cp2 = finalize_mvp_checkpoint(
        &input(2, cp1_root, good_aggregate.receipt_root, [27; 32]),
        &good,
        &good_receipts,
        &good_settlement,
        None,
    )
    .expect("honest retry checkpoint");

    assert!(cp2.extends(&cp1));
}
