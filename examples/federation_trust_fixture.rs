use synergy_pq_evm_core::trust_commitment_payload;

fn main() {
    let payload = trust_commitment_payload(
        "77777777-7777-4777-8777-777777777777",
        "synergy.accounting.recognition/v1",
        [0x42; 32],
        "synergy-dev",
        "FINALIZED",
        Some(42),
        Some("tx-demo".to_owned()),
        Some("PQ_ONLY".to_owned()),
    )
    .expect("valid trust commitment");

    println!(
        "{{\"source_event_id\":\"{}\",\"source_contract_id\":\"{}\",\"payload_sha256\":\"{}\",\"chain_id\":\"{}\",\"commitment_id\":\"{}\",\"finality_status\":\"{}\",\"block_height\":{},\"tx_id\":\"{}\",\"authorization_profile\":\"{}\"}}",
        payload.source_event_id,
        payload.source_contract_id,
        "42".repeat(32),
        payload.chain_id,
        payload.commitment_id,
        payload.finality_status,
        payload.block_height.unwrap_or(0),
        payload.tx_id.unwrap_or_default(),
        payload.authorization_profile.unwrap_or_default(),
    );
}
