use synergy_pq_evm_core::trust_commitment_payload;

fn hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 6 {
        eprintln!(
            "usage: source_event_id source_contract_id payload_sha256 chain_id finality_status"
        );
        std::process::exit(2);
    }

    let payload_sha256 = hex32(&args[3]).expect("payload_sha256");
    let payload = trust_commitment_payload(
        args[1].clone(),
        args[2].clone(),
        payload_sha256,
        args[4].clone(),
        args[5].clone(),
        Some(42),
        Some("m3-dynamic".to_owned()),
        Some("PQ_ONLY".to_owned()),
    )
    .expect("valid dynamic trust commitment");

    println!(
        "{{\"source_event_id\":\"{}\",\"source_contract_id\":\"{}\",\"payload_sha256\":\"{}\",\"chain_id\":\"{}\",\"commitment_id\":\"{}\",\"finality_status\":\"{}\",\"block_height\":{},\"tx_id\":\"{}\",\"authorization_profile\":\"{}\"}}",
        payload.source_event_id,
        payload.source_contract_id,
        args[3],
        payload.chain_id,
        payload.commitment_id,
        payload.finality_status,
        payload.block_height.unwrap_or(0),
        payload.tx_id.unwrap_or_default(),
        payload.authorization_profile.unwrap_or_default(),
    );
}
