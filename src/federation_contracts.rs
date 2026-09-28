use sha2::{Digest, Sha256};

pub const TRUST_CONTRACT_ID: &str = "synergy.trust.commitment/v1";
pub const TRANSPORT_CONTRACT_ID: &str = "synergy.transport.evidence/v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustCommitmentPayload {
    pub source_event_id: String,
    pub source_contract_id: String,
    pub payload_sha256: [u8; 32],
    pub chain_id: String,
    pub commitment_id: String,
    pub finality_status: String,
    pub block_height: Option<u64>,
    pub tx_id: Option<String>,
    pub authorization_profile: Option<String>,
}

pub fn trust_commitment_payload(
    source_event_id: impl Into<String>,
    source_contract_id: impl Into<String>,
    payload_sha256: [u8; 32],
    chain_id: impl Into<String>,
    finality_status: impl Into<String>,
    block_height: Option<u64>,
    tx_id: Option<String>,
    authorization_profile: Option<String>,
) -> Option<TrustCommitmentPayload> {
    let source_event_id=source_event_id.into();
    let source_contract_id=source_contract_id.into();
    let chain_id=chain_id.into();
    let finality_status=finality_status.into();
    if source_event_id.is_empty() || source_contract_id.is_empty() || chain_id.is_empty() || payload_sha256==[0;32] {
        return None;
    }
    if !matches!(finality_status.as_str(),"PENDING"|"FINALIZED"|"REORGED"|"REJECTED") {
        return None;
    }
    let mut h=Sha256::new();
    h.update(b"SYNERGY/TRUST-COMMITMENT/V1\0");
    h.update(source_contract_id.as_bytes());
    h.update([0]);
    h.update(source_event_id.as_bytes());
    h.update([0]);
    h.update(payload_sha256);
    h.update([0]);
    h.update(chain_id.as_bytes());
    let commitment_id=hex_lower(&h.finalize());
    Some(TrustCommitmentPayload{
        source_event_id,source_contract_id,payload_sha256,chain_id,commitment_id,
        finality_status,block_height,tx_id,authorization_profile
    })
}

fn hex_lower(bytes:&[u8])->String{
    const HEX:&[u8;16]=b"0123456789abcdef";
    let mut s=String::with_capacity(bytes.len()*2);
    for b in bytes {
        s.push(HEX[(b>>4) as usize] as char);
        s.push(HEX[(b&0xf) as usize] as char);
    }
    s
}

#[derive(Clone, Debug, PartialEq)]
pub struct TransportEvidenceInput {
    pub session_id:String,
    pub sender_peer:String,
    pub receiver_peer:String,
    pub content_sha256:[u8;32],
    pub authenticated:bool,
    pub route:Vec<String>,
    pub bytes_on_wire:u64,
    pub latency_ms:f64,
}

pub fn verify_transport_evidence(input:&TransportEvidenceInput)->bool{
    if input.session_id.is_empty() || input.sender_peer.is_empty() || input.receiver_peer.is_empty() ||
       input.content_sha256==[0;32] || !input.authenticated || input.route.len()<2 ||
       !input.latency_ms.is_finite() || input.latency_ms<0.0 {
        return false;
    }
    input.route.first()==Some(&input.sender_peer) && input.route.last()==Some(&input.receiver_peer)
}

#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn trust_payload_is_deterministic_and_finality_bounded(){
        let a=trust_commitment_payload("e","synergy.accounting.recognition/v1",[1;32],"dev","FINALIZED",Some(1),Some("tx".into()),Some("PQ_ONLY".into())).unwrap();
        let b=trust_commitment_payload("e","synergy.accounting.recognition/v1",[1;32],"dev","FINALIZED",Some(1),Some("tx".into()),Some("PQ_ONLY".into())).unwrap();
        assert_eq!(a.commitment_id,b.commitment_id);
        assert_eq!(a.commitment_id.len(),64);
    }
    #[test]
    fn transport_requires_authenticated_matching_route(){
        let good=TransportEvidenceInput{session_id:"s".into(),sender_peer:"a".into(),receiver_peer:"b".into(),content_sha256:[1;32],authenticated:true,route:vec!["a".into(),"b".into()],bytes_on_wire:10,latency_ms:1.0};
        assert!(verify_transport_evidence(&good));
        let mut bad=good.clone();bad.authenticated=false;assert!(!verify_transport_evidence(&bad));
    }
}


pub fn verify_budget_proof_root(
    dataset_id: &str,
    snapshot_id: &str,
    record_merkle_root: &str,
    record_count: u64,
) -> bool {
    if dataset_id.is_empty() || snapshot_id.is_empty() || record_count == 0 {
        return false;
    }
    if record_merkle_root.len() != 64 {
        return false;
    }
    record_merkle_root
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
