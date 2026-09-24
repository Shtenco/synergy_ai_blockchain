//! Binding between authenticated PQ transport sessions and off-chain stage RPC.
//!
//! The socket/runtime may live outside consensus, but a stage request is accepted
//! into canonical evidence only if it is bound to the exact authenticated
//! transport transcript and expected worker identity.

use sha2::{Digest, Sha256};

use crate::network::{TransportRole, TransportTranscript};

pub const STAGE_RPC_BINDING_DOMAIN: &[u8] = b"SYNERGY/STAGE-RPC-BINDING/V1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedStageRequest {
    pub request_id: [u8; 32],
    pub job_id: [u8; 32],
    pub stage_index: u32,
    pub requester_node_id: [u8; 32],
    pub worker_node_id: [u8; 32],
    pub model_root: [u8; 32],
    pub shard_root: [u8; 32],
    pub input_commitment: [u8; 32],
    pub endpoint_root: [u8; 32],
    pub expires_at: u64,
}

impl AuthenticatedStageRequest {
    pub fn validate_against_session(
        &self,
        transcript: &TransportTranscript,
    ) -> Result<[u8; 32], &'static str> {
        transcript.validate()?;
        if self.request_id == [0; 32]
            || self.job_id == [0; 32]
            || self.requester_node_id == [0; 32]
            || self.worker_node_id == [0; 32]
            || self.model_root == [0; 32]
            || self.shard_root == [0; 32]
            || self.input_commitment == [0; 32]
            || self.endpoint_root == [0; 32]
            || self.expires_at == 0
        {
            return Err("stage RPC commitments required");
        }
        if self.requester_node_id != transcript.initiator.node_id {
            return Err("stage requester is not PQ session initiator");
        }
        if self.worker_node_id != transcript.responder.node_id {
            return Err("stage worker is not PQ session responder");
        }
        transcript
            .commitment()
            .ok_or("authenticated transport transcript required")
    }

    pub fn commitment(
        &self,
        transcript: &TransportTranscript,
    ) -> Option<[u8; 32]> {
        let session_root = self.validate_against_session(transcript).ok()?;
        let mut h = Sha256::new();
        h.update(STAGE_RPC_BINDING_DOMAIN);
        h.update(crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes());
        h.update(session_root);
        h.update([TransportRole::Initiator.protocol_code()]);
        h.update(self.request_id);
        h.update(self.job_id);
        h.update(self.stage_index.to_be_bytes());
        h.update(self.requester_node_id);
        h.update(self.worker_node_id);
        h.update(self.model_root);
        h.update(self.shard_root);
        h.update(self.input_commitment);
        h.update(self.endpoint_root);
        h.update(self.expires_at.to_be_bytes());
        Some(h.finalize().into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedStageResponse {
    pub request_root: [u8; 32],
    pub worker_node_id: [u8; 32],
    pub output_commitment: [u8; 32],
    pub trace_root: [u8; 32],
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub elapsed_micros: u64,
}

impl AuthenticatedStageResponse {
    pub fn validate_against(
        &self,
        request: &AuthenticatedStageRequest,
        transcript: &TransportTranscript,
    ) -> Result<(), &'static str> {
        let expected_request_root = request
            .commitment(transcript)
            .ok_or("stage request/session binding invalid")?;
        if self.request_root != expected_request_root
            || self.worker_node_id != request.worker_node_id
            || self.output_commitment == [0; 32]
            || self.trace_root == [0; 32]
            || self.elapsed_micros == 0
        {
            return Err("stage response binding mismatch");
        }
        Ok(())
    }

    pub fn commitment(
        &self,
        request: &AuthenticatedStageRequest,
        transcript: &TransportTranscript,
    ) -> Option<[u8; 32]> {
        self.validate_against(request, transcript).ok()?;
        let mut h = Sha256::new();
        h.update(b"SYNERGY/STAGE-RPC-RESPONSE/V1\0");
        h.update(self.request_root);
        h.update(self.worker_node_id);
        h.update(self.output_commitment);
        h.update(self.trace_root);
        h.update(self.bytes_read.to_be_bytes());
        h.update(self.bytes_written.to_be_bytes());
        h.update(self.elapsed_micros.to_be_bytes());
        Some(h.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::{
        RekeyPolicy, TransportPeerIdentity, TransportPolicy, TransportRole,
        TransportTranscript,
    };

    fn transcript() -> TransportTranscript {
        TransportTranscript {
            network_id: [1; 32],
            epoch: 1,
            session_id: [2; 32],
            initiator: TransportPeerIdentity {
                node_id: [3; 32],
                ml_kem1024_public_key: vec![1; crate::network::ML_KEM_1024_PUBLIC_KEY_BYTES],
                legacy_kex_scheme: None,
                legacy_kex_public_key: vec![],
            },
            responder: TransportPeerIdentity {
                node_id: [4; 32],
                ml_kem1024_public_key: vec![2; crate::network::ML_KEM_1024_PUBLIC_KEY_BYTES],
                legacy_kex_scheme: None,
                legacy_kex_public_key: vec![],
            },
            policy: TransportPolicy::PqOnly,
            rekey_policy: RekeyPolicy { max_messages: 100, max_seconds: 60 },
            ml_kem_recipient: TransportRole::Responder,
            ml_kem_ciphertext: vec![7; crate::network::ML_KEM_1024_CIPHERTEXT_BYTES],
            classical_transcript_hash: None,
        }
    }

    fn request() -> AuthenticatedStageRequest {
        AuthenticatedStageRequest {
            request_id: [5; 32], job_id: [6; 32], stage_index: 0,
            requester_node_id: [3; 32], worker_node_id: [4; 32],
            model_root: [7; 32], shard_root: [8; 32],
            input_commitment: [9; 32], endpoint_root: [10; 32],
            expires_at: 100,
        }
    }

    #[test]
    fn request_binds_exact_pq_session_and_worker() {
        let t = transcript();
        assert!(request().commitment(&t).is_some());
        let mut wrong = request();
        wrong.worker_node_id = [99; 32];
        assert!(wrong.commitment(&t).is_none());
    }

    #[test]
    fn response_must_bind_exact_request_root() {
        let t=transcript(); let r=request(); let root=r.commitment(&t).unwrap();
        let response=AuthenticatedStageResponse {
            request_root:root, worker_node_id:r.worker_node_id,
            output_commitment:[11;32], trace_root:[12;32],
            bytes_read:10, bytes_written:20, elapsed_micros:1,
        };
        assert!(response.commitment(&r,&t).is_some());
    }
}
