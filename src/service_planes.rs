//! Canonical commitments for horizontally scaled SYNERGY service planes.
//!
//! World-scale payments, archival storage, CognitiveNodes and Autopilot work are
//! not executed as one giant serial EVM transaction stream. Each service plane
//! may execute/aggregate independently and the canonical chain commits bounded
//! roots plus availability/finality evidence.

use sha2::{Digest, Sha256};

use crate::pq::{
    verify_envelope_authorization, AuthPolicy, AuthorizationDomain, AuthorizationEnvelope,
    AuthorizationReplayState, AuthorizationValidationContext, ContextSignatureVerifier, HybridAuthorization,
};

const SERVICE_PLANE_CHECKPOINT_DOMAIN: &[u8] = b"SYNERGY/SERVICE-PLANE-CHECKPOINT/V1\0";


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServicePlaneRoots {
    pub epoch: u64,
    pub payment_global_checkpoint_root: [u8; 32],
    pub storage_catalog_root: [u8; 32],
    pub cognitive_registry_root: [u8; 32],
    pub cognitive_evidence_root: [u8; 32],
    pub autopilot_policy_graph_root: [u8; 32],
    pub data_availability_root: [u8; 32],
    pub service_finality_root: [u8; 32],
}

impl ServicePlaneRoots {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.epoch == 0 {
            return Err("service-plane epoch required");
        }
        if self.payment_global_checkpoint_root == [0; 32]
            || self.storage_catalog_root == [0; 32]
            || self.cognitive_registry_root == [0; 32]
            || self.cognitive_evidence_root == [0; 32]
            || self.autopilot_policy_graph_root == [0; 32]
            || self.data_availability_root == [0; 32]
            || self.service_finality_root == [0; 32]
        {
            return Err("all service-plane commitments are required");
        }
        Ok(())
    }
}


impl ServicePlaneRoots {
    pub fn authorization_commitment(&self) -> Option<[u8; 32]> {
        self.validate().ok()?;
        let mut hasher = Sha256::new();
        hasher.update(SERVICE_PLANE_CHECKPOINT_DOMAIN);
        hasher.update(self.epoch.to_be_bytes());
        hasher.update(self.payment_global_checkpoint_root);
        hasher.update(self.storage_catalog_root);
        hasher.update(self.cognitive_registry_root);
        hasher.update(self.cognitive_evidence_root);
        hasher.update(self.autopilot_policy_graph_root);
        hasher.update(self.data_availability_root);
        hasher.update(self.service_finality_root);
        Some(hasher.finalize().into())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServicePlaneCheckpointAuthorization {
    pub chain_id: [u8; 32],
    pub authorization_epoch: u64,
    pub nonce: u64,
    pub expires_at: u64,
    pub roots: ServicePlaneRoots,
    pub authorization: HybridAuthorization,
}

impl ServicePlaneCheckpointAuthorization {
    pub fn envelope(&self) -> Option<AuthorizationEnvelope> {
        Some(AuthorizationEnvelope {
            chain_id: self.chain_id,
            domain: AuthorizationDomain::ServicePlaneCheckpoint,
            epoch: self.authorization_epoch,
            nonce: self.nonce,
            expires_at: self.expires_at,
            payload_commitment: self.roots.authorization_commitment()?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServicePlaneCheckpointValidationContext {
    pub expected_chain_id: [u8; 32],
    pub expected_authorization_epoch: u64,
    pub expected_nonce: u64,
    pub current_service_plane_epoch: u64,
    pub expected_service_plane_epoch: u64,
    pub expected_authority_keyset_commitment: [u8; 32],
    pub now: u64,
    pub max_future_seconds: u64,
}

pub(crate) fn verify_service_plane_checkpoint<V: ContextSignatureVerifier>(
    verifier: &V,
    authorized: &ServicePlaneCheckpointAuthorization,
    validation: &ServicePlaneCheckpointValidationContext,
) -> bool {
    let next_epoch = match validation.current_service_plane_epoch.checked_add(1) {
        Some(epoch) => epoch,
        None => return false,
    };

    if authorized.authorization.policy != AuthPolicy::Max
        || validation.expected_service_plane_epoch != next_epoch
        || authorized.roots.epoch != validation.expected_service_plane_epoch
        || authorized.authorization.keyset_commitment()
            != Some(validation.expected_authority_keyset_commitment)
        || authorized.roots.validate().is_err()
    {
        return false;
    }

    let envelope = match authorized.envelope() {
        Some(envelope) => envelope,
        None => return false,
    };

    let auth_validation = AuthorizationValidationContext {
        expected_chain_id: validation.expected_chain_id,
        expected_domain: AuthorizationDomain::ServicePlaneCheckpoint,
        expected_policy: AuthPolicy::Max,
        expected_epoch: validation.expected_authorization_epoch,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServicePlaneCapacityEnvelope {
    /// Off-consensus payment intents represented by the payment checkpoint.
    pub payment_items: u64,
    /// Logical raw bytes represented by archival receipts in this epoch.
    pub logical_storage_bytes: u128,
    /// Incremental physical archive bytes after compression/dedup/erasure.
    pub physical_storage_bytes: u128,
    /// Verified cognitive work receipts represented by the evidence root.
    pub cognitive_receipts: u64,
    /// Autopilot proposals that reached externally authorized execution.
    pub authorized_autopilot_actions: u64,
}

impl ServicePlaneCapacityEnvelope {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.physical_storage_bytes > 0 && self.logical_storage_bytes == 0 {
            return Err("physical storage cannot exist without logical bytes");
        }
        Ok(())
    }

    /// Physical/logical storage ratio in basis points. This is an aggregate byte
    /// metric only; monetary saving also depends on provider prices.
    pub fn physical_to_logical_storage_bps(&self) -> Option<u64> {
        if self.logical_storage_bytes == 0 {
            return None;
        }
        let numerator = self.physical_storage_bytes.checked_mul(10_000)?;
        let value = numerator.checked_div(self.logical_storage_bytes)?;
        u64::try_from(value).ok()
    }
}


pub fn verify_service_plane_checkpoint_and_consume<V: ContextSignatureVerifier>(
    verifier: &V,
    authorized: &ServicePlaneCheckpointAuthorization,
    validation: &ServicePlaneCheckpointValidationContext,
    replay: &mut AuthorizationReplayState,
) -> bool {
    if !verify_service_plane_checkpoint(verifier, authorized, validation) {
        return false;
    }
    let envelope = match authorized.envelope() {
        Some(envelope) => envelope,
        None => return false,
    };
    replay.consume_verified_for_subject(
        &authorized.authorization,
        &envelope,
        validation.expected_authority_keyset_commitment,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pq::{
        AuthScheme, ContextSignatureVerifier, SignatureEvidence, ML_DSA_87_PUBLIC_KEY_BYTES,
        ML_DSA_87_SIGNATURE_BYTES, SECP256K1_PUBLIC_KEY_BYTES, SECP256K1_SIGNATURE_BYTES,
        SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES, SLH_DSA_SHAKE_256S_SIGNATURE_BYTES,
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

    fn max_authorization() -> HybridAuthorization {
        let mut secp_key = vec![1u8; SECP256K1_PUBLIC_KEY_BYTES];
        secp_key[0] = 0x02;
        let mut secp_sig = vec![2u8; SECP256K1_SIGNATURE_BYTES];
        secp_sig[SECP256K1_SIGNATURE_BYTES - 1] = 0;
        HybridAuthorization {
            policy: AuthPolicy::Max,
            evidence: vec![
                SignatureEvidence {
                    scheme: AuthScheme::Secp256k1,
                    public_key: secp_key,
                    signature: secp_sig,
                },
                SignatureEvidence {
                    scheme: AuthScheme::MlDsa87,
                    public_key: vec![3u8; ML_DSA_87_PUBLIC_KEY_BYTES],
                    signature: vec![4u8; ML_DSA_87_SIGNATURE_BYTES],
                },
                SignatureEvidence {
                    scheme: AuthScheme::SlhDsaShake256s,
                    public_key: vec![5u8; SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES],
                    signature: vec![6u8; SLH_DSA_SHAKE_256S_SIGNATURE_BYTES],
                },
            ],
        }
    }

    fn roots() -> ServicePlaneRoots {
        ServicePlaneRoots {
            epoch: 7,
            payment_global_checkpoint_root: [1; 32],
            storage_catalog_root: [2; 32],
            cognitive_registry_root: [3; 32],
            cognitive_evidence_root: [4; 32],
            autopilot_policy_graph_root: [5; 32],
            data_availability_root: [6; 32],
            service_finality_root: [7; 32],
        }
    }


    #[test]
    fn service_plane_checkpoint_requires_registered_max_authority() {
        let authorized = ServicePlaneCheckpointAuthorization {
            chain_id: [0xA1; 32],
            authorization_epoch: 8,
            nonce: 9,
            expires_at: 1_100,
            roots: roots(),
            authorization: max_authorization(),
        };
        let envelope = authorized.envelope().expect("service checkpoint envelope");
        let verifier = ExpectedVerifier {
            message: envelope.canonical_message(AuthPolicy::Max).expect("message"),
            context: envelope.fips_signature_context(AuthPolicy::Max).expect("context"),
        };
        let validation = ServicePlaneCheckpointValidationContext {
            expected_chain_id: [0xA1; 32],
            expected_authorization_epoch: 8,
            expected_nonce: 9,
            current_service_plane_epoch: 6,
            expected_service_plane_epoch: 7,
            expected_authority_keyset_commitment: authorized
                .authorization
                .keyset_commitment()
                .expect("authority keyset"),
            now: 1_000,
            max_future_seconds: 200,
        };

        assert!(verify_service_plane_checkpoint(
            &verifier,
            &authorized,
            &validation,
        ));

        let mut stale = validation;
        stale.expected_service_plane_epoch += 1;
        assert!(!verify_service_plane_checkpoint(
            &verifier,
            &authorized,
            &stale,
        ));
    }

    #[test]
    fn service_plane_checkpoint_requires_exact_next_epoch() {
        let authorized = ServicePlaneCheckpointAuthorization {
            chain_id: [0xA1; 32],
            authorization_epoch: 8,
            nonce: 9,
            expires_at: 1_100,
            roots: roots(),
            authorization: max_authorization(),
        };
        let envelope = authorized.envelope().expect("service checkpoint envelope");
        let verifier = ExpectedVerifier {
            message: envelope.canonical_message(AuthPolicy::Max).expect("message"),
            context: envelope.fips_signature_context(AuthPolicy::Max).expect("context"),
        };
        let mut validation = ServicePlaneCheckpointValidationContext {
            expected_chain_id: [0xA1; 32],
            expected_authorization_epoch: 8,
            expected_nonce: 9,
            current_service_plane_epoch: 5,
            expected_service_plane_epoch: 7,
            expected_authority_keyset_commitment: authorized
                .authorization
                .keyset_commitment()
                .expect("authority keyset"),
            now: 1_000,
            max_future_seconds: 200,
        };

        assert!(!verify_service_plane_checkpoint(
            &verifier,
            &authorized,
            &validation,
        ));

        validation.current_service_plane_epoch = 7;
        validation.expected_service_plane_epoch = 7;
        assert!(!verify_service_plane_checkpoint(
            &verifier,
            &authorized,
            &validation,
        ));
    }

    #[test]
    fn service_plane_checkpoint_commitment_binds_every_root() {
        let base = roots();
        let commitment = base.authorization_commitment().expect("commitment");

        let mut changed = base.clone();
        changed.service_finality_root[0] ^= 1;
        assert_ne!(commitment, changed.authorization_commitment().expect("finality change"));

        let mut changed = base;
        changed.payment_global_checkpoint_root[0] ^= 1;
        assert_ne!(commitment, changed.authorization_commitment().expect("payment change"));
    }

    #[test]
    fn parallel_plane_roots_are_fail_closed() {
        let roots = ServicePlaneRoots {
            epoch: 1,
            payment_global_checkpoint_root: [1; 32],
            storage_catalog_root: [2; 32],
            cognitive_registry_root: [3; 32],
            cognitive_evidence_root: [4; 32],
            autopilot_policy_graph_root: [5; 32],
            data_availability_root: [6; 32],
            service_finality_root: [7; 32],
        };
        assert_eq!(roots.validate(), Ok(()));
    }

    #[test]
    fn aggregate_storage_ratio_fails_closed_on_overflow() {
        let capacity = ServicePlaneCapacityEnvelope {
            payment_items: 0,
            logical_storage_bytes: 1,
            physical_storage_bytes: u128::MAX,
            cognitive_receipts: 0,
            authorized_autopilot_actions: 0,
        };
        assert_eq!(capacity.physical_to_logical_storage_bps(), None);
    }

    #[test]
    fn aggregate_storage_ratio_uses_real_physical_bytes() {
        let capacity = ServicePlaneCapacityEnvelope {
            payment_items: 1_000_000,
            logical_storage_bytes: 1_000_000,
            physical_storage_bytes: 100_000,
            cognitive_receipts: 100,
            authorized_autopilot_actions: 1000,
        };
        assert_eq!(capacity.physical_to_logical_storage_bps(), Some(1000));
    }
}
