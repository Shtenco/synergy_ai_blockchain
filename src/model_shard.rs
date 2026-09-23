//! Immutable model-manifest and model-shard lineage primitives.
//!
//! The chain commits identities and lineage. Model bytes remain in the storage
//! plane and are referenced by content/storage commitments.

use sha2::{Digest, Sha256};

use crate::pq::{
    verify_envelope_authorization, AuthPolicy, AuthorizationDomain, AuthorizationEnvelope,
    AuthorizationValidationContext, ContextSignatureVerifier, HybridAuthorization,
};

const MODEL_UPGRADE_DOMAIN: &[u8] = b"SYNERGY/MODEL-UPGRADE/V1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelManifestCommitment {
    pub model_root: [u8; 32],
    pub generation: u64,
    pub shard_count: u32,
    pub ordered_shard_root: [u8; 32],
    pub architecture_root: [u8; 32],
    pub tokenizer_root: [u8; 32],
    pub numeric_representation_root: [u8; 32],
}

impl ModelManifestCommitment {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.model_root == [0; 32]
            || self.ordered_shard_root == [0; 32]
            || self.architecture_root == [0; 32]
            || self.tokenizer_root == [0; 32]
            || self.numeric_representation_root == [0; 32]
        {
            return Err("model manifest commitments required");
        }
        if self.shard_count == 0 {
            return Err("model must contain at least one shard");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelShardOutput {
    /// Stable commitment to this exact shard output/version.
    pub shard_commitment: [u8; 32],
    pub model_root: [u8; 32],
    pub generation: u64,
    pub shard_index: u32,
    pub shard_count: u32,
    /// Previous immutable shard output when this is an update.
    pub parent_shard_commitment: Option<[u8; 32]>,
    /// Commits tensor names/ranges/order represented by this shard.
    pub tensor_manifest_root: [u8; 32],
    /// Hash of the compute-native bytes after primary quantization/factorization.
    pub content_hash: [u8; 32],
    /// Object identifier in the storage plane (ArchiveReceipt.object_id).
    pub storage_object_id: [u8; 32],
    pub codec_version_commitment: [u8; 32],
    pub logical_bytes: u64,
    pub stored_bytes: u64,
    pub availability_root: [u8; 32],
}

impl ModelShardOutput {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.shard_commitment == [0; 32]
            || self.model_root == [0; 32]
            || self.tensor_manifest_root == [0; 32]
            || self.content_hash == [0; 32]
            || self.storage_object_id == [0; 32]
            || self.codec_version_commitment == [0; 32]
            || self.availability_root == [0; 32]
        {
            return Err("model shard commitments required");
        }
        if self.shard_count == 0 || self.shard_index >= self.shard_count {
            return Err("invalid shard position");
        }
        if self.logical_bytes == 0 || self.stored_bytes == 0 {
            return Err("model shard byte lengths must be positive");
        }
        match (self.generation, self.parent_shard_commitment) {
            (0, None) => {}
            (0, Some(_)) => return Err("generation zero cannot have a parent shard"),
            (_, None) => return Err("updated shard requires parent commitment"),
            (_, Some(parent)) if parent == [0; 32] || parent == self.shard_commitment => {
                return Err("invalid parent shard commitment")
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelLineageTransition {
    pub transition_commitment: [u8; 32],
    pub target_model_root: [u8; 32],
    pub generation: u64,
    /// Inputs consumed by this transition. Empty only for generation zero.
    pub consumed_shards: Vec<[u8; 32]>,
    /// New immutable outputs. Unchanged shards may be referenced by the new
    /// manifest instead of being recreated.
    pub created_shards: Vec<ModelShardOutput>,
    pub activation_epoch: u64,
}

impl ModelLineageTransition {
    pub fn authorization_commitment(&self) -> Option<[u8; 32]> {
        self.validate().ok()?;

        let mut hasher = Sha256::new();
        hasher.update(MODEL_UPGRADE_DOMAIN);
        hasher.update(self.transition_commitment);
        hasher.update(self.target_model_root);
        hasher.update(self.generation.to_be_bytes());
        hasher.update(self.activation_epoch.to_be_bytes());

        hasher.update((self.consumed_shards.len() as u64).to_be_bytes());
        for consumed in &self.consumed_shards {
            hasher.update(consumed);
        }

        hasher.update((self.created_shards.len() as u64).to_be_bytes());
        for shard in &self.created_shards {
            hasher.update(shard.shard_commitment);
            hasher.update(shard.model_root);
            hasher.update(shard.generation.to_be_bytes());
            hasher.update(shard.shard_index.to_be_bytes());
            hasher.update(shard.shard_count.to_be_bytes());
            match shard.parent_shard_commitment {
                Some(parent) => {
                    hasher.update([1]);
                    hasher.update(parent);
                }
                None => hasher.update([0]),
            }
            hasher.update(shard.tensor_manifest_root);
            hasher.update(shard.content_hash);
            hasher.update(shard.storage_object_id);
            hasher.update(shard.codec_version_commitment);
            hasher.update(shard.logical_bytes.to_be_bytes());
            hasher.update(shard.stored_bytes.to_be_bytes());
            hasher.update(shard.availability_root);
        }

        Some(hasher.finalize().into())
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.transition_commitment == [0; 32] || self.target_model_root == [0; 32] {
            return Err("lineage transition commitments required");
        }
        if self.created_shards.is_empty() {
            return Err("lineage transition must create at least one shard");
        }
        if self.generation == 0 && !self.consumed_shards.is_empty() {
            return Err("generation zero cannot consume previous shards");
        }
        if self.generation > 0 && self.consumed_shards.is_empty() {
            return Err("nonzero generation must consume previous shard lineage");
        }

        for (i, consumed) in self.consumed_shards.iter().enumerate() {
            if *consumed == [0; 32] {
                return Err("zero consumed shard commitment");
            }
            if self.consumed_shards[..i].contains(consumed) {
                return Err("duplicate consumed shard");
            }
        }

        let first = &self.created_shards[0];
        for (i, shard) in self.created_shards.iter().enumerate() {
            shard.validate()?;
            if shard.model_root != self.target_model_root || shard.generation != self.generation {
                return Err("created shard does not belong to target generation");
            }
            if shard.shard_count != first.shard_count {
                return Err("created shard count mismatch");
            }
            if self.created_shards[..i]
                .iter()
                .any(|prior| prior.shard_commitment == shard.shard_commitment)
            {
                return Err("duplicate created shard commitment");
            }
            if self.created_shards[..i]
                .iter()
                .any(|prior| prior.shard_index == shard.shard_index)
            {
                return Err("duplicate created shard index");
            }
            if self.generation > 0 {
                let parent = shard
                    .parent_shard_commitment
                    .ok_or("updated shard requires parent commitment")?;
                if !self.consumed_shards.contains(&parent) {
                    return Err("created shard parent was not consumed by transition");
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelUpgradeAuthorization {
    pub chain_id: [u8; 32],
    pub epoch: u64,
    pub nonce: u64,
    pub expires_at: u64,
    pub transition: ModelLineageTransition,
    pub authorization: HybridAuthorization,
}

impl ModelUpgradeAuthorization {
    pub fn envelope(&self) -> Option<AuthorizationEnvelope> {
        Some(AuthorizationEnvelope {
            chain_id: self.chain_id,
            domain: AuthorizationDomain::ModelUpgrade,
            epoch: self.epoch,
            nonce: self.nonce,
            expires_at: self.expires_at,
            payload_commitment: self.transition.authorization_commitment()?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModelUpgradeValidationContext {
    pub expected_chain_id: [u8; 32],
    pub expected_epoch: u64,
    pub expected_nonce: u64,
    pub expected_authority_keyset_commitment: [u8; 32],
    pub expected_activation_epoch: u64,
    pub now: u64,
    pub max_future_seconds: u64,
}

pub fn verify_model_upgrade<V: ContextSignatureVerifier>(
    verifier: &V,
    upgrade: &ModelUpgradeAuthorization,
    validation: &ModelUpgradeValidationContext,
) -> bool {
    if upgrade.authorization.policy != AuthPolicy::Max
        || upgrade.transition.activation_epoch != validation.expected_activation_epoch
        || upgrade.authorization.keyset_commitment()
            != Some(validation.expected_authority_keyset_commitment)
    {
        return false;
    }
    let envelope = match upgrade.envelope() {
        Some(envelope) => envelope,
        None => return false,
    };
    let auth_validation = AuthorizationValidationContext {
        expected_chain_id: validation.expected_chain_id,
        expected_domain: AuthorizationDomain::ModelUpgrade,
        expected_policy: AuthPolicy::Max,
        expected_epoch: validation.expected_epoch,
        expected_nonce: validation.expected_nonce,
        now: validation.now,
        max_future_seconds: validation.max_future_seconds,
    };

    verify_envelope_authorization(
        verifier,
        &upgrade.authorization,
        &envelope,
        &auth_validation,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shard(generation: u64, index: u32, parent: Option<[u8; 32]>) -> ModelShardOutput {
        ModelShardOutput {
            shard_commitment: [10 + index as u8; 32],
            model_root: [1; 32],
            generation,
            shard_index: index,
            shard_count: 2,
            parent_shard_commitment: parent,
            tensor_manifest_root: [2; 32],
            content_hash: [3; 32],
            storage_object_id: [4; 32],
            codec_version_commitment: [5; 32],
            logical_bytes: 1_000,
            stored_bytes: 700,
            availability_root: [6; 32],
        }
    }

    #[test]
    fn genesis_shard_has_no_parent() {
        assert_eq!(shard(0, 0, None).validate(), Ok(()));
    }

    #[test]
    fn updated_shard_requires_parent() {
        assert!(shard(1, 0, None).validate().is_err());
        assert_eq!(shard(1, 0, Some([9; 32])).validate(), Ok(()));
    }

    #[test]
    fn transition_rejects_duplicate_consumed_inputs() {
        let t = ModelLineageTransition {
            transition_commitment: [7; 32],
            target_model_root: [1; 32],
            generation: 1,
            consumed_shards: vec![[9; 32], [9; 32]],
            created_shards: vec![shard(1, 0, Some([9; 32]))],
            activation_epoch: 10,
        };
        assert!(t.validate().is_err());
    }

    #[test]
    fn transition_rejects_duplicate_created_shard_index() {
        let mut second = shard(1, 0, Some([9; 32]));
        second.shard_commitment = [12; 32];

        let transition = ModelLineageTransition {
            transition_commitment: [7; 32],
            target_model_root: [1; 32],
            generation: 1,
            consumed_shards: vec![[8; 32], [9; 32]],
            created_shards: vec![
                shard(1, 0, Some([8; 32])),
                second,
            ],
            activation_epoch: 10,
        };
        assert!(transition.validate().is_err());
    }

    #[test]
    fn transition_rejects_parent_outside_consumed_lineage() {
        let transition = ModelLineageTransition {
            transition_commitment: [7; 32],
            target_model_root: [1; 32],
            generation: 1,
            consumed_shards: vec![[8; 32], [9; 32]],
            created_shards: vec![
                shard(1, 0, Some([8; 32])),
                shard(1, 1, Some([10; 32])),
            ],
            activation_epoch: 10,
        };
        assert!(transition.validate().is_err());
    }

    #[test]
    fn transition_closes_generation_identity() {
        let t = ModelLineageTransition {
            transition_commitment: [7; 32],
            target_model_root: [1; 32],
            generation: 1,
            consumed_shards: vec![[8; 32], [9; 32]],
            created_shards: vec![
                shard(1, 0, Some([8; 32])),
                shard(1, 1, Some([9; 32])),
            ],
            activation_epoch: 10,
        };
        assert_eq!(t.validate(), Ok(()));
    }

    #[derive(Clone)]
    struct ExpectedUpgradeVerifier {
        message: Vec<u8>,
        context: Vec<u8>,
    }

    impl crate::pq::ContextSignatureVerifier for ExpectedUpgradeVerifier {
        fn verify_with_context(
            &self,
            _scheme: crate::pq::AuthScheme,
            _public_key: &[u8],
            message: &[u8],
            context: &[u8],
            _signature: &[u8],
        ) -> bool {
            message == self.message && context == self.context
        }
    }

    fn max_authorization() -> crate::pq::HybridAuthorization {
        use crate::pq::{
            AuthScheme, SignatureEvidence, ML_DSA_87_PUBLIC_KEY_BYTES,
            ML_DSA_87_SIGNATURE_BYTES, SECP256K1_PUBLIC_KEY_BYTES,
            SECP256K1_SIGNATURE_BYTES, SLH_DSA_SHAKE_256S_PUBLIC_KEY_BYTES,
            SLH_DSA_SHAKE_256S_SIGNATURE_BYTES,
        };
        let mut secp_key = vec![1u8; SECP256K1_PUBLIC_KEY_BYTES];
        secp_key[0] = 0x02;
        let mut secp_sig = vec![2u8; SECP256K1_SIGNATURE_BYTES];
        secp_sig[SECP256K1_SIGNATURE_BYTES - 1] = 0;

        crate::pq::HybridAuthorization {
            policy: crate::pq::AuthPolicy::Max,
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

    #[test]
    fn model_upgrade_requires_max_state_aware_authorization() {
        let transition = ModelLineageTransition {
            transition_commitment: [7; 32],
            target_model_root: [1; 32],
            generation: 1,
            consumed_shards: vec![[8; 32], [9; 32]],
            created_shards: vec![
                shard(1, 0, Some([8; 32])),
                shard(1, 1, Some([9; 32])),
            ],
            activation_epoch: 10,
        };
        let upgrade = ModelUpgradeAuthorization {
            chain_id: [0x71; 32],
            epoch: 10,
            nonce: 11,
            expires_at: 1_100,
            transition,
            authorization: max_authorization(),
        };
        let envelope = upgrade.envelope().expect("upgrade envelope");
        let verifier = ExpectedUpgradeVerifier {
            message: envelope
                .canonical_message(crate::pq::AuthPolicy::Max)
                .expect("upgrade message"),
            context: envelope
                .fips_signature_context(crate::pq::AuthPolicy::Max)
                .expect("upgrade context"),
        };
        let validation = ModelUpgradeValidationContext {
            expected_chain_id: [0x71; 32],
            expected_epoch: 10,
            expected_nonce: 11,
            expected_authority_keyset_commitment: max_authorization()
                .keyset_commitment()
                .expect("model authority keyset"),
            expected_activation_epoch: 10,
            now: 1_000,
            max_future_seconds: 200,
        };

        assert!(verify_model_upgrade(&verifier, &upgrade, &validation));

        let mut downgraded = upgrade.clone();
        downgraded.authorization.policy = crate::pq::AuthPolicy::Online;
        assert!(!verify_model_upgrade(&verifier, &downgraded, &validation));
    }

    #[test]
    fn model_upgrade_rejects_unregistered_authority_keyset() {
        let transition = ModelLineageTransition {
            transition_commitment: [7; 32],
            target_model_root: [1; 32],
            generation: 1,
            consumed_shards: vec![[8; 32], [9; 32]],
            created_shards: vec![
                shard(1, 0, Some([8; 32])),
                shard(1, 1, Some([9; 32])),
            ],
            activation_epoch: 10,
        };
        let upgrade = ModelUpgradeAuthorization {
            chain_id: [0x71; 32],
            epoch: 10,
            nonce: 11,
            expires_at: 1_100,
            transition,
            authorization: max_authorization(),
        };
        let envelope = upgrade.envelope().expect("upgrade envelope");
        let verifier = ExpectedUpgradeVerifier {
            message: envelope
                .canonical_message(AuthPolicy::Max)
                .expect("upgrade message"),
            context: envelope
                .fips_signature_context(AuthPolicy::Max)
                .expect("upgrade context"),
        };
        let mut validation = ModelUpgradeValidationContext {
            expected_chain_id: [0x71; 32],
            expected_epoch: 10,
            expected_nonce: 11,
            expected_authority_keyset_commitment: upgrade
                .authorization
                .keyset_commitment()
                .expect("model authority keyset"),
            expected_activation_epoch: 10,
            now: 1_000,
            max_future_seconds: 200,
        };
        validation.expected_authority_keyset_commitment[0] ^= 1;

        assert!(!verify_model_upgrade(&verifier, &upgrade, &validation));
    }

    #[test]
    fn model_upgrade_rejects_wrong_activation_epoch() {
        let transition = ModelLineageTransition {
            transition_commitment: [7; 32],
            target_model_root: [1; 32],
            generation: 1,
            consumed_shards: vec![[8; 32], [9; 32]],
            created_shards: vec![
                shard(1, 0, Some([8; 32])),
                shard(1, 1, Some([9; 32])),
            ],
            activation_epoch: 10,
        };
        let upgrade = ModelUpgradeAuthorization {
            chain_id: [0x71; 32],
            epoch: 10,
            nonce: 11,
            expires_at: 1_100,
            transition,
            authorization: max_authorization(),
        };
        let envelope = upgrade.envelope().expect("upgrade envelope");
        let verifier = ExpectedUpgradeVerifier {
            message: envelope
                .canonical_message(AuthPolicy::Max)
                .expect("upgrade message"),
            context: envelope
                .fips_signature_context(AuthPolicy::Max)
                .expect("upgrade context"),
        };
        let mut validation = ModelUpgradeValidationContext {
            expected_chain_id: [0x71; 32],
            expected_epoch: 10,
            expected_nonce: 11,
            expected_authority_keyset_commitment: upgrade
                .authorization
                .keyset_commitment()
                .expect("model authority keyset"),
            expected_activation_epoch: 11,
            now: 1_000,
            max_future_seconds: 200,
        };

        assert!(!verify_model_upgrade(&verifier, &upgrade, &validation));

        validation.expected_activation_epoch = 10;
        assert!(verify_model_upgrade(&verifier, &upgrade, &validation));
    }

    #[test]
    fn model_upgrade_commitment_binds_lineage_and_activation_epoch() {
        let base = ModelLineageTransition {
            transition_commitment: [7; 32],
            target_model_root: [1; 32],
            generation: 1,
            consumed_shards: vec![[8; 32], [9; 32]],
            created_shards: vec![
                shard(1, 0, Some([8; 32])),
                shard(1, 1, Some([9; 32])),
            ],
            activation_epoch: 10,
        };
        let commitment = base.authorization_commitment().expect("commitment");

        let mut changed = base.clone();
        changed.activation_epoch += 1;
        assert_ne!(commitment, changed.authorization_commitment().expect("changed commitment"));

        let mut changed = base;
        changed.created_shards[0].content_hash[0] ^= 1;
        assert_ne!(commitment, changed.authorization_commitment().expect("changed content"));
    }

}
