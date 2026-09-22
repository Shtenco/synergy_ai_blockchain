//! Immutable model-manifest and model-shard lineage primitives.
//!
//! The chain commits identities and lineage. Model bytes remain in the storage
//! plane and are referenced by content/storage commitments.

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
        }
        Ok(())
    }
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
}
