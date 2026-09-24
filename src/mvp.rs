//! Canonical cross-plane MVP checkpoint.
//!
//! This module is intentionally small: it does not duplicate networking,
//! inference, verification, storage or settlement logic. It binds the roots
//! produced by those planes into one deterministic checkpoint so a three-host
//! MVP run can prove that every subsystem participated in the same job.

use sha2::{Digest, Sha256};

pub const MVP_CHECKPOINT_DOMAIN: &[u8] = b"SYNERGY/MVP-CHECKPOINT/V1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MvpCheckpoint {
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
    pub settlement_root: [u8; 32],
    pub scheduler_root: [u8; 32],
    pub node_set_root: [u8; 32],
}

impl MvpCheckpoint {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.chain_id == [0; 32] {
            return Err("chain id required");
        }
        if self.epoch == 0 || self.sequence == 0 {
            return Err("epoch and sequence must be positive");
        }
        for root in [
            self.model_root,
            self.network_root,
            self.provider_root,
            self.inference_root,
            self.verification_root,
            self.kv_root,
            self.storage_root,
            self.settlement_root,
            self.scheduler_root,
            self.node_set_root,
        ] {
            if root == [0; 32] {
                return Err("all MVP plane roots are required");
            }
        }
        if self.sequence > 1 && self.previous_checkpoint == [0; 32] {
            return Err("non-genesis MVP checkpoint requires previous checkpoint");
        }
        Ok(())
    }

    pub fn commitment(&self) -> Option<[u8; 32]> {
        self.validate().ok()?;
        let mut h = Sha256::new();
        h.update(MVP_CHECKPOINT_DOMAIN);
        h.update(crate::pq::CRYPTO_PROFILE_VERSION.to_be_bytes());
        h.update(self.chain_id);
        h.update(self.epoch.to_be_bytes());
        h.update(self.sequence.to_be_bytes());
        h.update(self.previous_checkpoint);
        h.update(self.model_root);
        h.update(self.network_root);
        h.update(self.provider_root);
        h.update(self.inference_root);
        h.update(self.verification_root);
        h.update(self.kv_root);
        h.update(self.storage_root);
        h.update(self.settlement_root);
        h.update(self.scheduler_root);
        h.update(self.node_set_root);
        Some(h.finalize().into())
    }

    pub fn extends(&self, previous: &MvpCheckpoint) -> bool {
        let Some(previous_commitment) = previous.commitment() else {
            return false;
        };
        self.validate().is_ok()
            && self.chain_id == previous.chain_id
            && self.epoch >= previous.epoch
            && self.sequence == previous.sequence + 1
            && self.previous_checkpoint == previous_commitment
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checkpoint(sequence: u64, previous: [u8; 32]) -> MvpCheckpoint {
        MvpCheckpoint {
            chain_id: [1; 32],
            epoch: 7,
            sequence,
            previous_checkpoint: previous,
            model_root: [2; 32],
            network_root: [3; 32],
            provider_root: [4; 32],
            inference_root: [5; 32],
            verification_root: [6; 32],
            kv_root: [7; 32],
            storage_root: [8; 32],
            settlement_root: [9; 32],
            scheduler_root: [10; 32],
            node_set_root: [11; 32],
        }
    }

    #[test]
    fn checkpoint_binds_every_mvp_plane() {
        let base = checkpoint(1, [0; 32]);
        let root = base.commitment().expect("valid MVP checkpoint");

        let mut changed = base.clone();
        changed.inference_root = [42; 32];
        assert_ne!(changed.commitment().unwrap(), root);

        let mut changed = base.clone();
        changed.settlement_root = [43; 32];
        assert_ne!(changed.commitment().unwrap(), root);

        let mut changed = base.clone();
        changed.network_root = [44; 32];
        assert_ne!(changed.commitment().unwrap(), root);
    }

    #[test]
    fn chain_extension_is_exact() {
        let c1 = checkpoint(1, [0; 32]);
        let c1_root = c1.commitment().unwrap();
        let c2 = checkpoint(2, c1_root);
        assert!(c2.extends(&c1));

        let mut wrong = c2.clone();
        wrong.previous_checkpoint = [99; 32];
        assert!(!wrong.extends(&c1));
    }

    #[test]
    fn missing_plane_root_is_rejected() {
        let mut c = checkpoint(1, [0; 32]);
        c.verification_root = [0; 32];
        assert!(c.validate().is_err());
        assert!(c.commitment().is_none());
    }
}
