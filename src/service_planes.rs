//! Canonical commitments for horizontally scaled SYNERGY service planes.
//!
//! World-scale payments, archival storage, CognitiveNodes and Autopilot work are
//! not executed as one giant serial EVM transaction stream. Each service plane
//! may execute/aggregate independently and the canonical chain commits bounded
//! roots plus availability/finality evidence.

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
        let value = self.physical_storage_bytes
            .saturating_mul(10_000)
            / self.logical_storage_bytes;
        Some(value.min(u64::MAX as u128) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
