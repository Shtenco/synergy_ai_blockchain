//! Provenance-aware admission primitives for bonded CognitiveNodes.
//!
//! Economic identity is not cognitive independence. A Sybil operator must not
//! obtain N independent-node rewards by registering the same model/checkpoint
//! under N different node ids. These types commit model lineage and frozen
//! benchmark evidence separately from the operational node manifest.

use crate::cognitive::CognitiveNodeManifest;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CognitiveNodeProvenance {
    pub node_id: [u8; 32],
    pub model_root: [u8; 32],
    pub lineage_root: [u8; 32],
    pub implementation_root: [u8; 32],
    pub benchmark_root: [u8; 32],
    pub evidence_root: [u8; 32],
    pub role_commitment: [u8; 32],
    pub frozen_trace_count: u64,
}

impl CognitiveNodeProvenance {
    pub fn validate_against(&self, node: &CognitiveNodeManifest) -> Result<(), &'static str> {
        if self.node_id != node.node_id {
            return Err("provenance node mismatch");
        }
        if self.model_root != node.model_root {
            return Err("provenance model root mismatch");
        }
        if self.lineage_root == [0; 32]
            || self.implementation_root == [0; 32]
            || self.benchmark_root == [0; 32]
            || self.evidence_root == [0; 32]
            || self.role_commitment == [0; 32]
        {
            return Err("complete provenance commitments required");
        }
        if self.frozen_trace_count == 0 {
            return Err("frozen benchmark trace required");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndependenceVerdict {
    Independent,
    DuplicateModel,
    DuplicateLineageAndRole,
    DuplicateImplementationAndRole,
}

/// Deterministic structural anti-clone gate.
///
/// This gate cannot prove statistical independence by itself; pairwise error
/// correlation remains an off-consensus evidence metric committed through
/// `evidence_root`. It does prevent the strongest trivial Sybil cases on-chain.
pub fn structural_independence(
    left: &CognitiveNodeProvenance,
    right: &CognitiveNodeProvenance,
) -> IndependenceVerdict {
    if left.model_root == right.model_root {
        return IndependenceVerdict::DuplicateModel;
    }
    if left.lineage_root == right.lineage_root && left.role_commitment == right.role_commitment {
        return IndependenceVerdict::DuplicateLineageAndRole;
    }
    if left.implementation_root == right.implementation_root
        && left.role_commitment == right.role_commitment
    {
        return IndependenceVerdict::DuplicateImplementationAndRole;
    }
    IndependenceVerdict::Independent
}

/// Count only structurally independent provenance entries toward an economic
/// diversity quorum. The caller must provide a deterministic order.
pub fn independent_prefix_count(entries: &[CognitiveNodeProvenance]) -> usize {
    let mut accepted: Vec<&CognitiveNodeProvenance> = Vec::new();
    'candidate: for candidate in entries {
        for old in &accepted {
            if structural_independence(candidate, old) != IndependenceVerdict::Independent {
                continue 'candidate;
            }
        }
        accepted.push(candidate);
    }
    accepted.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cognitive::CognitiveRole;

    fn manifest(id: u8, model: u8) -> CognitiveNodeManifest {
        CognitiveNodeManifest {
            node_id: [id; 32],
            owner_account: [2; 32],
            pq_identity_commitment: [3; 32],
            software_commitment: [4; 32],
            model_root: [model; 32],
            policy_root: [6; 32],
            role: CognitiveRole::LogicVerifier,
            trust_tier: 1,
            bond: 100,
            max_unit_price: 10,
            valid_from_epoch: 1,
            valid_until_epoch: 100,
        }
    }

    fn provenance(id: u8, model: u8, lineage: u8, implementation: u8) -> CognitiveNodeProvenance {
        CognitiveNodeProvenance {
            node_id: [id; 32],
            model_root: [model; 32],
            lineage_root: [lineage; 32],
            implementation_root: [implementation; 32],
            benchmark_root: [9; 32],
            evidence_root: [10; 32],
            role_commitment: [11; 32],
            frozen_trace_count: 100,
        }
    }

    #[test]
    fn provenance_must_match_operational_manifest() {
        let node = manifest(1, 5);
        let p = provenance(1, 5, 7, 8);
        assert_eq!(p.validate_against(&node), Ok(()));
    }

    #[test]
    fn same_checkpoint_is_not_two_independent_nodes() {
        let a = provenance(1, 5, 7, 8);
        let b = provenance(2, 5, 9, 10);
        assert_eq!(structural_independence(&a, &b), IndependenceVerdict::DuplicateModel);
        assert_eq!(independent_prefix_count(&[a, b]), 1);
    }

    #[test]
    fn distinct_model_lineage_and_implementation_count_independently() {
        let a = provenance(1, 5, 7, 8);
        let b = provenance(2, 6, 9, 10);
        assert_eq!(structural_independence(&a, &b), IndependenceVerdict::Independent);
        assert_eq!(independent_prefix_count(&[a, b]), 2);
    }
}
