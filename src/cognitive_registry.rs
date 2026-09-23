//! Provenance-aware admission primitives for bonded CognitiveNodes.
//!
//! Economic identity is not cognitive independence. A Sybil operator must not
//! obtain N independent-node rewards by registering the same model/checkpoint
//! under N different node ids. These types commit model lineage and frozen
//! benchmark evidence separately from the operational node manifest.

use sha2::{Digest, Sha256};

use crate::cognitive::{CognitiveNodeManifest, CognitiveRole};

fn canonical_role_commitment(role: CognitiveRole) -> [u8; 32] {
    const DOMAIN: &[u8] = b"SYNERGY/COGNITIVE-ROLE/V1\0";
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update([role.protocol_code()]);
    hasher.finalize().into()
}

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
        if self.implementation_root != node.software_commitment {
            return Err("provenance implementation root mismatch");
        }
        if self.role_commitment != canonical_role_commitment(node.role) {
            return Err("provenance role commitment mismatch");
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
/// diversity quorum. Ordering is canonicalized internally by node_id so callers
/// cannot change quorum membership by permuting otherwise identical evidence.
pub(crate) fn independent_prefix_count(entries: &[CognitiveNodeProvenance]) -> usize {
    let mut ordered: Vec<&CognitiveNodeProvenance> = entries.iter().collect();
    ordered.sort_by_key(|entry| entry.node_id);

    let mut accepted: Vec<&CognitiveNodeProvenance> = Vec::new();
    'candidate: for candidate in ordered {
        for old in &accepted {
            if structural_independence(candidate, old) != IndependenceVerdict::Independent {
                continue 'candidate;
            }
        }
        accepted.push(candidate);
    }
    accepted.len()
}

pub fn independent_registered_count(
    entries: &[(&CognitiveNodeManifest, &CognitiveNodeProvenance)],
    epoch: u64,
) -> Result<usize, &'static str> {
    let mut ordered: Vec<(&CognitiveNodeManifest, &CognitiveNodeProvenance)> =
        entries.iter().copied().collect();
    ordered.sort_by_key(|(node, _)| node.node_id);

    let mut provenances = Vec::with_capacity(ordered.len());
    let mut previous_node_id: Option<[u8; 32]> = None;

    for (node, provenance) in ordered {
        node.validate(epoch)?;
        provenance.validate_against(node)?;

        if previous_node_id == Some(node.node_id) {
            return Err("duplicate cognitive node id");
        }
        previous_node_id = Some(node.node_id);
        provenances.push(provenance.clone());
    }

    Ok(independent_prefix_count(&provenances))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(id: u8, model: u8, implementation: u8) -> CognitiveNodeManifest {
        CognitiveNodeManifest {
            node_id: [id; 32],
            owner_account: [2; 32],
            pq_identity_commitment: [3; 32],
            software_commitment: [implementation; 32],
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
            role_commitment: canonical_role_commitment(CognitiveRole::LogicVerifier),
            frozen_trace_count: 100,
        }
    }

    #[test]
    fn provenance_must_match_operational_manifest() {
        let node = manifest(1, 5, 8);
        let p = provenance(1, 5, 7, 8);
        assert_eq!(p.validate_against(&node), Ok(()));
    }

    #[test]
    fn provenance_cannot_spoof_role_or_implementation_identity() {
        let node = manifest(1, 5, 8);
        let mut p = provenance(1, 5, 7, 8);
        assert_eq!(p.validate_against(&node), Ok(()));

        p.implementation_root = [99; 32];
        assert!(p.validate_against(&node).is_err());

        let mut p = provenance(1, 5, 7, 8);
        p.role_commitment[0] ^= 1;
        assert!(p.validate_against(&node).is_err());
    }

    #[test]
    fn registered_quorum_rejects_inactive_or_duplicate_nodes() {
        let node_a = manifest(1, 5, 8);
        let mut node_b = manifest(2, 6, 10);
        let prov_a = provenance(1, 5, 7, 8);
        let prov_b = provenance(2, 6, 9, 10);

        assert_eq!(
            independent_registered_count(&[(&node_a, &prov_a), (&node_b, &prov_b)], 10),
            Ok(2)
        );

        node_b.valid_until_epoch = 5;
        assert!(independent_registered_count(
            &[(&node_a, &prov_a), (&node_b, &prov_b)],
            10
        )
        .is_err());

        let duplicate = manifest(1, 6, 10);
        let duplicate_prov = provenance(1, 6, 9, 10);
        assert!(independent_registered_count(
            &[(&node_a, &prov_a), (&duplicate, &duplicate_prov)],
            10
        )
        .is_err());
    }

    #[test]
    fn same_checkpoint_is_not_two_independent_nodes() {
        let a = provenance(1, 5, 7, 8);
        let b = provenance(2, 5, 9, 10);
        assert_eq!(structural_independence(&a, &b), IndependenceVerdict::DuplicateModel);
        assert_eq!(independent_prefix_count(&[a, b]), 1);
    }

    #[test]
    fn independence_quorum_is_permutation_invariant() {
        let a = provenance(1, 5, 7, 8);
        let b = provenance(2, 5, 9, 10);
        let c = provenance(3, 6, 11, 12);

        let first = independent_prefix_count(&[a.clone(), b.clone(), c.clone()]);
        let second = independent_prefix_count(&[c.clone(), b.clone(), a.clone()]);
        let third = independent_prefix_count(&[b, a, c]);

        assert_eq!(first, second);
        assert_eq!(second, third);
        assert_eq!(first, 2);
    }

    #[test]
    fn distinct_model_lineage_and_implementation_count_independently() {
        let a = provenance(1, 5, 7, 8);
        let b = provenance(2, 6, 9, 10);
        assert_eq!(structural_independence(&a, &b), IndependenceVerdict::Independent);
        assert_eq!(independent_prefix_count(&[a, b]), 2);
    }
}
