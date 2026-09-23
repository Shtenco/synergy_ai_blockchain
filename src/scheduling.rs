//! Heterogeneous and locality-aware scheduling primitives.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeClass {
    Mobile,
    Desktop,
    Gpu,
    Accelerator,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeCapacity {
    pub node_id: [u8; 32],
    pub class: NodeClass,
    pub memory_bytes: u64,
    pub accelerator_memory_bytes: u64,
    pub storage_bytes: u64,
    pub max_input_bytes: u64,
    pub max_output_bytes: u64,
    pub max_compute_units: u64,
    pub locality_domain: [u8; 32],
    pub capability_root: [u8; 32],
}

impl NodeCapacity {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.node_id == [0; 32] || self.locality_domain == [0; 32] || self.capability_root == [0; 32] {
            return Err("node capacity commitments required");
        }
        if self.memory_bytes == 0 || self.max_compute_units == 0 {
            return Err("node capacity must be positive");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkRequirements {
    pub minimum_memory_bytes: u64,
    pub minimum_accelerator_memory_bytes: u64,
    pub minimum_storage_bytes: u64,
    pub input_bytes: u64,
    pub output_bytes: u64,
    pub compute_units: u64,
    pub preferred_locality_domain: Option<[u8; 32]>,
}

impl WorkRequirements {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.compute_units == 0 {
            return Err("work compute units required");
        }
        if matches!(self.preferred_locality_domain, Some([0u8; 32])) {
            return Err("preferred locality domain must be nonzero");
        }
        Ok(())
    }
}

pub fn can_host(node: &NodeCapacity, work: &WorkRequirements) -> bool {
    node.validate().is_ok()
        && work.validate().is_ok()
        && node.memory_bytes >= work.minimum_memory_bytes
        && node.accelerator_memory_bytes >= work.minimum_accelerator_memory_bytes
        && node.storage_bytes >= work.minimum_storage_bytes
        && node.max_input_bytes >= work.input_bytes
        && node.max_output_bytes >= work.output_bytes
        && node.max_compute_units >= work.compute_units
}

pub fn placement_score(node: &NodeCapacity, work: &WorkRequirements) -> Option<u128> {
    if !can_host(node, work) {
        return None;
    }
    let locality_penalty = match work.preferred_locality_domain {
        Some(domain) if domain != node.locality_domain => 1_000_000u128,
        _ => 0,
    };
    let memory_slack = u128::from(node.memory_bytes - work.minimum_memory_bytes);
    let compute_slack = u128::from(node.max_compute_units - work.compute_units);
    Some(locality_penalty + memory_slack / 1_048_576u128 + compute_slack)
}

pub fn choose_node<'a>(nodes: &'a [NodeCapacity], work: &WorkRequirements) -> Option<&'a NodeCapacity> {
    if work.validate().is_err() {
        return None;
    }
    for (index, node) in nodes.iter().enumerate() {
        if node.validate().is_err()
            || nodes[..index].iter().any(|prior| prior.node_id == node.node_id)
        {
            return None;
        }
    }

    nodes.iter()
        .filter_map(|node| placement_score(node, work).map(|score| (score, node)))
        .min_by_key(|(score, node)| (*score, node.node_id))
        .map(|(_, node)| node)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: u8, class: NodeClass, mem: u64, accel: u64, compute: u64, locality: u8) -> NodeCapacity {
        NodeCapacity {
            node_id: [id; 32],
            class,
            memory_bytes: mem,
            accelerator_memory_bytes: accel,
            storage_bytes: 10_000,
            max_input_bytes: 10_000,
            max_output_bytes: 10_000,
            max_compute_units: compute,
            locality_domain: [locality; 32],
            capability_root: [9; 32],
        }
    }

    #[test]
    fn never_assigns_work_beyond_hard_capacity() {
        let mobile = node(1, NodeClass::Mobile, 100, 0, 100, 1);
        let work = WorkRequirements {
            minimum_memory_bytes: 101,
            minimum_accelerator_memory_bytes: 0,
            minimum_storage_bytes: 0,
            input_bytes: 1,
            output_bytes: 1,
            compute_units: 10,
            preferred_locality_domain: None,
        };
        assert!(!can_host(&mobile, &work));
    }

    #[test]
    fn scheduler_is_permutation_invariant_on_equal_scores() {
        let a = node(1, NodeClass::Gpu, 2_000_000, 2_000_000, 1000, 7);
        let b = node(2, NodeClass::Gpu, 2_000_000, 2_000_000, 1000, 7);
        let work = WorkRequirements {
            minimum_memory_bytes: 1_000_000,
            minimum_accelerator_memory_bytes: 1_000_000,
            minimum_storage_bytes: 1,
            input_bytes: 1,
            output_bytes: 1,
            compute_units: 100,
            preferred_locality_domain: Some([7; 32]),
        };

        let first = choose_node(&[b.clone(), a.clone()], &work)
            .expect("node")
            .node_id;
        let second = choose_node(&[a.clone(), b.clone()], &work)
            .expect("node")
            .node_id;
        assert_eq!(first, second);
        assert_eq!(first, a.node_id);
    }

    #[test]
    fn scheduler_rejects_duplicate_node_identity() {
        let a = node(1, NodeClass::Gpu, 2_000_000, 2_000_000, 1000, 7);
        let mut duplicate = a.clone();
        duplicate.max_compute_units = 2_000;
        let work = WorkRequirements {
            minimum_memory_bytes: 1,
            minimum_accelerator_memory_bytes: 0,
            minimum_storage_bytes: 0,
            input_bytes: 0,
            output_bytes: 0,
            compute_units: 1,
            preferred_locality_domain: None,
        };
        assert!(choose_node(&[a, duplicate], &work).is_none());
    }

    #[test]
    fn scheduler_rejects_invalid_work_or_node() {
        let mut invalid_node = node(1, NodeClass::Gpu, 2_000_000, 2_000_000, 1000, 7);
        invalid_node.capability_root = [0; 32];
        let invalid_work = WorkRequirements {
            minimum_memory_bytes: 0,
            minimum_accelerator_memory_bytes: 0,
            minimum_storage_bytes: 0,
            input_bytes: 0,
            output_bytes: 0,
            compute_units: 0,
            preferred_locality_domain: None,
        };
        assert!(choose_node(&[invalid_node], &invalid_work).is_none());
    }

    #[test]
    fn locality_wins_when_both_nodes_fit() {
        let local = node(1, NodeClass::Gpu, 2_000_000, 2_000_000, 1000, 7);
        let remote = node(2, NodeClass::Gpu, 2_000_000, 2_000_000, 1000, 8);
        let work = WorkRequirements {
            minimum_memory_bytes: 1_000_000,
            minimum_accelerator_memory_bytes: 1_000_000,
            minimum_storage_bytes: 1,
            input_bytes: 1,
            output_bytes: 1,
            compute_units: 100,
            preferred_locality_domain: Some([7; 32]),
        };
        assert_eq!(choose_node(&[remote, local.clone()], &work).unwrap().node_id, local.node_id);
    }
}
