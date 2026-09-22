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

pub fn can_host(node: &NodeCapacity, work: &WorkRequirements) -> bool {
    node.memory_bytes >= work.minimum_memory_bytes
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
    let memory_slack = (node.memory_bytes - work.minimum_memory_bytes) as u128;
    let compute_slack = (node.max_compute_units - work.compute_units) as u128;
    Some(locality_penalty + memory_slack / (1024 * 1024) as u128 + compute_slack)
}

pub fn choose_node<'a>(nodes: &'a [NodeCapacity], work: &WorkRequirements) -> Option<&'a NodeCapacity> {
    nodes.iter()
        .filter_map(|node| placement_score(node, work).map(|score| (score, node)))
        .min_by_key(|(score, _)| *score)
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
