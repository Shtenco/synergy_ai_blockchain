#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrecompileAddress(pub u16);

impl PrecompileAddress {
    /// Chain-local reserved addresses. Client integrations map these to
    /// 0x0000000000000000000000000000000000000900 + offset.
    pub const ML_DSA_VERIFY: Self = Self(0x0900);
    pub const SLH_DSA_VERIFY: Self = Self(0x0901);
    pub const NEXUS_INFER: Self = Self(0x0910);
    pub const NEXUS_PROOF_VERIFY: Self = Self(0x0911);
    pub const LEGACY_BINDING_VERIFY: Self = Self(0x0920);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrecompileGasSchedule {
    pub base: u64,
    pub per_input_byte: u64,
    pub per_output_byte: u64,
    pub per_nexus_node: u64,
    pub per_nexus_edge: u64,
    pub per_nexus_layer: u64,
}

impl Default for PrecompileGasSchedule {
    fn default() -> Self {
        Self {
            base: 25_000,
            per_input_byte: 8,
            per_output_byte: 16,
            per_nexus_node: 250,
            per_nexus_edge: 40,
            per_nexus_layer: 5_000,
        }
    }
}

impl PrecompileGasSchedule {
    pub fn nexus_cost(
        &self,
        input_bytes: usize,
        output_bytes: usize,
        nodes: usize,
        edges: usize,
        layers: usize,
    ) -> Option<u64> {
        let input = self.per_input_byte.checked_mul(input_bytes as u64)?;
        let output = self.per_output_byte.checked_mul(output_bytes as u64)?;
        let node = self.per_nexus_node.checked_mul(nodes as u64)?;
        let edge = self.per_nexus_edge.checked_mul(edges as u64)?;
        let layer = self.per_nexus_layer.checked_mul(layers as u64)?;
        self.base
            .checked_add(input)?
            .checked_add(output)?
            .checked_add(node)?
            .checked_add(edge)?
            .checked_add(layer)
    }
}

/// Consensus-critical rule: precompile implementation, model manifest hash and gas
/// schedule are activated only at an explicit block height. No validator may fetch
/// model weights or code from the network while executing a block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsensusActivation {
    pub activation_block: u64,
    pub model_manifest_hash: [u8; 32],
    pub implementation_hash: [u8; 32],
    pub gas_schedule: PrecompileGasSchedule,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gas_cost_is_deterministic() {
        let s = PrecompileGasSchedule::default();
        assert_eq!(s.nexus_cost(32, 32, 16, 32, 3), s.nexus_cost(32, 32, 16, 32, 3));
    }
}
