use crate::consensus::PrecompileGasSchedule;

pub const Q: i64 = 1 << 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NexusMode {
    Score,
    Policy,
    ProofAssist,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NexusManifest {
    /// Hash of the quantized consensus model artifact, not the PyTorch file.
    pub model_root: [u8; 32],
    /// Provenance hash for NEXUS V18 checkpoint from agi_olga.
    pub source_checkpoint_sha256_hex: &'static str,
    pub nodes: u16,
    pub layers: u16,
    pub q_bits: u8,
    pub max_input_values: u16,
    pub max_output_values: u16,
}

impl NexusManifest {
    pub const V18_SOURCE_CHECKPOINT: &'static str =
        "74433965c8193b6f75b42c197a4394bb14e37f2ef0ea0c7eb8b826e46c65c4e4";

    pub fn v18_consensus_profile(model_root: [u8; 32]) -> Self {
        Self {
            model_root,
            source_checkpoint_sha256_hex: Self::V18_SOURCE_CHECKPOINT,
            nodes: 16,
            layers: 3,
            q_bits: 16,
            max_input_values: 512,
            max_output_values: 64,
        }
    }

    pub fn validate(&self) -> Result<(), NexusError> {
        if self.model_root == [0u8; 32]
            || self.source_checkpoint_sha256_hex != Self::V18_SOURCE_CHECKPOINT
            || self.nodes != 16
            || self.layers != 3
            || self.q_bits != 16
            || self.max_input_values != 512
            || self.max_output_values != 64
        {
            return Err(NexusError::InvalidManifest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NexusRequest {
    pub mode: NexusMode,
    /// Signed Q16.16 values. Floats are forbidden in consensus execution.
    pub input_q16: Vec<i64>,
    pub max_output_values: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NexusResponse {
    pub output_q16: Vec<i64>,
    pub gas_used: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NexusError {
    InvalidManifest,
    InvalidShape,
    UnsupportedMode,
    GasOverflow,
}

fn i128_to_i64_saturating(value: i128) -> i64 {
    if value > i128::from(i64::MAX) {
        i64::MAX
    } else if value < i128::from(i64::MIN) {
        i64::MIN
    } else {
        match i64::try_from(value) {
            Ok(value) => value,
            Err(_) => {
                if value.is_negative() {
                    i64::MIN
                } else {
                    i64::MAX
                }
            }
        }
    }
}

fn qmul(a: i64, b: i64) -> i64 {
    let p = i128::from(a) * i128::from(b);
    i128_to_i64_saturating(p >> 16)
}

fn avg3(a: i64, b: i64, c: i64) -> i64 {
    let sum = i128::from(a) + i128::from(b) + i128::from(c);
    i128_to_i64_saturating(sum / 3)
}

fn qadd_saturating(a: i64, b: i64) -> i64 {
    a.saturating_add(b)
}

fn graph_step(x: &[i64]) -> Vec<i64> {
    let n = x.len();
    let mut out = vec![0i64; n];
    if n == 0 { return out; }
    for i in 0..n {
        // Ring + deterministic shortcut. Integer-only analogue of the
        // ring-plus-shortcuts small-world transition used by NEXUS V18.
        let left = x[(i + n - 1) % n];
        let right = x[(i + 1) % n];
        let shortcut = x[(i * 5 + 3) % n];
        out[i] = avg3(left, right, shortcut);
    }
    out
}

fn residual_mix(x: &[i64]) -> Vec<i64> {
    let p1 = graph_step(x);
    let p2 = graph_step(&p1);
    let p4 = graph_step(&graph_step(&p2));
    // Fixed consensus coefficients sum to 1.0 in Q16.16.
    let w0 = 22938i64; // 0.35
    let w1 = 19661i64; // 0.30
    let w2 = 13107i64; // 0.20
    let w4 = 9830i64;  // 0.15
    x.iter().enumerate().map(|(i, &v)| {
        let a = qadd_saturating(qmul(v, w0), qmul(p1[i], w1));
        let b = qadd_saturating(a, qmul(p2[i], w2));
        qadd_saturating(b, qmul(p4[i], w4))
    }).collect()
}

/// Consensus-safe reference kernel. This is the deterministic graph brick and ABI
/// for NEXUS-in-EVM, not a claim that the full PyTorch V18 checkpoint has already
/// been losslessly quantized. Production activation requires a separately frozen
/// quantized weight artifact whose root equals `manifest.model_root`.
pub fn infer_reference(
    manifest: &NexusManifest,
    gas: &PrecompileGasSchedule,
    request: &NexusRequest,
) -> Result<NexusResponse, NexusError> {
    manifest.validate()?;
    if request.mode != NexusMode::Score {
        return Err(NexusError::UnsupportedMode);
    }
    if request.input_q16.is_empty()
        || request.input_q16.len() > usize::from(manifest.max_input_values)
        || request.max_output_values == 0
        || request.max_output_values > manifest.max_output_values
    {
        return Err(NexusError::InvalidShape);
    }

    let nodes = usize::from(manifest.nodes);
    let output_len = usize::min(usize::from(request.max_output_values), nodes);
    let input_bytes = request
        .input_q16
        .len()
        .checked_mul(core::mem::size_of::<i64>())
        .ok_or(NexusError::GasOverflow)?;
    let output_bytes = output_len
        .checked_mul(core::mem::size_of::<i64>())
        .ok_or(NexusError::GasOverflow)?;
    let edges = nodes.checked_mul(3).ok_or(NexusError::GasOverflow)?;
    let gas_used = gas
        .nexus_cost(
            input_bytes,
            output_bytes,
            nodes,
            edges,
            usize::from(manifest.layers),
        )
        .ok_or(NexusError::GasOverflow)?;

    // Gas/shape feasibility is established before allocation and graph execution.
    let mut state = vec![0i64; nodes];
    for (i, v) in request.input_q16.iter().enumerate() {
        state[i % nodes] = qadd_saturating(state[i % nodes], *v);
    }

    for _ in 0..manifest.layers {
        state = residual_mix(&state);
    }

    let output = state[..output_len].to_vec();
    Ok(NexusResponse { output_q16: output, gas_used })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_v1_rejects_manifest_parameter_drift() {
        let base = NexusManifest::v18_consensus_profile([7u8; 32]);

        let mut changed = base.clone();
        changed.nodes = 17;
        assert_eq!(changed.validate(), Err(NexusError::InvalidManifest));

        let mut changed = base.clone();
        changed.layers = 4;
        assert_eq!(changed.validate(), Err(NexusError::InvalidManifest));

        let mut changed = base.clone();
        changed.max_input_values = 513;
        assert_eq!(changed.validate(), Err(NexusError::InvalidManifest));

        let mut changed = base;
        changed.source_checkpoint_sha256_hex = "00";
        assert_eq!(changed.validate(), Err(NexusError::InvalidManifest));
    }

    #[test]
    fn rejects_zero_node_manifest_without_panicking() {
        let mut m = NexusManifest::v18_consensus_profile([7u8; 32]);
        m.nodes = 0;
        let r = NexusRequest {
            mode: NexusMode::Score,
            input_q16: vec![Q],
            max_output_values: 1,
        };
        assert_eq!(
            infer_reference(&m, &PrecompileGasSchedule::default(), &r),
            Err(NexusError::InvalidManifest)
        );
    }

    #[test]
    fn profile_v1_rejects_unimplemented_nexus_modes() {
        let m = NexusManifest::v18_consensus_profile([7u8; 32]);
        for mode in [NexusMode::Policy, NexusMode::ProofAssist] {
            let r = NexusRequest {
                mode,
                input_q16: vec![Q],
                max_output_values: 1,
            };
            assert_eq!(
                infer_reference(&m, &PrecompileGasSchedule::default(), &r),
                Err(NexusError::UnsupportedMode)
            );
        }
    }

    #[test]
    fn q16_saturation_is_explicit_and_deterministic() {
        assert_eq!(qadd_saturating(i64::MAX, 1), i64::MAX);
        assert_eq!(qadd_saturating(i64::MIN, -1), i64::MIN);
        assert_eq!(qmul(i64::MAX, i64::MAX), i64::MAX);
    }

    #[test]
    fn fixed_point_inference_is_bit_exact() {
        let m = NexusManifest::v18_consensus_profile([7u8; 32]);
        let r = NexusRequest { mode: NexusMode::Score, input_q16: vec![Q, 2*Q, -Q], max_output_values: 8 };
        let a = infer_reference(&m, &PrecompileGasSchedule::default(), &r).unwrap();
        let b = infer_reference(&m, &PrecompileGasSchedule::default(), &r).unwrap();
        assert_eq!(a, b);
    }
}
