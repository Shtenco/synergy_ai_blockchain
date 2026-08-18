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
    InvalidShape,
    GasOverflow,
}

fn qmul(a: i64, b: i64) -> i64 {
    let p = (a as i128) * (b as i128);
    let shifted = p >> 16;
    shifted.clamp(i64::MIN as i128, i64::MAX as i128) as i64
}

fn avg3(a: i64, b: i64, c: i64) -> i64 {
    ((a as i128 + b as i128 + c as i128) / 3) as i64
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
        qmul(v, w0)
            .saturating_add(qmul(p1[i], w1))
            .saturating_add(qmul(p2[i], w2))
            .saturating_add(qmul(p4[i], w4))
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
    if request.input_q16.is_empty()
        || request.input_q16.len() > manifest.max_input_values as usize
        || request.max_output_values == 0
        || request.max_output_values > manifest.max_output_values
    {
        return Err(NexusError::InvalidShape);
    }

    let nodes = manifest.nodes as usize;
    let mut state = vec![0i64; nodes];
    for (i, v) in request.input_q16.iter().enumerate() {
        state[i % nodes] = state[i % nodes].saturating_add(*v);
    }

    for _ in 0..manifest.layers {
        state = residual_mix(&state);
    }

    let output_len = usize::min(request.max_output_values as usize, state.len());
    let output = state[..output_len].to_vec();
    let input_bytes = request.input_q16.len() * 8;
    let output_bytes = output.len() * 8;
    let edges = nodes * 3;
    let gas_used = gas
        .nexus_cost(input_bytes, output_bytes, nodes, edges, manifest.layers as usize)
        .ok_or(NexusError::GasOverflow)?;

    Ok(NexusResponse { output_q16: output, gas_used })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_point_inference_is_bit_exact() {
        let m = NexusManifest::v18_consensus_profile([7u8; 32]);
        let r = NexusRequest { mode: NexusMode::Score, input_q16: vec![Q, 2*Q, -Q], max_output_values: 8 };
        let a = infer_reference(&m, &PrecompileGasSchedule::default(), &r).unwrap();
        let b = infer_reference(&m, &PrecompileGasSchedule::default(), &r).unwrap();
        assert_eq!(a, b);
    }
}
