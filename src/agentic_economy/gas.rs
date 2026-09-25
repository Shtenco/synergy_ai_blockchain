use super::constants::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GasDecision {
    pub execute: bool,
    pub gas_cost_micro_usdc: i128,
    pub required_benefit_micro_usdc: i128,
}

pub fn decide_gas_aware_execution(
    block_height: u64,
    last_execution_block: u64,
    desired_notional_micro: i128,
    benefit_micro: i128,
    weth_price_micro: i128,
    active_legs: u64,
) -> GasDecision {
    if active_legs == 0 || desired_notional_micro.abs() < GAS_MIN_NOTIONAL_MICRO {
        return GasDecision {
            execute: false,
            gas_cost_micro_usdc: 0,
            required_benefit_micro_usdc: 0,
        };
    }
    if block_height.saturating_sub(last_execution_block) < GAS_MIN_INTERVAL_BLOCKS {
        return GasDecision {
            execute: false,
            gas_cost_micro_usdc: 0,
            required_benefit_micro_usdc: 0,
        };
    }
    let units = GAS_BASE_UNITS.saturating_add(GAS_UNITS_PER_LEG.saturating_mul(active_legs));
    let gas = (units as i128)
        .saturating_mul(GAS_BASE_FEE_WEI as i128)
        .saturating_mul(weth_price_micro)
        .saturating_mul(GAS_L1_FACTOR_PPM as i128)
        / 1_000_000
        / 1_000_000_000_000_000_000i128;
    let required = gas.saturating_mul(GAS_SAFETY_PPM as i128) / 1_000_000;
    GasDecision {
        execute: benefit_micro > required,
        gas_cost_micro_usdc: gas,
        required_benefit_micro_usdc: required,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cadence_and_economic_gate_match_reference_policy() {
        let x = decide_gas_aware_execution(1, 0, 1_000_000, 1_000_000, 3_000_000_000, 2);
        assert!(!x.execute);
        let y = decide_gas_aware_execution(10, 0, 1_000_000, 1_000_000, 3_000_000_000, 2);
        assert!(y.execute);
    }
}
