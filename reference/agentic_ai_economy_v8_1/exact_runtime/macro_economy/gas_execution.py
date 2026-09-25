from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

D = Decimal


@dataclass(frozen=True)
class GasExecutionConfig:
    min_interval_blocks: int = 6
    safety_multiple: Decimal = D('1.50')
    base_gas_units: int = 90_000
    gas_units_per_leg: int = 33_000
    base_fee_wei: Decimal = D('5000000')
    l1_data_factor: Decimal = D('1.30')
    min_notional_usdc: Decimal = D('0.15')


@dataclass(frozen=True)
class GasExecutionDecision:
    execute: bool
    gas_cost_usdc: Decimal
    required_benefit_usdc: Decimal
    risk_benefit_usdc: Decimal
    reason: str


class GasAwareHedgeExecutor:
    """Cost-aware batch execution gate for multi-asset hedge updates.

    All active hedge legs are treated as one batched transaction.  The gate
    refuses execution until the minimum interval has elapsed and the estimated
    risk reduction exceeds gas plus a configurable safety margin.
    """

    def __init__(self, config: GasExecutionConfig | None = None) -> None:
        self.config = config or GasExecutionConfig()
        self.last_execution_block = -10**9
        self.executions = 0
        self.skipped = 0

    def estimate_batch_gas_usd(self, *, weth_price: Decimal, active_legs: int) -> Decimal:
        legs = max(0, int(active_legs))
        if legs == 0:
            return D('0')
        gas_units = self.config.base_gas_units + self.config.gas_units_per_leg * legs
        eth = D(gas_units) * self.config.base_fee_wei / D(10**18)
        return eth * D(weth_price) * self.config.l1_data_factor

    def decide(
        self,
        *,
        block: int,
        desired_notional_change: Decimal,
        risk_benefit_usdc: Decimal,
        weth_price: Decimal,
        active_legs: int,
        execution_fee_usdc: Decimal = D('0'),
    ) -> GasExecutionDecision:
        notional = abs(D(desired_notional_change))
        benefit = max(D('0'), D(risk_benefit_usdc))
        gas = self.estimate_batch_gas_usd(weth_price=D(weth_price), active_legs=active_legs)
        required = (gas + max(D('0'), D(execution_fee_usdc))) * self.config.safety_multiple
        if active_legs <= 0 or notional < self.config.min_notional_usdc:
            self.skipped += 1
            return GasExecutionDecision(False, gas, required, benefit, 'notional-band')
        if block - self.last_execution_block < self.config.min_interval_blocks:
            self.skipped += 1
            return GasExecutionDecision(False, gas, required, benefit, 'cadence')
        if benefit <= required:
            self.skipped += 1
            return GasExecutionDecision(False, gas, required, benefit, 'economics')
        return GasExecutionDecision(True, gas, required, benefit, 'execute')

    def mark_executed(self, block: int) -> None:
        self.last_execution_block = int(block)
        self.executions += 1
