from __future__ import annotations

from dataclasses import asdict, dataclass, field
from decimal import Decimal
from typing import Any

from .dual_contour_engine import DualContourConfig, DualContourEconomy
from .engine import q
from .banking_risk import BankingMetrics, BankingRiskEngine, CollateralTier
from .gas_execution import GasAwareHedgeExecutor, GasExecutionConfig

D = Decimal
Q = D('0.000000000001')
YEAR_SECONDS = D(365 * 24 * 60 * 60)


def clamp(x: Decimal, lo: Decimal, hi: Decimal) -> Decimal:
    return max(lo, min(hi, D(x)))


@dataclass(frozen=True)
class StabilityPolicy:
    regime: str
    fund_fraction: Decimal
    hedge_ratio: Decimal
    credit_multiplier: Decimal
    recursive_growth_multiplier: Decimal


class StabilityFund:
    """Risk-budget overlay controlling 35–80% of system wealth.

    Allocated capital is a designation of existing wealth, not newly created NAV.
    Protected wealth is a monotone bookkeeping ratchet and cannot exceed world
    wealth. Hedge PnL is real external derivative PnL and is tracked separately.
    """

    def __init__(
        self,
        *,
        opening_world_wealth: Decimal,
        initial_fraction: Decimal = D('0.50'),
        floor_buffer_fraction: Decimal = D('0.0015'),
        protected_fraction_of_fund: Decimal = D('0.60'),
        profit_lock_fraction: Decimal = D('0.70'),
    ) -> None:
        wealth = D(opening_world_wealth)
        fraction = D(initial_fraction)
        if wealth <= 0 or not D('0.35') <= fraction <= D('0.80'):
            raise ValueError('invalid stability-fund configuration')
        self.opening_world_wealth = wealth
        self.target_fraction = fraction
        self.allocated_capital = q(wealth * fraction)
        self.world_wealth_effect = D('0')
        self.floor_buffer_fraction = D(floor_buffer_fraction)
        self.profit_lock_fraction = D(profit_lock_fraction)
        self.high_water_mark = wealth
        self.protected_wealth = q(self.allocated_capital * D(protected_fraction_of_fund))

    @property
    def wealth_floor(self) -> Decimal:
        return q(self.high_water_mark * (D('1') - self.floor_buffer_fraction))

    def observe_wealth(self, wealth: Decimal) -> None:
        wealth = D(wealth)
        if wealth > self.high_water_mark:
            gain = wealth - self.high_water_mark
            self.high_water_mark = wealth
            self.protected_wealth = q(min(wealth, self.protected_wealth + gain * self.profit_lock_fraction))

    def policy_for(self, *, wealth: Decimal, volatility: Decimal, ccr: Decimal, lcr: Decimal) -> StabilityPolicy:
        wealth = D(wealth)
        vol = max(D('0'), D(volatility))
        ccr, lcr = D(ccr), D(lcr)
        dd = max(D('0'), (self.high_water_mark - wealth) / max(D('1'), self.high_water_mark))

        if dd >= D('0.0015') or vol >= D('0.075') or ccr < D('0.90') or lcr < D('0.75'):
            regime = 'RED'
            frac, hedge, credit, recursive = D('0.80'), D('1.05'), D('0.10'), D('0.15')
        elif dd >= D('0.0008') or vol >= D('0.045') or ccr < D('1.10') or lcr < D('0.95'):
            regime = 'ORANGE'
            frac, hedge, credit, recursive = D('0.70'), D('1.01'), D('0.35'), D('0.40')
        elif dd >= D('0.0003') or vol >= D('0.025') or ccr < D('1.35') or lcr < D('1.15'):
            regime = 'YELLOW'
            frac, hedge, credit, recursive = D('0.60'), D('0.98'), D('0.60'), D('0.70')
        else:
            regime = 'GREEN'
            frac, hedge, credit, recursive = D('0.50'), D('0.94'), D('0.85'), D('1.00')
        self.target_fraction = frac
        return StabilityPolicy(regime, frac, hedge, credit, recursive)


@dataclass(frozen=True)
class StabilityConfig(DualContourConfig):
    enable_stability_fund: bool = True
    stability_initial_fraction: Decimal = D('0.50')
    wealth_floor_buffer_fraction: Decimal = D('0.0015')
    hedge_execution_fee_bps: Decimal = D('1.5')
    hedge_funding_apr: Decimal = D('0.03')
    max_hedge_leverage_on_fund: Decimal = D('1.0')
    recursive_claim_growth_per_block: Decimal = D('0.0015')
    max_internal_claims_multiple_of_hard_nav: Decimal = D('1.75')
    enable_gas_aware_execution: bool = False
    gas_min_interval_blocks: int = 6
    gas_safety_multiple: Decimal = D('1.50')
    gas_base_units: int = 90000
    gas_units_per_leg: int = 33000
    gas_base_fee_wei: Decimal = D('5000000')
    gas_l1_factor: Decimal = D('1.30')
    gas_min_notional_usdc: Decimal = D('0.15')
    gas_risk_benefit_multiplier: Decimal = D('3.0')


@dataclass(frozen=True)
class StabilityReport:
    v8_enabled: bool
    blocks: int
    block_seconds: int
    elapsed_seconds: int
    opening_system_real_wealth: Decimal
    closing_system_real_wealth: Decimal
    v5_closing_system_real_wealth: Decimal
    net_external_capital_flow: Decimal
    capital_adjusted_closing_wealth: Decimal
    closing_hodl_benchmark: Decimal
    system_alpha_vs_hodl: Decimal
    max_adjusted_drawdown_pct: Decimal
    stability_fund_initial_allocation: Decimal
    stability_fund_nav_end: Decimal
    protected_wealth_end: Decimal
    high_water_mark_end: Decimal
    wealth_floor_end: Decimal
    floor_breaches: int
    minimum_floor_buffer_pct: Decimal
    stability_hedge_pnl: Decimal
    stability_hedge_fees: Decimal
    stability_hedge_funding_cost: Decimal
    hedge_gas_cost_usdc: Decimal
    hedge_batch_executions: int
    hedge_execution_skips: int
    protection_drag_vs_unhedged: Decimal
    hedge_turnover_usdc: Decimal
    average_hedge_ratio: Decimal
    regime_counts: dict[str, int]
    gross_tvl_end: Decimal
    collateral_nav_end: Decimal
    economic_net_worth_end: Decimal
    internal_claims_end: Decimal
    ccr_end: Decimal
    lcr_end: Decimal
    allowed_rehypothecation_depth_end: int
    snapshots: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        def cv(v: Any) -> Any:
            if isinstance(v, Decimal):
                return str(v)
            if isinstance(v, dict):
                return {str(k): cv(x) for k, x in v.items()}
            if isinstance(v, list):
                return [cv(x) for x in v]
            return v
        return cv(asdict(self))


class StabilityEconomyV8(DualContourEconomy):
    """v8 global stability fund layered over the verified v5 engine.

    The hedge is an external short-delta overlay. It can reduce drawdown, but it
    gives up upside and pays fees/funding. Internal recursive claims affect TVL
    and banking ratios but never Economic Net Worth.
    """

    def __init__(self, config: StabilityConfig | None = None) -> None:
        self.stability_config = config or StabilityConfig()
        super().__init__(self.stability_config)
        self.bank = BankingRiskEngine()
        self.fund = StabilityFund(
            opening_world_wealth=self.opening_system_real_wealth,
            initial_fraction=self.stability_config.stability_initial_fraction,
            floor_buffer_fraction=self.stability_config.wealth_floor_buffer_fraction,
        )
        self.hedge_qty: dict[str, Decimal] = {s: D('0') for s in self.base_symbols}
        self.hedge_pnl = D('0')
        self.hedge_fees = D('0')
        self.hedge_funding = D('0')
        self.hedge_turnover = D('0')
        self.internal_claims = D('0')
        self.floor_breaches = 0
        self.min_floor_buffer_pct = D('999')
        self.regime_counts = {'GREEN': 0, 'YELLOW': 0, 'ORANGE': 0, 'RED': 0}
        self.hedge_ratio_sum = D('0')
        self.hedge_ratio_count = 0
        self.v8_snapshots: list[dict[str, Any]] = []
        self.hedge_gas_cost = D('0')
        self.gas_executor = GasAwareHedgeExecutor(GasExecutionConfig(
            min_interval_blocks=self.stability_config.gas_min_interval_blocks,
            safety_multiple=self.stability_config.gas_safety_multiple,
            base_gas_units=self.stability_config.gas_base_units,
            gas_units_per_leg=self.stability_config.gas_units_per_leg,
            base_fee_wei=self.stability_config.gas_base_fee_wei,
            l1_data_factor=self.stability_config.gas_l1_factor,
            min_notional_usdc=self.stability_config.gas_min_notional_usdc * self.stability_config.capital_scale,
        ))
        self.last_banking_metrics = self._banking_metrics(1)
        if self.stability_config.enable_stability_fund:
            policy = self.fund.policy_for(
                wealth=self.opening_system_real_wealth,
                volatility=D('0'), ccr=self.last_banking_metrics.ccr, lcr=self.last_banking_metrics.lcr,
            )
            self._rebalance_hedge(policy, block=0, charge_fee=False)

    def _current_base_quantities(self) -> dict[str, Decimal]:
        qty: dict[str, Decimal] = {s: D('0') for s in self.base_symbols}
        for symbol, pool in self.core.markets.pools.items():
            qty[symbol] += pool.reserve_a + self.core.markets.treasury_assets.get(symbol, D('0'))
        for agent in self.core.agents:
            for symbol, amount in agent.holdings.items():
                if symbol in qty:
                    qty[symbol] += amount
        for company in self.core.capital.securities.companies.values():
            for symbol, amount in company.holdings.items():
                if symbol in qty:
                    qty[symbol] += amount
        for symbol, amount in self.core.capital.credit.seized_assets.items():
            if symbol in qty:
                qty[symbol] += amount
        for symbol, amount in self.bridge.real_balances.items():
            if symbol in qty:
                qty[symbol] += amount
        return qty

    def _liquid_assets(self) -> Decimal:
        total = self.bridge.real_balances.get('USDC', D('0'))
        total += self.core.markets.treasury_usdc
        total += self.core.capital.credit.reserve_usdc
        total += max(D('0'), self.core.triangle.treasury_usdc - self.core.triangle.reserve_floor_usdc)
        return q(total)

    def _avg_volatility(self) -> Decimal:
        if not self.volatility:
            return D('0')
        return q(sum(self.volatility.values(), D('0')) / D(len(self.volatility)))

    def _banking_metrics(self, block: int) -> BankingMetrics:
        hard = super().system_real_wealth()
        leverage = max(D('1'), self._synthetic_leverage())
        vol = self._avg_volatility()
        secured = self.internal_claims + self.core.capital.portfolio_debt(block)
        liquid = self._liquid_assets()
        liquidity_stress = clamp(D('0.8') - liquid / max(D('1'), hard) * D('4'), D('0'), D('1'))
        return self.bank.metrics(
            hard_nav=hard,
            liquid_assets=liquid,
            secured_liabilities=secured,
            internal_claims=self.internal_claims,
            volatility=vol,
            leverage=leverage,
            liquidity_stress=liquidity_stress,
        )

    def _settle_existing_hedge(self, old_prices: dict[str, Decimal], new_prices: dict[str, Decimal]) -> None:
        if not self.stability_config.enable_stability_fund:
            return
        pnl = D('0')
        funding = D('0')
        for symbol, short_qty in self.hedge_qty.items():
            p0 = D(old_prices[symbol])
            p1 = D(new_prices[symbol])
            pnl += short_qty * (p0 - p1)
            notional = abs(short_qty) * p0
            funding += notional * self.stability_config.hedge_funding_apr * D(self.config.block_seconds) / YEAR_SECONDS
        self.hedge_pnl += pnl
        self.hedge_funding += funding

    def _v8_real_wealth(self) -> Decimal:
        return q(super().system_real_wealth() + self.hedge_pnl - self.hedge_fees - self.hedge_funding - self.hedge_gas_cost)

    def _v8_adjusted_wealth(self) -> Decimal:
        return q(self._v8_real_wealth() - self.core.net_external_capital_flow)

    def _rebalance_hedge(self, policy: StabilityPolicy, *, block: int, charge_fee: bool = True) -> None:
        if not self.stability_config.enable_stability_fund:
            return
        qty = self._current_base_quantities()
        target: dict[str, Decimal] = {s: qty[s] * policy.hedge_ratio for s in self.base_symbols}
        total_notional = sum((target[s] * self.core.prices[s] for s in self.base_symbols), D('0'))
        fund_budget = self._v8_real_wealth() * policy.fund_fraction * self.stability_config.max_hedge_leverage_on_fund
        scale = min(D('1'), fund_budget / total_notional) if total_notional > 0 else D('0')
        desired: dict[str, Decimal] = {s: target[s] * scale for s in self.base_symbols}
        deltas: dict[str, Decimal] = {s: desired[s] - self.hedge_qty[s] for s in self.base_symbols}
        notionals = {s: abs(deltas[s]) * self.core.prices[s] for s in self.base_symbols}
        active = [s for s in self.base_symbols if notionals[s] > D('0.000000001')]
        total_change = sum((notionals[s] for s in active), D('0'))
        fee_rate = self.stability_config.hedge_execution_fee_bps / D('10000')
        expected_fee = total_change * fee_rate if charge_fee else D('0')

        if charge_fee and self.stability_config.enable_gas_aware_execution and active:
            # Observed per-block volatility plus proximity to the wealth floor proxy
            # the expected value of reducing hedge error over the next cadence window.
            avg_vol = max(self._avg_volatility(), D('0.00005'))
            adjusted = self._v8_adjusted_wealth()
            floor_gap = max(D('0'), adjusted - self.fund.wealth_floor) / max(D('1'), adjusted)
            urgency = D('1') + max(D('0'), D('0.0015') - floor_gap) * D('250')
            risk_benefit = total_change * avg_vol * self.stability_config.gas_risk_benefit_multiplier * urgency
            weth = self.core.prices.get('WETH', D('2500'))
            decision = self.gas_executor.decide(
                block=block,
                desired_notional_change=total_change,
                risk_benefit_usdc=risk_benefit,
                weth_price=weth,
                active_legs=len(active),
                execution_fee_usdc=expected_fee,
            )
            if not decision.execute:
                self.hedge_ratio_sum += policy.hedge_ratio * scale
                self.hedge_ratio_count += 1
                return
            self.hedge_gas_cost += decision.gas_cost_usdc
            self.gas_executor.mark_executed(block)

        for s in active:
            delta = deltas[s]
            traded = notionals[s]
            self.hedge_turnover += traded
            if charge_fee:
                self.hedge_fees += traded * fee_rate
            self.hedge_qty[s] = desired[s]
        self.hedge_ratio_sum += policy.hedge_ratio * scale
        self.hedge_ratio_count += 1

    def _update_recursive_claims(self, metrics: BankingMetrics, policy: StabilityPolicy) -> None:
        if not self.stability_config.enable_stability_fund:
            self.internal_claims = D('0')
            return
        hard = super().system_real_wealth()
        cap = hard * self.stability_config.max_internal_claims_multiple_of_hard_nav
        if metrics.allowed_depth <= 1 or policy.regime == 'RED':
            self.internal_claims *= D('0.985')
        else:
            issue = hard * self.stability_config.recursive_claim_growth_per_block * D(metrics.allowed_depth) / D('4')
            issue *= policy.recursive_growth_multiplier
            self.internal_claims = min(cap, self.internal_claims + issue)
        self.internal_claims = q(max(D('0'), self.internal_claims))

    def _v8_snapshot(self, block: int, base_snap: dict[str, Any], metrics: BankingMetrics, policy: StabilityPolicy) -> dict[str, Any]:
        real = self._v8_real_wealth()
        adjusted = self._v8_adjusted_wealth()
        self.fund.observe_wealth(adjusted)
        floor = self.fund.wealth_floor
        if adjusted < floor:
            self.floor_breaches += 1
        floor_buffer_pct = (adjusted - floor) / max(D('1'), self.fund.high_water_mark) * D('100')
        self.min_floor_buffer_pct = min(self.min_floor_buffer_pct, floor_buffer_pct)
        fund_nav = q(self.fund.allocated_capital + self.hedge_pnl - self.hedge_fees - self.hedge_funding - self.hedge_gas_cost)
        snap = dict(base_snap)
        snap.update({
            'system_real_wealth': float(real),
            'capital_adjusted_wealth': float(adjusted),
            'economic_net_worth': float(adjusted),
            'unhedged_capital_adjusted_wealth': float(q(super().system_real_wealth() - self.core.net_external_capital_flow)),
            'alpha_vs_hodl': float(q(adjusted - self.hodl_benchmark())),
            'stability_fund_nav': float(fund_nav),
            'stability_fund_fraction': float(policy.fund_fraction),
            'protected_wealth': float(self.fund.protected_wealth),
            'risk_capital': float(max(D('0'), adjusted - self.fund.protected_wealth)),
            'high_water_mark': float(self.fund.high_water_mark),
            'wealth_floor': float(floor),
            'floor_buffer_pct': float(q(floor_buffer_pct)),
            'risk_regime': policy.regime,
            'target_hedge_ratio': float(policy.hedge_ratio),
            'hedge_pnl': float(q(self.hedge_pnl)),
            'hedge_fees': float(q(self.hedge_fees)),
            'hedge_funding_cost': float(q(self.hedge_funding)),
            'hedge_gas_cost': float(q(self.hedge_gas_cost)),
            'hedge_batch_executions': self.gas_executor.executions,
            'hedge_execution_skips': self.gas_executor.skipped,
            'hedge_turnover': float(q(self.hedge_turnover)),
            'internal_claims': float(q(self.internal_claims)),
            'gross_tvl': float(metrics.gross_tvl),
            'collateral_nav': float(metrics.collateral_nav),
            'ccr': float(metrics.ccr),
            'lcr': float(metrics.lcr),
            'allowed_rehypothecation_depth': metrics.allowed_depth,
            'tier_haircuts': {f'T{int(k)}': float(v) for k, v in metrics.haircuts.items()},
        })
        return snap

    def run(self) -> StabilityReport:
        peak_adjusted = self.opening_system_real_wealth
        max_drawdown = D('0')
        for block in range(1, self.config.blocks + 1):
            old_prices = dict(self.core.prices)
            self.core.prev_prices = dict(self.core.prices)
            stepped = self.core.reference.step()
            self.core.prices = {s: D(str(p)) for s, p in stepped.items()}
            self._settle_existing_hedge(old_prices, self.core.prices)

            self.core._outside_base_flows()
            self.core._outside_triangle_flow()
            for agent in self.core.agents:
                self.core._agent_base_action(agent)
            self.core._agent_triangle_action()
            self.core.capital.step(block=block, prices=self.core.prices, prev_prices=self.core.prev_prices)
            self.core._controller()

            self._shadow_noise_flow()
            if self.config.enable_external_delta_control:
                self._external_delta_control()
            else:
                for symbol in self.base_symbols:
                    self._state(symbol, self.core.prices[symbol], self.core.prev_prices[symbol])
            if self.config.enable_shadow_mm:
                self._stabilize_shadow()
            else:
                self._record_uncontrolled_spread_errors()
            self._enforce_synthetic_capacity()
            self._seal_chain_block(block)

            metrics_pre = self._banking_metrics(block)
            wealth_pre = self._v8_adjusted_wealth()
            policy = self.fund.policy_for(
                wealth=wealth_pre,
                volatility=self._avg_volatility(),
                ccr=metrics_pre.ccr,
                lcr=metrics_pre.lcr,
            ) if self.stability_config.enable_stability_fund else StabilityPolicy('OFF', D('0'), D('0'), D('1'), D('0'))
            if policy.regime in self.regime_counts:
                self.regime_counts[policy.regime] += 1
            self._update_recursive_claims(metrics_pre, policy)
            metrics = self._banking_metrics(block)
            self.last_banking_metrics = metrics
            self._rebalance_hedge(policy, block=block)

            base_snap = super()._snapshot(block)
            snap = self._v8_snapshot(block, base_snap, metrics, policy)
            self.v8_snapshots.append(snap)
            adjusted = D(str(snap['capital_adjusted_wealth']))
            peak_adjusted = max(peak_adjusted, adjusted)
            if peak_adjusted > 0:
                max_drawdown = max(max_drawdown, (peak_adjusted - adjusted) / peak_adjusted * D('100'))

        closing = self._v8_real_wealth()
        unhedged_closing = super().system_real_wealth()
        adjusted = self._v8_adjusted_wealth()
        unhedged_adjusted = q(unhedged_closing - self.core.net_external_capital_flow)
        hodl = self.hodl_benchmark()
        m = self.last_banking_metrics
        avg_hedge = self.hedge_ratio_sum / D(self.hedge_ratio_count) if self.hedge_ratio_count else D('0')
        protection_drag = q(unhedged_adjusted - adjusted)
        fund_nav = q(self.fund.allocated_capital + self.hedge_pnl - self.hedge_fees - self.hedge_funding - self.hedge_gas_cost)
        min_buf = self.min_floor_buffer_pct if self.min_floor_buffer_pct != D('999') else D('0')
        return StabilityReport(
            v8_enabled=self.stability_config.enable_stability_fund,
            blocks=self.config.blocks,
            block_seconds=self.config.block_seconds,
            elapsed_seconds=self.config.blocks * self.config.block_seconds,
            opening_system_real_wealth=q(self.opening_system_real_wealth),
            closing_system_real_wealth=q(closing),
            v5_closing_system_real_wealth=q(unhedged_closing),
            net_external_capital_flow=q(self.core.net_external_capital_flow),
            capital_adjusted_closing_wealth=adjusted,
            closing_hodl_benchmark=q(hodl),
            system_alpha_vs_hodl=q(adjusted - hodl),
            max_adjusted_drawdown_pct=q(max_drawdown),
            stability_fund_initial_allocation=q(self.fund.allocated_capital),
            stability_fund_nav_end=fund_nav,
            protected_wealth_end=q(self.fund.protected_wealth),
            high_water_mark_end=q(self.fund.high_water_mark),
            wealth_floor_end=q(self.fund.wealth_floor),
            floor_breaches=self.floor_breaches,
            minimum_floor_buffer_pct=q(min_buf),
            stability_hedge_pnl=q(self.hedge_pnl),
            stability_hedge_fees=q(self.hedge_fees),
            stability_hedge_funding_cost=q(self.hedge_funding),
            hedge_gas_cost_usdc=q(self.hedge_gas_cost),
            hedge_batch_executions=self.gas_executor.executions,
            hedge_execution_skips=self.gas_executor.skipped,
            protection_drag_vs_unhedged=protection_drag,
            hedge_turnover_usdc=q(self.hedge_turnover),
            average_hedge_ratio=q(avg_hedge),
            regime_counts=dict(self.regime_counts),
            gross_tvl_end=q(m.gross_tvl),
            collateral_nav_end=q(m.collateral_nav),
            economic_net_worth_end=q(adjusted),
            internal_claims_end=q(self.internal_claims),
            ccr_end=q(m.ccr),
            lcr_end=q(m.lcr),
            allowed_rehypothecation_depth_end=m.allowed_depth,
            snapshots=self.v8_snapshots,
        )
