from __future__ import annotations

from decimal import Decimal

from .engine import AgentEconomy, EconomyConfig, EconomyReport


def run_default_scenario(config: EconomyConfig | None = None) -> EconomyReport:
    """Run the default deterministic SYNERGY Agent Economy scenario."""
    return AgentEconomy(config or EconomyConfig()).run()


def stress_credit_config(*, seed: int = 3) -> EconomyConfig:
    """Credit-stress preset with thin initial liquidity and frequent finance.

    This profile is intentionally harsh: it is used to verify that real losses
    and defaults appear instead of being patched by synthetic balance creation.
    """
    return EconomyConfig(
        agent_count=12,
        steps=120,
        seed=seed,
        initial_cash=Decimal("8"),
        external_job_every=8,
        credit_every=2,
        deposit_every=3,
        investment_every=7,
        company_revenue_every=15,
        policy_research_every=4,
        subcontract_every=2,
    )


def internal_finance_config(*, seed: int = 5) -> EconomyConfig:
    """Preset with external revenue switched effectively off.

    Useful for demonstrating that loans, deposits and investments cannot be
    misclassified as new system profit.
    """
    return EconomyConfig(
        agent_count=10,
        steps=35,
        seed=seed,
        initial_cash=Decimal("25"),
        external_job_every=10_000,
        company_revenue_every=10_000,
        credit_every=3,
        deposit_every=4,
        investment_every=5,
        policy_research_every=6,
        subcontract_every=2,
    )
