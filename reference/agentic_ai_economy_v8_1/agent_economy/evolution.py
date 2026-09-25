from __future__ import annotations

from decimal import Decimal

from .models import AgentState


class EvolutionEngine:
    """Outcome-driven adaptation of mutable strategy on top of fixed genome."""

    def adapt(self, agent: AgentState, *, wealth_change: Decimal) -> int:
        s = agent.strategy
        if s is None:
            raise RuntimeError("agent strategy was not initialized")
        before = (
            s.exploration_rate,
            s.lending_appetite,
            s.hiring_appetite,
            s.research_intensity,
            s.risk_budget,
        )

        if wealth_change > 0:
            s.exploration_rate += 0.01
        elif wealth_change < 0:
            s.exploration_rate -= 0.02
            s.risk_budget -= 0.03

        # Defaults teach deleveraging much more strongly than short-term profit
        # encourages risk-taking.
        if agent.memory.loan_defaults:
            penalty = min(0.35, 0.08 * agent.memory.loan_defaults)
            s.risk_budget -= penalty
            s.lending_appetite -= penalty * 0.4
        if agent.memory.deposit_defaults:
            s.lending_appetite -= min(0.25, 0.07 * agent.memory.deposit_defaults)

        job_edge = agent.memory.jobs_completed - agent.memory.jobs_failed
        if job_edge > 0:
            s.hiring_appetite += min(0.12, 0.01 * job_edge)
        elif job_edge < 0:
            s.hiring_appetite -= min(0.12, 0.02 * abs(job_edge))

        if agent.memory.research_reports:
            s.research_intensity += min(0.08, 0.005 * agent.memory.research_reports)

        if agent.memory.loans_repaid > agent.memory.loan_defaults:
            s.lending_appetite += 0.01

        s.clamp()
        after = (
            s.exploration_rate,
            s.lending_appetite,
            s.hiring_appetite,
            s.research_intensity,
            s.risk_budget,
        )
        return sum(1 for a, b in zip(before, after) if a != b)
