from __future__ import annotations

from dataclasses import dataclass
import random

from .models import AgentState


@dataclass(frozen=True)
class PolicyExperiment:
    experiment_id: str
    researcher_id: str
    domain: str
    tick: int
    parameters: dict[str, float]
    scenario_metrics: dict[str, dict[str, float]]
    confidence: float
    notes: str


class PolicyLab:
    """Neutral protocol/economic-policy scenario laboratory.

    It explores system rules such as credit rates, reserves and marketplace
    fees. It intentionally does not model political parties, candidates or
    persuasion targets.
    """

    DOMAINS = ("credit", "fees", "liquidity", "labor_market", "treasury")

    def __init__(self, *, seed: int = 0) -> None:
        self._rng = random.Random(seed)
        self._next_id = 1
        self.reports: list[PolicyExperiment] = []

    def run_experiment(
        self,
        researcher: AgentState,
        *,
        tick: int,
        system_metrics: dict[str, float] | None = None,
    ) -> PolicyExperiment:
        metrics = dict(system_metrics or {})
        default_rate = max(0.0, min(1.0, float(metrics.get("default_rate", 0.05))))
        liquidity = max(0.0, min(1.0, float(metrics.get("liquidity", 0.65))))
        throughput = max(0.0, float(metrics.get("job_throughput", 1.0)))
        founder_yield = max(0.0, float(metrics.get("founder_yield", 0.02)))
        domains = list(self.DOMAINS)
        # Researchers with strong economics/research skill lean toward credit and
        # liquidity, while still exploring every protocol domain over time.
        if researcher.skill("economics") + researcher.skill("research") > 1.2:
            domains.extend(["credit", "liquidity"])
        domain = self._rng.choice(domains)
        shock = self._rng.uniform(-0.20, 0.20)

        baseline = {
            "default_rate": default_rate,
            "liquidity": liquidity,
            "job_throughput": throughput,
            "founder_yield": founder_yield,
        }
        alternative = dict(baseline)
        params: dict[str, float]

        if domain == "credit":
            rate_change = shock * 0.08
            params = {"base_rate_change": rate_change}
            alternative["default_rate"] = max(0.0, default_rate * (1.0 - rate_change * 2.0))
            alternative["job_throughput"] = max(0.0, throughput * (1.0 - max(rate_change, 0.0)))
        elif domain == "fees":
            fee_change = shock * 0.03
            params = {"marketplace_fee_change": fee_change}
            alternative["founder_yield"] = max(0.0, founder_yield + fee_change * 0.45)
            alternative["job_throughput"] = max(0.0, throughput * (1.0 - max(fee_change, 0.0) * 2.0))
        elif domain == "liquidity":
            reserve_change = shock * 0.25
            params = {"reserve_target_change": reserve_change}
            alternative["liquidity"] = max(0.0, min(1.0, liquidity + reserve_change))
            alternative["default_rate"] = max(0.0, default_rate * (1.0 - reserve_change * 0.7))
        elif domain == "labor_market":
            matching_change = shock * 0.20
            params = {"matching_selectivity_change": matching_change}
            alternative["job_throughput"] = max(0.0, throughput * (1.0 + matching_change * 0.5))
        else:
            reinvest_change = shock * 0.30
            params = {"treasury_reinvestment_change": reinvest_change}
            alternative["liquidity"] = max(0.0, min(1.0, liquidity + reinvest_change * 0.2))
            alternative["founder_yield"] = max(0.0, founder_yield + reinvest_change * 0.05)

        expertise = 0.5 * researcher.skill("research") + 0.3 * researcher.skill("economics") + 0.2 * researcher.reputation
        confidence = max(0.05, min(0.98, 0.35 + 0.55 * expertise))
        report = PolicyExperiment(
            experiment_id=f"policy:{self._next_id}",
            researcher_id=researcher.agent_id,
            domain=domain,
            tick=tick,
            parameters=params,
            scenario_metrics={"baseline": baseline, "alternative": alternative},
            confidence=confidence,
            notes=(
                "Neutral protocol-policy scenario analysis. Results describe simulated economic trade-offs "
                "and are not political advocacy or a recommendation about real-world political actors."
            ),
        )
        self._next_id += 1
        self.reports.append(report)
        researcher.memory.research_reports += 1
        return report
