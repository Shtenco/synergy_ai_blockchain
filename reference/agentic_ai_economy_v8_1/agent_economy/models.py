from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from typing import Iterable


def _unit(name: str, value: float) -> float:
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"{name} must be in [0, 1], got {value}")
    return float(value)


@dataclass(frozen=True)
class AgentGenome:
    risk: float = 0.5
    curiosity: float = 0.5
    policy_curiosity: float = 0.5
    entrepreneurship: float = 0.5
    trust: float = 0.5
    patience: float = 0.5
    leverage_tolerance: float = 0.5
    liquidity_preference: float = 0.5

    def __post_init__(self) -> None:
        for field_name in (
            "risk",
            "curiosity",
            "policy_curiosity",
            "entrepreneurship",
            "trust",
            "patience",
            "leverage_tolerance",
            "liquidity_preference",
        ):
            object.__setattr__(self, field_name, _unit(field_name, getattr(self, field_name)))


@dataclass
class AdaptiveStrategy:
    exploration_rate: float
    lending_appetite: float
    hiring_appetite: float
    research_intensity: float
    risk_budget: float

    @classmethod
    def from_genome(cls, genome: AgentGenome) -> "AdaptiveStrategy":
        return cls(
            exploration_rate=(genome.curiosity + genome.risk) / 2.0,
            lending_appetite=(genome.trust + genome.patience) / 2.0,
            hiring_appetite=genome.entrepreneurship,
            research_intensity=(genome.curiosity + genome.policy_curiosity) / 2.0,
            risk_budget=(genome.risk + genome.leverage_tolerance) / 2.0,
        )

    def clamp(self) -> None:
        for name in (
            "exploration_rate",
            "lending_appetite",
            "hiring_appetite",
            "research_intensity",
            "risk_budget",
        ):
            setattr(self, name, max(0.05, min(0.95, float(getattr(self, name)))))


@dataclass
class AgentMemory:
    jobs_completed: int = 0
    jobs_failed: int = 0
    loans_repaid: int = 0
    loan_defaults: int = 0
    deposit_defaults: int = 0
    investments_profitable: int = 0
    investments_lost: int = 0
    research_reports: int = 0
    hired_agents: int = 0
    earned_external: Decimal = Decimal("0")
    earned_internal: Decimal = Decimal("0")
    paid_fees: Decimal = Decimal("0")


@dataclass
class AgentState:
    agent_id: str
    name: str
    profession: str
    genome: AgentGenome = field(default_factory=AgentGenome)
    skills: dict[str, float] = field(default_factory=dict)
    reputation: float = 0.5
    employer_id: str | None = None
    company_ids: list[str] = field(default_factory=list)
    memory: AgentMemory = field(default_factory=AgentMemory)
    strategy: AdaptiveStrategy | None = None
    active: bool = True

    def __post_init__(self) -> None:
        self.reputation = _unit("reputation", self.reputation)
        if self.strategy is None:
            self.strategy = AdaptiveStrategy.from_genome(self.genome)
        self.strategy.clamp()
        for name, score in self.skills.items():
            _unit(f"skill:{name}", score)

    def skill(self, name: str) -> float:
        return self.skills.get(name, 0.0)


@dataclass
class Company:
    company_id: str
    name: str
    founder_agent_id: str
    treasury_account: str
    specialty: str
    employee_ids: set[str] = field(default_factory=set)
    investor_ids: set[str] = field(default_factory=set)
    active: bool = True
    retained_earnings: Decimal = Decimal("0")


@dataclass(frozen=True)
class ExecutionMandate:
    mode: str = "simulation"
    per_transaction_limit: Decimal = Decimal("1000")
    daily_limit: Decimal = Decimal("5000")
    allowed_actions: frozenset[str] = frozenset(
        {
            "job_payment",
            "job_escrow",
            "loan",
            "loan_repayment",
            "deposit",
            "deposit_withdrawal",
            "investment",
            "investment_distribution",
            "fee",
            "collateral",
            "research_purchase",
        }
    )

    def __post_init__(self) -> None:
        if self.mode not in {"simulation", "shadow", "live"}:
            raise ValueError("mode must be simulation, shadow or live")
        if self.per_transaction_limit <= 0 or self.daily_limit <= 0:
            raise ValueError("mandate limits must be positive")

    def allows(self, action: str, amount: Decimal, spent_today: Decimal) -> bool:
        amount = Decimal(amount)
        spent_today = Decimal(spent_today)
        return (
            action in self.allowed_actions
            and amount >= 0
            and amount <= self.per_transaction_limit
            and spent_today + amount <= self.daily_limit
        )

    @classmethod
    def with_actions(
        cls,
        actions: Iterable[str],
        *,
        mode: str = "simulation",
        per_transaction_limit: Decimal = Decimal("1000"),
        daily_limit: Decimal = Decimal("5000"),
    ) -> "ExecutionMandate":
        return cls(
            mode=mode,
            per_transaction_limit=per_transaction_limit,
            daily_limit=daily_limit,
            allowed_actions=frozenset(actions),
        )
