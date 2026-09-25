from __future__ import annotations

from dataclasses import dataclass

from .models import AgentState


@dataclass(frozen=True)
class ReputationSnapshot:
    agent_id: str
    reputation: float
    credit_score: float
    completed_jobs: int
    defaults: int


class ReputationEngine:
    """Small deterministic reputation model used by every market.

    Reputation is intentionally explicit and inspectable. It is not a hidden ML
    score: job performance and payment history change the score by documented
    increments, and credit pricing consumes the same public score.
    """

    def record_job(self, agent: AgentState, success: bool, quality: float) -> None:
        quality = max(0.0, min(1.0, float(quality)))
        if success:
            agent.memory.jobs_completed += 1
            delta = 0.02 + 0.04 * quality
        else:
            agent.memory.jobs_failed += 1
            delta = -(0.04 + 0.06 * (1.0 - quality))
        agent.reputation = max(0.0, min(1.0, agent.reputation + delta))

    def record_loan_repayment(self, agent: AgentState) -> None:
        agent.memory.loans_repaid += 1
        agent.reputation = min(1.0, agent.reputation + 0.025)

    def record_loan_default(self, agent: AgentState) -> None:
        agent.memory.loan_defaults += 1
        agent.reputation = max(0.0, agent.reputation - 0.18)

    def record_deposit_default(self, agent: AgentState) -> None:
        agent.memory.deposit_defaults += 1
        agent.reputation = max(0.0, agent.reputation - 0.22)

    def credit_score(self, agent: AgentState) -> float:
        history_bonus = min(agent.memory.loans_repaid, 8) * 0.02
        default_penalty = agent.memory.loan_defaults * 0.12 + agent.memory.deposit_defaults * 0.08
        score = 0.15 + 0.7 * agent.reputation + history_bonus - default_penalty
        return max(0.0, min(1.0, score))

    def snapshot(self, agent: AgentState) -> ReputationSnapshot:
        return ReputationSnapshot(
            agent_id=agent.agent_id,
            reputation=agent.reputation,
            credit_score=self.credit_score(agent),
            completed_jobs=agent.memory.jobs_completed,
            defaults=agent.memory.loan_defaults + agent.memory.deposit_defaults,
        )
