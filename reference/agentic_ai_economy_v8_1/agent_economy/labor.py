from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal

from .ledger import Ledger, money
from .models import AgentState
from .reputation import ReputationEngine


@dataclass(frozen=True)
class Bid:
    bid_id: str
    job_id: str
    bidder_id: str
    price: Decimal
    skill_score: float
    reputation: float
    tick: int


@dataclass
class Job:
    job_id: str
    client_id: str
    title: str
    skill: str
    budget: Decimal
    min_skill: float
    escrow_account: str
    funding_source: str
    posted_tick: int
    parent_job_id: str | None = None
    contractor_id: str | None = None
    awarded_price: Decimal | None = None
    status: str = "open"
    bids: list[Bid] = field(default_factory=list)
    completed_tick: int | None = None
    quality: float | None = None


class LaborMarket:
    def __init__(
        self,
        ledger: Ledger,
        reputation: ReputationEngine,
        *,
        founder_account: str = "founder:treasury",
        fee_bps: int = 300,
    ) -> None:
        if not 0 <= fee_bps <= 2500:
            raise ValueError("fee_bps must be between 0 and 2500")
        self.ledger = ledger
        self.reputation = reputation
        self.founder_account = founder_account
        self.fee_bps = int(fee_bps)
        self.jobs: dict[str, Job] = {}
        self._next_job = 1
        self._next_bid = 1

    def _new_job(
        self,
        *,
        client_id: str,
        title: str,
        skill: str,
        budget: Decimal | str,
        min_skill: float,
        tick: int,
        funding_source: str,
        parent_job_id: str | None = None,
    ) -> Job:
        amount = money(budget)
        if amount <= 0:
            raise ValueError("job budget must be positive")
        if not 0 <= min_skill <= 1:
            raise ValueError("min_skill must be in [0, 1]")
        job_id = f"job:{self._next_job}"
        self._next_job += 1
        escrow = f"escrow:{job_id}"
        self.ledger.set_tick(tick)
        if funding_source == "external":
            self.ledger.external_inflow(
                escrow,
                amount,
                "external_job_funding",
                job_id,
                source=client_id if client_id.startswith("external:") else "external:buyer",
                metadata={"title": title, "skill": skill},
            )
        else:
            self.ledger.transfer(
                client_id,
                escrow,
                amount,
                "job_escrow",
                job_id,
                metadata={"title": title, "skill": skill},
            )
        job = Job(
            job_id=job_id,
            client_id=client_id,
            title=title,
            skill=skill,
            budget=amount,
            min_skill=float(min_skill),
            escrow_account=escrow,
            funding_source=funding_source,
            posted_tick=tick,
            parent_job_id=parent_job_id,
        )
        self.jobs[job_id] = job
        return job

    def post_external_job(self, **kwargs) -> Job:
        return self._new_job(funding_source="external", **kwargs)

    def post_internal_job(self, **kwargs) -> Job:
        return self._new_job(funding_source="internal", **kwargs)

    def submit_bid(
        self,
        job_id: str,
        bidder: AgentState,
        *,
        price: Decimal | str,
        tick: int,
    ) -> Bid:
        job = self.jobs[job_id]
        if job.status != "open":
            raise ValueError("job is not open")
        amount = money(price)
        if amount <= 0 or amount > job.budget:
            raise ValueError("bid price must be positive and no higher than budget")
        skill = bidder.skill(job.skill)
        if skill < job.min_skill:
            raise ValueError("bidder does not meet minimum skill")
        bid = Bid(
            bid_id=f"bid:{self._next_bid}",
            job_id=job_id,
            bidder_id=bidder.agent_id,
            price=amount,
            skill_score=skill,
            reputation=bidder.reputation,
            tick=tick,
        )
        self._next_bid += 1
        job.bids.append(bid)
        return bid

    def ranked_bids(self, job_id: str) -> list[Bid]:
        job = self.jobs[job_id]
        return sorted(
            job.bids,
            key=lambda b: (
                -(0.55 * b.skill_score + 0.30 * b.reputation + 0.15 * float(1 - b.price / job.budget)),
                b.tick,
                b.bid_id,
            ),
        )

    def award(self, job_id: str, contractor_id: str | None = None, *, tick: int) -> Bid:
        job = self.jobs[job_id]
        if job.status != "open":
            raise ValueError("job is not open")
        bids = self.ranked_bids(job_id)
        if not bids:
            raise ValueError("job has no bids")
        if contractor_id is None:
            chosen = bids[0]
        else:
            chosen = next((b for b in bids if b.bidder_id == contractor_id), None)
            if chosen is None:
                raise ValueError("contractor did not bid on job")
        job.contractor_id = chosen.bidder_id
        job.awarded_price = chosen.price
        job.status = "awarded"
        self.ledger.set_tick(tick)
        return chosen

    def create_subcontract(
        self,
        *,
        parent_job_id: str,
        contractor: AgentState,
        title: str,
        skill: str,
        budget: Decimal | str,
        min_skill: float,
        tick: int,
    ) -> Job:
        parent = self.jobs[parent_job_id]
        if parent.contractor_id != contractor.agent_id or parent.status not in {"awarded", "in_progress"}:
            raise ValueError("only the awarded contractor can subcontract an active job")
        child = self._new_job(
            client_id=contractor.agent_id,
            title=title,
            skill=skill,
            budget=budget,
            min_skill=min_skill,
            tick=tick,
            funding_source="internal",
            parent_job_id=parent_job_id,
        )
        contractor.memory.hired_agents += 1
        parent.status = "in_progress"
        return child

    def complete(self, job_id: str, contractor: AgentState, *, quality: float, tick: int) -> Job:
        job = self.jobs[job_id]
        if job.status not in {"awarded", "in_progress"}:
            raise ValueError("job is not active")
        if job.contractor_id != contractor.agent_id:
            raise ValueError("only the awarded contractor can complete the job")
        quality = max(0.0, min(1.0, float(quality)))
        if job.awarded_price is None:
            raise RuntimeError("awarded job has no price")
        self.ledger.set_tick(tick)
        payout = job.awarded_price
        fee = payout * Decimal(self.fee_bps) / Decimal(10000)
        worker_net = payout - fee
        if worker_net > 0:
            self.ledger.transfer(
                job.escrow_account,
                contractor.agent_id,
                worker_net,
                "job_payment",
                job.job_id,
                metadata={"funding_source": job.funding_source},
            )
        if fee > 0:
            self.ledger.transfer(
                job.escrow_account,
                self.founder_account,
                fee,
                "marketplace_fee",
                job.job_id,
                metadata={"funding_source": job.funding_source},
            )
            contractor.memory.paid_fees += fee
        if job.funding_source == "external":
            contractor.memory.earned_external += worker_net
        else:
            contractor.memory.earned_internal += worker_net
        job.status = "completed"
        job.completed_tick = tick
        job.quality = quality
        self.reputation.record_job(contractor, True, quality)
        return job

    def fail(self, job_id: str, contractor: AgentState, *, quality: float, tick: int) -> Job:
        job = self.jobs[job_id]
        if job.contractor_id != contractor.agent_id or job.status not in {"awarded", "in_progress"}:
            raise ValueError("job is not active for contractor")
        job.status = "failed"
        job.completed_tick = tick
        job.quality = max(0.0, min(1.0, quality))
        self.reputation.record_job(contractor, False, job.quality)
        return job
