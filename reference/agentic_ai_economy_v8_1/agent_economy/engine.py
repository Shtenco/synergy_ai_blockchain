from __future__ import annotations

from dataclasses import asdict, dataclass, field
from decimal import Decimal
import random
from typing import Any

from .capital import CapitalMarket
from .credit import CreditMarket
from .evolution import EvolutionEngine
from .founder import FounderTreasury
from .labor import LaborMarket
from .ledger import InsufficientFunds, Ledger
from .models import AgentGenome, AgentState, Company, ExecutionMandate
from .policy_lab import PolicyLab
from .reputation import ReputationEngine
from .risk import BankruptcyEngine, InsuranceMarket


@dataclass(frozen=True)
class EconomyConfig:
    agent_count: int = 24
    steps: int = 365
    seed: int = 42
    initial_cash: Decimal = Decimal("30")
    marketplace_fee_bps: int = 300
    credit_origination_fee_bps: int = 100
    investment_distribution_fee_bps: int = 150
    external_job_every: int = 3
    credit_every: int = 7
    deposit_every: int = 11
    investment_every: int = 13
    company_revenue_every: int = 17
    policy_research_every: int = 5
    subcontract_every: int = 4
    insurance_every: int = 3
    evolution_every: int = 5
    execution_mode: str = "simulation"

    def __post_init__(self) -> None:
        if self.agent_count < 4:
            raise ValueError("agent_count must be at least 4")
        if self.steps <= 0:
            raise ValueError("steps must be positive")
        if self.initial_cash <= 0:
            raise ValueError("initial_cash must be positive")
        for name in (
            "external_job_every",
            "credit_every",
            "deposit_every",
            "investment_every",
            "company_revenue_every",
            "policy_research_every",
            "subcontract_every",
            "insurance_every",
            "evolution_every",
        ):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")
        if self.execution_mode not in {"simulation", "shadow"}:
            raise ValueError("v2 engine only executes simulation or shadow mode")


@dataclass(frozen=True)
class EconomyReport:
    steps: int
    agent_count: int
    opening_capital: Decimal
    closing_system_cash: Decimal
    external_income: Decimal
    external_expense: Decimal
    conservation_gap: Decimal
    founder_cash: Decimal
    founder_total_revenue: Decimal
    founder_external_attributed_revenue: Decimal
    founder_internal_fee_revenue: Decimal
    jobs_posted: int
    jobs_completed: int
    subcontracts_completed: int
    loans_originated: int
    loans_repaid: int
    loans_defaulted: int
    deposits_opened: int
    deposits_repaid: int
    deposits_defaulted: int
    companies_formed: int
    investments_opened: int
    policy_reports: int
    insurance_policies: int
    insurance_claims_paid: Decimal
    insurer_defaults: int
    bankruptcy_cases: int
    strategy_updates: int
    bad_debt_loss: Decimal
    bankrupt_agents: tuple[str, ...]
    agent_net_worth: dict[str, Decimal]
    founder_revenue_by_category: dict[str, Decimal] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        def convert(value: Any) -> Any:
            if isinstance(value, Decimal):
                return str(value)
            if isinstance(value, tuple):
                return [convert(v) for v in value]
            if isinstance(value, dict):
                return {k: convert(v) for k, v in value.items()}
            return value

        return convert(asdict(self))


class AgentEconomy:
    SKILLS = ("coding", "research", "data", "ops", "finance", "economics", "risk")
    PROFESSIONS = ("researcher", "builder", "lender", "operator", "analyst", "banker")

    def __init__(self, config: EconomyConfig | None = None) -> None:
        self.config = config or EconomyConfig()
        self.rng = random.Random(self.config.seed)
        self.ledger = Ledger()
        self.reputation = ReputationEngine()
        self.labor = LaborMarket(
            self.ledger,
            self.reputation,
            founder_account="founder:treasury",
            fee_bps=self.config.marketplace_fee_bps,
        )
        self.credit = CreditMarket(
            self.ledger,
            self.reputation,
            founder_account="founder:treasury",
            origination_fee_bps=self.config.credit_origination_fee_bps,
        )
        self.capital = CapitalMarket(
            self.ledger,
            founder_account="founder:treasury",
            distribution_fee_bps=self.config.investment_distribution_fee_bps,
        )
        self.founder = FounderTreasury(self.ledger, account="founder:treasury")
        self.policy = PolicyLab(seed=self.config.seed + 991)
        self.insurance = InsuranceMarket(self.ledger, founder_account="founder:treasury", platform_fee_bps=250)
        self.bankruptcy = BankruptcyEngine()
        self.evolution = EvolutionEngine()
        self.mandate = ExecutionMandate(mode=self.config.execution_mode)
        self.agents: dict[str, AgentState] = {}
        self._external_job_count = 0
        self._strategy_updates = 0
        self._create_agents()
        self._create_initial_companies()
        self._last_cash = {aid: self.ledger.balance(aid) for aid in self.agents}

    def _create_agents(self) -> None:
        for i in range(self.config.agent_count):
            profession = self.PROFESSIONS[i % len(self.PROFESSIONS)]
            skills = {skill: self.rng.uniform(0.15, 0.45) for skill in self.SKILLS}
            primary = {
                "researcher": ("research", "economics", "data"),
                "builder": ("coding", "ops", "data"),
                "lender": ("finance", "risk", "economics"),
                "operator": ("ops", "coding", "finance"),
                "analyst": ("data", "research", "economics"),
                "banker": ("finance", "risk", "ops"),
            }[profession]
            for skill in primary:
                skills[skill] = self.rng.uniform(0.68, 0.96)
            policy_curiosity = self.rng.uniform(0.35, 0.85)
            if profession in {"researcher", "analyst"}:
                policy_curiosity = self.rng.uniform(0.78, 0.98)
            entrepreneurship = self.rng.uniform(0.25, 0.85)
            if i % 5 == 0:
                entrepreneurship = self.rng.uniform(0.82, 0.98)
            genome = AgentGenome(
                risk=self.rng.uniform(0.15, 0.9),
                curiosity=self.rng.uniform(0.45, 0.98),
                policy_curiosity=policy_curiosity,
                entrepreneurship=entrepreneurship,
                trust=self.rng.uniform(0.3, 0.9),
                patience=self.rng.uniform(0.3, 0.9),
                leverage_tolerance=self.rng.uniform(0.2, 0.85),
                liquidity_preference=self.rng.uniform(0.2, 0.9),
            )
            agent_id = f"agent:{i+1}"
            agent = AgentState(
                agent_id=agent_id,
                name=f"Agent-{i+1:02d}",
                profession=profession,
                genome=genome,
                skills=skills,
                reputation=self.rng.uniform(0.45, 0.75),
            )
            self.agents[agent_id] = agent
            self.ledger.seed(agent_id, self.config.initial_cash)

    def _create_initial_companies(self) -> None:
        count = max(1, min(4, self.config.agent_count // 6))
        founders = sorted(
            self.agents.values(),
            key=lambda a: (a.genome.entrepreneurship, a.reputation),
            reverse=True,
        )[:count]
        for idx, founder in enumerate(founders, 1):
            seed = min(Decimal("5"), self.ledger.balance(founder.agent_id) * Decimal("0.18"))
            company = self.capital.form_company(
                founder,
                name=f"Synergy Venture {idx}",
                specialty=max(founder.skills, key=founder.skills.get),
                seed_capital=seed,
                tick=0,
            )
            company.employee_ids.add(founder.agent_id)
            founder.employer_id = company.company_id

    def _agent(self, agent_id: str) -> AgentState:
        return self.agents[agent_id]

    def _settle_maturities(self, tick: int) -> None:
        for loan in list(self.credit.active_loans()):
            if loan.maturity_tick <= tick:
                self.credit.settle_loan(
                    loan.loan_id,
                    lender=self._agent(loan.lender_id),
                    borrower=self._agent(loan.borrower_id),
                    tick=tick,
                )
        for dep in list(self.credit.active_deposits()):
            if dep.maturity_tick <= tick:
                self.credit.settle_deposit(
                    dep.deposit_id,
                    depositor=self._agent(dep.depositor_id),
                    institution=self._agent(dep.institution_id),
                    tick=tick,
                )

    def _job_skill(self) -> str:
        return self.rng.choice(("coding", "research", "data", "ops", "finance"))

    def _post_and_execute_external_job(self, tick: int) -> None:
        self._external_job_count += 1
        skill = self._job_skill()
        budget = Decimal(str(self.rng.randint(8, 22)))
        job = self.labor.post_external_job(
            client_id=f"external:buyer:{tick}",
            title=f"External {skill} contract #{self._external_job_count}",
            skill=skill,
            budget=budget,
            min_skill=0.25,
            tick=tick,
        )
        eligible: list[AgentState] = []
        for candidate in self.agents.values():
            if not candidate.active or candidate.skill(skill) < job.min_skill:
                continue
            try:
                # Fully funded price avoids artificial stranded escrow in the
                # long simulation while bid ranking still uses skill/reputation.
                self.labor.submit_bid(job.job_id, candidate, price=budget, tick=tick)
                eligible.append(candidate)
            except ValueError:
                continue
        if not eligible:
            return
        chosen_bid = self.labor.award(job.job_id, tick=tick)
        contractor = self._agent(chosen_bid.bidder_id)

        # Every Nth externally funded project creates a genuine agent-to-agent
        # subcontract if the prime contractor has enough liquidity.
        if self._external_job_count % self.config.subcontract_every == 0:
            sub_skill = "research" if skill != "research" else "coding"
            subcontract_budget = min(Decimal("3"), budget * Decimal("0.20"))
            if self.ledger.balance(contractor.agent_id) >= subcontract_budget:
                candidates = [
                    a
                    for a in self.agents.values()
                    if a.agent_id != contractor.agent_id and a.skill(sub_skill) >= 0.2 and a.active
                ]
                if candidates:
                    child = self.labor.create_subcontract(
                        parent_job_id=job.job_id,
                        contractor=contractor,
                        title=f"Subcontract for {job.job_id}",
                        skill=sub_skill,
                        budget=subcontract_budget,
                        min_skill=0.2,
                        tick=tick,
                    )
                    for candidate in candidates:
                        self.labor.submit_bid(child.job_id, candidate, price=subcontract_budget, tick=tick)
                    child_bid = self.labor.award(child.job_id, tick=tick)
                    subagent = self._agent(child_bid.bidder_id)
                    sub_quality = min(1.0, 0.55 + 0.4 * subagent.skill(sub_skill) + self.rng.uniform(-0.04, 0.04))
                    self.labor.complete(child.job_id, subagent, quality=sub_quality, tick=tick)
                    if contractor.company_ids:
                        company = self.capital.companies[contractor.company_ids[0]]
                        company.employee_ids.add(subagent.agent_id)
                        if subagent.employer_id is None:
                            subagent.employer_id = company.company_id

        quality = min(1.0, 0.58 + 0.38 * contractor.skill(skill) + self.rng.uniform(-0.03, 0.03))
        self.labor.complete(job.job_id, contractor, quality=quality, tick=tick)

    def _originate_credit(self, tick: int) -> None:
        ranked = sorted(self.agents.values(), key=lambda a: self.ledger.balance(a.agent_id))
        borrower = next((a for a in ranked if a.active), None)
        lender = next((a for a in reversed(ranked) if a.active and a is not borrower), None)
        if borrower is None or lender is None:
            return
        lender_cash = self.ledger.balance(lender.agent_id)
        principal = min(Decimal("5"), lender_cash * Decimal("0.10"))
        if principal < Decimal("0.75"):
            return
        try:
            loan = self.credit.originate_loan(
                lender,
                borrower,
                principal=principal,
                term_ticks=5,
                collateral_ratio=Decimal("0.20"),
                tick=tick,
            )
        except InsufficientFunds:
            return
        # Risky borrowers may lose part of their newly available capital in the
        # outside world. That loss is explicit, making later default genuine.
        if borrower.genome.risk > 0.72 and self.rng.random() < 0.35:
            max_loss = min(self.ledger.balance(borrower.agent_id), loan.principal * Decimal("0.9"))
            if max_loss > Decimal("0.25"):
                self.ledger.external_outflow(
                    borrower.agent_id,
                    max_loss,
                    "external_business_loss",
                    f"risk:{loan.loan_id}",
                )

    def _buy_credit_insurance(self, tick: int) -> None:
        insured = {p.reference_id for p in self.insurance.policies.values() if p.reference_type == "loan"}
        uninsured = [l for l in self.credit.active_loans() if l.loan_id not in insured]
        if not uninsured:
            return
        loan = min(uninsured, key=lambda l: self.reputation.credit_score(self._agent(l.borrower_id)))
        holder = self._agent(loan.lender_id)
        borrower = self._agent(loan.borrower_id)
        candidates = [
            a for a in self.agents.values()
            if a.active and a.agent_id not in {holder.agent_id, borrower.agent_id}
            and a.profession in {"banker", "lender"}
        ]
        if not candidates:
            return
        insurer = max(candidates, key=lambda a: (self.ledger.balance(a.agent_id), a.reputation))
        borrower_risk = 1.0 - self.reputation.credit_score(borrower)
        premium_rate = Decimal(str(round(0.015 + 0.05 * borrower_risk, 6)))
        coverage_ratio = Decimal("0.50") if holder.strategy and holder.strategy.risk_budget < 0.7 else Decimal("0.35")
        try:
            self.insurance.purchase_loan_cover(
                holder, insurer, loan, coverage_ratio=coverage_ratio, premium_rate=premium_rate, tick=tick
            )
        except (InsufficientFunds, ValueError):
            return

    def _settle_insurance(self, tick: int) -> None:
        for policy in list(self.insurance.policies.values()):
            if policy.status != "active" or policy.reference_type != "loan":
                continue
            loan = self.credit.loans[policy.reference_id]
            if loan.status == "active":
                continue
            self.insurance.settle_loan_policy(
                policy.policy_id,
                loan,
                holder=self._agent(policy.holder_id),
                insurer=self._agent(policy.insurer_id),
                tick=tick,
            )

    def _adapt_and_check_bankruptcy(self, tick: int) -> None:
        net_worth = self._agent_net_worth()
        for agent_id, agent in self.agents.items():
            current_cash = self.ledger.balance(agent_id)
            previous_cash = self._last_cash.get(agent_id, current_cash)
            if agent.active:
                self._strategy_updates += self.evolution.adapt(agent, wealth_change=current_cash - previous_cash)
                if net_worth[agent_id] < Decimal("-0.50"):
                    self.bankruptcy.evaluate(agent, net_worth=net_worth[agent_id], tick=tick)
            self._last_cash[agent_id] = current_cash

    def _open_deposit(self, tick: int) -> None:
        savers = sorted(self.agents.values(), key=lambda a: self.ledger.balance(a.agent_id), reverse=True)
        institutions = [a for a in self.agents.values() if a.profession in {"banker", "lender"} and a.active]
        if not savers or not institutions:
            return
        saver = savers[0]
        institution = max(institutions, key=lambda a: (a.reputation, self.ledger.balance(a.agent_id)))
        if saver.agent_id == institution.agent_id:
            saver = next((a for a in savers if a.agent_id != institution.agent_id), saver)
        principal = min(Decimal("3"), self.ledger.balance(saver.agent_id) * Decimal("0.06"))
        if principal < Decimal("0.50"):
            return
        rate = Decimal("0.04") + Decimal(str(0.04 * (1.0 - institution.reputation)))
        try:
            self.credit.open_deposit(
                saver,
                institution,
                principal=principal,
                annual_rate=rate,
                term_ticks=4,
                tick=tick,
            )
        except InsufficientFunds:
            return

    def _open_investment(self, tick: int) -> None:
        companies = [c for c in self.capital.companies.values() if c.active]
        if not companies:
            return
        company = self.rng.choice(companies)
        candidates = [a for a in self.agents.values() if a.agent_id != company.founder_agent_id and a.active]
        if not candidates:
            return
        investor = max(candidates, key=lambda a: (self.ledger.balance(a.agent_id), a.genome.risk))
        amount = min(Decimal("2.5"), self.ledger.balance(investor.agent_id) * Decimal("0.05"))
        if amount < Decimal("0.50"):
            return
        share = Decimal(str(round(self.rng.uniform(0.05, 0.18), 4)))
        try:
            self.capital.invest(investor, company, amount=amount, revenue_share=share, tick=tick)
        except InsufficientFunds:
            return

    def _company_external_revenue(self, tick: int) -> None:
        companies = [c for c in self.capital.companies.values() if c.active]
        if not companies:
            return
        company = max(companies, key=lambda c: len(c.employee_ids))
        amount = Decimal(str(self.rng.randint(3, 8)))
        self.capital.record_external_revenue(
            company,
            amount=amount,
            source_id=f"external:enterprise-client:{tick}",
            tick=tick,
        )

    def _distribute_company_returns(self, tick: int) -> None:
        for investment in list(self.capital.investments.values()):
            if investment.status != "active":
                continue
            company = self.capital.companies[investment.company_id]
            retained = company.retained_earnings
            if retained <= Decimal("1"):
                continue
            gross = min(Decimal("1"), retained * investment.revenue_share)
            if gross <= Decimal("0.05"):
                continue
            investor = self._agent(investment.investor_id)
            try:
                self.capital.distribute(
                    investment.investment_id,
                    company,
                    investor,
                    gross_amount=gross,
                    tick=tick,
                )
            except InsufficientFunds:
                continue

    def _run_policy_research(self, tick: int) -> None:
        researchers = sorted(
            self.agents.values(),
            key=lambda a: (a.strategy.research_intensity if a.strategy else a.genome.policy_curiosity, a.skill("research"), a.reputation),
            reverse=True,
        )
        researcher = researchers[(tick // self.config.policy_research_every) % min(len(researchers), 4)]
        defaulted = sum(1 for l in self.credit.loans.values() if l.status == "defaulted")
        settled = sum(1 for l in self.credit.loans.values() if l.status in {"defaulted", "repaid"})
        default_rate = defaulted / settled if settled else 0.0
        agent_cash = sum((self.ledger.balance(a.agent_id) for a in self.agents.values()), Decimal("0"))
        liquidity = float(agent_cash / self.ledger.system_cash()) if self.ledger.system_cash() > 0 else 0.0
        founder_yield = float(self.founder.total_revenue() / self.ledger.opening_capital()) if self.ledger.opening_capital() else 0.0
        self.policy.run_experiment(
            researcher,
            tick=tick,
            system_metrics={
                "default_rate": default_rate,
                "liquidity": max(0.0, min(1.0, liquidity)),
                "job_throughput": len([j for j in self.labor.jobs.values() if j.status == "completed"]) / max(1, tick),
                "founder_yield": founder_yield,
            },
        )

    def _agent_net_worth(self) -> dict[str, Decimal]:
        worth = {agent_id: self.ledger.balance(agent_id) for agent_id in self.agents}
        # Pledged collateral remains the borrower's asset while a loan is active;
        # claims and obligations cancel in the aggregate but matter per agent.
        for loan in self.credit.loans.values():
            if loan.status == "active":
                due = loan.amount_due()
                worth[loan.lender_id] += due
                worth[loan.borrower_id] -= due
                worth[loan.borrower_id] += self.ledger.balance(loan.collateral_account)
        for dep in self.credit.deposits.values():
            if dep.status == "active":
                due = dep.amount_due()
                worth[dep.depositor_id] += due
                worth[dep.institution_id] -= due
        for investment in self.capital.investments.values():
            if investment.status == "active":
                worth[investment.investor_id] += max(Decimal("0"), investment.principal - investment.distributions)
        return worth

    def run(self) -> EconomyReport:
        for tick in range(1, self.config.steps + 1):
            self.ledger.set_tick(tick)
            self._settle_maturities(tick)
            self._settle_insurance(tick)
            if tick % self.config.external_job_every == 0:
                self._post_and_execute_external_job(tick)
            if tick % self.config.credit_every == 0:
                self._originate_credit(tick)
            if tick % self.config.insurance_every == 0:
                self._buy_credit_insurance(tick)
            if tick % self.config.deposit_every == 0:
                self._open_deposit(tick)
            if tick % self.config.investment_every == 0:
                self._open_investment(tick)
            if tick % self.config.company_revenue_every == 0:
                self._company_external_revenue(tick)
            if tick % self.config.policy_research_every == 0:
                self._run_policy_research(tick)
            self._distribute_company_returns(tick)
            if tick % self.config.evolution_every == 0:
                self._adapt_and_check_bankruptcy(tick)

        founder_report = self.founder.report()
        loan_defaults = [l for l in self.credit.loans.values() if l.status == "defaulted"]
        deposit_defaults = [d for d in self.credit.deposits.values() if d.status == "defaulted"]
        bad_debt = sum((l.loss_given_default for l in loan_defaults), Decimal("0")) + sum(
            (d.loss_given_default for d in deposit_defaults), Decimal("0")
        )
        net_worth = self._agent_net_worth()
        bankrupt = tuple(
            sorted(
                agent_id
                for agent_id, value in net_worth.items()
                if value <= Decimal("0.01") and self.agents[agent_id].reputation < 0.25
            )
        )
        return EconomyReport(
            steps=self.config.steps,
            agent_count=self.config.agent_count,
            opening_capital=self.ledger.opening_capital(),
            closing_system_cash=self.ledger.system_cash(),
            external_income=self.ledger.external_income(),
            external_expense=self.ledger.external_expense(),
            conservation_gap=self.ledger.conservation_gap(),
            founder_cash=self.ledger.balance("founder:treasury"),
            founder_total_revenue=founder_report["total_revenue"],
            founder_external_attributed_revenue=founder_report["external_attributed_revenue"],
            founder_internal_fee_revenue=founder_report["internal_fee_revenue"],
            jobs_posted=len(self.labor.jobs),
            jobs_completed=sum(1 for j in self.labor.jobs.values() if j.status == "completed"),
            subcontracts_completed=sum(
                1 for j in self.labor.jobs.values() if j.parent_job_id is not None and j.status == "completed"
            ),
            loans_originated=len(self.credit.loans),
            loans_repaid=sum(1 for l in self.credit.loans.values() if l.status == "repaid"),
            loans_defaulted=len(loan_defaults),
            deposits_opened=len(self.credit.deposits),
            deposits_repaid=sum(1 for d in self.credit.deposits.values() if d.status == "repaid"),
            deposits_defaulted=len(deposit_defaults),
            companies_formed=len(self.capital.companies),
            investments_opened=len(self.capital.investments),
            policy_reports=len(self.policy.reports),
            insurance_policies=len(self.insurance.policies),
            insurance_claims_paid=sum((p.claim_paid for p in self.insurance.policies.values()), Decimal("0")),
            insurer_defaults=sum(1 for p in self.insurance.policies.values() if p.status == "insurer_default"),
            bankruptcy_cases=len(self.bankruptcy.cases),
            strategy_updates=self._strategy_updates,
            bad_debt_loss=bad_debt,
            bankrupt_agents=bankrupt,
            agent_net_worth=net_worth,
            founder_revenue_by_category=founder_report["by_category"],
        )
