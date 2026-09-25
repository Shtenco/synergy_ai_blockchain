from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

from .ledger import Ledger, money
from .models import AgentState, Company


@dataclass
class InvestmentContract:
    investment_id: str
    investor_id: str
    company_id: str
    principal: Decimal
    revenue_share: Decimal
    start_tick: int
    distributions: Decimal = Decimal("0")
    fees_paid: Decimal = Decimal("0")
    status: str = "active"

    @property
    def cash_return(self) -> Decimal:
        return self.distributions - self.principal


class CapitalMarket:
    def __init__(
        self,
        ledger: Ledger,
        *,
        founder_account: str = "founder:treasury",
        distribution_fee_bps: int = 200,
    ) -> None:
        if not 0 <= distribution_fee_bps <= 2500:
            raise ValueError("distribution_fee_bps must be between 0 and 2500")
        self.ledger = ledger
        self.founder_account = founder_account
        self.distribution_fee_bps = int(distribution_fee_bps)
        self.companies: dict[str, Company] = {}
        self.investments: dict[str, InvestmentContract] = {}
        self._next_company = 1
        self._next_investment = 1

    def form_company(
        self,
        founder: AgentState,
        *,
        name: str,
        specialty: str,
        seed_capital: Decimal | str,
        tick: int,
    ) -> Company:
        amount = money(seed_capital)
        if amount <= 0:
            raise ValueError("seed_capital must be positive")
        company_id = f"company:{self._next_company}"
        self._next_company += 1
        treasury = f"treasury:{company_id}"
        self.ledger.set_tick(tick)
        self.ledger.transfer(founder.agent_id, treasury, amount, "company_seed_capital", company_id)
        company = Company(
            company_id=company_id,
            name=name,
            founder_agent_id=founder.agent_id,
            treasury_account=treasury,
            specialty=specialty,
        )
        self.companies[company_id] = company
        founder.company_ids.append(company_id)
        return company

    def invest(
        self,
        investor: AgentState,
        company: Company,
        *,
        amount: Decimal | str,
        revenue_share: Decimal | str,
        tick: int,
    ) -> InvestmentContract:
        principal = money(amount)
        share = money(revenue_share)
        if principal <= 0:
            raise ValueError("investment amount must be positive")
        if not Decimal("0") < share <= Decimal("1"):
            raise ValueError("revenue_share must be in (0, 1]")
        investment_id = f"investment:{self._next_investment}"
        self._next_investment += 1
        self.ledger.set_tick(tick)
        self.ledger.transfer(
            investor.agent_id,
            company.treasury_account,
            principal,
            "investment_principal",
            investment_id,
        )
        contract = InvestmentContract(
            investment_id=investment_id,
            investor_id=investor.agent_id,
            company_id=company.company_id,
            principal=principal,
            revenue_share=share,
            start_tick=tick,
        )
        self.investments[investment_id] = contract
        company.investor_ids.add(investor.agent_id)
        return contract

    def record_external_revenue(
        self,
        company: Company,
        *,
        amount: Decimal | str,
        source_id: str,
        tick: int,
    ) -> None:
        amount_d = money(amount)
        self.ledger.set_tick(tick)
        source = source_id if source_id.startswith("external:") else "external:client"
        self.ledger.external_inflow(
            company.treasury_account,
            amount_d,
            "company_external_revenue",
            company.company_id,
            source=source,
            metadata={"funding_source": "external", "company_id": company.company_id},
        )
        company.retained_earnings += amount_d

    def distribute(
        self,
        investment_id: str,
        company: Company,
        investor: AgentState,
        *,
        gross_amount: Decimal | str,
        tick: int,
    ) -> InvestmentContract:
        investment = self.investments[investment_id]
        if investment.company_id != company.company_id or investment.investor_id != investor.agent_id:
            raise ValueError("investment parties do not match")
        if investment.status != "active":
            raise ValueError("investment is not active")
        gross = money(gross_amount)
        if gross <= 0:
            raise ValueError("distribution must be positive")
        fee = gross * Decimal(self.distribution_fee_bps) / Decimal(10000)
        net = gross - fee
        # The ledger performs the liquidity check on each transfer. We pre-check
        # the gross amount so fee+net can never partially execute.
        if self.ledger.balance(company.treasury_account) < gross:
            from .ledger import InsufficientFunds

            raise InsufficientFunds("company does not have cash for distribution")
        self.ledger.set_tick(tick)
        if net > 0:
            self.ledger.transfer(
                company.treasury_account,
                investor.agent_id,
                net,
                "investment_distribution",
                investment_id,
                metadata={"funding_source": "external" if company.retained_earnings > 0 else "internal"},
            )
        if fee > 0:
            funding_source = "external" if company.retained_earnings > 0 else "internal"
            self.ledger.transfer(
                company.treasury_account,
                self.founder_account,
                fee,
                "investment_distribution_fee",
                investment_id,
                metadata={"funding_source": funding_source},
            )
            investment.fees_paid += fee
            investor.memory.paid_fees += fee
        investment.distributions += net
        company.retained_earnings = max(Decimal("0"), company.retained_earnings - gross)
        if investment.distributions > investment.principal:
            investor.memory.investments_profitable += 1
        return investment

    def close_investment(self, investment_id: str) -> None:
        investment = self.investments[investment_id]
        investment.status = "closed"
