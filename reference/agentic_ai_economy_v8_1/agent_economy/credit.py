from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

from .ledger import Ledger, money
from .models import AgentState
from .reputation import ReputationEngine

YEAR_TICKS = Decimal("365")


@dataclass
class LoanContract:
    loan_id: str
    lender_id: str
    borrower_id: str
    principal: Decimal
    annual_rate: Decimal
    start_tick: int
    maturity_tick: int
    collateral_ratio: Decimal
    collateral_amount: Decimal
    collateral_account: str
    origination_fee: Decimal
    status: str = "active"
    amount_repaid: Decimal = Decimal("0")
    collateral_recovered: Decimal = Decimal("0")
    loss_given_default: Decimal = Decimal("0")

    def amount_due(self) -> Decimal:
        term = Decimal(self.maturity_tick - self.start_tick)
        return self.principal * (Decimal("1") + self.annual_rate * term / YEAR_TICKS)


@dataclass
class DepositContract:
    deposit_id: str
    depositor_id: str
    institution_id: str
    principal: Decimal
    annual_rate: Decimal
    start_tick: int
    maturity_tick: int
    status: str = "active"
    amount_paid: Decimal = Decimal("0")
    loss_given_default: Decimal = Decimal("0")

    def amount_due(self) -> Decimal:
        term = Decimal(self.maturity_tick - self.start_tick)
        return self.principal * (Decimal("1") + self.annual_rate * term / YEAR_TICKS)


class CreditMarket:
    def __init__(
        self,
        ledger: Ledger,
        reputation: ReputationEngine,
        *,
        founder_account: str = "founder:treasury",
        base_rate: Decimal | str = Decimal("0.08"),
        risk_spread: Decimal | str = Decimal("0.32"),
        origination_fee_bps: int = 100,
    ) -> None:
        self.ledger = ledger
        self.reputation = reputation
        self.founder_account = founder_account
        self.base_rate = money(base_rate)
        self.risk_spread = money(risk_spread)
        if self.base_rate < 0 or self.risk_spread < 0:
            raise ValueError("rates must be non-negative")
        if not 0 <= origination_fee_bps <= 2500:
            raise ValueError("origination_fee_bps must be between 0 and 2500")
        self.origination_fee_bps = int(origination_fee_bps)
        self.loans: dict[str, LoanContract] = {}
        self.deposits: dict[str, DepositContract] = {}
        self._next_loan = 1
        self._next_deposit = 1

    def quote_rate(self, borrower: AgentState) -> Decimal:
        score = Decimal(str(self.reputation.credit_score(borrower)))
        return self.base_rate + (Decimal("1") - score) * self.risk_spread

    def originate_loan(
        self,
        lender: AgentState,
        borrower: AgentState,
        *,
        principal: Decimal | str,
        term_ticks: int,
        collateral_ratio: Decimal | str = Decimal("0.50"),
        tick: int,
    ) -> LoanContract:
        principal_d = money(principal)
        collateral_ratio_d = money(collateral_ratio)
        if principal_d <= 0:
            raise ValueError("principal must be positive")
        if term_ticks <= 0:
            raise ValueError("term_ticks must be positive")
        if not Decimal("0") <= collateral_ratio_d <= Decimal("2"):
            raise ValueError("collateral_ratio must be between 0 and 2")
        loan_id = f"loan:{self._next_loan}"
        self._next_loan += 1
        collateral = principal_d * collateral_ratio_d
        fee = principal_d * Decimal(self.origination_fee_bps) / Decimal(10000)
        collateral_account = f"collateral:{loan_id}"
        self.ledger.set_tick(tick)
        # Principal is a pure transfer. It does not create external income.
        self.ledger.transfer(lender.agent_id, borrower.agent_id, principal_d, "loan_principal", loan_id)
        if collateral > 0:
            self.ledger.transfer(
                borrower.agent_id,
                collateral_account,
                collateral,
                "loan_collateral_lock",
                loan_id,
            )
        if fee > 0:
            self.ledger.transfer(
                borrower.agent_id,
                self.founder_account,
                fee,
                "credit_origination_fee",
                loan_id,
            )
            borrower.memory.paid_fees += fee
        loan = LoanContract(
            loan_id=loan_id,
            lender_id=lender.agent_id,
            borrower_id=borrower.agent_id,
            principal=principal_d,
            annual_rate=self.quote_rate(borrower),
            start_tick=tick,
            maturity_tick=tick + int(term_ticks),
            collateral_ratio=collateral_ratio_d,
            collateral_amount=collateral,
            collateral_account=collateral_account,
            origination_fee=fee,
        )
        self.loans[loan_id] = loan
        return loan

    def settle_loan(
        self,
        loan_id: str,
        *,
        lender: AgentState,
        borrower: AgentState,
        tick: int,
    ) -> LoanContract:
        loan = self.loans[loan_id]
        if loan.status != "active":
            return loan
        if tick < loan.maturity_tick:
            raise ValueError("loan has not matured")
        if lender.agent_id != loan.lender_id or borrower.agent_id != loan.borrower_id:
            raise ValueError("loan parties do not match")
        self.ledger.set_tick(tick)
        due = loan.amount_due()
        available = self.ledger.balance(borrower.agent_id)
        if available >= due:
            self.ledger.transfer(borrower.agent_id, lender.agent_id, due, "loan_repayment", loan_id)
            loan.amount_repaid = due
            collateral = self.ledger.balance(loan.collateral_account)
            if collateral > 0:
                self.ledger.transfer(
                    loan.collateral_account,
                    borrower.agent_id,
                    collateral,
                    "loan_collateral_release",
                    loan_id,
                )
            loan.status = "repaid"
            self.reputation.record_loan_repayment(borrower)
            return loan

        # Default waterfall: recover free borrower cash first, then collateral.
        paid = min(available, due)
        if paid > 0:
            self.ledger.transfer(borrower.agent_id, lender.agent_id, paid, "loan_default_cash_recovery", loan_id)
        remaining = due - paid
        collateral_available = self.ledger.balance(loan.collateral_account)
        collateral_recovery = min(collateral_available, remaining)
        if collateral_recovery > 0:
            self.ledger.transfer(
                loan.collateral_account,
                lender.agent_id,
                collateral_recovery,
                "loan_collateral_liquidation",
                loan_id,
            )
        residual_collateral = self.ledger.balance(loan.collateral_account)
        if residual_collateral > 0:
            self.ledger.transfer(
                loan.collateral_account,
                borrower.agent_id,
                residual_collateral,
                "loan_collateral_surplus_return",
                loan_id,
            )
        loan.amount_repaid = paid
        loan.collateral_recovered = collateral_recovery
        loan.loss_given_default = max(Decimal("0"), due - paid - collateral_recovery)
        loan.status = "defaulted"
        self.reputation.record_loan_default(borrower)
        return loan

    def open_deposit(
        self,
        depositor: AgentState,
        institution: AgentState,
        *,
        principal: Decimal | str,
        annual_rate: Decimal | str,
        term_ticks: int,
        tick: int,
    ) -> DepositContract:
        principal_d = money(principal)
        rate_d = money(annual_rate)
        if principal_d <= 0 or rate_d < 0 or term_ticks <= 0:
            raise ValueError("invalid deposit terms")
        deposit_id = f"deposit:{self._next_deposit}"
        self._next_deposit += 1
        self.ledger.set_tick(tick)
        self.ledger.transfer(
            depositor.agent_id,
            institution.agent_id,
            principal_d,
            "deposit_principal",
            deposit_id,
        )
        dep = DepositContract(
            deposit_id=deposit_id,
            depositor_id=depositor.agent_id,
            institution_id=institution.agent_id,
            principal=principal_d,
            annual_rate=rate_d,
            start_tick=tick,
            maturity_tick=tick + int(term_ticks),
        )
        self.deposits[deposit_id] = dep
        return dep

    def settle_deposit(
        self,
        deposit_id: str,
        *,
        depositor: AgentState,
        institution: AgentState,
        tick: int,
    ) -> DepositContract:
        dep = self.deposits[deposit_id]
        if dep.status != "active":
            return dep
        if tick < dep.maturity_tick:
            raise ValueError("deposit has not matured")
        if depositor.agent_id != dep.depositor_id or institution.agent_id != dep.institution_id:
            raise ValueError("deposit parties do not match")
        self.ledger.set_tick(tick)
        due = dep.amount_due()
        available = self.ledger.balance(institution.agent_id)
        paid = min(available, due)
        if paid > 0:
            self.ledger.transfer(
                institution.agent_id,
                depositor.agent_id,
                paid,
                "deposit_withdrawal",
                deposit_id,
            )
        dep.amount_paid = paid
        if paid >= due:
            dep.status = "repaid"
        else:
            dep.status = "defaulted"
            dep.loss_given_default = due - paid
            self.reputation.record_deposit_default(institution)
        return dep

    def active_loans(self) -> tuple[LoanContract, ...]:
        return tuple(l for l in self.loans.values() if l.status == "active")

    def active_deposits(self) -> tuple[DepositContract, ...]:
        return tuple(d for d in self.deposits.values() if d.status == "active")
