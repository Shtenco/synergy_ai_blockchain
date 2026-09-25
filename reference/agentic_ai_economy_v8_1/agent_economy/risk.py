from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

from .credit import LoanContract
from .ledger import InsufficientFunds, Ledger, money
from .models import AgentState


@dataclass
class InsurancePolicy:
    policy_id: str
    holder_id: str
    insurer_id: str
    reference_type: str
    reference_id: str
    coverage: Decimal
    premium: Decimal
    platform_fee: Decimal
    start_tick: int
    status: str = "active"
    claim_paid: Decimal = Decimal("0")
    claim_shortfall: Decimal = Decimal("0")


@dataclass
class BankruptcyCase:
    case_id: str
    agent_id: str
    tick: int
    net_worth: Decimal
    reason: str
    status: str = "opened"


class InsuranceMarket:
    def __init__(
        self,
        ledger: Ledger,
        *,
        founder_account: str = "founder:treasury",
        platform_fee_bps: int = 300,
    ) -> None:
        if not 0 <= platform_fee_bps <= 2500:
            raise ValueError("platform_fee_bps must be between 0 and 2500")
        self.ledger = ledger
        self.founder_account = founder_account
        self.platform_fee_bps = int(platform_fee_bps)
        self.policies: dict[str, InsurancePolicy] = {}
        self._next_policy = 1

    def purchase_loan_cover(
        self,
        holder: AgentState,
        insurer: AgentState,
        loan: LoanContract,
        *,
        coverage_ratio: Decimal | str,
        premium_rate: Decimal | str,
        tick: int,
    ) -> InsurancePolicy:
        if holder.agent_id != loan.lender_id:
            raise ValueError("loan cover holder must be the lender")
        if insurer.agent_id in {loan.lender_id, loan.borrower_id}:
            raise ValueError("insurer must be independent from loan parties")
        ratio = money(coverage_ratio)
        rate = money(premium_rate)
        if not Decimal("0") < ratio <= Decimal("1"):
            raise ValueError("coverage_ratio must be in (0, 1]")
        if rate <= 0:
            raise ValueError("premium_rate must be positive")
        coverage = loan.principal * ratio
        premium = coverage * rate
        fee = premium * Decimal(self.platform_fee_bps) / Decimal(10000)
        insurer_net = premium - fee
        if self.ledger.balance(holder.agent_id) < premium:
            raise InsufficientFunds("holder cannot fund insurance premium")
        policy_id = f"insurance:{self._next_policy}"
        self._next_policy += 1
        self.ledger.set_tick(tick)
        if insurer_net > 0:
            self.ledger.transfer(
                holder.agent_id,
                insurer.agent_id,
                insurer_net,
                "insurance_premium",
                policy_id,
            )
        if fee > 0:
            self.ledger.transfer(
                holder.agent_id,
                self.founder_account,
                fee,
                "insurance_platform_fee",
                policy_id,
                metadata={"funding_source": "internal"},
            )
            holder.memory.paid_fees += fee
        policy = InsurancePolicy(
            policy_id=policy_id,
            holder_id=holder.agent_id,
            insurer_id=insurer.agent_id,
            reference_type="loan",
            reference_id=loan.loan_id,
            coverage=coverage,
            premium=premium,
            platform_fee=fee,
            start_tick=tick,
        )
        self.policies[policy_id] = policy
        return policy

    def settle_loan_policy(
        self,
        policy_id: str,
        loan: LoanContract,
        *,
        holder: AgentState,
        insurer: AgentState,
        tick: int,
    ) -> InsurancePolicy:
        policy = self.policies[policy_id]
        if policy.status != "active":
            return policy
        if loan.status == "active":
            raise ValueError("referenced loan has not settled")
        if holder.agent_id != policy.holder_id or insurer.agent_id != policy.insurer_id:
            raise ValueError("insurance parties do not match")
        self.ledger.set_tick(tick)
        if loan.status != "defaulted" or loan.loss_given_default <= 0:
            policy.status = "expired"
            return policy
        claim = min(policy.coverage, loan.loss_given_default)
        available = self.ledger.balance(insurer.agent_id)
        paid = min(available, claim)
        if paid > 0:
            self.ledger.transfer(
                insurer.agent_id,
                holder.agent_id,
                paid,
                "insurance_claim",
                policy_id,
            )
        policy.claim_paid = paid
        policy.claim_shortfall = claim - paid
        policy.status = "claimed" if policy.claim_shortfall <= 0 else "insurer_default"
        return policy


class BankruptcyEngine:
    def __init__(self) -> None:
        self.cases: dict[str, BankruptcyCase] = {}
        self._next_case = 1

    def evaluate(
        self,
        agent: AgentState,
        *,
        net_worth: Decimal,
        tick: int,
        reason: str = "economic_insolvency",
    ) -> BankruptcyCase | None:
        if net_worth >= 0 or not agent.active:
            return None
        case_id = f"bankruptcy:{self._next_case}"
        self._next_case += 1
        case = BankruptcyCase(
            case_id=case_id,
            agent_id=agent.agent_id,
            tick=tick,
            net_worth=net_worth,
            reason=reason,
        )
        self.cases[case_id] = case
        agent.active = False
        return case
