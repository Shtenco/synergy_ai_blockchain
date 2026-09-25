from __future__ import annotations

from decimal import Decimal

from .ledger import Ledger, LedgerEntry


class FounderTreasury:
    REVENUE_CATEGORIES = {
        "marketplace_fee",
        "credit_origination_fee",
        "investment_distribution_fee",
        "platform_service_fee",
        "settlement_fee",
        "research_market_fee",
        "insurance_platform_fee",
    }

    def __init__(self, ledger: Ledger, *, account: str = "founder:treasury") -> None:
        self.ledger = ledger
        self.account = account

    @staticmethod
    def _metadata(entry: LedgerEntry) -> dict[str, str]:
        return dict(entry.metadata)

    def revenue_entries(self) -> tuple[LedgerEntry, ...]:
        return tuple(
            e
            for e in self.ledger.entries
            if e.destination == self.account and e.category in self.REVENUE_CATEGORIES
        )

    def total_revenue(self) -> Decimal:
        return sum((e.amount for e in self.revenue_entries()), Decimal("0"))

    def external_attributed_revenue(self) -> Decimal:
        return sum(
            (
                e.amount
                for e in self.revenue_entries()
                if self._metadata(e).get("funding_source") == "external"
            ),
            Decimal("0"),
        )

    def internal_fee_revenue(self) -> Decimal:
        return self.total_revenue() - self.external_attributed_revenue()

    def by_category(self) -> dict[str, Decimal]:
        out: dict[str, Decimal] = {}
        for entry in self.revenue_entries():
            out[entry.category] = out.get(entry.category, Decimal("0")) + entry.amount
        return out

    def report(self) -> dict[str, object]:
        return {
            "cash_balance": self.ledger.balance(self.account),
            "total_revenue": self.total_revenue(),
            "external_attributed_revenue": self.external_attributed_revenue(),
            "internal_fee_revenue": self.internal_fee_revenue(),
            "by_category": self.by_category(),
        }
