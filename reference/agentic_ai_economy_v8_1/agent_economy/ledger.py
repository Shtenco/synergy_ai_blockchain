from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Iterable


class InsufficientFunds(ValueError):
    pass


class InvalidAmount(ValueError):
    pass


CASH_QUANTUM = Decimal("0.000000000001")


def money(value: Decimal | str | int | float) -> Decimal:
    try:
        amount = value if isinstance(value, Decimal) else Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise InvalidAmount(f"invalid money value: {value!r}") from exc
    if not amount.is_finite():
        raise InvalidAmount("amount must be finite")
    return amount


@dataclass(frozen=True)
class LedgerEntry:
    entry_id: int
    source: str
    destination: str
    amount: Decimal
    category: str
    contract_id: str | None = None
    tick: int = 0
    external: bool = False
    opening: bool = False
    metadata: tuple[tuple[str, str], ...] = ()


class Ledger:
    """Cash ledger for all system entities.

    External and opening accounts are excluded from ``system_cash``. Their
    negative balances are bookkeeping counterparts to cash that entered the
    simulated economy; system actors themselves may never spend below zero.
    """

    def __init__(self) -> None:
        self._balances: dict[str, Decimal] = {}
        self._entries: list[LedgerEntry] = []
        self._next_id = 1
        self._tick = 0

    @property
    def entries(self) -> tuple[LedgerEntry, ...]:
        return tuple(self._entries)

    @property
    def tick(self) -> int:
        return self._tick

    def set_tick(self, tick: int) -> None:
        if tick < 0:
            raise ValueError("tick must be non-negative")
        self._tick = int(tick)

    def balance(self, account: str) -> Decimal:
        return self._balances.get(account, Decimal("0"))

    @staticmethod
    def is_counterparty_account(account: str) -> bool:
        return account.startswith("external:") or account.startswith("opening:")

    def seed(self, destination: str, amount: Decimal | str | int | float) -> LedgerEntry:
        return self._move(
            "opening:capital",
            destination,
            amount,
            category="opening_capital",
            opening=True,
            external=False,
        )

    def external_inflow(
        self,
        destination: str,
        amount: Decimal | str | int | float,
        category: str = "external_income",
        contract_id: str | None = None,
        *,
        source: str = "external:world",
        metadata: dict[str, str] | None = None,
    ) -> LedgerEntry:
        if not source.startswith("external:"):
            raise ValueError("external inflow source must start with external:")
        return self._move(
            source,
            destination,
            amount,
            category,
            contract_id,
            external=True,
            metadata=metadata,
        )

    def external_outflow(
        self,
        source: str,
        amount: Decimal | str | int | float,
        category: str = "external_expense",
        contract_id: str | None = None,
        *,
        destination: str = "external:world",
        metadata: dict[str, str] | None = None,
    ) -> LedgerEntry:
        if not destination.startswith("external:"):
            raise ValueError("external outflow destination must start with external:")
        return self._move(
            source,
            destination,
            amount,
            category,
            contract_id,
            external=True,
            metadata=metadata,
        )

    def transfer(
        self,
        source: str,
        destination: str,
        amount: Decimal | str | int | float,
        category: str,
        contract_id: str | None = None,
        *,
        metadata: dict[str, str] | None = None,
    ) -> LedgerEntry:
        if self.is_counterparty_account(source) or self.is_counterparty_account(destination):
            raise ValueError("use external_inflow/outflow or seed for counterparty accounts")
        return self._move(source, destination, amount, category, contract_id, metadata=metadata)

    def _move(
        self,
        source: str,
        destination: str,
        amount: Decimal | str | int | float,
        category: str,
        contract_id: str | None = None,
        *,
        external: bool = False,
        opening: bool = False,
        metadata: dict[str, str] | None = None,
    ) -> LedgerEntry:
        amount_d = money(amount).quantize(CASH_QUANTUM)
        if amount_d <= 0:
            raise InvalidAmount("amount must be positive")
        if not self.is_counterparty_account(source) and self.balance(source) < amount_d:
            raise InsufficientFunds(
                f"{source} has {self.balance(source)} but attempted to spend {amount_d}"
            )
        self._balances[source] = self.balance(source) - amount_d
        self._balances[destination] = self.balance(destination) + amount_d
        entry = LedgerEntry(
            entry_id=self._next_id,
            source=source,
            destination=destination,
            amount=amount_d,
            category=category,
            contract_id=contract_id,
            tick=self._tick,
            external=external,
            opening=opening,
            metadata=tuple(sorted((metadata or {}).items())),
        )
        self._next_id += 1
        self._entries.append(entry)
        return entry

    def system_cash(self) -> Decimal:
        return sum(
            (balance for account, balance in self._balances.items() if not self.is_counterparty_account(account)),
            Decimal("0"),
        )

    def opening_capital(self) -> Decimal:
        return sum((e.amount for e in self._entries if e.opening), Decimal("0"))

    def external_income(self) -> Decimal:
        return sum(
            (
                e.amount
                for e in self._entries
                if e.external and e.source.startswith("external:") and not e.destination.startswith("external:")
            ),
            Decimal("0"),
        )

    def external_expense(self) -> Decimal:
        return sum(
            (
                e.amount
                for e in self._entries
                if e.external and e.destination.startswith("external:") and not e.source.startswith("external:")
            ),
            Decimal("0"),
        )

    def category_total(
        self,
        category: str,
        *,
        source: str | None = None,
        destination: str | None = None,
    ) -> Decimal:
        return sum(
            (
                e.amount
                for e in self._entries
                if e.category == category
                and (source is None or e.source == source)
                and (destination is None or e.destination == destination)
            ),
            Decimal("0"),
        )

    def entries_for(self, account: str) -> tuple[LedgerEntry, ...]:
        return tuple(e for e in self._entries if e.source == account or e.destination == account)

    def conservation_gap(self) -> Decimal:
        expected = self.opening_capital() + self.external_income() - self.external_expense()
        return self.system_cash() - expected

    def balances(self) -> dict[str, Decimal]:
        return dict(self._balances)
