"""SYNERGY Autonomous Agent Economy v2.

The package is intentionally standard-library only so economic experiments remain
portable and auditable. Cash mutations are routed through :class:`Ledger`.
"""

from .engine import AgentEconomy, EconomyConfig, EconomyReport
from .evolution import EvolutionEngine
from .ledger import InsufficientFunds, Ledger, LedgerEntry
from .models import AdaptiveStrategy, AgentGenome, AgentState, Company, ExecutionMandate
from .protocols import (
    AgentIdentityCard,
    MachinePaymentRequest,
    PaymentMandateEnvelope,
    ProtocolRegistry,
    TaskEnvelope,
)
from .risk import BankruptcyEngine, InsuranceMarket

__all__ = [
    "AgentEconomy",
    "EconomyConfig",
    "EconomyReport",
    "AdaptiveStrategy",
    "AgentGenome",
    "AgentState",
    "Company",
    "ExecutionMandate",
    "InsufficientFunds",
    "Ledger",
    "LedgerEntry",
    "InsuranceMarket",
    "BankruptcyEngine",
    "EvolutionEngine",
    "AgentIdentityCard",
    "TaskEnvelope",
    "PaymentMandateEnvelope",
    "MachinePaymentRequest",
    "ProtocolRegistry",
]
