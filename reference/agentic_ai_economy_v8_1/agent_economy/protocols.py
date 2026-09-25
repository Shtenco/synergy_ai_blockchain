from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

from .models import AgentState


@dataclass(frozen=True)
class AgentIdentityCard:
    agent_id: str
    name: str
    capabilities: tuple[str, ...]
    reputation: float
    endpoint: str | None = None
    identity_hint: str = "erc8004-compatible-metadata"
    task_protocol_hint: str = "a2a-compatible-task-envelope"

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "capabilities": list(self.capabilities),
            "reputation": self.reputation,
            "endpoint": self.endpoint,
            "identity_hint": self.identity_hint,
            "task_protocol_hint": self.task_protocol_hint,
        }


@dataclass(frozen=True)
class TaskEnvelope:
    task_id: str
    sender_id: str
    recipient_id: str
    capability: str
    description: str
    budget: Decimal
    status: str = "offered"
    metadata: tuple[tuple[str, str], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "sender_id": self.sender_id,
            "recipient_id": self.recipient_id,
            "capability": self.capability,
            "description": self.description,
            "budget": str(self.budget),
            "status": self.status,
            "metadata": dict(self.metadata),
            "protocol_hint": "a2a-compatible-task-envelope",
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "TaskEnvelope":
        return cls(
            task_id=str(payload["task_id"]),
            sender_id=str(payload["sender_id"]),
            recipient_id=str(payload["recipient_id"]),
            capability=str(payload["capability"]),
            description=str(payload["description"]),
            budget=Decimal(str(payload["budget"])),
            status=str(payload.get("status", "offered")),
            metadata=tuple(sorted((str(k), str(v)) for k, v in dict(payload.get("metadata", {})).items())),
        )


@dataclass
class PaymentMandateEnvelope:
    mandate_id: str
    payer_id: str
    allowed_actions: tuple[str, ...]
    max_transaction: Decimal
    max_total: Decimal
    expires_tick: int
    payee_id: str | None = None
    purpose: str = "bounded autonomous payment"
    spent: Decimal = Decimal("0")
    protocol_hint: str = "ap2-compatible-mandate-intent"

    def consume(self, action: str, amount: Decimal, *, tick: int, payee_id: str | None = None) -> bool:
        amount = Decimal(amount)
        if tick > self.expires_tick:
            return False
        if action not in self.allowed_actions:
            return False
        if amount <= 0 or amount > self.max_transaction:
            return False
        if self.spent + amount > self.max_total:
            return False
        if self.payee_id is not None and payee_id is not None and payee_id != self.payee_id:
            return False
        self.spent += amount
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "mandate_id": self.mandate_id,
            "payer_id": self.payer_id,
            "payee_id": self.payee_id,
            "purpose": self.purpose,
            "allowed_actions": list(self.allowed_actions),
            "max_transaction": str(self.max_transaction),
            "max_total": str(self.max_total),
            "spent": str(self.spent),
            "expires_tick": self.expires_tick,
            "protocol_hint": self.protocol_hint,
        }


@dataclass(frozen=True)
class MachinePaymentRequest:
    request_id: str
    payee_id: str
    amount: Decimal
    asset: str
    resource: str
    network: str = "simulation"
    protocol_hint: str = "x402-compatible-intent"

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "payee_id": self.payee_id,
            "amount": str(self.amount),
            "asset": self.asset,
            "resource": self.resource,
            "network": self.network,
            "protocol_hint": self.protocol_hint,
        }


class ProtocolRegistry:
    @staticmethod
    def identity_card(agent: AgentState, *, endpoint: str | None = None) -> AgentIdentityCard:
        capabilities = tuple(sorted(skill for skill, score in agent.skills.items() if score >= 0.50))
        return AgentIdentityCard(
            agent_id=agent.agent_id,
            name=agent.name,
            capabilities=capabilities,
            reputation=agent.reputation,
            endpoint=endpoint,
        )
