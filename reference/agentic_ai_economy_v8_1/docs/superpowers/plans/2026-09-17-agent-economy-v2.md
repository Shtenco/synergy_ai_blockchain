# SYNERGY Autonomous Agent Economy v2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an auditable autonomous agent economy with labor, P2P credit, deposits, investments, policy research, companies and Founder Treasury revenue attribution.

**Architecture:** Keep the existing DQN/Base-fork code as a regression laboratory and add a clean standard-library Python package for the new economy. The ledger is the cash system of record; market contracts represent claims/liabilities, and the simulation engine orchestrates heterogeneous agents through deterministic seeded decisions.

**Tech Stack:** Python 3.11 standard library, `unittest`, existing React/TypeScript UI as a presentation shell, existing NumPy DQN experiment retained unchanged.

**Spec:** `docs/superpowers/specs/2026-09-17-agent-economy-v2-design.md`

## Global Constraints

- No new Python dependencies.
- All cash movements must be ledgered.
- Internal transfers must not be counted as external profit.
- Founder revenue must be categorized and attributable.
- Defaults must reduce wealth rather than minting replacement cash.
- Version 2 defaults to simulation mode; no real-money/private-key execution.
- Policy research must remain neutral and scenario-based.

---

### Task 1: Accounting kernel and core models

**Files:**
- Create: `agent_economy/__init__.py`
- Create: `agent_economy/models.py`
- Create: `agent_economy/ledger.py`
- Test: `tests/test_agent_economy_ledger.py`

**Interfaces:**
- Produces `Ledger`, `LedgerEntry`, `AgentGenome`, `AgentState`, `ExecutionMandate`, `Company`.
- `Ledger.transfer(source, destination, amount, category, contract_id, external=False)` is the only cash mutation API used by later tasks.

- [ ] Write tests proving internal transfers conserve system cash, external income increases system cash, insufficient balances fail, and founder revenue categories can be queried.
- [ ] Run the tests and verify they fail because the package does not exist.
- [ ] Implement Decimal-based immutable ledger entries and core dataclasses.
- [ ] Re-run tests until green.

### Task 2: Reputation, labor market and agent-to-agent hiring

**Files:**
- Create: `agent_economy/reputation.py`
- Create: `agent_economy/labor.py`
- Test: `tests/test_agent_economy_labor.py`

**Interfaces:**
- Produces `ReputationEngine`, `LaborMarket`, `Job`, `Bid`.
- `LaborMarket.post_job(...)`, `submit_bid(...)`, `award(...)`, `complete(...)`.

- [ ] Write tests for escrow funding, external jobs, internal jobs, bidding, award, completion, founder marketplace fee and subcontracting.
- [ ] Verify RED.
- [ ] Implement minimal labor/reputation logic.
- [ ] Verify GREEN and cash conservation.

### Task 3: P2P credit and deposits

**Files:**
- Create: `agent_economy/credit.py`
- Test: `tests/test_agent_economy_credit.py`

**Interfaces:**
- Produces `CreditMarket`, `LoanContract`, `DepositContract`.
- Risk pricing consumes `ReputationEngine.credit_score`.

- [ ] Write tests for risk-priced origination, collateral lock/release, repayment, liquidation/default loss and term-deposit maturity/default.
- [ ] Verify RED.
- [ ] Implement loan and deposit state machines using ledger transfers.
- [ ] Verify GREEN and system conservation.

### Task 4: Companies, investments and Founder Treasury attribution

**Files:**
- Create: `agent_economy/capital.py`
- Create: `agent_economy/founder.py`
- Test: `tests/test_agent_economy_capital.py`

**Interfaces:**
- Produces `CapitalMarket`, `InvestmentContract`, `FounderTreasury`.
- Founder metrics classify fee revenue from externally funded versus internally funded contracts.

- [ ] Write tests showing investment principal is not revenue, returns require available company cash, and founder fee reporting is categorized.
- [ ] Verify RED.
- [ ] Implement company formation, investment funding/distributions and treasury reporting.
- [ ] Verify GREEN.

### Task 5: Neutral policy laboratory and autonomous engine

**Files:**
- Create: `agent_economy/policy_lab.py`
- Create: `agent_economy/engine.py`
- Create: `agent_economy/scenario.py`
- Test: `tests/test_agent_economy_engine.py`

**Interfaces:**
- Produces `PolicyLab`, `PolicyExperiment`, `AgentEconomy`, `EconomyConfig`, `EconomyReport`.
- Engine composes ledger, labor, credit, capital, founder and policy components.

- [ ] Write deterministic scenario tests proving job creation, agent hiring, credit/deposit use, investment, policy research and founder fee capture occur over a seeded run.
- [ ] Add conservation assertions: closing system cash equals opening cash plus external inflows minus external outflows; aggregate internal principal does not inflate external income.
- [ ] Verify RED.
- [ ] Implement seeded heterogeneous-agent behavior and market orchestration.
- [ ] Verify GREEN.

### Task 6: CLI, docs and legacy regression

**Files:**
- Create: `run_agent_economy.py`
- Modify: `README.md` or create it if absent.
- Modify: `experiments/README.md`

**Interfaces:**
- `python run_agent_economy.py --agents 24 --steps 365 --seed 42 --json <path>` prints a human summary and optionally writes a JSON report.

- [ ] Add CLI smoke test via `tests/test_agent_economy_cli.py`.
- [ ] Verify RED, implement CLI, verify GREEN.
- [ ] Document architecture, economics, live-mode boundary and metrics.
- [ ] Run the complete `unittest` suite.
- [ ] Run `MODE=unit SCALE=1 python experiments/dqn_cb_market/experiment_syna.py` and require `UNIT PASS`.
- [ ] Run a 365-step scenario and inspect Founder/external-income/default metrics.

### Task 7: Insurance, bankruptcy and adaptive strategy

**Files:**
- Create: `agent_economy/risk.py`
- Create: `agent_economy/evolution.py`
- Modify: `agent_economy/models.py`
- Modify: `agent_economy/engine.py`
- Test: `tests/test_agent_economy_risk_evolution.py`

- [ ] Write failing tests for loan-default insurance premium/claim conservation, insurer shortfall, bankruptcy deactivation and adaptive strategy response to success/default history.
- [ ] Implement the minimal risk and adaptation state machines.
- [ ] Integrate optional insurance and periodic adaptation in the seeded economy.
- [ ] Verify the complete v2 suite remains green.

### Task 8: Agent interoperability compatibility envelopes

**Files:**
- Create: `agent_economy/protocols.py`
- Test: `tests/test_agent_economy_protocols.py`

- [ ] Write failing tests for identity cards, task envelopes and bounded payment mandates.
- [ ] Implement dependency-free serialization structures with no private-key handling.
- [ ] Verify round-trip serialization and mandate limit enforcement.
