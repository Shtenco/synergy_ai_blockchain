# SYNERGY Agent Capital Markets v4 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Build endogenous allocation, company equity/bonds, portfolio-backed lending and a dynamic SYNERGY yield curve on top of the verified v3 macro economy.

**Architecture:** New focused modules own portfolio allocation and capital markets. Existing RUBX-RUBZ-USDC and Base AMMs remain the settlement substrate. `MacroEconomy` orchestrates the modules and keeps internal claims excluded from system real wealth.

**Tech Stack:** Python 3.11 standard library, `decimal.Decimal`, `unittest`, matplotlib for report rendering.

**Spec:** `docs/superpowers/specs/2026-09-17-agent-capital-markets-v4-design.md`

## Global Constraints
- Preserve literal 12-second block time and ACT/365 rate accrual.
- No internal security, loan principal, mint or subscription may create external/system income.
- All cash payments are bounded by payer cash; defaults are explicit.
- No new runtime dependency is required for the simulation core.
- Existing v3 reports/CLI behavior remains backward compatible.

---

### Task 1: Yield curve and portfolio policy
**Files:** create `macro_economy/yield_curve.py`, `macro_economy/portfolio.py`; modify `macro_economy/agents.py`; test `tests/test_capital_yield_portfolio.py`.
**Interfaces:** produces `SynergyYieldCurve`, `PortfolioAllocator`, expanded `MarketAgent` portfolio metadata.
- [x] Write tests for monotonic term tenors, stress/credit sensitivity, bounded normalized target weights and deterministic allocation.
- [x] Run the tests and confirm failure from missing modules.
- [x] Implement minimal curve and allocator.
- [x] Run focused and full tests.

### Task 2: Equity and corporate bond market
**Files:** create `macro_economy/securities.py`; test `tests/test_capital_securities.py`.
**Interfaces:** produces `AgentCompany`, `EquityPosition`, `CorporateBond`, `SecuritiesMarket`.
- [x] Write tests proving formation/primary issuance conserve real cash, shares price from NAV, bond subscription transfers cash, coupon/default cannot print cash.
- [x] Confirm failing tests.
- [x] Implement securities market with ACT/365 discounting and cash-bounded settlement.
- [x] Run focused and full tests.

### Task 3: Portfolio-backed credit
**Files:** create `macro_economy/portfolio_credit.py`; test `tests/test_portfolio_credit.py`.
**Interfaces:** produces `PortfolioCreditFacility`, `PortfolioLoan`, collateral valuation/haircuts, margin/liquidation metrics.
- [x] Write tests for capacity, reserve-funded borrowing, real-time accrual, margin calls, liquidation and bad debt.
- [x] Confirm failure.
- [x] Implement reserve-backed credit without money creation.
- [x] Run focused and full tests.

### Task 4: Capital-markets orchestration
**Files:** create `macro_economy/capital_markets.py`; modify `macro_economy/engine.py`, `macro_economy/__init__.py`; test `tests/test_capital_markets_engine.py` and extend `tests/test_macro_engine.py`.
**Interfaces:** produces `CapitalMarketsEngine`; expands `MacroReport` and per-block snapshots.
- [x] Write integration tests requiring issuance, allocation, credit and curve metrics in deterministic 500-block run.
- [x] Confirm failing tests.
- [x] Integrate modules without changing real-wealth accounting semantics.
- [x] Add stress configuration and deterministic accounting assertions.
- [x] Run full suite.

### Task 5: CLI and reporting
**Files:** modify `run_macro_economy.py`, `scripts/render_macro_report.py`, `README.md`; extend `tests/test_macro_cli.py`, `tests/test_macro_report_render.py`.
**Interfaces:** v4 JSON/CSV plus HTML/PNG report.
- [x] Write failing tests for v4 fields and >=18 charts.
- [x] Implement CLI output and charts for curve, allocation, securities, credit and existing wealth metrics.
- [x] Run renderer/CLI tests and full suite.

### Task 6: 500-block verification, robustness and release
**Files:** generate `reports/capital_500_blocks_seed77.*`, robustness/stress outputs and release archive.
**Interfaces:** verified v4 release artifact.
- [x] Run 500 x 12s seed-77 reference scenario and render charts.
- [x] Run multi-seed robustness and a high-utilization credit stress scenario.
- [x] Run full tests and legacy DQN invariant suite.
- [x] Commit verified tree, create Git archive ZIP, unpack it, and rerun tests from the unpacked release.
