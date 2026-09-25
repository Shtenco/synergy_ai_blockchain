# SYNERGY Dual Contour v5 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and verify the two-contour SYNERGY CHAIN + AI market-maker layer on top of v4.

**Architecture:** Keep v4 real accounting untouched as the external economy. Add an isolated shadow-chain ledger, one-way inventory bridge, adaptive exact-target synthetic market maker, external delta controller, deterministic chain blocks and a wrapper orchestrator.

**Tech Stack:** Python 3, Decimal fixed-point accounting, deterministic RNG, matplotlib report renderer.

**Spec:** `docs/superpowers/specs/2026-09-17-dual-contour-synergy-chain-v5-design.md`

## Global Constraints

- Synthetic supply never counts as HardNAV.
- No shadow-to-external redemption.
- No private keys or live execution.
- 500 reference blocks at 12 seconds each.
- Preserve all v4 and legacy DQN tests.

---

### Task 1: Shadow supply ledger
- [x] Add mint/burn supply accounting with explicit zero HardNAV effect.
- [x] Test mint/burn totals and conservation semantics.

### Task 2: One-way inventory bridge
- [x] Add real inventory custody, cost basis, external buy/sell, realized PnL and execution fees.
- [x] Bound synthetic capacity against real inventory.

### Task 3: Adaptive AI market maker
- [x] Add exact CPMM target sizing.
- [x] Add counter-cyclical spread policy: mint/sell on strength; buyback/burn on weakness.
- [x] Add real external delta target policy.

### Task 4: SYNERGY CHAIN block layer
- [x] Add chain id, 13-asset registry, block clock, hash linkage and transaction journal.
- [x] Encode one-way bridge/accounting rules in Base-fork manifest.

### Task 5: v4 integration
- [x] Add dual-contour wrapper around the verified v4 macro engine.
- [x] Transfer inventory without changing opening real wealth.
- [x] Seal one SYNERGY CHAIN block per macro block.

### Task 6: Reporting and CLI
- [x] Add machine-readable CLI output.
- [x] Add self-contained HTML report and 20 standalone v5 charts.

### Task 7: Verification
- [x] Run full Python test suite.
- [x] Run legacy DQN `MODE=unit` suite.
- [x] Run v4/no-delta/full-v5 reference comparison.
- [x] Run 20-seed robustness.
- [x] Run 5× volatility stress.
- [x] Re-run the full suite from the final unpacked release ZIP.
