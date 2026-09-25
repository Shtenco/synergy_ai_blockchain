# SYNERGY Agentic AI Economy — Full Chat Archive

This repository preserves the engineering artifacts created across the SYNERGY agentic-economy chat: source code, tests, design specifications, historical source snapshots, original input prototypes, simulation results, gas-aware training, and walk-forward OOS evaluation.

## Current implementation

The repository root contains the expanded latest v8.1 gas-aware implementation that was uploaded in source batches. The exact complete latest source/test/doc tree is also preserved as:

`archive/latest_source_tests_docs.tar.gz`

SHA-256: `ff9d161a4276cf6b73b9f7e5e1a9360b383a62add7ca1b41ad9b73844eb0abe0`

## Historical source snapshots

`archive/historical_source_snapshots_v2_v3_v4_v5_v8.tar.xz`

Contains source/tests/docs snapshots for:
- v2 Autonomous Agent Economy
- v3 RUBX/RUBZ/USDC macro economy
- v4 Agent Capital Markets
- v5 Dual-Contour SYNERGY CHAIN + AI Market Maker
- v8 Global Stability Fund

SHA-256: `d2eb8f1b5b7d03170232c0b4339a24611fca6eaf84e4e5966dd692d807ef809c`

## Source history patches

`archive/source_history_patches.tar.xz`

Contains deterministic unified patches and version SHA manifests between the preserved source versions.

SHA-256: `e0c2ab71c083577ba4c4b0aa9c8483437e2a74e7f739dbdc65c7822f92193c91`

## Original user-supplied prototypes

`archive/original_inputs_source_only.tar.xz`

Contains readable source/test/doc trees extracted from:
- `RUBX_RUBZ_RELEASE.zip`
- `2CHAN_PRINT_MONEY.zip`

Build/cache output was intentionally excluded; source, tests, scripts and documentation were retained.

SHA-256: `6bb25a64122f2f9e225b84b1508db9e3b1afced36c0fd4ee4d7fd3d51255e158`

## Key test and validation results

`archive/key_test_results.tar.xz`

Contains compact JSON/CSV/TXT/MD outputs, walk-forward summaries, holdout validation, gas-aware results and raw-report SHA manifests.

SHA-256: `6f31261d2e9c1bdd4391ecf78f9cc51e5cdd6d63506a47cf3664b12e8b6f8333`

## Full block-level simulation data

The complete JSON/CSV simulation-data archive is preserved as multipart binary files:

`archive/simulation_data/all_simulation_data_json_csv.tar.xz.part01`
through
`archive/simulation_data/all_simulation_data_json_csv.tar.xz.part10`

Rebuild:

```bash
cat archive/simulation_data/all_simulation_data_json_csv.tar.xz.part{01..10} > all_simulation_data_json_csv.tar.xz
sha256sum all_simulation_data_json_csv.tar.xz
# expected:
# 1e15c7db0ffc4483bb6bae773e7c3507012d42ecfae8a3c4c7684725a5d61646
tar -xJf all_simulation_data_json_csv.tar.xz
```

The archive contains the available block-level JSON/CSV results from the macro, dual-contour, stability, $1,000/1000-block gas tests and 1500-TRAIN/500-OOS walk-forward work.

## Development progression

1. v2 — autonomous agents, labor market, P2P lending/deposits, companies, insurance, bankruptcy, founder treasury.
2. v3 — RUBX/RUBZ/USDC triangle, 10 Base assets, real-vs-internal market accounting.
3. v4 — equities, bonds, portfolio credit, margin/liquidation, yield curve.
4. v5 — SYNERGY CHAIN shadow contour, inventory bridge, mint/sell + buyback/burn AI MM, delta control.
5. v6/v7 research — recursive collateral accounting, central-bank policy, collateral quality tiers, haircuts, CCR/LCR-style internal controls. Where an intermediate worktree did not survive a tool-session reset, the preserved later releases contain the retained/integrated mechanisms and chat documentation records the design.
6. v8 — Global Stability Fund, wealth floor, protected wealth, 50% initial system wealth under market-maker/risk mandate.
7. v8.1 — gas-aware execution: netting, batching, no-trade band, economic execution gate, adaptive cadence.
8. Walk-forward — 2000 blocks total: 1500 TRAIN + final 500 strict OOS.

## Accounting rules preserved throughout

- Internal minting is never counted as external profit.
- Capital inflows are separated from operating profit.
- GrossTVL is not treated as Economic Net Worth.
- CollateralNAV applies haircuts / claim accounting.
- HardNAV / economic wealth uses realizable external assets without double-counting internal claims.
- Gas and execution costs are deducted from strategy outcomes in gas-aware tests.

## Interpretation

This is a research/simulation codebase. Recorded deterministic simulations are not guarantees of real-world returns, and SYNERGY CHAIN is a Base-fork-style simulation layer unless/until separately deployed as production infrastructure.
