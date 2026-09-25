# Reproducibility and Economic Interpretation

The repository is designed as a deterministic research/simulation environment.

Important accounting distinctions:

- **External income**: modeled value entering from external customers/markets.
- **External capital flow**: investor/depositor capital; not profit.
- **Internal transfers**: loans, deposits, investment principal, collateral movement and internal fees; do not create new system wealth.
- **GrossTVL**: may count recursively locked collateral and therefore is intentionally not equivalent to net wealth.
- **CollateralNAV**: haircut-adjusted collateral value.
- **HardNAV / Economic Net Worth**: realizable external asset value with internal claims de-duplicated.
- **Alpha vs HODL**: strategy result versus passive holding on the same simulated path.
- **After-gas result**: execution/gas model deducted.

The Base market layer is simulated/reference-market logic unless explicitly connected to live infrastructure. SYNERGY CHAIN is a deterministic Base-fork-style simulation layer in the preserved releases, not a claim that a production OP Stack network was deployed.
