# Test Matrix and Recorded Checkpoints

| Version / stage | Recorded verification |
|---|---|
| v2 | 35/35 agent-economy tests PASS; legacy economic unit suite PASS |
| v3 | 59/59 Python tests PASS; legacy unit suite PASS |
| v4 | 82/82 tests PASS; legacy unit suite PASS |
| v5 | 96/96 tests PASS; legacy unit suite PASS |
| v6/v7 development | cumulative central-bank/banking extensions tested over prior suite during the chat |
| v8 release | 106/106 release tests PASS; legacy unit suite PASS |
| v8.1 gas-aware | focused/extended gas-aware suites PASS; holdout results archived |

## $1,000 / 1,000-block gas-aware experiment

Recorded trained policy:
- minimum batch interval: 8 blocks
- safety multiple: 1.50x
- risk-benefit multiplier: 3.0

Recorded seed-77 result:
- opening capital: $1,000
- capital after gas / excluding external capital flow: about $1,003.51
- modeled gas: about $0.324
- batch executions: 49
- skipped hedge executions: 951/1000
- max drawdown: about 0.00737%

Holdout seeds 4–13:
- positive net after gas: 10/10
- mean net after gas: about +$3.39
- worst recorded net after gas: about +$2.97

## 2000-block walk-forward

Protocol:
- blocks 1–1500: TRAIN / policy selection
- blocks 1501–2000: frozen-policy OOS
- initial capital: $1,000

Selected training policy:
- minimum interval: 6 blocks
- safety multiple: 1.35x
- risk-benefit multiplier: 2.75x

Recorded:
- TRAIN end capital after gas: $1,005.418672
- TRAIN net after gas: +$5.418672
- OOS final capital: $1,007.352063
- OOS last-500 net after gas: +$1.933391
- OOS gas: $0.173637
- OOS max drawdown: ~0.002106%
- full 2000-block net after gas: +$7.352063

These are simulation results, not guaranteed live returns.
