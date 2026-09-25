# Economic Testnet Local Execution Evidence v1 — 2026-08-28

This additive generation records a real deterministic execution of the Economic OS testnet checkpoint protocol in one ephemeral local Python process. It does **not** claim that a persistent or multi-node network testnet ran.

## Source boundary

The executed protocol source is pinned to:

- repository: `Shtenco/synergy_ai_blockchain`
- branch: `feat/economic-os-testnet-v1-20260828`
- source commit: `af12f7e4e09ad77d8c8c90a45611846115526147`
- genesis: `cfba3627eb65d933ed1dec416bfe1c28ecf586312028efc7e629859f315678b2`
- EconomicCycle v1: `83f9c3ee0c168ca50212ebaa1e64c58c08eb87fd040a8b5f214ee4987242f3f1`
- economic commitment v1: `9ffd71e7f535ff91cd4cedfb229ac0b43972bc8a2e82f8dce269b7440a9e65a8`
- compute trust context: `608b0ca91e905cb0345d345af9e1246489236a8e672a07fb60ea4cfb8691d397`

The source commit also fixes the Python test harness so a dynamically loaded module is registered in `sys.modules` before `exec_module`; this is required by the module's dataclass definitions under postponed annotations. The protocol semantics and genesis roots are unchanged by that harness correction.

## Observed local execution

Runner facts:

- class: `EPHEMERAL_LOCAL_PYTHON_SANDBOX`
- runtime: `CPython 3.13.5`
- platform: `Linux x86_64`
- network mode: `IN_PROCESS_NO_EXTERNAL_NETWORK`
- persistence: `EPHEMERAL`
- node count: `1`

The exact evidence-root set hashes to:

`c804516869743b9215cc7c46749412209fa929ee941a259a726bfd1c97c9a1a0`

Two checkpoints were produced in the append-only chain:

1. `69897b297fde6a25a9c123fe1c21b5ea31f2da2dc463edfc1c7a2364812ca8ab`
   - previous = exact genesis digest
2. `3742319fa196294a16f9bd80fc502cbd25c06040b569b9080dfeb2893100dedd`
   - previous = checkpoint #1 digest

Canonical local execution evidence root:

`a841d4a662feca85ad459ce2da157279d7a754280dfb75aa1ef025f92c7f1268`

## Claim boundary

The only positive execution claim introduced here is:

`LOCAL_PROTOCOL_EXECUTION_VERIFIED_NOT_NETWORK_TESTNET`

The following remain explicitly false or absent:

- network testnet executed: **NO**
- live network claim: **false**
- multi-node claim: **false**
- persistent runner claim: **false**
- consensus claim: **NONE**
- signing: **UNSIGNED**
- blockchain submission: **NOT_SUBMITTED**
- accounting / financial / payment / signing / submission / execution authority: **NONE**

The remaining execution blocker is therefore narrowed, not removed:

`PERSISTENT_MULTI_NODE_TESTNET_EXECUTION_NOT_CAPTURED`

This artifact must not be used to relabel the Economic OS testnet as live, final, signed, submitted or consensus-backed.

## GitHub Actions evidence boundary

An earlier hosted workflow invocation for the parent testnet branch concluded `failure`, but the GitHub API exposed no job steps and the associated log blob was unavailable. That run is not reclassified here as either a code PASS or a code-level FAIL. The local deterministic execution evidence is a separate evidence class.
