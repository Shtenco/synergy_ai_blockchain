# LEGACY DISTILLATION V2 — Import Queue

Canonical owner: `Shtenco/synergy_ai_blockchain`

Nothing in this queue is auto-promoted to production. Every mechanism must pass the listed gate in this repository authority boundary.

| Priority | ID | Family | Action | Occurrences | Test gate | Representative |
|---|---|---|---|---:|---|---|
| P0_REWRITE | M171 | TOKEN_ERC20 | REWRITE_REQUIRED | 205 | `erc20_supply_access_invariants` | transfer |
| P0_REWRITE | M173 | TOKEN_ERC20 | REWRITE_REQUIRED | 117 | `erc20_supply_access_invariants` | _clamp |
| P0_REWRITE | M174 | TOKEN_ERC20 | REWRITE_REQUIRED | 103 | `erc20_supply_access_invariants` | transferWpol |
| P1_REWRITE | M175 | TOKEN_ERC20 | REWRITE_REQUIRED | 74 | `erc20_supply_access_invariants` | record_arb_result |
| P0_PROMOTE_WITH_GATE | M172 | TOKEN_ERC20 | PROMOTION_CANDIDATE | 147 | `erc20_supply_access_invariants` | balanceOf |
| P1_REWRITE | M177 | TOKEN_ERC20 | REWRITE_REQUIRED | 32 | `erc20_supply_access_invariants` | _transferFrom |
| P1_PROMOTE_WITH_GATE | M176 | TOKEN_ERC20 | PROMOTION_CANDIDATE | 62 | `erc20_supply_access_invariants` | constructor |
| P1_REWRITE | M179 | TOKEN_ERC20 | REWRITE_REQUIRED | 8 | `erc20_supply_access_invariants` | SYNR |
| P1_PROMOTE_WITH_GATE | M178 | TOKEN_ERC20 | PROMOTION_CANDIDATE | 23 | `erc20_supply_access_invariants` | _getETHReserve |
