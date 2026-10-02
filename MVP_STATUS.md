# MVP STATUS (2026-10-02)

## Done
- Stage 0 (git base): repo/ is a git repo, branch mvp/local-green-20261001,
  merged main + pq-internet-phases-1-3, local additions preserved.
- Stage 1 (gates): ALL GREEN — fmt, check x2, clippy x2, test 368 (default),
  test 388 + 5 ACVP (reference-pq), doctest, release 388, python 18,
  node-runtime 6, solc 0.8.26 x3 contracts.
- Stage 2 (CLI): src/bin/synergy-mvp.rs `finalize` (+ --prev), cli feature,
  tested match / mismatch+slash / chain extension.
- Stage 3 (e2e): scripts/mvp_full_e2e.py — 10/10 steps PASS with real
  llama.cpp inference. Evidence: evidence/mvp_full_e2e.json
  (evidence_root b4c75b02...), bundle regenerated.
- Stage 4 (docs): README "Full local MVP (single command)" section.
- Stage 5 (commits): e7b6176 (e2e), 54aa1cb (evidence+docs). Tree clean.

## Key fixes during e2e
- llama-cli.exe enters interactive chat and hangs -> use llama-completion.exe.
- LlamaCppSingleTokenBackend: stdin=DEVNULL, accept output on nonzero exit
  when stdout non-empty (EOF-by-user after generation), num_tokens param.
- mvp_node.py trained-worker: --tokens flag.
- Receipt lists must be sorted by verifier_id (strict ordering rule).
- Slash one-shot replay test uses state=Consumed (CLI is stateless).

## Remaining
- Stage 6 (cloud): e2-1/e2-2/MIDAS all SSH-reachable, remote PQ tunnels +
  ggml-rpc running. Blocked on user: OCI security-list ingress for current
  home IP (now 188.130.156.212, rules still pin 109.248.159.212).
- Note: this PC (i7-3610QM, 2012) overheats and hard-resets under full
  cargo/llama load. Use -j 2, close Chrome, avoid parallel heavy jobs.
