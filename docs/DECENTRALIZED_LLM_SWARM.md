# Decentralized LLM swarm: measured 28.09.2026

Workers run full Llama-3.2-1B-Instruct-Q4_K_M (770 MB) via mmap from SSD —
no RAM fit required. Home Gemma 4 E2B verifies/aggregates. Fan-out is
parallel; agreement + verifier verdict per prompt.

## Topology

| Node | Role | Model | RAM | How it fits |
|------|------|-------|-----|-------------|
| e2-1 (51.170.89.241) | worker | Llama-3.2-1B Q4_K_M | 954 MB | mmap, b11026 ubuntu build |
| e2-2 (129.151.138.7) | worker | Llama-3.2-1B Q4_K_M | 954 MB | mmap, b11026 ubuntu build |
| home | verifier | Gemma 4 E2B-it Q4_K_M | 8 GB | resident, Turbo API :8787 |

RPC offload of Gemma layers to e2 was rejected by llama.cpp fit check
(`failed to fit params`, -ngl 1/2/4 + explicit `--override-tensor`).
Full-model mmap workers are the working pattern on 1 GB boxes.

## Measured (temp 0, max_tokens 10, ctx 256)

| Prompt | e2-1 | e2-2 | Agreement | Gemma verdict |
|--------|------|------|-----------|---------------|
| 2+2? | '2' 20.6s | '2' 25.6s | True (both wrong) | '4' 72.6s |
| Capital of France? | 'Paris' 22.1s | 'Paris' 22.0s | True | 'Paris' 10.7s |
| 7*8? | '76' 21.8s | '76' 21.8s | True (both wrong) | '56' 11.7s |

Workers are deterministic and agree; the verifier corrects systematic
1B errors. Throughput is mmap-paging bound (~20s/answer on E2 micro).
