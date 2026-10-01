# Llama 3.2 3B mmap pipeline on two E2 workers

This deployment runs a real contiguous-layer pipeline using prima.cpp:

- rank 0 (`10.0.1.122`): decoder layers 0-13, tokenizer, and output;
- rank 1 (`10.0.1.210`): decoder layers 14-27;
- public IPs: e2-1 `51.170.89.241`, e2-2 `129.151.138.7`
- both nodes map the same Q4_K_M GGUF from local SSD;
- ZMQ transfers intermediate activations over the private OCI subnet;
- the OpenAI-compatible API binds to rank 0 loopback only.

The fixed `-lw 14,14` assignment is important. Automatic scheduling can remove
an E2 node because both workers are slow. Do not add `--prefetch` on these
954 MiB machines: measured cold inference was about four times slower because
the kernel repeatedly evicted and reread GGUF pages.

## Runtime files

```text
/home/ubuntu/prima.cpp/llama-cli
/home/ubuntu/prima.cpp/llama-server
/home/ubuntu/prima.cpp/Llama-3.2-3B-Instruct-Q4_K_M.gguf
/swapfile-prima
```

The GGUF must have SHA-256:

```text
6c1a2b41161032677be168d354123594c0e6e67d2b9227c84f296ad037c728ff
```

Each node needs 4 GiB SSD-backed swap because mmap page cache is still RAM and
the OS needs eviction headroom. Persist it once:

```sh
echo '/swapfile-prima none swap sw 0 0' | sudo tee -a /etc/fstab
```

## Network

Allow TCP `9000-9001` and `10000-10001` only between `10.0.1.122` and
`10.0.1.210`, in both OCI ingress and host INPUT/OUTPUT policy. prima.cpp adds
the rank to each base port.

This ring is private-VCN transport, not the repository's PQ transport. Do not
expose these ports publicly.

## Install

Copy the matching unit to each host, then start rank 1 before rank 0:

```sh
sudo install -m 0644 synergy-prima-rank1.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now synergy-prima-rank1
```

```sh
sudo install -m 0644 synergy-prima-rank0.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now synergy-prima-rank0
```

Call the API from rank 0 or through an SSH/PQ loopback tunnel:

```sh
curl http://127.0.0.1:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"messages":[{"role":"user","content":"What is 2+2?"}],"max_tokens":8,"temperature":0}'
```

## Measured 28.09.2026

`Llama-3.2-3B-Instruct-Q4_K_M.gguf`, 28 layers, 14 layers per E2:

| Mode | Inference total | Prompt rate | Peak RSS rank 0 | Peak RSS rank 1 |
|---|---:|---:|---:|---:|
| `--prefetch` | 242.6 s | 0.33 tok/s | 698 MiB | 687 MiB |
| demand mmap | 64.3 s | 0.16 tok/s | 688 MiB | 640 MiB |

The prefetch run generated `2+2 = 4` and both ranks exited with status 0.
Demand mmap is the deployed mode because it minimizes rereads and amortizes
the 39-second model initialization in persistent server mode.

The deployed API returned `4` for a 22-token chat prompt. The first persistent
request took about 66 seconds end to end. SSD paging makes this fit, but it is
not fast compared with keeping all weights resident; `99% SSD` and high token
throughput are conflicting requirements on these two-core E2 shapes.
