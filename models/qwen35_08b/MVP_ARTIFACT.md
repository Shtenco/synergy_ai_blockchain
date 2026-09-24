# Canonical Qwen3.5 trained artifact for MVP

Model family:
- official base model: `Qwen/Qwen3.5-0.8B`
- license: Apache-2.0

Canonical GGUF for first GREENFULL attempt:
- repository: `bartowski/Qwen_Qwen3.5-0.8B-GGUF`
- file: `Qwen_Qwen3.5-0.8B-Q4_K_M.gguf`
- quantization: `Q4_K_M`
- expected size: ~580 MB
- SHA-256: `fb044e93939a70469c905781334f5de1e6c8b608ced6cbc8c9249bd4127d9526`
- download URL: `https://huggingface.co/bartowski/Qwen_Qwen3.5-0.8B-GGUF/resolve/main/Qwen_Qwen3.5-0.8B-Q4_K_M.gguf?download=true`

Acceptance:
1. downloaded file exists;
2. SHA-256 exactly matches;
3. `llama-cli` supports Qwen3.5;
4. deterministic text inference returns non-empty output;
5. model/runtime hashes are recorded into MVP evidence;
6. the Stage RPC trained-worker adapter runs the same artifact;
7. verifier receipt and final checkpoint bind the resulting output commitment.

Do not substitute a same-name file with a different hash.
