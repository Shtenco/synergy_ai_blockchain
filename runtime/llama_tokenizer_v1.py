from __future__ import annotations

from pathlib import Path

import regex

from .gguf_v3 import GGUFFile


class LlamaTokenizerError(ValueError):
    pass


_LLAMA_BPE_PATTERN = regex.compile(
    r"(?i:'s|'t|'re|'ve|'m|'ll|'d)"
    r"|[^\r\n\p{L}\p{N}]?\p{L}+"
    r"|\p{N}{1,3}"
    r"| ?[^\s\p{L}\p{N}]+[\r\n]*"
    r"|\s*[\r\n]+"
    r"|\s+(?!\S)"
    r"|\s+"
)


class LlamaBpeTokenizer:
    def __init__(self, gguf_path: str | Path):
        with GGUFFile(gguf_path) as g:
            if g.metadata.get("tokenizer.ggml.model") != "gpt2":
                raise LlamaTokenizerError("only gpt2 tokenizer supported")
            self.tokens: list[str] = g.metadata["tokenizer.ggml.tokens"]
            self.merges: list[str] = g.metadata["tokenizer.ggml.merges"]
            self.token_types: list[int] = g.metadata["tokenizer.ggml.token_type"]
            self.bos_token_id: int = g.metadata["tokenizer.ggml.bos_token_id"]
            self.eos_token_id: int = g.metadata["tokenizer.ggml.eos_token_id"]
            self.pretokenizer: str = g.metadata.get("tokenizer.ggml.pre", "")
            self.chat_template: str = g.metadata.get("tokenizer.chat_template", "")

        if self.pretokenizer != "llama-bpe":
            raise LlamaTokenizerError(f"unsupported pre-tokenizer {self.pretokenizer!r}")

        self._byte_encoder = _bytes_to_unicode()
        self._byte_decoder = {v: k for k, v in self._byte_encoder.items()}
        self._token_to_id = {t: i for i, t in enumerate(self.tokens)}
        self._merge_ranks = {tuple(m.split(" ")): i for i, m in enumerate(self.merges)}
        self._cache: dict[str, list[str]] = {}
        self.special_token_ids = {i for i, kind in enumerate(self.token_types) if kind == 3}
        self.eog_token_ids = {
            i for i in self.special_token_ids
            if self.tokens[i] in {"<|end_of_text|>", "<|eom_id|>", "<|eot_id|>"}
        }

    def encode(self, text: str, add_bos: bool = True) -> list[int]:
        ids: list[int] = []
        if add_bos:
            ids.append(self.bos_token_id)
        for token in self._bpe_tokenize(text):
            ids.append(self._token_to_id[token])
        return ids

    def decode(self, ids: list[int], skip_special: bool = True) -> str:
        out: list[str] = []
        for i in ids:
            if not 0 <= i < len(self.tokens):
                raise LlamaTokenizerError(f"token ID {i} outside vocabulary")
            if skip_special and i in self.special_token_ids:
                continue
            out.append(self.tokens[i])
        text = "".join(out)
        return bytearray([self._byte_decoder[c] for c in text]).decode("utf-8", errors="replace")

    def _bpe_tokenize(self, text: str) -> list[str]:
        if text in self._cache:
            return self._cache[text]
        words = _LLAMA_BPE_PATTERN.findall(text)
        result: list[str] = []
        for word in words:
            token = "".join(self._byte_encoder[b] for b in word.encode("utf-8"))
            parts = self._bpe(token)
            result.extend(parts)
        self._cache[text] = result
        return result

    def _bpe(self, token: str) -> list[str]:
        if len(token) <= 1:
            return [token]
        parts = list(token)
        while True:
            best_rank = None
            best_pair = None
            for i in range(len(parts) - 1):
                pair = (parts[i], parts[i + 1])
                rank = self._merge_ranks.get(pair)
                if rank is not None and (best_rank is None or rank < best_rank):
                    best_rank = rank
                    best_pair = pair
            if best_pair is None:
                break
            merged = best_pair[0] + best_pair[1]
            new_parts: list[str] = []
            i = 0
            while i < len(parts):
                if i < len(parts) - 1 and parts[i] == best_pair[0] and parts[i + 1] == best_pair[1]:
                    new_parts.append(merged)
                    i += 2
                else:
                    new_parts.append(parts[i])
                    i += 1
            parts = new_parts
        return parts


def _bytes_to_unicode() -> dict[int, str]:
    bs = (
        list(range(ord("!"), ord("~") + 1))
        + list(range(ord("\xa1"), ord("\xac") + 1))
        + list(range(ord("\xae"), ord("\xff") + 1))
    )
    cs = bs[:]
    n = 0
    for b in range(256):
        if b not in bs:
            bs.append(b)
            cs.append(256 + n)
            n += 1
    return {b: chr(c) for b, c in zip(bs, cs)}
