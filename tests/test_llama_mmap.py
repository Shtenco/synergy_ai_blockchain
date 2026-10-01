import struct
import tempfile
from pathlib import Path
import unittest

import numpy as np

from runtime.gguf_v3 import F32, GGUFFile, Q4_K, dequantize_q4_k, dequantize_q6_k
from runtime.llama_mmap_v1 import ACTIVATIONS, LOGITS, TOKENS, decode_payload, encode_activations, encode_logits, encode_tokens


def _string(value: str) -> bytes:
    raw = value.encode()
    return struct.pack("<Q", len(raw)) + raw


def _synthetic_gguf(path: Path) -> None:
    metadata = [
        (_string("general.architecture"), 8, _string("llama")),
        (_string("general.alignment"), 4, struct.pack("<I", 32)),
        (_string("test.array"), 9, struct.pack("<IQ3i", 5, 3, -2, 0, 9)),
    ]
    tensors = [
        _string("weight") + struct.pack("<I2QIQ", 2, 4, 2, F32, 0),
        _string("quant") + struct.pack("<I2QIQ", 2, 256, 1, Q4_K, 32),
    ]
    header = b"GGUF" + struct.pack("<IQQ", 3, len(tensors), len(metadata))
    table = header + b"".join(k + struct.pack("<I", t) + v for k, t, v in metadata) + b"".join(tensors)
    data_start = (len(table) + 31) // 32 * 32
    q4 = struct.pack("<ee", 1.0, 0.0) + bytes([1] * 12) + bytes([0x21] * 128)
    path.write_bytes(table + bytes(data_start - len(table)) + np.arange(8, dtype="<f4").tobytes() + q4)


class GGUFTests(unittest.TestCase):
    def test_parses_v3_metadata_tensors_and_mapped_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.gguf"
            _synthetic_gguf(path)
            with GGUFFile(path) as gguf:
                self.assertEqual(gguf.metadata["general.architecture"], "llama")
                self.assertEqual(gguf.metadata["test.array"], [-2, 0, 9])
                self.assertEqual(gguf.tensor("weight").shape, (2, 4))
                np.testing.assert_array_equal(gguf.tensor("weight").rows(1, 2), [[4, 5, 6, 7]])
                np.testing.assert_array_equal(gguf.tensor("weight").gather(np.array([1, 0])), [[4, 5, 6, 7], [0, 1, 2, 3]])
            with GGUFFile(path, metadata_filter=lambda key: key != "test.array") as gguf:
                self.assertNotIn("test.array", gguf.metadata)
                self.assertEqual(gguf.tensor("weight").shape, (2, 4))

    def test_q4_k_reference_layout(self):
        packed = bytes([1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0])
        block = struct.pack("<ee", 0.5, 0.25) + packed + bytes([0x21] * 128)
        actual = dequantize_q4_k(block)[0]
        scales = [packed[i] & 63 for i in range(4)] + [
            (packed[i + 4] & 15) | ((packed[i - 4] >> 6) << 4) for i in range(4, 8)
        ]
        mins = [packed[i + 4] & 63 for i in range(4)] + [
            (packed[i + 4] >> 4) | ((packed[i] >> 6) << 4) for i in range(4, 8)
        ]
        expected = np.concatenate([
            np.full(32, 0.5 * scales[i] * (1 if i % 2 == 0 else 2) - 0.25 * mins[i], dtype=np.float32)
            for i in range(8)
        ])
        np.testing.assert_array_equal(actual, expected)

    def test_q6_k_reference_layout(self):
        ql = bytes([0x21] * 128)
        qh = bytes([0b11100100] * 64)
        scales = bytes(range(1, 17))
        block = ql + qh + scales + struct.pack("<e", 0.5)
        actual = dequantize_q6_k(block)[0]
        expected_quant = [1 - 32, 17 - 32, 34 - 32, 50 - 32]
        expected = []
        for half in range(2):
            base = half * 8
            for group, quant in enumerate(expected_quant):
                expected.extend([0.5 * (base + group * 2 + 1) * quant] * 16)
                expected.extend([0.5 * (base + group * 2 + 2) * quant] * 16)
        np.testing.assert_array_equal(actual, np.asarray(expected, dtype=np.float32))


class PayloadTests(unittest.TestCase):
    def test_round_trips_all_payload_kinds(self):
        kind, position, values, top = decode_payload(encode_tokens([4, 8], 3))
        self.assertEqual((kind, position, top), (TOKENS, 3, None))
        np.testing.assert_array_equal(values, [4, 8])
        hidden = np.arange(6, dtype=np.float32).reshape(2, 3)
        kind, position, values, _ = decode_payload(encode_activations(hidden, 7))
        self.assertEqual((kind, position), (ACTIVATIONS, 7))
        np.testing.assert_array_equal(values, hidden)
        kind, position, values, top = decode_payload(encode_logits(np.array([1, 5, 2], np.float32), 9))
        self.assertEqual((kind, position, top), (LOGITS, 9, 1))
        np.testing.assert_array_equal(values, [[1, 5, 2]])


if __name__ == "__main__":
    unittest.main()
