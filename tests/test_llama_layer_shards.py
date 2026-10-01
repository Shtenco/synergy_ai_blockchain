import unittest

from scripts.llama_layer_shards import canonical_json, layer_ranges, tensor_names


class LlamaLayerShardTests(unittest.TestCase):
    def test_balanced_ranges_cover_every_layer_once(self):
        self.assertEqual(layer_ranges(28, 4), [(0, 7), (7, 14), (14, 21), (21, 28)])

    def test_first_middle_and_tied_final_tensor_sets(self):
        names = {"token_embd.weight", "output_norm.weight"}
        names.update(f"blk.{layer}.weight" for layer in range(4))
        self.assertEqual(tensor_names(names, 0, 1, 4), {"token_embd.weight", "blk.0.weight"})
        self.assertEqual(tensor_names(names, 1, 3, 4), {"blk.1.weight", "blk.2.weight"})
        self.assertEqual(
            tensor_names(names, 3, 4, 4),
            {"blk.3.weight", "output_norm.weight", "token_embd.weight"},
        )

    def test_manifest_serialization_is_canonical(self):
        self.assertEqual(canonical_json({"z": 1, "a": "x"}), '{"a":"x","z":1}\n')


if __name__ == "__main__":
    unittest.main()
