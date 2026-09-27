"""Storage-split manifest rejects corruption or missing pieces."""

import importlib.util
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "gemma_storage_shards.py"
SPEC = importlib.util.spec_from_file_location("gemma_storage_shards", SCRIPT)
shards = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(shards)


class ShardManifestTests(unittest.TestCase):
    def test_order_integrity_and_missing_piece(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            model = root / "model.gguf"
            model.write_bytes(b"GGUF-test-data")
            first = root / "model.gguf-00001-of-00002.gguf"
            second = root / "model.gguf-00002-of-00002.gguf"
            first.write_bytes(b"GGUF-piece-one")
            second.write_bytes(b"GGUF-piece-two")
            manifest = shards.inventory(model, root)
            self.assertFalse(manifest["executable_layer_stages"])
            self.assertEqual(manifest["shard_count"], 2)
            second.write_bytes(b"GGUF-piece-evil")
            self.assertNotEqual(shards.inventory(model, root), manifest)
            second.unlink()
            with self.assertRaises(ValueError):
                shards.inventory(model, root)


if __name__ == "__main__":
    unittest.main()
