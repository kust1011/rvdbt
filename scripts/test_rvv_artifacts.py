import tempfile
import unittest
from pathlib import Path
from rvv_tests import digest
from verify_rvv_artifacts import verify


class ArtifactTests(unittest.TestCase):
    def test_missing_changed_and_ambiguous_payloads_are_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            p = root / 'a.tar.gz'
            p.write_bytes(b'archive')
            registry = {'artifacts': [{'file': p.name, 'bytes': 7, 'sha256': digest(p)}]}
            self.assertEqual(verify(registry, root), [p.name])
            p.write_bytes(b'changed')
            with self.assertRaises(ValueError): verify(registry, root)
            p.unlink()
            with self.assertRaises(ValueError): verify(registry, root)
            p.write_bytes(b'archive')
            (root / 'duplicate').mkdir()
            (root / 'duplicate' / p.name).write_bytes(b'archive')
            with self.assertRaises(ValueError): verify(registry, root)
