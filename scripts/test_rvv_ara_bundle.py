"""Focused offline package boundary rejection tests; no guest executions."""
import json
from pathlib import Path
import tempfile
import unittest

from verify_rvv_ara_bundle import digest, package_path, verify


class PackagePathTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'data').mkdir()
        (self.root / 'data/raw').write_bytes(b'original')

    def test_relative_file(self):
        self.assertEqual(package_path(self.root, 'data/raw').read_bytes(), b'original')

    def test_noncanonical_names_rejected(self):
        for name in ('/etc/passwd', '../raw', 'data/../data/raw', './data/raw',
                     '', 'data//raw', 'data/', 'data\\raw'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                package_path(self.root, name)

    def test_file_symlinks_rejected_even_with_matching_hash(self):
        for target in (self.root / 'data/raw', self.root / 'missing'):
            link = self.root / 'alias'
            link.symlink_to(target)
            (self.root / 'FILES.json').write_text(json.dumps({
                'alias': {'sha256': digest(b'original'), 'bytes': 8}}))
            with self.assertRaisesRegex(ValueError, 'symlink package path'):
                verify(self.root)
            link.unlink()

    def test_parent_symlinks_rejected(self):
        (self.root / 'alias').symlink_to(self.root / 'data', target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'symlink package path'):
            package_path(self.root, 'alias/raw')
        (self.root / 'alias').unlink()
        (self.root / 'alias').symlink_to(self.root.parent, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'symlink package path'):
            package_path(self.root, 'alias/raw')

    def test_manifest_symlink_rejected_before_read(self):
        (self.root / 'manifest').write_text('{}')
        (self.root / 'FILES.json').symlink_to(self.root / 'manifest')
        with self.assertRaisesRegex(ValueError, 'symlink package path'):
            verify(self.root)

    def test_unmanifested_navigation_rejected(self):
        (self.root / 'FILES.json').write_text('{}')
        (self.root / 'ARA_EVIDENCE.json').write_text('{}')
        with self.assertRaisesRegex(ValueError, 'unmanifested package path'):
            verify(self.root)


if __name__ == '__main__':
    unittest.main()
