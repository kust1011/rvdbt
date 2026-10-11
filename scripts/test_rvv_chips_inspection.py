"""Focused temporary-directory regressions for Task94 inspection helpers."""
import json
from pathlib import Path
import tempfile
import unittest

from package_rvv_chips_inspection import copy
from verify_rvv_chips_inspection import safe


class InspectionHelpers(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        (self.root/'data').mkdir()
        (self.root/'data/valid').write_bytes(b'good')
        self.files={'data/valid':{}}
        (self.root/'FILES.json').write_text(json.dumps(self.files))

    def test_valid_manifested_file(self):
        self.assertEqual(safe(self.root,'data/valid',self.files).read_bytes(),b'good')
        self.assertEqual(safe(self.root,'data/valid').read_bytes(),b'good')

    def test_invalid_paths(self):
        for name in ('../data/valid','data/../data/valid',str(self.root/'data/valid'),
                     '','data//valid','data/./valid','data\\valid'):
            with self.subTest(name=name),self.assertRaises(ValueError):
                safe(self.root,name,self.files)

    def test_unmanifested_existing_file(self):
        (self.root/'unlisted').write_bytes(b'good')
        with self.assertRaisesRegex(ValueError,'unmanifested'):
            safe(self.root,'unlisted',self.files)

    def test_symlink_file_and_directory(self):
        (self.root/'link').symlink_to(self.root/'data/valid')
        (self.root/'alias').symlink_to(self.root/'data',target_is_directory=True)
        (self.root/'broken').symlink_to(self.root/'absent')
        (self.root/'outside').symlink_to('/etc/hosts')
        for name in ('link','alias/valid','broken','outside'):
            with self.subTest(name=name),self.assertRaisesRegex(ValueError,'symlink'):
                safe(self.root,name,{name:{}})

    def test_symlink_root_component(self):
        (self.root/'alias').symlink_to(self.root/'data',target_is_directory=True)
        with self.assertRaisesRegex(ValueError,'symlink'):
            safe(self.root/'alias','valid',{'valid':{}})

    def test_symlink_manifest(self):
        (self.root/'FILES.json').unlink()
        (self.root/'manifest').write_text(json.dumps(self.files))
        (self.root/'FILES.json').symlink_to(self.root/'manifest')
        with self.assertRaisesRegex(ValueError,'symlink'):
            safe(self.root,'data/valid')

    def test_copy_replaces_stale_equal_size_destination(self):
        source=self.root/'source';destination=self.root/'nested/destination'
        source.write_bytes(b'old!');copy(source,destination)
        source.write_bytes(b'new!');copy(source,destination)
        self.assertEqual(destination.read_bytes(),b'new!')
        other=self.root/'other-source';other.write_bytes(b'next')
        copy(other,destination)
        self.assertEqual(destination.read_bytes(),b'next')
        copy(source,destination)
        self.assertEqual(destination.read_bytes(),source.read_bytes())


if __name__=='__main__':unittest.main()
