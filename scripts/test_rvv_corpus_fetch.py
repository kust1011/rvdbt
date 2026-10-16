# SPDX-License-Identifier: MIT
import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock
import shutil
import subprocess

import fetch_rvv_corpus as fetch


class AcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cache = self.root / 'cache'
        self.cache.mkdir()
        self.output = self.root / 'corpus'

    def manifest(self, names=('data/test.S',), link=False):
        path = self.cache / 'tests.tar.gz'
        with tarfile.open(path, 'w:gz') as tar:
            for name in names:
                item = tarfile.TarInfo(name)
                if link:
                    item.type = tarfile.SYMTYPE
                    item.linkname = '/tmp'
                    tar.addfile(item)
                else:
                    item.size = 4
                    tar.addfile(item, io.BytesIO(b'test'))
        return dict(schema='rvv-corpus-release-1', max_files=10, max_members=20,
                    max_unpacked_bytes=100, archives=[dict(name=path.name,
                    format='tar.gz', bytes=path.stat().st_size,
                    sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                    url='https://example.invalid/tests.tar.gz')])

    def reject(self, manifest):
        with self.assertRaises((ValueError, OSError)):
            fetch.install(manifest, self.output, self.cache)
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.glob('corpus.partial-*')), [])

    def test_cached_archive_installs_without_network(self):
        result = fetch.install(self.manifest(), self.output, self.cache)
        self.assertEqual((self.output / 'data/test.S').read_bytes(), b'test')
        self.assertEqual(result, dict(files=1, bytes=4))

    def test_parent_escape(self):
        self.reject(self.manifest(('../outside',)))
        self.assertFalse((self.root / 'outside').exists())

    def test_absolute_path(self):
        self.reject(self.manifest(('/outside',)))

    def test_symlink(self):
        self.reject(self.manifest(link=True))

    def test_duplicate_file(self):
        self.reject(self.manifest(('data/test.S', 'data/test.S')))

    def test_corrupt_cached_archive(self):
        manifest = self.manifest()
        (self.cache / 'tests.tar.gz').write_bytes(b'wrong')
        self.reject(manifest)

    def test_unpacked_limit(self):
        manifest = self.manifest()
        manifest['max_unpacked_bytes'] = 3
        self.reject(manifest)

    def test_directory_limit(self):
        manifest = self.manifest()
        path = self.cache / 'tests.tar.gz'
        with tarfile.open(path, 'w:gz') as tar:
            for i in range(21):
                item = tarfile.TarInfo('dir' + str(i))
                item.type = tarfile.DIRTYPE
                tar.addfile(item)
        manifest['archives'][0].update(bytes=path.stat().st_size,
                                      sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        self.reject(manifest)

    def test_corrupt_gzip_footer_even_when_archive_hash_matches(self):
        manifest = self.manifest()
        path = self.cache / 'tests.tar.gz'
        payload = bytearray(path.read_bytes())
        payload[-8] ^= 1
        path.write_bytes(payload)
        manifest['archives'][0]['sha256'] = hashlib.sha256(payload).hexdigest()
        self.reject(manifest)

    def test_existing_output_not_overwritten(self):
        manifest = self.manifest()
        self.output.mkdir()
        (self.output / 'keep').write_text('original')
        with self.assertRaises(ValueError):
            fetch.install(manifest, self.output, self.cache)
        self.assertEqual((self.output / 'keep').read_text(), 'original')

    def test_http_url_rejected(self):
        manifest = self.manifest()
        manifest['archives'][0]['url'] = 'http://example.invalid/tests.tar.gz'
        self.reject(manifest)

    def test_download_verifies_bytes_and_digest(self):
        manifest = self.manifest()
        path = self.cache / 'tests.tar.gz'
        payload = path.read_bytes()
        path.unlink()
        response = io.BytesIO(payload)
        response.geturl = lambda: 'https://example.invalid/tests.tar.gz'
        with mock.patch.object(fetch.urllib.request, 'urlopen', return_value=response):
            self.assertEqual(fetch.fetch(manifest['archives'][0], self.cache).read_bytes(), payload)

    def test_bad_download_not_published_to_cache(self):
        manifest = self.manifest()
        path = self.cache / 'tests.tar.gz'
        path.unlink()
        response = io.BytesIO(b'corrupt')
        response.geturl = lambda: 'https://example.invalid/tests.tar.gz'
        with mock.patch.object(fetch.urllib.request, 'urlopen', return_value=response):
            with self.assertRaises(ValueError):
                fetch.fetch(manifest['archives'][0], self.cache)
        self.assertEqual(list(self.cache.iterdir()), [])

    @unittest.skipUnless(shutil.which('zstd'), 'zstd is required for this archive format')
    def test_zstd_archive(self):
        manifest = self.manifest()
        tar_bytes = io.BytesIO()
        with tarfile.open(fileobj=tar_bytes, mode='w') as tar:
            member = tarfile.TarInfo('data/test.S')
            member.size = 4
            tar.addfile(member, io.BytesIO(b'test'))
        payload = subprocess.check_output(['zstd', '-q', '-c'], input=tar_bytes.getvalue())
        path = self.cache / 'tests.tar.zst'
        path.write_bytes(payload)
        manifest['archives'][0].update(name=path.name, format='tar.zst', bytes=len(payload),
                                      sha256=hashlib.sha256(payload).hexdigest())
        self.assertEqual(fetch.install(manifest, self.output, self.cache), dict(files=1, bytes=4))


if __name__ == '__main__':
    unittest.main()
