"""Atomic dependency acquisition controls; all network/git operations are mocked."""
import io
import errno
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import fetch_rvv_external as fetch


class ExternalAcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='external fetch mocks ')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.output = self.root / 'new dependencies'
        self.lock = json.loads((fetch.SCRIPTS / 'rvv/sources.lock.json').read_text())['sources']
        self.urls = []
        self.commands = []
        self.fail_download = None
        self.fail_git = None
        self.changed = None
        self.bad_rvvts_license = False
        self.paths = {value: name for name, value in self.lock['ara']['paths'].items()}
        self.paths['LICENSE'] = 'LICENSE'
        for patcher in (patch.object(fetch.urllib.request, 'urlopen', side_effect=self.download),
                        patch.object(fetch.subprocess, 'run', side_effect=self.git)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def download(self, url, timeout):
        self.assertFalse(os.path.lexists(self.output))
        staging, = self.root.glob(self.output.name + '.partial-*')
        self.assertEqual(staging.stat().st_mode & 0o777, 0o700)
        self.assertEqual(staging.parent, self.output.parent)
        self.assertEqual(timeout, 60)
        prefix = 'https://raw.githubusercontent.com/pulp-platform/ara/' + self.lock['ara']['revision'] + '/'
        self.assertTrue(url.startswith(prefix))
        relative = url[len(prefix):]
        name = self.paths[relative]
        self.urls.append(url)
        if len(self.urls) == self.fail_download:
            raise OSError('injected download failure')
        bundled = 'vredsum.original.c' if name == 'vredsum.c' else name
        data = (fetch.SCRIPTS / 'rvv/fixtures/ara-vredsum' / bundled).read_bytes()
        if name == self.changed:
            data = b'wrong pinned bytes'
        # The upstream macro header is intentionally distinct from the bundled adapter.
        if name == 'vector_macros.h':
            data = b'mock upstream header, not the adapted fixture'
        return io.BytesIO(data)

    def git(self, command, check):
        self.assertFalse(os.path.lexists(self.output))
        self.assertTrue(check)
        self.commands.append(command)
        if command[1] == 'clone':
            self.assertEqual(command[2], self.lock['rvvts']['url'])
            checkout = Path(command[3])
            checkout.mkdir()
            content = (fetch.SCRIPTS / 'rvv/fixtures/rvvts-20261089/LICENSE').read_bytes()
            (checkout / 'LICENSE').write_bytes(b'changed' if self.bad_rvvts_license else content)
        else:
            self.assertEqual(command[1], '-C')
            self.assertEqual(command[3:], ['checkout', '--detach', self.lock['rvvts']['revision']])
        if len(self.commands) == self.fail_git:
            raise subprocess.CalledProcessError(7, command)
        return subprocess.CompletedProcess(command, 0)

    def assert_clean_failure(self):
        self.assertFalse(os.path.lexists(self.output))
        self.assertEqual(list(self.root.glob(self.output.name + '.partial-*')), [])

    def test_success_publishes_verified_inputs_and_original_receipt_schema(self):
        receipt = fetch.acquire(self.output)
        self.assertEqual(set(receipt), {'ara', 'rvvts', 'files'})
        self.assertEqual(receipt['ara'], self.lock['ara'])
        self.assertEqual(receipt['rvvts'], self.lock['rvvts'])
        self.assertEqual(json.loads((self.output / 'fetch.json').read_text()), receipt)
        self.assertEqual(len(self.urls), len(self.paths))
        self.assertEqual(len(self.commands), 2)
        for name, digest in receipt['files'].items():
            self.assertTrue(name.startswith('ara/'))
            self.assertFalse(Path(name).is_absolute())
            self.assertEqual(fetch.digest(self.output / name), digest)
        self.assertNotIn('.partial-', json.dumps(receipt))
        self.assertEqual(list(self.root.glob(self.output.name + '.partial-*')), [])

    def test_mid_ara_download_failure_cleans_staging_and_allows_retry(self):
        self.fail_download = 3
        with self.assertRaisesRegex(OSError, 'download failure'):
            fetch.acquire(self.output)
        self.assert_clean_failure()
        self.assertEqual(self.commands, [])
        self.fail_download = None
        fetch.acquire(self.output)
        self.assertTrue((self.output / 'fetch.json').is_file())

    def test_ara_hash_mismatch_cleans_staging(self):
        self.changed = 'printf.c'
        with self.assertRaisesRegex(ValueError, 'pinned Ara input differs: printf.c'):
            fetch.acquire(self.output)
        self.assert_clean_failure()
        self.assertEqual(self.commands, [])

    def test_ara_license_mismatch_cleans_staging(self):
        self.changed = 'LICENSE'
        with self.assertRaisesRegex(ValueError, 'pinned Ara input differs: LICENSE'):
            fetch.acquire(self.output)
        self.assert_clean_failure()

    def test_git_clone_or_checkout_failure_cleans_staging(self):
        for failure in (1, 2):
            with self.subTest(failure=failure):
                self.commands.clear()
                self.fail_git = failure
                with self.assertRaises(subprocess.CalledProcessError):
                    fetch.acquire(self.output)
                self.assert_clean_failure()

    def test_rvvts_license_mismatch_cleans_staging(self):
        self.bad_rvvts_license = True
        with self.assertRaisesRegex(ValueError, 'pinned RVVTS license differs'):
            fetch.acquire(self.output)
        self.assert_clean_failure()

    def test_existing_output_file_directory_and_symlinks_are_never_touched(self):
        target = self.root / 'preserve'
        target.write_bytes(b'original')
        for kind in ('file', 'directory', 'symlink', 'dangling-symlink'):
            with self.subTest(kind=kind):
                if kind == 'file':
                    self.output.write_bytes(b'existing output')
                elif kind == 'directory':
                    self.output.mkdir()
                    (self.output / 'keep').write_bytes(b'existing child')
                else:
                    self.output.symlink_to(target if kind == 'symlink' else self.root / 'absent')
                with self.assertRaises(FileExistsError):
                    fetch.acquire(self.output)
                if kind == 'directory':
                    self.assertEqual((self.output / 'keep').read_bytes(), b'existing child')
                    (self.output / 'keep').unlink()
                    self.output.rmdir()
                else:
                    if kind == 'file':
                        self.assertEqual(self.output.read_bytes(), b'existing output')
                    else:
                        self.assertTrue(self.output.is_symlink())
                    self.output.unlink()
                self.assertEqual(target.read_bytes(), b'original')
                self.assertEqual(self.urls, [])
                self.assertEqual(self.commands, [])

    def test_output_appearing_at_publish_is_not_replaced(self):
        original_publish = fetch.publish
        for kind in ('empty-directory', 'symlink'):
            with self.subTest(kind=kind):
                target = self.root / 'other-owner'
                target.write_bytes(b'preserve')
                def race(staging, output):
                    if kind == 'empty-directory':
                        output.mkdir()
                    else:
                        output.symlink_to(target)
                    original_publish(staging, output)
                with patch.object(fetch, 'publish', side_effect=race):
                    with self.assertRaises(FileExistsError):
                        fetch.acquire(self.output)
                self.assertEqual(list(self.root.glob(self.output.name + '.partial-*')), [])
                self.assertEqual(target.read_bytes(), b'preserve')
                if kind == 'empty-directory':
                    self.assertEqual(list(self.output.iterdir()), [])
                    self.output.rmdir()
                else:
                    self.assertTrue(self.output.is_symlink())
                    self.output.unlink()

    def test_directory_created_during_acquire_survives_real_publish_collision(self):
        original_git = self.git
        def git_creates_output(command, check):
            result = original_git(command, check)
            if command[1] == '-C':
                self.output.mkdir()
                (self.output / 'other-owner').write_bytes(b'keep')
            return result
        with patch.object(fetch.subprocess, 'run', side_effect=git_creates_output):
            with self.assertRaises(FileExistsError):
                fetch.acquire(self.output)
        self.assertEqual((self.output / 'other-owner').read_bytes(), b'keep')
        self.assertEqual(list(self.output.iterdir()), [self.output / 'other-owner'])
        self.assertEqual(list(self.root.glob(self.output.name + '.partial-*')), [])

    def test_cli_failure_is_nonzero_and_has_no_published_output(self):
        self.fail_download = 2
        with patch('sys.stderr', new_callable=io.StringIO) as stderr:
            with self.assertRaises(SystemExit) as result:
                fetch.main(['--output', str(self.output)])
        self.assertEqual(result.exception.code, 1)
        self.assertIn('External acquisition failed', stderr.getvalue())
        self.assert_clean_failure()

    def test_missing_no_replace_primitive_fails_closed_and_cleans_staging(self):
        with patch.object(fetch.ctypes, 'CDLL', return_value=SimpleNamespace()):
            with self.assertRaises(OSError) as error:
                fetch.acquire(self.output)
        self.assertEqual(error.exception.errno, errno.ENOTSUP)
        self.assert_clean_failure()


if __name__ == '__main__':
    unittest.main()
