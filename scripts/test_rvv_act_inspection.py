# SPDX-License-Identifier: Apache-2.0
"""Focused path and original-predicate adapter controls, no guest execution."""
import tempfile
import os
import subprocess
import sys
from pathlib import Path
import unittest
from verify_rvv_act_inspection import original_predicates, package_path, validate_receipt


# Small stand-in isolates AST selection; real archived predicates are exercised
# on the clean xbd extraction by check_rvv_act_rejection.py.
AUDIT = '''
raise RuntimeError('runner must never execute')
def accepted(raw,N):
 return raw['returncode']==0 and raw['text'].count(f'RVCP-SUMMARY: TEST PASSED - Test File "{N}.S"')==1 and 'TEST FAILED' not in raw['text']
def audit():
 ok=raw['returncode']==0 and 'SUCCESS' in text and f'TEST SIGRUN - Test File "{N}.S"' in text and 'FAILED' not in text
'''


class Controls(unittest.TestCase):
    def test_optimized_acceptance_rejects_before_payload_access(self):
        script = Path(__file__).with_name('verify_rvv_act_inspection.py').resolve()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)/'missing-payload'
            for flags, optimize in ((['-O'], None), (['-OO'], None), ([], '1'), ([], '2')):
                for entry in ('executable', 'imported'):
                    with self.subTest(flags=flags, optimize=optimize, entry=entry):
                        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
                        env.pop('PYTHONOPTIMIZE', None)
                        if optimize is not None:
                            env['PYTHONOPTIMIZE'] = optimize
                        if entry == 'executable':
                            args = [str(script), str(root)]
                        else:
                            args = ['-c', 'from pathlib import Path; from verify_rvv_act_inspection import verify; '
                                    'print(verify(Path(__import__("sys").argv[1])))', str(root)]
                        result = subprocess.run([sys.executable, *flags, *args], cwd=script.parent,
                                                env=env, capture_output=True, text=True)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn('ACT acceptance requires Python assertions enabled', result.stderr)
                        self.assertNotIn('FileNotFoundError', result.stderr)
                        self.assertNotIn('PASS', result.stdout + result.stderr)

    def test_original_predicates_do_not_execute_runner(self):
        accepted,sail=original_predicates(AUDIT)
        validate_receipt(accepted,{'returncode':0},'RVCP-SUMMARY: TEST PASSED - Test File "c.S"','c')
        validate_receipt(sail,{'returncode':0},'SUCCESS TEST SIGRUN - Test File "c.S"','c')

    def test_wrong_result_exit_zero_rejects(self):
        accepted,_=original_predicates(AUDIT)
        with self.assertRaisesRegex(ValueError,'original predicate rejected'):
            validate_receipt(accepted,{'returncode':0},'RVCP-SUMMARY: TEST FAILED - Test File "c.S"','c')

    def test_ambiguous_sail_predicate_rejects(self):
        with self.assertRaisesRegex(ValueError,'not uniquely resolved'):
            original_predicates(AUDIT+"\ndef other():\n ok='TEST SIGRUN' in text\n")

    def test_traversal_absolute_empty_and_backslash_reject(self):
        for name in ('../receipt','/receipt','a/../receipt','a//b','a/./b','a\\b',''):
            with self.subTest(name=name), self.assertRaises(ValueError):
                package_path(Path('/tmp'),name)

    def test_symlink_parent_rejects(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'alias').symlink_to('/tmp',target_is_directory=True)
            with self.assertRaisesRegex(ValueError,'symlink'):
                package_path(root,'alias/receipt')

    def test_relative_path_allowed(self):
        self.assertEqual(package_path(Path('/tmp'),'records/raw/stdout'),Path('/tmp/records/raw/stdout'))


if __name__=='__main__':unittest.main()
