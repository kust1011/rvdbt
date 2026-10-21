#!/usr/bin/env python3
"""Mock-only scalar runner contracts; no RISC-V instructions are executed."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
RUNNERS = {
    'prebuilt-riscv-tests.sh': 'prebuilts/riscv-tests',
    'riscv-tests.sh': 'riscv-tests/isa',
}
UI = ('add addi and andi auipc beq bge bgeu blt bltu bne jal jalr lb lbu lh '
      'lhu lui lw or ori sb sh sll simple slli slt slti sltiu sltu sra srai '
      'srl srli sub sw xor xori').split()
UM = 'div divu mul mulh mulhu mulhsu rem remu'.split()
GUESTS = ['rv32ui-p-' + name for name in UI] + ['rv32um-p-' + name for name in UM]
MOCK = '''#!/usr/bin/env python3
import os
from pathlib import Path
import sys
if sys.argv[1:-1] != ['--fsroot', 'troot', '--cache', 'tcache', '--logs', 'dbt', '--']:
    sys.exit(80)
guest = sys.argv[-1]
with open(os.environ['MOCK_LOG'], 'a') as log:
    log.write(guest + '\\n')
if (Path('troot') / guest).read_text() != 'fresh input':
    sys.exit(81)
sys.exit(7 if guest == os.environ.get('MOCK_FAIL') else 0)
'''


class LegacyScalarRunnerTests(unittest.TestCase):
    def fixture(self, temporary, runner, build_name='build-llvm-19'):
        repo = Path(temporary) / 'repo with spaces'
        (repo / 'scripts').mkdir(parents=True)
        script = repo / 'scripts' / runner
        shutil.copyfile(ROOT / 'scripts' / runner, script)
        inputs = repo / RUNNERS[runner]
        inputs.mkdir(parents=True)
        for guest in GUESTS:
            (inputs / guest).write_text('fresh input')
        build = repo / build_name
        (build / 'bin').mkdir(parents=True)
        engine = build / 'bin/elfrun'
        engine.write_text(MOCK)
        engine.chmod(0o755)
        log = repo / 'mock calls.txt'
        env = {**os.environ, 'MOCK_LOG': str(log)}
        return repo, script, inputs, build, log, env

    def run_script(self, script, env, *args):
        return subprocess.run(['bash', str(script), *map(str, args)],
                              cwd=script.parents[2], env=env,
                              capture_output=True, text=True, timeout=30)

    def calls(self, log):
        return log.read_text().splitlines() if log.exists() else []

    def test_success_default_preserves_guest_set_and_dut_arguments(self):
        for runner in RUNNERS:
            with self.subTest(runner=runner), tempfile.TemporaryDirectory() as tmp:
                repo, script, inputs, build, log, env = self.fixture(tmp, runner)
                result = self.run_script(script, env)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.calls(log), GUESTS)
                self.assertTrue((build / 'troot').is_dir())
                self.assertTrue((build / 'tcache').is_dir())

    def test_relative_and_absolute_build_paths_with_spaces(self):
        for runner in RUNNERS:
            for absolute in (False, True):
                with self.subTest(runner=runner, absolute=absolute), tempfile.TemporaryDirectory() as tmp:
                    repo, script, inputs, build, log, env = self.fixture(tmp, runner, 'custom build')
                    result = self.run_script(script, env, build if absolute else 'custom build')
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(self.calls(log), GUESTS)

    def test_failed_guest_makes_overall_result_nonzero(self):
        for runner in RUNNERS:
            for failed in ('rv32ui-p-add', 'rv32um-p-div'):
                with self.subTest(runner=runner, failed=failed), tempfile.TemporaryDirectory() as tmp:
                    repo, script, inputs, build, log, env = self.fixture(tmp, runner)
                    env['MOCK_FAIL'] = failed
                    result = self.run_script(script, env)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(self.calls(log), GUESTS)

    def test_missing_input_never_executes_stale_binary(self):
        for runner in RUNNERS:
            with self.subTest(runner=runner), tempfile.TemporaryDirectory() as tmp:
                repo, script, inputs, build, log, env = self.fixture(tmp, runner)
                missing = GUESTS[0]
                (inputs / missing).unlink()
                (build / 'troot').mkdir()
                (build / 'troot' / missing).write_text('stale binary')
                result = self.run_script(script, env)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Missing or unreadable input:', result.stderr)
                self.assertEqual(self.calls(log), GUESTS[1:])
                self.assertEqual((build / 'troot' / missing).read_text(), 'stale binary')

    def test_copy_failure_never_executes_stale_binary(self):
        for runner in RUNNERS:
            with self.subTest(runner=runner), tempfile.TemporaryDirectory() as tmp:
                repo, script, inputs, build, log, env = self.fixture(tmp, runner)
                (build / 'troot').mkdir()
                (build / 'troot' / GUESTS[0]).write_text('stale binary')
                tools = repo / 'mock tools'
                tools.mkdir()
                cp = tools / 'cp'
                cp.write_text('#!/bin/sh\nexit 73\n')
                cp.chmod(0o755)
                env['PATH'] = str(tools) + os.pathsep + env['PATH']
                result = self.run_script(script, env)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.calls(log), [])

    def test_missing_build_fails_before_guest_launch(self):
        for runner in RUNNERS:
            with self.subTest(runner=runner), tempfile.TemporaryDirectory() as tmp:
                repo, script, inputs, build, log, env = self.fixture(tmp, runner)
                missing = repo / 'missing build'
                result = self.run_script(script, env, missing)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Missing build directory or executable elfrun:', result.stderr)
                self.assertFalse(missing.exists())
                self.assertEqual(self.calls(log), [])

    def test_missing_or_nonexecutable_elfrun_fails_before_launch(self):
        for runner in RUNNERS:
            for missing in (False, True):
                with self.subTest(runner=runner, missing=missing), tempfile.TemporaryDirectory() as tmp:
                    repo, script, inputs, build, log, env = self.fixture(tmp, runner)
                    engine = build / 'bin/elfrun'
                    if missing:
                        engine.unlink()
                    else:
                        engine.chmod(0o644)
                    result = self.run_script(script, env)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(self.calls(log), [])

    def test_setup_failure_and_extra_arguments_are_errors(self):
        for runner in RUNNERS:
            with self.subTest(runner=runner), tempfile.TemporaryDirectory() as tmp:
                repo, script, inputs, build, log, env = self.fixture(tmp, runner)
                (build / 'troot').write_text('not a directory')
                result = self.run_script(script, env)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.calls(log), [])
                result = self.run_script(script, env, build, 'extra')
                self.assertEqual(result.returncode, 2)
                self.assertEqual(self.calls(log), [])


if __name__ == '__main__':
    unittest.main()
