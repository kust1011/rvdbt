#!/usr/bin/env python3
"""Mock-only legacy Spike/DUT exit-status checks, not ISA validation."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
UI = ('add addi and andi auipc beq bge bgeu blt bltu bne jal jalr lb lbu lh '
      'lhu lui lw or ori sb sh sll simple slli slt slti sltiu sltu sra srai '
      'srl srli sub sw xor xori').split()
UM = 'div divu mul mulh mulhu mulhsu rem remu'.split()
GUESTS = ['rv32ui-p-' + name for name in UI] + ['rv32um-p-' + name for name in UM]
MOCK = '''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys
role = 'dut' if Path(sys.argv[0]).name == 'elfrun' else 'spike'
if role == 'spike':
    if len(sys.argv) != 3 or sys.argv[1] != '--isa=RV32IM':
        sys.exit(80)
    path = Path(sys.argv[2])
    guest = path.name
    if str(path) != 'troot/' + guest:
        sys.exit(81)
else:
    if sys.argv[1:-1] != ['--fsroot', 'troot', '--cache', 'tcache', '--logs', 'dbt', '--']:
        sys.exit(82)
    guest = sys.argv[-1]
    path = Path('troot') / guest
with open(os.environ['MOCK_LOG'], 'a') as log:
    log.write(json.dumps({'role': role, 'guest': guest}) + '\\n')
if path.read_text() != 'fresh input':
    sys.exit(83)
if guest == os.environ.get('MOCK_FAIL_GUEST'):
    sys.exit(int(os.environ.get('MOCK_' + role.upper() + '_RC', '0')))
sys.exit(0)
'''


class LegacySpikeRunnerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='legacy spike ')
        self.addCleanup(temporary.cleanup)
        self.cwd = Path(temporary.name)
        self.repo = self.cwd / 'repo with spaces'
        (self.repo / 'scripts').mkdir(parents=True)
        self.script = self.repo / 'scripts/riscv-tests-spike.sh'
        shutil.copyfile(ROOT / 'scripts/riscv-tests-spike.sh', self.script)
        self.inputs = self.repo / 'riscv-tests/isa'
        self.inputs.mkdir(parents=True)
        for guest in GUESTS:
            (self.inputs / guest).write_text('fresh input')
        self.build = self.repo / 'build-llvm-19'
        (self.build / 'bin').mkdir(parents=True)
        self.engine = self.build / 'bin/elfrun'
        self.engine.write_text(MOCK)
        self.engine.chmod(0o755)
        self.tools = self.repo / 'tools with spaces'
        self.tools.mkdir()
        self.spike = self.tools / 'spike'
        self.spike.write_text(MOCK)
        self.spike.chmod(0o755)
        self.log = self.repo / 'calls.jsonl'
        self.env = {**os.environ, 'SPIKE': str(self.spike), 'MOCK_LOG': str(self.log)}
        for name in ('MOCK_FAIL_GUEST', 'MOCK_SPIKE_RC', 'MOCK_DUT_RC'):
            self.env.pop(name, None)

    def run_script(self, *args):
        return subprocess.run(['bash', str(self.script), *map(str, args)],
                              cwd=self.cwd, env=self.env, text=True,
                              capture_output=True, timeout=30)

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def expected_calls(self, guests=GUESTS):
        return [{'role': role, 'guest': guest} for guest in guests for role in ('spike', 'dut')]

    def reset_log(self):
        if self.log.exists():
            self.log.unlink()

    def test_success_preserves_guests_isa_and_dut_arguments(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls(), self.expected_calls())
        self.assertEqual(result.stdout.count('Both exit-status checks passed'), len(GUESTS))

    def test_same_nonzero_is_not_a_pass(self):
        for rc in ('7', '127'):
            for guest in (GUESTS[0], 'rv32um-p-div'):
                with self.subTest(rc=rc, guest=guest):
                    self.reset_log()
                    self.env.update(MOCK_FAIL_GUEST=guest, MOCK_SPIKE_RC=rc, MOCK_DUT_RC=rc)
                    result = self.run_script()
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(self.calls(), self.expected_calls())
                    self.assertEqual(result.stdout.count('Both exit-status checks passed'), len(GUESTS) - 1)
                    self.assertIn('Exit-status check failed', result.stderr)

    def test_either_side_failure_is_nonzero(self):
        for spike_rc, dut_rc in (('9', '0'), ('0', '9')):
            with self.subTest(spike=spike_rc, dut=dut_rc):
                self.reset_log()
                self.env.update(MOCK_FAIL_GUEST=GUESTS[0], MOCK_SPIKE_RC=spike_rc, MOCK_DUT_RC=dut_rc)
                result = self.run_script()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.calls(), self.expected_calls())
                self.assertEqual(result.stdout.count('Both exit-status checks passed'), len(GUESTS) - 1)

    def test_missing_or_nonexecutable_spike_fails_before_launch(self):
        for tool in (self.tools / 'missing spike', self.spike):
            with self.subTest(tool=tool):
                self.env['SPIKE'] = str(tool)
                self.spike.chmod(0o644)
                result = self.run_script()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Missing executable Spike:', result.stderr)
                self.assertEqual(self.calls(), [])
                self.assertFalse((self.build / 'troot').exists())

    def test_missing_build_or_dut_fails_before_launch(self):
        result = self.run_script(self.repo / 'missing build')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(), [])
        for missing in (False, True):
            with self.subTest(missing=missing):
                if missing:
                    self.engine.unlink()
                else:
                    self.engine.chmod(0o644)
                result = self.run_script()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Missing build directory or executable elfrun:', result.stderr)
                self.assertEqual(self.calls(), [])

    def test_missing_input_never_runs_stale_guest(self):
        (self.inputs / GUESTS[0]).unlink()
        (self.build / 'troot').mkdir()
        stale = self.build / 'troot' / GUESTS[0]
        stale.write_text('stale binary')
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Missing or unreadable input:', result.stderr)
        self.assertEqual(self.calls(), self.expected_calls(GUESTS[1:]))
        self.assertEqual(stale.read_text(), 'stale binary')

    def test_failed_copy_launches_neither_tool(self):
        (self.build / 'troot').mkdir()
        stale = self.build / 'troot' / GUESTS[0]
        stale.write_text('stale binary')
        cp = self.tools / 'cp'
        cp.write_text('#!/bin/sh\nexit 73\n')
        cp.chmod(0o755)
        self.env['PATH'] = str(self.tools) + os.pathsep + self.env['PATH']
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(), [])
        self.assertEqual(stale.read_text(), 'stale binary')

    def test_spaces_relative_and_absolute_build_and_spike_paths(self):
        new_build = self.repo / 'custom build'
        self.build.rename(new_build)
        self.env['SPIKE'] = os.path.relpath(self.spike, self.cwd)
        for argument in ('custom build', new_build):
            with self.subTest(build=argument):
                self.reset_log()
                result = self.run_script(argument)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.calls(), self.expected_calls())

    def test_default_spike_resolves_from_path(self):
        self.env.pop('SPIKE')
        self.env['PATH'] = str(self.tools) + os.pathsep + self.env['PATH']
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls(), self.expected_calls())

    def test_extra_arguments_and_setup_failure_are_nonzero(self):
        result = self.run_script(self.build, 'extra')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.calls(), [])
        (self.build / 'troot').write_text('not a directory')
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(), [])


if __name__ == '__main__':
    unittest.main()
