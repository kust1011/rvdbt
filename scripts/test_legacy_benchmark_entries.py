"""Exercise shell entry points with a mock Python, never benchmark a guest."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
ENTRIES = {
    'hotspot.sh': ['--rvdbt-jit-merge-ls', '--rvdbt-llvmaot-hotspot'],
    'test-rv32emu-im.sh': ['--cache-dir', 'rv32emu-no-prop', '--no-qemu',
                         '--rvdbt-jit', '--rvdbt-llvmaot', '--rvdbt-llvmaot-hotspot',
                         '--rvdbt-llvmaot-noprop', '--benchmark', 'rv32emu'],
    'rv32emu-not-freq.sh': ['--cache-dir', 'spec2017_not_freq',
                          '--rvdbt-jit-not-freq', '--benchmark', 'rv32emu'],
    'spec2017/ref.sh': ['--cache-dir', 'spec2017-ref-tb', '--no-qemu',
                        '--rvdbt-llvmaot-hotspot', '--benchmark', 'SPEC2017Rate'],
    'spec2017/ref-no-prop.sh': ['--cache-dir', 'spec2017-ref-tb-noprop', '--no-qemu',
                               '--rvdbt-llvmaot-hotspot', '--rvdbt-llvmaot-noprop',
                               '--benchmark', 'SPEC2017Rate'],
    'spec2017/train.sh': ['--cache-dir', 'spec2017-train', '--no-qemu',
                          '--rvdbt-llvmaot-hotspot', '--benchmark', 'SPEC2017RateTrain'],
}


class LegacyBenchmarkEntries(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='benchmark entries ')
        self.addCleanup(temporary.cleanup)
        self.cwd = Path(temporary.name)
        self.repo = self.cwd / 'repo with spaces'
        for name in [*ENTRIES, 'spec2017/test.sh']:
            target = self.repo / 'scripts' / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / 'scripts' / name, target)
        tools = self.cwd / 'tools'
        tools.mkdir()
        python = tools / 'python3'
        # Use the actual interpreter explicitly to avoid recursive PATH resolution.
        import sys
        python.write_text('#!' + sys.executable + '\n'
                          'import json, os, sys\n'
                          'print(json.dumps([os.getcwd(), sys.argv[1:]]))\n'
                          'sys.exit(int(os.environ.get("MOCK_RC", "0")))\n')
        python.chmod(0o755)
        self.env = {**os.environ, 'PATH': str(tools) + os.pathsep + os.environ['PATH'],
                    'MOCK_RC': '0'}

    def run_entry(self, name, *args):
        return subprocess.run(['bash', str(self.repo / 'scripts' / name), *args],
                              cwd=self.cwd, env=self.env, text=True,
                              capture_output=True, timeout=10)

    def test_paths_modes_and_arguments_are_preserved(self):
        for name, flags in ENTRIES.items():
            for version in (None, '19'):
                with self.subTest(name=name, version=version):
                    result = self.run_entry(name, *([] if version is None else [version]))
                    self.assertEqual(result.returncode, 0, result.stderr)
                    cwd, args = json.loads(result.stdout)
                    self.assertEqual(cwd, str(self.repo))
                    gcc = ('riscv32-unknown-linux-gnu-gcc' if name == 'test-rv32emu-im.sh'
                           else 'riscv32-unknown-elf-gcc')
                    self.assertEqual(args, [str(self.repo / 'examples/benchmarks.py'),
                                           '--rvdbt-build-dir',
                                           str(self.repo / ('build-llvm-' + (version or '20'))),
                                           '--prebuilts', str(self.repo / 'prebuilts'),
                                           '--riscv32-gcc', gcc, *flags])

    def test_failure_is_propagated(self):
        self.env['MOCK_RC'] = '37'
        for name in ENTRIES:
            with self.subTest(name=name):
                self.assertEqual(self.run_entry(name).returncode, 37)

    def test_invalid_arguments_do_not_launch_runner(self):
        for name in ENTRIES:
            for args in [('bad',), ('20', 'extra')]:
                with self.subTest(name=name, args=args):
                    result = self.run_entry(name, *args)
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, '')

    def test_undefined_spec_test_input_is_not_substituted(self):
        result = self.run_entry('spec2017/test.sh')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, '')
        self.assertIn('no workload definition', result.stderr)


if __name__ == '__main__':
    unittest.main()
