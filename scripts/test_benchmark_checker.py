"""Checker negative controls; no RISC-V compiler or emulator required."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "examples/benchmarks.py"
spec = importlib.util.spec_from_file_location("benchmarks", SOURCE)
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


def execution(name="dut", rc=0, output=b"42", seconds=1):
    return SimpleNamespace(name=name, rc=rc, out=output, err=b"", time=seconds,
                           aot_size=0, aot_time=0)


class CheckerTests(unittest.TestCase):
    def test_wrong_stdout_has_no_score(self):
        b = bench.Benchmark(".", ["guest"], cmp_out=True)
        result = b.result(execution(output=b"999"), execution("ref"))
        self.assertEqual(result.res, "stdout:0")
        self.assertIsNone(result.score)

    def test_same_failure_and_reference_self_fail(self):
        b = bench.Benchmark(".", ["guest"])
        ref = execution("ref", rc=1)
        for dut in (ref, execution(rc=1), execution()):
            result = b.result(dut, ref)
            self.assertEqual(result.res.split(":")[0], "reference-failed")
            self.assertIsNone(result.score)

    def test_explicit_expected_exit(self):
        b = bench.Benchmark(".", ["guest"], cmp_out=True, expected_rc=1)
        self.assertEqual(b.result(execution(rc=1), execution("ref", rc=1)).res, "ok:1")
        self.assertEqual(b.result(execution(rc=2), execution("ref", rc=1)).res, "execution-failed:2")

    def test_missing_stdout_not_equal(self):
        b = bench.Benchmark(".", ["guest"], cmp_out=True)
        self.assertEqual(b.verify(execution(output=None), execution(output=None)), "stdout-missing")

    def test_file_content_not_metadata(self):
        with tempfile.TemporaryDirectory() as root:
            b = bench.Benchmark(root, ["guest"], ofile="out")
            dut, ref = execution(), execution("ref")
            a, z = Path(b.get_ofile(dut)), Path(b.get_ofile(ref))
            a.write_bytes(b"bad"); z.write_bytes(b"yes")
            os.utime(a, (100, 100)); os.utime(z, (100, 100))
            self.assertEqual(b.verify(dut, ref), "outfile-diff")
            z.unlink()
            self.assertEqual(b.verify(dut, ref), "reference-outfile-missing")
            z.write_bytes(b"yes"); a.unlink()
            self.assertEqual(b.verify(dut, ref), "outfile-missing")

    def test_file_comparison_is_not_cached_across_runs(self):
        with tempfile.TemporaryDirectory() as root:
            b = bench.Benchmark(root, ["guest"], ofile="out")
            dut, ref = execution(), execution("ref")
            a, z = Path(b.get_ofile(dut)), Path(b.get_ofile(ref))
            for p in (a, z):
                p.write_bytes(b"yes")
                os.utime(p, (100, 100))
            self.assertIsNone(b.verify(dut, ref))
            a.write_bytes(b"bad")
            os.utime(a, (100, 100))
            self.assertEqual(b.verify(dut, ref), "outfile-diff")

    def test_failed_setup_and_missing_prebuilt(self):
        b = bench.Benchmark(".", ["guest"])
        dut = execution()
        dut.failure = "setup-failed"
        self.assertIsNone(b.result(dut, execution("ref")).score)
        with tempfile.TemporaryDirectory() as root:
            self.assertFalse(bench.compile_benchmark(None, root, "missing"))

    def test_timeout_reaps_process(self):
        p = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(30)"],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             start_new_session=True)
        with patch.object(bench, "EXECUTION_TIMEOUT", .05):
            with self.assertRaises(subprocess.TimeoutExpired):
                bench.collect_output(p)
        self.assertIsNotNone(p.returncode)

    def test_qemu_does_not_replace_guest_file_with_stdout(self):
        with tempfile.TemporaryDirectory() as root:
            b = bench.Benchmark(root, ["-c", "from pathlib import Path;Path('out').write_text('guest');print('stdout')"], ofile="out")
            Path(root, "out").write_text("stale")
            with patch.object(bench.QEMUExec, "bin_path", sys.executable):
                ref = b.launch_with(bench.QEMUExec())
            self.assertEqual(Path(b.get_ofile(ref)).read_text(), "guest")
            self.assertEqual(ref.out, b"stdout\n")

    def test_job_process_exit_and_failed_score(self):
        # Run the real job driver in a subprocess with tiny deterministic engines.
        template = '''
import importlib.util,sys
from types import SimpleNamespace
s=importlib.util.spec_from_file_location('bench',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
b=m.Benchmark('.', ['guest'], cmp_out=True)
m.GetBenchmarks=lambda opts:[b]
m.compile_benchmark=lambda *args: {build}
class Fake(m.BaseExec):
 def __init__(self,*args,**kwargs):
  super().__init__();self.name='dut'
 def run(self):
  self.rc=0;self.out={output};self.time=1
class Ref(Fake):
 def __init__(self):
  super().__init__();self.name='ref'
 def run(self):
  super().run();self.out=b'42';self.rc={ref_rc}
m.QEMUExec=Ref;m.RVDBTExec=Fake
opts=SimpleNamespace(no_qemu=False,libriscv=False,rvdbt_jit=True,rvdbt_jit_not_freq=False,rvdbt_jit_merge_ls=False,rvdbt_qcgaot=False,rvdbt_llvmaot=False,rvdbt_llvmaot_1000=False,rvdbt_llvmaot_opt=False,rvdbt_llvmaot_hotspot=False,rvdbt_llvmaot_noprop=False,riscv32_gcc=None,objective='test')
sys.exit(m.RunTests(opts))
'''
        for build, output, rc, expected in [(True, "b'42'", 0, 0), (True, "b'999'", 0, 1), (True, "b'42'", 1, 1), (False, "b'42'", 0, 1)]:
            result = subprocess.run([sys.executable, "-c", template.format(build=build, output=output, ref_rc=rc), str(SOURCE)], capture_output=True, text=True)
            self.assertEqual(result.returncode, expected, result.stderr)
            if output == "b'999'":
                self.assertIn("Score: None", result.stdout)


if __name__ == "__main__":
    unittest.main()
