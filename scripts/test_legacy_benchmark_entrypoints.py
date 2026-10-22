"""Mock-only wrapper/checker controls; no compiler, emulator or benchmark is run."""
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


REPO = Path(__file__).resolve().parents[1]
SOURCE = REPO / "examples/benchmarks.py"
spec = importlib.util.spec_from_file_location("legacy_bench_under_test", SOURCE)
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


def executable(path, body):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!" + sys.executable + "\n" + body)
    path.chmod(0o755)


class WrapperTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="benchmark mocks ")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo with spaces"
        self.bin = self.root / "mock tools"
        self.log = self.root / "calls.jsonl"
        for name in ("build.sh", "test.sh", "benchmark.sh", "rvdbt_benchmark.sh", "spec2017/ref-no-freq.sh"):
            target = self.repo / "scripts" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO / "scripts" / name, target)
        body = '''import json,os,sys
from pathlib import Path
with open(os.environ['MOCK_LOG'],'a') as f:
 f.write(json.dumps({'args':sys.argv[1:],'CC':os.environ.get('CC'),'CXX':os.environ.get('CXX')})+'\\n')
sys.exit(int(os.environ.get('MOCK_BUILD_RC' if '--build' in sys.argv else 'MOCK_RC','0')))
'''
        for tool in ("python3", "cmake"):
            executable(self.bin / tool, body)
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"], MOCK_LOG=str(self.log))
        for key in ("RVDBT_BUILD_DIR", "RVDBT_PREBUILTS", "LLVM_PATH", "RVDBT_JOBS", "CC", "CXX"):
            self.env.pop(key, None)

    def run_wrapper(self, name, args=(), **env):
        return subprocess.run(["sh", str(self.repo / "scripts" / name), *args],
                              cwd=self.root, env=dict(self.env, **env), capture_output=True, text=True)

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def test_build_source_and_default_paths_ignore_cwd(self):
        result = self.run_wrapper("build.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        configure, build = self.calls()
        self.assertEqual(configure["args"][:4], ["-S", str(self.repo), "-B", str(self.repo / "build-llvm-20")])
        self.assertEqual(configure["CC"], "clang")
        self.assertEqual(build["args"], ["--build", str(self.repo / "build-llvm-20"), "--parallel", "4"])

    def test_build_overrides_and_spaces(self):
        result = self.run_wrapper("build.sh", ["19"], RVDBT_BUILD_DIR="custom build", LLVM_PATH="llvm path", RVDBT_JOBS="2", CC="my cc", CXX="my cxx")
        self.assertEqual(result.returncode, 0, result.stderr)
        configure, build = self.calls()
        self.assertIn(str(self.repo / "custom build"), configure["args"])
        self.assertIn("-DLLVM_PATH=" + str(self.repo / "llvm path"), configure["args"])
        self.assertEqual(configure["CXX"], "my cxx")
        self.assertEqual(build["args"][-1], "2")

    def test_configure_failure_never_builds(self):
        self.assertEqual(self.run_wrapper("build.sh", MOCK_RC="7").returncode, 7)
        self.assertEqual(len(self.calls()), 1)

    def test_build_failure_propagates(self):
        self.assertEqual(self.run_wrapper("build.sh", MOCK_BUILD_RC="9").returncode, 9)
        self.assertEqual(len(self.calls()), 2)

    def test_invalid_parameters_never_launch_tools(self):
        for args, env in ((["bad"], {}), (["19", "20"], {}), ([], {"RVDBT_JOBS": "0"})):
            self.assertNotEqual(self.run_wrapper("build.sh", args, **env).returncode, 0)
        self.assertEqual(self.calls(), [])

    def test_checker_wrappers_paths_modes_and_failure(self):
        modes = {"test.sh": "--objective", "benchmark.sh": "--rvdbt-jit-merge-ls", "rvdbt_benchmark.sh": "--rvdbt-llvmaot-hotspot", "spec2017/ref-no-freq.sh": "--rvdbt-jit-not-freq"}
        for name, mode in modes.items():
            with self.subTest(name=name):
                result = self.run_wrapper(name, ["19"], RVDBT_BUILD_DIR="custom build", RVDBT_PREBUILTS=str(self.root / "guest inputs"), MOCK_RC="17")
                self.assertEqual(result.returncode, 17, result.stderr)
                args = self.calls()[-1]["args"]
                self.assertEqual(args[0], str(self.repo / "examples" / ("benchmarks_nofreq.py" if "no-freq" in name else "benchmarks.py")))
                self.assertEqual(args[args.index("--rvdbt-build-dir") + 1], str(self.repo / "custom build"))
                self.assertEqual(args[args.index("--prebuilts") + 1], str(self.root / "guest inputs"))
                self.assertIn(mode, args)
                self.assertNotIn("--libriscv-build-dir", args)


class CheckerIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="checker mock ")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.build = self.root / "build with spaces"
        self.tools = self.root / "mock tools"
        self.inputs = self.root / "inputs"
        self.guest = self.inputs / "automotive/basicmath/basicmath_loop"
        self.guest.parent.mkdir(parents=True)
        self.guest.write_bytes(b"not a real ELF; mock only")
        self.identity = hashlib.md5(self.guest.read_bytes()).hexdigest()
        self.log = self.root / "launch.jsonl"
        body = '''import hashlib,json,os,sys,time
from pathlib import Path
name=Path(sys.argv[0]).name
with open(os.environ['MOCK_LOG'],'a') as f: f.write(json.dumps({'tool':name,'args':sys.argv[1:]})+'\\n')
if os.environ.get('MOCK_SLEEP')==name: time.sleep(30)
if name=='elfaot':
 cache=Path(next(a.split('=',1)[1] for a in sys.argv if a.startswith('--cache=')))
 guest=Path(next(a.split('=',1)[1] for a in sys.argv if a.startswith('--elf=')))
 identity=hashlib.md5(guest.read_bytes()).hexdigest()
 assert (cache/(identity+'.prof')).is_file()
 if not os.environ.get('MOCK_NO_AOT'): (cache/(identity+'.v128.aot.so')).write_bytes(b'mock AOT')
 (cache/'modulegraph.gv').write_text('mock graph')
elif name=='elfrun':
 cache=Path(next(a.split('=',1)[1] for a in sys.argv if a.startswith('--cache=')))
 root=Path(next(a.split('=',1)[1] for a in sys.argv if a.startswith('--fsroot=')))
 args=sys.argv[sys.argv.index('--')+1:]
 identity=hashlib.md5((root/args[0]).read_bytes()).hexdigest()
 (cache/(identity+'.prof')).write_bytes(b'mock profile')
print('wrong' if os.environ.get('MOCK_WRONG')==name else '42')
sys.exit(int(os.environ.get('MOCK_RC','0')) if os.environ.get('MOCK_FAIL')==name else 0)
'''
        for tool in ("elfrun", "elfaot"):
            executable(self.build / "bin" / tool, body)
        executable(self.tools / "qemu-riscv32", body)
        self.env = dict(os.environ, PATH=str(self.tools) + os.pathsep + os.environ["PATH"], MOCK_LOG=str(self.log), PYTHONDONTWRITEBYTECODE="1")

    def invoke(self, extra=(), runner="benchmarks.py", **env):
        return subprocess.run([sys.executable, str(REPO / "examples" / runner),
                               "--rvdbt-build-dir", str(self.build), "--prebuilts", str(self.inputs),
                               "--rvdbt-jit", *extra], cwd=self.root, env=dict(self.env, **env),
                              capture_output=True, text=True, timeout=10)

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def test_jit_aot_exact_identity_isolated_caches_and_historical_preservation(self):
        old = self.build / "dbtcache"
        old.mkdir()
        (old / "unrelated.prof").write_bytes(b"old")
        (old / (self.identity + ".v128.aot.so")).write_bytes(b"stale")
        output = self.root / "new results"
        result = self.invoke(["--rvdbt-llvmaot", "--rvdbt-qcgaot", "--output-dir", str(output)])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.calls()
        compiles = [c for c in calls if c["tool"] == "elfaot"]
        self.assertEqual(len(compiles), 2)
        caches = [next(a.split("=", 1)[1] for a in c["args"] if a.startswith("--cache=")) for c in compiles]
        self.assertEqual(len(set(caches)), 2)
        for cache in caches:
            self.assertEqual(Path(cache, self.identity + ".v128.aot.so").read_bytes(), b"mock AOT")
            self.assertEqual(Path(cache, self.identity + ".prof").read_bytes(), b"mock profile")
        self.assertEqual((old / (self.identity + ".v128.aot.so")).read_bytes(), b"stale")
        self.assertEqual((old / "unrelated.prof").read_bytes(), b"old")
        self.assertEqual((output / "0/qemu.stdout").read_bytes(), b"42\n")
        self.assertIn("rvdbt-qcgaot", result.stdout.rsplit("AOT size:", 1)[1])

    def test_aot_missing_does_not_use_stale_artifact(self):
        old = self.build / "dbtcache"
        old.mkdir()
        (old / (self.identity + ".v128.aot.so")).write_bytes(b"stale")
        result = self.invoke(["--rvdbt-llvmaot"], MOCK_NO_AOT="1")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("Score: None", result.stdout)
        self.assertEqual(len([c for c in self.calls() if c["tool"] == "elfrun"]), 1)

    def test_nofreq_shared_failure_policy_and_timeout(self):
        for environment in ({"MOCK_FAIL": "qemu-riscv32", "MOCK_RC": "3"}, {"MOCK_FAIL": "elfrun", "MOCK_RC": "4"}, {"MOCK_SLEEP": "elfrun"}):
            with self.subTest(environment=environment):
                result = self.invoke(["--rvdbt-jit-not-freq", "--timeout", "0.1"], runner="benchmarks_nofreq.py", **environment)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("Score: None", result.stdout)
        self.assertIn("timeout", result.stdout)

    def test_nofreq_library_optional_without_library_mode(self):
        result = self.invoke(["--rvdbt-jit-not-freq"], runner="benchmarks_nofreq.py")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [c for c in self.calls() if c["tool"] == "elfrun"]
        self.assertTrue(any("--not-freq=on" in c["args"] for c in calls))
        result = self.invoke(["--libriscv"], runner="benchmarks_nofreq.py")
        self.assertEqual(result.returncode, 2)

    def test_no_qemu_test_rejected_before_execution(self):
        result = self.invoke(["--no-qemu", "--objective", "test"])
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.calls(), [])
        self.assertIn("reference", result.stderr)

    def test_no_qemu_benchmark_is_exit_status_only_without_scores(self):
        (self.tools / "qemu-riscv32").unlink()
        result = self.invoke(["--no-qemu"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Result: exit-status-only:0", result.stdout)
        self.assertIn("Score: None", result.stdout)
        self.assertNotIn("Result: ok:", result.stdout)
        self.assertEqual([c["tool"] for c in self.calls()], ["elfrun"])
        result = self.invoke(["--no-qemu"], MOCK_FAIL="elfrun", MOCK_RC="7")
        self.assertEqual(result.returncode, 1)
        self.assertIn("execution-failed:7", result.stdout)

    def test_missing_tool_prebuilt_and_invalid_build(self):
        (self.build / "bin/elfrun").unlink()
        result = self.invoke()
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.calls(), [])
        self.assertEqual(list(self.build.glob("benchmark-run-*")), [])
        result = self.invoke(["--rvdbt-build-dir", str(self.root / "nonexistent")])
        self.assertEqual(result.returncode, 2)
        self.assertFalse((self.root / "nonexistent").exists())
        # Restore only a mock executable; a missing guest must not trigger compilation.
        executable(self.build / "bin/elfrun", "raise SystemExit(0)\n")
        self.guest.unlink()
        result = self.invoke()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.calls(), [])

    def test_existing_output_directory_is_not_reused(self):
        output = self.root / "old results"
        output.mkdir()
        (output / "preserve").write_text("old")
        result = self.invoke(["--output-dir", str(output)])
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((output / "preserve").read_text(), "old")
        self.assertEqual(self.calls(), [])


class ArtifactTests(unittest.TestCase):
    def test_profile_identity_and_copy_failure_prevent_setup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "guest").write_bytes(b"guest")
            identity = bench.guest_hash(directory, "guest")
            with patch.multiple(bench.RVDBTExec, cache_full_dir=directory, profile_dir=directory):
                for profile in ("wrong-identity", identity):
                    b = bench.Benchmark(directory, ["guest"], name="case with spaces", prof=profile)
                    e = bench.RVDBTExec(True, True)
                    with patch.object(e, "setup") as setup:
                        with self.assertRaises(OSError):
                            b.launch_with(e)
                        setup.assert_not_called()

    def test_checked_profile_copy_handles_spaces_and_preserves_source(self):
        with tempfile.TemporaryDirectory(prefix="profile spaces ") as directory:
            root = Path(directory)
            (root / "guest").write_bytes(b"guest")
            identity = bench.guest_hash(directory, "guest")
            source = root / "case with spaces.prof"
            source.write_bytes(b"original")
            b = bench.Benchmark(directory, ["guest"], name="case with spaces", prof=identity)
            e = bench.RVDBTExec(True, True)
            def setup(*args):
                self.assertEqual(Path(e.cache_path, identity + ".prof").read_bytes(), b"original")
                Path(e.cache_path, identity + ".v128.aot.so").write_bytes(b"compiled")
                e.setup_ok = True
            with patch.multiple(bench.RVDBTExec, cache_full_dir=directory, profile_dir=directory), patch.object(e, "setup", side_effect=setup), patch.object(e, "run"):
                b.launch_with(e)
            self.assertEqual(source.read_bytes(), b"original")

    def test_fresh_jit_profile_overrides_stale_historical_hint(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "guest").write_bytes(b"guest")
            identity = bench.guest_hash(directory, "guest")
            b = bench.Benchmark(directory, ["guest"], prof="stale catalogue hint")
            jit = bench.RVDBTExec(False)
            def run_jit():
                jit.rc = 0
                Path(jit.cache_path, identity + ".prof").write_bytes(b"fresh same-workload profile")
            with patch.multiple(bench.RVDBTExec, cache_full_dir=directory, profile_dir=directory):
                with patch.object(jit, "run", side_effect=run_jit):
                    b.launch_with(jit)
                self.assertEqual(b.profile_path, str(Path(jit.cache_path, identity + ".prof")))
                aot = bench.RVDBTExec(True, True)
                def setup_aot(*args):
                    self.assertEqual(Path(aot.cache_path, identity + ".prof").read_bytes(), b"fresh same-workload profile")
                    Path(aot.cache_path, identity + ".v128.aot.so").write_bytes(b"compiled")
                    aot.setup_ok = True
                with patch.object(aot, "setup", side_effect=setup_aot), patch.object(aot, "run"):
                    b.launch_with(aot)

    def test_existing_guest_output_is_preserved_and_gcc_is_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            b = bench.Benchmark(directory, ["guest", "-o", "result.s"], name="gcc-ref")
            b.output_dir = directory
            output = Path(directory, "result.s")
            output.write_bytes(b"existing")
            e = bench.QEMUExec()
            with patch.object(e, "run") as run:
                with self.assertRaises(FileExistsError):
                    b.launch_with(e)
                run.assert_not_called()
            self.assertEqual(output.read_bytes(), b"existing")
            output.unlink()
            for name, content in (("qemu", b"correct"), ("dut", b"wrong")):
                Path(directory, "result.s." + name).write_bytes(content)
            ref, dut = bench.BaseExec(), bench.BaseExec()
            ref.name, dut.name = "qemu", "dut"
            ref.rc = dut.rc = 0
            self.assertEqual(b.verify(dut, ref), "outfile-diff")

    def test_nofreq_catalogue_and_python310_syntax(self):
        source = REPO / "examples/benchmarks_nofreq.py"
        ast.parse(source.read_text(), feature_version=(3, 10))
        with patch.dict(sys.modules, {"benchmarks": bench}):
            spec = importlib.util.spec_from_file_location("nofreq_catalogue", source)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        cases = module.GetBenchmarks_SPEC2017Rate("/inputs")
        self.assertEqual(len(cases), 11)
        self.assertEqual([(b.name, b.args[0], b.args[-1]) for b in cases[:5]], [(f"gcc-ref{i}", f"ref{i}", f"ref{i}.s") for i in range(1, 6)])
        self.assertEqual(cases[-1].args[-1], "7")
        self.assertEqual(cases[0].prof, "37a45829a600f065d02f8349fde44dec")
        self.assertEqual(len(bench.GetBenchmarks_SPEC2017Rate("/inputs")), 14)


if __name__ == "__main__":
    unittest.main()
