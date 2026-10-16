import csv
import optparse
import os
import subprocess
import filecmp
import sys
import time
from typing import Type
import glob
import signal
import math

EXECUTION_TIMEOUT = 600


def collect_output(process):
    try:
        return process.communicate(timeout=EXECUTION_TIMEOUT)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
        raise

class BaseExec:
    def __init__(self):
        self.name = None
        self.root = None
        self.args = None
        self.rc = None
        self.out = None
        self.err = None
        self.time = None
        self.aot_size = 0
        self.aot_time = 0

    def setup(self, root, cmd):
        self.root = root
        self.args = cmd
    
    def print_dir(self):
        print(f"Under {self.root}")

    def run(self):
        pass


class QEMUExec(BaseExec):
    bin_path = "qemu-riscv32"

    def __init__(self):
        super().__init__()
        self.name = "qemu"
        self.aot_size = 0
        self.aot_time = 0

    def run(self):
        pargs = [QEMUExec.bin_path] + self.args
        self.print_dir()
        print(" ".join(pargs))
        timer = time.time()
        p = subprocess.Popen(pargs, cwd=self.root,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        self.out, self.err = collect_output(p)
        timer = time.time() - timer
        self.rc = p.returncode
        self.time = timer
        

class LIBRISCVExec(BaseExec):
    build_dir = None

    def __init__(self, mode):
        super().__init__()
        # mode: "interp" (interpreter) or "bt" (binary translation)
        self.name = f"rvlinux-{mode}"
        self.mode = mode

    def setup(self, root, cmd):
        super().setup(root, cmd)
        # No setup needed for interpreter mode
        if self.mode == "interp":
            self.setup_ok = True
            return
        
        # Setup environment for binary translation mode
        env = os.environ.copy()
        
        # Run setup compilation if needed
        pargs = [LIBRISCVExec.build_dir + "/rvlinux", self.root + "/" + self.args[0]]
        self.bin_path = LIBRISCVExec.build_dir + "/rvlinux"
        p = subprocess.Popen(pargs, cwd=LIBRISCVExec.build_dir,
                           env=env,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, start_new_session=True)
        self.out, self.err = collect_output(p)
        self.rc = p.returncode
        self.setup_ok = self.rc == 0

    def run(self):
        pargs = [LIBRISCVExec.build_dir + "/rvlinux"] + self.args
        self.print_dir()
        print(" ".join(pargs))
        env = os.environ.copy()
        
        if self.mode == "interp":
            pargs.append("--no-translate")
        
        timer = time.time()
        p = subprocess.Popen(pargs, cwd=self.root,
                           env=env,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, start_new_session=True)
        self.out, self.err = collect_output(p)
        timer = time.time() - timer
        self.rc = p.returncode
        self.time = timer

class RVDBTExec(BaseExec):
    build_dir = None
    cache_dir = None

    def __init__(self, aot, llvm=False, hotspot_threshold=0, jit_merge_ls=False, llvmopt=False, not_freq=False, noprop=False):
        super().__init__()
        self.name = "rvdbt-" + ("jit", ("qcgaot", "llvmaot")[llvm])[aot] + ("", "-opt")[llvmopt]
        if jit_merge_ls:
            self.name += "-merge-ls"
        if hotspot_threshold > 0:
            self.name += "-hotspot-" + str(hotspot_threshold)
        if not_freq:
            self.name += "-no-freq"
        if noprop:
            self.name += "-noprop"
        self.aot = aot
        self.llvm = llvm
        self.hotspot_threshold = hotspot_threshold
        self.jit_merge_ls = jit_merge_ls
        self.llvmopt = llvmopt
        self.not_freq = not_freq
        self.noprop = noprop
    def setup(self, root, cmd):
        super().setup(root, cmd)
        if not self.aot:
            self.setup_ok = True
            return
        # make sure dbtcache exists
        pargs = [RVDBTExec.build_dir + "/bin/elfaot",
                 "--propagate-exec-count=" + ("on", "off")[self.noprop],
                 "--cache=" + RVDBTExec.cache_dir,
                 "--llvm=" + ("off", "on")[self.llvm],
                 "--threshold=" + str(self.hotspot_threshold),
                 "--elf=" + self.root + "/" + self.args[0],
                 "--mgdump=" + RVDBTExec.cache_dir,
                 "--llvmopt=" + ("off", "on")[self.llvmopt]]
        print(" ".join(pargs))
        start_time = time.time()
        p = subprocess.Popen(pargs, cwd=RVDBTExec.build_dir,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        self.out, self.err = collect_output(p)
        self.aot_time = time.time() - start_time
        print(f"AOT time: {self.aot_time:.2f} seconds")
        self.rc = p.returncode
        self.setup_ok = self.rc == 0

    def run(self):
        if not self.setup_ok:
            return
        pargs = [RVDBTExec.build_dir + "/bin/elfrun",
                 "--cache=" + RVDBTExec.cache_dir,
                 "--fsroot=" + self.root,
                 "--not-freq=" + ("off", "on")[self.not_freq],
                 "--aot=" + ("off", "on")[self.aot],
                 "--merge-ls=" + ("off", "on")[self.jit_merge_ls]]
        pargs += ["--"] + self.args
        
        self.print_dir()
        print(" ".join(pargs))
        timer = time.time()
        p = subprocess.Popen(pargs, cwd=RVDBTExec.build_dir,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        self.out, self.err = collect_output(p)
        timer = time.time() - timer
        self.rc = p.returncode
        self.time = timer

def get_latest_aot_so_hash():
    """Get the filename without extension of the most recently created .aot.so file in the cache directory."""
    
    # Get the cache directory
    cache_dir = RVDBTExec.build_dir + "/" + RVDBTExec.cache_dir + "/"
    
    # Find all .aot.so files
    aot_so_files = glob.glob(os.path.join(cache_dir, "*.aot.so"))
    
    if not aot_so_files:
        raise FileNotFoundError("No .aot.so files found in the cache directory")
    
    latest_aot_so = max(aot_so_files, key=os.path.getmtime)
    
    return os.path.basename(latest_aot_so).split(".")[0]

def get_latest_prof_hash():
    """Get the filename without extension of the most recently created .prof file in the cache directory."""
    cache_dir = RVDBTExec.build_dir + "/" + RVDBTExec.cache_dir + "/"
    prof_files = glob.glob(os.path.join(cache_dir, "*.prof"))
    if not prof_files:
        raise FileNotFoundError("No .prof files found in the cache directory")
    latest_prof = max(prof_files, key=os.path.getmtime)
    return os.path.basename(latest_prof).split(".")[0]

class Benchmark:
    def __init__(self, root, args, cmp_out=False, ofile=None, name=None, prof=None, expected_rc=0):
        self.name = name
        if self.name is None:
            self.name = args[0]
        self.root = root
        self.args = args
        self.cmp_out = cmp_out  
        self.ofile = self.root + "/" + ofile if ofile is not None else None
        self.prof = prof
        self.expected_rc = expected_rc

    def get_ofile(self, exec):
        assert (self.ofile is not None)
        return self.ofile + "." + exec.name
    
    def set_ofile(self, ofile):
        self.ofile = self.root + "/" + ofile

    def launch_with(self, exec: BaseExec):
        # A failed run must not inherit a previous run's output file.
        if self.ofile:
            for path in (self.ofile, self.get_ofile(exec)):
                if os.path.isfile(path):
                    os.remove(path)
        if "rvdbt-llvmaot" in exec.name and self.prof != None:
            # cp old prof file named by name to prof hash stored in exec.prof
            os.system(f"cp {RVDBTExec.build_dir}/{RVDBTExec.cache_dir}/{self.name}.prof {RVDBTExec.build_dir}/{RVDBTExec.cache_dir}/{self.prof}.prof")
            print(f"cp {RVDBTExec.build_dir}/{RVDBTExec.cache_dir}/{self.name}.prof {RVDBTExec.build_dir}/{RVDBTExec.cache_dir}/{self.prof}.prof")
        exec.setup(self.root, self.args)
        if not getattr(exec, 'setup_ok', True):
            exec.failure = "setup-failed"
            return exec
        if self.ofile:
            exec.ofile = self.ofile

        if "rvdbt-llvmaot" in exec.name: # if setup with elfaot and success, then change the modulegraph.gv into name
            new_base_name = self.name + "_" + exec.name
            new_name = new_base_name + ".gv"
            print(f"Renaming modulegraph.gv `to {new_name}")
            os.rename(RVDBTExec.build_dir + "/" + RVDBTExec.cache_dir + "/modulegraph.gv", RVDBTExec.build_dir + "/" + RVDBTExec.cache_dir + "/" + new_name)
            try:
                aot_so_hash = get_latest_aot_so_hash()
            except FileNotFoundError:
                print("No .aot.so files found in the cache directory")
                exec.failure = "aot-missing"
                return exec
            cache_path = RVDBTExec.build_dir + "/" + RVDBTExec.cache_dir + "/" + aot_so_hash + ".aot.so"
            assert os.path.isfile(cache_path), f"AOT file {cache_path} does not exist"
            os.system(f"cp {cache_path} {RVDBTExec.build_dir}/{RVDBTExec.cache_dir}/{new_base_name}.aot.so")
            exec.aot_size = os.path.getsize(cache_path)
            print(f"AOT size: {exec.aot_size} bytes")
            # also copy the prof file to avoid re-running the profiler
        
        exec.run()
        if self.ofile is not None and os.path.isfile(self.ofile):
            os.rename(self.ofile, self.get_ofile(exec))
        if len(self.name) > 3 and self.name[:4] == "gcc":
            # I only name gcc outputs to ref, so I need to rename the output file with the exec as postfix
            os.rename(self.root + "/" + self.args[-1], self.root + "/" + self.args[-1] + "." + exec.name)

        return exec

    def verify(self, exec: BaseExec, exec_ref: BaseExec):
        if getattr(exec_ref, 'failure', None) or exec_ref.rc != self.expected_rc:
            return "reference-failed"
        if getattr(exec, 'failure', None):
            return exec.failure
        if exec.rc != self.expected_rc:
            return "execution-failed"
        if self.cmp_out and (exec_ref.out is None or exec.out is None):
            return "stdout-missing"
        if self.cmp_out and exec_ref.out != exec.out:
            return "stdout"

        if self.ofile is not None:
            if not os.path.isfile(self.get_ofile(exec_ref)):
                return "reference-outfile-missing"
            if not os.path.isfile(self.get_ofile(exec)):
                return "outfile-missing"
            filecmp.clear_cache()
            if not filecmp.cmp(self.get_ofile(exec_ref), self.get_ofile(exec), shallow=False):
                return "outfile-diff"

        return None

    class Result:
        def __init__(self, res, time, score, output=None, aot_size=0, aot_time=0):
            self.res = res
            self.time = time
            self.score = score
            self.aot_size = aot_size
            self.aot_time = aot_time

    def result(self, exec: BaseExec, exec_ref: BaseExec = None) -> Result:
        exec_ref = exec if exec_ref is None else exec_ref
        res = self.verify(exec, exec_ref) or "ok"
        passed = res == "ok"
        res += ":" + str(exec.rc)
        score = None
        if (passed and exec.time is not None and math.isfinite(exec.time) and exec.time > 0
                and exec_ref.time is not None and math.isfinite(exec_ref.time) and exec_ref.time > 0):
            score = f"{exec_ref.time / exec.time:.3f}"
        return Benchmark.Result(res, exec.time, score, aot_size=exec.aot_size, aot_time=exec.aot_time)


# mibench.automotive
def GetBenchmarks_Automotive(prebuilts_dir):
    b: list[Benchmark] = []
    root = os.path.join(prebuilts_dir + "/automotive")
    # b.append(Benchmark(root + "/basicmath", ["basicmath_small"], True))
    b.append(Benchmark(root + "/basicmath", ["basicmath_loop", "10"]))
    # b.append(Benchmark(root + "/bitcount", ["bitcnts", "30000000"]))
    # b.append(Benchmark(root + "/qsort",
    # #         ["qsort_small", "input_small.dat"], True))
    # b.append(Benchmark(root + "/qsort",
    #          ["qsort_large", "input_large.dat"], True)) # default is 50000
    # b.append(Benchmark(root + "/qsort",
    #          ["qsort_large_variable_length", "1000000", "qsort_large_input.txt"], True))
    # convert large.pgm to 10x large.pgm by cmd "convert -size 8192x8192 xc:gray input_huge.pgm" from imagemagick
    # b.append(Benchmark(root + "/susan",
    #          ["susan", "input_huge.pgm", "_bout", "-c"], False, "_bout"))
    return b


# mibench.network
def GetBenchmarks_Network(prebuilts_dir):
    b: list[Benchmark] = []
    root = os.path.join(prebuilts_dir + "/network")
    # b.append(Benchmark(root + "/dijkstra",
    #        ["dijkstra_small", "input.dat"], True))
    b.append(Benchmark(root + "/dijkstra",
             ["dijkstra_large", "input.dat"], True))
    return b


# mibench.security
def GetBenchmarks_Security(prebuilts_dir):
    b: list[Benchmark] = []
    root = os.path.join(prebuilts_dir + "/security")
    b.append(Benchmark(root + "/blowfish",
             ["bf", "e", "input_large.asc", "_bout", "1234567890abcdeffedcba0987654321"], False, "_bout"))
    return b


# mibench.telecomm
def GetBenchmarks_Telecomm(prebuilts_dir):
    b: list[Benchmark] = []
    root = os.path.join(prebuilts_dir + "/telecomm")
    b.append(Benchmark(root + "/FFT", ["fft", "8", f"{32768}"], True))
    b.append(Benchmark(root + "/FFT", ["fft_ia", "8", f"{32768}"], True))
    # b.append(Benchmark(root + "/gsm",
    #          ["toast", "-c", "big.au"], True)) # 10x times larger than large.au by cmd "sox large.au big.au repeat 10"
    return b


# coremark
def GetBenchmarks_Coremark(prebuilts_dir):
    b: list[Benchmark] = []
    root = os.path.join(prebuilts_dir + "/coremark")
    b.append(Benchmark(
        root + "/", ["coremark.exe", "0x0", "0x0", "0x66", "15000", "7", "1", "2000"]))
    return b

# rv32emu workload
def GetBenchmarks_RV32EMU(prebuilts_dir):
    b: list[Benchmark] = []
    root = os.path.join(prebuilts_dir + "/rv32emu-workload")
    b.append(Benchmark(root + "/", ["nbench", "0"], name="numeric-sort"))
    b.append(Benchmark(root + "/", ["nbench", "1"], name="string-sort"))
    b.append(Benchmark(root + "/", ["nbench", "2"], name="bitfield"))
    b.append(Benchmark(root + "/", ["nbench", "3"], name="emfloat"))
    b.append(Benchmark(root + "/", ["nbench", "5"], name="assignment"))
    # b.append(Benchmark(root + "/", ["nbench", "6"], name="IDEA"))
    b.append(Benchmark(root + "/", ["nbench", "7"], name="Huffman"))
    # b.append(Benchmark(root + "/", ["dhrystone"]))
    # b.append(Benchmark(root + "/", ["primes"], cmp_out=True))
    # b.append(Benchmark(root + "/", ["sha512"], cmp_out=True, prof="abcb268030866addb89628ee612792d3"))
    return b

# rv32emu workload, but compiled with rv32ia
def GetBenchmarks_RV32IA(prebuilts_dir):
    b: list[Benchmark] = []
    root = os.path.join(prebuilts_dir + "/rv32ia")
    # b.append(Benchmark(root + "/", ["nbench", "0"], name="numeric-sort"))
    # b.append(Benchmark(root + "/", ["nbench", "1"], name="string-sort"))
    # b.append(Benchmark(root + "/", ["nbench", "2"], name="bitfield"))
    # b.append(Benchmark(root + "/", ["nbench", "3"], name="emfloat"))
    # b.append(Benchmark(root + "/", ["nbench", "5"], name="assignment"))
    # b.append(Benchmark(root + "/", ["nbench", "6"], name="IDEA"))
    # b.append(Benchmark(root + "/", ["nbench", "7"], name="Huffman"))
    # b.append(Benchmark(root + "/", ["dhrystone"]))
    # b.append(Benchmark(root + "/", ["primes"], cmp_out=True))
    b.append(Benchmark(root + "/", ["sha512"], cmp_out=True))
    return b

def GetBenchmarks_RV32I(prebuilts_dir):
    b: list[Benchmark] = []
    root = os.path.join(prebuilts_dir + "/rv32emu-i")
    # b.append(Benchmark(root + "/", ["nbench", "0"], name="numeric-sort"))
    # b.append(Benchmark(root + "/", ["nbench", "1"], name="string-sort"))
    # b.append(Benchmark(root + "/", ["nbench", "2"], name="bitfield"))
    # b.append(Benchmark(root + "/", ["nbench", "3"], name="emfloat"))
    # b.append(Benchmark(root + "/", ["nbench", "5"], name="assignment"))
    # b.append(Benchmark(root + "/", ["nbench", "6"], name="IDEA"))
    # b.append(Benchmark(root + "/", ["nbench", "7"], name="Huffman"))
    b.append(Benchmark(root + "/", ["dhrystone"]))
    # b.append(Benchmark(root + "/", ["primes"], cmp_out=True))
    b.append(Benchmark(root + "/", ["sha512"], cmp_out=True))
    return b

def GetBenchmarks_SPEC2017Rate(prebuilts_dir):
    # ref commands
    b: list[Benchmark] = []
    root = os.path.join(prebuilts_dir)
    # all the args[0]s are the same, just renamed for different cache file
    b.append(Benchmark(root + "/500.perlbench_r/" , ["perlbench_r_base.riscv_wendell_debug-32", "checkspam.pl", "2500", "5", "25", "11", "150", "1", "1", "1", "1"], name="perl-ref1", prof="083af8c9c06a649f7bc5807de91bf588"))
    b.append(Benchmark(root + "/500.perlbench_r/" , ["perlbench_r_base.riscv_wendell_debug-32", "diffmail.pl", "4", "800", "10", "17", "19", "300"], name="perl-ref2", prof="083af8c9c06a649f7bc5807de91bf588"))
    b.append(Benchmark(root + "/500.perlbench_r/" , ["perlbench_r_base.riscv_wendell_debug-32", "splitmail.pl", "6400", "12", "26", "16", "100", "0"], name="perl-ref3", prof="083af8c9c06a649f7bc5807de91bf588"))

    # b.append(Benchmark(root + "/502.gcc_r/", ["ref1", "gcc-pp.c", "-O3", "-finline-limit=0", "-fif-conversion", "-fif-conversion2", "-o", "ref1.s"], name="gcc-ref1", prof="37a45829a600f065d02f8349fde44dec"))
    # b.append(Benchmark(root + "/502.gcc_r/", ["ref2", "gcc-pp.c", "-O2", "-finline-limit=36000", "-fpic", "-o", "ref2.s"], name="gcc-ref2", prof="37a45829a600f065d02f8349fde44dec"))
    # b.append(Benchmark(root + "/502.gcc_r/", ["ref3", "gcc-smaller.c", "-O3", "-fipa-pta", "-o", "ref3.s"], name="gcc-ref3", prof="37a45829a600f065d02f8349fde44dec"))
    # b.append(Benchmark(root + "/502.gcc_r/", ["ref4", "ref32.c", "-O5", "-o", "ref4.s"], name="gcc-ref4", prof="37a45829a600f065d02f8349fde44dec"))
    # b.append(Benchmark(root + "/502.gcc_r/", ["ref5", "ref32.c", "-O3", "-fselective-scheduling", "-fselective-scheduling2", "-o", "ref5.s"], name="gcc-ref5", prof="37a45829a600f065d02f8349fde44dec"))
 
    b.append(Benchmark(root + "/505.mcf_r/" , ["mcf_r_base.riscv_wendell_debug-32", "inp.in"], prof="a3be544809c765eab54401626d24b4f5"))
    
    b.append(Benchmark(root + "/520.omnetpp_r/", ["omnetpp_r_base.riscv_wendell_debug-32", "-c", "General", "-r", "0"], prof="e8a0fb640a21e3bac3bf100788cdb679"))

    b.append(Benchmark(root + "/523.xalancbmk_r/" , ["cpuxalan_r_base.riscv_wendell_debug-32", "-v", "refrate/t5.xml", "refrate/xalanc.xsl"], prof="a7b11fb066dfc7d7c0c3d4f589ca90ef"))

    # b.append(Benchmark(root + "/525.x264_r/" , ["x264_r_base.riscv_wendell_debug-32", "--pass", "1", "--stats", "x264_stats.log", "--bitrate", "1000", "--frames", "1000", "-o", "BuckBunny_New.264", "BuckBunny.yuv", "1280x720"], name="x264-ref1", prof="ef7fc15cfefb9d5503158f939cf0ac10"))
    b.append(Benchmark(root + "/525.x264_r/" , ["x264_r_base.riscv_wendell_debug-32", "--pass", "2", "--stats", "x264_stats.log", "--bitrate", "1000", "--dumpyuv", "200", "--frames", "1000", "-o", "BuckBunny_New.264", "BuckBunny.yuv", "1280x720"], name="x264-ref2", prof="ef7fc15cfefb9d5503158f939cf0ac10"))
    b.append(Benchmark(root + "/525.x264_r/" , ["x264_r_base.riscv_wendell_debug-32", "--seek", "500", "--dumpyuv", "200", "--frames", "1250", "-o", "BuckBunny_New.264", "BuckBunny.yuv", "1280x720"], name="x264-ref3", prof="ef7fc15cfefb9d5503158f939cf0ac10"))

    b.append(Benchmark(root + "/531.deepsjeng_r/" , ["deepsjeng_r_base.riscv_wendell_debug-32", "ref.txt"], name="deepsjeng-ref", prof="03775932bdec0f4d1ea6738257da1cee"))
    
    b.append(Benchmark(root + "/541.leela_r/" , ["leela_r_base.riscv_wendell_debug-32", "ref.sgf"], name="leela-ref", prof="2d784e9416d01ffbf111822dd0c10a69"))

    b.append(Benchmark(root + "/548.exchange2_r/" , ["exchange2_r_base.riscv_wendell_debug-32", "6"], name="exchange2-ref", prof="5e22a2b35bcdde3fb1529ad06daa9817"))

    b.append(Benchmark(root + "/557.xz_r/" , ["xz_r_base.riscv_wendell_debug-32", "cld.tar.xz", "160", "19cf30ae51eddcbefda78dd06014b4b96281456e078ca7c13e1c0c9e6aaea8dff3efb4ad6b0456697718cede6bd5454852652806a657bb56e07d61128434b474", "59796407", "61004416", "6"], name="xz_ref1", prof="eb9efbd2247cb4d6745a5da8721840ef"))
    b.append(Benchmark(root + "/557.xz_r/" , ["xz_r_base.riscv_wendell_debug-32", "cpu2006docs.tar.xz", "250", "055ce243071129412e9dd0b3b69a21654033a9b723d874b2015c774fac1553d9713be561ca86f74e4f16f22e664fc17a79f30caa5ad2c04fbc447549c2810fae", "23047774", "23513385", "6e"], name="xz_ref2", prof="eb9efbd2247cb4d6745a5da8721840ef"))
    b.append(Benchmark(root + "/557.xz_r/" , ["xz_r_base.riscv_wendell_debug-32", "input.combined.xz", "250", "a841f68f38572a49d86226b7ff5baeb31bd19dc637a922a972b2e6d1257a890f6a544ecab967c313e370478c74f760eb229d4eef8a8d2836d233d3e9dd1430bf", "40401484", "41217675", "7"], name="xz_ref3", prof="eb9efbd2247cb4d6745a5da8721840ef"))
    return b

def GetBenchmarks_SPEC2017RateTrain(prebuilts_dir):
    b: list[Benchmark] = []
    root = os.path.join(prebuilts_dir)
    # x264 merge_ls errs
    # 525
    # BuckBunny.264 BuckBunny.yuv no_md5 BuckBunny_New.264 1280x720 500 1000 1250 200 200 400 600 700 800 900 999 1100 1249
    # b.append(Benchmark(root + "/525.x264_r/" , ["x264_r_base.riscv_wendell_debug-32", "BuckBunny.264", "BuckBunny.yuv", "no_md5", "BuckBunny_New.264", "1280x720", "0", "142", "0", "50", "50", "100", "141"]))
    # train ./x264_r_base.riscv_wendell_debug-32 --dumpyuv 50 --frames 142 -o BuckBunny_New.264 BuckBunny.yuv 1280x720
    # b.append(Benchmark(root + "/525.x264_r/" , ["x264_r_base.riscv_wendell_debug-32", "--dumpyuv", "50", "--frames", "142", "-o", "BuckBunny_New.264", "BuckBunny.yuv", "1280x720"]))
    # ./x264_r_base.riscv_wendell_debug-64 --pass 1 --stats x264_stats.log --bitrate 1000 --frames 1000 -o BuckBunny_New.264 BuckBunny.yuv 1280x720
    # b.append(Benchmark(root + "/525.x264_r/" , ["x264_r_base.riscv_wendell_debug-32", "--pass", "1", "--stats", "x264_stats.log", "--bitrate", "1000", "--frames", "100", "-o", "BuckBunny_New.264", "BuckBunny.yuv", "1280x720"]))
    # 557
    # ./xz_r_base.riscv_wendell_debug-64 cld.tar.xz 160 19cf30ae51eddcbefda78dd06014b4b96281456e078ca7c13e1c0c9e6aaea8dff3efb4ad6b0456697718cede6bd5454852652806a657bb56e07d61128434b474 59796407 61004416 6
    # b.append(Benchmark(root + "/557.xz_r/", ["xz_r_base.riscv_wendell_debug-32", "cld.tar.xz", "1",
    #                                          "19cf30ae51eddcbefda78dd06014b4b96281456e078ca7c13e1c0c9e6aaea8dff3efb4ad6b0456697718cede6bd5454852652806a657bb56e07d61128434b474",
    #                                          "59796407", "61004416", "3"]))
    # 502.gcc
    # ./cpugcc_r_base.riscv_wendell_debug-64 gcc-pp.c -O3 -finline-limit=0 -fif-conversion -fif-conversion2 -o gcc-pp.opts-O3_-finline-limit_0_-fif-conversion_-fif-conversion2.s
    # b.append(Benchmark(root + "/502.gcc_r/", ["cpugcc_r_base.riscv_wendell_debug-32", "gcc-pp.c", "-O3", "-finline-limit=0", "-fif-conversion", "-fif-conversion2", "-o", "gcc-pp.opts-O3_-finline-limit_0_-fif-conversion_-fif-conversion2.s"]))
    # ./cpugcc_r_base.riscv_wendell_debug-32 train01.c -O3 -finline-limit=50000

    # b.append(Benchmark(root + "/502.gcc_r/", ["cpugcc_r_base.riscv_wendell_debug-32", "scilab.c", "-O3", "-finline-limit=50000", "-o", "scilab.s"], name="gcc-train1"))
    # b.append(Benchmark(root + "/502.gcc_r/", ["cpugcc_r_base.riscv_wendell_debug-32", "train01.c", "-O3", "-finline-limit=50000", "-o", "train01.s"], name="gcc-train2"))
    # b.append(Benchmark(root + "/502.gcc_r/", ["cpugcc_r_base.riscv_wendell_debug-32", "t1.c", "-O3", "-finline-limit=50000", "-o", "t1.s"], name="gcc-train3"))
    # 500.perl
    # ref
    # checkspam.pl 100 1 5 2 10 0 0 0 0
    b.append(Benchmark(root + "/502.gcc_r/", ["ref5", "ref32.c", "-O3", "-fselective-scheduling", "-fselective-scheduling2", "-o", "ref5.s"], name="gcc-ref5", prof="37a45829a600f065d02f8349fde44dec"))
    # b.append(Benchmark(root + "/500.perlbench_r/", ["perlbench_r_base.riscv_wendell_debug-32", "checkspam.pl", "100", "1", "5", "2", "10", "0", "0", "0", "0"]))
    # diffmail.pl 4 800 10 17 19 300
    # b.append(Benchmark(root + "/500.perlbench_r/", ["perlbench_r_base.riscv_wendell_debug-32", "diffmail.pl", "4", "800", "10", "17", "19", "300"]))
    # 4 70 15 24 23 100 
    # b.append(Benchmark(root + "/500.perlbench_r/", ["perlbench_r_base.riscv_wendell_debug-32", "diffmail.pl", "4", "70", "15", "24", "23", "100"]))
    # perfect.pl b 3
    # b.append(Benchmark(root + "/500.perlbench_r/", ["perlbench_r_base.riscv_wendell_debug-32", "perfect.pl", "b", "3"]))
    # 505.mcf
    # b.append(Benchmark(root + "/505.mcf_r/", ["mcf_r_base.riscv_wendell_debug-32", "test.in"]))

    # g++ test
    # 520 /usr/bin/qemu-riscv32 -L /opt/riscv/sysroot ./omnetpp_r_base.riscv_wendell_debug-32 -c General -r 0
    # bug out when loading files with chdir
    # b.append(Benchmark(root + "/520.omnetpp_r/", ["omnetpp_r_base.riscv_wendell_debug-32", "-f", "train.ini", "-c", "General", "-r", "0"]))
    # 523 ./cpuxalan_r_base.riscv_wendell_debug-32 -v t5.xml xalanc.xsl
    # b.append(Benchmark(root + "/523.xalancbmk_r/", ["cpuxalan_r_base.riscv_wendell_debug-32", "-v", "test/test.xml", "test/xalanc.xsl"]))
    # b.append(Benchmark(root + "/523.xalancbmk_r/", ["cpuxalan_r_base.riscv_wendell_debug-32", "-v", "train/allbooks.xml", "train/xalanc.xsl"]))
    # b.append(Benchmark(root + "/523.xalancbmk_r/", ["cpuxalan_r_base.riscv_wendell_debug-32", "-v", "refrate/t5.xml", "refrate/xalanc.xsl"]))
    # 531
    # /usr/bin/qemu-riscv32 -L /opt/riscv/sysroot ./deepsjeng_r_base.riscv_wendell_debug-32 ref.txt
    # b.append(Benchmark(root + "/531.deepsjeng_r/", ["deepsjeng_r_base.riscv_wendell_debug-32", "test.txt"]))
    # 541
    # b.append(Benchmark(root + "/541.leela_r/", ["leela_r_base.riscv_wendell_debug-32", "test.sgf"]))

    # fortran train 
    # 548 ./exchange2_r_base.riscv_wendell_debug-32 6
    # b.append(Benchmark(root + "/548.exchange2_r/", ["exchange2_r_base.riscv_wendell_debug-32", "1"]))
    return b

def GetBenchmarks(opts):
    benchmarks: list[Benchmark] = []
    if opts.benchmark == "mibench":
        benchmarks += GetBenchmarks_Automotive(opts.prebuilts_dir)
        # benchmarks += GetBenchmarks_Network(opts.prebuilts_dir) # This is not tested in pukhovv/rvdbt
        # benchmarks += GetBenchmarks_Security(opts.prebuilts_dir) # Note bf exit with return code 1 
        # benchmarks += GetBenchmarks_Telecomm(opts.prebuilts_dir)
        # benchmarks += GetBenchmarks_Coremark(opts.prebuilts_dir)
    elif opts.benchmark == "automotive":
        benchmarks += GetBenchmarks_Automotive(opts.prebuilts_dir)
    elif opts.benchmark == "network":
        benchmarks += GetBenchmarks_Network(opts.prebuilts_dir)
    elif opts.benchmark == "security":
        benchmarks += GetBenchmarks_Security(opts.prebuilts_dir)
    elif opts.benchmark == "telecomm":
        benchmarks += GetBenchmarks_Telecomm(opts.prebuilts_dir)
    elif opts.benchmark == "coremark":
        benchmarks += GetBenchmarks_Coremark(opts.prebuilts_dir)
    elif opts.benchmark == "rv32emu":
        benchmarks += GetBenchmarks_RV32EMU(opts.prebuilts_dir)
    elif opts.benchmark == "rv32i":
        benchmarks += GetBenchmarks_RV32I(opts.prebuilts_dir)
    elif opts.benchmark == "rv32ia":
        benchmarks += GetBenchmarks_RV32IA(opts.prebuilts_dir)
    elif opts.benchmark == "SPEC2017Rate":
        benchmarks += GetBenchmarks_SPEC2017Rate(opts.prebuilts_dir)
    elif opts.benchmark == "SPEC2017RateTrain":
        benchmarks += GetBenchmarks_SPEC2017RateTrain(opts.prebuilts_dir)
    return benchmarks


def compile_benchmark(gcc_path: str, root_dir: str, target: str) -> bool:
    """Require an explicitly built guest; never silently rebuild with other flags."""
    if os.path.isfile(f"{root_dir}/{target}"):
        print(f"Executable of workload {root_dir}/{target} already exists, skip compiling and jump into execution")
        return True
    print(f"Missing prebuilt executable: {root_dir}/{target}", file=sys.stderr)
    return False


def RunTests(opts):
    benchmarks = GetBenchmarks(opts)
    failures = 0
    if not benchmarks:
        print("No benchmarks selected", file=sys.stderr)
        return 1

    # Modified to use opts
    def get_execs(): 
        execs = [QEMUExec()]  # QEMU is always included as reference
        if opts.no_qemu:
            execs = []
        if opts.libriscv:
            execs.append(LIBRISCVExec("bt"))  # LibRISCV BT mode
        if opts.rvdbt_jit:
            execs.append(RVDBTExec(False, jit_merge_ls=False))  # JIT mode
        if opts.rvdbt_jit_not_freq:
            execs.append(RVDBTExec(False, jit_merge_ls=False, not_freq=True))  # JIT mode
        if opts.rvdbt_jit_merge_ls:
            execs.append(RVDBTExec(False, jit_merge_ls=True))  # JIT merge ls mode
        if opts.rvdbt_qcgaot:
            execs.append(RVDBTExec(True, False))  # QCG AOT
        if opts.rvdbt_llvmaot:
            execs.append(RVDBTExec(True, True))  # LLVM AOT
        if opts.rvdbt_llvmaot_1000:
            execs.append(RVDBTExec(True, True, 1000))  # LLVM AOT with hotspot threshold
        if opts.rvdbt_llvmaot_opt:
            execs.append(RVDBTExec(True, True, 1000, llvmopt=True))  # LLVM AOT with optimization
        if opts.rvdbt_llvmaot_hotspot:
            # execs.append(RVDBTExec(True, llvm=True, hotspot_threshold=8192))  
            # execs.append(RVDBTExec(True, llvm=True, hotspot_threshold=16384)) 
            # execs.append(RVDBTExec(True, llvm=True, hotspot_threshold=32768)) 
            # execs.append(RVDBTExec(True, llvm=True, hotspot_threshold=65536)) 
            # execs.append(RVDBTExec(True, llvm=True, hotspot_threshold=131072)) 
            execs.append(RVDBTExec(True, llvm=True, hotspot_threshold=262144)) 
            # execs.append(RVDBTExec(True, llvm=True, hotspot_threshold=524288)) 
            # execs.append(RVDBTExec(True, llvm=True, hotspot_threshold=1048576)) 
            # execs.append(RVDBTExec(True, llvm=True, hotspot_threshold=2097152)) 
            # execs.append(RVDBTExec(True, llvm=True, hotspot_threshold=4194304)) 
            # execs.append(RVDBTExec(True, llvm=True, hotspot_threshold=8388608)) 
            # execs.append(RVDBTExec(True, llvm=True, hotspot_threshold=16777216)) 
            # execs.append(RVDBTExec(True, llvm=True, hotspot_threshold=33554432)) 
            # execs.append(RVDBTExec(True, llvm=True, hotspot_threshold=67108864))  # rv32emu max
            # execs.append(RVDBTExec(True, llvm=True, hotspot_threshold=134217728)) 
            # execs.append(RVDBTExec(True, llvm=True, hotspot_threshold=268435456)) 
            # execs.append(RVDBTExec(True, llvm=True, hotspot_threshold=536870912)) 
            # execs.append(RVDBTExec(True, llvm=True, hotspot_threshold=1073741824)) 
        if opts.rvdbt_llvmaot_noprop:
            execs.append(RVDBTExec(True, llvm=True, hotspot_threshold=262144, not_freq=True, noprop=True)) 
        return execs
    
    # if opts.objective == "test":
    #     benchmarks = [b for b in benchmarks if b.cmp_out]

    score_csvtab = [["benchmark-name"] + list(map(lambda e: e.name, get_execs()))]
    if not get_execs():
        print("No execution engines selected", file=sys.stderr)
        return 1
    time_csvtab = [["benchmark-name"] + list(map(lambda e: e.name, get_execs()))]
    total_time_csvtab = [["benchmark-name"] + list(map(lambda e: e.name, get_execs()))]

    def get_aot_execs():
        return [e for e in get_execs() if e.name.startswith("rvdbt-llvmaot")]

    aot_size_csvtab = [["benchmark-name"] + list(map(lambda e: e.name, get_aot_execs()))]
    aot_time_csvtab = [["benchmark-name"] + list(map(lambda e: e.name, get_aot_execs()))]

    for b in benchmarks:
        print(f"\nCompiling benchmark under: {b.root}")
        if not compile_benchmark(opts.riscv32_gcc, b.root, b.args[0]):
            print(f"FAIL: missing or failed benchmark build: {b.root}")
            failures += 1
            continue

        print(f"\nRunning benchmark:")
        execs = get_execs()
        scores = [b.name]
        ref_exec = execs[0]
        aot_sizes = [b.name]
        aot_times = [b.name]
        times = [b.name]
        total_times = [b.name]
        for e in execs:
            print(f"Running {b.name} with {e.name}")
            try:
                b.launch_with(e)
            except (OSError, subprocess.SubprocessError) as error:
                e.failure = "timeout" if isinstance(error, subprocess.TimeoutExpired) else "launch-failed"
                e.rc = None
                e.time = None
                e.err = str(error)
            res = b.result(e, ref_exec)
            passed = res.res.startswith("ok:")
            failures += not passed
            print(f"  Result: {res.res}")
            print(f"  Time: {res.time}")
            print(f"  Score: {res.score}")
            print(f"  Return code: {e.rc}") # if the return code is 0, then below is logs
            print(f"  Error output or logs: {e.err}") # E.g., [aot] is log_aot
            scores += [res.score]
            times += [res.time if passed else None]
            if e.name.startswith("rvdbt-llvmaot"):  
                aot_sizes += [res.aot_size]
                aot_times += [res.aot_time]
                total_times += [res.time + res.aot_time if passed and res.time is not None else None]
            else:
                total_times += [res.time if passed else None]
        score_csvtab += [scores]    
        time_csvtab += [times]
        aot_size_csvtab += [aot_sizes]
        aot_time_csvtab += [aot_times]
        total_time_csvtab += [total_times]
        # move the prof file to another name to avoid the same name being used by different commands with the same args[0]
        if (opts.rvdbt_jit or opts.rvdbt_jit_merge_ls) and opts.objective != "test":
            try:
                aot_so_hash = get_latest_prof_hash()
            except FileNotFoundError:
                continue
            prof_path = RVDBTExec.cache_full_dir + "/" + aot_so_hash + ".prof"
            print(f"move {prof_path} to")
            print(f"{RVDBTExec.cache_full_dir}/{b.name}.prof")
            os.system(f"mv {prof_path} {RVDBTExec.cache_full_dir}/{b.name}.prof")

    print("Score:")
    csv.writer(sys.stdout).writerows(score_csvtab)
    print("Time:")
    csv.writer(sys.stdout).writerows(time_csvtab)
    print("AOT size:")
    csv.writer(sys.stdout).writerows(aot_size_csvtab)
    print("AOT time:")
    csv.writer(sys.stdout).writerows(aot_time_csvtab)
    print("Total time:")
    csv.writer(sys.stdout).writerows(total_time_csvtab)
    return 1 if failures else 0


def main():
    global EXECUTION_TIMEOUT
    op = optparse.OptionParser()
    op.add_option("--riscv32-gcc", dest="riscv32_gcc")
    op.add_option("--rvdbt-build-dir", dest="rvdbt_build_dir")
    op.add_option("--cache-dir", dest="cache_dir", default="dbtcache", help="Cache the frequency profile under rvdbt-build-dir. Note if the cache dir not exists, it will err")
    op.add_option("--libriscv-build-dir", dest="libriscv_build_dir")
    op.add_option("--prebuilts", dest="prebuilts_dir")
    op.add_option("--timeout", type="float", default=600, help="Per-process timeout in seconds (default: 600)")
    # Add new options for execution modes
    op.add_option("--no-qemu", action="store_true", dest="no_qemu", default=False)
    op.add_option("--rvdbt-jit", action="store_true", dest="rvdbt_jit", default=False)
    op.add_option("--rvdbt-jit-not-freq", action="store_true", dest="rvdbt_jit_not_freq", default=False)
    op.add_option("--rvdbt-jit-merge-ls", action="store_true", dest="rvdbt_jit_merge_ls", default=False)
    op.add_option("--rvdbt-qcgaot", action="store_true", dest="rvdbt_qcgaot", default=False)
    op.add_option("--rvdbt-llvmaot", action="store_true", dest="rvdbt_llvmaot", default=False)
    op.add_option("--rvdbt-llvmaot-1000", action="store_true", dest="rvdbt_llvmaot_1000", default=False)
    op.add_option("--rvdbt-llvmaot-opt", action="store_true", dest="rvdbt_llvmaot_opt", default=False)
    op.add_option("--rvdbt-llvmaot-hotspot", action="store_true", dest="rvdbt_llvmaot_hotspot", default=False)
    op.add_option("--rvdbt-llvmaot-noprop", action="store_true", dest="rvdbt_llvmaot_noprop", default=False)
    op.add_option("--libriscv", action="store_true", dest="libriscv", default=False)
    op.add_option("--benchmark", dest="benchmark", type="choice", 
                 choices=["automotive", "network", "security", "telecomm", "coremark", "rv32emu", "rv32ia", "rv32i", "mibench", "SPEC2017Rate", "SPEC2017RateTrain"], default="automotive",
                 help="Set the benchmark: 'automotive', 'network', 'security', 'telecomm', 'coremark', 'rv32emu', 'rv32ia', 'rv32i', 'mibench', 'SPEC2017Rate', 'SPEC2017RateTrain'")
    # set objective to "benchmark" or "test" 
    op.add_option("--objective", dest="objective", type="choice", 
                 choices=["benchmark", "test"], default="benchmark",
                 help="Set the objective: 'benchmark' or 'test'")

    (opts, args) = op.parse_args()
    if not opts.rvdbt_build_dir or not opts.prebuilts_dir or (opts.libriscv and not opts.libriscv_build_dir):
        op.error("usage")
    if not math.isfinite(opts.timeout) or opts.timeout <= 0:
        op.error("--timeout must be positive")
    if opts.objective == "test" and opts.no_qemu:
        op.error("test requires the QEMU reference; --no-qemu is benchmark-only")
    EXECUTION_TIMEOUT = opts.timeout
    os.makedirs(opts.rvdbt_build_dir + "/" + opts.cache_dir, exist_ok=True)
    os.makedirs(opts.rvdbt_build_dir + "/logs", exist_ok=True)

    RVDBTExec.build_dir = opts.rvdbt_build_dir
    LIBRISCVExec.build_dir = opts.libriscv_build_dir
    RVDBTExec.cache_dir = opts.cache_dir
    RVDBTExec.cache_full_dir = opts.rvdbt_build_dir + "/" + opts.cache_dir
    return RunTests(opts)


if __name__ == "__main__":
    sys.exit(main())
