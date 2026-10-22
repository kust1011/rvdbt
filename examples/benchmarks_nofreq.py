"""Legacy no-frequency workload catalogue, using the checked execution engine."""
import os
import sys

import benchmarks as engine
from benchmarks import Benchmark


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
    b.append(Benchmark(root + "/", ["nbench", "6"], name="IDEA"))
    b.append(Benchmark(root + "/", ["nbench", "7"], name="Huffman"))
    b.append(Benchmark(root + "/", ["dhrystone"]))
    # b.append(Benchmark(root + "/", ["primes"], cmp_out=True))
    b.append(Benchmark(root + "/", ["sha512"], cmp_out=True, prof="abcb268030866addb89628ee612792d3"))
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
    # b.append(Benchmark(root + "/500.perlbench_r/" , ["perlbench_r_base.riscv_wendell_debug-32", "checkspam.pl", "2500", "5", "25", "11", "150", "1", "1", "1", "1"], name="perl-ref1", prof="083af8c9c06a649f7bc5807de91bf588"))
    # b.append(Benchmark(root + "/500.perlbench_r/" , ["perlbench_r_base.riscv_wendell_debug-32", "diffmail.pl", "4", "800", "10", "17", "19", "300"], name="perl-ref2", prof="083af8c9c06a649f7bc5807de91bf588"))
    # b.append(Benchmark(root + "/500.perlbench_r/" , ["perlbench_r_base.riscv_wendell_debug-32", "splitmail.pl", "6400", "12", "26", "16", "100", "0"], name="perl-ref3", prof="083af8c9c06a649f7bc5807de91bf588"))

    b.append(Benchmark(root + "/502.gcc_r/", ["ref1", "gcc-pp.c", "-O3", "-finline-limit=0", "-fif-conversion", "-fif-conversion2", "-o", "ref1.s"], name="gcc-ref1", prof="37a45829a600f065d02f8349fde44dec"))
    b.append(Benchmark(root + "/502.gcc_r/", ["ref2", "gcc-pp.c", "-O2", "-finline-limit=36000", "-fpic", "-o", "ref2.s"], name="gcc-ref2", prof="37a45829a600f065d02f8349fde44dec"))
    b.append(Benchmark(root + "/502.gcc_r/", ["ref3", "gcc-smaller.c", "-O3", "-fipa-pta", "-o", "ref3.s"], name="gcc-ref3", prof="37a45829a600f065d02f8349fde44dec"))
    b.append(Benchmark(root + "/502.gcc_r/", ["ref4", "ref32.c", "-O5", "-o", "ref4.s"], name="gcc-ref4", prof="37a45829a600f065d02f8349fde44dec"))
    b.append(Benchmark(root + "/502.gcc_r/", ["ref5", "ref32.c", "-O3", "-fselective-scheduling", "-fselective-scheduling2", "-o", "ref5.s"], name="gcc-ref5", prof="37a45829a600f065d02f8349fde44dec"))
 
    # b.append(Benchmark(root + "/505.mcf_r/" , ["mcf_r_base.riscv_wendell_debug-32", "inp.in"], prof="a3be544809c765eab54401626d24b4f5"))
    
    # b.append(Benchmark(root + "/520.omnetpp_r/", ["omnetpp_r_base.riscv_wendell_debug-32", "-c", "General", "-r", "0"], prof="e8a0fb640a21e3bac3bf100788cdb679"))

    # b.append(Benchmark(root + "/523.xalancbmk_r/" , ["cpuxalan_r_base.riscv_wendell_debug-32", "-v", "refrate/t5.xml", "refrate/xalanc.xsl"], prof="a7b11fb066dfc7d7c0c3d4f589ca90ef"))

    # b.append(Benchmark(root + "/525.x264_r/" , ["x264_r_base.riscv_wendell_debug-32", "--pass", "1", "--stats", "x264_stats.log", "--bitrate", "1000", "--frames", "1000", "-o", "BuckBunny_New.264", "BuckBunny.yuv", "1280x720"], name="x264-ref1", prof="ef7fc15cfefb9d5503158f939cf0ac10"))
    # b.append(Benchmark(root + "/525.x264_r/" , ["x264_r_base.riscv_wendell_debug-32", "--pass", "2", "--stats", "x264_stats.log", "--bitrate", "1000", "--dumpyuv", "200", "--frames", "1000", "-o", "BuckBunny_New.264", "BuckBunny.yuv", "1280x720"], name="x264-ref2", prof="ef7fc15cfefb9d5503158f939cf0ac10"))
    # b.append(Benchmark(root + "/525.x264_r/" , ["x264_r_base.riscv_wendell_debug-32", "--seek", "500", "--dumpyuv", "200", "--frames", "1250", "-o", "BuckBunny_New.264", "BuckBunny.yuv", "1280x720"], name="x264-ref3", prof="ef7fc15cfefb9d5503158f939cf0ac10"))

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



if __name__ == "__main__":
    sys.exit(engine.main(catalogue=GetBenchmarks))
