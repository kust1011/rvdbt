import os,subprocess,fcntl
from pathlib import Path
b=Path('/home/vick/rvv-directed-task179')
with open('/home/vick/rvv-directed-task179.own-semaphore','a') as lock:
 fcntl.flock(lock,fcntl.LOCK_EX)
 for mode,exe,lib in [('old',b/'baseline-contract/rvv_vector_run_codegen_test174','/home/vick/rvdbt-host512-task174-build/build/lib'),('new',Path('/home/vick/rvdbt-host512-task179-build/build/bin/rvv_vector_run_codegen_test'),'/home/vick/rvdbt-host512-task179-build/build/lib')]:
  d=b/f'golden-{mode}';d.mkdir()
  r=subprocess.run([str(exe),'--goldens-only'],env=dict(os.environ,RVV_GOLDEN_DUMP=str(d),LD_LIBRARY_PATH=lib),capture_output=True)
  (d/'stdout').write_bytes(r.stdout);(d/'stderr').write_bytes(r.stderr)
  print(mode,r.returncode)
