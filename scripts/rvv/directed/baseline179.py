import shlex,subprocess,os,json
from pathlib import Path
b=Path('/home/vick/rvdbt-host512-task179-build/build');d=Path('/home/vick/rvv-directed-task179/baseline-contract');d.mkdir()
c=shlex.split((b/'dbt/CMakeFiles/rvv_vector_run_codegen_test.dir/link.txt').read_text())
c[c.index('-o')+1]=str(d/'rvv_vector_run_codegen_test174')
c=[('/home/vick/rvdbt-host512-task174-build/build/lib/'+Path(a).name) if a.startswith('../lib/') else a for a in c]
c=[a.replace('/home/vick/rvdbt-host512-task179-build/build/lib','/home/vick/rvdbt-host512-task174-build/build/lib') for a in c]
(d/'link-command.json').write_text(json.dumps(c,indent=2));subprocess.run(c,cwd=b/'dbt',check=True)
r=subprocess.run([str(d/'rvv_vector_run_codegen_test174')],capture_output=True,env=dict(os.environ,LD_LIBRARY_PATH='/home/vick/rvdbt-host512-task174-build/build/lib'),timeout=90)
(d/'stdout').write_bytes(r.stdout);(d/'stderr').write_bytes(r.stderr);(d/'RESULT.json').write_text(json.dumps(dict(returncode=r.returncode)))
print(r.returncode);print('\n'.join(x for x in r.stderr.decode().splitlines() if 'FAIL' in x))
