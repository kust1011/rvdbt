#!/usr/bin/env python3
"""Bounded isolated host512 build and normal-only checks; retain every command."""
import hashlib,json,pathlib,resource,subprocess,sys
root=pathlib.Path('/home/vick/rvdbt-goldens-task137')
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
arm=sys.argv[1];stage=sys.argv[2];r=root/arm

def run(name,cmd,limit=900,env=None):
 d=r/'receipts'/name;d.mkdir(parents=True,exist_ok=False)
 (d/'command.json').write_text(json.dumps(cmd,indent=2))
 with (d/'stdout').open('w') as out,(d/'stderr').open('w') as err:
  p=subprocess.run(cmd,cwd=d,stdout=out,stderr=err,timeout=limit,env=env)
 (d/'rc').write_text(str(p.returncode));print(arm,name,p.returncode,flush=True)
 return p.returncode

def pin():
 return {str(p.relative_to(r)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((r/'build/bin').glob('*')) if p.is_file()} | {str(p.relative_to(r)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((r/'build/lib').glob('*.so'))}
if stage.startswith('build'):
 if not (r/'build/CMakeCache.txt').exists():
  assert run('configure',['cmake','-S',str(r/'source'),'-B',str(r/'build'),'-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=clang-22','-DCMAKE_CXX_COMPILER=clang++-22','-DLLVM_DIR=/usr/lib/llvm-22/cmake','-DRVV_HOST_CHUNK_BITS=512','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON'],180)==0
 targets=['rvv_vector_run_codegen_test']
 if arm=='current':targets+=['elfrun','rvv_vector_run_admission_test','rv32_grouped_memory_fault_test','rv32_scalar_native_fault_test','rv32_whole_native_fault_test']
 rc=run(stage,['taskset','-c','28-31','nice','-n','10','cmake','--build',str(r/'build'),'-j4','--target',*targets])
 if rc:sys.exit(rc)
 (r/'BUILD_SUCCESS.json').write_text(json.dumps(pin(),indent=2))
else:
 pins=json.loads((r/'BUILD_SUCCESS.json').read_text());assert pin()==pins
 (r/(stage+'.pre.json')).write_text(json.dumps(pins,indent=2))
 import os
 env=os.environ.copy()
 if stage in ('baseline','before','after','repeat','final-dump'):
  dump=r/stage;dump.mkdir(exist_ok=False);env['RVV_GOLDEN_DUMP']=str(dump)
  args=['rvv_vector_run_codegen_test','--goldens-only']
 else:args=sys.argv[3:]
 rc=run(stage,['taskset','-c','28','nice','-n','10','timeout','60',str(r/'build/bin'/args[0]),*args[1:]],90,env)
 assert pin()==pins
 (r/(stage+'.post.json')).write_text(json.dumps(pins,indent=2))
 sys.exit(rc)
