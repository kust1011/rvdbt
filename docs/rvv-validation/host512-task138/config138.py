import json,hashlib,sys,subprocess
from pathlib import Path
R=Path('/home/vick/rvdbt-host512-task138'); B=Path('/home/vick/rvdbt-goldens-task137/current/build'); S=B.parent/'source'
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
expected=json.loads(Path('/home/vick/rvdbt-goldens-task137/EXPECTED_SOURCE.json').read_text())['current']['files']
assert all(sha(S/p)==h for p,h in expected.items())
cache=(B/'CMakeCache.txt').read_text();assert 'RVV_HOST_CHUNK_BITS:STRING=512' in cache and 'CMAKE_BUILD_TYPE:STRING=Release' in cache
commands=json.loads((B/'compile_commands.json').read_text())
production=[c for c in commands if 'CMakeFiles/dbtstatic.dir/' in c['command'] or 'CMakeFiles/dbtjitshared.dir/' in c['command'] or 'CMakeFiles/elfrun.dir/' in c['command']]
assert all(all(flag in c['command'] for flag in ('-DRVV_HOST_CHUNK_BITS=512','-mavx512f','-mavx512bw','-O3','-DNDEBUG')) for c in production if c['file'].endswith('.cpp'))
assert 'static constexpr u32 ELEN_BITS = 64;' in (S/'dbt/guest/rv32_vector.h').read_text()
elfs={}
for suite,key in [('chips','cells'),('act','calls'),('ara','calls')]:
 for c in json.loads((R/suite/'QUEUE.json').read_text())[key]:
  if suite=='chips': p=Path('/home/vick/rvv_final_regression_20261007/inputs')/(c['elf_sha256']+'.elf')
  elif suite=='act':p=Path(c['elf'])
  else:p=Path(c['elf'].replace('/home/user/research/materials/thesis_rvv_20260921/artifacts/rvv_validation_delivery_20261009/','/home/vick/'))
  if str(p) in elfs:continue
  with p.open('rb') as f: h=f.read(20)
  assert h[:4]==b'\x7fELF' and h[4]==1 and h[5]==1 and int.from_bytes(h[18:20],'little')==243
  elfs[str(p)]=dict(ELFCLASS=32,machine='RISC-V',sha256=c['elf_sha256'])
result=dict(status='PASS',phase=sys.argv[1],build=str(B),production_commands=len(production),cpp=sum(c['file'].endswith('.cpp') for c in production),host_chunk_bits=512,XLEN=32,ELEN=64,
 configuration_evidence='Actual cache and production compile commands select host512. All original guests are little-endian RISC-V ELF32 and use the compiled rv32 engine. ELEN64 is the authenticated compiled implementation constant, not a runtime tuple census.',
 files={str(p):sha(p) for p in (B/'CMakeCache.txt',B/'compile_commands.json',B/'bin/elfrun',B/'lib/libdbtjitshared.so')},source_revision='58c96128b15ba2f278b3b6d589f53d646cc82af2',source_files=expected,guest_ELFs=elfs,
 load=subprocess.check_output(['uptime'],text=True),lscpu=subprocess.check_output(['lscpu'],text=True),affinity=subprocess.check_output(['taskset','-pc',sys.argv[2]],text=True) if len(sys.argv)>2 else None)
(R/('CONFIGURATION_'+sys.argv[1]+'.json')).write_text(json.dumps(result,indent=2)+'\n')
for name in ('CMakeCache.txt','compile_commands.json'):(R/name).write_bytes((B/name).read_bytes())
print('CONFIGURATION_PASS',sys.argv[1],len(production),len(elfs),flush=True)
