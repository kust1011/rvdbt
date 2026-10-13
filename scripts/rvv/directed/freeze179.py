#!/usr/bin/env python3
"""Pin and freeze isolated179, comparing only its small DBT source tree to174."""
import hashlib,json,os,subprocess,fcntl
from pathlib import Path
B=Path('/home/vick/rvdbt-host512-task179-build');O=Path('/home/vick/rvdbt-host512-task174-build');E=Path('/home/vick/rvv-directed-task179')
lock=open('/home/vick/rvv-directed-task179.own-semaphore','a');fcntl.flock(lock,fcntl.LOCK_EX)
assert os.getpriority(os.PRIO_PROCESS,0)==10
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
r=subprocess.run(['diff','-qr',str(O/'source/dbt'),str(B/'source/dbt')],capture_output=True,text=True)
assert r.returncode==1 and len(r.stdout.splitlines())==2,r.stdout
paths=['dbt/qmc/qcg/qemit.cpp','dbt/qmc/qcg/rvv_vector_run_codegen_test.cpp']
for p in paths:assert str(B/'source'/p) in r.stdout
assert json.loads((E/'FOCUSED_REPLAY.json').read_text())['status']=='PASS'
assert json.loads((E/'CONTRACTS.json').read_text())['status']=='PASS'
for t in [0,1]:
 for group in ['main','cache64']:assert json.loads((E/f'audit-trace{t}-{group}/AUDIT.json').read_text())['status']=='PASS'
artifacts={str(p.relative_to(B)):sha(p) for p in [B/'build/lib/libdbtstatic.a',B/'build/lib/libdbtjitshared.so',*sorted((B/'build/bin').iterdir())]}
manifest=dict(base=str(O),base_manifest_sha256=sha(O/'MANIFEST.json'),base_candidate_sha256=sha(O/'build/bin/elfrun'),production_change='Emit_Cache trace call preserves the nonleaf region frame',production_source_changes=[paths[0]],test_source_changes=[paths[1]],changes=[dict(path=p,old_sha256=sha(O/'source'/p),new_sha256=sha(B/'source'/p)) for p in paths],unchanged_source_evidence=r.stdout,artifacts=artifacts,configuration=dict(build_jobs=4,nice=10,affinity='none',host_chunk_bits=512,compiler='clang22',build_type='Release',rvdbt_census=True,rvdbt_fast_stats=True,fp_contract_off=True,host_fma=False,fround_impl=2),full_common_build='NOT_RUN;178 remains pinned174',scope='focused trace/default and existing P3 contract regression')
(B/'MANIFEST.json').write_text(json.dumps(manifest,indent=2)+'\n');(B/'FROZEN').write_text(artifacts['build/bin/elfrun']+'\n')
for t in [0,1]:
 for part in ['integer','fp','cache','cache64']:
  pin=json.loads((E/f'trace{t}/{part}/identities-after.json').read_text())
  assert pin[str(B/'build/bin/elfrun')]==artifacts['build/bin/elfrun'] and pin[str(B/'build/lib/libdbtjitshared.so')]==artifacts['build/lib/libdbtjitshared.so']
for tree in [B/'source',B/'build']:
 for p in tree.rglob('*'):
  if not p.is_symlink():p.chmod(p.stat().st_mode&~0o222)
 tree.chmod(tree.stat().st_mode&~0o222)
print(artifacts['build/bin/elfrun'])
