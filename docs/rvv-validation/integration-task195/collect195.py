"""Seal Task195-owned raw, dereferencing only its explicitly reused long192 unit."""
import hashlib,json,os,shutil,tarfile
from pathlib import Path as P
r=P('/home/vick/rvv-integration-task195');f=P('/home/vick/rvv-long-task192');admin=r/'administrative'
def sha(p):return hashlib.sha256(P(p).read_bytes()).hexdigest()
def save(p,x):P(p).write_text(json.dumps(x,indent=2)+'\n')
assert os.getpriority(os.PRIO_PROCESS,0)==10 and shutil.disk_usage(r).free>=10*1024**3
for p in list(P('/home/vick').glob('run195*.py'))+list(P('/home/vick').glob('task195-*.log')):shutil.copy2(p,admin/p.name)
for p in ['CMakeCache.txt','dbt/CMakeFiles/vchunk_dataflow_test.dir/flags.make','dbt/CMakeFiles/rvv_fp_shared_mask_test.dir/flags.make','dbt/CMakeFiles/vchunk_dataflow_test.dir/link.txt','dbt/CMakeFiles/rvv_fp_shared_mask_test.dir/link.txt']:
 shutil.copy2(f/'build'/p,admin/p.replace('/','__'))
for p in ['dbt/qmc/qcg/vchunk_dataflow_test.cpp','dbt/qmc/qcg/rvv_fp_shared_mask_test.cpp','dbt/qmc/qcg/qra.cpp']:shutil.copy2(f/'source'/p,admin/P(p).name)
for p in ['SUMMARY.json','FIXED_PIN.json','MANIFEST.json','ORIGINAL_FAILURE.tar.gz']:
 source=f/p
 if source.exists():shutil.copy2(source,admin/('task192-'+p))
# Frozen CHIPS ELF/oracle provenance and original source metadata: read-only reuse.
original=P('/home/vick/rvv_final_regression_20261007');m=json.loads((original/'MANIFEST.json').read_text());sel=json.loads((r/'SELECTION.json').read_text());hashes={x['cell']['elf_sha256'] for x in sel['chips_calls']}
provenance=dict(original_manifest_sha256=sha(original/'MANIFEST.json'),task120_manifest_sha256=sha('/home/vick/chips-current120/manifest.json'),task121_queue_sha256=sha('/home/vick/act-current121/QUEUE.json'),inputs={h:m['inputs'][h] for h in hashes},expected_predicate='original chips120.classify: original returncode and exact stdout',source_metadata=m['source_hashes'])
for p,h in m['source_hashes'].items():
 assert sha(original/p)==h
 shutil.copy2(original/p,admin/P(p).name)
save(r/'PROVENANCE.json',provenance)
# Complete raw file index; no runtime binaries included.
files={str(p.relative_to(r)):dict(bytes=p.stat().st_size,sha256=sha(p)) for p in sorted(r.rglob('*')) if p.is_file() and p.name not in ('raw-receipts.tar.gz','RAW_INDEX.json','RETENTION.json','ARCHIVE_OMISSIONS.json')}
save(r/'RAW_INDEX.json',files)
archive=r/'raw-receipts.tar.gz'
omitted=[]
def add(t,p,arc):
 if '__pycache__' in p.parts:return
 if p.is_symlink() and not p.exists():
  omitted.append(dict(path=str(p.relative_to(r)),target=os.readlink(p),reason='unused broken reuse symlink; no bytes exist'));return
 t.add(p,arcname=arc,recursive=False)
 if p.is_dir():
  for child in sorted(p.iterdir()):add(t,child,arc+'/'+child.name)
with tarfile.open(archive,'w:gz',dereference=True) as t:
 for p in sorted(r.iterdir()):
  if p.name not in (archive.name,'RETENTION.json','ARCHIVE_OMISSIONS.json'):add(t,p,'task195/'+p.name)
 omission=r/'ARCHIVE_OMISSIONS.json';save(omission,omitted);t.add(omission,arcname='task195/ARCHIVE_OMISSIONS.json')
receipt=dict(bytes=archive.stat().st_size,sha256=sha(archive),remote=str(archive),free_bytes_after=shutil.disk_usage(r).free)
assert receipt['free_bytes_after']>=10*1024**3
save(r/'RETENTION.json',receipt);print(json.dumps(receipt))
