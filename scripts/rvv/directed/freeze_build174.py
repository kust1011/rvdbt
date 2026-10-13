#!/usr/bin/env python3
import hashlib,json,os
from pathlib import Path
base=Path('/home/vick/rvdbt-host512-task174-build');old=Path('/home/vick/rvdbt-host512-task172-build/source')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
changes=[];same=0
for p in sorted((base/'source/dbt').rglob('*')):
 if not p.is_file():continue
 rel=p.relative_to(base/'source');prior=old/rel
 if prior.exists() and sha(prior)==sha(p):same+=1
 else:changes.append(dict(path=str(rel),old_sha256=sha(prior) if prior.exists() else None,new_sha256=sha(p)))
assert {x['path'] for x in changes}=={'dbt/guest/rv32_interp.cpp','dbt/qmc/qcg/qemit.cpp','dbt/CMakeLists.txt','dbt/guest/rv32_vector_scalar_insert_test.cpp','dbt/guest/rv32_vector_fma_invalid_test.cpp'},changes
for name in ('BUILD','SCALAR','CONVERSION','FMA','ROUTE','FMA_FINAL'):assert (base/(name+'_RC')).read_text().strip()=='0'
artifacts={str(p.relative_to(base)):sha(p) for p in [base/'build/bin'/x for x in ('elfrun','rv32_vector_scalar_insert_test','rv32_vector_fpconvert_test','rv32_vector_fma_invalid_test','vfma_typedchunk_route_test')]+[base/'build/lib/libdbtjitshared.so',base/'build/lib/libdbtstatic.a']}
manifest=dict(base='immutable172 (167 FMA +172 conversion)',insertion='ONLY three production hunks from73fc8e2',production_changes=['dbt/guest/rv32_interp.cpp:vmvsx/vfmvsf','dbt/qmc/qcg/qemit.cpp:Emit_vscalarmove'],changed_sources=changes,unchanged_source_files=same,artifacts=artifacts,checks=dict(scalar=(base/'scalar.stdout').read_text(),conversion=(base/'conversion.stdout').read_text(),fma=(base/'fma-final.stdout').read_text(),fma_fusion=(base/'fma-final-fusion.stdout').read_text(),route=(base/'route.stderr').read_text()[-300:]),configuration=dict(build_jobs=4,nice=10,affinity='none',host_chunk_bits=512),scope='focused integration only; full family same-build rerun NOT_RUN')
(base/'MANIFEST.json').write_text(json.dumps(manifest,indent=2)+'\n')
(base/'FROZEN').write_text(artifacts['build/bin/elfrun']+'\n')
for tree in (base/'source',base/'build'):
 for p in tree.rglob('*'):
  if not p.is_symlink():p.chmod(p.stat().st_mode&~0o222)
 tree.chmod(tree.stat().st_mode&~0o222)
print(artifacts['build/bin/elfrun'])
