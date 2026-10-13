#!/usr/bin/env python3
"""Join disjoint conversion pilot/full partitions; zero guest or reference replay."""
import collections,csv,json,shutil,sys
from pathlib import Path
import fpconvert172 as f
import vadd as v

def join(base):
 out=base/'review';out.mkdir(exist_ok=False);root=out/'corpus';root.mkdir();(root/'runs').mkdir();rows=f.cases()
 for i,c in enumerate(rows):c['ordinal']=i
 v.save(root/'manifest.json',dict(family='fpconvert172',project_tests=True,cases=rows,units=len({c['unit'] for c in rows}),planned_case_executions=len(rows)*5,reference='pinned Spike/Sail + exact rational/bit predicates'))
 results=[];builds=[];seen=set();lineage=[];identities=None
 for branch in ('same','widen','narrow'):
  for phase in ('pilot','remaining'):
   original=base/(branch+'-'+phase)/'corpus';manifest=json.loads((original/'manifest.json').read_text());units={c['unit'] for c in manifest['cases']};assert not seen&units;seen|=units
   result=json.loads((original/'results.json').read_text());assert len(result)==len(manifest['cases'])*5 and all(r['status']=='PASS' for r in result)
   for unit in units:(root/unit).symlink_to(original/unit,target_is_directory=True);(root/'runs'/unit).symlink_to(original/'runs'/unit,target_is_directory=True)
   results+=result;builds+=json.loads((original/'build-commands.json').read_text())
   a=json.loads((original/'identities-before.json').read_text());assert a==json.loads((original/'identities-after.json').read_text())
   if identities is None:identities=a
   assert a==identities
   lineage.append(dict(original=str(original),cases=len(manifest['cases']),units=len(units),manifest_sha256=v.sha(original/'manifest.json'),results_sha256=v.sha(original/'results.json')))
 assert seen=={c['unit'] for c in rows}
 assert {(r['case'],r['arm']) for r in results}=={(c['id'],a) for c in rows for a in ('Reference','B','M1','M2','BOTH')}
 v.save(root/'results.json',results);v.save(root/'build-commands.json',builds)
 for name in ('user.ld','sail.ld'):shutil.copy2(base/'same-pilot/corpus'/name,root/name)
 for name in ('identities-before.json','identities-after.json'):v.save(root/name,identities)
 v.save(out/'VIEW_LINEAGE.json',dict(parts=lineage,cases=len(rows),checks=len(results),units=len(seen),guest_executions_added=0,reference_executions_added=0,disjoint_units=True))
 ids={c['id']:c for c in rows};counts=collections.Counter((ids[r['case']]['mnemonic'],r['arm'],r['status']) for r in results)
 with (out/'PER_FORM.csv').open('w') as stream:
  writer=csv.writer(stream);writer.writerow(['form','arm','status','checks'])
  for key,n in sorted(counts.items()):writer.writerow([*key,n])
 v.save(out/'EXECUTION_SUMMARY.json',dict(cases=len(rows),units=len(seen),commands=len(seen)*5,checks=len(results),arms={a:dict(collections.Counter(r['status'] for r in results if r['arm']==a)) for a in ('Reference','B','M1','M2','BOTH')}))
 print(len(rows),len(results),flush=True)
if __name__=='__main__':join(Path(sys.argv[1]))
