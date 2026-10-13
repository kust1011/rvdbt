#!/usr/bin/env python3
"""Read-only repaired pilot view: reuse successful units, replace reserved-layout units."""
import collections,json,shutil,sys
from pathlib import Path
import fpcompare170 as f
import vadd as v

def join(base):
 original=base/'compare-class-pilot'/'corpus';repair=base/'compare-class-pilot-repair'/'corpus';root=base/'compare-class-pilot-v2'/'corpus';root.mkdir(parents=True,exist_ok=False)
 rows=f.cases()
 for i,c in enumerate(rows):c['ordinal']=i
 units=json.loads((base/'prepared-v2'/'compare-class-pilot.json').read_text());selected=[c for c in rows if c['unit'] in set(units)]
 manifest=dict(family='fpcompare170',project_tests=True,pilot_units=units,cases=selected,units=len(units),planned_case_executions=len(selected)*5,reference='fixed Spike/Sail + independent V1.0 predicates; reserved-layout repair')
 v.save(root/'manifest.json',manifest);replacement=set(json.loads((base/'REPAIR_PILOT_UNITS.json').read_text()));results=[];builds=[];lineage=[]
 for source,wanted in ((original,set(units)-replacement),(repair,replacement)):
  srcmanifest=json.loads((source/'manifest.json').read_text());assert [c for c in srcmanifest['cases'] if c['unit'] in wanted]==[c for c in selected if c['unit'] in wanted]
  srcids={c['id'] for c in selected if c['unit'] in wanted}
  current=[r for r in json.loads((source/'results.json').read_text()) if r['case'] in srcids];assert len(current)==len(srcids)*5 and all(r['status']=='PASS' for r in current)
  results+=current
  for build in json.loads((source/'build-commands.json').read_text()):
   if Path(build['command'][-1]).parent.name in wanted:builds.append(build)
  for unit in wanted:
   (root/unit).symlink_to(source/unit,target_is_directory=True);(root/'runs').mkdir(exist_ok=True);(root/'runs'/unit).symlink_to(source/'runs'/unit,target_is_directory=True)
  lineage.append(dict(source=str(source),units=sorted(wanted),manifest_sha256=v.sha(source/'manifest.json'),results_sha256=v.sha(source/'results.json')))
 v.save(root/'results.json',results);v.save(root/'build-commands.json',builds)
 for name in ('user.ld','sail.ld','identities-before.json','identities-after.json'):shutil.copy2(repair/name,root/name)
 v.save(root.parent/'REPAIR_LINEAGE.json',dict(parts=lineage,reexecuted_units=len(replacement),reused_units=len(units)-len(replacement),original_reserved_failures='retained at compare-class-pilot; excluded from ordinary corrected view'))
 print(len(selected),len(results))
if __name__=='__main__':join(Path(sys.argv[1]))
