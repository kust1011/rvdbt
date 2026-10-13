#!/usr/bin/env python3
"""New-DUT/reused-reference pilot view, with explicit original failure lineage."""
import collections,json,shutil,sys
from pathlib import Path
import vadd as v

def pilot_view(base):
 original=base/'narrow-pilot/corpus';replay=base/'narrow-pilot-fixed/replay';out=base/'narrow-pilot-fixed/corpus';out.mkdir(exist_ok=False);(out/'runs').mkdir()
 manifest=json.loads((original/'manifest.json').read_text());rows=manifest['cases'];units={c['unit'] for c in rows};new=json.loads((replay/'results.json').read_text());assert len(new)==len(rows)*4 and all(r['status']=='PASS' for r in new)
 prior=json.loads((original/'results.json').read_text());refs=[r for r in prior if r['arm']=='Reference'];assert len(refs)==len(rows) and all(r['status']=='PASS' for r in refs)
 for u in units:
  (out/u).symlink_to(original/u,target_is_directory=True);(out/'runs'/u).mkdir()
  (out/'runs'/u/'Reference').symlink_to(original/'runs'/u/'Reference',target_is_directory=True)
  for arm in ('B','M1','M2','BOTH'):(out/'runs'/u/arm).symlink_to(replay/'runs'/u/arm,target_is_directory=True)
 for name in ('manifest.json','build-commands.json','user.ld','sail.ld'):shutil.copy2(original/name,out/name)
 for name in ('identities-before.json','identities-after.json'):shutil.copy2(replay/name,out/name)
 v.save(out/'results.json',refs+new);summary=dict(planned_cases=len(rows),planned_executions=len(rows)*5,executed=len(rows)*5,counts={'PASS':len(rows)*5},arms={a:{'PASS':len(rows)} for a in ('Reference','B','M1','M2','BOTH')},reference_execution='REUSED original pinned reference packets; zero new pilot reference commands',new_dut_commands=len(units)*4)
 v.save(out/'summary.json',summary)
 v.save(base/'narrow-pilot-fixed/PILOT_REPAIR_LINEAGE.json',dict(original=str(original),new_replay=str(replay),reference_cases_reused=len(rows),reference_commands_reused=len(units),new_dut_checks=len(new),new_dut_commands=len(units)*4,original_dut_failures=sum(r['status']=='FAIL' for r in prior),original_results_sha256=v.sha(original/'results.json'),checker='unchanged frozen original conversion predicates',original_failures_retained=True))
if __name__=='__main__':pilot_view(Path(sys.argv[1]))
