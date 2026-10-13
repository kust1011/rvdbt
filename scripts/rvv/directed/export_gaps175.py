#!/usr/bin/env python3
"""Export compact receipts from final complete raw audits; no replay or tree hashing."""
import collections,csv,json,shutil,sys
from pathlib import Path
import vadd as v

def read(p):return json.loads(p.read_text())
def export(base,out):
 out.mkdir(parents=True,exist_ok=False);combined=[];ids=set();total_units=0;total_controls=0;total_allowed=0;pilot=0;sail_commands=0;sail_checks=0;profiles=collections.defaultdict(set);counts=collections.Counter();maincounts=collections.Counter();suppcounts=collections.Counter();identity=None;records=[]
 for family in ('fpslide175','fpmerge175','narrow175','supplement'):
  p=base/family;assert (p/'COMPLETE').exists(),family;d=out/family;d.mkdir()
  root=p/'corpus' if family=='supplement' else p/'review/corpus'
  aud=p/'audit' if family=='supplement' else p/'review'/('audit-parallel-v2/audit' if family=='fpslide175' else 'audit-parallel/audit')
  a=read(aud/'audit.json');assert not a['failures'] and all(x['FAIL']==x['ISA_ONLY_REFERENCE_BLOCKED']==0 for x in a['counts'].values())
  manifest=read(root/'manifest.json');rows=manifest['cases'];results=read(root/'results.json');case={c['id']:c for c in rows};assert len(case)==len(rows) and not ids&case.keys();ids|=case.keys()
  assert len(results)==len(rows)*5==a['executed_case_checks'] and all(r['status']=='PASS' for r in results)
  assert {(r['case'],r['arm']) for r in results}=={(c['id'],arm) for c in rows for arm in ('Reference','B','M1','M2','BOTH')}
  before=read(root/'identities-before.json');assert before==read(root/'identities-after.json')
  if identity is None:identity=before
  assert identity==before and list(before.values())[0]==v.FPREDUCE174_PIN
  control=read(p/'controls/CONTROLS.json');assert control['status']=='PASS' and control['selected_actual_packets']>0;total_controls+=control['effective_rejections'];total_allowed+=control['changed_allowed']
  total_units+=manifest['units'];combined+=rows
  for r in results:
   c=case[r['case']];form=c['mnemonic']+'.'+c['form'];counts[form,r['arm']]+=1
  for c in rows:
   form=c['mnemonic']+'.'+c['form'];profiles[form].add((c['vlen'],c['sew'],c['lmul'],c['vlmax'],c['src_registers'],c['group_registers']))
   (suppcounts if family=='supplement' else maincounts)[form]+=1
  for src,name in [(aud/'audit.json','AUDIT.json'),(p/'controls/CONTROLS.json','CONTROLS.json'),(p/'prepared/DECLARATION.json','DECLARATION.json'),(p/'FREEZE.sha256','FREEZE.sha256')]:shutil.copy2(src,d/name)
  if family!='supplement':
   cross=read(p/'sail-crosscheck/SUMMARY.json');assert cross['status']=='PASS';sail_commands+=cross['commands'];sail_checks+=cross['case_checks'];shutil.copy2(p/'sail-crosscheck/SUMMARY.json',d/'SAIL_CROSSCHECK.json');shutil.copy2(p/'review/VIEW_LINEAGE.json',d/'VIEW_LINEAGE.json');pilot+=read(p/'pilot/corpus/summary.json')['planned_cases']
  if (p/'PIPELINE_STATUS.json').exists():shutil.copy2(p/'PIPELINE_STATUS.json',d/'PIPELINE_STATUS.json')
  if family=='fpslide175':
   # Original audit failure is a tuple/list comparison error; final audit is separate.
   v.save(d/'FINAL_REVIEW.json',dict(status='PASS',original_pipeline_stage='audit',original_returncode=1,corrected_audit='review/audit-parallel-v2/audit',guest_replay=0,checker_change='canonical JSON list normalization only',original_tools=str(base/'tools'),review_tools=str(base/'tools-review175')))
  with (d/'PER_FORM.csv').open('w') as stream:
   w=csv.writer(stream);w.writerow(['form','arm','status','checks'])
   for key,n in sorted(collections.Counter((case[r['case']]['mnemonic']+'.'+case[r['case']]['form'],r['arm']) for r in results).items()):w.writerow([*key,'PASS',n])
  v.save(d/'RAW_AUDIT_COMPLETENESS.json',dict(raw_root=str(p),guest_elf_identities=len(read(aud/'guest-pins.json')),cases=len(rows),checks=len(results),commands=a['executed_commands'],adapter_verified_units=a['adapter_verified_units'],extra_raw_file_inventory='NONE'))
  records.append(dict(family=family,cases=len(rows),units=manifest['units'],checks=len(results),commands=a['executed_commands']))
 per=[]
 for form,configs in sorted(profiles.items()):
  item=dict(form=form,status='PASS_FINITE_SCOPE',main_cases_per_arm=maincounts[form],supplement_cases_per_arm=suppcounts[form],cases_per_arm=maincounts[form]+suppcounts[form],arms={a:counts[form,a] for a in ('Reference','B','M1','M2','BOTH')},configurations=len(configs),build_sha256=v.FPREDUCE174_PIN,failures=0)
  assert len(set(item['arms'].values()))==1;per.append(item);v.save(out/(form.replace('.','-')+'.json'),item)
 v.save(out/'PER_FORM.json',per)
 with (out/'PER_FORM.csv').open('w') as stream:
  writer=csv.writer(stream);writer.writerow(['form','arm','status','checks'])
  for (form,arm),n in sorted(counts.items()):writer.writerow([form,arm,'PASS',n])
 v.save(out/'PROFILE_COMPACT.json',[dict(form=form,configs=[dict(zip(('vlen','sew','lmul','vlmax','source_regs','destination_regs'),x)) for x in sorted(configs)]) for form,configs in sorted(profiles.items())]);v.save(out/'IDENTITIES.json',identity)
 totals=dict(status='PASS_FINITE_SCOPE',forms=len(per),cases_per_arm=len(combined),checks=len(combined)*5,dut_checks=len(combined)*4,units=total_units,commands=total_units*5,reference_commands=total_units,dut_commands=total_units*4,pilot_cases=pilot,supplement_cases=len(read(base/'supplement/corpus/manifest.json')['cases']),partitions=records,effective_rejections=total_controls,changed_allowed=total_allowed,Sail_zero_start_crosscheck_commands=sail_commands,Sail_zero_start_crosscheck_checks=sail_checks,crosscheck_ordinary_credit=0,form_configurations=sum(len(x) for x in profiles.values()),accepted_before175=565,accepted_after175=574,remaining_forms=21,task173_forms=18,session3_unary_forms=3,final_common_build_validation='NOT_RUN',production_changes=0)
 assert len(per)==9;v.save(out/'FINAL_TOTALS.json',totals)
 samples=[json.loads(l) for p in base.glob('*/monitor/RESOURCE_SAMPLES.jsonl') for l in p.read_text().splitlines()];own=[];nice=set();aff=set()
 names=('vfslide1up','vfslide1down','vfmerge','vnsrl','vnsra')
 for snap in samples:
  rs=[r for r in snap['rows'] if any('rvv-directed-task175' in a or any(n in a for n in names) for a in r['args'])];own.append((sum(r['guest'] for r in rs),sum(r['offline'] for r in rs)))
  for r in rs:nice.add(r['nice']);aff.add(r['affinity'])
 v.save(out/'RESOURCES.json',dict(samples=len(samples),own_guest_peak=max(x[0] for x in own),shared_guest_peak=max(x['guests'] for x in samples),own_offline_peak=max(x[1] for x in own),shared_offline_peak=max(x['offline'] for x in samples),minimum_free_bytes=min(x['free_bytes'] for x in samples),nice_values=sorted(nice),affinity_values=sorted(aff),policy=dict(own_guest=8,shared_guest=16,own_build=4,shared_offline=4,own_offline=4,nice=10,affinity='none',reserve=10*1024**3),limits='sampled occupancy only; relative guest args classified by these nine exclusive target forms; standalone zero-start crosschecks and corrected slide audit may occur between monitor samples; build jobs constrained by CLI'))
 print(json.dumps(totals),flush=True)
if __name__=='__main__':export(Path(sys.argv[1]),Path(sys.argv[2]))
