#!/usr/bin/env python3
"""Export compact Task170 evidence and exact totals; never execute a guest."""
import collections,csv,gzip,hashlib,json,shutil,sys
from pathlib import Path
import vadd as v

def export(base,out):
 assert (base/'COMPLETE_V2').exists();out.mkdir(parents=True,exist_ok=False)
 audit=base/'review/audit-parallel/audit'
 for source,name in [(audit/'audit.json','AUDIT.json'),(audit/'observed-checks.csv.gz','observed-checks.csv.gz'),(base/'review/PER_FORM.csv','PER_FORM.csv'),(base/'review/EXECUTED_MANIFEST.json.gz','EXECUTED_MANIFEST.json.gz'),(base/'review/EXECUTION_SUMMARY.json','EXECUTION_SUMMARY.json'),(base/'review/VIEW_LINEAGE.json','VIEW_LINEAGE.json'),(base/'review/audit-parallel/workers.json','AUDIT_WORKERS.json'),(base/'review/audit-parallel/parallel.json','PARALLEL.json'),(base/'OFFLINE_V2_ADMISSION.json','OFFLINE_ADMISSION.json'),(base/'PIPELINE_V2_STATUS.json','PIPELINE_STATUS.json'),(base/'REVIEW_V2_STATUS.json','REVIEW_STATUS.json')]:
  if source.exists():shutil.copy2(source,out/name)
 # The finalizer trap writes REVIEW_V2_STATUS only on exit; the COMPLETE marker
 # is written immediately before its successful exit. Validate both externally.
 manifest=json.loads((base/'review/corpus/manifest.json').read_text());cases=manifest['cases'];ids={c['id']:c for c in cases}
 forms=collections.Counter();widths=collections.Counter()
 for c in cases:forms[c['mnemonic']+'.'+c['form']]+=1;widths[(c['mnemonic']+'.'+c['form'],c['vlen'])]+=1
 with (out/'PER_FORM_WIDTH.csv').open('w') as stream:
  w=csv.writer(stream);w.writerow(['form','vlen','checks_per_arm'])
  for key,n in sorted(widths.items()):w.writerow([*key,n])
 generic=collections.Counter();semantic=collections.Counter();effective_allow=collections.Counter();allow_calls=collections.Counter();selected_cases=set();control_parts=[]
 for branch in ('minmax','sign','compare-class'):
  for phase in ('pilot','remaining'):
   part=base/(branch+'-'+phase+('-v2' if branch=='compare-class' else ''));g=json.loads((part/'controls/CONTROLS.json').read_text());s=json.loads((part/'semantic-controls/SEMANTIC_CONTROLS.json').read_text())
   assert g['status']==s['status']=='PASS' and not selected_cases&set(g['selected']);selected_cases.update(g['selected']);assert set(g['selected'])<=set(ids)
   generic.update(g['rejections']);allow_calls.update(g['allowed_variants'])
   for r in s['by_form_control']:semantic[(r['form'],r['control'])]+=r['count']
   for r in s['allowed_by_form']:effective_allow[(r['form'],r['control'])]+=r['count']
   control_parts.append(dict(part=str(part),generic_rejections=g['effective_rejections'],semantic_rejections=s['effective_rejections'],effective_allowed_variants=s['effective_allowed_variants'],generic_sha256=v.sha(part/'controls/CONTROLS.json'),semantic_sha256=v.sha(part/'semantic-controls/SEMANTIC_CONTROLS.json')))
   prefix=branch+'-'+phase
   shutil.copy2(part/'controls/CONTROLS.json',out/(prefix+'-CONTROLS.json'));shutil.copy2(part/'semantic-controls/SEMANTIC_CONTROLS.json',out/(prefix+'-SEMANTIC_CONTROLS.json'));shutil.copy2(part/'semantic-controls/MUTATIONS.json.gz',out/(prefix+'-MUTATIONS.json.gz'))
 assert set(form for form,control in semantic)==set(forms)
 v.save(out/'CONTROL_TOTALS.json',dict(parts=control_parts,selected_generic_actual_packets=len(selected_cases)*5,generic_effective_rejections=sum(generic.values()),semantic_effective_rejections=sum(semantic.values()),total_effective_rejections=sum(generic.values())+sum(semantic.values()),effective_allowed_variants=sum(effective_allow.values()),generic_by_control=dict(generic),semantic_by_form_control=[dict(form=form,control=name,count=n) for (form,name),n in sorted(semantic.items())],effective_allow_by_form=[dict(form=form,control=name,count=n) for (form,name),n in sorted(effective_allow.items())],generic_allowance_checks_including_identity_calls=dict(allow_calls),metadata_note='The semantic tool actual_mutations field counts logged rejection/mask records and omits vector-tail allowance records. Exact effective totals here use its separately asserted rejection/changed-allowance counters. Generic allowance calls may be identity variants and receive no effective-allowance credit.'))
 samples=[]
 for monitor in ('monitor','monitor-v2'):
  p=base/monitor/'RESOURCE_SAMPLES.jsonl'
  if p.exists():
   shutil.copy2(p,out/(monitor+'-RESOURCE_SAMPLES.jsonl'));samples.extend(json.loads(s) for s in p.read_text().splitlines())
 own_guest=[];own_offline=[];nices=set();affinities=set()
 for s in samples:
  ours=[r for r in s['rows'] if any('/rvv-directed-task170/' in a for a in r['args'])]
  own_guest.append(sum(r['guest'] for r in ours));own_offline.append(sum(r['offline'] for r in ours))
  for r in ours:
   if r['guest'] or r['offline']:nices.add(r['nice']);affinities.add(r['affinity'])
 v.save(out/'RESOURCE_VERIFICATION.json',dict(samples=len(samples),own_guest_peak=max(own_guest,default=0),shared_guest_peak=max((s['guests'] for s in samples),default=0),own_offline_peak=max(own_offline,default=0),shared_offline_peak=max((s['offline'] for s in samples),default=0),sampled_min_free_bytes=min(s['free_bytes'] for s in samples),own_guest_offline_nice_values=sorted(nices),observed_affinities=sorted(affinities),build_parallelism='CLI --build-jobs4, one build stage at a time; compiler processes not sampled by this observer',startup_limits='8 guest / 4 build / 4 offline; shared16/4; 10GiB reserve',sampling_limits='monitor began after min/max pilot; a gap separates the stopped original controller from the repaired controller. Samples are observations, not a claim of continuous early/startup coverage. Existing Task168 offline admission and resources164 guest gate receipts remain with each stage.'))
 summary=json.loads((audit/'audit.json').read_text());assert summary['planned_cases']==96681 and summary['executed_case_checks']==483405 and not summary['failures'];assert all(x['PASS']==96681 and x['FAIL']==x['ISA_ONLY_REFERENCE_BLOCKED']==0 for x in summary['counts'].values())
 # Exact retained commands, not the repeated per-case receipts.
 v.save(out/'FINAL_TOTALS.json',dict(forms=len(forms),geometries=len({(c['vlen'],c['sew'],c['lmul']) for c in cases}),ordinary_cases=96681,checks_per_arm=96681,accepted_DUT_checks=386724,accepted_reference_checks=96681,accepted_checks=483405,accepted_units=2268,accepted_DUT_commands=9072,accepted_reference_commands=2268,accepted_commands=11340,original_reserved_layout_attempt_units=10,original_failed_case_receipts=3660,all_new_matrix_case_receipts=487065,all_new_matrix_commands=11390,reference_blocked_ordinary=0,missing_checks=0,execution_anomalies=0,scalar_regression_checks=896,scalar_regression_DUT_commands=32,initial_scalar_harness='Two vv units / 8 DUT commands ran before vf assembly failure; retained but no added ordinary credit.',per_form_checks_per_arm=dict(forms),method_admission='NOT_ESTABLISHED per target M1/M2; configuration-arm labels are architectural differential checks'))
 v.save(out/'EVIDENCE_SHA256.json',{p.name:v.sha(p) for p in out.iterdir() if p.is_file()})
 print(json.loads((out/'FINAL_TOTALS.json').read_text()))
if __name__=='__main__':export(Path(sys.argv[1]),Path(sys.argv[2]))
