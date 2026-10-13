#!/usr/bin/env python3
"""Compact export after one reviewed raw-completeness audit; no replay/package crawl."""
import collections,csv,hashlib,json,shutil,sys
from pathlib import Path

def read(p):return json.loads(p.read_text())
def save(p,x):p.write_text(json.dumps(x,indent=2)+'\n')
def export(base,out):
 assert (base/'COMPLETE_FIXED').exists();out.mkdir(parents=True,exist_ok=False)
 audit=base/'review/audit-parallel/audit';a=read(audit/'audit.json');s=read(base/'review/EXECUTION_SUMMARY.json');assert not a['failures'] and a['executed_case_checks']==s['checks']
 assert all(x['FAIL']==0 and x['ISA_ONLY_REFERENCE_BLOCKED']==0 for x in a['counts'].values())
 for source,name in [(audit/'audit.json','AUDIT.json'),(base/'review/PER_FORM.csv','PER_FORM.csv'),(base/'review/VIEW_LINEAGE.json','VIEW_LINEAGE.json'),(base/'review/EXECUTION_SUMMARY.json','EXECUTION_SUMMARY.json'),(base/'FREEZE.sha256','FREEZE.sha256'),(base/'PIPELINE_FIXED_STATUS.json','PIPELINE_FIXED_STATUS.json'),(base/'FINALIZATION_FIXED_STATUS.json','FINALIZATION_FIXED_STATUS.json'),(base/'same-pilot/corpus/identities-before.json','IDENTITIES.json')]:shutil.copy2(source,out/name)
 rejections=collections.Counter();allowances=collections.Counter();controls=[];parts=[];cases=units=0
 for branch in ('same','widen','narrow'):
  for phase in ('pilot','remaining'):
   part=base/(branch+'-'+phase+('-fixed' if branch=='narrow' else ''));p=read(part/'corpus/summary.json');m=read(part/'corpus/manifest.json');u=len({c['unit'] for c in m['cases']});cases+=p['planned_cases'];units+=u
   assert p['counts']=={'PASS':p['planned_executions']}
   c=read(part/'controls/CONTROLS.json');assert c['status']=='PASS';rejections.update(c['rejections']);allowances.update(c['allowances'])
   # Export counts, provenance and semantic totals only, avoiding repetitive IDs.
   small={k:v for k,v in c.items() if k!='selected'};save(out/(branch+'-'+phase+'-CONTROLS.json'),small);controls.append(dict(part=part.name,**small))
   parts.append(dict(part=part.name,cases=p['planned_cases'],units=u,commands=u*5,checks=p['planned_executions'],arms=p['arms']))
 assert cases==s['cases'] and units==s['units'];save(out/'CONTROL_TOTALS.json',dict(effective_rejections=sum(rejections.values()),effective_changed_allowances=sum(allowances.values()),rejections=dict(rejections),allowances=dict(allowances),selected_actual_packets=sum(c['selected_actual_packets'] for c in controls)))
 save(out/'FINAL_TOTALS.json',dict(cases=cases,units=units,forms=21,form_config_pairs=864,geometries=162,commands=units*5,dut_commands=units*4,reference_commands=units,checks=cases*5,dut_checks=cases*4,per_arm_checks=cases,pilot_cases=sum(p['cases'] for p in parts if '-pilot' in p['part']),pilot_units=sum(p['units'] for p in parts if '-pilot' in p['part']),remaining_cases=sum(p['cases'] for p in parts if '-remaining' in p['part']),remaining_units=sum(p['units'] for p in parts if '-remaining' in p['part']),parts=parts,reference_packets_reused=8280,reference_reuse_scope='corrected narrowing pilot reuses validated original references; each unique reference case executed once during Task172',accepted_build_scope='same/widen immutable167; narrow immutable172; separate final same-build regression remains queued',retained_original_pilot_dut_checks=33120,retained_original_pilot_dut_commands=224,retained_original_dut_failures=48,total_new_matrix_commands=units*5+224,total_new_matrix_receipts=cases*5+33120,diagnostic_commands=9,diagnostic_case_credit=0,guest_replays_added_by_export=0,raw_completeness='single complete independently reviewed audit; no extra recursive retention packaging/checksum census'))
 pins=read(audit/'guest-pins.json');adapters=read(audit/'adapter-verification.json');save(out/'AUDIT_COMPLETENESS.json',dict(elf_identities=len(pins),sail_adapters=len(adapters),executed_commands=a['executed_commands'],executed_case_checks=a['executed_case_checks'],identity_scope='all guest build hashes, generated target words, shared Sail body/adapters, raw logical/compressed storage receipts, extraction, denominator and independently checked packet states in existing audit',large_raw_evidence_retained=str(base),extra_file_inventory='NONE'))
 samples=[]
 for folder in ('monitor','monitor-finalize','monitor-fixed','monitor-fixed-finalize'):
  path=base/folder/'RESOURCE_SAMPLES.jsonl'
  if path.exists():samples.extend(json.loads(line) for line in path.read_text().splitlines())
 own_guest=[];own_offline=[];nice=set();affinity=set();peak_guest=peak_offline=0
 for snap in samples:
  own=[r for r in snap['rows'] if any('rvv-directed-task172' in x for x in r['args'])]
  own_guest.append(sum(r['guest'] for r in own));own_offline.append(sum(r['offline'] for r in own));peak_guest=max(peak_guest,snap['guests']);peak_offline=max(peak_offline,snap['offline'])
  for r in own:nice.add(r['nice']);affinity.add(r['affinity'])
 save(out/'RESOURCES.json',dict(sample_count=len(samples),own_guest_peak=max(own_guest,default=0),shared_guest_peak=peak_guest,own_offline_peak=max(own_offline,default=0),shared_offline_peak=peak_offline,min_free_bytes=min(x['free_bytes'] for x in samples),nice_values=sorted(nice),affinities=sorted(affinity),policy=dict(own_guests=8,own_build_jobs=4,shared_guests=16,shared_offline=4,own_offline=4,nice=10,affinity='none assigned',disk_reserve_bytes=10*1024**3),monitoring='original and fixed guest/finalizer monitors; diagnostic/build repair interval is a monitoring gap; sampled occupancy only; build concurrency enforced by CLI'))
 shutil.copy2(Path('/home/vick/rvdbt-host512-task172-build/MANIFEST.json'),out/'BUILD_MANIFEST.json')
 shutil.copy2(base/'FIXED_FREEZE.sha256',out/'FIXED_FREEZE.sha256')
 shutil.copy2(base/'narrow-pilot-fixed/PILOT_REPAIR_LINEAGE.json',out/'PILOT_REPAIR_LINEAGE.json')
 print(cases,units,sum(rejections.values()),sum(allowances.values()))
if __name__=='__main__':export(Path(sys.argv[1]),Path(sys.argv[2]))
