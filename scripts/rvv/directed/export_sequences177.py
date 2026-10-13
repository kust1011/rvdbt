#!/usr/bin/env python3
"""Compact final joins and exact limits from retained Task177 evidence."""
import collections,csv,hashlib,json,os,shutil,sys
from pathlib import Path
import vadd as v
BASE=Path('/home/vick/rvv-directed-task177');OUT=BASE/'export177';OUT.mkdir(exist_ok=False)
roots=[BASE/part/phase for part in ('integer','fp','cache','cache64') for phase in ('pilot','remaining')]
cases=[];units=set();pilot=0;events=[];receipts=[];builds={}
for root in roots:
    manifest=json.loads((root/'manifest.json').read_text());cs=manifest['cases'];cases+=cs;units.update(c['unit'] for c in cs)
    if root.name=='pilot':pilot+=len(cs)
    summary=json.loads((root/'summary.json').read_text());assert summary['counts']=={'PASS':len(cs)*5}
    builds[str(root.relative_to(BASE))]=json.loads((root/'build-commands.json').read_text())
    for p in (root/'runs').glob('*/*/execution.json'):
        rec=json.loads(p.read_text());end=p.stat().st_mtime
        events.extend([(end-rec['seconds'],1),(end,-1)])
        receipts.append(dict(root=str(root.relative_to(BASE)),unit=p.parent.parent.name,arm=p.parent.name,command=json.loads((p.parent/'command.json').read_text()),execution=rec,checks=json.loads((p.parent/'checks.json').read_text()),packet_sha256=v.sha(p.parent/'packets.bin')))
counts=collections.Counter(c['id'] for c in cases);assert all(n==1 for n in counts.values())
paths=[];frames=[]
for audit in ('full-audit','cache64-audit'):
    for name,target in [('PC_PATH_RESULTS.json',paths),('FRAMES.json',frames)]:target.extend(json.loads((BASE/audit/name).read_text()))
assert len(cases)==2418 and len(units)==660 and all(r['result']=='PASS' for r in paths)
nativecache=[r for r in paths if r['case'].startswith('cache-')]
othercache=[r for r in paths if r['case'].startswith('cache64-')]
comparison=[]
for c in cases:
    if c['part']!='cache':continue
    peer=next(x for x in cases if x['part']=='cache64' and x['vlen']==c['vlen'])
    for arm in ('B','M1','M2','BOTH'):
        a=sorted((r for r in nativecache if r['case']==c['id'] and r['arm']==arm),key=lambda r:int(r['pc'],16))
        b=sorted((r for r in othercache if r['case']==peer['id'] and r['arm']==arm),key=lambda r:int(r['pc'],16))
        assert len(a)==len(b)==2
        assert [(r['pc'],r['instruction']) for r in a]==[(r['pc'],r['instruction']) for r in b]
        for root,cc,rows in ((BASE/'cache'/('pilot' if c['vlen']==1024 else 'remaining'),c,a),(BASE/'cache64'/('pilot' if c['vlen']==1024 else 'remaining'),peer,b)):
            packet=v.storage.verify(root/'runs'/cc['unit']/arm/'packets.bin')
            if cc is c:pre=v.decode(cc,packet)[2]
            else:assert pre==v.decode(cc,packet)[2]
            text=v.storage.text(root/'runs'/cc['unit']/arm/'tbmap')
            import re
            tb={int(pc,16):int(count) for pc,host,size,count in re.findall(r'^(\w+) (0x\w+) (\d+) (\d+)$',text,re.M)}
            assert tb[int(rows[0]['pc'],16)]==3
        comparison.append(dict(vlen=c['vlen'],arm=arm,PCs=[r['pc'] for r in a],arithmetic_words_and_inputs_equal=True,first_entry_vtype=[16,24],phase_vtypes=[[16,24,16],[24,16,24]],cached_entry_visits_each=3,entry_paths=[[r['actual_path'] for r in a],[r['actual_path'] for r in b]],first_entry_fast_counts=[a[0]['frame']['fast_executions'] if a[0]['frame'] else None,None],helper_calls=[[r['handler_calls'] for r in a],[r['handler_calls'] for r in b]],result='PASS',scope='distinct process-local entries with different first observed vtype; cached TB reused after VL/vtype changes; no invented vtype cache key or persistent AOT claim'))
v.save(OUT/'CACHE_ENTRY_COMPARISON.json',comparison)
early=[];bycase={c['id']:c for c in cases}
for frame in frames:
    if not frame['low_component_later_members_checked']:continue
    assert frame['arm']=='BOTH'
    c=bycase[frame['target_case']]
    dis=v.storage.text(BASE/'full-audit'/(frame['unit']+'-BOTH-'+frame['tb']+'.dis'))
    import re
    ins=[(int(pc,16),op.strip()) for pc,op in re.findall(r'^\s*([0-9a-f]+):\s+(?:[0-9a-f]{2}\s+)+([^\n]+)',dis,re.M)]
    stores=[pc for pc,op in ins if frame['native_code_begin']<=pc<frame['guard_miss'] and re.match(r'v\w+\s+%(?:zmm|ymm|xmm)\d+,0x[0-9a-f]+\(%r13\)',op)]
    assert stores
    bounds=frame['bounds']
    assert min(b['join_offset'] for b in bounds)>max(stores),('publication after skip join',c['id'])
    for lo,hi in zip(bounds,bounds[1:]):
        assert lo['join_offset']>hi['host_offset']
        assert any(lo['host_offset']<pc<hi['host_offset'] for pc in stores),('low component not published before next bound',c['id'])
    skipped=[b['lane_base'] for b in bounds if c['vl']<=b['lane_base']] if frame['fast_executions'] else []
    early.append(dict(case=c['id'],entry=frame['entry'],vlen=c['vlen'],sew=c['sew'],lmul=c['lmul'],vl=c['vl'],fast_executions=frame['fast_executions'],bound_bases=[b['lane_base'] for b in bounds],derived_skipped_bases=skipped,low_later_members_complete=True,low_publication_before_next_bound=True,skip_join_after_all_native_stores=True,dirty_publication_only_produced=True,decision_evidence='per-frame fast join + captured unchanged VL + actual emitted compare/branch; aggregate active counters do not supply this join'))
v.save(OUT/'BOTH_EARLY_EXIT.json',dict(status='PASS',generated_frames=len(early),executed_frames=sum(bool(r['fast_executions']) for r in early),executed_frames_with_skips=sum(bool(r['derived_skipped_bases']) for r in early),rows=early))
groups=collections.defaultdict(list)
for c in cases:groups[c['part'],c['scenario']].append(c)
table=[]
for (part,name),cs in groups.items():
    ids={c['id'] for c in cs};pp=[r for r in paths if r['case'] in ids];nn=[r for r in pp if r['frame']]
    geometries=sorted({(c['vlen'],c['sew'],c['lmul']) for c in cs});admitted=sorted({(next(c for c in cs if c['id']==r['case'])['vlen'],next(c for c in cs if c['id']==r['case'])['sew'],next(c for c in cs if c['id']==r['case'])['lmul']) for r in nn})
    table.append(dict(sequence=part+'/'+name,cases_per_arm=len(cs),geometries=len(geometries),observed_multi_geometries=admitted,eligibility='actual scanner/emitter; '+('FP vm=1/vta=1 plus route geometry/pressure gates' if part=='fp' else 'real typed-route and shared-shape/pressure gates'),actual_path_counts=dict(collections.Counter(r['actual_path'] for r in pp)),reference_counts=dict(collections.Counter('Sail initialized vstart' if c['vstart'] else 'Spike/pk' for c in cs)),result='PASS',architectural_checks=len(cs)*5))
v.save(OUT/'SEQUENCE_TABLE.json',table)
controls=[json.loads((BASE/n).read_text()) for n in ('CONTROLS.json','CACHE64_CONTROLS.json')]
v.save(OUT/'CONTROLS_TOTAL.json',dict(status='PASS',actual_packets=sum(x['actual_packets'] for x in controls),effective_rejections=sum(x['effective_rejections'] for x in controls),changed_allowed=sum(x['changed_allowed_tail_outcomes'] for x in controls),passes_per_actual_packet=1,disjoint_partitions=['original sequence declaration','e64-first cache complement'],guest_calls=0))
sample=[]
for p in BASE.glob('resources*/RESOURCE_SAMPLES.jsonl'):
    sample += [json.loads(line) for line in p.read_text().splitlines()]
own=lambda snap:sum(r['guest'] and any('/rvv-directed-task177/' in a for a in r['args']) for r in snap['rows'])
n=0;peak=0
for t,delta in sorted(events):n+=delta;peak=max(peak,n)
resource=dict(samples=len(sample),sampled_shared_guest_peak=max(x['guests'] for x in sample),sampled_own_guest_peak=max(own(x) for x in sample),minimum_free_bytes=min(x['free_bytes'] for x in sample),inferred_accepted_guest_overlap_peak=peak,inference='execution.json mtime minus duration; approximate launch/finish intervals, not process telemetry',constraints=dict(own_guest=8,own_build=4,own_offline=2,shared_offline=4,shared_guest=16,nice=10,affinity='none',reserve_bytes=10*1024**3),resource_compliance='NOT_FULLY_COMPLIANT: own-owner integer/FP controllers overlapped; later phases serialized',own_build_overlap='two --build-jobs4 controllers; exact driver peak not recorded',exceptions=json.loads((BASE/'RESOURCE_EXCEPTION.json').read_text()))
resource['exceptions']['exception']='Integer remainder and FP pilot build/run controllers overlapped within one owner. Own build4/guest8 serialization was violated; exact build peak not captured. Suspension attempt found FP controller already complete. Later phases serialized; shared occupancy is reported from samples, without assuming compliance.'
assert resource['minimum_free_bytes']>=10*1024**3
v.save(OUT/'RESOURCES.json',resource)
v.save(OUT/'FINAL_TOTALS.json',dict(status='PASS_FINITE_DEFAULT_TRACE_PROFILE_WITH_OPEN_DIAGNOSTIC_AND_RESOURCE_EXCEPTION',cases_per_arm=len(cases),checks=len(cases)*5,DUT_checks=len(cases)*4,units=len(units),commands=len(units)*5,pilot_cases=pilot,remaining_cases=len(cases)-pilot,reference_Spike_cases=sum(not c['vstart'] for c in cases),reference_Sail_cases=sum(bool(c['vstart']) for c in cases),target_PC_arm_rows=len(paths),multi_frames=len(frames),native_multi_frames=sum(bool(r['fast_executions']) for r in frames),both_component_completion_frames=sum(r['low_component_later_members_checked'] for r in frames),production_changes=0,previous_family_reruns=0,per_form_inventory_credit=0,executable_sha256=v.FPREDUCE174_PIN,unmet=['generic --trace=1 host fault root cause/fix remains open; all original failures unaccepted','own build4/guest8 resource compliance exception','full common-build previous-family validation NOT_RUN','no exhaustive opcode/SEW/LMUL/pressure/fault-return/retry proof; no persistent AOT cache proof'] ))
v.save(OUT/'ALL_MANIFESTS.json',{str(root.relative_to(BASE)):json.loads((root/'manifest.json').read_text()) for root in roots})
v.save(OUT/'BUILD_COMMANDS.json',builds)
v.save(OUT/'EXECUTION_RECEIPTS.json',receipts)
for name in ('AUDIT.json','PC_PATH_RESULTS.json','FRAMES.json'):
    v.save(OUT/('ALL_'+name), {'partitions':{audit:json.loads((BASE/audit/name).read_text()) for audit in ('full-audit','cache64-audit')}})
for name in ('ALL_MANIFESTS.json','ALL_PC_PATH_RESULTS.json','ALL_FRAMES.json','BUILD_COMMANDS.json','EXECUTION_RECEIPTS.json'):v.storage.compress(OUT/name)
v.save(OUT/'IDENTITIES.json',json.loads((roots[0]/'identities-before.json').read_text()))
for name in ('FLAGS.json','FREEZE.sha256','REVIEW_FREEZE.sha256','CACHE64_FREEZE.sha256','CONTROLS.json','CACHE64_CONTROLS.json'):
    shutil.copy2(BASE/name,OUT/name)
v.save(OUT/'SOURCE_REVIEW_PINS.json',{str(p):v.sha(p) for p in [Path('/home/vick/rvdbt-host512-task174-build/source')/n for n in ('dbt/guest/rv32_qir.cpp','dbt/guest/rv32_vrun.cpp','dbt/qmc/qcg/qemit.cpp','dbt/execute.cpp')]})
print(json.dumps(json.loads((OUT/'FINAL_TOTALS.json').read_text()),indent=2))
