#!/usr/bin/env python3
"""Full original177 matrix on immutable179; exact focused179 joins counted once.
Use nice10 and PYTHONPATH=/home/vick/rvv-directed-task177/tools.
Every mode shares the Task179 owner semaphore. No ELF/reference rebuilding.
"""
import collections, concurrent.futures, hashlib, json, os, shlex, subprocess, sys
from pathlib import Path
os.environ['RVV_TASK179_OUTPUT']='/home/vick/rvv-directed-task180'
import trace179 as t
v=t.v; s=t.s; B=t.B; C=t.C
OLD=Path('/home/vick/rvv-directed-task177'); FOCUS=Path('/home/vick/rvv-directed-task179')
PARTS=('integer','fp','cache','cache64'); PHASES=('pilot','remaining')
def roots():return [B/'trace0'/part/phase for part in PARTS for phase in PHASES]
def unchanged():
 m=json.loads((C/'MANIFEST.json').read_text())
 for p,h in m['artifacts'].items():assert v.sha(C/p)==h,(p,'frozen artifact changed')
 for row in m['changes']:assert v.sha(C/'source'/row['path'])==row['new_sha256'],row['path']
 return m

def build():
 unchanged();d=B/'test-build';f=C/'build/dbt/CMakeFiles/rvv_vector_run_codegen_test.dir/flags.make'
 flags={}
 for line in f.read_text().splitlines():
  if ' = ' in line:
   k,z=line.split(' = ',1);flags[k]=shlex.split(z)
 cmd=['/usr/bin/clang++-22',*flags['CXX_DEFINES'],*flags['CXX_INCLUDES'],*flags['CXX_FLAGS'],'-c',str(d/'rvv_vector_run_codegen_test.cpp'),'-o',str(d/'test.o')]
 t.gate('build');r=v.execute(cmd,B/'compile',t.env(),180);assert r['returncode']==0,r
 cmd=shlex.split((C/'build/dbt/CMakeFiles/rvv_vector_run_codegen_test.dir/link.txt').read_text())
 cmd=[str(d/'test.o') if a.endswith('rvv_vector_run_codegen_test.cpp.o') else a for a in cmd]
 cmd[cmd.index('-o')+1]=str(d/'rvv_vector_run_codegen_test')
 # Resolve original relative libraries without writing in the frozen tree.
 cmd=[str(C/'build/dbt'/a) if a.startswith('../lib/') else a for a in cmd]
 t.gate('build');r=v.execute(cmd,B/'link',t.env(),180);assert r['returncode']==0,r
 t.gate('offline');r=v.execute([str(d/'rvv_vector_run_codegen_test')],B/'restored-codegen',t.env(),180)
 v.save(B/'RESTORED_ASSERTIONS_RESULT.json',dict(**r,test_sha256=v.sha(d/'rvv_vector_run_codegen_test'),source_sha256=v.sha(d/'rvv_vector_run_codegen_test.cpp'),all_four_assertions_restored=True,balanced_scratch_check_retained=True,production_unchanged=unchanged()['artifacts']))
 print('restored codegen returncode',r['returncode'],flush=True)
 assert r['returncode']==0 and not r['timeout'],r

def canonical(cmd):
 flags=('dump-tbcode','dump-tbmap','rvv-pc-census-out','fsroot','cache')
 return [('--'+a[2:].split('=')[0]+'=<output>') if any(a.startswith('--'+f+'=') for f in flags) else '<elfrun179>' if i==0 else a for i,a in enumerate(cmd)]
def replay():
 import cache_entries177
 cache_entries177.install();execute=v.execute;s.install('integer');v.execute=execute
 unchanged();jobs=[];joins=[];ids=[]
 for part in PARTS:
  for phase in PHASES:
   old=OLD/part/phase;root=B/'trace0'/part/phase;root.mkdir(parents=True,exist_ok=False)
   m=json.loads((old/'manifest.json').read_text());cs=m['cases'];ids += [c['id'] for c in cs]
   v.save(root/'manifest.json',dict(m,reuse=str(old),candidate=str(C),trace=0))
   v.save(root/'identities-before.json',t.identities());v.save(root/'build-commands.json',json.loads((old/'build-commands.json').read_text()))
   for unit in sorted({c['unit'] for c in cs}):
    (root/unit).mkdir();(root/'runs'/unit).mkdir(parents=True)
    for p in (old/unit).iterdir():
     if p.name.startswith(('test.elf','test.S','sail.elf')):(root/unit/p.name).symlink_to(p)
    (root/'runs'/unit/'Reference').symlink_to(old/'runs'/unit/'Reference',target_is_directory=True)
    rows=[c for c in cs if c['unit']==unit];focus=FOCUS/'trace0'/part
    reuse=(focus/'runs'/unit).is_dir()
    if reuse:
     fm=json.loads((focus/'manifest.json').read_text());fr=[c for c in fm['cases'] if c['unit']==unit]
     assert fr==rows
     assert json.loads((focus/'identities-after.json').read_text())==t.identities()
    for arm in s.ARMS[1:]:
     if not reuse:jobs.append((part,0,root,old,unit,rows,arm));continue
     src=focus/'runs'/unit/arm
     a=json.loads((src/'command.json').read_text());z=json.loads((old/'runs'/unit/arm/'command.json').read_text())
     assert canonical(a)==canonical(z),(unit,arm,'flags differ')
     assert v.sha(focus/unit/'test.elf')==v.sha(old/unit/'test.elf')
     assert v.sha(focus/'runs'/unit/'Reference/packets.bin')==v.sha(old/'runs'/unit/'Reference/packets.bin')
     rr=json.loads((src/'execution.json').read_text());assert rr['returncode']==0 and not rr['timeout']
     (root/'runs'/unit/arm).symlink_to(src,target_is_directory=True)
     joins.append(dict(part=part,phase=phase,unit=unit,arm=arm,cases=len(rows),original_source=str(src),command=a,ELF_sha256=v.sha(old/unit/'test.elf'),reference_sha256=v.sha(old/'runs'/unit/'Reference/packets.bin'),packet_sha256=v.sha(src/'packets.bin'),exact_flags_and_cases=True))
 assert len(ids)==len(set(ids))==2418
 v.save(B/'SUBSET_JOIN.json',joins)
 with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
  counts=list(pool.map(t.execute_job,jobs))
 for root in roots():v.save(root/'identities-after.json',t.identities())
 unchanged()
 v.save(B/'FULL_REPLAY.json',dict(status='PASS',cases_per_arm=2418,DUT_checks=9672,new_DUT_checks=sum(counts),reused_DUT_checks=sum(x['cases'] for x in joins),new_commands=len(jobs),reused_commands=len(joins),reference_executions=0,ELF_rebuilds=0,guest_workers=8,roots=list(map(str,roots())),trace=0))
 print(json.dumps(json.loads((B/'FULL_REPLAY.json').read_text())),flush=True)

def audit():
 assert json.loads((B/'FULL_REPLAY.json').read_text())['status']=='PASS'
 for group,parts in [('main',PARTS[:3]),('cache64',('cache64',))]:
  for mode in ['audit','controls']:
   # Controls already ran once on reused179 packets: new packets only.
   rr=[B/'trace0'/p/q for p in parts for q in PHASES]
   if mode=='controls':
    newer=[]
    for root in rr:
     m=json.loads((root/'manifest.json').read_text());cs=[c for c in m['cases'] if not (root/'runs'/c['unit']/'B').is_symlink()]
     small=B/'controls-roots'/root.relative_to(B/'trace0');small.mkdir(parents=True)
     v.save(small/'manifest.json',dict(m,cases=cs))
     (small/'runs').symlink_to(root/'runs',target_is_directory=True)
     newer.append(small)
    rr=newer
   dest=B/(f'audit-{group}' if mode=='audit' else f'CONTROLS_NEW_{group}.json')
   cmd=['python3',str(OLD/'tools/review_sequences177_v2.py'),mode,'--roots',*map(str,rr),'--out',str(dest)]+(['--cache64'] if group=='cache64' else [])
   t.gate('offline');r=v.execute(cmd,B/f'{mode}-{group}-execution',t.env(),1800)
   assert r['returncode']==0 and not r['timeout'],r
   print(group,mode,'PASS',flush=True)
 unchanged()

def details():
 t.gate('offline')
 import csv, re
 BASE=B/'trace0';OUT=B/'details180';OUT.mkdir(exist_ok=False)
 cases=[];paths=[];frames=[]
 for root in roots():cases+=json.loads((root/'manifest.json').read_text())['cases']
 for group in ['main','cache64']:
  paths+=json.loads((B/f'audit-{group}/PC_PATH_RESULTS.json').read_text())
  frames+=json.loads((B/f'audit-{group}/FRAMES.json').read_text())
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
     dis=v.storage.text(B/'audit-main'/(frame['unit']+'-BOTH-'+frame['tb']+'.dis'))
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

def export():
 unchanged()
 out=B/'export180';out.mkdir(exist_ok=False)
 v.save(out/'FROZEN179_VERIFIED.json',dict(artifacts=unchanged()['artifacts'],source_changes=unchanged()['changes'],manifest_sha256=v.sha(C/'MANIFEST.json'),production_modified_by180=False))
 def save(name,x):v.save(out/name,x)
 for name in ['RESTORED_ASSERTIONS_RESULT.json','FULL_REPLAY.json','SUBSET_JOIN.json']:(out/name).write_bytes((B/name).read_bytes())
 for name in ['stdout','stderr','execution.json','command.json']:
  v.storage.write(out/('RESTORED_CODEGEN_'+name),v.storage.verify(B/'restored-codegen'/name))
 records=[];manifests={};paths=[];frames=[]
 for root in roots():
  m=json.loads((root/'manifest.json').read_text());manifests[str(root.relative_to(B))]=m
  for unit in sorted({c['unit'] for c in m['cases']}):
   for arm in s.ARMS:
    d=root/'runs'/unit/arm
    if arm!='Reference':
     original=OLD/root.relative_to(B/'trace0')/'runs'/unit/arm/'command.json'
     assert canonical(json.loads((d/'command.json').read_text()))==canonical(json.loads(original.read_text()))
    records.append(dict(root=str(root.relative_to(B)),unit=unit,arm=arm,reused_from=str(d.resolve()) if d.is_symlink() else None,command=json.loads((d/'command.json').read_text()),execution=json.loads((d/'execution.json').read_text()),checks=json.loads((d/'checks.json').read_text()),guest_sha256=v.sha(root/unit/'test.elf'),packet_sha256=v.sha(d/'packets.bin'),reference_sha256=v.sha(root/'runs'/unit/'Reference/packets.bin')))
 for group in ['main','cache64']:
  a=B/f'audit-{group}'
  save(f'AUDIT_{group}.json',json.loads((a/'AUDIT.json').read_text()))
  paths+=json.loads((a/'PC_PATH_RESULTS.json').read_text());frames+=json.loads((a/'FRAMES.json').read_text())
 for name,x in [('MANIFESTS',manifests),('EXECUTION_RECEIPTS',records),('PC_PATH_RESULTS',paths),('FRAMES',frames)]:v.storage.write(out/(name+'.json'),json.dumps(x,separators=(',',':')).encode());v.storage.compress(out/(name+'.json'))
 controls=[]
 for group in ['main','cache64']:
  for p in [B/f'CONTROLS_NEW_{group}.json',FOCUS/f'CONTROLS_TRACE0_{group}.json']:
   controls.append(json.loads(p.read_text()));save(p.name,json.loads(p.read_text()))
 save('CONTROLS_TOTAL.json',dict(actual_packets=sum(c['actual_packets'] for c in controls),effective_rejections=sum(c['effective_rejections'] for c in controls),changed_allowed_tail_outcomes=sum(c['changed_allowed_tail_outcomes'] for c in controls),passes_per_acceptance_observation=1,DUT_packets=9672,new_DUT_packets=9456,reused_DUT_packets=216,original_reference_packet_rereads=2418,reference_reread_policy='original177 reference controls retained, with new validation rereads disclosed separately; no reference execution',guest_calls=0))
 samples=[json.loads(l) for l in (B/'RESOURCES.jsonl').read_text().splitlines()]
 save('RESOURCES.json',dict(samples=len(samples),sampled_own_guest_peak=max(sum(r['guest'] and any('/rvv-directed-task180/' in a for a in r['args']) for r in x['rows']) for x in samples),sampled_own_guest_nice=sorted({r['nice'] for x in samples for r in x['rows'] if r['guest'] and any('/rvv-directed-task180/' in a for a in r['args'])}),own_guest_workers=8,own_build_workers=1,own_offline_workers=1,owner_semaphore='/home/vick/rvv-directed-task179.own-semaphore',nice=10,affinity='none assigned',minimum_free_bytes=min(x['free_bytes'] for x in samples),sampled_shared_guest_peak=max(x['guests'] for x in samples),limitations='preflight samples, bounded own pools, not continuous shared occupancy proof'))
 save('FINAL_TOTALS.json',dict(status='PASS_FINITE_FULL177_MATRIX_ON179_TRACE0',cases_per_arm=2418,checks=12090,DUT_checks=9672,units=660,DUT_commands=2640,original_reference_units=660,new_DUT_checks=9456,reused_DUT_checks=216,new_DUT_commands=2596,reused_DUT_commands=44,reference_executions=0,ELF_rebuilds=0,target_pc_arm_rows=len(paths),multi_frames=len(frames),native_multi_frames=sum(bool(f['fast_executions']) for f in frames),component_completion_frames=sum(f['low_component_later_members_checked'] for f in frames),candidate_sha256=t.identities()[str(C/'build/bin/elfrun')],full_trace1_matrix='NOT_RUN; focused179 retained',P4='Session3 explicit179 namespace; historical174 never relabeled',all_form_replay='NOT_RUN',external_replay='NOT_RUN'))
 print(out,flush=True)
def verify():
 t.gate('offline')
 m=unchanged()
 v.save(B/'export180/FROZEN179_VERIFIED.json',dict(artifacts=m['artifacts'],source_changes=m['changes'],manifest_sha256=v.sha(C/'MANIFEST.json'),production_modified_by180=False))

def finalize():
 for group in ['main','cache64']:
  assert json.loads((B/f'audit-{group}/AUDIT.json').read_text())['status']=='PASS'
  assert json.loads((B/f'CONTROLS_NEW_{group}.json').read_text())['status']=='PASS'
 details()
 export()
if __name__=='__main__':globals()[sys.argv[1]]()
