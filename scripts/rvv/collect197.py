#!/usr/bin/env python3
"""Collect exact Task197 progress and compact evidence without execution credit reuse."""
import collections
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import time

B=Path('/home/vick/rvv-task197')
OUT=B/'compact';OUT.mkdir(exist_ok=True)
read=lambda p:json.loads(Path(p).read_text())
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
P=read(B/'DIRECTED_PLAN.json')
oldplan=Path('/home/vick/rvv-task181/DIRECTED_PLAN.json')
assert sha(oldplan)=='6a57de0fb7c149ea865a62a27055db1a438610336fa6bb34b9c185e91e6ad929'
previous=read(oldplan);expected=dict(previous,build=P['build']);assert P==expected
plan_join=dict(original_plan=str(oldplan),original_plan_sha256=sha(oldplan),new_plan_sha256=sha(B/'DIRECTED_PLAN.json'),
               changed_fields=['build'],selectors_flags_sources_units_and_references_unchanged=True,old_DUT_credit=0)
(OUT/'PLAN_JOIN197.json').write_text(json.dumps(plan_join,indent=2)+'\n')
build={str(p):sha(p) for p in (Path('/home/vick/rvv-long-task192/build/bin/elfrun'),Path('/home/vick/rvv-long-task192/build/lib/libdbtjitshared.so'))}
assert list(build.values())==['908df235e36fe49f8a64793a8e4a401987f9b2c56da10179470b7bc7bd5ffbc4','79d0ba2a9ddea24d49d7282012fdc373b92a26756bb5452c1f41c66d533887af']
entries=[];units=[];forms=collections.defaultdict(collections.Counter);check_receipts=[]
for e in P['entries']:
    d=B/'directed'/e['id'];stages={}
    for stage in ('pilot','remaining','audit'):
        if (d/stage/'COMPLETE').exists():stages[stage]=read(d/stage/'summary.json')
    if 'audit' in stages:
        s=stages['audit'];assert s['failed']==0 and s['checks']==4*e['accepted_cases']
        assert {f:c['PASS'] for f,c in s['forms'].items()}=={f:n*4 for f,n in e['forms'].items()}
    transferred=None
    if (d/'TRANSFER.json').exists():
        r=read(d/'TRANSFER.json')
        transferred={k:r[k] for k in ('entry','archive','bytes','sha256','storage_receipts')}
        transferred.update(full_ledger=str(d/'TRANSFER.json'),ledger_sha256=sha(d/'TRANSFER.json'))
    passed=set();audited=set()
    metadata_transfer=read(d/'METADATA_TRANSFER.json') if (d/'METADATA_TRANSFER.json').exists() else None
    if metadata_transfer:
        assert set(stages)=={'pilot','remaining','audit'} and stages['audit']['failed']==0
        passed={(u,a) for u in e['units'] for a in ('B','M1','M2','BOTH')};audited=set(passed)
        for form,counts in stages['audit']['forms'].items():forms[form]['passed']+=counts['PASS']
    for stage in ('pilot','remaining','audit'):
        if metadata_transfer:continue
        root=d/stage
        if not root.exists():continue
        for f in root.glob('*-checks.json.gz'):
            rows=json.loads(gzip.decompress(f.read_bytes()))
            assert rows and len({(r['case'],r['arm']) for r in rows})==len(rows)
            arm=rows[0]['arm'];unit=f.name.removesuffix('-'+arm+'-checks.json.gz')
            ok=all(r['status']=='PASS' for r in rows)
            check_receipts.append(dict(entry=e['id'],unit=unit,arm=arm,stage=stage,checks=len(rows),passed=ok,receipt_sha256=sha(f)))
            if ok:
                (audited if stage=='audit' else passed).add((unit,arm))
                if stage=='audit':
                    for r in rows:forms[r['form']]['passed']+=1
    for u in e['units']:
        for a in ('B','M1','M2','BOTH'):
            units.append(dict(entry=e['id'],family=e['batch'],unit=u,arm=a,
                              execution='PASS' if (u,a) in passed else 'PENDING',
                              audit='PASS' if (u,a) in audited else 'PENDING'))
    entries.append(dict(entry=e['id'],batch=e['batch'],forms=e['forms'],accepted_cases=e['accepted_cases'],stages=stages,transfer=transferred,metadata_transfer=metadata_transfer,
                        fully_audited='audit' in stages,manifest_sha256=e['manifest_sha256'],original=e['original']))
focus=[]
for name in ('guard165','guard166','faults','fof-startmask','vill'):
    d=B/'focused'/name
    focus.append(dict(suite=name,stages={s:read(d/s/'summary.json') for s in ('replay','audit') if (d/s/'COMPLETE').exists()}))
ext={}
scoped=[]
for suite in ('chips','act','ara'):
    d=B/'external'/suite
    if not (d/'QUEUE.json').exists():continue
    q=read(d/'QUEUE.json')['cells' if suite=='chips' else 'calls'];rows=[]
    for c in q:
        f=d/'raw'/(Path(c['case'])/c['arm'] if suite=='act' else c['id'])/'result.json'
        rows.append(dict(id=c.get('id',c.get('case')),arm=c.get('arm'),status=read(f)['status'] if f.exists() else 'PENDING',control=c.get('control'),scope=c.get('scope')))
        if suite=='ara' and c.get('scope')=='TEST_CASE1_2_ONLY' and f.exists():
            r=read(f);old=Path('/home/vick/rvv-task181/external/ara/raw')/c['id']/'result.json';previous=read(old)
            assert r['status']=='SCOPED_PASS' and not r['whole_file_pass']
            scoped.append(dict(id=c['id'],scope=c['scope'],whole_file_pass=False,
                               original_result=str(old),original_result_sha256=sha(old),new_result_sha256=sha(f),
                               original_stdout_sha256=previous['stdout_sha256'],new_stdout_sha256=r['stdout_sha256'],
                               same_failure_payload=r['stdout_sha256']==previous['stdout_sha256'],historical_DUT_credit=False))
    ext[suite]=dict(counts=dict(collections.Counter(r['status'] for r in rows)),rows=rows)
seq=B/'sequence';sequence={}
if (seq/'REPLAY.json').exists():sequence['execution']=read(seq/'REPLAY.json')
sequence['audit_complete']=(seq/'AUDIT_COMPLETE').exists()
for f in seq.glob('audit-trace*/AUDIT.json'):
    sequence[str(f.parent.name)]=read(f)
for f in seq.glob('controls-trace*.json'):
    sequence[f.name]=read(f)
samples=[]
if (B/'RESOURCES.jsonl').exists():
    for line in (B/'RESOURCES.jsonl').open():
        try:samples.append(json.loads(line))
        except json.JSONDecodeError:pass
resources=dict(samples=len(samples),minimum_free_bytes=min((r['free'] for r in samples),default=None),
               own_guest_peak=max((sum(p['kind']=='guest' and p['own'] for p in r['processes']) for r in samples),default=0),
               shared_guest_peak=max((sum(p['kind']=='guest' for p in r['processes']) for r in samples),default=0),
               own_nice=sorted({p['nice'] for r in samples for p in r['processes'] if p['own']}),
               affinity='inherited; no assignment',limitation='sparse census; not continuous occupancy proof')
status=dict(time=time.time(),build=build,entries_planned=len(entries),entries_audited=sum(e['fully_audited'] for e in entries),
            directed_audited_checks=sum(e['stages'].get('audit',{}).get('checks',0) for e in entries),
            directed_command_counts=dict(collections.Counter(r['execution'] for r in units)),
            directed_audit_counts=dict(collections.Counter(r['audit'] for r in units)),
            focused=focus,external={s:r['counts'] for s,r in ext.items()},sequence=sequence,resources=resources,
            new_reference_executions=0,ELF_rebuilds=0,old_DUT_credit=0,
            runner_pins={str(p):sha(p) for p in (B/'tools').glob('*.py')},
            exclusions=['service-blocked P4-04 / handler repair-return / retry excluded','two original ACT reference blockers remain excluded','16 Ara TEST_CASE1/2 scoped calls preserve TEST_CASE3/4 exclusions; no whole-file credit','original source-reserved declarations remain excluded'])
for name,obj in [('STATUS',status),('ENTRY_RECEIPTS',entries),('DIRECTED_UNIT_STATUS',units),('CHECK_RECEIPTS',check_receipts),('EXTERNAL_UNIT_STATUS',ext),('PER_FORM_PROGRESS',dict(forms))]:
    data=(json.dumps(obj,separators=(',',':'))+'\n').encode()
    if name=='STATUS':(OUT/'STATUS.json').write_bytes(data)
    else:(OUT/(name+'.json.gz')).write_bytes(gzip.compress(data,mtime=0))
for f in (B/'BUDGET.json',B/'original-runner-pins.json'):
    if f.exists():shutil.copy2(f,OUT/f.name)
if (B/'worker-epoch-2/RESOURCE_DECISION.json').exists():
    shutil.copy2(B/'worker-epoch-2/RESOURCE_DECISION.json',OUT/'WORKER_DECISION197.json')
(OUT/'EXTERNAL_EXCLUSIONS197.json').write_text(json.dumps(dict(scoped_calls=scoped,
    ACT_original_reference_blockers=['Vf32-vfmv.f.s','Vf64-vfmv.f.s'],adjudication_owner='session3',
    rule='Original exclusions preserved; no new whole-file credit or reference execution'),indent=2)+'\n')
complete=(all(e['fully_audited'] for e in entries)
          and all(e['transfer'] and e['metadata_transfer'] for e in entries)
          and all(set(r['stages'])=={'replay','audit'} for r in focus)
          and (B/'external/audit/COMPLETE').exists()
          and sequence.get('audit_complete',False))
if complete:
    assert len(forms)==595
    directed=sum(e['stages']['audit']['checks'] for e in entries)
    assert directed==12069048 and all(e['stages']['audit']['failed']==0 for e in entries)
    assert all(r['stages']['replay']==r['stages']['audit'] and r['stages']['audit']['failed']==0 for r in focus)
    assert sum(r['stages']['audit']['checks'] for r in focus)==2848
    assert resources['minimum_free_bytes']>=10*1024**3 and resources['own_guest_peak']<=8 and resources['own_nice']==[10]
    rows=[]
    for form,batch in sorted(P['owners'].items()):
        ordinary=forms[form]['passed'];focused=sum(r['stages']['audit']['forms'].get(form,{}).get('PASS',0) for r in focus)
        expected=sum(e['forms'].get(form,0)*4 for e in P['entries'])
        assert ordinary==expected,(form,ordinary,expected)
        rows.append(dict(form=form,batch=batch,ordinary_DUT_checks=ordinary,focused_positive_DUT_checks=focused,status='PASS_FINITE_SCOPE',build_sha256=P['build']))
    result=dict(status='PASS_FINITE_SCOPE',build=build,forms=595,
                directed_new_DUT_commands=sum(e['stages'][s]['new_dut_calls'] for e in entries for s in ('pilot','remaining')),
                directed_new_DUT_checks=directed,focused=focus,
                external=read(B/'external/audit/SUMMARY.json'),sequence=sequence,resources=resources,
                new_reference_executions=0,ELF_rebuilds=0,historical_DUT_credit=0,exclusions=status['exclusions'])
    assert result['directed_new_DUT_commands']==380968
    assert result['external']['exact_joins']==21316
    (OUT/'RESULT197.json').write_text(json.dumps(result,indent=2)+'\n')
    (OUT/'PER_FORM_RESULTS.json.gz').write_bytes(gzip.compress(json.dumps(rows,separators=(',',':')).encode(),mtime=0))
    (B/'FINAL_COMPLETE').write_text('PASS_FINITE_SCOPE\n')
print(json.dumps({k:status[k] for k in ('entries_audited','directed_command_counts','directed_audit_counts','external','resources')}),flush=True)
