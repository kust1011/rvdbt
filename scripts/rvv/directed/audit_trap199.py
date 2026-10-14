#!/usr/bin/env python3
"""Compact retained evidence and offline adjudication, without ISA executions."""
import argparse
import base64
import copy
import gzip
import hashlib
import json
from pathlib import Path
import collections

import trap199 as t


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def collect(root, out):
    t.gate(root)
    manifest=json.loads((root/'cases/manifest.json').read_text())
    bundle=dict(manifest=manifest,records=[],builds=[],source_pins={},
                original_observer_attempt={},pins=t.PINS)
    for p in (root/'tools').glob('*'):
        if p.is_file():bundle['source_pins'][p.name]=digest(p.read_bytes())
    for x in manifest['cases']:
        d=root/'cases'/x['name']
        for name in ('test.S','test.elf'):
            if name=='test.elf':assert digest((d/name).read_bytes())==x['elf_sha256']
        bundle['builds'].append(dict(name=x['name'],source_sha256=digest((d/'test.S').read_bytes()),
                                    execution=json.loads((d/'build/execution.json').read_text())))
        for arm in ('B','M1','M2','BOTH'):
            a=d/arm
            r=dict(name=x['name'],arm=arm,
                   execution=json.loads((a/'run/execution.json').read_text()),
                   host_stdout=(a/'run/stdout').read_text(errors='replace') if not x['control'] else '',
                   host_stderr=(a/'run/stderr').read_text(errors='replace'))
            if x['control']:
                r['packet_b64']=base64.b64encode((a/'run/stdout').read_bytes()).decode()
            else:
                r.update(snapshot=json.loads((a/'snapshot.json').read_text()),
                         guest_stdout_b64=base64.b64encode((a/'guest.stdout').read_bytes()).decode(),
                         guest_stderr=(a/'guest.stderr').read_text(),
                         gdb_script=(a/'observe.gdb').read_text())
            bundle['records'].append(r)
    a=root/'observer-attempt1/B'
    for p in a.rglob('*'):
        if p.is_file() and p.name in ('stdout','stderr','execution.json','guest.stderr','observe.gdb'):
            bundle['original_observer_attempt'][str(p.relative_to(a))]=p.read_text(errors='replace')
    bundle['sidecar']=dict(sha256=digest((root/'types.o').read_bytes()),
                          execution=json.loads((root/'types-build/execution.json').read_text()))
    src=Path('/home/vick/rvv-long-task192/source')
    bundle['layout_source_pins']={str(p.relative_to(src)):digest(p.read_bytes()) for p in
        [src/'dbt/guest/rv32_cpu.h',src/'dbt/guest/rv32_vector.h',src/'dbt/guest/rv32_fpu.h',src/'dbt/ukernel.cpp']}
    bundle['identity_after']=[t.v.sha(t.ENGINE),t.v.sha(t.ENGINE.parent.parent/'lib/libdbtjitshared.so')]
    bundle['normative_sha256']=t.v.sha(Path('/home/vick/rvv-closure198-review/inputs/v-st-ext.adoc'))
    out.write_bytes(gzip.compress(json.dumps(bundle,separators=(',',':')).encode(),mtime=0))


def audit(path, out):
    data=json.loads(gzip.decompress(path.read_bytes()))
    assert data['identity_after']==list(t.PINS)==data['pins']
    assert data['normative_sha256']=='f114464f32de3825863df04ff903137685a94a89973a8b38df3c4e804adf116f'
    cases={x['name']:x for x in data['manifest']['cases']}
    assert len(cases)==135 and {t.form(x['case']) for x in cases.values()}==t.FORMS
    byform=collections.defaultdict(collections.Counter);seen=set();resources=[]
    for r in data['records']:
        x=cases[r['name']];c=x['case'];key=(r['name'],r['arm'])
        assert x['raw']==t.MODULES[c['family']].instruction(c)
        assert key not in seen;seen.add(key)
        assert r['arm'] in ('B','M1','M2','BOTH') and r['execution']['returncode']==0
        resources += [r['execution'][k] for k in ('before','after')]
        if x['control']:
            t.MODULES[c['family']].check_isa(c,base64.b64decode(r['packet_b64']),0,False)
        else:
            assert not base64.b64decode(r['guest_stdout_b64'])
            assert 'hit Breakpoint 1' in r['host_stdout'] and 'killed' in r['host_stdout']
            t.check_trap(x,r['snapshot'],r['guest_stderr'])
            assert c['vstart']==1 and c['lmul']=='m1' and c['vlen']==128
        byform[t.form(c)]['control_checks' if x['control'] else 'trap_checks']+=1
    assert len(seen)==540
    for f,counts in byform.items():
        assert counts==dict(control_checks=4 if f=='vcompress.vm' else 8,
                           trap_checks=8 if f=='vcompress.vm' else 16)
        rows=[x for x in cases.values() if t.form(x['case'])==f]
        for masked in ([False] if f=='vcompress.vm' else [False,True]):
            traps=[x for x in rows if not x['control'] and (x['case']['mask']!='none')==masked]
            assert len(traps)==2 and min(x['case']['vl'] for x in traps)==0 and max(x['case']['vl'] for x in traps)>1
    # The checker must reject corrupted architectural/cause observations.
    x=next(x for x in cases.values() if not x['control'])
    r=next(r for r in data['records'] if r['name']==x['name'])
    corruptions={
        'pc':lambda s:s.update(pc=s['pc']+4),
        'trap_reason':lambda s:s.update(trapno=4),
        'gpr':lambda s:s['gpr'].__setitem__(9,0),
        'fpr':lambda s:s['fpr_hex'].__setitem__(31,'0000000000000000'),
        'vector':lambda s:s['vreg_hex'].__setitem__(8,'00'*16),
        'vstart':lambda s:s['csrs'].update(vstart=0),
        'flags':lambda s:s['csrs'].update(fflags=0),
        'open_fp_run':lambda s:s.update(fp_run_closed=False),
    }
    for name,mutate in corruptions.items():
        s=copy.deepcopy(r['snapshot']);mutate(s)
        try:t.check_trap(x,s,r['guest_stderr'])
        except AssertionError:pass
        else:raise AssertionError(('accepted corruption',name))
    for stderr in ('',r['guest_stderr'].replace('ILLEGAL_INSN','ECALL'),
                   r['guest_stderr'].replace(f"raw={x['raw']:08x}",'raw=00000000')):
        try:t.check_trap(x,r['snapshot'],stderr)
        except AssertionError:pass
        else:raise AssertionError('accepted corrupt diagnostic')
    for b in data['builds']+[data['sidecar']]:
        assert b['execution']['returncode']==0
        resources += [b['execution'][k] for k in ('before','after')]
    attempt=json.loads(data['original_observer_attempt']['run/execution.json'])
    assert attempt['returncode']!=0
    resources += [attempt[k] for k in ('before','after')]
    assert all(s['nice']==10 and min(s['free_bytes'],s['available_ram_bytes'])>=10*1024**3 for s in resources)
    result=dict(status='PASS',forms=23,trap_cases=90,trap_observations=360,
                control_cases=45,control_checks=180,unique_case_arm_checks=540,
                compiler_calls=136,workers=1,pin=list(t.PINS),
                retained_failed_observer_attempts=1,total_DUT_launches=541,
                per_form=dict(sorted(byform.items())),checker_corruptions_rejected=11,
                min_free_bytes=min(s['free_bytes'] for s in resources),
                min_available_ram_bytes=min(s['available_ram_bytes'] for s in resources),
                evidence_sha256=digest(path.read_bytes()),
                limitations=['finite VLEN128 e8/e32 m1 configurations',
                    'terminal GDB inspection then kill; no guest recovery or normal exit claim',
                    'fixed192-only symbol offset and sidecar layout; rebuild requires readjudication',
                    'all active vector bytes; no nonarchitectural storage padding or full guest-memory audit',
                    'arm switches do not establish native per-target route admission',
                    'resource endpoints are sampled, not a continuous system-wide guarantee'])
    out.write_text(json.dumps(result,indent=2)+'\n')


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('mode',choices=['collect','audit']);p.add_argument('input',type=Path);p.add_argument('output',type=Path);a=p.parse_args()
    globals()[a.mode](a.input,a.output)
