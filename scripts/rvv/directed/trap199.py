#!/usr/bin/env python3
"""Bounded required-vstart traps; existing181 cases, encoders and predicates.

GDB stops after the existing terminal diagnostic's fflush, reads live
CPUState, then kills the inferior. No inferior calls, writes, handler or retry.
The debug-only type object is never linked into or loaded by the DUT.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import types

import audit
import vadd as v
import permute162 as perm
import reduction163 as red
import mask158 as mask
import prefix169 as prefix
import fpreduce174 as fp

ENGINE = Path('/home/vick/rvv-long-task192/build/bin/elfrun')
PINS = ('908df235e36fe49f8a64793a8e4a401987f9b2c56da10179470b7bc7bd5ffbc4',
        '79d0ba2a9ddea24d49d7282012fdc373b92a26756bb5452c1f41c66d533887af')
MODULES = dict(permute162=perm, reduction163=red, mask158=mask,
               prefix169=prefix, fpreduce174=fp)
FORMS = {'vcompress.vm', 'vcpop.m', 'vfirst.m', 'vmsbf.m', 'vmsif.m',
         'vmsof.m', 'viota.m'} | {x+'.vs' for x in red.FORMS} | set(fp.FORMS)


def form(c):
    return c['mnemonic'] if c['family']=='fpreduce174' else c['mnemonic']+'.'+c['form']


def save(p, x):
    p.write_text(json.dumps(x, indent=2)+'\n')


def gate(root):
    free = os.statvfs(root).f_bavail * os.statvfs(root).f_frsize
    ram = int(re.search(r'MemAvailable:\s+(\d+)', Path('/proc/meminfo').read_text())[1])*1024
    assert min(free, ram) >= 10*1024**3, (free, ram)
    assert os.getpriority(os.PRIO_PROCESS, 0)==10
    return dict(free_bytes=free, available_ram_bytes=ram, nice=10,
                affinity='inherited; no pinning')


def run(cmd, d, env=None):
    d.mkdir(parents=True, exist_ok=False)
    before=gate(d)
    p=subprocess.run(list(map(str,cmd)), capture_output=True, env=env, timeout=60)
    (d/'stdout').write_bytes(p.stdout); (d/'stderr').write_bytes(p.stderr)
    save(d/'execution.json', dict(command=list(map(str,cmd)), returncode=p.returncode,
                                 before=before, after=gate(d)))
    return p


def assembly(c):
    m=MODULES[c['family']]
    if m is not fp:
        return m.assembly([c])
    # Literal existing Task145 FP observer, rebound to Task174's semantics.
    import fp157
    proxy=types.SimpleNamespace(target=fp.target, scalar=fp.scalar)
    original=fp157.target, fp157.scalar
    try:
        fp157.target,fp157.scalar=proxy.target,proxy.scalar
        observer=types.FunctionType(v.assembly.__code__, dict(v.assembly.__globals__,
                  initial=fp.initial, packet_size=v.packet_size))
        return observer([c])
    finally:
        fp157.target,fp157.scalar=original


def prepare(root, plan):
    root.mkdir(exist_ok=False); gate(root)
    entries=json.loads(gzip.decompress(plan.read_bytes()))['entries']
    wanted={'b159-015','b162-023','b163-024','b169-047','b174-089'}
    candidates=[]; inputs=[]
    for e in entries:
        if e['id'] not in wanted: continue
        p=Path(e['original'])/'manifest.json'
        raw=v.storage.verify(p)
        assert hashlib.sha256(raw).hexdigest()==e['manifest_sha256']
        inputs.append(dict(entry=e['id'], path=str(p), sha256=e['manifest_sha256']))
        rows=json.loads(raw)['cases']
        for i in e['accepted_indices']:
            c=rows[i]
            if (c['vlen']==128 and c['lmul']=='m1' and
                c['sew']==(32 if c['family']=='fpreduce174' else 8) and
                form(c) in FORMS and c['vstart']==0 and c['vl']>1 and
                not c['ta'] and not c['ma'] and c['vd']!=0 and c['vs2']!=0):
                candidates.append((c, dict(entry=e['id'], index=i, original_id=c['id'])))
    cases=[]
    for f in sorted(FORMS, key=lambda f:(f!='vcompress.vm',f)):
        for masked in ([False] if f=='vcompress.vm' else [False,True]):
            choices=[(c,j) for c,j in candidates if form(c)==f and (c['mask']!='none')==masked]
            assert choices, (f,masked,'no accepted181 control')
            c,join=min(choices,key=lambda x:(x[0]['vl'],x[0]['id']))
            c=dict(c,ordinal=0)
            if hasattr(MODULES[c['family']], 'validate'): MODULES[c['family']].validate(c)
            stem=f.replace('.','-')+('-masked' if masked else '-unmasked')
            cases.append(dict(name=stem+'-control', case=c, control=True, accepted181=join))
            for vl in (0,c['vl']):
                t=dict(c,vl=vl,vstart=1)
                if f=='vcompress.vm':t['vs1']=17  # exact Task198 smallest encoding
                cases.append(dict(name=stem+'-trap-vl'+str(vl),case=t,control=False,
                                  accepted181=join, derivation='vstart1; VL0 or accepted positive VL; compress selector v17'))
    assert len(cases)==135 and sum(not x['control'] for x in cases)==90
    for x in cases:
        c=x['case']; m=MODULES[c['family']]; d=root/x['name'];d.mkdir()
        # Build the existing observer for controls. Traps share its initialization
        # and target, with independently known full scalar sentinels at the target.
        src=assembly(c)
        if not x['control']:
            setup=['la t0,trap199_fprs']+[f'fld f{i},{i*8}(t0)' for i in range(32)]
            setup += [f'li x{i},{0x19900000+i}' for i in range(1,32)]
            src=src.replace('target_0:\n', '\n'.join(setup)+'\ntarget_0:\n')
            src += '\n.balign 8\ntrap199_fprs:\n'+ '\n'.join(f'.dword {0x1234567800000000+i}' for i in range(32))+'\n'
        (d/'test.S').write_text(src)
        cmd=['clang-22','--target=riscv32-unknown-elf','-march=rv32gcv','-mabi=ilp32d',
             '-nostdlib','-static','-fuse-ld=lld','-Wl,--no-relax',
             '-Wl,-T,/home/vick/rvv-directed-task145/link.ld',d/'test.S','-o',d/'test.elf']
        assert run(cmd,d/'build').returncode==0
        sections,symbols=audit.elf_sections_symbols(d/'test.elf')
        pc=symbols['target_0'];addr,data=sections['.text']
        word=int.from_bytes(data[pc-addr:pc-addr+4],'little')
        assert word==m.instruction(c),(x['name'],hex(word),hex(m.instruction(c)))
        x.update(pc=pc,raw=word,elf_sha256=v.sha(d/'test.elf'))
    save(root/'manifest.json',dict(cases=cases,inputs=inputs))


def observe_script(d, types_obj):
    # Read the same architectural fields as WriteMemoryFaultSnapshot. Unlike that
    # memory-only formatter, read them at the existing illegal terminal boundary.
    return f'''set pagination off
set confirm off
set disable-randomization off
set language c++
handle SIGALRM nostop noprint pass
add-symbol-file {types_obj} 0
# Pinned fixed192: after ILLEGAL_INSN diagnostic/fflush, before inlined
# EnqueueTermination; RBX is the dispatcher CPUState (callee-saved).
break *('dbt::ukernel::Execute()'+0x2c2)
run
python
import gdb,json
s=gdb.parse_and_eval('(dbt::CPUState*)$rbx').dereference()
def n(x): return int(x)
def arr(x): return x['_M_elems']
v=s['vec']; f=s['fpu']; b=n(v['vlenb']); fc=n(f['fcsr'])
cs={{k:n(v[k]) for k in ('vl','vtype','vstart','vlenb','vxrm','vxsat')}}
cs.update(vcsr=cs['vxrm']*2+cs['vxsat'],fcsr=fc,frm=fc>>5&7,fflags=fc&31)
vs=arr(v['vreg'])
regs=[bytes(n(arr(vs[r])[i]) for i in range(b)).hex() for r in range(32)]
out=dict(pc=n(s['ip']),trapno=n(s['trapno']),gpr=[n(arr(s['gpr'])[i]) for i in range(32)],fpr_hex=[format(n(f['f'][i]),'016x') for i in range(32)],csrs=cs,vreg_hex=regs,fp_run_closed=not bool(f['fround_run_open']))
open({str(d/'snapshot.json')!r},'w').write(json.dumps(out,indent=2)+'\\n')
end
kill
'''


def check_trap(x, snapshot, stderr):
    c=x['case']; m=MODULES[c['family']]
    assert snapshot['pc']==x['pc'] and snapshot['trapno']==2
    assert re.findall(r'ILLEGAL_INSN ip=([0-9a-f]+) raw=([0-9a-f]+)',stderr)==[(f"{x['pc']:08x}",f"{x['raw']:08x}")]
    assert snapshot['gpr']==[0]+[0x19900000+i for i in range(1,32)]
    assert snapshot['fpr_hex']==[f'{0x1234567800000000+i:016x}' for i in range(32)]
    assert ''.join(snapshot['vreg_hex'])==m.initial(c).hex()
    fc=(c['frm']*32+c['fflags_initial']) if m is fp else 117
    vxrm=2 if m is fp else c['vxrm_initial'];sat=1 if m is fp else c['vxsat_initial']
    assert snapshot['csrs']==dict(vl=c['vl'],vtype=(c['sew'].bit_length()-4)*8,
          vstart=1,vlenb=16,vxrm=vxrm,vxsat=sat,vcsr=vxrm*2+sat,
          fcsr=fc,frm=fc>>5,fflags=fc&31)
    assert snapshot['fp_run_closed']


def execute(root, phase, types_obj):
    gate(root)
    assert (v.sha(ENGINE),v.sha(ENGINE.parent.parent/'lib/libdbtjitshared.so'))==PINS
    cases=json.loads((root/'manifest.json').read_text())['cases']
    results=[]
    for x in cases:
        if (form(x['case'])=='vcompress.vm') != (phase=='pilot'): continue
        for arm in ('B','M1','M2','BOTH'):
            d=root/x['name']/arm;d.mkdir();fs=d/'fs';fs.mkdir();(fs/'t.elf').write_bytes((d.parent/'test.elf').read_bytes());(d/'cache').mkdir()
            # Reuse exact accepted192 arm switches; replace only owned paths/VLEN.
            sample=next(Path('/home/vick/rvv-long-task192/remaining/runs').glob('*/'+arm+'/command.json'))
            old=json.loads(sample.read_text());flags=[]
            for a in old[1:old.index('--')]:
                if a.startswith(('--dump-','--fsroot=','--cache=','--rvv-pc-census-out=')):continue
                flags.append('--vlen=128' if a.startswith('--vlen=') else a)
            cmd=[str(ENGINE),*flags,'--fsroot='+str(fs),'--cache='+str(d/'cache'),'--','/t.elf']
            env=dict(os.environ,LD_LIBRARY_PATH=str(ENGINE.parent.parent/'lib')+':/home/vick/boost_vendor/lib')
            if x['control']:
                p=run(cmd,d/'run',env)
                MODULES[x['case']['family']].check_isa(x['case'],p.stdout,p.returncode,False)
            else:
                script=observe_script(d,types_obj)
                # Inferior output redirection must preserve explicit argv in GDB.
                script=script.replace('\nrun\n','\nrun '+shlex.join(cmd[1:])+' > '+str(d/'guest.stdout')+' 2> '+str(d/'guest.stderr')+'\n')
                (d/'observe.gdb').write_text(script)
                p=run(['gdb','--batch','-x',d/'observe.gdb','--args',*cmd],d/'run',env)
                assert p.returncode==0 and not (d/'guest.stdout').read_bytes()
                check_trap(x,json.loads((d/'snapshot.json').read_text()),(d/'guest.stderr').read_text())
            results.append(dict(name=x['name'],form=form(x['case']),arm=arm,control=x['control'],status='PASS'))
            save(root/(phase+'-progress.json'),results)
            print(x['name'],arm,'PASS',flush=True)
    assert (v.sha(ENGINE),v.sha(ENGINE.parent.parent/'lib/libdbtjitshared.so'))==PINS
    save(root/(phase+'-result.json'),dict(status='PASS',checks=results,pins=PINS,resources=gate(root)))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('mode',choices=['prepare','pilot','remaining']);p.add_argument('root',type=Path);p.add_argument('input',type=Path);a=p.parse_args()
    if a.mode=='prepare':prepare(a.root,a.input)
    else:execute(a.root,a.mode,a.input)
