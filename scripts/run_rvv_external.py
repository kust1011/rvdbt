#!/usr/bin/env python3
"""Portable complete Ara and retained RVVTS API sequence replay; new output only."""
import argparse, ast, json, os, re, shutil, signal, subprocess, sys, time
from pathlib import Path
from rvv_tests import digest, save
sys.path.insert(0,str(Path(__file__).resolve().parent/'rvv'))
from ara_observations import observations
F=Path(__file__).resolve().parent/'rvv/fixtures'

def call(cmd,d,env=None,timeout=120):
    d.mkdir(parents=True,exist_ok=False);save(d/'command.json',list(map(str,cmd)))
    start=time.monotonic();rc=None;expired=False
    with (d/'stdout').open('wb') as so,(d/'stderr').open('wb') as se:
        p=subprocess.Popen(list(map(str,cmd)),stdout=so,stderr=se,env=env,start_new_session=True)
        try: rc=p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            expired=True;os.killpg(p.pid,signal.SIGKILL);rc=p.wait()
    r=dict(returncode=rc,timeout=expired,elapsed_seconds=time.monotonic()-start,stdout_sha256=digest(d/'stdout'),stderr_sha256=digest(d/'stderr'))
    save(d/'result.json',r);return r

def ara_check(raw,rc,timeout=False):
    expected=json.loads((F/'ara-vredsum/expected-observations.json').read_text())
    obs=observations(raw);text=raw.decode(errors='replace')
    # Addresses/line provenance are fixed by the retained adapter; expected values are upstream literals.
    sequences=list(map(int,re.findall(r'ARA_ASSERT[^\n]+ sequence=(\d+)',text)))
    return rc==0 and not timeout and obs==expected and sequences==list(range(1,21)) and text.count('PASSED.\n')==20 and text.count('ARA_CASE_BEGIN ')==5 and text.count('ARA_CASE_END ')==5 and 'FAILED' not in text and 'ERROR' not in text

def verify_fixtures():
    for n,h in json.loads((F/'external-sha256.json').read_text()).items():
        if not (F/n).is_file() or digest(F/n)!=h:raise ValueError('missing/changed fixture: '+n)
    original=(F/'ara-vredsum/vredsum.original.c').read_text();adapted=(F/'ara-vredsum/context_original_vredsum.c').read_text()
    restored=re.sub(r'ara_case_begin\("(TEST_CASE\d+)"\); (TEST_CASE\d+)\(\); ara_case_end\("TEST_CASE\d+",num_failed\);',r'\2();',adapted)
    if restored!=original:raise ValueError('Ara original functions/main initialization changed')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ['output','rvvts','engine','library-dir','spike','pk','libgcc']:p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--compiler',default='clang-22');p.add_argument('--llc',default='llc-22');p.add_argument('--timeout',type=int,default=120)
    a=p.parse_args();verify_fixtures()
    lock=json.loads((F.parent/'sources.lock.json').read_text())['sources']['rvvts']
    rev=subprocess.check_output(['git','-C',str(a.rvvts),'rev-parse','HEAD'],text=True).strip()
    if rev!=lock['revision'] or subprocess.check_output(['git','-C',str(a.rvvts),'status','--porcelain','--untracked-files=no'],text=True):raise ValueError('RVVTS revision/source changed')
    for x in [a.engine,a.spike,a.pk,a.libgcc]:
        if not x.is_file():raise ValueError('missing dependency: '+str(x))
    for x in [a.compiler,a.llc]:
        if not shutil.which(x):raise ValueError('missing compiler tool: '+x)
    sys.path.insert(0,str(a.rvvts.resolve()));from rvvts_packet import decode,audit_input_unchanged
    out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    ids={str(x.resolve()):digest(x) for x in [a.engine,a.library_dir/'libdbtjitshared.so',a.spike,a.pk,a.libgcc]}
    save(out/'identity.json',dict(files=ids,rvvts_revision=rev,compiler=subprocess.check_output([a.compiler,'--version'],text=True),host=list(os.uname()),argv=sys.argv))
    ar=F/'ara-vredsum';rv=F/'rvvts-20261089';build=out/'guests';build.mkdir()
    base=[a.compiler,'--target=riscv32-unknown-elf','-mabi=ilp32d']
    for name,src in [('test',ar/'context_original_vredsum.c'),('user_runtime',ar/'user_runtime.c'),('printf',ar/'printf.c')]:
        cmds=[base+['-march=rv32g','-O0','-ffreestanding','-fno-builtin','-fno-vectorize','-fno-slp-vectorize','-msmall-data-limit=0','-I'+str(ar),'-DPRINTF_DISABLE_SUPPORT_FLOAT','-DPRINTF_DISABLE_SUPPORT_LONG_LONG','-include',ar/'asm_environment.h','-S','-emit-llvm',src,'-o',build/(name+'.ll')], [a.llc,'--no-integrated-as',build/(name+'.ll'),'-o',build/(name+'.s')],base+['-march=rv32gv','-c',build/(name+'.s'),'-o',build/(name+'.o')]]
        for i,c in enumerate(cmds):
            if call(c,out/'build-logs'/f'{name}-{i}')['returncode']!=0:raise RuntimeError('build failed: '+name)
    araelf=build/'ara.elf';rvelse=build/'rvvts.elf'
    for name,c in [('ara',base+['-march=rv32gv','-static','-nostdlib','-fuse-ld=lld','-Wl,--no-relax','-Wl,-T,'+str(ar/'link.ld'),ar/'start.S',build/'test.o',build/'user_runtime.o',build/'printf.o',a.libgcc,'-o',araelf]),('rvvts',[a.compiler,'--target=riscv32-unknown-elf','-march=rv32gv','-mabi=ilp32f','-static','-nostdlib','-fuse-ld=lld','-Wl,--no-relax','-Wl,-T,'+str(rv/'link.ld'),rv/'replay-ready-ported.S','-o',rvelse])]:
        if call(c,out/'build-logs'/name)['returncode']!=0:raise RuntimeError('link failed: '+name)
    flags=json.loads((F/'external-flags.json').read_text());results=[]
    env=dict(os.environ);env['LD_LIBRARY_PATH']=str(a.library_dir.resolve())
    for name,elf,vl in [('ara',araelf,1024),('rvvts',rvelse,2048)]:
        ref=None
        for arm in ['Spike','B','M1','M2','BOTH']:
            d=out/'runs'/name/arm;work=out/'work'/name/arm;(work/'fs').mkdir(parents=True);(work/'cache').mkdir();shutil.copyfile(elf,work/'fs/t.elf')
            if arm=='Spike':cmd=[a.spike,f'--isa=rv32gcv_zvl{vl}b',a.pk,elf]
            else:
                fs=[f'--vlen={vl}' if x.startswith('--vlen=') else x for x in flags[arm]]
                cmd=[a.engine,*fs,'--dump-tbcode='+str(d/'tbcode.txt'),'--dump-tbmap='+str(d/'tbmap.txt')]
                if arm in ['M1','BOTH']:cmd+=['--rvv-run-frame-census=1']
                cmd+=['--fsroot='+str(work/'fs'),'--cache='+str(work/'cache'),'--','/t.elf']
            r=call(cmd,d,env,a.timeout);raw=(d/'stdout').read_bytes();ok=False
            try:
                if name=='ara':ok=ara_check(raw,r['returncode'],r['timeout']);save(d/'observations.json',observations(raw))
                else:
                    state=audit_input_unchanged(raw,json.loads((rv/'INPUT.json').read_text()),(rv/'native16.txt').read_text(),d)
                    if arm=='Spike':ref=state;ok=True
                    else:ok,diff=ref.compare(state,diff_full=True);(d/'original-compare.txt').write_text(diff)
                    ok=ok and r['returncode']==0 and not r['timeout']
            except (AssertionError,ValueError,KeyError) as e:r['checker_error']=str(e)
            r.update(fixture=name,arm=arm,checker_pass=ok,elf_sha256=digest(elf));save(d/'result.json',r);results.append(r);save(out/'results.json',results)
            if not ok:raise RuntimeError('checker failed: '+name+'/'+arm)
    if ids!={x:digest(x) for x in ids}:raise RuntimeError('runtime identity changed')
    save(out/'summary.json',dict(status='PASS',calls=10,results=results,scope='two fixtures; not historical595 forms'))
    print('PASS: two fixtures, ten calls')
if __name__=='__main__':
    try:main()
    except Exception as e:print(str(e),file=sys.stderr);sys.exit(1)
