#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded implementation-tree verification, NOT a complete unordered ISA oracle.

Reuses Task174 observation/preservation harness and Task157 rational rounding.
The ISA witness set contains all binary trees at destination precision for these
small inputs; nonmembership is UNVERIFIED, never an ISA-defect verdict.
"""
import collections, functools, gzip, json, os, resource, struct, sys
from fractions import Fraction
from pathlib import Path
import fp157 as fp
import fpreduce174 as f
import vadd as v
import storage149 as storage
PIN='8a468967852b8f16225b359fce99c0d22ab286d6314cb90a79934a7376207281'
LIB='79d0ba2a9ddea24d49d7282012fdc373b92a26756bb5452c1f41c66d533887af'
SPIKE='cddd7a406bd92836f220e929aca0f4925542e80d0b2246b8920e6f49648a6994'
PK='30f4e5906b13264ff98a8fa36dfea848f8504a65c028e96930329668f1f564ad'
BASE=Path('/home/vick/rvdbt-host512-task179-build')
_original_allowed=f.allowed

def sequential(c,before):
    seed,xs=f.operands(c,before);acc=seed;flags=c['fflags_initial'];steps=[]
    for i,x in enumerate(xs):
        y,pfl=f.promote(c,x)
        out,fl=fp.arithmetic(c['dst_eew'],'vfadd',acc,y,c['frm'])
        a,b=fp.unpack(c['dst_eew'],acc),fp.unpack(c['dst_eew'],y)
        exact=str(a[2]+b[2]) if a[1]==b[1]=='finite' else None
        flags|=pfl|fl
        steps.append(dict(active_index=i,input=x,promoted=y,promotion_flags=pfl,
                          accumulator=acc,exact_sum=exact,rounded=out,add_flags=fl,sticky=flags))
        acc=out
    return (acc,flags),steps

def selected_allowed(c,before):return {sequential(c,before)[0]}

def check(c,raw,rc=0,timeout=False,allowed=selected_allowed):
    # Sequential reuse of the existing full-state checker. No thread races.
    old=f.allowed;f.allowed=allowed
    try:return f.check_isa(c,raw,rc,timeout)
    finally:f.allowed=old

@functools.lru_cache(maxsize=512)
def tree_results(bits,rm,leaves):
    """Certified minimum-format tree outcomes and constructive witnesses.

    All labeled leaves appear exactly once. Each internal node rounds with frm;
    root conversion is exact at the same width. Optional final ISA identity is
    also evaluated. This is a sufficient legal set, not an exhaustive ISA set.
    """
    @functools.lru_cache(None)
    def visit(mask):
        if mask & (mask-1)==0:
            i=mask.bit_length()-1;return {(leaves[i],0):str(i)}
        answers={};sub=(mask-1)&mask
        while sub:
            other=mask^sub
            if other and sub<other:
                for (a,af),aw in visit(sub).items():
                    for (b,bf),bw in visit(other).items():
                        out,fl=fp.arithmetic(bits,'vfadd',a,b,rm)
                        answers.setdefault((out,af|bf|fl),f'({aw}+{bw})')
            sub=(sub-1)&mask
        return answers
    answers=dict(visit((1<<len(leaves))-1))
    identity=0 if rm==2 else fp.constants(bits)['negzero']
    for (out,fl),w in list(answers.items()):
        y,yfl=fp.arithmetic(bits,'vfadd',out,identity,rm)
        answers.setdefault((y,fl|yfl),f'({w}+identity)')
    return answers

def witnesses(c,before):
    seed,xs=f.operands(c,before)
    if not c['vl'] or not xs:return {sequential(c,before)[0]:'copy seed (selected legal choice)'}
    ys=[];flags=c['fflags_initial']
    for x in xs:
        y,fl=f.promote(c,x);ys.append(y);flags|=fl
    return {(x,flags|fl):w for (x,fl),w in tree_results(c['dst_eew'],c['frm'],tuple([seed]+ys)).items()}

def cases():
    rows=[]
    for form,sew in [('vfredusum.vs',32),('vfredusum.vs',64),('vfwredusum.vs',32)]:
      dst=64 if form.startswith('vfw') else sew;k=fp.constants(sew);dk=fp.constants(dst)
      p=fp.layout(dst)[0]+1
      big=fp.rounded(sew,Fraction(2)**p,0)[0]
      negbig=big|k['negzero']
      for w,exp in [(128,1),(1024,0)]:
       n=(w//sew)*(1<<exp);unit=form.replace('.','-')+f'-e{sew}-w{w}-m{1<<exp}'
       for rm in range(5):
        def add(tag,seed,values,**kw):
            c=dict(family='fpreduce174',mnemonic=form,form='vs',vlen=w,sew=sew,dst_eew=dst,lmul=f'm{1<<exp}',lmul_exp=exp,vlmax=n,group_registers=1<<exp,vs2=16,vs1=24,vd=8,operand=0x81234567,seed=190,frm=rm,fflags_initial=0,vl=3,vstart=0,mask='none',ta=False,ma=False,values=values,seed_word=seed,tag=tag,unit=unit)
            c.update(kw);c['id']=unit+f'-rm{rm}-'+tag;c['ordinal']=len(rows);f.validate(c);rows.append(c)
        add('cancel-after-loss',dk['zero'],[big,k['one'],negbig])
        add('seed-halfway-even',dk['one'],[k['halfulp'] if sew==dst else fp.rounded(32,Fraction(2)**-53,0)[0],k['zero'],k['zero']])
        add('seed-halfway-odd',dk['nextone'],[k['halfulp'] if sew==dst else fp.rounded(32,Fraction(2)**-53,0)[0],k['zero'],k['zero']],fflags_initial=8)
        add('overflow-positive',dk['maxfinite'],[k['maxfinite'],k['one'],k['zero']])
        add('overflow-negative',dk['maxfinite']|dk['negzero'],[k['maxfinite']|k['negzero'],k['negone'],k['zero']],fflags_initial=2)
        add('subnormal-cancel',dk['minnormal'],[k['minsub']|k['negzero'],k['minsub'],k['zero']],fflags_initial=2)
        add('sticky-all',dk['zero'],[big,k['one'],negbig],fflags_initial=31)
        add('mask-two-active',dk['zero'],[big,k['snan'],k['one'],k['snan']],vl=4,mask='alternating',ta=True,ma=True,fflags_initial=16)
        add('partial-poison-tail',dk['zero'],[big,k['one'],negbig,k['snan']],vl=3,ta=True)
        add('all-masked',dk['one'],[k['snan'],k['maxfinite']],mask='zero',fflags_initial=9)
        add('zero-length',dk['one'],[k['snan']],vl=0,fflags_initial=3)
        add('all-on-two-active',dk['one'],[k['halfulp'],k['minsub'],k['snan']],vl=2,mask='all',fflags_initial=4)
    return rows

def prepare(out):
    out.mkdir(parents=True,exist_ok=False);rows=cases();expected=[]
    for c in rows:
        before=f.initial(c);result,steps=sequential(c,before);legal=witnesses(c,before)
        if result not in legal:raise ValueError('selected tree lacks legal witness')
        expected.append(dict(case=c['id'],selected=list(result),steps=steps,
                             legal_minimum_format_witnesses=[dict(result=list(r),tree=w) for r,w in sorted(legal.items())]))
    v.save(out/'MANIFEST.json',rows)
    with gzip.open(out/'EXPECTED.json.gz','wt') as stream:json.dump(expected,stream,indent=2)
    v.save(out/'DECLARATION.json',dict(cases=len(rows),units=len({c['unit'] for c in rows}),DUT_checks=len(rows)*4,reference_checks=len(rows),commands=len({c['unit'] for c in rows})*5,per_form=dict(collections.Counter(c['mnemonic']+f'/e{c["sew"]}' for c in rows)),frm=list(range(5)),guest_jobs=1,compile_jobs=2,nice=10,affinity='none',reserve_GiB=10,ISA_oracle='constructive subset of permitted trees; nonmembership UNVERIFIED',selected_tree='left fold in active lane order; each add rounded at dst_eew',UF='unreachable newly raised by selected same-format add tree; exact subnormal and sticky UF tested',execution='NOT_RUN'))
    print(len(rows),'cases /',len({c['unit'] for c in rows}),'units',flush=True)

def gate(out,label):
    status=Path('/proc/meminfo').read_text();available=int(next(x.split()[1] for x in status.splitlines() if x.startswith('MemAvailable:')))*1024
    free=__import__('shutil').disk_usage(out).free
    row=dict(label=label,available_bytes=available,disk_free_bytes=free,nice=os.getpriority(os.PRIO_PROCESS,0),affinity='no affinity assigned',own_guest_limit=1,own_compile_limit=2)
    with (out/'RESOURCES.jsonl').open('a') as stream:stream.write(json.dumps(row)+'\n')
    if min(available,free)<10*1024**3:raise RuntimeError('10GiB reserve')
    if row['nice']!=10:raise RuntimeError('nice must be 10')

def build(out):
    gate(out,'build');rows=json.loads((out/'MANIFEST.json').read_text());f.cases=lambda:rows
    v.build(out/'corpus','clang-22',Path('/home/vick/rvv-directed-task145/link.ld'),'fpreduce174',2)

def run(out):
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    engine=BASE/'build/bin/elfrun';lib=BASE/'build/lib/libdbtjitshared.so'
    spike=Path('/home/vick/rvv-directed-task145/deps/spike');pk=spike.with_name('pk')
    paths=[engine,lib,spike,pk];pins={str(p):v.sha(p) for p in paths}
    if list(pins.values())!=[PIN,LIB,SPIKE,PK]:raise ValueError('frozen identities')
    v.save(out/'IDENTITIES_BEFORE.json',pins)
    root=out/'corpus';manifest=json.loads((root/'manifest.json').read_text());units=collections.defaultdict(list)
    if manifest['cases']!=json.loads((out/'MANIFEST.json').read_text()):raise ValueError('manifest changed')
    flags=json.loads((out/'FLAGS.json').read_text());results=[]
    builds=json.loads((root/'build-commands.json').read_text())
    for b in builds:
        elf=Path(b['command'][-1])
        if b['returncode'] or v.sha(elf)!=b['elf_sha256']:raise ValueError('ELF identity')
    for c in manifest['cases']:units[c['unit']].append(c)
    for unit,cs in units.items():
      elf=root/unit/'test.elf';storage.materialize(elf);reference={}
      for arm in ['Reference','B','M1','M2','BOTH']:
        gate(out,unit+'/'+arm);d=root/'runs'/unit/arm;env=dict(os.environ)
        if arm=='Reference':cmd=[spike,f'--isa=rv32gcv_zvl{cs[0]["vlen"]}b',pk,elf]
        else:
            fs=root/'work'/unit/arm/'fs';fs.mkdir(parents=True);cache=fs.parent/'cache';cache.mkdir();os.link(elf,fs/'t.elf')
            env['LD_LIBRARY_PATH']=str(lib.parent)+':/home/vick/boost_vendor/lib'
            opts=[f'--vlen={cs[0]["vlen"]}' if x.startswith('--vlen=') else x for x in flags[arm]]
            cmd=[engine,*opts,'--dump-tbmap='+str(d/'tbmap'),'--fsroot='+str(fs),'--cache='+str(cache),'--','/t.elf']
        rec=v.execute(cmd,d,env);raw=storage.verify(d/'stdout');size=v.packet_size(cs[0]);errors=[]
        for i,c in enumerate(cs):
            packet=raw[i*size:(i+1)*size];status='PASS';error=None;actual=None;witness=None
            try:
                if len(raw)!=size*len(cs):raise ValueError('packet extent')
                if arm=='Reference':
                    legal=witnesses(c,f.initial(c))
                    check(c,packet,rec['returncode'],rec['timeout'],lambda c,b:legal)
                else:check(c,packet,rec['returncode'],rec['timeout'])
                pre,post,before,after=v.decode(c,packet)
                off=c['vd']*(c['vlen']//8);e=c['dst_eew']//8
                actual=(int.from_bytes(after[off:off+e],'little'),post[7]) if c['vl'] else sequential(c,before)[0]
                witness=witnesses(c,before).get(actual)
                if arm=='Reference':reference[c['id']]=actual
            except ValueError as ex:
                status='UNVERIFIED' if arm=='Reference' and str(ex)=='reduction result/flags' else 'FAIL'
                error=str(ex);errors.append(dict(case=c['id'],error=error))
            results.append(dict(case=c['id'],arm=arm,status=status,error=error,actual=actual,legal_tree_witness=witness,
                                reference_agreement=(actual==reference.get(c['id'])) if arm!='Reference' else None,
                                raw=str(d/'stdout'),offset=i*size,size=size,
                                predicate='ISA permitted-tree witness' if arm=='Reference' else 'source-selected sequential tree + full state'))
        v.save(d/'errors.json',errors);storage.compress(d/'tbmap')
        print(unit,arm,len(cs),len(errors),'errors',flush=True)
        if arm!='Reference':(fs/'t.elf').unlink()
      elf.unlink() # new materialization only; permanent .gz original retained
    v.save(out/'RESULTS.json',results)
    after={str(p):v.sha(p) for p in paths};v.save(out/'IDENTITIES_AFTER.json',after)
    if after!=pins:raise ValueError('identity changed')
    v.save(out/'SUMMARY.json',dict(cases=len(manifest['cases']),DUT_checks=sum(r['arm']!='Reference' for r in results),reference_checks=sum(r['arm']=='Reference' for r in results),counts=dict(collections.Counter(r['status'] for r in results)),arms={a:dict(collections.Counter(r['status'] for r in results if r['arm']==a)) for a in ['Reference','B','M1','M2','BOTH']},reference_disagreement=sum(r['reference_agreement'] is False for r in results),native_admission='not inferred from switches or packet PASS'))
    if any(r['status']!='PASS' for r in results):raise SystemExit(1)

if __name__=='__main__':
    action,out=sys.argv[1],Path(sys.argv[2]);{'prepare':prepare,'build':build,'run':run}[action](out)
