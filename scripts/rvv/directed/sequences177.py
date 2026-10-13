#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""P3 sequences using Task145's observer, build, execution and packet retention.

No production changes. Each element operation updates the reference image in
guest order. FP arithmetic uses the retained exact-rational predicate; actual
independent answers still come from the original Spike/Sail executables.
"""
import argparse, collections, hashlib, itertools, json, os, re, struct, subprocess
from fractions import Fraction
from pathlib import Path
import vadd as v
import fp157 as f

ARMS = ('Reference', 'B', 'M1', 'M2', 'BOTH')
WIDTHS = (128, 256, 512, 1024, 2048, 4096)

def program(name, fp=False):
    add, sub = ('vfadd', 'vfsub') if fp else ('vadd', 'vsub')
    # op, destination, source2, source1, masked
    if name in ('liveout', 'reject-tu', 'reject-mask'):
        return [(add,8,16,24,name=='reject-mask'),(sub,12,8,20,False)]
    if name == 'overwrite':
        return [(add,8,16,24,False),(sub,8,20,24,False),(add,12,8,16,False)]
    if name == 'alias':
        return [(add,16,16,24,False),(sub,16,16,24,False),(add,8,16,24,False)]
    if name == 'masked-update':
        return [(add,8,16,24,False),(add,8,20,24,True),(sub,12,8,16,False)]
    if name == 'boundary':
        return [(add,8,16,24,False),(sub,12,8,20,False),
                ('vmaxu',12,12,24,True),('vadd',28,12,8,False),('vxor',28,28,24,False)]
    if name == 'chain':
        return [(add,8,16,24,False),(sub,12,8,20,False),
                (add,8,12,24,False),(sub,12,8,16,False),(add,28,12,8,False)]
    if name == 'cache':
        return [('vadd',8,8,16,False),('vxor',12,8,24,False)]
    raise ValueError(name)

def cases(part):
    result=[]
    fp=part=='fp'
    geometries = ((32,0),(16,0),(64,0),(32,1)) if part=='integer' else ((32,0),(64,0),(32,1),(64,1),(32,-1)) if fp else ((32,0),)
    names = ('liveout','overwrite','alias','masked-update','boundary','chain') if part=='integer' else ('liveout','overwrite','alias','chain','reject-tu','reject-mask') if fp else ('cache',)
    for w in WIDTHS:
      for sew,exp in geometries:
        n=int(Fraction(w,sew)*Fraction(2)**exp)
        lengths=sorted({0,1,n,max(1,n//2),n-1} | {x for x in (512//sew-1,512//sew,512//sew+1) if 0<=x<=n})
        for name in names:
          specs=[(vl,0,False) for vl in (lengths if part!='cache' else [n])]
          if part!='cache': specs += [(n,min(3,n-1),False)]
          if fp and name=='chain': specs += [(min(n,512//sew+1),0,True)]
          for vl,start,special in specs:
            lm = 'mf2' if exp==-1 else 'm'+str(2**exp)
            unit=f'{part}-w{w}-e{sew}-{lm}-{name}'+('-start' if start else '-zero')
            tag=f'vl{vl}-start{start}'+('-special' if special else '')
            c=dict(id=unit+'-'+tag,unit=unit,part=part,scenario=name,fp=fp,
                   vlen=w,sew=sew,lmul=lm,lmul_exp=exp,vlmax=n,vl=vl,
                   vstart=start,ta=fp and name!='reject-tu',ma=False,
                   mask='alternating',vd=8,vs2=16,vs1=24,operand=0x80000001,
                   form='vv',family='fp157',group_registers=max(1,2**exp),
                   frm=0,fflags_initial=5,seed=146,tag=tag,special=special)
            c['ops']=program(name,fp)
            result.append(c)
    for i,c in enumerate(result): c['ordinal']=i
    return result

legacy_initial=v.initial
def initial(c):
    if not c['fp']:
        return legacy_initial(dict(c,family='integer146'))
    b,e=c['vlen']//8,c['sew']//8
    image=bytearray(32*b)
    for r in range(32):
      for lane in range(b//e):
        bits,_=f.rounded(c['sew'],Fraction((r+1)*4+lane),0)
        if c['special'] and r in (16,24) and lane%5==0:
            bits=f.constants(c['sew'])['snan' if r==16 else 'inf']
        image[r*b+lane*e:r*b+(lane+1)*e]=bits.to_bytes(e,'little')
    image[:b]=v.mask_bytes(c)
    return bytes(image)

def target(c):
    tag=c['ordinal']
    def encoded(ops):
        return [f'.globl seq_{tag}_{i}\nseq_{tag}_{i}:\n{op}.vv v{d},v{a},v{z}'+(',v0.t' if masked else '') for i,(op,d,a,z,masked) in enumerate(ops)]
    if c['scenario']!='cache': return '\n'.join(encoded(c['ops']))+f'\n.globl seq_end_{tag}\nseq_end_{tag}:'
    # Three visits to exactly the same arithmetic PCs, with e32/full,
    # e64/partial, e32/partial. Normal direct guest edges only.
    n=c['vlmax']; p=max(1,n//4)
    lines=['li t3,0',f'j cfg_{tag}_0']
    for phase,(sew,vl) in enumerate(((32,n),(64,max(1,n//4)),(32,p))):
        lines += [f'cfg_{tag}_{phase}:',f'li t0,{vl}',f'vsetvli zero,t0,e{sew},m1,tu,mu',f'j common_{tag}']
    lines += [f'common_{tag}:']+encoded(c['ops'])+['addi t3,t3,1','li t4,1',f'beq t3,t4,cfg_{tag}_1','li t4,2',f'beq t3,t4,cfg_{tag}_2',f'.globl seq_end_{tag}',f'seq_end_{tag}:']
    return '\n'.join(lines)

def expectation(c):
    """Exact bytes plus independently allowed tail words (no tail-to-active edges)."""
    image=bytearray(initial(c)); b=c['vlen']//8
    flags=c['fflags_initial']; start=c['vstart']; tails={}
    phases=[(c['sew'],c['vl'],c['ta'],start)]
    if c['scenario']=='cache':
        phases=[(32,c['vlmax'],False,0),(64,max(1,c['vlmax']//4),False,0),(32,max(1,c['vlmax']//4),False,0)]
    for sew,vl,ta,start in phases:
      e=sew//8; n=int(Fraction(c['vlen'],sew)*Fraction(2)**c['lmul_exp'])
      for op,d,a,z,masked in c['ops']:
        old=bytes(image)
        for lane in range(n):
          off=d*b+lane*e
          active=start<=lane<vl and (not masked or bool(old[lane//8]>>(lane%8)&1))
          if active:
            x=int.from_bytes(old[a*b+lane*e:a*b+(lane+1)*e],'little')
            y=int.from_bytes(old[z*b+lane*e:z*b+(lane+1)*e],'little')
            if op.startswith('vf'):
                word,ff=f.arithmetic(sew,op,x,y,c['frm']);flags|=ff
            else:
                word={'vadd':lambda:x+y,'vsub':lambda:x-y,'vxor':lambda:x^y,'vmaxu':lambda:max(x,y)}[op]()%(1<<sew)
            image[off:off+e]=word.to_bytes(e,'little')
          elif start<vl and lane>=vl and ta:
            tails[off]=e
        # Fractional LMUL's physical-register tail is also architectural.
        if start<vl and ta:
            for off in range(d*b+n*e,(d+1)*b,e): tails[off]=e
        start=0
    sew,vl,ta,_=phases[-1]
    vt=(c['lmul_exp']&7)+([8,16,32,64].index(sew)<<3)+(int(ta)<<6)
    csr=[vl,vt,b,0,2,1,5,flags,c['frm'],(c['frm']<<5)|flags,c['operand']&0xffffffff]
    return bytes(image),tails,csr

def check_isa(c,raw,rc=0,timeout=False):
    if rc or timeout: raise ValueError('failed execution/timeout')
    pre,post,before,after=v.decode(c,raw)
    expected_pre=v.csr_expected(c)+[c['operand']&0xffffffff]
    expected_pre[7:10]=[c['fflags_initial'],c['frm'],(c['frm']<<5)|c['fflags_initial']]
    if pre!=expected_pre or before!=initial(c): raise ValueError('physical prestate mismatch')
    want,tails,csrs=expectation(c)
    if post!=csrs: raise ValueError(f'final CSR/scalar mismatch: {post} != {csrs}')
    n=96+64*(c['vlen']//8)
    scalar=f.scalar(c).to_bytes(8,'little')
    if raw[n:n+8]!=scalar or raw[n+8:n+16]!=scalar: raise ValueError('FP scalar preservation')
    allowed=bytearray(want)
    for off,e in tails.items():
        actual=after[off:off+e]
        if actual not in (want[off:off+e],b'\xff'*e): raise ValueError(f'illegal tail at byte {off}')
        allowed[off:off+e]=actual
    if after!=allowed:
        off=next(i for i,(x,y) in enumerate(zip(after,allowed)) if x!=y)
        raise ValueError(f'final register byte {off}: {after[off]:02x} != {allowed[off]:02x}')
    return True

def check_reference(c,raw,reference):
    check_isa(c,reference);check_isa(c,raw)
    a=v.decode(c,raw)[3];r=v.decode(c,reference)[3]
    _,tails,_=expectation(c);skip={i for off,e in tails.items() for i in range(off,off+e)}
    if any(x!=y for i,(x,y) in enumerate(zip(a,r)) if i not in skip): raise ValueError('independent full defined-state mismatch')
    return True

def install(part):
    v.initial=initial; f.target=target
    v.manifest_cases=lambda family:cases(part)
    v.check_isa=check_isa;v.check_reference=check_reference
    v.PIN=v.FPREDUCE174_PIN
    original=v.execute
    def execute(cmd,d,env,timeout=120):
        if Path(str(cmd[0])).name=='elfrun':
            cmd=[cmd[0],f'--dump-tbcode={d}/tbcode','--rvv-pc-census=1',f'--rvv-pc-census-out={d}/pc-census.csv',*cmd[1:]]
        rec=original(cmd,d,env,timeout)
        v.storage.compress(d/'tbcode');v.storage.compress(d/'pc-census.csv')
        return rec
    v.execute=execute

def controls(roots,out):
    counts=collections.Counter();allowed=0;packets=0
    def reject(c,raw,name):
        try:check_isa(c,raw)
        except ValueError:counts[name]+=1;return
        raise AssertionError((c['id'],name))
    for root in roots:
      rows=json.loads((root/'manifest.json').read_text())['cases'];groups=collections.defaultdict(list)
      for c in rows:groups[c['unit']].append(c)
      for unit,cs in groups.items():
        size=v.packet_size(cs[0])
        for arm in ARMS:
          stream=v.storage.verify(root/'runs'/unit/arm/'packets.bin')
          for j,c in enumerate(cs):
            raw=stream[j*size:(j+1)*size];check_isa(c,raw);packets+=1
            base=96+32*(c['vlen']//8);want,tails,_=expectation(c)
            # Every final vector register, including intermediate live-outs,
            # unwritten registers, masks, prestart and VL0 preservation.
            for reg in range(32):
                off=base+reg*(c['vlen']//8)
                bad=bytearray(raw);bad[off]^=1;reject(c,bad,'register-'+str(reg))
            for j,csr in enumerate(v.CSRS):
                bad=bytearray(raw);bad[52+4*j]^=1;reject(c,bad,'CSR-'+csr)
            for off,name in ((92,'s0'),(size-1,'fs0')):
                bad=bytearray(raw);bad[off]^=1;reject(c,bad,name)
            if tails:
                off,e=next(iter(tails.items()));good=bytearray(raw);good[base+off:base+off+e]=b'\xff'*e
                if good!=raw:check_isa(c,good);check_reference(c,good,raw);allowed+=1
    v.save(out,dict(status='PASS',actual_packets=packets,effective_rejections=sum(counts.values()),rejections=dict(counts),changed_allowed_tail_outcomes=allowed,guest_calls=0,passes=1))

def main():
    p=argparse.ArgumentParser();p.add_argument('mode',choices=('prepare','build','run','controls'))
    p.add_argument('--part',choices=('integer','fp','cache'),default='integer');p.add_argument('--root',type=Path,required=True);p.add_argument('--units',type=Path);p.add_argument('--roots',type=Path,nargs='*');a=p.parse_args()
    a.root=a.root.resolve()
    install(a.part)
    if a.mode=='prepare':
        a.root.mkdir(parents=True,exist_ok=False);cs=cases(a.part);units=list(dict.fromkeys(c['unit'] for c in cs))
        # Include each new semantic scenario in the pilot; full geometry/length
        # coverage follows in disjoint units, without adding pilot counts twice.
        pilot=[u for u in units if '-w1024-' in u and '-e32-m1-' in u]
        v.save(a.root/'pilot.json',pilot);v.save(a.root/'remaining.json',[u for u in units if u not in pilot]);v.save(a.root/'declaration.json',dict(cases=len(cs),units=len(units),part=a.part,per_scenario=dict(collections.Counter(c['scenario'] for c in cs)),geometries=sorted({(c['vlen'],c['sew'],c['lmul']) for c in cs})))
    elif a.mode=='build':v.build(a.root,'clang-22',Path('/home/vick/rvv-directed-task145/link.ld'),'sequences177',4,json.loads(a.units.read_text()))
    elif a.mode=='run':v.run(a.root,Path('/home/vick/rvdbt-host512-task174-build/build/bin/elfrun'),Path('/home/vick/rvv-directed-task145/deps/spike'),Path('/home/vick/rvv-directed-task145/deps/pk'),Path('/home/vick/rvv-act4-tools/bin/sail_riscv_sim'),Path('/home/vick/rvv-directed-task177/FLAGS.json'),8)
    else:controls(a.roots,a.root)

if __name__=='__main__':main()
