#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Task147 finite configuration family; independent RVV1.0 constraints.

Uses vadd.py's builder, packets, capture, pinned references and bounded runner.
No DUT implementation supplies any predicate. Reserved x0/x0 transitions are
observations only, with no universal target-state assertion.
"""
import collections, json
from pathlib import Path

LMUL=[('mf8',-3),('mf4',-2),('mf2',-1),('m1',0),('m2',1),('m4',2),('m8',3)]
VILL=1<<31

def vtype(e,exp,ta=False,ma=False):
    return (exp&7)+([8,16,32,64].index(e)<<3)+(int(ta)<<6)+(int(ma)<<7)

def cases():
    rows=[]
    for w in [128,256,512,1024,2048,4096]:
      for e in [8,16,32,64]:
       for lm,exp in LMUL:
        if e>64*2**exp: continue
        n=int(w/e*2**exp)
        for form in ['vsetvli','vsetivli','vsetvl']:
         for ta,ma in [(False,False),(False,True),(True,False),(True,True)]:
          vt=vtype(e,exp,ta,ma)
          base=f'w{w}-e{e}-{lm}-{form}'
          def add(tag,avl=1,rd=8,rs1=9,rs2=18,start=0,prevt=None,prevl=None,newvt=None,classification='legal'):
            newvt=vt if newvt is None else newvt
            prevt=vtype(e,exp,not ta,not ma) if prevt is None else prevt
            prevl=max(1,n//2) if prevl is None else prevl
            if prevt==VILL: prevl=0
            unit=base+('-start' if start else '-zero')
            rows.append(dict(id=f'{base}-p{int(ta)}{int(ma)}-{tag}',unit=unit,
              family='configuration147',form=form,mnemonic=form,tag=tag,vlen=w,sew=e,
              lmul=lm,lmul_exp=exp,vlmax=n,vl=prevl,ta=ta,ma=ma,vstart=start,
              avl=avl,rd=rd,rs1=rs1,rs2=rs2,new_vtype=newvt,pre_vtype=prevt,
              classification=classification,seed=147,group_registers=1,mask='none',operand=0))
          values={0,1,n-1,n,n+1,(3*n)//2,2*n-1,2*n,2*n+1,0xffffffff}
          if form=='vsetivli': values={0,1,15,16,30,31}|{x for x in values if x<=31}
          for a in sorted(values): add('avl'+str(a),a)
          # Same inputs repeated after a different initialized vstart/pre-state.
          a=min(31,n+1) if form=='vsetivli' else n+1
          add('deterministic-repeat',a,start=1,prevl=0)
          add('start-zero-avl',0,start=1)
          add('start-maxcsr',1,start=w-1,classification='legal' if n==w else 'reserved-vstart-profile')
          add('vill-recovery',1,start=1,prevt=VILL)
          add('rd-zero',min(31,n) if form=='vsetivli' else n,rd=0)
          if form!='vsetivli':
            add('rs1-zero-max',0,rs1=0,start=1)
            add('rd-rs1-overlap',n+1,rs1=8)
            for pv in sorted({0,1,n//2,n}):
              add('preserve-policy-vl'+str(pv),rd=0,rs1=0,prevl=pv,start=1)
            # Enumerate every other legal equal-ratio predecessor.
            for pe in [8,16,32,64]:
              for plm,pexp in LMUL:
                if pe<=64*2**pexp and pexp-[8,16,32,64].index(pe)==exp-[8,16,32,64].index(e) and pe!=e:
                  add(f'preserve-e{pe}-{plm}',rd=0,rs1=0,prevt=vtype(pe,pexp,not ta,not ma),start=1)
            # This ratio change is reserved even if current VL fits both ratios.
            pvt=0 if n!=w//8 else 8
            add('reserved-preserve-ratio-change',rd=0,rs1=0,prevt=pvt,prevl=1,classification='reserved-preserve')
          if form=='vsetvl':
            add('rd-rs2-overlap',n+1,rd=18)
            add('rs1-rs2-overlap',vt,rs1=18)
            if vt==0: add('rs2-zero',n+1,rs2=0)
            # All upper vtype bits must be inspected, including the vill input.
            for bit in range(8,32):
              add('upper-bit'+str(bit),1,newvt=vt|(1<<bit),start=1,classification='unsupported-vtype')
            for val,name in [(4,'lmul100'),(32,'sew128'),(63,'sew1024'),(31,'e64-mf2'),(0xffffffff,'allbits')]:
              add('unsupported-'+name,1,newvt=val,start=1,classification='unsupported-vtype')
    assert len({c['id'] for c in rows})==len(rows)
    return rows

def rd_before(c):
    if c['rd']==0: return 0
    if c['rd']==c['rs2'] and c['form']=='vsetvl': return c['new_vtype']
    if c['rd']==c['rs1'] and c['form']!='vsetivli': return c['avl']
    return 0x147abcd

def setup(c):
    # No vector instruction between establishing pre-vill and target capture.
    lines=['csrwi vcsr,5','li t0,117','csrw fcsr,t0',f'li t0,{c["vl"]}',
           f'li t3,{c["pre_vtype"]}','vsetvl t2,t0,t3',
           f'li x{c["rd"]},{rd_before(c)}'] if c['rd'] else ['csrwi vcsr,5','li t0,117','csrw fcsr,t0',f'li t0,{c["vl"]}',f'li t3,{c["pre_vtype"]}','vsetvl t2,t0,t3']
    if c['form']!='vsetivli' and c['rs1']: lines += [f'li x{c["rs1"]},{c["avl"]}']
    if c['form']=='vsetvl' and c['rs2']: lines += [f'li x{c["rs2"]},{c["new_vtype"]}']
    lines += [f'li t0,{c["vstart"]}','csrw vstart,t0']
    return lines

def opcode(c):
    common=(7<<12)|(c['rd']<<7)|0x57
    if c['form']=='vsetvli': return common|(c['rs1']<<15)|(c['new_vtype']<<20)
    if c['form']=='vsetivli': return common|(c['avl']<<15)|(c['new_vtype']<<20)|0xc0000000
    return common|(c['rs1']<<15)|(c['rs2']<<20)|0x80000000

def target(c):
    # Raw encoding permits testing unsupported vtype values without assembler
    # pseudo-instructions; full exact encoding is independently audited.
    return f'.word 0x{opcode(c):08x} # {c["form"]} target'

def bounds(c):
    n=c['vlmax']
    if c['classification']=='unsupported-vtype': return 0,0
    if c['form']!='vsetivli' and c['rs1']==0:
      a=c['vl'] if c['rd']==0 else 0xffffffff
    else: a=c['avl']
    if a<=n: return a,a
    if a<2*n: return (a+1)//2,n
    return n,n

def check_isa(c,raw,rc=0,timeout=False):
    import vadd as v
    if rc!=0 or timeout: raise ValueError('failed execution/timeout')
    pre,post,before,after=v.decode(c,raw)
    expected=[c['vl'],c['pre_vtype'],c['vlen']//8,c['vstart'],2,1,5,21,3,117,rd_before(c)]
    if pre!=expected: raise ValueError(f'pre CSR/rd mismatch: {pre} != {expected}')
    if before!=v.initial(c): raise ValueError('observed pre-register mismatch')
    if after!=before: raise ValueError('configuration changed vector registers')
    if post[2]!=pre[2] or post[4:10]!=pre[4:10]: raise ValueError('preserved CSR mismatch')
    if c['classification']=='reserved-preserve': return True # observation-only
    vt=VILL if c['classification']=='unsupported-vtype' else c['new_vtype']
    if post[1]!=vt: raise ValueError(f'post vtype {post[1]:08x} != {vt:08x}')
    if post[3]!=0: raise ValueError('vstart not cleared')
    lo,hi=bounds(c)
    if not lo<=post[0]<=hi: raise ValueError(f'VL {post[0]} outside allowed [{lo},{hi}]')
    if post[10]!=(post[0] if c['rd'] else 0): raise ValueError('actual rd does not equal VL/x0')
    return True

def check_reference(c,raw,reference):
    import vadd as v
    # Compare invariant observations; both packets independently satisfy bounds.
    check_isa(c,reference)
    a=v.decode(c,raw);b=v.decode(c,reference)
    if a[0]!=b[0] or a[2:]!=b[2:]: raise ValueError('independent pre/register mismatch')
    if c['classification']=='reserved-preserve':
      indices=[2,4,5,6,7,8,9] # no universal reserved result requirement
    else:
      indices=[1,2,3,4,5,6,7,8,9]
      if bounds(c)[0]==bounds(c)[1]: indices += [0,10]
    if any(a[1][i]!=b[1][i] for i in indices): raise ValueError('independent invariant CSR/rd mismatch')
    return True

def determinism(root, packet_overrides=None):
    import vadd as v
    m=json.loads((root/'manifest.json').read_text());units=collections.defaultdict(list)
    for c in m['cases']: units[c['unit']].append(c)
    seen={};errors=[];comparisons=0
    for unit,cs in units.items():
      for arm in ['Reference','B','M1','M2','BOTH']:
        raw=(root/'runs'/unit/arm/'packets.bin').read_bytes();size=v.packet_size(cs[0])
        if len(raw)!=len(cs)*size: continue
        for i,c in enumerate(cs):
          if c['classification'] not in ['legal','reserved-vstart-profile']: continue
          a=c['avl'] if c['form']=='vsetivli' or c['rs1'] else c['vl'] if c['rd']==0 else 0xffffffff
          implementation=('Sail-ceil' if cs[0]['vstart'] else 'Spike') if arm=='Reference' else arm
          key=(implementation,c['vlen'],a,c['vlmax'])
          packet=(packet_overrides or {}).get((c['id'],arm),raw[i*size:(i+1)*size])
          vl=v.decode(c,packet)[1][0]
          if key in seen:
            comparisons+=1
            if vl!=seen[key][0]: errors.append(dict(case=c['id'],arm=arm,previous=seen[key][1],previous_vl=seen[key][0],vl=vl))
          else: seen[key]=(vl,c['id'])
    return dict(comparisons=comparisons,distinct_inputs=len(seen),failures=errors)
