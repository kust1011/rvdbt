#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Additive immediate-vtype delta. Does not regenerate configuration147."""
import config

def cases():
    rows=[]
    for w in [128,256,512,1024,2048,4096]:
      for form,width in [('vsetvli',11),('vsetivli',10)]:
       for ta,ma in [(False,False),(False,True),(True,False),(True,True)]:
        vt=config.vtype(8,0,ta,ma);n=w//8
        base=f'delta148-w{w}-{form}-p{int(ta)}{int(ma)}'
        def add(tag,newvt,avl=1,start=0,prevt=None,rd=8,rs1=9,classification='unsupported-vtype'):
            assert 0<=newvt<1<<width
            assert form!='vsetivli' or 0<=avl<=31
            pre=config.vtype(8,0,not ta,not ma) if prevt is None else prevt
            rows.append(dict(id=base+'-'+tag,unit=base+('-start' if start else '-zero'),
              family='configuration148',form=form,mnemonic=form,tag=tag,vlen=w,sew=8,
              lmul='m1',lmul_exp=0,vlmax=n,vl=0 if pre==config.VILL else n//2,
              ta=ta,ma=ma,vstart=start,avl=avl,rd=rd,rs1=rs1,rs2=18,
              new_vtype=newvt,pre_vtype=pre,classification=classification,
              seed=148,group_registers=1,mask='none',operand=0))
        invalid=[(4,'lmul100')]+[(s<<3,f'sew-encoding{s}') for s in range(4,8)]
        invalid += [(8|5,'e16-mf8'),(16|5,'e32-mf8'),(16|6,'e32-mf4'),
                    (24|5,'e64-mf8'),(24|6,'e64-mf4'),(24|7,'e64-mf2')]
        invalid += [(1<<b,'upper-bit'+str(b)) for b in range(8,width)]
        invalid += [(((1<<width)-1)&~255,'all-upper'),((1<<width)-1,'all-immediate')]
        for value,name in invalid:
          value |= (int(ta)<<6)|(int(ma)<<7)
          for avl in [0,1,31]:
            for start in [0,1]:add(name+f'-avl{avl}-start{start}',value,avl,start)
          add(name+'-pre-vill',value,1,1,config.VILL)
          add(name+'-rd-zero',value,1,1,rd=0)
          if form=='vsetvli':
            add(name+'-avl-xlenmax',value,0xffffffff,0)
            add(name+'-rs1-zero',value,0,1,rs1=0)
        # Recovery is directly credited to each immediate opcode, from vill.
        for avl in [0,1,31]:
          for start in [0,1]:
            add(f'vill-recovery-avl{avl}-start{start}',vt,avl,start,config.VILL,classification='legal')
    assert len(rows)==len({c['id'] for c in rows})
    return rows
