#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Actual-packet controls for the immediate delta and shift/minmax family."""
import argparse,json,struct
from pathlib import Path
import vadd as v

def run(root,out):
    out.mkdir(parents=True,exist_ok=False)
    cs=json.loads((root/'manifest.json').read_text())['cases'];records=[]
    def packet(c,arm='B'):
      unit=[x for x in cs if x['unit']==c['unit']];size=v.packet_size(c);offset=unit.index(c)*size
      path=root/'runs'/c['unit']/arm/'packets.bin'
      return path.read_bytes()[offset:offset+size],str(path),offset
    def reject(c,name,pos=None,replacement=None,rc=0,timeout=False,missing=False,reference_only=False):
      raw,source,offset=packet(c);ref,_,_=packet(c,'Reference');v.check(c,raw,reference=ref)
      bad=bytearray(raw)
      if pos is not None:bad[pos]^=1
      if replacement is not None:
        p,b=replacement;bad[p:p+len(b)]=b
      if missing:bad=bad[:-1]
      path=out/f'{len(records):04d}-{name}.bin';path.write_bytes(bad)
      try:
        if reference_only:v.check_reference(c,bad,ref)
        else:v.check(c,bad,rc,timeout,ref)
      except ValueError as ex:records.append(dict(case=c['id'],control=name,rejected=True,error=str(ex),source=source,offset=offset,corrupt=path.name,sha256=v.sha(path)))
      else:raise ValueError(f'accepted corruption {c["id"]}: {name}')
    if cs[0]['family']=='configuration148':
      for form in ['vsetvli','vsetivli']:
        for label in ['lmul100','sew-encoding4','e64-mf2','upper-bit8','all-upper','vill-recovery']:
          c=next(c for c in cs if c['form']==form and c['vlen']==128 and not c['ta'] and not c['ma'] and c['tag'].startswith(label) and c['vstart']==1 and c['avl']==1)
          for name,pos in [('rd',92),('vl',52),('vtype',56),('vstart',64),('vlenb',60),('preserved-csr',68),('pre-rd',48),('pre-register',113),('post-register',96+32*16+17)]:reject(c,name,pos)
          reject(c,'missing',missing=True);reject(c,'crash',rc=-11);reject(c,'timeout',timeout=True)
          reject(c,'independent-csr',68,reference_only=True)
    else:
      import shift148
      for mnemonic,forms in shift148.FORMS.items():
        for form in forms:
          subset=[c for c in cs if c['mnemonic']==mnemonic and c['form']==form and c['vlen']==128 and c['lmul']=='m1']
          c=next(c for c in subset if c['sew']==16 and c['tag']=='length1')
          b=16;e=2;post=96+32*b;off=post+c['vd']*b
          for name,pos in [('active',off),('tail',off+e),('source',post+c['vs2']*b),('pre-source',96+c['vs2']*b),('scalar',92)]:reject(c,name,pos)
          for j,csr in enumerate(v.CSRS):reject(c,'post-'+csr,52+4*j)
          reject(c,'missing',missing=True);reject(c,'crash',rc=-11);reject(c,'timeout',timeout=True)
          c=next(c for c in subset if c['sew']==16 and c['tag']=='mask-alternating')
          reject(c,'masked-undisturbed',post+c['vd']*b+e)
          for tag in ['start1','start-zero-vl','start-equal-partial','start-above-partial','start-partial-active']:
            c=next(c for c in subset if c['sew']==16 and c['tag']==tag)
            reject(c,tag+'-preserve',post+c['vd']*b)
          # Choose an active lane where each deliberate semantic mistake differs.
          c=next(c for c in subset if c['sew']==64 and c['tag']=='length2')
          before=v.initial(c);e=8;off=post+c['vd']*b
          mistakes={}
          for i in range(c['vl']):
            a=int.from_bytes(before[c['vs2']*b+i*e:c['vs2']*b+(i+1)*e],'little')
            z=int.from_bytes(before[c['vs1']*b+i*e:c['vs1']*b+(i+1)*e],'little') if form=='vv' else c['operand'] if form=='vi' else (c['operand']&0xffffffff)-(1<<32) if c['operand']&0x80000000 else c['operand']
            actual=v.arithmetic(c,a,z)
            wrong='vsra' if mnemonic=='vsrl' else 'vsrl' if mnemonic in ['vsll','vsra'] else {'vmin':'vminu','vminu':'vmin','vmax':'vmaxu','vmaxu':'vmax'}[mnemonic]
            bad=v.arithmetic(dict(c,mnemonic=wrong),a,z)
            if bad!=actual:mistakes.setdefault('wrong-signedness-or-operation',(off+i*e,bad))
            if form=='vx' and mnemonic in ['vmin','vminu','vmax','vmaxu']:
              bad=v.arithmetic(c,a,c['operand']&0xffffffff)
              if bad!=actual:mistakes.setdefault('zero-extended-scalar',(off+i*e,bad))
          for name,replacement in mistakes.items():
            reject(c,name,replacement=replacement);reject(c,name+'-reference-only',replacement=replacement,reference_only=True)
          if not mistakes:raise ValueError('no distinguishing semantic control '+mnemonic+'.'+form)
          if form=='vi':
            found=False
            for i in range(c['vl']):
              a=int.from_bytes(before[c['vs2']*b+i*e:c['vs2']*b+(i+1)*e],'little')
              bad=v.arithmetic(c,a,c['operand']-32)
              if bad!=v.arithmetic(c,a,c['operand']):
                reject(c,'signed-immediate-count',replacement=(off+i*e,bad));found=True;break
            if not found:raise ValueError('no signed immediate witness')
      # At SEW64, use enough distinct data/count pairs to expose a five-bit mask.
      for mnemonic in ['vsll','vsrl','vsra']:
        c=next(c for c in cs if c['mnemonic']==mnemonic and c['form']=='vv' and c['vlen']==128 and c['sew']==64 and c['lmul']=='m4' and c['tag']=='count-edges')
        before=v.initial(c);off=96+512+c['vd']*16;found=False
        for i in range(c['vl']):
          a=int.from_bytes(before[c['vs2']*16+i*8:c['vs2']*16+(i+1)*8],'little')
          z=int.from_bytes(before[c['vs1']*16+i*8:c['vs1']*16+(i+1)*8],'little')
          bad=v.arithmetic(c,a,z&31)
          if bad!=v.arithmetic(c,a,z):
            reject(c,'fixed-five-bit-count-mask',replacement=(off+i*8,bad));found=True;break
        if not found:raise ValueError('no five-bit mask witness')
      # Shift-specific count errors at SEW8, including immediate unsigned 31.
      for mnemonic in ['vsll','vsrl','vsra']:
        for form in ['vv','vx','vi']:
          tag='operand8' if form in ['vi','vx'] else 'count-edges'
          c=next(c for c in cs if c['mnemonic']==mnemonic and c['form']==form and c['vlen']==128 and c['sew']==8 and c['lmul']=='m1' and c['tag']==tag)
          before=v.initial(c);post=96+512;found=False
          for i in range(c['vl']):
            a=before[c['vs2']*16+i];z=before[c['vs1']*16+i] if form=='vv' else c['operand']
            signed_a=a-256 if a&128 else a
            wrong=(a<<z if mnemonic=='vsll' else a>>z if mnemonic=='vsrl' else signed_a>>z)&255
            if bytes([wrong])!=v.arithmetic(c,a,z):
              reject(c,'unmasked-shift-count',replacement=(post+c['vd']*16+i,bytes([wrong])));found=True;break
          if not found:raise ValueError('no unmasked-count witness')
    v.save(out/'summary.json',dict(controls=len(records),rejected=len(records),records=records))
    print(len(records),'controls rejected')
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('root',type=Path);p.add_argument('out',type=Path);a=p.parse_args();run(a.root,a.out)
