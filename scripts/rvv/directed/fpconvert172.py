#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""RVV1.0 conversions: exact rational/bit predicates, distinct operand EEWs.

Only FP32/64 are admitted. Integer16 to FP32 and FP32 to integer16
need no half FP extension. No host floating conversion or DUT golden.
"""
import json,struct
from fractions import Fraction
from functools import lru_cache
from pathlib import Path
import fp157 as fp
SUB={
 'vfcvt.xu.f.v':0,'vfcvt.x.f.v':1,'vfcvt.f.xu.v':2,'vfcvt.f.x.v':3,
 'vfcvt.rtz.xu.f.v':6,'vfcvt.rtz.x.f.v':7,
 'vfwcvt.xu.f.v':8,'vfwcvt.x.f.v':9,'vfwcvt.f.xu.v':10,'vfwcvt.f.x.v':11,
 'vfwcvt.f.f.v':12,'vfwcvt.rtz.xu.f.v':14,'vfwcvt.rtz.x.f.v':15,
 'vfncvt.xu.f.w':16,'vfncvt.x.f.w':17,'vfncvt.f.xu.w':18,'vfncvt.f.x.w':19,
 'vfncvt.f.f.w':20,'vfncvt.rod.f.f.w':21,'vfncvt.rtz.xu.f.w':22,'vfncvt.rtz.x.f.w':23}
FORMS=tuple(SUB)
QEMU_PATH=Path(__file__).with_name('qemu_fpconvert172.json')
QEMU=json.loads(QEMU_PATH.read_text()) if QEMU_PATH.exists() else {}
active=fp.active

def widths(form,sew):
 return (sew*2,sew) if form.startswith('vfn') else (sew,sew*2) if form.startswith('vfw') else (sew,sew)
def kinds(form):
 kind=SUB[form]&7
 return ('fp','int') if kind in (0,1,6,7) else ('int','fp') if kind in (2,3) else ('fp','fp')
def supported(form,sew):
 sw,dw=widths(form,sew);sk,dk=kinds(form)
 return max(sw,dw)<=64 and (sk!='fp' or sw in (32,64)) and (dk!='fp' or dw in (32,64))
def geometry(form,w,sew,exp):
 if not supported(form,sew) or sew>64*Fraction(2)**exp:return None
 sw,dw=widths(form,sew);sx=exp+int(form.startswith('vfn'));dx=exp+int(form.startswith('vfw'))
 if max(sx,dx)>3:return None
 lm=lambda x:'m'+str(1<<x) if x>=0 else 'mf'+str(1<<-x)
 return dict(vlen=w,sew=sew,lmul=lm(exp),lmul_exp=exp,emul=lm(exp),vlmax=int(Fraction(w,sew)*Fraction(2)**exp),src_eew=sw,dst_eew=dw,src_emul=lm(sx),dst_emul=lm(dx),src_exp=sx,dst_exp=dx,src_regs=max(1,1<<max(sx,0)),dst_regs=max(1,1<<max(dx,0)),group_registers=max(1,1<<max(dx,0)))
def validate(c):
 g=geometry(c['mnemonic'],c['vlen'],c['sew'],c['lmul_exp']);assert g
 assert all(c[k]==x for k,x in g.items())
 for reg,n in ((c['vs2'],c['src_regs']),(c['vd'],c['dst_regs'])):assert reg%n==0 and reg+n<=32
 assert c['mask']=='none' or (c['vd']!=0 and c['vs2']!=0)
 overlap=max(c['vd'],c['vs2'])<min(c['vd']+c['dst_regs'],c['vs2']+c['src_regs'])
 if overlap and c['dst_eew']>c['src_eew']:assert c['src_exp']>=0 and c['vs2']==c['vd']+c['dst_regs']-c['src_regs']
 if overlap and c['dst_eew']<c['src_eew']:assert c['vd']==c['vs2']
 assert 0<=c['vstart']<c['vlmax'] and 0<=c['vl']<=c['vlmax'] and c['frm'] in range(5)
 return True

def target(c):return c['mnemonic']+f' v{c["vd"]},v{c["vs2"]}'+(',v0.t' if c['mask']!='none' else '')
def instruction(c):return 18<<26|int(c['mask']=='none')<<25|c['vs2']<<20|SUB[c['mnemonic']]<<15|1<<12|c['vd']<<7|0x57
def scalar(c):return 0x123456789abcdef0 # unrelated scalar FP register must survive bit-for-bit

def round_integer(value,rm):
 sign=int(value<0);q=abs(value);n,r=divmod(q.numerator,q.denominator)
 inc=(2*r>q.denominator or (2*r==q.denominator and (rm==4 or n&1))) if rm in (0,4) else bool(r and sign) if rm==2 else bool(r and not sign) if rm==3 else False
 return (-1 if sign else 1)*(n+int(inc)),bool(r)

def round_odd(bits,value,zero_sign):
 # IEEE jamming: first round with minMag, then set result significand LSB
 # if inexact. UF is decided with unbounded precision-rounded exponent,
 # independently of the final subnormal encoding (same predicate as Task157).
 word,flags=fp.rounded(bits,value,1,zero_sign)
 if flags&1:word|=1
 return word,flags

@lru_cache(maxsize=131072)
def element(form,sw,dw,word,frm):
 sk,dk=kinds(form);kind=SUB[form]&7;rm=1 if '.rtz.' in form else frm
 if sk=='int':
  value=word-(1<<sw) if kind==3 and word>>(sw-1) else word
  return fp.rounded(dw,Fraction(value),rm)
 sign,k,value,snan=fp.unpack(sw,word)
 if dk=='fp':
  if k=='nan':return fp.constants(dw)['canonical'],16 if snan else 0
  if k=='inf':return sign<<(dw-1)|fp.constants(dw)['inf'],0
  return round_odd(dw,value,sign) if '.rod.' in form else fp.rounded(dw,value,rm,sign)
 signed=kind in (1,7);lo=-(1<<(dw-1)) if signed else 0;hi=(1<<(dw-int(signed)))-1
 if k=='nan':return hi,16
 if k=='inf':return (lo if sign else hi)%(1<<dw),16
 result,nx=round_integer(value,rm)
 if result<lo or result>hi:return min(hi,max(lo,result))%(1<<dw),16
 return result%(1<<dw),int(nx)

@lru_cache(maxsize=256)
def inputs(form,sw,dw):
 sk,dk=kinds(form);out=[]
 def add(name,word):out.append((name,word% (1<<sw)))
 if sk=='int':
  for name,x in [('zero',0),('one',1),('negone',-1),('signed-min',-(1<<(sw-1))),('signed-max',(1<<(sw-1))-1),('unsigned-max',(1<<sw)-1),('highbit',(1<<(sw-1))),('carry32',0xffffffff)]:add(name,x)
  precision=fp.layout(dw)[0]+1
  for p in sorted({precision,sw-1}):
   for delta in (-3,-1,0,1,2,3):
    x=(1<<p)+delta
    if x<(1<<sw):add('integer-edge-'+str(p)+'-'+str(delta),x);add('integer-neg-edge-'+str(p)+'-'+str(delta),-x)
 else:
  k=fp.constants(sw)
  for name in ('zero','negzero','one','negone','half','minsub','maxsub','minnormal','maxfinite','inf','neginf','qnan','snan'):add(name,k[name])
  add('negative-qnan',k['qnan']|k['negzero']);add('negative-snan',k['snan']|k['negzero'])
  def exact(name,x):
   word,_=fp.rounded(sw,Fraction(x),0);add(name,word)
   if word&~k['negzero']:
    add(name+'-prev',word-1);add(name+'-next',word+1)
  if dk=='int':
   for p in (dw-1,dw):
    exact('int-boundary-pos-'+str(p),1<<p);exact('int-boundary-neg-'+str(p),-(1<<p))
   for x in (Fraction(1,2),Fraction(3,2),Fraction(5,2),Fraction(-1,2),Fraction(-3,2),Fraction(-5,2)):exact('tie-'+str(x).replace('/','over'),x)
   for x in ((1<<(dw-1))-1,(1<<dw)-1,-(1<<(dw-1))-1):exact('int-limit-'+str(x),x)
  elif sw>dw:
   d=fp.constants(dw);f=fp.layout(dw)[0];bias=fp.layout(dw)[2]
   for name,x in [('tie-even',Fraction(1)+Fraction(2)**(-f-1)),('tie-odd',Fraction(1)+3*Fraction(2)**(-f-1)),('minsub-half',Fraction(2)**(1-bias-f-1)),('minnormal-edge',Fraction(2)**(1-bias)-Fraction(2)**(1-bias-f-1)),('overflow-tie',fp.unpack(dw,d['maxfinite'])[2]+Fraction(2)**(bias-f-1)),('maxfinite-dest',fp.unpack(dw,d['maxfinite'])[2])]:
    exact(name,x);exact('negative-'+name,-x)
   exact('minsub-dest',Fraction(2)**(1-bias-f))
 return tuple(dict.fromkeys(out))

def initial(c):
 import vadd as v
 b=c['vlen']//8;e=c['src_eew']//8
 raw=bytearray((r*37+i*13+0x53)&255 for r in range(32) for i in range(b))
 values=c.get('qemu_inputs') or [x for _,x in inputs(c['mnemonic'],c['src_eew'],c['dst_eew'])]
 for i in range(c['src_regs']*b//e):
  word=c.get('input_word',values[i%len(values)])
  if 'exception_lane' in c and i!=c['exception_lane']:word=0
  raw[c['vs2']*b+i*e:c['vs2']*b+(i+1)*e]=word.to_bytes(e,'little')
 raw[:b]=sum(1<<i for i in range(c['vlmax']) if i%2).to_bytes(b,'little') if c['mask']=='odd' else v.mask_bytes(c)
 return bytes(raw)
def lane(c,before,i):
 b=c['vlen']//8;e=c['src_eew']//8;off=c['vs2']*b+i*e
 return element(c['mnemonic'],c['src_eew'],c['dst_eew'],int.from_bytes(before[off:off+e],'little'),c['frm'])
def expected_flags(c,before):
 flags=c['fflags_initial']
 for i in range(c['vstart'],c['vl']):
  if active(c,before,i):flags|=lane(c,before,i)[1]
 return flags
def csr_expected(c,post=False,before=None):
 import vadd as v
 rows=v.csr_expected(c,post);flags=expected_flags(c,before if before is not None else initial(c)) if post else c['fflags_initial'];rows[7:]=[flags,c['frm'],c['frm']<<5|flags];return rows

def check_isa(c,raw,rc=0,timeout=False):
 import vadd as v
 if rc or timeout:raise ValueError('execution/timeout')
 pre,post,before,after=v.decode(c,raw);x=c['operand']&0xffffffff
 if pre!=csr_expected(c)+[x] or post!=csr_expected(c,True,before)+[x]:raise ValueError('conversion CSR/exact flags/frm/scalar')
 if raw[-16:]!=struct.pack('<2Q',scalar(c),scalar(c)):raise ValueError('scalar FP preservation')
 if before!=initial(c):raise ValueError('conversion prestate')
 b=c['vlen']//8;e=c['dst_eew']//8;start=c['vd']*b;end=start+c['dst_regs']*b
 if after[:start]!=before[:start] or after[end:]!=before[end:]:raise ValueError('other register preservation')
 for i in range((end-start)//e):
  old=before[start+i*e:start+(i+1)*e];actual=after[start+i*e:start+(i+1)*e]
  if active(c,before,i):
   if actual!=lane(c,before,i)[0].to_bytes(e,'little'):raise ValueError('conversion active result '+str(i))
  else:
   agnostic=c['vstart']<c['vl'] and i>=c['vstart'] and ((i>=c['vl'] and c['ta']) or (i<c['vl'] and c['ma']))
   if actual!=old and not (agnostic and actual==b'\xff'*e):raise ValueError('conversion inactive/prestart/tail/no-body '+str(i))
 return True

def check_reference(c,raw,reference):
 import vadd as v
 _,post,before,after=v.decode(c,raw);_,rp,_,ra=v.decode(c,reference)
 if post[7:10]!=rp[7:10]:raise ValueError('independent conversion flags/frm')
 b=c['vlen']//8;e=c['dst_eew']//8
 for i in range(c['vstart'],c['vl']):
  if active(c,before,i):
   off=c['vd']*b+i*e
   if after[off:off+e]!=ra[off:off+e]:raise ValueError('independent active conversion')
 return True

def cases():
 rows=[]
 for form in FORMS:
  for w in (128,256,512,1024,2048,4096):
   for sew in (16,32,64):
    for exp in range(-2,4):
     g=geometry(form,w,sew,exp)
     if not g:continue
     n=g['vlmax'];prefix=form.replace('.','-')+f'-w{w}-e{sew}-{g["lmul"]}-'
     def add(tag,**kw):
      c=dict(g,family='fpconvert172',mnemonic=form,form='v',seed=172,vs2=16,vs1=24,vd=8,operand=0x81234567,frm=0,fflags_initial=0,vl=n,vstart=0,mask='none',ta=False,ma=False,tag=tag);c.update(kw);c['id']=prefix+tag;c['unit']=prefix+('start' if c['vstart'] else 'zero');validate(c);rows.append(c)
     # Both operand widths: actual 512-bit chunk boundaries and neighboring lanes.
     boundaries={512//g['src_eew'],512//g['dst_eew']}
     for length in sorted({0,1,n,n-1,max(1,n//2)}|{x+d for x in boundaries for d in (-1,0,1) if 0<=x+d<=n}):add('length'+str(length),vl=length)
     for mask in ('all','off','alternating','single-on','single-off'):add('mask-'+mask,vl=min(n,max(boundaries)+1),mask=mask)
     for ta,ma in ((False,True),(True,False),(True,True)):add('policy'+str(int(ta))+str(int(ma)),vl=max(1,n-1),mask='alternating',ta=ta,ma=ma)
     add('end-group',vd=32-g['dst_regs'])
     aliases=[]
     if g['dst_eew']<=g['src_eew']:aliases=[(16,16)]
     elif g['src_exp']>=0:aliases=[(8,8+g['dst_regs']-g['src_regs'])]
     for vd,vs2 in aliases:
      add('legal-overlap',vd=vd,vs2=vs2);add('legal-overlap-masked',vd=vd,vs2=vs2,mask='alternating',ta=True,ma=True)
     for start in sorted({1,n-1}|{x+d for x in boundaries for d in (-1,0,1) if 0<x+d<n}):
      if start<n:add('start'+str(start),vstart=start,mask='alternating',ta=True,ma=True)
     if n>1:
      add('no-body-zero',vl=0,vstart=1,ta=True,ma=True);partial=max(1,n//2);add('no-body-equal',vl=partial,vstart=partial,ta=True,ma=True)
     for rm in range(5):
      # Every semantic datum is a separate active one-lane case in every mode.
      for name,word in inputs(form,g['src_eew'],g['dst_eew']):add('semantic-'+name+'-rm'+str(rm),vl=1,input_word=word,frm=rm)
      add('sticky-rm'+str(rm),frm=rm,fflags_initial=10)
      for initial_flags in (16,31):add('sticky-clean-'+str(initial_flags)+'-rm'+str(rm),frm=rm,fflags_initial=initial_flags,vl=1,input_word=0)
     sk,dk=kinds(form);bad=fp.constants(g['src_eew'])['snan'] if sk=='fp' else (1<<g['src_eew'])-1
     for name,length,start,mask,lane_index in [('off',1,0,'off',0),('masked',min(n,2),0,'alternating',1),('tail',1,0,'none',1),('prestart',n,1,'none',0),('zero',0,0,'none',0),('no-body',0,1,'none',0)]:
      if start<n:add('suppress-'+name,vl=length,vstart=start,mask=mask,input_word=bad,exception_lane=lane_index,fflags_initial=9)
     values=QEMU.get(form,{}).get(str(g['src_eew']))
     if values:
      for name,mask in [('partial','none'),('even','alternating'),('odd','odd')]:add('qemu-'+name,vl=n-1 if mask=='none' else n,mask=mask,qemu_inputs=values)
 assert len(rows)==len({c['id'] for c in rows})
 return rows
