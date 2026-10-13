#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""RVV1.0 scaling/multiply/narrowing predicates; executed Spike/Sail required.

Unbounded integer intermediates implement the spec rounding bit predicates.
The DUT is never consulted by generation or expected-state calculation.
"""
import saturation153 as s
FUNCT6={'vssrl':42,'vssra':43,'vsmul':39,'vnclipu':46,'vnclip':47}

def rounded(value,d,rm):
    if d==0:return value
    discarded=value&((1<<d)-1);half=1<<(d-1);retained=(value>>d)&1
    inc=[bool(discarded&half),bool(discarded&half) and (bool(discarded&(half-1)) or bool(retained)),False,bool(discarded) and not retained][rm]
    return (value>>d)+int(inc)

def result(c,a,z):
    e=c['sew'];op=c['mnemonic'];rm=c['vxrm_initial'];mask=(1<<e)-1
    if op=='vsmul':
        value=rounded(s.signed(a,e)*s.signed(z,e),e-1,rm);lo,hi=-(1<<(e-1)),(1<<(e-1))-1
    elif op.startswith('vnclip'):
        value=rounded(a&((1<<(2*e))-1) if op=='vnclipu' else s.signed(a,2*e),z&(2*e-1),rm)
        lo,hi=(0,mask) if op=='vnclipu' else (-(1<<(e-1)),(1<<(e-1))-1)
    else:
        value=rounded(a&mask if op=='vssrl' else s.signed(a,e),z&(e-1),rm)
        return value&mask,False
    return min(hi,max(lo,value))&mask,not lo<=value<=hi

def arithmetic(c,a,z):return result(c,a,z)[0].to_bytes(c['sew']//8,'little')

def initial(c):
    import vadd as v
    raw=bytearray(v.initial(dict(c,family='fixedpoint-baseline',seed=146)))
    b=c['vlen']//8;e=c['sew'];narrow=c['mnemonic'].startswith('vnclip');wide=2*e if narrow else e;size=wide//8;small=e//8
    lim=(1<<wide)-1;top=(1<<(e-1))-1;bottom=1<<(e-1)
    if c['mnemonic']=='vsmul':
        pairs=[(bottom,bottom),(top,top),(bottom,top),(bottom,1),(top,1),(1,bottom//2),(3,bottom//2),(-1,bottom//2),(-3,bottom//2),(0,top),(bottom,-1)]
    else:
        pairs=[(0,0),(1,1),(3,1),(5,1),(-1,1),(-3,1),(-5,1),(7,2),(11,2),(lim,wide-1),(1<<(wide-1),wide-1),(top,0),(bottom,0),(lim,wide),(lim,wide+1)]
    count=c.get('source_group_registers',c['group_registers'])*b//size
    for i in range(count):
        a,z=c.get('pair_override',pairs[i%len(pairs)])
        if 'witness' in c:
            a,z=witness_pair(c,c['witness'] if i==c.get('sat_lane',-1) else 'safe')
        raw[16*b+i*size:16*b+(i+1)*size]=(a&lim).to_bytes(size,'little')
        raw[24*b+i*small:24*b+(i+1)*small]=(z&((1<<e)-1)).to_bytes(small,'little')
    return bytes(raw)

def witness_pair(c,which):
    e=c['sew'];bottom=1<<(e-1);top=bottom-1
    if c['mnemonic']=='vsmul':return (bottom,bottom) if which=='saturating' else (0,bottom)
    unsigned=c['mnemonic']=='vnclipu';hi=(1<<e)-1 if unsigned else top
    if which=='safe':return (0,0)
    if which=='lower':return (-(bottom+1),0)
    if which=='round-overflow':return ((hi<<1)+1,1)
    return (hi+1,0)

def operands(c,before,i):
    b=c['vlen']//8;e=c['sew']//8;wide=e*2 if c['mnemonic'].startswith('vnclip') else e
    a=int.from_bytes(before[c['vs2']*b+i*wide:c['vs2']*b+(i+1)*wide],'little')
    z=int.from_bytes(before[c['vs1']*b+i*e:c['vs1']*b+(i+1)*e],'little') if c['form'] in ('vv','wv') else s.signed(c['operand'],32) if c['form'] in ('vx','wx') else c['operand']
    return a,z

def saturation(c):
    before=initial(c);sat=c['vxsat_initial']
    for i in range(c['vstart'],c['vl']):
        if c['mask']!='none' and not(before[i//8]>>(i%8)&1):continue
        sat |= result(c,*operands(c,before,i))[1]
    return int(sat)

def instruction(c):
    f=c['form'];operand=c['vs1'] if f in ('vv','wv') else 8 if f in ('vx','wx') else c['operand']&31
    return (FUNCT6[c['mnemonic']]<<26)|(int(c['mask']=='none')<<25)|(c['vs2']<<20)|(operand<<15)|({'vv':0,'vx':4,'vi':3,'wv':0,'wx':4,'wi':3}[f]<<12)|(c['vd']<<7)|0x57

def check_isa(c,raw,rc=0,timeout=False):
    import vadd as v
    if rc or timeout:raise ValueError('failed execution/timeout')
    pre,post,before,after=v.decode(c,raw);scalar=c['operand']&0xffffffff
    if pre!=v.csr_expected(c)+[scalar] or post!=v.csr_expected(c,True)+[scalar]:raise ValueError('fixed-point CSR/scalar mismatch')
    if before!=initial(c):raise ValueError('pre-register mismatch')
    b=c['vlen']//8;size=c['sew']//8;vd=c['vd']*b;end=vd+c['group_registers']*b
    if after[:vd]!=before[:vd] or after[end:]!=before[end:]:raise ValueError('non-destination changed')
    for i in range((end-vd)//size):
        off=vd+i*size;old=before[off:off+size];actual=after[off:off+size]
        active=c['vstart']<=i<c['vl'] and (c['mask']=='none' or before[i//8]>>(i%8)&1)
        agnostic=c['vstart']<c['vl'] and i>=c['vstart'] and ((i>=c['vl'] and c['ta']) or (i<c['vl'] and not active and c['ma']))
        if active:
            if actual!=arithmetic(c,*operands(c,before,i)):raise ValueError('active fixed-point lane '+str(i))
        elif actual!=old and not(agnostic and actual==b'\xff'*size):raise ValueError('preserved/agnostic lane '+str(i))
    return True

def check_reference(c,raw,reference):
    import vadd as v
    if v.decode(c,raw)[1][4:7]!=v.decode(c,reference)[1][4:7]:raise ValueError('independent reference fixed-point CSR mismatch')
    return v.check_reference(dict(c,family='fixedpoint-baseline'),raw,reference)
