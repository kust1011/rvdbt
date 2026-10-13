#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite RVV1.0 packed-mask predicates; goldens require executed references."""
import struct
LOGIC={'vmand':25,'vmnand':29,'vmandn':24,'vmxor':27,'vmor':26,'vmnor':30,'vmorn':28,'vmxnor':31}
FORMS={**{op:('mm',) for op in LOGIC},'vcpop':('m',),'vfirst':('m',)}
FAMILY='mask158'

def cases():
    import vadd as v
    rows=[]
    for w in [128,256,512,1024,2048,4096]:
     for e in [8,16,32,64]:
      for lm,exp in v.LMUL:
       if e>64*2**exp:continue
       n=int(w/e*2**exp)
       for op in FORMS:
        unit=f'{op}-w{w}-e{e}-{lm}'
        def add(tag,**kw):
            c=dict(id=unit+'-'+tag,unit=unit+'-zero',family=FAMILY,mnemonic=op,form='mm' if op in LOGIC else 'm',vlen=w,sew=e,lmul=lm,lmul_exp=exp,emul='m1',group_registers=1,vlmax=n,vl=n,vstart=0,vd=7,vs2=17,vs1=25,rd=9,mask='none',ta=False,ma=False,operand=0x81234567,seed=158,tag=tag,source_pattern='truth',vxrm_initial=2,vxsat_initial=1,execution='NOT_RUN')
            c.update(kw)
            if c['vstart']:c['unit']=unit+'-start'
            rows.append(c)
        for vl in sorted({0,1,n,n-1,n//2}|{i for i in [7,8,9,31,32,33,63,64,65,511,512,513] if i<=n}):add('length'+str(vl),vl=vl)
        for ta,ma in [(False,False),(False,True),(True,False),(True,True)]:add(f'policy{int(ta)}{int(ma)}',vl=max(1,n-1),ta=ta,ma=ma)
        for p in ['off','all','even','odd']:add('source-'+p,source_pattern=p)
        if op in LOGIC:
            for tag,kw in [('dest-source2',dict(vd=17)),('dest-source1',dict(vd=25)),('same-sources',dict(vs1=17)),('all-alias',dict(vd=17,vs1=17)),('dest-v0',dict(vd=0)),('source2-v0',dict(vs2=0)),('source1-v0',dict(vs1=0)),('all-v0',dict(vd=0,vs2=0,vs1=0)),('end-register',dict(vd=31,vs2=30,vs1=29))]:add(tag,**kw)
            for start in sorted({1,n-1}|{i for i in [7,8,31,32,63,64,511,512,513] if i<n}):
                if 0<start<n:add('start'+str(start),vstart=start,vd=17,ta=True,ma=True)
            if n<w:add('start-equal-full',vstart=n)
            add('start-equal-partial',vstart=max(1,n//2),vl=max(1,n//2))
            add('start-above-partial',vstart=min(w-1,max(1,n//2)+1),vl=max(1,n//2))
            add('start-zero-vl',vstart=1,vl=0)
            add('start-zero-vl-maxcsr',vstart=w-1,vl=0)
            for name,base in [('vmmv',dict(mnemonic='vmand',vs1=17)),('vmclr',dict(mnemonic='vmxor',vd=17,vs1=17)),('vmset',dict(mnemonic='vmxnor',vd=17,vs1=17)),('vmnot',dict(mnemonic='vmnand',vs1=17))]:
                if base['mnemonic']==op:add('pseudo-'+name,asm_alias=name+'.m',**base)
        else:
            for mask in ['all','off','alternating','single-on','single-off']:
                add('mask-'+mask,mask=mask)
                add('source-v0-'+mask,mask=mask,vs2=0)
            for rd in [0,8,9]:add('scalar-rd'+str(rd),rd=rd)
            for bit in [0,7,8,31,32,63,64,511,512,513,n-1]:
                if bit>=n:continue
                add('hit'+str(bit),source_pattern='single',source_bit=bit)
                add('exclude'+str(bit),source_pattern='single',source_bit=bit,mask='alternating' if bit%2 else 'off')
                add('tail-hit'+str(bit),source_pattern='single',source_bit=bit,vl=bit)
        add('csr-clear',vxrm_initial=0,vxsat_initial=0)
    # Some boundary positions coincide with n-1; keep one identical declaration.
    unique={}
    for c in rows:
        if c['id'] in unique:assert unique[c['id']]==c
        unique[c['id']]=c
    return list(unique.values())

def restrictions():
    return [dict(form=op+'.m',vstart=s,vl=vl,execution='NOT_RUN',expected='illegal instruction',reason='nonzero vstart forbidden; no handler-return expansion') for op in ['vcpop','vfirst'] for s,vl in [(1,0),(1,1),(7,4)]]+[dict(form=op+'.mm',vm=0,execution='NOT_RUN',expected='reserved encoding') for op in LOGIC]

def bit(raw,reg,i,b):return raw[reg*b+i//8]>>(i%8)&1

def logic(op,a,z):
    return {'vmand':a&z,'vmnand':1^(a&z),'vmandn':a&(1^z),'vmxor':a^z,'vmor':a|z,'vmnor':1^(a|z),'vmorn':a|(1^z),'vmxnor':1^(a^z)}[op]

def initial(c):
    b=c['vlen']//8;w=c['vlen'];raw=bytearray((r*37+i*13+0x53)&255 for r in range(32) for i in range(b))
    p=c['source_pattern']
    for reg,which in [(17,0),(25,1),(30,0),(29,1)]:
        bits=sum(1<<i for i in range(w) if (i>>which)&1)
        if p!='truth':bits=sum(1<<i for i in range(w) if p=='all' or p=='even' and i%2==0 or p=='odd' and i%2==1 or p=='single' and i==c['source_bit'])
        raw[reg*b:(reg+1)*b]=bits.to_bytes(b,'little')
    m=c['mask'];boundary=min(c['vlmax']-1,512)
    bits=sum(1<<i for i in range(w) if m in ['all','none'] or m=='alternating' and i%2==0 or m=='single-on' and i==boundary or m=='single-off' and i!=boundary)
    raw[:b]=bits.to_bytes(b,'little')
    return bytes(raw)

def scalar_result(c,before):
    b=c['vlen']//8;hits=[i for i in range(c['vl']) if bit(before,c['vs2'],i,b) and (c['mask']=='none' or bit(before,0,i,b))]
    return (len(hits) if c['mnemonic']=='vcpop' else hits[0] if hits else -1)&0xffffffff

def scalar_pair(c,post=False):
    pair=[c['operand']&0xffffffff,0x6badcafe]
    if post and c['mnemonic'] not in LOGIC and c['rd']:
        pair[{8:0,9:1}[c['rd']]]=scalar_result(c,initial(c))
    return pair

def packet_size(c):return 104+64*(c['vlen']//8)

def decode(c,raw):
    if len(raw)!=packet_size(c):raise ValueError('missing/extra packet bytes')
    if struct.unpack_from('<2I',raw)!=(0x145add,c['ordinal']):raise ValueError('packet marker/order')
    b=c['vlen']//8
    return list(struct.unpack_from('<12I',raw,8)),list(struct.unpack_from('<12I',raw,56)),raw[104:104+32*b],raw[104+32*b:]

def check_isa(c,raw,rc=0,timeout=False):
    import vadd as v
    if rc or timeout:raise ValueError('failed execution/timeout')
    pre,post,before,after=decode(c,raw)
    if pre!=v.csr_expected(c)+scalar_pair(c) or post!=v.csr_expected(c,True)+scalar_pair(c,True):raise ValueError('CSR/scalar destination/preservation mismatch')
    if before!=initial(c):raise ValueError('pre-register mismatch')
    if c['mnemonic'] not in LOGIC:
        if c['vstart']:raise ValueError('forbidden scalar-mask nonzero vstart')
        if after!=before:raise ValueError('scalar mask modified vector register')
        return True
    b=c['vlen']//8;d=c['vd']*b
    if after[:d]!=before[:d] or after[d+b:]!=before[d+b:]:raise ValueError('preserved non-destination register')
    for i in range(c['vlen']):
        old=bit(before,c['vd'],i,b);got=bit(after,c['vd'],i,b)
        result=logic(c['mnemonic'],bit(before,c['vs2'],i,b),bit(before,c['vs1'],i,b))
        allowed={result} if c['vstart']<=i<c['vl'] else {old,1,result} if c['vstart']<c['vl'] and i>=c['vl'] else {old}
        if got not in allowed:raise ValueError('packed mask bit '+str(i))
    return True

def check_reference(c,raw,ref):
    after=decode(c,raw);reference=decode(c,ref)
    if after[1]!=reference[1]:raise ValueError('independent scalar/CSR mismatch')
    if c['mnemonic'] in LOGIC:
        b=c['vlen']//8
        for i in range(c['vstart'],c['vl']):
            if bit(after[3],c['vd'],i,b)!=bit(reference[3],c['vd'],i,b):raise ValueError('independent packed active bit mismatch')
    return True

def target(c):
    if c.get('asm_alias'):
        return c['asm_alias']+f' v{c["vd"]}'+('' if c['asm_alias'] in ['vmclr.m','vmset.m'] else f',v{c["vs2"]}')
    if c['mnemonic'] in LOGIC:return f'{c["mnemonic"]}.mm v{c["vd"]},v{c["vs2"]},v{c["vs1"]}'
    return f'{c["mnemonic"]}.m x{c["rd"]},v{c["vs2"]}'+(',v0.t' if c['mask']!='none' else '')

def instruction(c):
    scalar=c['mnemonic'] not in LOGIC
    return ((16 if scalar else LOGIC[c['mnemonic']])<<26)|(int(c['mask']=='none')<<25)|(c['vs2']<<20)|((16 if c['mnemonic']=='vcpop' else 17 if scalar else c['vs1'])<<15)|(2<<12)|((c['rd'] if scalar else c['vd'])<<7)|0x57

def assembly(cs):
    import vadd as v
    b=cs[0]['vlen']//8;size=packet_size(cs[0])
    lines=['.option norvc','.option norelax','.text','.globl _start','_start:','#ifdef SAIL','li t0,0x6600','csrs mstatus,t0','#endif']
    for c in cs:
        tag=c['ordinal'];lines+=['csrwi vstart,0',f'la t0,initial_{tag}']
        for r in range(32):lines += [f'vl1re8.v v{r},(t0)',f'addi t0,t0,{b}']
        lines += [f'la a3,packet_{tag}','li t0,0x145add','sw t0,0(a3)',f'li t0,{tag}','sw t0,4(a3)','addi t1,a3,104']
        for r in range(32):lines += [f'vs1r.v v{r},(t1)',f'addi t1,t1,{b}']
        lines += [f'csrwi vcsr,{c["vxrm_initial"]*2+c["vxsat_initial"]}','li t0,117','csrw fcsr,t0',f'li t0,{c["vl"]}',f'vsetvli t2,t0,e{c["sew"]},{c["lmul"]},{"ta" if c["ta"] else "tu"},{"ma" if c["ma"] else "mu"}',f'li s0,{c["operand"]&0xffffffff}','li s1,0x6badcafe',f'li t0,{c["vstart"]}','csrw vstart,t0']
        for j,csr in enumerate(v.CSRS):lines += [f'csrr t0,{csr}',f'sw t0,{8+4*j}(a3)']
        lines += ['sw s0,48(a3)','sw s1,52(a3)',f'.globl target_{tag}',f'target_{tag}:',target(c)]
        for j,csr in enumerate(v.CSRS):lines += [f'csrr t0,{csr}',f'sw t0,{56+4*j}(a3)']
        lines += ['sw s0,96(a3)','sw s1,100(a3)','csrwi vstart,0',f'li t0,{104+32*b}','add t1,a3,t0']
        for r in range(32):lines += [f'vs1r.v v{r},(t1)',f'addi t1,t1,{b}']
    lines += ['#ifdef SAIL','la t0,tohost','li t1,1','sw t1,0(t0)','1: j 1b','#else','li a0,1','la a1,begin_signature',f'li a2,{size*len(cs)}','li a7,64','ecall',f'li t0,{size*len(cs)}','bne a0,t0,write_failed','li a0,0','li a7,93','ecall','write_failed:','li a0,99','li a7,93','ecall','#endif','.data','.balign 16']
    for c in cs:lines += [f'initial_{c["ordinal"]}:','.byte '+','.join(map(str,initial(c)))]
    lines += ['.balign 16','.globl begin_signature,end_signature','begin_signature:']
    for c in cs:lines += [f'packet_{c["ordinal"]}:',f'.zero {size}']
    return '\n'.join(lines+['end_signature:','.balign 64','.globl tohost,fromhost','tohost: .dword 0','fromhost: .dword 0'])+'\n'

def install(v):
    original=v.manifest_cases
    v.manifest_cases=lambda family:cases() if family==FAMILY else original(family)
    for name in ['initial','packet_size','decode','check_isa','check_reference','assembly']:
        setattr(v,name,globals()[name])
