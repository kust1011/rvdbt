#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real independent packets reject state, arithmetic, oracle and storage damage."""
import argparse,json
from pathlib import Path
import vadd as v
import muldiv149 as m

def run(root,out):
    out.mkdir(parents=True,exist_ok=False)
    cs=json.loads((root/'manifest.json').read_text())['cases'];records=[]
    units={}
    for c in cs:units.setdefault(c['unit'],[]).append(c)
    def packet(c,arm='B'):
        p=root/'runs'/c['unit']/arm/'packets.bin';size=v.packet_size(c);offset=units[c['unit']].index(c)*size
        return v.storage.verify(p)[offset:offset+size],str(p),offset
    def reject(c,name,pos=None,replacement=None,rc=0,timeout=False,missing=False,refonly=False):
        raw,source,offset=packet(c);ref,_,_=packet(c,'Reference');v.check(c,raw,reference=ref);bad=bytearray(raw)
        if pos is not None:bad[pos]^=1
        if replacement is not None:p,data=replacement;bad[p:p+len(data)]=data
        if missing:bad=bad[:-1]
        path=out/f'{len(records):04d}-{name}.bin';v.storage.write(path,bad)
        try:
            if refonly:v.check_reference(c,bad,ref)
            else:v.check(c,bad,rc,timeout,ref)
        except ValueError as ex:records.append(dict(case=c['id'],control=name,rejected=True,error=str(ex),source=source,offset=offset,corrupt=path.name,logical_sha256=v.sha(path)))
        else:raise ValueError('accepted corruption '+c['id']+': '+name)
    for op,forms in m.FORMS.items():
      for form in forms:
        subset=[c for c in cs if c['mnemonic']==op and c['form']==form and c['vlen']==128 and c['lmul']=='m1' and c['sew']==16]
        c=next(c for c in subset if c['tag']=='length1');post=96+512;off=post+c['vd']*16
        for name,pos in [('active',off),('tail',off+2),('source',post+c['vs2']*16),('pre-source',96+c['vs2']*16),('scalar',92)]:reject(c,name,pos)
        for j,csr in enumerate(v.CSRS):reject(c,'post-'+csr,52+4*j)
        reject(c,'missing',missing=True);reject(c,'crash',rc=-11);reject(c,'timeout',timeout=True)
        c=next(c for c in subset if c['tag']=='mask-alternating');reject(c,'mask-preserve',post+c['vd']*16+2)
        for tag in ['start1','start-zero-vl','start-equal-partial','start-above-partial','start-partial-active']:
            c=next(c for c in subset if c['tag']==tag);reject(c,tag,post+c['vd']*16)
        # Opposite high product signedness and wrong divide/remainder semantics.
        candidates=[c for c in cs if c['mnemonic']==op and c['form']==form and c['vlen']==128 and c['lmul']=='m4' and c['sew']==64 and c['tag'].startswith('witness-')]
        mistakes={}
        for c in candidates:
            a=c['witness_a'];z=c['witness_z'];e=c['sew'];mask=(1<<e)-1
            if form=='vx':z=(z&0xffffffff)-(1<<32) if z&0x80000000 else z
            correct=v.arithmetic(c,a,z);off=post+c['vd']*16
            wrongop={'vmul':'vmulhu','vmulh':'vmulhu','vmulhu':'vmulh','vmulhsu':'vmulh','vdiv':'vdivu','vdivu':'vdiv','vrem':'vremu','vremu':'vrem'}[op]
            bad=v.arithmetic(dict(c,mnemonic=wrongop),a,z)
            if bad!=correct:mistakes.setdefault('wrong-operation-or-signedness',(c,bad))
            if op=='vmulhsu':
                bad=((a&mask)*m.signed(z&mask,e)>>e & mask).to_bytes(8,'little')
                if bad!=correct:mistakes.setdefault('swapped-mixed-signedness',(c,bad))
            if op in ['vdiv','vrem'] and z and c['tag']=='witness-negative-positive':
                q=m.signed(a&mask,e)//m.signed(z&mask,e)
                bad=((q if op=='vdiv' else m.signed(a&mask,e)-q*m.signed(z&mask,e))&mask).to_bytes(8,'little')
                if bad!=correct:mistakes.setdefault('floor-instead-of-truncation',(c,bad))
            if op in ['vdiv','vdivu','vrem','vremu'] and c['tag']=='witness-zero-divisor':
                bad=b'\0'*8
                if bad!=correct:mistakes.setdefault('wrong-zero-divisor',(c,bad))
            if op in ['vdiv','vrem'] and c['tag']=='witness-min-minus-one':
                bad=(0 if op=='vdiv' else a).to_bytes(8,'little')
                if bad!=correct:mistakes.setdefault('wrong-signed-overflow',(c,bad))
            if form=='vx' and z<0:
                bad=v.arithmetic(c,a,c['operand']&0xffffffff)
                if bad!=correct:mistakes.setdefault('scalar-zero-extension',(c,bad))
        required={'wrong-operation-or-signedness'}
        if op=='vmulhsu':required.add('swapped-mixed-signedness')
        if op in ['vdiv','vrem']:required|={'floor-instead-of-truncation','wrong-zero-divisor','wrong-signed-overflow'}
        if op in ['vdivu','vremu']:required.add('wrong-zero-divisor')
        if form=='vx':required.add('scalar-zero-extension')
        if not required<=mistakes.keys():raise ValueError('missing distinguishing controls '+op+'.'+form+str(required-mistakes.keys()))
        for name,(c,bad) in mistakes.items():
            reject(c,name,replacement=(post+c['vd']*16,bad));reject(c,name+'-reference',replacement=(post+c['vd']*16,bad),refonly=True)
    # All compressed NEW artifacts are restored and checked against logical and stored identities.
    paths=list(root.rglob('*.storage.json'));logical=stored=0
    for meta in paths:
        p=Path(str(meta).removesuffix('.storage.json'));raw=v.storage.verify(p);r=json.loads(meta.read_text());logical+=len(raw);stored+=r['stored_bytes']
    # Mutate a compressed copy; do not touch the original retained raw.
    p=root/'runs'/cs[0]['unit']/'B'/'packets.bin';raw=v.storage.verify(p)
    corrupt=out/'storage-corruption.bin';v.storage.write(corrupt,raw)
    gz=Path(str(corrupt)+'.gz');bad=bytearray(gz.read_bytes());bad[len(bad)//2]^=1;gz.write_bytes(bad)
    try:v.storage.verify(corrupt)
    except (ValueError,OSError,EOFError, __import__('zlib').error) as ex:records.append(dict(control='compressed-corruption',rejected=True,error=str(ex)))
    else:raise ValueError('compressed corruption accepted')
    v.save(out/'summary.json',dict(controls=len(records),rejected=len(records),storage_verified_files=len(paths),logical_bytes=logical,stored_bytes=stored,records=records))
    print(len(records),'controls rejected;',len(paths),'lossless artifact identities verified')
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('root',type=Path);p.add_argument('out',type=Path);a=p.parse_args();run(a.root,a.out)
