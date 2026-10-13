#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Effective bounded controls of actual FMA packets; zero guest execution."""
import collections,gzip,hashlib,json,sys
from pathlib import Path
import fma164 as f
import fp157 as fp
import vadd as v

def run(root,out,mode="full"):
    out.mkdir(parents=True,exist_ok=False);rows=json.loads((root/'manifest.json').read_text())['cases']
    geoms=sorted({(c['vlen'],c['sew'],c['lmul']) for c in rows});rank={g:i for i,g in enumerate(geoms)}
    byunit=collections.defaultdict(list);selected=[]
    semantic=('fp-fused-cancel','fp-fused-overflow-rescue','fp-destructive-role','suppress-zero-inf','fp-prestart-exception','fp-no-body-flags')
    available={((c['vlen'],c['sew'],c['lmul']),c['frm']) for c in rows if c['tag']=='fp-fused-cancel'}
    for c in rows:
        byunit[c['unit']].append(c);g=c['vlen'],c['sew'],c['lmul']
        rm=rank[g]%5 if (g,rank[g]%5) in available else 0
        extra=c['vlen']==128 and c['lmul']==('mf2' if c['sew']==32 else 'm1') and c['tag'] in ('fp-fused-cancel','fp-fused-overflow-rescue','fp-destructive-role')
        if mode=='rounding':
            if extra:selected.append(c)
            continue
        if extra or c['frm']==0 and c['tag'] in ('length1','policy11','dest-source2','dest-source1','all-alias') or c['frm']==rm and c['tag'] in semantic:
            selected.append(c)
    records=[];allowed=[];originals=[];grouped=collections.defaultdict(list)
    for c in selected:grouped[c['unit']].append(c)
    for unit,cs in grouped.items():
        raw=v.storage.verify(root/'runs'/unit/'B'/'packets.bin');refs=v.storage.verify(root/'runs'/unit/'Reference'/'packets.bin');indices={c['id']:i for i,c in enumerate(byunit[unit])}
        for c in cs:
            size=v.packet_size(c);offset=indices[c['id']]*size;packet=raw[offset:offset+size];ref=refs[offset:offset+size]
            fp.check_isa(c,packet);fp.check_reference(c,packet,ref)
            b,e=c['vlen']//8,c['sew']//8;before=v.decode(c,packet)[2]
            originals.append(dict(case=c['id'],unit=unit,offset=offset,bytes=size,packet_sha256=hashlib.sha256(packet).hexdigest(),reference_sha256=hashlib.sha256(ref).hexdigest(),geometry=[c['vlen'],c['sew'],c['lmul']],frm=c['frm']))
            def reject(label,bad,predicate='ISA'):
                assert bad!=packet,(c['id'],label)
                try:fp.check_isa(c,bad) if predicate=='ISA' else fp.check_reference(c,bad,ref)
                except ValueError as ex:records.append(dict(case=c['id'],control=label,predicate=predicate,rejected=True,error=str(ex),mutation_sha256=hashlib.sha256(bad).hexdigest()))
                else:raise ValueError('accepted effective FMA mutation '+c['id']+' '+label)
            def flip(label,pos,predicate='ISA'):
                bad=bytearray(packet);bad[pos]^=1;reject(label,bad,predicate)
            for base in (8,52):
                for j in range(11):flip('CSR-scalar-'+str(base)+'-'+str(j),base+4*j)
            for name,pos in [('fs0-pre',size-16),('fs0-post',size-8),('captured-source',96+c['vs2']*b),('captured-old-dest',96+c['vd']*b)]:flip(name,pos)
            other=next(r for r in range(1,32) if not c['vd']<=r<c['vd']+c['group_registers'])
            flip('other-register',96+32*b+other*b)
            active=[i for i in range(c['vstart'],c['vl']) if fp.active(c,before,i)]
            if active:
                pos=96+32*b+c['vd']*b+active[0]*e
                flip('active-low',pos);flip('active-high',pos+e-1)
                flip('independent-active',pos,'reference');flip('independent-fflags',80,'reference')
            inactive=[i for i in range(c['group_registers']*b//e) if not fp.active(c,before,i)]
            preserved=[i for i in inactive if i<c['vstart'] or c['vstart']>=c['vl'] or (i>=c['vl'] and not c['ta']) or (i<c['vl'] and not c['ma'])]
            if preserved:flip('preservation',96+32*b+c['vd']*b+preserved[0]*e)
            if c['tag'].startswith('fp-fused-'):
                word,flags=f.nonfused(c,before,0);assert (word,flags)!=f.lane(c,before,0)
                bad=bytearray(packet);pos=96+32*b+c['vd']*b;bad[pos:pos+e]=word.to_bytes(e,'little')
                bad[80:84]=(flags|c['fflags_initial']).to_bytes(4,'little');bad[88:92]=((c['frm']<<5)|flags|c['fflags_initial']).to_bytes(4,'little')
                reject('nonfused-two-roundings',bad);reject('nonfused-two-roundings',bad,'reference')
            if c['tag']=='fp-destructive-role':
                swapped=dict(c,mnemonic={'vfmacc':'vfmadd','vfnmacc':'vfnmadd','vfmsac':'vfmsub','vfnmsac':'vfnmsub','vfmadd':'vfmacc','vfnmadd':'vfnmacc','vfmsub':'vfmsac','vfnmsub':'vfnmsac'}[c['mnemonic']])
                word,_=f.lane(swapped,before,0);assert word!=f.lane(c,before,0)[0]
                bad=bytearray(packet);pos=96+32*b+c['vd']*b;bad[pos:pos+e]=word.to_bytes(e,'little')
                reject('wrong-destructive-role',bad);reject('wrong-destructive-role',bad,'reference')
                a,z,d=f.operands(c,before,0);sign=1 << (c['sew']-1)
                for name,args in [('wrong-product-sign',(a^sign,z,d)),('wrong-addend-sign',(a,z,d^sign))]:
                    word,_=f.fused(c['sew'],*args,c['frm']);bad=bytearray(packet);bad[pos:pos+e]=word.to_bytes(e,'little')
                    reject(name,bad);reject(name,bad,'reference')
            if c['tag']=='policy11':
                bad=bytearray(packet)
                for i in inactive:
                    if i>=c['vstart']:
                        pos=96+32*b+c['vd']*b+i*e;old=before[c['vd']*b+i*e:c['vd']*b+(i+1)*e]
                        bad[pos:pos+e]=old if packet[pos:pos+e]==b'\xff'*e else b'\xff'*e
                assert bad!=packet;fp.check_isa(c,bad);fp.check_reference(c,bad,ref)
                allowed.append(dict(case=c['id'],control='effective-agnostic-old-or-ones',accepted=True,mutation_sha256=hashlib.sha256(bad).hexdigest()))
    for name,value in [('records',records),('allowed',allowed),('selected',originals)]:
        with gzip.open(out/(name+'.json.gz'),'wt') as stream:json.dump(value,stream,separators=(',',':'))
    if mode=='rounding':geoms=sorted({(c['vlen'],c['sew'],c['lmul']) for c in selected})
    forms={c['mnemonic']+'.'+c['form'] for c in rows}
    assert {(c['mnemonic']+'.'+c['form'],c['vlen'],c['sew'],c['lmul']) for c in selected}=={(form,*g) for form in forms for g in geoms}
    summary=dict(actual_packets=len(selected),rejected=len(records),allowed=len(allowed),geometries=len(geoms),forms=sorted(forms),rounding_modes=sorted({c['frm'] for c in selected}),guest_reruns=0,by_control=dict(collections.Counter(r['control'] for r in records)))
    v.save(out/'summary.json',summary);print(json.dumps(summary))
if __name__=='__main__':run(Path(sys.argv[1]),Path(sys.argv[2]),sys.argv[3] if len(sys.argv)>3 else 'full')
