#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Freeze a finite FMA manifest; validate encodings and closed-form witnesses."""
import collections,gzip,json,struct,subprocess,sys
from pathlib import Path
import fma164 as f
import fp157 as fp
import vadd as v
import audit
from prepare_fp157 import synthetic

def prepare(out):
    out.mkdir(parents=True,exist_ok=False);rows=f.cases();units={};encodings={}
    for i,c in enumerate(rows):
        c['ordinal']=i;units.setdefault(c['unit'],c);encodings.setdefault(f.target(c),f.instruction(c))
        assert c['sew'] in (32,64) and c['frm'] in range(5) and 0<=c['vstart']<c['vlmax']
        assert c['vd']%c['group_registers']==c['vs1']%c['group_registers']==c['vs2']%c['group_registers']==0
        assert max(c['vd'],c['vs1'],c['vs2'])+c['group_registers']<=32
    pilot=[u for u,c in units.items() if (c['vlen'],c['sew'],c['lmul']) in
           [(128,32,'mf2'),(128,64,'m1')] or
           (c['vlen'],c['sew'],c['lmul'],c['frm']) in [(1024,64,'m8',0),(4096,32,'m1',0)]]
    selected=[c for c in rows if c['unit'] in set(pilot)]
    analytical=[]
    for bits in (32,64):
        k=fp.constants(bits);frac=fp.layout(bits)[0]
        for frm in range(5):
            for name,a,b,z,expected in [
                ('exact',k['one'],k['two'],k['three'],fp.rounded(bits,5,frm)),
                ('cancellation',k['one'],k['one'],k['negone'],(k['negzero'] if frm==2 else 0,0)),
                ('fused-exact',k['nextone'],k['one']-2,k['negone'],fp.rounded(bits,-fp.Fraction(2)**(-2*frac),frm)),
                ('overflow-rescue',k['maxfinite'],k['two'],k['maxfinite']|k['negzero'],(k['maxfinite'],0)),
                ('invalid-qnan-addend',0,k['inf'],k['qnan'],(k['canonical'],16))]:
                assert f.fused(bits,a,b,z,frm)==expected
                analytical.append(dict(bits=bits,frm=frm,witness=name,expected=list(expected)))
    for c in selected:fp.check_isa(c,synthetic(c))
    source=out/'TARGET_ENCODING_CHECK.S';source.write_text('.option norvc\n.text\n'+'\n'.join(encodings)+'\n')
    obj=out/'TARGET_ENCODING_CHECK.o'
    run=subprocess.run(['clang-20','--target=riscv32-unknown-elf','-march=rv32gcv','-mabi=ilp32d','-c',str(source),'-o',str(obj)],capture_output=True)
    (out/'BUILD.stderr').write_bytes(run.stderr)
    if run.returncode:raise RuntimeError(run.stderr.decode())
    sections,_=audit.elf_sections_symbols(obj)
    assert list(struct.unpack('<'+'I'*len(encodings),sections['.text'][1]))==list(encodings.values())
    # Every form/precision/mode has effective fused-versus-two-step witnesses.
    distinguishing=[]
    for c in rows:
        if c['tag'] in ('fp-fused-cancel','fp-fused-overflow-rescue'):
            before=f.initial(c);fused=f.lane(c,before,0);two=f.nonfused(c,before,0)
            assert fused!=two
            distinguishing.append(dict(case=c['id'],fused=list(fused),nonfused=list(two)))
    with gzip.open(out/'PREPARED_MANIFEST.json.gz','wt') as stream:json.dump(rows,stream,separators=(',',':'))
    v.save(out/'PILOT_UNITS.json',pilot)
    v.save(out/'DECLARATION.json',dict(forms=[op+'.'+form for op,forms in f.FORMS.items() for form in forms],cases=len(rows),units=len(units),checks=len(rows)*5,commands=len(units)*5,ordinary=len(rows),reserved_start=0,geometries=len({(c['vlen'],c['sew'],c['lmul']) for c in rows}),rounding_modes=list(range(5)),reserved_encodings=f.reserved_declarations(),execution='NOT_RUN',guest_credit=0,per_form=dict(collections.Counter(c['mnemonic']+'.'+c['form'] for c in rows))))
    v.save(out/'LOCAL_CHECKS.json',dict(layouts=len(rows),distinct_compiled_encodings=len(encodings),synthetic_pilot_predicates=len(selected),pilot_units=len(pilot),pilot_cases=len(selected),pilot_checks=len(selected)*5,pilot_commands=len(pilot)*5,closed_form_checks=len(analytical),fused_distinguishing_witnesses=len(distinguishing),guest_credit=0))
    v.save(out/'ANALYTICAL_CHECKS.json',analytical)
    with gzip.open(out/'FUSED_DISTINGUISHING.json.gz','wt') as stream:json.dump(distinguishing,stream,separators=(',',':'))
    print(json.loads((out/'LOCAL_CHECKS.json').read_text()))
if __name__=='__main__':prepare(Path(sys.argv[1]))
