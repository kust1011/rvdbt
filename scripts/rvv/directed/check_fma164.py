#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent closed-form role/sign checks and FP157 compatibility samples."""
from fractions import Fraction
import hashlib,json,subprocess,sys,types
from pathlib import Path
import fma164 as f
import fp157 as fp
import vadd as v
from prepare_fp157 import synthetic

def run(out):
    original=types.ModuleType('original_fp157')
    exec(subprocess.check_output(['git','show','725a7ab:scripts/rvv/directed/fp157.py']).decode(),original.__dict__)
    role_answers={'vfmacc':Fraction(13,2),'vfnmacc':Fraction(-13,2),
                  'vfmsac':Fraction(11,2),'vfnmsac':Fraction(-11,2),
                  'vfmadd':Fraction(7,2),'vfnmadd':Fraction(-7,2),
                  'vfmsub':Fraction(-1,2),'vfnmsub':Fraction(1,2)}
    rows=[]
    for c in f.cases():
        if c['vlen']!=128 or c['lmul']!='m1' or c['tag']!='fp-destructive-role':continue
        expected=fp.rounded(c['sew'],role_answers[c['mnemonic']],c['frm'])
        assert f.lane(c,f.initial(c),0)==expected
        rows.append(dict(case=c['id'],closed_form=str(role_answers[c['mnemonic']]),expected=list(expected)))
    before=original.cases();after=fp.cases();assert before==after
    samples={}
    for c in before:
        samples.setdefault((c['mnemonic'],c['form'],c['sew'],c['frm'],bool(c['vstart'])),c)
    for i,c in enumerate(samples.values()):
        c=dict(c,ordinal=i);assert original.initial(c)==fp.initial(c)
        assert original.target(c)==fp.target(c) and original.instruction(c)==fp.instruction(c)
        for lane in range(min(c['vlmax'],4)):
            assert original.lane(c,original.initial(c),lane)==fp.lane(c,fp.initial(c),lane)
        packet=synthetic(c);original.check_isa(c,packet);fp.check_isa(c,packet)
    out.write_text(json.dumps(dict(closed_form_role_checks=len(rows),roles=rows,fp157_unchanged_declaration_cases=len(before),fp157_compatibility_samples=len(samples),guest_executions=0),indent=2)+'\n')
    print(len(rows),'role checks;',len(samples),'FP157 samples; no guest execution')
if __name__=='__main__':run(Path(sys.argv[1]))
