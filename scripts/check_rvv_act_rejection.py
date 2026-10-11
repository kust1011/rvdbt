# SPDX-License-Identifier: Apache-2.0
"""Deliberately wrong raw-result controls, independent of transport hashes."""
import argparse
import json
from pathlib import Path
from verify_rvv_act_inspection import original_predicates, validate_receipt


def controls(root):
    accepted, sail=original_predicates((root/'records/audit.py').read_text())
    case='Vx8-vaadd.vv-00'
    d=root/'records/cases'/case/'raw/DUT-B'
    result=json.loads((d/'result.json').read_text())
    text=(d/'stdout').read_text()+(d/'stderr').read_text()
    validate_receipt(accepted,result,text,case)
    summary=f'RVCP-SUMMARY: TEST PASSED - Test File "{case}.S"'
    tests=[('wrong-result-exit0',result,text.replace(summary,summary.replace('TEST PASSED','TEST FAILED'))),
           ('failure-alongside-pass',result,text+'\nTEST FAILED\n'),
           ('duplicate-pass',result,text+'\n'+summary),
           ('nonzero-exit',dict(result,returncode=1),text),
           ('wrong-case',result,text.replace(case,'deliberately-wrong-case'))]
    rejected=[]
    for label,r,raw in tests:
        try:validate_receipt(accepted,r,raw,case)
        except ValueError as e:
            assert 'original predicate rejected' in str(e);rejected.append(label)
        else:raise AssertionError('bad result accepted: '+label)
    d=root/'records/cases'/case/'raw/sail-signature'
    result=json.loads((d/'result.json').read_text());text=(d/'stdout').read_text()+(d/'stderr').read_text()
    validate_receipt(sail,result,text,case)
    try:validate_receipt(sail,result,text+'\nFAILED\n',case)
    except ValueError:rejected.append('sail-failure-alongside-success')
    else:raise AssertionError('bad Sail result accepted')
    return dict(status='PASS',rejected=rejected,hash_verification_invoked=False,
                archived_files_modified=0,new_ISA_executions=0,
                method='Original pure audit predicates applied to deliberately altered in-memory raw result; no hash gate can cause rejection.')


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('root',type=Path);a=ap.parse_args()
    print(json.dumps(controls(a.root),indent=2))
