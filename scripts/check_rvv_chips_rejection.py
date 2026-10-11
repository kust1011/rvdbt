#!/usr/bin/env python3
"""Exercise retained parser and rehashed bad-result rejection on a disposable extraction."""
import argparse
import csv
import json
from pathlib import Path
import subprocess
import sys
from verify_rvv_chips_inspection import digest,producer


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('root',type=Path);ap.add_argument('output',type=Path);a=ap.parse_args();root=a.root.resolve();out=a.output;out.mkdir(parents=True,exist_ok=True)
    nav=next(n for n in csv.DictReader((root/'NAVIGATION.csv').open()) if n['candidate']=='clean961' and n['control']=='False')
    directory=root/nav['receipt'];stdout=directory/'stdout';result=directory/'result.json';manifest=root/'FILES.json'
    original_bytes={p:p.read_bytes() for p in (stdout,result,manifest)}
    cell=json.loads((directory/'case.json').read_text());r=json.loads(result.read_text());runner=producer(root)
    corrupt=stdout.read_bytes().replace(b'CHIPS_PASS',b'CHIPS_FAIL',1);assert corrupt!=stdout.read_bytes()
    assert runner.classify(r['returncode'],corrupt,cell)=='OUTPUT_MISMATCH'
    assert runner.classify(1,stdout.read_bytes(),cell)=='EXIT_MISMATCH'
    control=next(n for n in csv.DictReader((root/'NAVIGATION.csv').open()) if n['candidate']=='clean961' and n['control']=='True')
    control_dir=root/control['receipt'];control_case=json.loads((control_dir/'case.json').read_text());control_result=json.loads((control_dir/'result.json').read_text());control_stdout=(control_dir/'stdout').read_bytes()
    assert control_case['expected_returncode']==1 and b'CHIPS_FAIL' in control_stdout
    assert runner.classify(control_result['returncode'],control_stdout,control_case)=='PASS'
    assert runner.classify(0,control_stdout,control_case)=='EXIT_MISMATCH'
    try:
        stdout.write_bytes(corrupt);r['stdout_sha256']=digest(stdout);result.write_text(json.dumps(r,indent=2)+'\n')
        hashes=json.loads(manifest.read_text())
        for p in (stdout,result):hashes[str(p.relative_to(root))]={'sha256':digest(p),'bytes':p.stat().st_size}
        manifest.write_text(json.dumps(hashes,indent=2)+'\n')
        completed=subprocess.run([sys.executable,str(root/'tools/verify_rvv_chips_inspection.py'),str(root)],capture_output=True,text=True,env={'PYTHONDONTWRITEBYTECODE':'1'})
        (out/'HASH_INDEPENDENT_REJECTION.stdout').write_text(completed.stdout);(out/'HASH_INDEPENDENT_REJECTION.stderr').write_text(completed.stderr)
        assert completed.returncode==1 and 'original assertion/exit acceptance rejected' in completed.stderr,completed.stderr
        record={'status':'PASS','altered_receipt':nav['receipt'],'updated_hashes':['FILES.json payload stdout/result','result.json stdout_sha256'],'checker_exit':completed.returncode,'reason':completed.stderr.strip(),'producer_bad_stdout':'OUTPUT_MISMATCH','producer_nonzero_exit':'EXIT_MISMATCH','original_fail_control_accepted':True,'fail_control_exit0_rejected':True,'new_guest_executions':0}
    finally:
        for p,b in original_bytes.items():p.write_bytes(b)
        assert all(p.read_bytes()==b for p,b in original_bytes.items())
    record['disposable_extraction_restored']=True;(out/'REJECTION_CHECK.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))

if __name__=='__main__':main()
