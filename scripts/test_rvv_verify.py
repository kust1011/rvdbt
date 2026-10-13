#!/usr/bin/env python3
"""Exercise output rejection using one real accepted reference packet."""
import argparse, importlib.util, json, sys
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--checkout',type=Path,required=True);p.add_argument('--raw',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
if a.output.exists():raise ValueError('output already exists')
sys.path.insert(0,str(a.checkout/'scripts'));sys.path.insert(0,str(a.checkout/'scripts/rvv/directed'))
import rvv_verify as entry
import vadd as v
unit='w128-e32-m1-vv-zero';m=json.loads((a.raw/'manifest.json').read_text());group=[c for c in m['cases'] if c['unit']==unit];ref=v.storage.verify(a.raw/'runs'/unit/'Reference/packets.bin');ok=dict(returncode=0,timeout=False)
assert len(entry.validate_packets(v,group,ref,ref,ok))==17
checks=[]
corrupt=bytearray(ref);corrupt[8]^=1
for label,out,rec in [('missing-output',b'',ok),('truncated-output',ref[:-1],ok),('nonzero-exit',ref,dict(returncode=1,timeout=False)),('timeout',ref,dict(returncode=0,timeout=True)),('corrupted-CSR',bytes(corrupt),ok)]:
 try:entry.validate_packets(v,group,out,ref,rec)
 except (ValueError,AssertionError) as ex:checks.append(dict(control=label,result='REJECTED',reason=str(ex)))
 else:raise AssertionError('accepted '+label)
a.output.write_text(json.dumps(dict(status='PASS',positive_checks=17,rejections=checks),indent=2)+'\n');print('17 accepted reference packets; five invalid outputs rejected')
