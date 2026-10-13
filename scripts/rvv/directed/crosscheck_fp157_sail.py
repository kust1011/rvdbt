#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Same capture/target body on pinned Sail for four Spike boundary units.

Reference-only crosscheck; no DUT calls and no extra family case credit.
"""
import json
from pathlib import Path
import subprocess
import sys
import os
import vadd as v

def crosscheck(root,out):
    root=root.resolve();out.mkdir(parents=True,exist_ok=False)
    sail=Path('/home/vick/rvv-act4-tools/bin/sail_riscv_sim')
    identities=json.loads((root/'identities-before.json').read_text())
    if v.sha(sail)!=identities[str(sail)]:raise ValueError('Sail reference pin changed')
    rows=json.loads((root/'manifest.json').read_text())['cases'];units={}
    for c in rows:
        if c['mnemonic']=='vfdiv' and c['frm']==3 and c['vstart']==0 and c['vlen']==128 and c['tag'].startswith('fp-'):
            units.setdefault(c['unit'],[]).append(c)
    # Include every case from each original unit, preserving source/ordinal order.
    units={u:[c for c in rows if c['unit']==u] for u in units}
    receipts=[]
    for unit,cs in units.items():
        d=out/unit;d.mkdir();source=d/'test.S';source.write_text(v.storage.text(root/unit/'test.S'))
        link=d/'sail.ld';link.write_text((root/'sail.ld').read_text());elf=d/'sail.elf'
        cmd=['clang-22','--target=riscv32-unknown-elf','-march=rv32gcv','-mabi=ilp32d','-nostdlib','-static','-fuse-ld=lld','-Wl,--no-relax','-Wl,-T,'+str(link),'-DSAIL',str(source),'-o',str(elf)]
        build=subprocess.run(cmd,capture_output=True);(d/'build.stderr').write_bytes(build.stderr)
        if build.returncode:raise ValueError(build.stderr.decode())
        config=d/'sail-config.json';v.save(config,{'base':{'xlen':32},'extensions':{'V':{'vlen_exp':7,'elen_exp':6,'vstart':{'zero_required':{'arith':False}}},'D':{'supported':True}}})
        run=d/'Reference'
        rec=v.execute([sail,'--rv32','--config-override',config,'--stop-at-pc',v.sail_stop(elf),'--inst-limit','10000000','--test-signature',run/'signature','--signature-granularity','4',elf],run,dict(os.environ))
        raw=b''.join(int(line,16).to_bytes(4,'little') for line in (run/'signature').read_text().splitlines())
        v.storage.write(run/'packets.bin',raw)
        spike=v.storage.verify(root/'runs'/unit/'Reference/packets.bin');size=v.packet_size(cs[0])
        if len(raw)!=size*len(cs):raise ValueError('Sail crosscheck extent')
        for i,c in enumerate(cs):
            packet=raw[i*size:(i+1)*size];v.check_isa(c,packet,rec['returncode'],rec['timeout']);v.check_reference(c,packet,spike[i*size:(i+1)*size])
        receipts.append(dict(unit=unit,cases=len(cs),build=cmd,elf_sha256=v.sha(elf),execution=rec,comparison='Sail active results/fflags/frm versus pinned Spike packet plus corrected rational predicates'))
    v.save(out/'summary.json',dict(units=len(units),case_checks=sum(r['cases'] for r in receipts),reference_commands=len(units),DUT_commands=0,family_case_credit=0,Sail_sha256=v.sha(sail),receipts=receipts))
    print(dict(units=len(units),checks=sum(r['cases'] for r in receipts)))

if __name__=='__main__':crosscheck(Path(sys.argv[1]),Path(sys.argv[2]))
