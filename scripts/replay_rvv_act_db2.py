# SPDX-License-Identifier: Apache-2.0
"""Export one frozen Task109 case's commands to configurable roots; no guest runs."""
import argparse
import json
from pathlib import Path
import shlex
import shutil


def main():
    if not __debug__:
        raise RuntimeError('remove optimized Python')
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('package',type=Path);ap.add_argument('--case',required=True)
    ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--sail',type=Path,required=True);ap.add_argument('--qemu',type=Path,required=True)
    ap.add_argument('--stage',type=Path,required=True);ap.add_argument('--clang',default='clang-22')
    a=ap.parse_args();root=a.package.resolve();out=a.output.resolve()
    cases=json.loads((root/'CASES.json').read_text()); c=next((c for c in cases if c['case']==a.case),None)
    if c is None: raise ValueError('unknown Task109 case; Task104 join must use its own runner')
    out.mkdir(parents=True,exist_ok=False);shutil.copyfile(root/c['source'],out/(a.case+'.S'))
    for n in ('fs','cache','raw'): (out/n).mkdir()
    old='/home/vick/rvv-task109';base=old+'/cases/'+a.case
    mapping=[(base,str(out)),(old+'/common',str(root/'records/common')),
             (old+'/producer',str(root/'records/producer')),
             ('/home/vick/rvv-act4-tools/bin/sail_riscv_sim',str(a.sail.resolve())),
             ('/home/vick/rvv_qemu_compare_20260930/bin/qemu-riscv32',str(a.qemu.resolve())),
             ('/home/vick/ara-clean961-stage',str(a.stage.resolve())),('/usr/bin/clang-22',a.clang)]
    labels=['compile-reference','sail-signature','compile-user','qemu-selfcheck']
    r=json.loads((root/c['result']).read_text());labels += ['DUT-'+d['arm'] for d in r['DUT']]
    pins=json.loads((root/'records/LAUNCH_REGISTRATION.json').read_text())['pins']
    toolpins={str(a.sail.resolve()):pins['/home/vick/rvv-act4-tools/bin/sail_riscv_sim'],str(a.qemu.resolve()):pins['/home/vick/rvv_qemu_compare_20260930/bin/qemu-riscv32'],str(a.stage.resolve()/'elfrun'):pins['/home/vick/ara-clean961-stage/elfrun'],str(a.stage.resolve()/'libdbtjitshared.so'):pins['/home/vick/ara-clean961-stage/libdbtjitshared.so']}
    code='import hashlib; from pathlib import Path; pins='+repr(toolpins)+'; bad=[p for p,h in pins.items() if hashlib.sha256(Path(p).read_bytes()).hexdigest()!=h]; raise SystemExit("tool identity changed: "+repr(bad) if bad else 0)'
    pin_check=code
    commands=[];shell=['#!/bin/sh','set -eu', 'cd '+shlex.quote(str(out)),
        'export LD_LIBRARY_PATH='+shlex.quote(str(a.stage.resolve()))+':${LD_LIBRARY_PATH:-}',
        '# Task110 export, NOT the historical runner. Verify tool pins before replay.',
        '# This script executes guests only when the reader explicitly invokes it.']
    shell.append('python3 -c '+shlex.quote(pin_check))
    for label in labels:
        cmd=json.loads((root/c['raw']/label/'command.json').read_text())
        changed=[]
        for arg in cmd:
            for src,dst in mapping:arg=arg.replace(src,dst)
            if arg.startswith('--fsroot='):arg='--fsroot='+str(out/'fs')
            if arg.startswith('--cache='):arg='--cache='+str(out/'cache')
            changed.append(arg)
        if any(old+'/' in x for x in changed):raise ValueError('unmapped historical path')
        raw=out/'raw'/label;raw.mkdir()
        if label.startswith('DUT-'):
            # Isolated cache and FS for each arm, as in the archived runner.
            fs=out/('fs-'+label);cache=out/('cache-'+label);fs.mkdir();cache.mkdir()
            changed=['--fsroot='+str(fs) if x.startswith('--fsroot=') else '--cache='+str(cache) if x.startswith('--cache=') else x for x in changed]
            shell.append('cp '+shlex.quote(str(out/(a.case+'.elf')))+' '+shlex.quote(str(fs/'t.elf')))
        commands.append(dict(label=label,command=changed))
        shell.append('rc=0; timeout 300 '+shlex.join(changed)+' >'+shlex.quote(str(raw/'stdout'))+' 2>'+shlex.quote(str(raw/'stderr'))+' || rc=$?')
        code='import json,sys; from pathlib import Path; rc=int(sys.argv[1]); Path('+repr(str(raw/'result.json'))+').write_text(json.dumps(dict(returncode=rc,timeout=rc==124))+"\n"); raise SystemExit(rc)'
        shell.append('python3 -c '+shlex.quote(code)+' "$rc"')
        if label=='sail-signature':
            predicate='from pathlib import Path; p=Path('+repr(str(raw))+'); t=(p/"stdout").read_text(errors="replace")+(p/"stderr").read_text(errors="replace"); raise SystemExit(0 if "SUCCESS" in t and '+repr('TEST SIGRUN - Test File "'+a.case+'.S"')+' in t and "FAILED" not in t else 1)'
            shell.append('python3 -c '+shlex.quote(predicate))
            code='import importlib.util; from pathlib import Path; s=importlib.util.spec_from_file_location("original",'+repr(str(root/'records/producer/framework/src/act/sig_modify.py'))+'); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); m.process_signature_file(Path('+repr(str(out/(a.case+'.sig')))+'),32)'
            shell.append('python3 -c '+shlex.quote(code))
            shell.append('cmp '+shlex.quote(str(out/(a.case+'.results')))+' '+shlex.quote(str(root/c['expected'])))
        if label=='qemu-selfcheck' or label.startswith('DUT-'):
            # A zero exit without the original summary must fail replay as well.
            code='from pathlib import Path; p=Path('+repr(str(raw))+'); t=(p/"stdout").read_text(errors="replace")+(p/"stderr").read_text(errors="replace"); s='+repr('RVCP-SUMMARY: TEST PASSED - Test File "'+a.case+'.S"')+'; raise SystemExit(0 if t.count(s)==1 and "TEST FAILED" not in t else 1)'
            shell.append('python3 -c '+shlex.quote(code))
    (out/'COMMANDS.json').write_text(json.dumps(commands,indent=2)+'\n')
    (out/'replay.sh').write_text('\n'.join(shell)+'\n')
    print(json.dumps(dict(case=a.case,status='EXPORTED_ONLY',commands=len(commands),script=str(out/'replay.sh'),new_guest_calls=0,blocked=c['status']!='PASS'),indent=2))

if __name__=='__main__':main()
