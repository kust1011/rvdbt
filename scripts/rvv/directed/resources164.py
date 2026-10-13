#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Shared-host capacity and occupancy receipts. No global setting changes."""
import json,os,shutil,sys,time
from pathlib import Path

def snapshot():
    rows=[]
    for p in Path('/proc').iterdir():
        if not p.name.isdecimal():continue
        try:
            args=(p/'cmdline').read_bytes().split(b'\0');args=[a.decode(errors='replace') for a in args if a]
            if not args:continue
            exe=Path(args[0]).name
            guest=exe in ('elfrun','spike','sail_riscv_sim')
            offline=exe.startswith('python') and len(args)>1 and ('audit' in Path(args[1]).name or 'controls_' in Path(args[1]).name) and 'audit_parallel' not in Path(args[1]).name
            owner=exe in ('bash','python3','python') and any('rvv-task163' in a for a in args[1:3])
            if guest or offline or owner:
                status=(p/'status').read_text();stat=(p/'stat').read_text().split(') ')[1].split()
                rows.append(dict(pid=int(p.name),ppid=int(stat[1]),nice=int(stat[16]),guest=guest,offline=offline,task163_owner=owner,args=args,affinity=[s for s in status.splitlines() if s.startswith('Cpus_allowed_list:')][0]))
        except (FileNotFoundError,PermissionError,ProcessLookupError):pass
    return dict(time=time.time(),free_bytes=shutil.disk_usage('/home/vick').free,memory_available_kib=int(Path('/proc/meminfo').read_text().split('MemAvailable:')[1].split()[0]),guests=sum(r['guest'] for r in rows),offline=sum(r['offline'] for r in rows),rows=rows)

if __name__=='__main__':
    if sys.argv[1]=='gate':
        mode=sys.argv[2];out=Path(sys.argv[3]);s=snapshot();out.write_text(json.dumps(s,indent=2)+'\n')
        # Reserve Task163's whole offline pool while its controller is alive.
        busy=s['offline']>0 or any(r['task163_owner'] for r in s['rows'])
        raise SystemExit(busy if mode=='offline' else s['guests']>8)
    out=Path(sys.argv[1]);pid=int(sys.argv[2]);out.mkdir(parents=True,exist_ok=True)
    with (out/'RESOURCE_SAMPLES.jsonl').open('a') as stream:
        while True:
            s=snapshot();stream.write(json.dumps(s,separators=(',',':'))+'\n');stream.flush()
            if not Path('/proc',str(pid)).exists():break
            time.sleep(10)
