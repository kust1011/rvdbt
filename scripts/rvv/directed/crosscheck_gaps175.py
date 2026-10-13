#!/usr/bin/env python3
"""Pinned Sail crosscheck and architecturally required vstart traps, zero ordinary credit."""
import json,os,struct,sys,time
from pathlib import Path
import vadd as v
import gaps175 as f
import resources164 as res

def gate():
 while True:
  snap=res.snapshot()
  own=sum(r['guest'] and any('rvv-directed-task175' in a or any(n in a for n in ('vfslide1up','vfslide1down','vfmerge','vnsrl','vnsra')) for a in r['args']) for r in snap['rows'])
  if own<8 and snap['guests']<16 and snap['free_bytes']>11*1024**3:return
  time.sleep(2)

def crosscheck(base):
 while not (base/'remaining/GUEST_COMPLETE').exists():time.sleep(2)
 out=base/'sail-crosscheck';out.mkdir();root=base/'pilot/corpus';rows=json.loads((root/'manifest.json').read_text())['cases'];records=[]
 sail=Path('/home/vick/rvv-act4-tools/bin/sail_riscv_sim');assert v.sha(sail)=='4ccc3bb600387165323f8812bf534e91740f51d1c05ebf6184afb4f6f2a9d2a9'
 units=sorted({c['unit'] for c in rows if c['vlen']==128 and not c['vstart']})
 for u in units:
  cs=[c for c in rows if c['unit']==u];d=out/u;d.mkdir();elf=d/'sail.elf';source=d/'test.S';source.write_text(v.storage.text(root/u/'test.S'))
  import subprocess
  cmd=['clang-22','--target=riscv32-unknown-elf','-march=rv32gcv','-mabi=ilp32d','-nostdlib','-static','-fuse-ld=lld','-Wl,--no-relax','-Wl,-T,'+str(root/'sail.ld'),'-DSAIL',str(source),'-o',str(elf)]
  build=subprocess.run(cmd,capture_output=True);(d/'build.stderr').write_bytes(build.stderr);assert build.returncode==0,build.stderr
  cfg=d/'config.json';v.save(cfg,dict(base=dict(xlen=32),extensions=dict(V=dict(vlen_exp=7,elen_exp=6),D=dict(supported=True))))
  gate();rec=v.execute([sail,'--rv32','--config-override',cfg,'--stop-at-pc',v.sail_stop(elf),'--inst-limit','10000000','--test-signature',d/'run/signature','--signature-granularity','4',elf],d/'run',dict(os.environ))
  raw=b''.join(int(x,16).to_bytes(4,'little') for x in (d/'run/signature').read_text().splitlines());v.storage.write(d/'run/packets.bin',raw)
  assert len(raw)==len(cs)*v.packet_size(cs[0]);reference=v.storage.verify(root/'runs'/u/'Reference/packets.bin')
  for i,c in enumerate(cs):
   n=v.packet_size(c);v.check_isa(c,raw[i*n:(i+1)*n],rec['returncode'],rec['timeout']);v.check_reference(c,raw[i*n:(i+1)*n],reference[i*n:(i+1)*n])
  records.append(dict(unit=u,cases=len(cs),elf_sha256=v.sha(elf),record=rec))
 v.save(out/'SUMMARY.json',dict(status='PASS',records=records,case_checks=sum(x['cases'] for x in records),commands=len(records),ordinary_credit=0,config='pinned Sail defaults; no vstart-success override',packet_rule='independent allowed-result predicate; no arbitrary Spike bit equality'))

if __name__=='__main__':crosscheck(Path(sys.argv[1]))
