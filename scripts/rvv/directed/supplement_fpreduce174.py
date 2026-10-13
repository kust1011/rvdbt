#!/usr/bin/env python3
"""Pinned Sail crosscheck and architecturally required vstart traps, zero ordinary credit."""
import json,os,struct,sys,time
from pathlib import Path
import vadd as v
import fpreduce174 as f
import resources164 as res

def gate():
 while True:
  snap=res.snapshot()
  own=sum(r['guest'] and any('rvv-directed-task174' in a for a in r['args']) for r in snap['rows'])
  if own<8 and snap['guests']<16 and snap['free_bytes']>11*1024**3:return
  time.sleep(2)

def crosscheck(base):
 out=base/'sail-crosscheck';out.mkdir();root=base/'pilot/corpus';rows=json.loads((root/'manifest.json').read_text())['cases'];records=[]
 sail=Path('/home/vick/rvv-act4-tools/bin/sail_riscv_sim');assert v.sha(sail)=='4ccc3bb600387165323f8812bf534e91740f51d1c05ebf6184afb4f6f2a9d2a9'
 units=sorted({c['unit'] for c in rows if c['vlen']==128 and c['sew']==32})
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

def traps(base):
 out=base/'nonzero-vstart';out.mkdir();engine=Path('/home/vick/rvdbt-host512-task174-build/build/bin/elfrun');sail=Path('/home/vick/rvv-act4-tools/bin/sail_riscv_sim');spike=Path('/home/vick/rvv-directed-task145/deps/spike');pk=Path('/home/vick/rvv-directed-task145/deps/pk');flags=json.loads((base/'FLAGS.json').read_text());records=[]
 assert v.sha(engine)==v.FPREDUCE174_PIN
 for form in f.FORMS:
  for vl in (0,1):
   d=out/(form.replace('.','-')+'-vl'+str(vl));d.mkdir();target=form+' v8,v16,v24';src=d/'test.S';link=d/'user.ld';link.write_text(Path('/home/vick/rvv-directed-task145/link.ld').read_text());sl=d/'sail.ld';sl.write_text(link.read_text().replace('0x10000','0x80000000'))
   # Trap handler captures mcause, mtval, mepc and vstart. Normal completion
   # leaves the 32-byte signature zero; only an actual illegal trap sets magic.
   asm=f'''.option norvc
.option norelax
.text
.globl _start
_start:
#ifdef SAIL
li t0,0x6600
csrs mstatus,t0
la t0,trap_handler
csrw mtvec,t0
#endif
li t0,{vl}
vsetvli t1,t0,e32,mf2,tu,mu
csrwi vstart,1
.globl target
target:
{target}
#ifdef SAIL
j finish
trap_handler:
la t0,begin_signature
li t1,0x174bad
sw t1,0(t0)
csrr t1,mcause
sw t1,4(t0)
csrr t1,mtval
sw t1,8(t0)
csrr t1,mepc
sw t1,12(t0)
csrr t1,vstart
sw t1,16(t0)
finish:
la t0,tohost
li t1,1
sw t1,0(t0)
1: j 1b
#else
li a0,1
la a1,begin_signature
li a2,32
li a7,64
ecall
li a0,0
li a7,93
ecall
#endif
.data
.balign 16
.globl begin_signature,end_signature
begin_signature: .zero 32
end_signature:
.balign 64
.globl tohost,fromhost
tohost: .dword 0
fromhost: .dword 0
''';src.write_text(asm)
   for machine in (False,True):
    elf=d/('sail.elf' if machine else 'test.elf');cmd=['clang-22','--target=riscv32-unknown-elf','-march=rv32gcv','-mabi=ilp32d','-nostdlib','-static','-fuse-ld=lld','-Wl,--no-relax','-Wl,-T,'+str(sl if machine else link)]+(['-DSAIL'] if machine else [])+[str(src),'-o',str(elf)]
    import subprocess
    p=subprocess.run(cmd,capture_output=True);(d/('sail-build.stderr' if machine else 'build.stderr')).write_bytes(p.stderr);assert p.returncode==0,p.stderr
   cfg=d/'config.json';v.save(cfg,dict(base=dict(xlen=32),extensions=dict(V=dict(vlen_exp=7,elen_exp=6),D=dict(supported=True))))
   gate();r=v.execute([sail,'--rv32','--config-override',cfg,'--stop-at-pc',v.sail_stop(d/'sail.elf'),'--test-signature',d/'Sail/signature','--signature-granularity','4','--inst-limit','1000000',d/'sail.elf'],d/'Sail',dict(os.environ))
   raw=b''.join(int(x,16).to_bytes(4,'little') for x in (d/'Sail/signature').read_text().splitlines());sig=struct.unpack('<8I',raw);assert r['returncode']==0 and sig[0]==0x174bad and sig[1]==2,(form,vl,r,sig)
   record=dict(form=form,vl=vl,vstart=1,Sail=dict(signature=list(sig),record=r),DUT={})
   for arm in ('B','M1','M2','BOTH'):
    ad=d/arm;fs=ad/'fs';fs.mkdir(parents=True);(fs/'t.elf').write_bytes((d/'test.elf').read_bytes());cache=ad/'cache';cache.mkdir();env=dict(os.environ,LD_LIBRARY_PATH=str(engine.parent.parent/'lib')+':/home/vick/boost_vendor/lib')
    gate();r=v.execute([engine,*[('--vlen=128' if x.startswith('--vlen=') else x) for x in flags[arm]],'--dump-tbmap='+str(ad/'run/tbmap'),'--fsroot='+str(fs),'--cache='+str(cache),'--','/t.elf'],ad/'run',env)
    stderr=v.storage.read(ad/'run/stderr').decode(errors='replace');stdout=v.storage.read(ad/'run/stdout')
    # Require the engine's specific RVV invalid-vstart diagnostic, not just
    # a generic failing process. Preserve stdout/stderr and original rc.
    assert r['returncode']!=0 and not r['timeout'] and not stdout and 'ILLEGAL_INSN' in stderr,(form,vl,arm,r,stderr[-1000:])
    record['DUT'][arm]=dict(record=r,stderr_tail=stderr[-1500:])
   records.append(record)
 v.save(out/'SUMMARY.json',dict(status='PASS',records=records,ordinary_credit=0,scope='six forms VLEN128 SEW32 mf2, vstart1, VL0/1; illegal-trap classification, not a successful reduction',config='Sail defaults; never disable zero_required'))
if __name__=='__main__':
 base=Path(sys.argv[1]);crosscheck(base);traps(base)
