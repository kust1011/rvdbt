#!/usr/bin/env python3
"""Guest scalar pressure across actual standalone and consecutive FMA frames."""
import json,os,struct,subprocess,sys
from pathlib import Path
import vadd as v

def run(out):
 out.mkdir(parents=True,exist_ok=False)
 flags=json.loads(Path('/home/vick/rvv-directed-task164/pilot/FLAGS.json').read_text())
 engine=Path('/home/vick/rvdbt-host512-task167-build/build/bin/elfrun')
 assert v.sha(engine)=='da4dec6bfc5e28c0574dd659d0c84762e6b1b9e3b07cd7571cce0f73b835bb96'
 results=[]
 # Every allocatable guest scalar is dirty before the frame and read after it.
 regs=[r for r in range(1,32) if r not in (2,3,4)]
 for bits in (32,64):
  for scalar in (False,True):
   for consecutive in (False,True):
    unit=f'e{bits}-vf{int(scalar)}-run{int(consecutive)}';d=out/unit;d.mkdir()
    ops=['vfmacc','vfmsac','vfnmsac','vfnmacc'] if consecutive else ['vfmacc']
    src=['.option norvc','.text','.globl _start','_start:',f'vsetvli t0,zero,e{bits},m1,tu,mu','la t0,data','vl1re8.v v8,(t0)','vl1re8.v v16,(t0)','vl1re8.v v24,(t0)','la t0,fp','fld fs0,0(t0)']
    src += [f'li x{r},{0x12340000+r*0x101}' for r in regs]
    src += [(f'{op}.vf v8,fs0,v16' if scalar else f'{op}.vv v8,v24,v16') for op in ops]
    src += ['addi sp,sp,-128']+[f'sw x{r},{i*4}(sp)' for i,r in enumerate(regs)]
    src += ['li a0,1','mv a1,sp',f'li a2,{len(regs)*4}','li a7,64','ecall','li a0,0','li a7,93','ecall','.data','.balign 16','data:','.fill 16,1,0','.balign 8','fp:',('.dword 0xffffffff3f800000' if bits==32 else '.dword 0x3ff0000000000000')]
    (d/'test.S').write_text('\n'.join(src)+'\n')
    cmd=['clang-22','--target=riscv32-unknown-elf','-march=rv32gcv','-mabi=ilp32d','-nostdlib','-static','-fuse-ld=lld','-Wl,--no-relax','-Wl,-T,/home/vick/rvv-directed-task145/link.ld',str(d/'test.S'),'-o',str(d/'test.elf')]
    p=subprocess.run(cmd,capture_output=True);v.save(d/'build.json',dict(command=cmd,returncode=p.returncode));(d/'build.stderr').write_bytes(p.stderr);assert p.returncode==0
    for arm,args in flags.items():
     fs=d/arm/'fs';fs.mkdir(parents=True);(fs/'t.elf').write_bytes((d/'test.elf').read_bytes());cache=fs.parent/'cache';cache.mkdir()
     run=d/arm/'execution';env=dict(os.environ,LD_LIBRARY_PATH=str(engine.parent.parent/'lib')+':/home/vick/boost_vendor/lib')
     rec=v.execute([engine,*[('--vlen=128' if x.startswith('--vlen=') else x) for x in args],f'--fsroot={fs}',f'--cache={cache}','--','/t.elf'],run,env)
     raw=v.storage.verify(run/'stdout');assert rec['returncode']==0 and not rec['timeout'] and raw==struct.pack('<'+'I'*len(regs),*[0x12340000+r*0x101 for r in regs]),(unit,arm,rec,raw.hex())
     results.append(dict(unit=unit,arm=arm,scalar_checks=len(regs),status='PASS',stderr=v.storage.text(run/'stderr')))
 v.save(out/'RESULT.json',dict(guest_units=8,arms=4,scalar_checks=len(regs)*32,results=results,engine_sha256=v.sha(engine),admission='stderr retained; source frame closure is separate from aggregate counters'))
if __name__=='__main__':run(Path(sys.argv[1]))
