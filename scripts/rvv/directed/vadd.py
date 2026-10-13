#!/usr/bin/env python3

# SPDX-License-Identifier: MIT
"""Project directed vadd template; no upstream test or DUT-derived golden."""
import argparse, collections, concurrent.futures, hashlib, json, os, resource
import shutil, signal, struct, subprocess, sys, time
from pathlib import Path
CSRS = ['vl','vtype','vlenb','vstart','vxrm','vxsat','vcsr','fflags','frm','fcsr']
LMUL = [('mf8',-3),('mf4',-2),('mf2',-1),('m1',0),('m2',1),('m4',2),('m8',3)]
PIN = 'e2559c5cd930e919503c79b44af219c243041e86f5b83a157bec860814e8336b'
def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def save(p,x): Path(p).write_text(json.dumps(x,indent=2)+'\n')
def cases():
    result=[]
    for w in [128,256,512,1024,2048,4096]:
      for e in [8,16,32,64]:
       for lm,exp in LMUL:
        if e > 64 * 2**exp: continue # mandatory ELEN64 legal profile
        n=int(w/e*2**exp); chunk=512//e; regs=max(1,2**exp)
        for form in ['vv','vx','vi']:
          unit=f'w{w}-e{e}-{lm}-{form}'
          def add(tag,vl=n,mask='none',ta=False,ma=False,start=0,vd=8,s2=16,s1=24,operand=None):
            c=dict(id=unit+'-'+tag,unit=unit+('-start' if start else '-zero'),vlen=w,sew=e,lmul=lm,lmul_exp=exp,emul=lm,vlmax=n,vl=vl,mask=mask,ta=ta,ma=ma,vstart=start,vd=vd,vs2=s2,vs1=s1,operand=operand if operand is not None else (-16 if form=='vi' else 0x80000001),form=form,tag=tag,group_registers=regs,seed=145)
            result.append(c)
          for vl in sorted({0,1,n,n-1,max(1,n//2)} | {x for x in [chunk-1,chunk,chunk+1] if 0<=x<=n}): add('length'+str(vl),vl)
          for m in ['all','off','alternating','single-on','single-off']:
            add('mask-'+m,min(n,chunk+1),m)
          for ta,ma in [(False,True),(True,False),(True,True)]:
            add('policy'+str(int(ta))+str(int(ma)),max(1,n-1),'alternating',ta,ma)
          add('dest-source2',max(1,n-1),'alternating',vd=16)
          add('end-group',vd=32-regs)
          if form=='vv':
            add('dest-source1',vd=24); add('same-sources',s1=16)
          else:
            for op in ([-16,-1,0,15] if form=='vi' else [0,0x7fffffff,0x80000000,0xffffffff]): add('operand'+str(op),operand=op)
          for start in sorted({1,n-1} | {x for x in [chunk-1,chunk,chunk+1] if 0<x<n}):
            if start>0 and start<n:
              add('start'+str(start),n,'alternating',True,True,start,vd=16)
    return result

def initial(c):
    b=c['vlen']//8; e=c['sew']//8; limit=(1<<c['sew'])-1
    raw=bytearray((r*37+i*13+0x53)&255 for r in range(32) for i in range(b))
    # Full source groups: wrap, signed edge, low32 carry and distinct high64.
    patterns=[limit,limit//2,0,1,0xffffffff,0x11223344ffffffff,0x8000000000000000,0x76543210abcdef01]
    for base,offset in [(16,0),(24,3)]:
      for i in range(c['group_registers']*b//e):
        v=patterns[(i+offset)%len(patterns)]&limit
        raw[base*b+i*e:base*b+(i+1)*e]=v.to_bytes(e,'little')
    raw[:b]=mask_bytes(c)
    return bytes(raw)

def mask_bytes(c):
    n=c['vlmax']; boundary=min(n-1,512//c['sew']); m=c['mask']
    bits=sum(1<<i for i in range(n) if m in ['none','all'] or (m=='alternating' and i%2==0) or (m=='single-on' and i==boundary) or (m=='single-off' and i!=boundary))
    return bits.to_bytes(c['vlen']//8,'little')

def csr_expected(c,post=False):
    vt=(c['lmul_exp']&7)+([8,16,32,64].index(c['sew'])<<3)+(int(c['ta'])<<6)+(int(c['ma'])<<7)
    return [c['vl'],vt,c['vlen']//8,0 if post else c['vstart'],2,1,5,21,3,117]

def packet_size(c): return 8+88+64*(c['vlen']//8)

def decode(c,raw):
    if len(raw)!=packet_size(c): raise ValueError('missing/extra packet bytes')
    magic,idx=struct.unpack_from('<2I',raw)
    if magic!=0x145add or idx!=c['ordinal']: raise ValueError('packet marker/order')
    pre=list(struct.unpack_from('<11I',raw,8));post=list(struct.unpack_from('<11I',raw,52))
    b=c['vlen']//8
    return pre,post,raw[96:96+32*b],raw[96+32*b:]

def check(c,raw,rc=0,timeout=False,reference=None):
    if rc!=0 or timeout: raise ValueError('failed execution/timeout')
    pre,post,before,after=decode(c,raw)
    scalar=c['operand']&0xffffffff
    if pre!=csr_expected(c)+[scalar]: raise ValueError('pre CSR/scalar mismatch')
    if post!=csr_expected(c,True)+[scalar]: raise ValueError('post CSR/scalar mismatch')
    if before!=initial(c): raise ValueError('observed pre-register mismatch')
    b=c['vlen']//8;e=c['sew']//8;vd=c['vd']*b;end=vd+c['group_registers']*b;mask=mask_bytes(c)
    if after[:vd]!=before[:vd] or after[end:]!=before[end:]: raise ValueError('preserved non-destination register')
    for i in range((end-vd)//e):
      off=vd+i*e;old=before[off:off+e];actual=after[off:off+e]
      active=c['vstart']<=i<c['vl'] and (c['mask']=='none' or mask[i//8]>>(i%8)&1)
      agnostic=c['vl']>c['vstart'] and i>=c['vstart'] and ((i>=c['vl'] and c['ta']) or (i<c['vl'] and not active and c['ma']))
      if active:
        a=int.from_bytes(before[c['vs2']*b+i*e:c['vs2']*b+(i+1)*e],'little')
        if c['form']=='vv': z=int.from_bytes(before[c['vs1']*b+i*e:c['vs1']*b+(i+1)*e],'little')
        elif c['form']=='vi': z=c['operand']
        else: z=scalar-(1<<32) if scalar&(1<<31) else scalar
        expected=((a+z)% (1<<c['sew'])).to_bytes(e,'little')
        if actual!=expected: raise ValueError(f'active element {i}: {actual.hex()} != {expected.hex()}')
        if reference is not None:
          ref_after=decode(c,reference)[3]
          if actual!=ref_after[off:off+e]: raise ValueError('independent reference active mismatch')
      elif actual!=old and not (agnostic and actual==b'\xff'*e):
        raise ValueError(f'preserved/agnostic element {i}')
    return True

def assembly(cs):
    c=cs[0];b=c['vlen']//8;size=packet_size(c)
    lines=['.option norvc','.option norelax','.text','.globl _start','_start:', '#ifdef SAIL','li t0, 0x6600','csrs mstatus, t0','#endif']
    # This body is literally shared by user and machine ELFs. Observation stores
    # do not modify vector registers. CSR capture precedes all post vector stores.
    for c in cs:
      tag=c['ordinal'];lines += ['csrwi vstart,0',f'la t0, initial_{tag}']
      for r in range(32): lines += [f'vl1re8.v v{r}, (t0)',f'addi t0,t0,{b}']
      lines += [f'la a3, packet_{tag}','li t0,0x145add','sw t0,0(a3)',f'li t0,{tag}','sw t0,4(a3)','addi t1,a3,96']
      for r in range(32): lines += [f'vs1r.v v{r},(t1)',f'addi t1,t1,{b}']
      lines += ['csrwi vcsr,5','li t0,117','csrw fcsr,t0',f'li t0,{c["vl"]}',f'vsetvli t2,t0,e{c["sew"]},{c["lmul"]},{"ta" if c["ta"] else "tu"},{"ma" if c["ma"] else "mu"}',f'li s0,{c["operand"]&0xffffffff}',f'li t0,{c["vstart"]}','csrw vstart,t0']
      for j,csr in enumerate(CSRS): lines += [f'csrr t0,{csr}',f'sw t0,{8+4*j}(a3)']
      lines += ['sw s0,48(a3)',f'.globl target_{tag}',f'target_{tag}:']
      op=f'v{c["vs1"]}' if c['form']=='vv' else 's0' if c['form']=='vx' else str(c['operand'])
      lines += [f'vadd.{c["form"]} v{c["vd"]},v{c["vs2"]},{op}'+(',v0.t' if c['mask']!='none' else '')]
      for j,csr in enumerate(CSRS): lines += [f'csrr t0,{csr}',f'sw t0,{52+4*j}(a3)']
      lines += ['sw s0,92(a3)','csrwi vstart,0',f'li t0,{96+32*b}','add t1,a3,t0']
      for r in range(32): lines += [f'vs1r.v v{r},(t1)',f'addi t1,t1,{b}']
    lines += ['#ifdef SAIL','la t0,tohost','li t1,1','sw t1,0(t0)','1: j 1b','#else', 'li a0,1','la a1,begin_signature',f'li a2,{size*len(cs)}','li a7,64','ecall',f'li t0,{size*len(cs)}','bne a0,t0,write_failed','li a0,0','li a7,93','ecall','write_failed:','li a0,99','li a7,93','ecall','#endif','.data','.balign 16']
    for c in cs:
      lines += [f'initial_{c["ordinal"]}:','.byte '+','.join(map(str,initial(c)))]
    lines += ['.balign 16','.globl begin_signature,end_signature','begin_signature:']
    for c in cs: lines += [f'packet_{c["ordinal"]}:',f'.zero {size}']
    lines += ['end_signature:','.balign 64','.globl tohost,fromhost','tohost: .dword 0','fromhost: .dword 0']
    return '\n'.join(lines)+'\n'

def build(out,compiler,link):
    out.mkdir(parents=True,exist_ok=False);cs=cases()
    for i,c in enumerate(cs): c['ordinal']=i
    units=collections.defaultdict(list)
    for c in cs: units[c['unit']].append(c)
    save(out/'manifest.json',dict(project_tests=True,cases=cs,units=len(units),planned_case_executions=len(cs)*5,reference='fixed Spike/pk for vstart0; fixed Sail0.14.1 for nonzero vstart; independently source-reviewed ISA predicates for every packet'))
    shutil.copy2(link,out/'user.ld')
    (out/'sail.ld').write_text(Path(link).read_text().replace('0x10000','0x80000000'))
    cmds=[]
    for unit,rows in units.items():
      d=out/unit;d.mkdir();(d/'test.S').write_text(assembly(rows))
      for machine in ([False,True] if rows[0]['vstart'] else [False]):
        elf=d/('sail.elf' if machine else 'test.elf')
        cmd=[compiler,'--target=riscv32-unknown-elf','-march=rv32gcv','-mabi=ilp32d','-nostdlib','-static','-fuse-ld=lld','-Wl,--no-relax','-Wl,-T,'+str(out/('sail.ld' if machine else 'user.ld'))]+(['-DSAIL'] if machine else [])+[str(d/'test.S'),'-o',str(elf)]
        r=subprocess.run(cmd,capture_output=True);(d/('sail-build.stderr' if machine else 'build.stderr')).write_bytes(r.stderr)
        cmds.append(dict(command=cmd,returncode=r.returncode,elf_sha256=sha(elf) if r.returncode==0 else None))
        if r.returncode: raise RuntimeError(r.stderr.decode())
    save(out/'build-commands.json',cmds)
    print(f'{len(cs)} cases / {len(units)} units built',flush=True)

def sail_stop(elf):
    raw=Path(elf).read_bytes()
    shoff=struct.unpack_from('<I',raw,32)[0]
    entsize,count,names=struct.unpack_from('<3H',raw,46)
    headers=[struct.unpack_from('<10I',raw,shoff+i*entsize) for i in range(count)]
    h=headers[names];strings=raw[h[4]:h[4]+h[5]]
    for h in headers:
      if strings[h[0]:].split(b'\0',1)[0]==b'.text':
        if raw[h[4]+h[5]-4:h[4]+h[5]]!=b'\x6f\0\0\0': raise ValueError('Sail completion loop changed')
        return hex(h[3]+h[5]-4)
    raise ValueError('ELF text missing')

def execute(cmd,d,env,timeout=120):
    # Same bounded process-group capture protocol as run_rvv_external.call.
    d.mkdir(parents=True,exist_ok=False);save(d/'command.json',list(map(str,cmd)));start=time.monotonic()
    with (d/'stdout').open('wb') as o,(d/'stderr').open('wb') as e:
      process=subprocess.Popen(list(map(str,cmd)),stdout=o,stderr=e,env=env,stdin=subprocess.DEVNULL,start_new_session=True)
      try: rc=process.wait(timeout=timeout);expired=False
      except subprocess.TimeoutExpired:
        expired=True
        try: os.killpg(process.pid,signal.SIGKILL)
        except ProcessLookupError: pass
        rc=process.wait()
    rec=dict(returncode=rc,timeout=expired,seconds=time.monotonic()-start,stdout_sha256=sha(d/'stdout'),stderr_sha256=sha(d/'stderr'))
    save(d/'execution.json',rec);return rec

def run(root,engine,spike,pk,sail,flags,jobs):
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    if sha(engine)!=PIN: raise ValueError('DUT executable pin mismatch')
    if jobs not in range(1,5): raise ValueError('jobs must be 1..4')
    manifest=json.loads((root/'manifest.json').read_text());units=collections.defaultdict(list)
    for c in manifest['cases']: units[c['unit']].append(c)
    flags_path=Path(flags)
    out=root/'runs';out.mkdir(exist_ok=False);flags=json.loads(flags_path.read_text())
    paths=[engine,engine.parent.parent/'lib/libdbtjitshared.so',spike,pk,sail]
    pins={str(p):sha(p) for p in paths}
    expected=['79d0ba2a9ddea24d49d7282012fdc373b92a26756bb5452c1f41c66d533887af','cddd7a406bd92836f220e929aca0f4925542e80d0b2246b8920e6f49648a6994','30f4e5906b13264ff98a8fa36dfea848f8504a65c028e96930329668f1f564ad','4ccc3bb600387165323f8812bf534e91740f51d1c05ebf6184afb4f6f2a9d2a9']
    if [pins[str(p)] for p in paths[1:]]!=expected: raise ValueError('fixed library/reference pin mismatch')
    save(root/'identities-before.json',pins)
    start=time.monotonic()
    build_rows=json.loads((root/'build-commands.json').read_text())
    for row in build_rows:
      original=Path(row['command'][-1]);guest=root/original.parent.name/original.name
      if row['returncode']!=0 or sha(guest)!=row['elf_sha256']: raise ValueError('guest build identity mismatch')
    save(root/'runner-identity.json',{'runner_sha256':sha(__file__),'manifest_sha256':sha(root/'manifest.json'),'flags_sha256':sha(flags_path)})
    def worker(item):
      unit,cs=item;w=cs[0]['vlen'];results=[];reference=None
      for arm in ['Reference','B','M1','M2','BOTH']:
        d=out/unit/arm;env=dict(os.environ)
        if arm=='Reference':
          if cs[0]['vstart']:
            config=root/unit/'sail-config.json';save(config,{'base':{'xlen':32},'extensions':{'V':{'vlen_exp':w.bit_length()-1,'elen_exp':6,'vstart':{'zero_required':{'arith':False}}},'D':{'supported':True}}})
            cmd=[sail,'--rv32','--config-override',config,'--stop-at-pc',sail_stop(root/unit/'sail.elf'),'--inst-limit','10000000','--test-signature',d/'signature','--signature-granularity','4',root/unit/'sail.elf']
          else: cmd=[spike,f'--isa=rv32gcv_zvl{w}b',pk,root/unit/'test.elf']
        else:
          fs=root/'work'/unit/arm/'fs';fs.mkdir(parents=True);cache=fs.parent/'cache';cache.mkdir();shutil.copy2(root/unit/'test.elf',fs/'t.elf')
          env['LD_LIBRARY_PATH']=str(engine.parent.parent/'lib')+':/home/vick/boost_vendor/lib'
          fsflags=[f'--vlen={w}' if x.startswith('--vlen=') else x for x in flags[arm]]
          cmd=[engine,*fsflags,'--dump-tbmap='+str(d/'tbmap'),'--fsroot='+str(fs),'--cache='+str(cache),'--','/t.elf']
        rec=execute(cmd,d,env)
        if arm=='Reference' and cs[0]['vstart']:
          try: raw=b''.join(int(line,16).to_bytes(4,'little') for line in (d/'signature').read_text().splitlines())
          except (OSError,ValueError): raw=b''
        else: raw=(d/'stdout').read_bytes()
        (d/'packets.bin').write_bytes(raw);size=packet_size(cs[0]);errors=[]
        for i,c in enumerate(cs):
          status='PASS';error=None
          try:
            if len(raw)!=size*len(cs): raise ValueError(f'output extent {len(raw)} != {size*len(cs)}')
            ref=reference[i*size:(i+1)*size] if reference is not None else None
            check(c,raw[i*size:(i+1)*size],rec['returncode'],rec['timeout'],ref)
          except ValueError as ex: status='FAIL';error=str(ex);errors.append(dict(case=c['id'],error=error))
          results.append(dict(case=c['id'],arm=arm,status=status,error=error,raw=str(d/'packets.bin'),offset=i*size,size=size))
        if arm=='Reference' and not errors: reference=raw
        if arm!='Reference' and reference is None:
          for r in results[-len(cs):]:
            if r['status']=='PASS': r['status']='ISA_ONLY_REFERENCE_BLOCKED'
        save(d/'checks.json',results[-len(cs):]);save(d/'errors.json',errors)
      return results
    results=[]
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
      for rows in pool.map(worker,units.items()):
        results.extend(rows);print(rows[0]['case'].split('-length')[0],collections.Counter(r['status'] for r in rows),flush=True)
    save(root/'results.json',results);save(root/'identities-after.json',{str(p):sha(p) for p in paths})
    assert pins=={str(p):sha(p) for p in paths}
    save(root/'summary.json',dict(planned_cases=len(manifest['cases']),planned_executions=len(manifest['cases'])*5,executed=len(results),counts=dict(collections.Counter(r['status'] for r in results)),arms={a:dict(collections.Counter(r['status'] for r in results if r['arm']==a)) for a in ['Reference','B','M1','M2','BOTH']},seconds=time.monotonic()-start,jobs=jobs))
    if any(r['status']!='PASS' for r in results): raise SystemExit(1)

def main():
    p=argparse.ArgumentParser();sub=p.add_subparsers(dest='action',required=True)
    b=sub.add_parser('build');b.add_argument('--output',type=Path,required=True);b.add_argument('--compiler',default='clang-22');b.add_argument('--link',type=Path,required=True)
    r=sub.add_parser('run');r.add_argument('--root',type=Path,required=True)
    for n in ['engine','spike','pk','sail','flags']: r.add_argument('--'+n,type=Path,required=True)
    r.add_argument('--jobs',type=int,default=2)
    a=p.parse_args()
    if a.action=='build':build(a.output,a.compiler,a.link)
    else:run(a.root,a.engine,a.spike,a.pk,a.sail,a.flags,a.jobs)
if __name__=='__main__':main()
