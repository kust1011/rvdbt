#!/usr/bin/env python3
"""Verify current multi-member execution and width-two host batch order."""
import argparse,json,re,subprocess
from pathlib import Path
from rvv_tests import save,digest
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--results',type=Path,required=True);p.add_argument('--source',type=Path,required=True);a=p.parse_args();rows=[]
for arm in ['M1','BOTH']:
 d=a.results/'runs/rvvts'/arm;text=(d/'stderr').read_text()
 forms=re.findall(r'RVV_RUN_FORM entry=(\w+) end=(\w+).*?members=(\d+) ops=(\S+)',text)
 frames=re.findall(r'RVV_RUN_FRAME (\w+),(\d+),(\d+),(\d+),(\d+)',text)
 assert forms and frames and 'guard_fallbacks=0' in text
 begin,end,n,ops=forms[0];begin=int(begin,16);end=int(end,16)
 assert end==begin+12 and int(n)==3 and ops=='falu,falu,falu'
 tb,idx,members,k,count=frames[0];assert (int(idx),int(members),int(k),int(count))==(0,3,4,1)
 mapping={int(pc,16):(int(host,16),int(size),int(cnt)) for pc,host,size,cnt in re.findall(r'^(\w+) (0x\w+) (\d+) (\d+)$',(d/'tbmap.txt').read_text(),re.M)}
 host,size,cnt=mapping[int(tb,16)];assert cnt==1
 codes={int(pc,16):bytes.fromhex(code) for pc,sz,code in re.findall(r'^(\w+) (\d+) (\w+)$',(d/'tbcode.txt').read_text(),re.M)};code=codes[int(tb,16)];assert len(code)==size
 binary=d/'target-host.bin';binary.write_bytes(code)
 cmd=['objdump','-D','-b','binary','-m','i386:x86-64','--adjust-vma='+str(host),str(binary)]
 dis=subprocess.check_output(cmd,text=True);(d/'target-host.disassembly').write_text(dis);save(d/'disassembly-command.json',cmd)
 ins=[(int(pc,16),op.strip()) for pc,op in re.findall(r'^\s*([0-9a-f]+):\s+(?:[0-9a-f]{2}\s+)+\s*([^\n]+)',dis,re.M)]
 start=next(i for i,(pc,op) in enumerate(ins) if f'$0x{begin:x},0xb8(%r13)' in op)
 stop=next(i for i in range(start+1,len(ins)) if f'$0x{end:x},0xb8(%r13)' in ins[i][1]);region=ins[start:stop]
 masks=[pc for pc,op in region if re.fullmatch(r'kmovw\s+%edx,%k[1-4]',op)];assert len(masks)==4
 boundary=masks[2]
 allstores=[(pc,op) for pc,op in region if re.fullmatch(r'vmovdqu64\s+%zmm\d+,0x\w+\(%r13\)',op)];assert len(allstores)==12
 finish=next(pc for pc,op in region if pc>allstores[-1][0] and op.startswith('stmxcsr'))
 batches=[]
 for lo,hi in [(masks[0],boundary),(boundary,finish)]:
  xs=[(pc,op) for pc,op in region if lo<=pc<hi]
  loads=[pc for pc,op in xs if re.fullmatch(r'vmovdqu64\s+0x\w+\(%r13\),%zmm\d+',op)]
  ops=[pc for pc,op in xs if op.startswith('vaddps')];stores=[pc for pc,op in xs if re.fullmatch(r'vmovdqu64\s+%zmm\d+,0x\w+\(%r13\)',op)]
  assert (len(loads),len(ops),len(stores))==(12,6,6)
  assert max(loads)<min(ops)<=max(ops)<min(stores)<=max(stores)<hi
  assert not any(op.startswith('call') for pc,op in xs)
  batches.append(dict(loads=12,lane_ops=6,stores=6,begin=hex(lo),end=hex(hi),publication_before_next_batch=True))
 rows.append(dict(arm=arm,form_begin=hex(begin),form_end=hex(end),original_ordinals=[1,2,3],members=3,chunks=4,frame_count=1,tb_count=1,guard_fallbacks=0,batch_width=2,batches=batches,host_code_sha256=digest(binary),diagnostics_sha256=digest(d/'stderr'),scope='code order + executed frame/TB + valid invariant guard; no direct per-batch telemetry'))
save(a.results/'admission.json',dict(status='PASS',rows=rows,source={n:digest(a.source/n) for n in ['dbt/guest/rv32_vrun.cpp','dbt/guest/rv32_vrun.h','dbt/guest/rv32_qir.cpp']},limits='one sequence; v26 later masked overwritten; no independent intermediate oracle, arbitrary pressure cuts, fault/retry or timing claim'))
print('PASS: M1/BOTH current multi-member frames and two width2 batches')
