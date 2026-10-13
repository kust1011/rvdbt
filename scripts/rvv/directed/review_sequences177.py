#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read retained P3 packets and existing PC/frame/generated-code observations."""
import argparse, collections, csv, functools, hashlib, json, re, struct, subprocess
from pathlib import Path
import sequences177 as s
import vadd as v

def memoize_dict(fn):
    @functools.lru_cache(maxsize=8192)
    def cached(key): return fn(json.loads(key))
    return lambda c:cached(json.dumps(c,sort_keys=True))
s.initial=memoize_dict(s.initial)
s.expectation=memoize_dict(s.expectation)

def elf_info(path):
    raw=v.storage.verify(path)
    shoff=struct.unpack_from('<I',raw,32)[0];ents,count=struct.unpack_from('<2H',raw,46)
    sections=[struct.unpack_from('<10I',raw,shoff+i*ents) for i in range(count)]
    symbols={}
    for h in sections:
      if h[1]==2:
        strings=sections[h[6]];names=raw[strings[4]:strings[4]+strings[5]]
        for off in range(h[4],h[4]+h[5],h[9]):
          name,addr,size,info,other,index=struct.unpack_from('<3I2BH',raw,off)
          symbols[names[name:].split(b'\0',1)[0].decode()]=addr
    def word(pc):
        h=next(h for h in sections if h[3]<=pc<h[3]+h[5] and h[1]==1)
        return struct.unpack_from('<I',raw,h[4]+pc-h[3])[0]
    return symbols,word

F6={'vadd':0,'vsub':2,'vxor':11,'vmaxu':6,'vfadd':0,'vfsub':2}
def encoding(op):
    name,d,a,b,mask=op
    return F6[name]<<26 | int(not mask)<<25 | a<<20 | b<<15 | int(name.startswith('vf'))<<12 | d<<7 | 0x57

def host_disassembly(code,out):
    # Existing tbcode hook and standard objdump; no new guest instrumentation.
    out.write_bytes(code)
    cmd=['objdump','-D','-b','binary','-m','i386:x86-64','--insn-width=16',str(out)]
    text=subprocess.check_output(cmd,text=True)
    return [(int(pc,16),op.strip()) for pc,op in re.findall(r'^\s*([0-9a-f]+):\s+(?:[0-9a-f]{2}\s+)+([^\n]+)',text,re.M)],text

def frame_code(ins,entry,end,c,member_ops):
    marker=f'$0x{entry:x},0xb8(%r13)'
    start=next(i for i,(_,op) in enumerate(ins) if marker in op)
    # The first conditional after this PC marker is the actual frame guard's
    # failure edge. Ordered helpers begin at that target, after the native body.
    branch=next((pc,op) for pc,op in ins[start:] if re.match(r'j(?:ne|e|a|b)',op))
    miss=int(re.search(r'0x([0-9a-f]+)',branch[1]).group(1),16)
    segment=[(pc,op) for pc,op in ins[start:] if pc<miss]
    assert segment and not any(op.startswith('call') for _,op in segment),(c['id'],entry,'native frame contains call')
    stores=[]
    for pc,op in segment:
      m=re.match(r'v\w+\s+%(?:zmm|ymm|xmm)\d+,0x([0-9a-f]+)\(%r13\)',op)
      if m:
        off=int(m[1],16)
        if 0xd0<=off<0x40d0: stores.append((pc,off))
    # Register file slots have fixed 512-byte stride in the pinned CPUState.
    regs={(off-0xd0)//512 for _,off in stores}
    produced=set()
    for op in member_ops:
        produced.update(range(op[1],op[1]+c['group_registers']))
    assert regs<=produced,(c['id'],entry,'unproduced dirty publication',regs,produced)
    bounds=[]
    for i,(pc,op) in enumerate(segment):
      m=re.match(r'jbe\s+0x([0-9a-f]+)',op)
      if not m or i==0:continue
      prev=segment[i-1][1];cmp=re.match(r'cmp\s+\$0x([0-9a-f]+),%eax',prev)
      vl_load=i>=2 and re.match(r'mov\s+0x40d4\(%r13\),%eax',segment[i-2][1])
      if cmp and vl_load and int(m[1],16)<miss and int(m[1],16)>pc:
        bounds.append(dict(host_offset=pc,lane_base=int(cmp[1],16),join_offset=int(m[1],16)))
    # For FP grouped frames each completed component must contain ALL later
    # members before reaching the bound for the next component.
    if c['fp'] and bounds and len(member_ops)>1:
      expected=sum(op[0] in ('vfadd','vfsub') for op in member_ops)
      for lo,hi in zip(bounds,bounds[1:]):
        between=[op for pc,op in segment if lo['host_offset']<pc<hi['host_offset']]
        actual=sum(bool(re.match(r'v(?:add|sub)p[sd]\s',op)) for op in between)
        assert actual==expected,(c['id'],entry,'low component incomplete',actual,expected)
      assert bounds[0]['lane_base']==0
    return dict(native_code_begin=ins[start][0],guard_miss=miss,
                native_vector_stores=len(stores),published_registers=sorted(regs),
                produced_registers=sorted(produced),bounds=bounds,
                low_component_later_members_checked=bool(c['fp'] and len(member_ops)>1 and len(bounds)>1))

def audit(roots,out):
    out.mkdir(parents=True,exist_ok=False);allrows=[];framesout=[];summary=collections.Counter();ids=set()
    for root in roots:
      manifest=json.loads((root/'manifest.json').read_text());rows=manifest['cases'];groups=collections.defaultdict(list)
      assert not ids.intersection(c['id'] for c in rows);ids.update(c['id'] for c in rows)
      for c in rows: groups[c['unit']].append(c)
      assert json.loads((root/'identities-before.json').read_text())==json.loads((root/'identities-after.json').read_text())
      builds=json.loads((root/'build-commands.json').read_text())
      for build in builds:
        p=Path(build['command'][-1]);assert build['returncode']==0 and v.sha(root/p.parent.name/p.name)==build['elf_sha256']
      for unit,cs in groups.items():
        guest=root/unit/'test.elf';symbols,word=elf_info(guest)
        assert v.storage.text(root/unit/'test.S')==v.assembly(cs)
        targetpcs={}
        for c in cs:
          for i,op in enumerate(c['ops']):
            pc=symbols[f'seq_{c["ordinal"]}_{i}'];assert word(pc)==encoding(op)
            targetpcs[pc]=(c,i)
        streams={arm:v.storage.verify(root/'runs'/unit/arm/'packets.bin') for arm in s.ARMS}
        size=v.packet_size(cs[0]);assert all(len(raw)==size*len(cs) for raw in streams.values())
        for arm in s.ARMS:
          d=root/'runs'/unit/arm;record=json.loads((d/'execution.json').read_text());assert record['returncode']==0 and not record['timeout']
          checks=json.loads((d/'checks.json').read_text());assert len(checks)==len(cs) and all(r['status']=='PASS' for r in checks)
          for j,c in enumerate(cs):
            packet=streams[arm][j*size:(j+1)*size];s.check_isa(c,packet)
            if arm!='Reference':s.check_reference(c,packet,streams['Reference'][j*size:(j+1)*size])
            summary[arm]+=1
          if arm=='Reference':continue
          command=json.loads((d/'command.json').read_text());assert '--rvv-pc-census=1' in command
          text=v.storage.text(d/'stderr');census=v.storage.text(d/'pc-census.csv')
          assert 'overflow=0' in census
          handlers={int(r['pc'],16):int(r['handler_calls']) for r in csv.DictReader(census.splitlines()[1:])}
          forms=[(int(a,16),int(b,16),int(n),ops) for a,b,n,ops in re.findall(r'RVV_RUN_FORM entry=(\w+) end=(\w+).*?members=(\d+) ops=(\S+)',text)]
          dynamic=[(int(tb,16),int(i),int(n),int(k),int(count)) for tb,i,n,k,count in re.findall(r'^RVV_RUN_FRAME (\w+),(\d+),(\d+),(\d+),(\d+)$',text,re.M)]
          assert len(forms)==len(dynamic),(unit,arm,'formation/emission mismatch')
          codes={int(pc,16):bytes.fromhex(code) for pc,size,code in re.findall(r'^(\w+) (\d+) (\w+)$',v.storage.text(d/'tbcode'),re.M)}
          tbmap={int(pc,16):(int(host,16),int(sz),int(count)) for pc,host,sz,count in re.findall(r'^(\w+) (0x\w+) (\d+) (\d+)$',v.storage.text(d/'tbmap'),re.M)}
          dis={};membership={}
          for form,frame in zip(forms,dynamic):
            entry,end,n,ops=form;tb,index,fn,k,count=frame
            assert n==fn and end-entry==n*4
            if entry not in targetpcs:continue
            c,_=targetpcs[entry];pcs=list(range(entry,end,4));assert all(pc in targetpcs for pc in pcs)
            memberops=[targetpcs[pc][0]['ops'][targetpcs[pc][1]] for pc in pcs]
            assert len(codes[tb])==tbmap[tb][1] and tbmap[tb][2]>0
            if tb not in dis:
                ins,dasm=host_disassembly(codes[tb],out/'temporary-host.bin');dis[tb]=ins
                v.storage.write(out/(unit+'-'+arm+'-'+hex(tb)+'.dis'),dasm.encode())
            detail=frame_code(dis[tb],entry,end,c,memberops)
            # The fallback-only handler census is PC-specific. Every fast join
            # is counted separately; adapter helper calls cannot inflate it.
            target_handlers={hex(pc):handlers.get(pc,0) for pc in pcs}
            if count:assert count==1 or c['scenario']=='cache'
            for pc in pcs:membership[pc]=dict(entry=hex(entry),end=hex(end),tb=hex(tb),index=index,members=n,k=k,fast_executions=count,**detail)
            framesout.append(dict(unit=unit,arm=arm,target_case=c['id'],entry=hex(entry),end=hex(end),tb=hex(tb),index=index,members=n,k=k,fast_executions=count,target_handlers=target_handlers,code_sha256=hashlib.sha256(codes[tb]).hexdigest(),**detail))
          for pc,(c,i) in targetpcs.items():
            frame=membership.get(pc);calls=handlers.get(pc,0)
            path='MULTI_MEMBER_NATIVE' if frame and frame['fast_executions'] and not calls else 'MULTI_MEMBER_MIXED' if frame and frame['fast_executions'] else 'ORDERED_RUN_FALLBACK' if frame else 'SINGLETON_OR_HELPER'
            if c['fp'] and c['scenario'] in ('reject-tu','reject-mask'):assert frame is None
            singleton=None
            if frame is None:
                marker=b'\x41\xc7\x85\xb8\x00\x00\x00'+struct.pack('<I',pc)
                containing=[tb for tb,code in codes.items() if marker in code]
                assert containing,(unit,arm,hex(pc),'missing emitted PC')
                tb=containing[0]
                assert tbmap[tb][2]>0 and len(codes[tb])==tbmap[tb][1]
                if tb not in dis:
                    ins,dasm=host_disassembly(codes[tb],out/'temporary-host.bin');dis[tb]=ins
                    v.storage.write(out/(unit+'-'+arm+'-'+hex(tb)+'.dis'),dasm.encode())
                singleton=dict(tb=hex(tb),code_sha256=hashlib.sha256(codes[tb]).hexdigest(),guest_pc_marker=True)
                if not calls:
                    singleton.update(frame_code(dis[tb],pc,pc+4,c,[c['ops'][i]]))
                    path='SINGLETON_NATIVE'
                else:path='SINGLETON_HANDLER_OR_GUARD_FALLBACK'
            allrows.append(dict(case=c['id'],arm=arm,pc=hex(pc),instruction=c['ops'][i],scanner='ADMITTED_MULTI' if frame else 'NO_MULTI_FRAME',actual_path=path,handler_calls=calls,frame=frame,singleton=singleton,result='PASS',reference='original Sail' if c['vstart'] else 'original Spike/pk',root=str(root)))
    (out/'temporary-host.bin').unlink(missing_ok=True)
    v.save(out/'PC_PATH_RESULTS.json',allrows);v.save(out/'FRAMES.json',framesout)
    v.save(out/'AUDIT.json',dict(status='PASS',cases=len(ids),checks=sum(summary.values()),arms=dict(summary),target_pc_arm_rows=len(allrows),multi_frames=len(framesout),native_multi_frames=sum(bool(r['fast_executions']) for r in framesout),fp_frames_with_component_completion_proof=sum(r['low_component_later_members_checked'] for r in framesout),paths=dict(collections.Counter(r['actual_path'] for r in allrows)),all_packet_outcomes_checked=True,prior_family_reruns=0,controls='separate one-pass over these actual packets'))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('mode',choices=('audit','controls'));p.add_argument('--roots',type=Path,nargs='+',required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--cache64',action='store_true');a=p.parse_args()
    if a.cache64:
        import cache_entries177
        cache_entries177.install()
    s.install('integer')
    if a.mode=='audit':audit(a.roots,a.out)
    else:s.controls(a.roots,a.out)
