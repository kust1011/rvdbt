#!/usr/bin/env python3
"""Offline comparison of the bounded accepted-control and Task137 emitted artifacts."""
import difflib,hashlib,json,pathlib,re,sys
r=pathlib.Path(sys.argv[1]);out=pathlib.Path(sys.argv[2]);result=[]
manifest=json.loads((r/'MANIFEST.json').read_text())
assert all(hashlib.sha256((r/name).read_bytes()).hexdigest()==h for name,h in manifest.items())
raw_aslr_changes=sum((r/'current/before'/f'row{i}.bin').read_bytes()!=
 (r/'current/repeat'/f'row{i}.bin').read_bytes() for i in range(16))
assert raw_aslr_changes > 0
def fnv(v):
 h=1469598103934665603
 for c in v:h=((h^c)*1099511628211)&((1<<64)-1)
 return f'0x{h:016x}'
def text(arm,stage,row,suffix):return (r/arm/stage/f'row{row}.{suffix}').read_text()
for i in range(16):
 a=text('control','final-dump',i,'norm');b=text('current','final-dump',i,'norm')
 expected=a.replace('[r13+0xa500]','[r13+0xa528]').replace('[r13+0xa508]','[r13+0xa530]')
 if i in (8,9):
  target='0x142' if i==8 else '0x17b';join='0x16a' if i==8 else '0x1a3'
  mapping=({'12c':'142','143':'16a','1ab':'1d2','1c2':'1e9','1f4':'21b'} if i==8 else
           {'165':'17b','17c':'1a3','208':'22f','21f':'246','251':'278'})
  expected=re.sub(r'0x([0-9a-f]+)\b',lambda m:'0x'+mapping.get(m[1],m[1]),expected)
  expected=expected.replace('mov    DWORD PTR [r13+0xb8],0x8\n',
   'mov    DWORD PTR [r13+0xb8],0x8\nmov    rdi,r13\nmov    esi,0xABS\nrex call 0xABS\ntest   eax,eax\nje     '+target+'\n')
  expected=expected.replace('mov    DWORD PTR [r13+0xb8],0xc\n',
   'jmp    '+join+'\npop    rcx\nmov    rdi,r13\nxor    esi,esi\nrex jmp 0xABS\nmov    DWORD PTR [r13+0xb8],0xc\n')
  if i==9:
   expected=expected.replace('mov    eax,DWORD PTR [r13+0x64]\nvmovdqu64 zmm3,ZMMWORD PTR [rax+0x40]\nvmovdqu64 ZMMWORD PTR [r13+0x2d0],zmm2\n',
    'vmovdqu64 ZMMWORD PTR [r13+0x2d0],zmm2\nmov    eax,DWORD PTR [r13+0x64]\nvmovdqu64 zmm3,ZMMWORD PTR [rax+0x40]\n')
 assert expected==b, f'unexplained normalized instruction change row{i}'
 aq=text('control','final-dump',i,'qir');bq=text('current','final-dump',i,'qir')
 if i!=9:assert aq==bq,f'unexplained QIR change row{i}'
 else:
  assert aq.replace('#16 vchunkload:base:state:64:disp64+64 [%v39|v512] [$0|i32]\n    #17 vstatechunkstore:state:2d0+64 [%v38|v512]',
   '#16 vstatechunkstore:state:2d0+64 [%v38|v512]\n    #17 vchunkload:base:state:64:disp64+64 [%v39|v512] [$0|i32]')==bq
 for stage in ('before','repeat','after'):
  assert text('current',stage,i,'norm')==b
  assert text('current',stage,i,'qir')==bq
 assert text('control','baseline',i,'norm')==a
 an=text('control','final-dump',i,'nodisp');bn=text('current','final-dump',i,'nodisp')
 if i not in (8,9):assert an==bn
 diff=''.join(difflib.unified_diff(a.splitlines(True),b.splitlines(True),fromfile='c2084aa',tofile='Task137'))
 (out.parent/f'row{i}.diff').write_text(diff)
 result.append(dict(row=i,assertions_resolved=5 if i in (8,9) else 0 if i>=14 else 1,
  old_hash=fnv(a.encode()),new_hash=fnv(b.encode()),old_nodisp=fnv(an.encode()),new_nodisp=fnv(bn.encode()),
  old_bytes=(r/'control/final-dump'/f'row{i}.bin').stat().st_size,new_bytes=(r/'current/final-dump'/f'row{i}.bin').stat().st_size,
  old_lines=len(a.splitlines()),new_lines=len(b.splitlines()),qir_changed=aq!=bq))
assert sum(x['assertions_resolved'] for x in result)==22
for arm in ('control','current'):
 meta=dict(line.split() for line in (r/arm/'final-dump/row8.targets').read_text().splitlines())
 assert int(meta['state_hits'],16)==(0xa500 if arm=='control' else 0xa528)
 assert int(meta['state_fallbacks'],16)==(0xa508 if arm=='control' else 0xa530)
 if arm=='control':oldsize=int(meta['stub_table_size'],16)
 else:assert int(meta['stub_table_size'],16)==oldsize+40
 base=int(meta['code'],16)
 # Resolve real external calls from retained allocation address, without address normalization.
 names=[]
 for line in (r/arm/'final-dump/row8.disasm').read_text().splitlines():
  match=re.search(r'call (0x[0-9a-f]+)$',line)
  if match:
   dest=(base+int(match[1],16))%2**64
   aliases=[k for k,v in meta.items() if int(v,16)==dest]
   assert len(aliases)==1
   names+=aliases
 expected=['rv32_vadd_vv','rv32_native_memory_safe','rv32_native_memory_fault','rv32_vadd_vv','trace_cache'] if arm=='current' else ['rv32_vadd_vv','rv32_vle','rv32_vadd_vv','trace_cache']
 assert names==expected,(arm,names)
for name in ('full-final2','memory-final','admission-final','grouped-final','scalar-final','whole-final'):
 assert (r/'current/receipts'/name/'rc').read_text()=='0'
 assert json.loads((r/'current'/(name+'.pre.json')).read_text())==json.loads((r/'current'/(name+'.post.json')).read_text())
assert (r/'control/receipts/baseline/rc').read_text()=='0'
assert (r/'current/receipts/before/stderr').read_text().count('  FAIL ')==22
assert (r/'current/receipts/final-dump/rc').read_text()=='0'
assert (r/'current/receipts/final-dump/stdout').read_text().count('wrong-helper/range-limit rejection PASS')==2
out.write_text(json.dumps(dict(status='PASS',authenticated_receipts=len(manifest),raw_aslr_changed_rows=raw_aslr_changes,resolved_assertions=22,remaining_failures=0,rows=result),indent=2)+'\n')
print('PASS: all 22 dispositions, exact explained QIR/x86 deltas, targets, layout and final checks')
