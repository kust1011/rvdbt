"""Offline receipt authentication and independent terminal-state/emission audit.
No guest execution, reference engine, mapping changes or restart.
"""
from pathlib import Path
import hashlib,json,re,struct,subprocess,sys
root=Path(sys.argv[1]); output=Path(sys.argv[2])
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
manifest=json.loads((root/'MANIFEST.json').read_text())
assert all(sha(root/p)==h for p,h in manifest.items())
fixture=root/'focused/rv32_native_memory_fault_test'
layout=json.loads((fixture/'dispatcher-layout.json').read_text())
snapshots=[]
for p in sorted(fixture.glob('dispatcher-*.bin')):
 m=re.fullmatch(r'dispatcher-store(\d)-eew(\d)-partial(\d)-first(\d)-pins(\d)-inside(\d+)\.bin',p.name)
 assert m
 store,eew,partial,first,pins,inside=map(int,m.groups());prefix=(0 if first else 64)+inside
 blob=p.read_bytes();assert len(blob)==layout['size']
 read=lambda o:struct.unpack_from('<I',blob,o)[0]
 event=struct.unpack_from('<12I',blob,layout['event'])
 expected_raw=(1<<25)|(5<<15)|((6 if eew==4 else 7)<<12)|(8<<7)|(0x27 if store else 7)
 assert event==(1 if inside else 2,store,2,0x80001238,expected_raw,0x24001000,prefix//eew,0,eew,1,11,2),event
 assert read(layout['pc'])==0x80001238 and read(layout['gpr']+6*4)==0x123
 assert read(layout['csrs']+3*4)==prefix//eew and read(layout['csrs']+7*4)==(96 if partial else 128)//eew
 start=layout['vreg']+8*layout['vreg_stride']
 expected=bytes((i*5+3)&255 if not store and i<prefix else 0x67 for i in range(layout['vreg_stride']))
 assert blob[start:start+layout['vreg_stride']]==expected
 mem=(fixture/p.name.replace('dispatcher-','memory-')).read_bytes()
 assert mem==bytes(0x67 if store else (i*5+3)&255 for i in range(prefix))
 snapshots.append({'file':p.name,'origin':'checked' if inside else 'native','vstart':prefix//eew,'destination_bytes_checked':layout['vreg_stride'],'memory_bytes_checked':prefix})
assert len(snapshots)==40
# Decode actual JIT instructions independently of the emitter's site recorder.
shapes=[]
for p in sorted(fixture.glob('sites-*.txt')):
 binary=fixture/p.name.replace('sites-','emitted-').replace('.txt','.bin')
 data=binary.read_bytes()
 dis=subprocess.check_output(['objdump','-D','-b','binary','-m','i386:x86-64',str(binary)],text=True)
 instructions={}
 for line in dis.splitlines():
  m=re.match(r'\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*(\S.*)',line)
  if m:instructions[int(m.group(1),16)]=m.group(3)
 sites=[]
 for line in p.read_text().splitlines():
  fields=dict(item.split('=') for item in line.split())
  off=int(fields['offset']);cold=int(fields['cold']);i=instructions[off]
  assert data[off]==0x62 and 'vmovdqu' in i and '(%rax)' in i
  assert (i.find('(%rax)')<i.find('%zmm'))==(fields['store']=='0')
  assert f"%zmm{fields['data_reg']}" in i and ('%k7' in i)==(fields['mask']=='7')
  if fields['disp']=='64':assert '0x40(%rax)' in i
  else:assert fields['disp']=='0' and '0x40(%rax)' not in i
  assert data[cold:cold+6]==bytes.fromhex('59 4c 89 ef 31 f6')
  assert 'jmp' in instructions[cold+6]
  assert fields['guest_pc']=='80001238'
  sites.append({'offset':off,'instruction':i,'cold_offset':cold})
 shapes.append({'file':p.name,'sites':sites})
assert len(shapes)==8 and sum(len(s['sites']) for s in shapes)==24
callback=(root/'NATIVE_CALLBACK.disasm').read_text()
assert not re.search(r'\tcall\s',callback)
result={'manifest_files':len(manifest),'differences':[],'snapshots':snapshots,'native_snapshots':32,'checked_crossing_snapshots':8,'emitted_shapes':shapes,'production_callback_calls':0,'guest_executions':0,'restart_verified':False}
output.write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'manifest_files':len(manifest),'snapshots':len(snapshots),'shapes':len(shapes),'exact_sites':24,'differences':0,'guest_executions':0}))
