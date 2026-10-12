"""Authenticate retained Task136 receipts and independently reconstruct state; no guests."""
from pathlib import Path
import ctypes as c
import hashlib,json,re,struct,subprocess,sys
root=Path(sys.argv[1]);out=Path(sys.argv[2])
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
manifest=json.loads((root/'MANIFEST.json').read_text())
assert all(sha(root/p)==h for p,h in manifest.items())
class Snapshot(c.Structure):
    _fields_=[('event',c.c_uint32*12),('pc',c.c_uint32),('vlenb',c.c_uint32),
              ('gpr',c.c_uint32*32),('fpr',c.c_uint64*32),('csrs',c.c_uint32*10),
              ('vreg',c.c_ubyte*(32*512))]
assert c.sizeof(Snapshot)==16864 and Snapshot.vreg.offset==480
pc=0x80001234;base=0x24000000
f=root/'focused/terminal';rows=[]
for id in range(10):
    whole=id<4 or id>=8;store=id%4>=2 if id<8 else id==9;second=id%2==1 if id<8 else False
    v=bytearray((r*19+b*7)&255 for r in range(32) for b in range(512))
    def alu(rd,a,b,x=False):
        for e in range(32):
            aa=struct.unpack_from('<I',v,a*512+e*4)[0];bb=struct.unpack_from('<I',v,b*512+e*4)[0]
            struct.pack_into('<I',v,rd*512+e*4,(aa^bb) if x else (aa+bb)&0xffffffff)
    alu(8,1,2);alu(9,8,3,True)
    memory=bytearray((b*5+3)&255 for b in range(8192))
    if second:v[8*512:8*512+128]=memory[512:640]
    if store:memory[4032:4096]=v[8*512:8*512+64]
    else:v[8*512:8*512+64]=memory[4032:4096]
    blob=(f/f'snapshot-{id}.bin').read_bytes();assert len(blob)==c.sizeof(Snapshot)
    snap=Snapshot.from_buffer_copy(blob)
    assert bytes(snap.vreg)==v==(f/f'expected-vregs-{id}.bin').read_bytes()
    assert memory[:4096]==(f/f'memory-{id}.bin').read_bytes()==(f/f'expected-memory-{id}.bin').read_bytes()
    faultpc=pc+(16 if second else 12);eew=1 if whole and store else 4
    raw=(1<<25)|(5<<15)|((0 if eew==1 else 6)<<12)|(8<<7)|(0x27 if store else 7)|(8<<20 if whole else 0)
    assert list(snap.event)==[2,int(store),2,faultpc,raw,base+4096,64//eew,0,eew,1,11,2]
    assert snap.pc==faultpc and snap.vlenb==128 and snap.gpr[5]==base+4032 and snap.gpr[6]==0x123 and snap.gpr[7]==base+512
    assert snap.csrs[3]==64//eew and snap.csrs[7]==32 and snap.csrs[8]==16 and snap.csrs[9]==128
    rows.append(dict(id=id,whole=whole,store=store,prior_load_same_destination=second,
                     pc=faultpc,eew=eew,element=64//eew,vector_bytes=16384,memory_bytes=4096))
assert len(re.findall('GROUPED_TERMINAL', (f/'stdout').read_text()))==10
shapes=[]
for p in sorted((root/'focused/normal-pinned-final').glob('sites-*.txt')):
    code=p.with_name(p.name.replace('sites-','emit-').replace('.txt','.bin'));data=code.read_bytes()
    dis=subprocess.check_output(['objdump','-D','-b','binary','-m','i386:x86-64',str(code)],text=True)
    ins={}
    for line in dis.splitlines():
        m=re.match(r'\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*(\S.*)',line)
        if m:ins[int(m[1],16)]=m[3]
    sites=[dict(t.split('=') for t in line.split()) for line in p.read_text().splitlines()]
    for s in sites:
        pos=int(s['offset']);cold=int(s['cold']);op=ins[pos]
        assert 'vmovdqu' in op and '(%rax)' in op and '%r13' not in op
        assert int(s['bytes'])==64 and cold>pos
        assert data[cold:cold+6]==bytes.fromhex('59 4c 89 ef 31 f6') and 'jmp' in ins[cold+6]
        if s['store']=='0':
            nxt=min([int(t['offset']) for t in sites if int(t['offset'])>pos and t['guest_pc']==s['guest_pc']]+[cold])
            assert any('vmovdqu' in op and '%r13)' in op and op.index('%zmm')<op.index('(%r13)')
                       for at,op in ins.items() if pos<at<nxt)
    shapes.append(dict(file=str(p.relative_to(root)),sites=len(sites)))
assert len(shapes)==40 and sum(s['sites'] for s in shapes)==120
baseline=(root/'focused/baseline/stdout').read_text();normal=(root/'focused/normal-pinned-final/stdout').read_text()
assert len(re.findall('has_mem=1',baseline))==20 and len(re.findall('memory_groups=1 sites=0',baseline))==20
assert 'has_mem=1' not in normal and len(re.findall('compute_groups=2',normal))==40
assert len(re.findall('memory_groups=0',normal))==40 and normal.count('LEGACY_GROUP')==2
for name in ['normal-pinned-final','terminal','scalar-normal','whole-normal','admission','codegen-focused']:
    assert (root/'focused'/name/'rc').read_text()=='0'
assert (root/'build.rc').read_text()=='0' and (root/'build.internal.rc').read_text()=='0'
summary=dict(manifest_files=len(manifest),differences=[],snapshot_layout=dict(size=c.sizeof(Snapshot),vreg=Snapshot.vreg.offset),
             terminal_cells=10,host_sigsegv=10,guest_executions=0,restart_verified=False,cells=rows,shapes=shapes,
             baseline_grouped_whole_shapes=20,final_singleton_memory_shapes=40,
             retained_full_codegen_failure='22 byte/hash golden checks; not granted passing credit',
             terminal_fixture_pin_limit='Fixture hash first recorded after terminal batch; production binaries pinned before/after.')
out.write_text(json.dumps(summary,indent=2)+'\n');print({k:v for k,v in summary.items() if k not in ['cells','shapes']})
