#!/usr/bin/env python3
"""Additive, offline final181 denial adjudication. Never imports execution tools."""
import argparse, collections, gzip, hashlib, json, re, struct
from pathlib import Path

ARMS = ('B', 'M1', 'M2', 'BOTH')
ENGINE = '/home/vick/rvdbt-host512-task179-build/build/bin/elfrun'
PIN = '8a468967852b8f16225b359fce99c0d22ab286d6314cb90a79934a7376207281'
LIBPIN = '79d0ba2a9ddea24d49d7282012fdc373b92a26756bb5452c1f41c66d533887af'
MARKER = 'RVDBT_MEMORY_FAULT_SNAPSHOT '

def digest(data):
    return hashlib.sha256(data).hexdigest()

def read(path):
    if path.exists():
        return path.read_bytes()
    return gzip.decompress(Path(str(path) + '.gz').read_bytes())

def elf(raw):
    """Read only ELF32 sections/symbols; no disassembler or guest execution."""
    if raw[:7] != b'\x7fELF\x01\x01\x01' or struct.unpack_from('<H', raw, 18)[0] != 243:
        raise ValueError('not RV32 little-endian ELF')
    start = struct.unpack_from('<I', raw, 32)[0]
    stride, count, namesidx = struct.unpack_from('<3H', raw, 46)
    headers = [struct.unpack_from('<10I', raw, start+i*stride) for i in range(count)]
    h = headers[namesidx]; names = raw[h[4]:h[4]+h[5]]
    sections, symbols = {}, {}
    for h in headers:
        name = names[h[0]:].split(b'\0', 1)[0].decode()
        sections[name] = (h[3], raw[h[4]:h[4]+h[5]])
        if h[1] == 2:
            st = headers[h[6]]; table = raw[st[4]:st[4]+st[5]]
            for pos in range(h[4], h[4]+h[5], h[9]):
                idx, value, _, _, _, _ = struct.unpack_from('<3I2BH', raw, pos)
                symbols[table[idx:].split(b'\0', 1)[0].decode()] = value
    return sections, symbols

def at(sections, address, size):
    for base, data in sections.values():
        if base <= address and address+size <= base+len(data):
            return data[address-base:address-base+size]
    raise ValueError('ELF symbol extent unavailable')

def expectations(suite, record, rawelf, source):
    """Derive before inspecting any DUT stream, from setup/ELF and V1.0 rules."""
    c = record['case']; sections, syms = elf(rawelf)
    b = c['vlen']//8; e = c['eew']//8; nf = c['nf']; size = 16*b+256
    pc = syms['target_0']; memory = syms['memory_0']; end = memory+size
    if end != sections['.data'][0]+len(sections['.data'][1]) or end % 4096:
        raise ValueError('setup is not the retained unmapped page edge')
    if c['mask'] not in ('none', 'all') or c['vstart'] != 0 or c['ta'] or c['ma']:
        raise ValueError('unexpected denial setup')
    width = {8:0,16:5,32:6,64:7}[c.get('index_eew', c['eew'])]
    word = (nf-1)<<29 | int(c['mask']=='none')<<25 | 18<<15 | width<<12 | c['vd']<<7 | (0x27 if c['store'] else 7)
    if suite == 'guard166':
        word |= (3 if c['ordered'] else 1)<<26 | c['vs2']<<20
    elif suite == 'faults':
        word |= 16<<20
        if 'element0' not in c['tag'] or c['fault_index'] != 0 or c['store']:
            raise ValueError('not a retained FOF element-zero control')
    elif c['strided']:
        word |= 2<<26 | c['rs2']<<20
    if int.from_bytes(at(sections, pc, 4), 'little') != word:
        raise ValueError('ELF target differs from independent encoding')
    if record.get('target_word') and int(record['target_word'], 16) != word:
        raise ValueError('original target manifest mismatch')
    base = memory+c['guard_base']
    def addr(i, f):
        if suite == 'guard166':
            offset = (nf*e if i == 0 else 0) if record['kind'].startswith('prestart') else (0 if i == 0 else nf*e)
        else:
            offset = i*(c['stride'] if c['strided'] else nf*e)
        return base+offset+f*e
    denied = [(i,f,addr(i,f)) for i in range(c['vl']) for f in range(nf) if addr(i,f) >= end]
    element = min(i for i,_,_ in denied)
    # Fields are unordered by V1.0 7.8. Accept any denied field in this segment.
    faults = [(f,a) for i,f,a in denied if i == element]
    initial = at(sections, syms['initial_0'], 32*b)
    # Independently validate source constants before using the ELF initialized bytes.
    payload = re.search(r'initial_0:\n.byte ([^\n]+)', source).group(1)
    if bytes(map(int,payload.split(','))) != initial:
        raise ValueError('ELF/source initial register mismatch')
    mem = at(sections, memory, size)
    if mem != bytes((i*29+(i>>8)*17+0xa7)&255 for i in range(size)):
        raise ValueError('ELF memory differs from original setup formula')
    required_setup = [f'li t0,{c["vl"]}', f'li s0,{c["operand"]&0xffffffff}', 'li s1,0x6badcafe', 'csrw fcsr,t0', 'li t0,117', f'li t0,{c["guard_base"]}', 'add s2,s2,t0']
    if any(x not in source[:source.index('target_0:')] for x in required_setup):
        raise ValueError('source prestate setup mismatch')
    csrs = dict(fflags=21, frm=3, fcsr=117, vstart=element, vxsat=1, vxrm=2, vcsr=5, vl=c['vl'], vtype=(c['lmul_exp']&7)+([8,16,32,64].index(c['sew'])<<3), vlenb=b)
    # Full untouched registers, prestart/tail and completed load prefix are observable.
    expected = bytearray(initial); checked = bytearray(b'\x01'*(32*b))
    if not c['store']:
        for f in range(nf):
            for i in range(c['vl']):
                q=(c['vd']+f*c['group_registers'])*b+i*e
                if i < element:
                    expected[q:q+e] = mem[addr(i,f)-memory:addr(i,f)-memory+e]
                else:
                    # Legal partial segment/spurious active suffix updates; no invented golden.
                    checked[q:q+e] = b'\0'*e
    return dict(pc=pc, raw=word, element=element, faults=faults, access='store' if c['store'] else 'load', reason='unmapped', eew_bytes=e, nf=nf, vlenb=b, csrs=csrs,
                gpr={0:0,5:c['guard_base'],7:c['vl'],8:c['operand']&0xffffffff,9:0x6badcafe,13:syms['packet_0'],18:base},
                vreg_expected=bytes(expected).hex(), vreg_checked=bytes(checked).hex(), store=c['store'])

def adjudicate(expected, execution, stdout, stderr, identity_errors=()):
    missing, mismatches = [], list(identity_errors)
    text = (stdout+stderr).decode(errors='replace')
    lines = [line[len(MARKER):] for line in text.splitlines() if line.startswith(MARKER)]
    rc = execution.get('returncode')
    if execution.get('timeout') or rc != 1:
        mismatches.append('expected owned terminal exit 1; got timeout/other exit/process signal')
    for key, data in [('stdout_sha256', stdout), ('stderr_sha256', stderr)]:
        if execution.get(key) != digest(data):
            mismatches.append(key+' capture identity mismatch')
    snapshot = None
    if len(lines) != 1:
        missing.append('one complete structured fault snapshot (PC/raw/address/element/field/cause/registers/CSRs)')
    else:
        try:
            snapshot = json.loads(lines[0])
            if not isinstance(snapshot, dict):
                raise ValueError('snapshot object required')
        except (ValueError, TypeError):
            missing.append('complete JSON snapshot (truncated/malformed)')
    if snapshot is not None:
        def check(key, value, obj=snapshot, prefix=''):
            if key not in obj: missing.append(prefix+key)
            elif type(obj[key]) is not type(value) or obj[key] != value: mismatches.append(prefix+key+' mismatch')
        for key in ('pc','raw','element','access','reason','eew_bytes','nf','vlenb'):
            check(key, expected[key])
        for key,value in dict(schema_version=1,status='HELPER_FAULT_CAPTURED',fp_run_closed=True).items(): check(key,value)
        if 'field' not in snapshot or 'address' not in snapshot:
            missing.extend(k for k in ('field','address') if k not in snapshot)
        elif type(snapshot['field']) is not int or type(snapshot['address']) is not int or (snapshot['field'],snapshot['address']) not in [tuple(x) for x in expected['faults']]:
            mismatches.append('field/address outside independently denied segment accesses')
        if not isinstance(snapshot.get('csrs'), dict): missing.append('csrs')
        else:
            for key,value in expected['csrs'].items(): check(key,value,snapshot['csrs'],'csrs.')
        gpr = snapshot.get('gpr')
        if not isinstance(gpr,list) or len(gpr)!=32 or any(type(x)!=int or not 0<=x<=0xffffffff for x in gpr): missing.append('complete 32 RV32 gpr values')
        else:
            for r,value in expected['gpr'].items():
                if gpr[int(r)]!=value: mismatches.append(f'gpr[{r}] setup/preservation mismatch')
        fpr = snapshot.get('fpr_hex')
        if not isinstance(fpr,list) or len(fpr)!=32 or any(not isinstance(x,str) or not re.fullmatch('[0-9a-fA-F]{16}',x) for x in fpr): missing.append('complete 32 fpr values')
        regs = snapshot.get('vreg_hex')
        if not isinstance(regs,list) or len(regs)!=32 or any(not isinstance(x,str) or not re.fullmatch('[0-9a-fA-F]{'+str(expected['vlenb']*2)+'}',x) for x in regs): missing.append('complete 32 vector registers')
        else:
            got=bytes.fromhex(''.join(regs)); want=bytes.fromhex(expected['vreg_expected']); mask=bytes.fromhex(expected['vreg_checked'])
            if any(m and a!=b for a,b,m in zip(got,want,mask)): mismatches.append('vector committed prefix/untouched register/prestart/tail mismatch')
        # Raw origin preserved; the known NativeUnit formatter bug forbids inference.
        if 'origin' not in snapshot: missing.append('origin raw label')
        # host_signal/code are host provenance, not architectural mcause.
        for k in ('host_signal','host_code'):
            check(k,0)
        terminal = re.findall(r'^RVDBT_SIGNAL_UNDELIVERABLE helper_sync signal=(\d+) code=(\d+)$', text, re.M)
        if not terminal: missing.append('owned terminal diagnostic signal/code')
        elif terminal != [('11','1')]: mismatches.append('terminal signal/code cause mismatch')
    if mismatches:
        category = 'GENERIC_FAILURE' if rc not in (0,None) else 'UNEXPECTED_SUCCESS'
    elif missing:
        category = 'INSUFFICIENT_OBSERVATION'
    else:
        category = 'EXACT_EXPECTED_FAULT'
    state_missing = ['pre-fault full GPR/FPR baseline for full scalar preservation', 'handler return/same-PC resumed completion and forward progress']
    if expected['store']: state_missing.append('fault-time memory image for committed store prefix/footprint')
    return dict(category=category, adjudication='VERIFIED_DENIAL_CONTROL' if category=='EXACT_EXPECTED_FAULT' else 'UNVERIFIED', missing_fields=missing, rejection_reasons=mismatches,
                raw_origin_label=snapshot.get('origin') if snapshot else None, native_admission='UNVERIFIED: origin formatter ambiguous',
                architectural_fault_state='UNVERIFIED', architectural_missing_fields=state_missing,
                architectural_cause='UNVERIFIED: no mcause/scause captured; access/reason identifies diagnostic cause only')

def audit(mirror, output):
    def path(original): return mirror/str(original).lstrip('/')
    rows=[]; inputs={}
    def retained(p):
        raw=read(p);inputs[str(p.relative_to(mirror))]=digest(raw);return raw
    focused=json.loads(Path('docs/rvv-validation/directed-task181/FOCUSED_PLAN.json').read_text())
    manifest=json.loads(Path('docs/rvv-validation/directed-task181/BUILD_MANIFEST_179.json').read_text())
    if manifest['artifacts']['build/bin/elfrun']!=PIN or manifest['artifacts']['build/lib/libdbtjitshared.so']!=LIBPIN: raise ValueError('179 manifest mismatch')
    for suite, count in [('guard165',48),('guard166',64),('faults',480)]:
        root=path('/home/vick/rvv-task181/focused')/suite
        plan=json.loads(retained(root/'audit/PLAN.json'))
        if plan['build_sha256']!=PIN or plan['library_sha256']!=LIBPIN: raise ValueError('focused manifest build mismatch')
        oldsummary=retained(path(plan['original'])/'summary.json')
        pin=next(x for x in focused if x['suite']==suite)
        if digest(oldsummary)!=plan['summary_sha256'] or digest(oldsummary)!=pin['summary_sha256']: raise ValueError('original summary pin mismatch')
        if json.loads(oldsummary)['records']!=plan['records']: raise ValueError('original case manifest changed')
        for tool,sha in plan['tools'].items():
            if digest(retained(path(tool)))!=sha: raise ValueError('retained setup tool changed: '+tool)
        records=[r for r in plan['records'] if r['status']!='PASS' and r['arm'] in ARMS]
        if len(records)!=count: raise ValueError('denominator changed')
        seen=set()
        for r in records:
            key=r['case']['mnemonic']+'-'+r['kind'] if suite.startswith('guard') else r['case']['id'];arm=r['arm']
            if (key,arm) in seen: raise ValueError('duplicate control')
            seen.add((key,arm));original=path(plan['original'])/key;run=root/'replay'/key/arm
            source=retained(original/'test.S');rawelf=retained(original/'test.elf')
            if digest(source)!=r['source_sha256'] or digest(rawelf)!=r['guest_sha256']: raise ValueError('source/ELF pin mismatch')
            expected=expectations(suite,r,rawelf,source.decode())
            receipts=json.loads(retained(root/'audit'/(key+'-RESULTS.json')));receipt=next(x for x in receipts if x['arm']==arm)
            cmdraw=retained(run/'command.json');execraw=retained(run/'execution.json');stdout=retained(run/'stdout');stderr=retained(run/'stderr');packet=retained(run/'packets.bin')
            command=json.loads(cmdraw);oldcommand=json.loads(retained(original/arm/'command.json'))
            identity=[]
            norm=lambda cmd:[x for x in cmd[1:] if not x.startswith(('--fsroot=','--cache=','--dump-tbmap='))]
            if command[0]!=ENGINE or norm(command)!=norm(oldcommand) or command[-2:]!=['--','/t.elf'] or f'--vlen={r["case"]["vlen"]}' not in command: identity.append('retained command target/flags mismatch')
            fs=f'--fsroot=/home/vick/rvv-task181/focused/{suite}/replay/work/{key}/{arm}/fs'
            if fs not in command: identity.append('wrong-target fsroot')
            for field,data in [('command_sha256',cmdraw),('execution_sha256',execraw),('raw_sha256',packet),('elf_sha256',rawelf)]:
                if receipt[field]!=digest(data): identity.append(field+' receipt mismatch')
            if packet!=stdout: identity.append('stdout/packet mismatch')
            result=adjudicate(expected,json.loads(execraw),stdout,stderr,identity)
            rows.append(dict(suite=suite,key=key,arm=arm,form=r['form'],original_receipt_status=receipt['status'],elf_sha256=digest(rawelf),command_sha256=digest(cmdraw),execution_sha256=digest(execraw),stdout_sha256=digest(stdout),stderr_sha256=digest(stderr),expected=expected,**result))
        if any({a for k,a in seen if k==key}!=set(ARMS) for key,_ in seen): raise ValueError('missing arm')
    counter=collections.Counter(r['category'] for r in rows)
    counts={k:counter[k] for k in ('EXACT_EXPECTED_FAULT','GENERIC_FAILURE','INSUFFICIENT_OBSERVATION','UNEXPECTED_SUCCESS')}
    result=dict(schema_version=1,controls=len(rows),counts=counts,by_suite={s:dict(collections.Counter(r['category'] for r in rows if r['suite']==s)) for s in ('guard165','guard166','faults')},architectural_fault_state_pass=0,store_memory_unobserved=sum(r['expected']['store'] for r in rows),positive_headline=dict(forms=595,checks=12071304,correction_delta=0,reaudited=False),new_execution_calls=0,rows=rows)
    output.mkdir(parents=True,exist_ok=True)
    (output/'RESULT.json.gz').write_bytes(gzip.compress((json.dumps(result,sort_keys=True,indent=2)+'\n').encode(),mtime=0))
    (output/'INPUTS.json.gz').write_bytes(gzip.compress((json.dumps(dict(files=inputs),sort_keys=True,indent=2)+'\n').encode(),mtime=0))
    (output/'SUMMARY.json').write_text(json.dumps({k:v for k,v in result.items() if k!='rows'},indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k!='rows'},indent=2))

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--mirror',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();audit(args.mirror,args.output)
