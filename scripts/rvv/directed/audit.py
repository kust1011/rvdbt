#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline complete denominator, raw predicate, target and adapter audit."""
import argparse, collections, csv, gzip, hashlib, importlib.util, json, struct
from pathlib import Path
spec=importlib.util.spec_from_file_location('vadd',Path(__file__).with_name('vadd.py'))
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
def elf_sections_symbols(path):
    raw=v.storage.verify(path)
    if raw[:7]!=b'\x7fELF\x01\x01\x01': raise ValueError('not RV32 little endian ELF')
    if struct.unpack_from('<H',raw,18)[0]!=243: raise ValueError('not RISC-V')
    start=struct.unpack_from('<I',raw,32)[0];stride,n,strings=struct.unpack_from('<3H',raw,46)
    headers=[struct.unpack_from('<10I',raw,start+i*stride) for i in range(n)]
    h=headers[strings];names=raw[h[4]:h[4]+h[5]];sections={};symbols={}
    for h in headers:
        name=names[h[0]:].split(b'\0',1)[0].decode();sections[name]=(h[3],raw[h[4]:h[4]+h[5]])
        if h[1]==2:
            st=headers[h[6]];table=raw[st[4]:st[4]+st[5]]
            for offset in range(h[4],h[4]+h[5],h[9]):
                pos,value,size,info,other,section=struct.unpack_from('<3I2BH',raw,offset)
                name=table[pos:].split(b'\0',1)[0].decode();symbols[name]=value
    return sections,symbols

def audit(root,out):
    v.storage.reserve(out.parent,1024**3)
    out.mkdir(parents=True,exist_ok=False)
    manifest=json.loads((root/'manifest.json').read_text());cases=manifest['cases'];results=json.loads((root/'results.json').read_text())
    regenerated=v.manifest_cases(manifest.get("family","vadd145"))
    for i,c in enumerate(regenerated):c['ordinal']=i
    if 'pilot_units' in manifest:
        selected=set(manifest['pilot_units'])
        if not selected <= {c['unit'] for c in regenerated}: raise ValueError('unknown pilot unit')
        regenerated=[c for c in regenerated if c['unit'] in selected]
    if regenerated!=cases:raise ValueError('manifest differs from finite generator')
    ids={c['id']:c for c in cases};units=collections.defaultdict(list)
    for c in cases:units[c['unit']].append(c)
    if len(ids)!=len(cases):raise ValueError('duplicate case')
    expected={(c['id'],arm) for c in cases for arm in ['Reference','B','M1','M2','BOTH']}
    observed={(r['case'],r['arm']) for r in results}
    receipts={(r['case'],r['arm']):r for r in results}
    if observed!=expected or len(results)!=len(expected):raise ValueError('missing/duplicate result')
    builds=json.loads((root/'build-commands.json').read_text());pins={}
    for r in builds:
        p=Path(r['command'][-1]);file=root/p.parent.name/p.name
        if r['returncode']!=0 or v.sha(file)!=r['elf_sha256']:raise ValueError('guest build/pin changed')
        pins[str(file.relative_to(root))]=v.sha(file)
    adapter=[]
    for unit,cs in units.items():
        source=root/unit/'test.S'
        if v.storage.text(source)!=v.assembly(cs):raise ValueError('generated source mismatch')
        user,syms=elf_sections_symbols(root/unit/'test.elf')
        targets=[]
        for c in cs:
            pc=syms['target_'+str(c['ordinal'])];textaddr,code=user['.text'];insn=code[pc-textaddr:pc-textaddr+4]
            word=int.from_bytes(insn,'little')
            if c.get('family') in ('configuration147','configuration148'):
                import config
                if word&127!=0x57 or (word>>12)&7!=7 or (word>>7)&31!=c['rd']:raise ValueError('configuration opcode/rd mismatch')
                if c['form']=='vsetvli':
                    valid=word>>31==0 and (word>>15)&31==c['rs1'] and (word>>20)&2047==c['new_vtype']
                elif c['form']=='vsetivli':
                    valid=word>>30==3 and (word>>15)&31==c['avl'] and (word>>20)&1023==c['new_vtype']
                else:
                    valid=word>>25==0x40 and (word>>15)&31==c['rs1'] and (word>>20)&31==c['rs2']
                if not valid:raise ValueError('configuration form/operand mismatch')
                expected_word=word
            elif c.get('family') in ('fp157','fma164'):
                import fp157
                expected_word=fp157.instruction(c)
            elif c.get('family')=='extend156':
                import extend156_next
                expected_word=extend156_next.instruction(c)
            elif c.get('family')=='wmac156':
                import wmac156
                expected_word=wmac156.instruction(c)
            elif c.get('family')=='widen154':
                import widen154_next
                expected_word=widen154_next.instruction(c)
            elif c.get('family')=='mac154':
                import mac152_next
                expected_word=mac152_next.instruction(c)
            elif c.get('family')=='compare152':
                import compare151_next
                expected_word=compare151_next.instruction(c)
            elif c.get('family')=='mergemove151':
                import mergemove150_next
                expected_word=mergemove150_next.instruction(c)
            elif c.get('family')=='carry150':
                import carry149_next
                expected_word=carry149_next.instruction(c)
            else:
                f3={'vv':0,'vx':4,'vi':3}[c['form']]
                if c.get('family')=='muldiv149':f3={'vv':2,'vx':6}[c['form']]
                operand=c['vs1'] if c['form']=='vv' else 8 if c['form']=='vx' else c['operand']&31
                funct6=v.FUNCT6
                if c.get('family')=='shiftminmax148':
                    import shift148
                    funct6=shift148.FUNCT6
                if c.get('family')=='muldiv149':
                    import muldiv149
                    funct6=muldiv149.FUNCT6
                expected_word=(funct6[c.get('mnemonic','vadd')]<<26)|(int(c['mask']=='none')<<25)|(c['vs2']<<20)|(operand<<15)|(f3<<12)|(c['vd']<<7)|0x57
            if word!=expected_word:raise ValueError('target opcode mismatch')
            targets.append(dict(case=c['id'],user_pc=hex(pc),instruction_hex=insn.hex()))
        if cs[0]['vstart']:
            machine,msyms=elf_sections_symbols(root/unit/'sail.elf')
            if user['.data'][1]!=machine['.data'][1]:raise ValueError('adapter data changed')
            # Preprocessor guards occur only at initialization and terminal IO.
            lines=v.storage.text(source).splitlines();guards=[i for i,l in enumerate(lines) if l.startswith('#')]
            if len(guards)!=5:raise ValueError('unexpected conditional adaptation')
            body='\n'.join(lines[guards[1]+1:guards[2]])+'\n'
            if any(line.lstrip().startswith('#') for line in body.splitlines()):raise ValueError('adaptation inside shared capture/target body')
            for t,c in zip(targets,cs):
                pc=msyms['target_'+str(c['ordinal'])];base,code=machine['.text']
                if code[pc-base:pc-base+4].hex()!=t['instruction_hex']:raise ValueError('adapter target changed')
                t['sail_pc']=hex(pc)
            adapter.append(dict(unit=unit,shared_body_sha256=hashlib.sha256(body.encode()).hexdigest(),data_sha256=hashlib.sha256(user['.data'][1]).hexdigest(),completion_pc=v.sail_stop(root/unit/'sail.elf'),targets=targets))
        v.save(out/(unit+'-targets.json'),targets)
    # Validate EVERY retained raw packet independently of the runner PASS labels.
    rows=[];counts=collections.Counter();first_failures=[];runtime=0;command_count=0
    for unit,cs in units.items():
        size=v.packet_size(cs[0]);ref=root/'runs'/unit/'Reference'/'packets.bin';refraw=v.storage.verify(ref)
        refrec=json.loads((ref.parent/'execution.json').read_text());reference_valid=True
        try:
            if len(refraw)!=len(cs)*size: raise ValueError('reference output extent')
            for i,c in enumerate(cs):v.check_isa(c,refraw[i*size:(i+1)*size],refrec['returncode'],refrec['timeout'])
        except ValueError:reference_valid=False
        for arm in ['Reference','B','M1','M2','BOTH']:
            d=root/'runs'/unit/arm;r=json.loads((d/'execution.json').read_text());runtime+=r['seconds'];command_count+=1
            if v.sha(d/'stdout')!=r['stdout_sha256'] or v.sha(d/'stderr')!=r['stderr_sha256']:raise ValueError('raw stream hash mismatch')
            raw=v.storage.verify(d/'packets.bin')
            if arm=='Reference' and cs[0]['vstart']:
                extracted=b''.join(int(line,16).to_bytes(4,'little') for line in v.storage.text(d/'signature').splitlines())
            else:extracted=v.storage.verify(d/'stdout')
            if raw!=extracted:raise ValueError('packet extraction mismatch')
            for i,c in enumerate(cs):
                packet=raw[i*size:(i+1)*size];error=None;isa_status='NOT_RUN';reference_status='ORACLE_PACKET' if arm=='Reference' else 'BLOCKED'
                try:
                    if len(raw)!=len(cs)*size:raise ValueError('output extent')
                    v.check_isa(c,packet,r['returncode'],r['timeout']);isa_status='PASS'
                    if arm!='Reference' and reference_valid:
                        reference_status='FAIL';v.check_reference(c,packet,refraw[i*size:(i+1)*size]);reference_status='PASS'
                except ValueError as e:
                    error=str(e)
                    if isa_status!='PASS':isa_status='FAIL'
                status='FAIL' if error else 'ISA_ONLY_REFERENCE_BLOCKED' if arm!='Reference' and not reference_valid else 'PASS'
                receipt=receipts[(c['id'],arm)]
                if receipt['status']!=status:raise ValueError('runner/audit status mismatch')
                if 'isa_status' in receipt and (receipt['isa_status']!=isa_status or receipt['reference_status']!=reference_status):raise ValueError('runner/audit oracle separation mismatch')
                counts[(arm,status)]+=1
                if error:first_failures.append(dict(case=c['id'],arm=arm,error=error))
                observed=v.decode(c,packet) if len(packet)==size else None
                rows.append(dict(case=c['id'],arm=arm,status=status,isa_status=isa_status,reference_status=reference_status,vstart_class=c.get('classification', 'zero-start' if c['vstart']==0 else 'reserved-start-profile' if c['vstart']>=c['vlmax'] else 'ordinary-nonzero-start'),pre_csrs=json.dumps(observed[0]) if observed else '',post_csrs=json.dumps(observed[1]) if observed else '',pre_register_sha256=hashlib.sha256(observed[2]).hexdigest() if observed else '',post_register_sha256=hashlib.sha256(observed[3]).hexdigest() if observed else '',raw=str((d/'packets.bin').relative_to(root)),offset=i*size,bytes=size,oracle='Sail0.14.1+ISA' if c['vstart'] else 'Spike20feb9c2+ISA'))
    if manifest.get('family') in ('configuration147','configuration148'):
        for row in rows:
            classification=ids[row['case']]['classification']
            row['semantic_status']=row['status'] if row['status']!='PASS' else 'OBSERVED_RESERVED' if classification=='reserved-preserve' else 'PROFILE_PASS' if classification=='reserved-vstart-profile' else 'PROFILE_UNSUPPORTED_VTYPE' if classification=='unsupported-vtype' and manifest.get('family')=='configuration148' else 'PASS'
    if manifest.get('family') in ('shiftminmax148','muldiv149','carry150','mergemove151','compare152','mac154','widen154','mac154qemu','wmac156','extend156','wmac156chunk','fp157','fma164'):
        for row in rows:
            c=ids[row['case']]
            row['semantic_status']=row['status'] if row['status']!='PASS' else 'PROFILE_RESERVED_START' if c['vstart']>=c['vlmax'] else 'PASS'
    with gzip.open(out/'observed-checks.csv.gz','wt') as f:
        writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
    v.save(out/'adapter-verification.json',adapter);v.save(out/'guest-pins.json',pins)
    v.save(out/'audit.json',dict(planned_cases=len(cases),executed_case_checks=len(rows),planned_commands=len(units)*5,executed_commands=command_count,aggregate_command_seconds=runtime,counts={a:{s:counts[(a,s)] for s in ['PASS','FAIL','ISA_ONLY_REFERENCE_BLOCKED']} for a in ['Reference','B','M1','M2','BOTH']},failures=first_failures,adapter_verified_units=len(adapter),full_state='32 vector registers, 10 CSRs and actual rd pre/post' if manifest.get('family') in ('configuration147','configuration148') else '32 vector registers, 10 CSRs, scalar s0 and fs0 raw bits pre/post' if manifest.get('family') in ('fp157','fma164') else '32 vector registers, 10 CSRs and scalar s0 pre/post',method_admission='NOT claimed; flags and aggregate counters do not identify per-target M1/M2 admission'))
    if manifest.get('family') in ('configuration147','configuration148'):
        import config
        deterministic=config.determinism(root);v.save(out/'determinism.json',deterministic)
        if deterministic['failures']: raise ValueError('configuration determinism failures')
    print(dict(counts))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('root',type=Path);p.add_argument('output',type=Path);a=p.parse_args();audit(a.root,a.output)
