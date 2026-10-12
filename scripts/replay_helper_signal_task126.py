"""Eight original ELFs/configurations, original checkers and retained reference bytes.
No reference runs, guest compilation, guest body changes, retry, or new ISA answers.
"""
from pathlib import Path
import hashlib, json, os, resource, shlex, shutil, struct, subprocess, time, traceback
R=Path(__file__).resolve().parent

def H(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p): return json.loads(p.read_text())
def save(p,x): p.write_text(json.dumps(x,indent=2)+'\n')
def validator(p):
    scope={};exec(compile(p.read_text(),str(p),'exec'),scope);return scope['validate']
def main():
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    exe=R/'build/bin/elfrun';lib=R/'build/lib/libdbtjitshared.so'
    ident=read(R/'SOURCE_IDENTITY.json')
    assert all(H(R/'source'/p)==h for p,h in ident['files'].items())
    assert (R/'build-evidence/build.returncode.txt').read_text().strip()=='0'
    identity=dict(base_commit=ident['base_commit'],source_manifest_sha256=ident['manifest_sha256'],
                  executable=str(exe),executable_sha256=H(exe),library=str(lib),library_sha256=H(lib),
                  candidate_directory=str(R),scope='Task126 unchanged exit-only predicted-helper delivery/control; no native recovery or guest retry')
    save(R/'CANDIDATE_IDENTITY_BEFORE.json',identity)
    originals=read(R/'ORIGINAL_COMMANDS.json');specs=read(R/'ORIGINAL_SPECS.json');gates=read(R/'ORIGINAL_MEMORY_GATES.json')
    preflight=[];planned=[]
    for spec in specs:
        name=spec['name'];elf=R/'inputs'/f'{name}.elf';checker=R/'inputs'/f'{name}_checker.py';reference=R/'inputs'/f'{name}_reference_reused/stdout'
        assert H(elf)==spec['key']['elf_sha256'] and H(checker)==spec['key']['checker_sha256']
        gate=next(x for x in gates if x['name']==name)
        b=elf.read_bytes();assert b[:7]==b'\x7fELF\x01\x01\x01'
        e=struct.unpack_from('<HHIIIIIHHHHHH',b,16);assert e[:4]==(2,243,1,0x80000000)
        ph=[struct.unpack_from('<8I',b,e[4]+i*e[8]) for i in range(e[9])]
        for owner in gate['owning_objects']:
            assert any(p[0]==1 and p[6]&2 and p[2]<=owner['address'] and owner['address']+owner['bytes']<=p[2]+p[5] for p in ph)
        assert gate['observer_disjoint'] and gate['permission_restore_before_source_dump']
        assert not gate['source_body_changed'] and not gate['checker_changed']
        target=next(p for p in ph if p[0]==1 and p[2]<=spec['pc'] and spec['pc']+4<=p[2]+p[4])
        assert struct.unpack_from('<I',b,target[1]+spec['pc']-target[2])[0]==spec['raw']
        v=validator(checker)
        refstate=v(reference.read_bytes(),spec['original_case'],1024,spec['pc']) if name=='first_fault_none' else v(reference.read_bytes(),spec['original_case'],1024)
        preflight.append(dict(name=name,elf_sha256=H(elf),checker_sha256=H(checker),reference_sha256=H(reference),reference_checker_state=refstate,
                              inherited_memory_gate=gate,actual_elf_ownership_and_opcode_rechecked=True,
                              authorization='Task113 eight exit-only helper delivery/control regressions; old candidate gates preserved',
                              signal_frame_capacity='5088 bytes at VLEN1024; full runtime writable extent checked before publication'))
        for arm in ['B','M1','M2','BOTH']:
            d=R/'runs'/f'{name}_{arm}';d.mkdir(parents=True,exist_ok=False)
            (d/'fs').mkdir();(d/'cache').mkdir();shutil.copy2(elf,d/'fs/t.elf')
            cmd=originals[name][arm][:];cmd[0]=str(exe)
            for prefix,path in {'--fsroot=':d/'fs','--cache=':d/'cache','--translate-ip-out=':d/'translations.csv'}.items():
                cmd=[prefix+str(path) if x.startswith(prefix) else x for x in cmd]
            assert '--vlen=1024' in cmd and '--aot=0' in cmd and '--aot-use-llvm=0' in cmd
            save(d/'command.json',cmd);(d/'command.sh').write_text(shlex.join(cmd)+'\n')
            env=dict(os.environ);env['LD_LIBRARY_PATH']=str(lib.parent)
            save(d/'environment.json',dict(LD_LIBRARY_PATH=env['LD_LIBRARY_PATH'],cwd=str(d),timeout_seconds=30,core_limit=0))
            planned.append(dict(name=name,arm=arm,directory=str(d),command=cmd,identity=identity,elf_sha256=H(elf),checker_sha256=H(checker)))
    save(R/'PREFLIGHT.json',preflight);save(R/'PLANNED_CALLS.json',planned)
    ledger=[]
    for plan in planned:
        name=plan['name'];arm=plan['arm'];d=Path(plan['directory']);spec=next(x for x in specs if x['name']==name)
        reference=R/'inputs'/f'{name}_reference_reused/stdout';checker=R/'inputs'/f'{name}_checker.py';v=validator(checker)
        row=dict(name=name,arm=arm,state='STARTED',directory=str(d),command=plan['command']);ledger.append(row);save(R/'LAUNCH_LEDGER.json',ledger)
        env=dict(os.environ);env['LD_LIBRARY_PATH']=str(lib.parent);start=time.monotonic();launch_error=None
        with (d/'stdout').open('wb') as out,(d/'stderr').open('wb') as err:
            try: rc=subprocess.run(plan['command'],env=env,cwd=d,stdout=out,stderr=err,timeout=30).returncode
            except subprocess.TimeoutExpired: rc=None;launch_error='timeout'
            except Exception as exc: rc=None;launch_error=repr(exc)
        raw=(d/'stdout').read_bytes();ref=reference.read_bytes();stderr=(d/'stderr').read_text(errors='replace')
        mismatches=[i for i,(a,b) in enumerate(zip(raw,ref)) if a!=b]
        comparison=dict(actual_bytes=len(raw),reference_bytes=len(ref),byte_equal=raw==ref,
                        actual_sha256=H(d/'stdout'),reference_sha256=H(reference),
                        different_byte_offsets=mismatches,unpaired_actual_bytes=max(0,len(raw)-len(ref)),unpaired_reference_bytes=max(0,len(ref)-len(raw)))
        save(d/'raw_comparison.json',comparison)
        r=subprocess.run(['cmp','-l',str(d/'stdout'),str(reference)],capture_output=True)
        (d/'cmp.stdout').write_bytes(r.stdout);(d/'cmp.stderr').write_bytes(r.stderr)
        save(d/'cmp.command.json',dict(command=['cmp','-l',str(d/'stdout'),str(reference)],returncode=r.returncode))
        errors=[];actual=None
        try:
            actual=v(raw,spec['original_case'],1024,spec['pc']) if name=='first_fault_none' else v(raw,spec['original_case'],1024)
            save(d/'state.json',actual)
        except Exception:
            errors.append('original checker rejected output');(d/'checker_failure.txt').write_text(traceback.format_exc())
        if rc!=0: errors.append('guest exit was not zero')
        if launch_error:errors.append(launch_error)
        if raw!=ref:errors.append('complete packet differs from retained same-ELF reference')
        if any(x in stderr for x in ['Panic','ILLEGAL_INSN','BADFRAME','UNDELIVERABLE']):errors.append('fatal/undeliverable diagnostic')
        snapshots=[json.loads(x.split(' ',1)[1]) for x in stderr.splitlines() if x.startswith('RVDBT_MEMORY_FAULT_SNAPSHOT ')]
        if snapshots:save(d/'fault_snapshots.json',snapshots)
        delivered=stderr.count('RVDBT_SIGNAL_DELIVERED ');returned=stderr.count('RVDBT_SIGNAL_RETURNED ')
        if name=='first_fault_none':
            if delivered!=1 or 'signal=11 pc=80000168 ' not in stderr:errors.append('missing/duplicate expected delivery diagnostic')
            if len(snapshots)!=1:errors.append('missing/duplicate helper snapshot')
        elif delivered or snapshots:errors.append('later FOF unexpectedly signalled')
        if returned:errors.append('unexpected sigreturn in exit-only inputs')
        passed=not errors
        result=dict(name=name,arm=arm,vlen=1024,returncode=rc,elapsed_seconds=time.monotonic()-start,
                    classification=('ORIGINAL_HANDLER_CHECKER_PASS' if name=='first_fault_none' else 'ORIGINAL_LATER_SUCCESS_CONTROL_PASS') if passed else 'FAILED',
                    passed=passed,errors=errors,original_checker_pass=actual is not None,raw_byte_equal=raw==ref,
                    stdout_sha256=H(d/'stdout'),stderr_sha256=H(d/'stderr'),guest_handler_reached=(name=='first_fault_none' and actual is not None and rc==0),
                    signal_deliveries=delivered,sigreturn_guest_executed=bool(returned),reference_calls=0,guest_compiler_calls=0,generator_calls=0,
                    native_admission_established=False,retry_established=False)
        save(d/'result.json',result);row.update(state='COMPLETED' if passed else 'FAILED',result=result);save(R/'LAUNCH_LEDGER.json',ledger)
        print(json.dumps(result),flush=True)
    assert all(H(R/'source'/p)==h for p,h in ident['files'].items()) and H(exe)==identity['executable_sha256'] and H(lib)==identity['library_sha256']
    save(R/'CANDIDATE_IDENTITY_AFTER.json',identity)
    save(R/'SUMMARY.json',dict(candidate=identity,guest_calls=len(ledger),pass_count=sum(x['result']['passed'] for x in ledger),failure_count=sum(not x['result']['passed'] for x in ledger),
                              reference_calls=0,guest_compiler_calls=0,generator_calls=0,results=[x['result'] for x in ledger]))
if __name__=='__main__':main()
