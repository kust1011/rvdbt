#!/usr/bin/env python3
"""Read-only Task198 source/receipt adjudication; never launches an ISA guest."""
import gzip
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import tarfile

ROOT = pathlib.Path(__file__).resolve().parents[3]
OUT = pathlib.Path(__file__).parent / 'CLOSURE198_EVIDENCE.json'
TMP = pathlib.Path(os.environ.get('RVV_REVIEW198_INPUTS', '/tmp/task198-review'))


def sha(b):
    return hashlib.sha256(b).hexdigest()


def main():
    assert shutil.disk_usage(ROOT).free >= 10 * 1024**3
    available = int(re.search(r'MemAvailable:\s+(\d+)', pathlib.Path('/proc/meminfo').read_text())[1]) * 1024
    assert available >= 10 * 1024**3 and os.getpriority(os.PRIO_PROCESS, 0) == 10
    evidence = dict(base='4ad13da7a0a973623e8e51c683b2328bfba47f1b',
                    new_compiler_calls=0, new_guest_calls=0,
                    new_reference_calls=0, original_predicates_changed=False)
    archive = ROOT / 'docs/rvv-validation/ara-review-task91/ara-review-task91.tar.gz'
    ara = []
    with tarfile.open(archive) as t:
        header = t.extractfile('records/ara-remainder52/adapter/vector_macros.h').read()
        evidence['ara_diagnostic_header_sha256'] = sha(header)
        evidence['ara_diagnostic'] = '%x receives uint64_t arguments; the failure branch compares uint64_t, but printed fields are not full values'
        for name in ['vmacc', 'vmadd', 'vnmsac', 'vnmsub']:
            path = 'sources/apps/riscv-tests/isa/rv64uv/' + name + '.c'
            raw = t.extractfile(path).read()
            adapter = t.extractfile('records/ara-remainder52/adapter/batch_' + name + '.c').read()
            cases = []
            for fn in [3, 4]:
                s = raw.decode().split('void TEST_CASE' + str(fn) + '()')[1].split('\nvoid ')[0].split('\nint main')[0]
                s = s.split('VSET(16, e64, m1);')[1]
                scalar = int(re.search(r'scalar = (-?\d+);', s)[1])
                x32 = scalar & 0xffffffff
                if x32 >= 1 << 31:
                    x32 -= 1 << 32
                vectors = {reg: [int(x.strip(), 0) for x in data.split(',')]
                           for reg, data in re.findall(r'VLOAD_64\((v\d+), (.*?)\);', s, re.S)}
                target = re.search(r'asm volatile\("(.*?)"', s)[1]
                dest, source = re.search(r'\.vx (v\d+), %\[A\], (v\d+)', target).groups()
                a, z = vectors[dest], vectors[source]
                literal = [int(x.strip(), 0) for x in re.search(r'VCMP_U64\(\d+, v\d+, (.*?)\);', s, re.S)[1].split(',')]
                mask = (1 << 64) - 1
                def calculate(scalar_value):
                    result = []
                    for i, (old, src) in enumerate(zip(a, z)):
                        if fn == 4 and i % 2 == 0:
                            value = old
                        elif name == 'vmacc':
                            value = old + scalar_value * src
                        elif name == 'vmadd':
                            value = scalar_value * old + src
                        elif name == 'vnmsac':
                            value = old - scalar_value * src
                        else:
                            value = -scalar_value * old + src
                        result.append(value & mask)
                    return result
                rv64, rv32 = calculate(scalar), calculate(x32)
                assert rv64 == literal
                active = list(range(16)) if fn == 3 else list(range(1, 16, 2))
                assert all(rv32[i] != literal[i] for i in active)
                first = active[0]
                cases.append(dict(function='TEST_CASE' + str(fn), target=target,
                                  source_line=raw.decode()[:raw.decode().index('void TEST_CASE' + str(fn))].count('\n') + 1,
                                  original_scalar=scalar, rv32_scalar=x32,
                                  rv64_all_literals_match=True,
                                  rv32_active_literal_mismatches=len(active),
                                  first_lane=first,
                                  first_literal=f'{literal[first]:016x}',
                                  first_rv32_spec_value=f'{rv32[first]:016x}',
                                  classification='PROFILE_INAPPLICABLE_RV64_SCALAR_ASSERTION'))
            receipts = []
            for arm in ['B', 'M1', 'M2', 'BOTH']:
                p = 'records/ara-remainder52/remote-raw/batch_' + name + '/' + arm + '/stdout'
                stream = t.extractfile(p).read()
                failures = re.findall(r'Index .* FAILED.*', stream.decode())
                assert len(failures) == 2
                receipts.append(dict(arm=arm, path=p, sha256=sha(stream), failed_predicates=failures))
            ara.append(dict(form=name + '.vx', source=path, source_sha256=sha(raw),
                            adapter_sha256=sha(adapter), cases=cases, receipts=receipts,
                            whole_file_pass=False, accepted_scope='TEST_CASE1_2_ONLY',
                            actual_full64_result_observed=False))
    evidence['ara'] = ara
    evidence['act_original_diagnosis'] = json.loads((TMP / 'BLOCKER_DIAGNOSIS.json').read_bytes())
    evidence['act_original_reference_diagnostics'] = json.loads((TMP / 'REFERENCE_DIAGNOSTICS.json').read_bytes())
    act = []
    for width in [32, 64]:
        p = TMP / f'Vf{width}-vfmv.f.s.S'
        raw = p.read_bytes()
        s = raw.decode()
        start = s.index('# Testcase cp_custom_vfp_state')
        end = s.index('# Testcase', start + 1)
        result = json.loads((TMP / ('RESULT.json' if width == 32 else 'RESULT64.json')).read_bytes())
        assert result['source_sha256'] == sha(raw)
        assert result['DUT'] == [] and result['reference'][1]['returncode'] == -4
        act.append(dict(case=result['case'], source_sha256=sha(raw),
                        source_line=s[:start].count('\n') + 1, original_window=s[start:end],
                        elf_sha256=result['elf_sha256'], checker_sha256=result['checker_sha256'],
                        original_result=result, classification='REFERENCE_TOOL_PLATFORM_PROBLEM',
                        profile_disposition='FS-state privileged setup inapplicable to declared user execution environment; vfmv.f.s FP32/64 remains applicable',
                        whole_file_pass=False, withheld_DUT_arm_slots=4))
    evidence['act'] = act
    header = (TMP / 'signature.h').read_bytes()
    assert sha(header) == act[0]['checker_sha256']
    evidence['act_assertion_header'] = dict(sha256=sha(header),
        scalar_FP_value='RVTEST_SIGUPD_F stores FP value and compares both RV32 words when FLEN>XLEN',
        flags='RVTEST_SIGUPD_FFLAGS reads fflags and compares original signature',
        FS_state_observed=False)
    evidence['act_original_trace_ends'] = [dict(width=width,
        sha256=sha((TMP / f'trace{width}').read_bytes()),
        last_lines=(TMP / f'trace{width}').read_text().splitlines()[-18:]) for width in [32, 64]]
    plan = json.loads(gzip.decompress((OUT.parent / 'DIRECTED_PLAN.json.gz').read_bytes()))
    # Select only four old semantic questions. No matrix predicate replay.
    selections = [('b159-016', 'tie'), ('b169-055', 'whole'),
                  ('b168-039', 'mask'), ('b159-015', 'logic')]
    joins = []
    for entryid, kind in selections:
        e = next(x for x in plan['entries'] if x['id'] == entryid)
        code = '''import pathlib,json,hashlib,shutil,re,os
assert shutil.disk_usage('/home/vick').free >= 10*1024**3
assert int(re.search(r'MemAvailable:\\s+(\\d+)',pathlib.Path('/proc/meminfo').read_text())[1])*1024 >= 10*1024**3
assert os.getpriority(os.PRIO_PROCESS,0)==10
p=pathlib.Path(ROOT)/'manifest.json';b=p.read_bytes();o=json.loads(b);cs=o if isinstance(o,list) else o['cases']
selected=[]
for i,c in enumerate(cs):
 yes=(KIND=='tie' and c['mnemonic']=='vsmul' and c['form']=='vx' and c['sew']==8 and c['vlen']==128 and c.get('pair_override')==[1,64] and c['vxrm_initial'] in [0,1]) or (KIND=='whole' and c.get('kind')=='whole' and c['vstart']==1 and c['sew']==8 and c['mnemonic']=='vmv1r') or (KIND=='mask' and c.get('kind')=='mask' and c.get('store') and c['vlen']==128 and c['vl']==9 and c['sew']==8 and c['lmul']=='m1') or (KIND=='logic' and c['mnemonic']=='vmand' and c['vlen']==128 and c['sew']==8 and c['lmul']=='m1' and c['vl']==9 and c['vstart']==0)
 if yes and len(selected)<2:selected.append(dict(index=i,case=c))
print(json.dumps(dict(manifest_sha256=hashlib.sha256(b).hexdigest(),declarations=len(cs),selected=selected)))
'''.replace('ROOT', repr(e['original'])).replace('KIND', repr(kind))
        command = ['python3', '-'] if os.environ.get('RVV_REVIEW198_ON_XBD') == '1' else ['ssh', 'xbd', 'nice -n 10 python3 -']
        r = subprocess.run(command, input=code,
                           text=True, capture_output=True, check=True)
        result = json.loads(r.stdout)
        assert result['manifest_sha256'] == e['manifest_sha256']
        assert result['selected']
        for row in result['selected']:
            assert row['index'] in e['accepted_indices']
            row['accepted181'] = True
        joins.append(dict(entry=entryid, kind=kind, original_root=e['original'], **result))
    evidence['old_semantic_question_joins'] = joins
    old = json.loads((ROOT / 'docs/rvv-validation/obligations-task187/EVIDENCE_REVIEW.json').read_bytes())
    evidence['mandatory_nonzero_start_trap_gap'] = dict(
        source='docs/rvv-validation/obligations-task187/EVIDENCE_REVIEW.json',
        forms=old['no_successful_nonzero_vstart_forms'],
        required_forms=23, accepted181_architectural_trap_cases=0,
        declaration_status='NOT_RUN in mask158, prefix169, reduction163, permute162; fpreduce174 requires vstart=0',
        smallest_handoff=dict(form='vcompress.vm', raw='5f08a457',
                             setup='VLEN128, e8/m1, VL0, vstart1, vd8, vs2=16, selector17; disjoint legal operands',
                             required='ILLEGAL_INSN at original PC/raw; no vector/CSR/GPR writes; vstart preserved by section3.7 illegal-instruction rule',
                             execution='NOT_AUTHORED_NOT_EXECUTED', recovery=False))
    evidence['reviewer_resource_gate'] = dict(nice=10, available_RAM_bytes=available,
        free_disk_bytes=shutil.disk_usage(ROOT).free, affinity_assigned=False,
        compiler_concurrency=0, guest_concurrency=0, read_only_remote_workers=1)
    evidence['denominators'] = dict(accepted_forms=595, inventory_forms=627,
                                    rv32_ei64_exclusions=32, ordinary_cases_per_arm=3017262,
                                    focused_positive_cases_per_arm=564, positive_DUT_checks=12071304,
                                    original_external_calls=21316, ACT_accepted_calls=7668,
                                    ACT_blocked_files=2, ACT_withheld_arm_slots=8,
                                    ARA_whole_file_calls=1888, ARA_scoped_calls=16,
                                    ARA_failed_e64_function_arm_observations=32)
    evidence['spec'] = dict(revision='6ee57d8997021aaa8025e208164763fe12e03c19',
                            path='src/v-st-ext.adoc', sha256=sha((TMP / 'v-st-ext.adoc').read_bytes()),
                            clauses=['11.1 XLEN<SEW sign extension', '10 FS context status',
                                     '18.3 RV32 index EEW64 exclusion'])
    OUT.write_text(json.dumps(evidence, indent=2) + '\n')
    print('Task198 source/receipt joins verified; zero guest/reference/compiler calls')


if __name__ == '__main__':
    main()
