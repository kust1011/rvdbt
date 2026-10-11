"""Offline evidence joins for the existing readable inventory. No subprocess or engines.

A program receipt establishes execution of a program, not execution/influence of
all its opcodes. Target/checker bindings and coupled endpoints are separate sets.
"""
import collections
import csv
import hashlib
import io
import json
import re
import struct
from pathlib import Path

UNKNOWN = 'UNKNOWN'
STAGES = ('source_present', 'compiled_source', 'emitted', 'program_executed',
          'executed_without_independent_form_check', 'result_checked', 'coupled_endpoint',
          'diagnostic_only', 'failed_or_blocked')
SPEC = 'artifacts/segment_stride_fields_20261007/spec/v-spec.adoc'
# Audited assembler pseudos; operand permutation is retained, never a new form.
PSEUDOS = {
    'vfabs.v': ('vfsgnjx.vv', '3608; vd,vs,vs'),
    'vfneg.v': ('vfsgnjn.vv', '3602-3605; vd,vs,vs'),
    'vneg.v': ('vrsub.vx', '2391; vd,vs,x0'),
    'vnot.v': ('vxor.vi', '2588; vd,vs,-1'),
    'vncvt.x.x.w': ('vnsrl.wx', '2643; vd,vs,x0'),
    'vwcvt.x.x.v': ('vwadd.vx', '2427; vd,vs,x0'),
    'vwcvtu.x.x.v': ('vwaddu.vx', '2427-2428; vd,vs,x0'),
    'vmfgt.vv': ('vmflt.vv', '3658; swap vector sources'),
    'vmfge.vv': ('vmfle.vv', '3659; swap vector sources'),
    'vmsgt.vv': ('vmslt.vv', '2706; swap vector sources'),
    'vmsgtu.vv': ('vmsltu.vv', '2706; swap vector sources'),
    'vmsge.vv': ('vmsle.vv', '2707; swap vector sources'),
    'vmsgeu.vv': ('vmsleu.vv', '2707; swap vector sources'),
    'vmmv.m': ('vmand.mm', '4071; duplicate source'),
    'vmclr.m': ('vmxor.mm', '4072; all operands destination'),
    'vmset.m': ('vmxnor.mm', '4073; all operands destination'),
    'vmnot.m': ('vmnand.mm', '4074; duplicate source'),
}


def js(x):
    return json.dumps(x, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def csv_bytes(rows, fields):
    b = io.StringIO(newline='')
    w = csv.DictWriter(b, fields, lineterminator='\n')
    w.writeheader(); w.writerows(rows)
    return b.getvalue().encode()


def tokens(value):
    if value.startswith('['):
        return json.loads(value)
    return value.removeprefix('STATIC_PRESENCE_ONLY:').split(';')


class EncodingIndex:
    """Match retained rv_v fields, including nf expansion and vm-specific forms.

    ELF parsing only visits executable sections at instruction boundaries. It does
    not execute code or infer branch reachability. Symbol membership is static.
    """
    def __init__(self, text, names):
        self.table = collections.defaultdict(list)
        self.names = names
        for line, raw in enumerate(text.splitlines(), 1):
            fields = raw.split('#')[0].split()
            if not fields or fields[0].startswith('$'): continue
            name = fields[0]; mask = match = 0
            for part in fields[1:]:
                m = re.fullmatch(r'(\d+)(?:\.\.(\d+))?=(0x[0-9a-fA-F]+|\d+)', part)
                if m:
                    hi, lo = int(m[1]), int(m[2] or m[1])
                    bits = ((1 << (hi-lo+1))-1) << lo
                    mask |= bits; match |= int(m[3], 0) << lo
            assert mask & 127 == 127
            self.table[match & 127].append((name, mask, match, 'nf' in fields, line))

    def decode(self, word):
        for name, mask, match, nf, line in self.table.get(word & 127, []):
            if word & mask != match: continue
            if nf and (n := 1 + (word >> 29 & 7)) > 1:
                for pat, replacement in (
                    (r'vle(\d+)(ff)?\.v', lambda m: f'vlseg{n}e{m[1]}{m[2] or ""}.v'),
                    (r'vse(\d+)\.v', lambda m: f'vsseg{n}e{m[1]}.v'),
                    (r'vlse(\d+)\.v', lambda m: f'vlsseg{n}e{m[1]}.v'),
                    (r'vsse(\d+)\.v', lambda m: f'vssseg{n}e{m[1]}.v'),
                    (r'(v[ls](?:ux|ox))ei(\d+)\.v', lambda m: f'{m[1]}seg{n}ei{m[2]}.v')):
                    if m := re.fullmatch(pat, name): name = replacement(m); break
            assert name in self.names, name
            role = ('configuration' if name.startswith('vset') else
                    'v0 carry/borrow operand' if name.startswith(('vadc.', 'vsbc.')) else
                    'v0 selection operand' if name.startswith(('vmerge.', 'vfmerge.')) else
                    'v0 carry/borrow operand' if name.startswith(('vmadc.', 'vmsbc.')) and name.endswith('m') else
                    'unmasked' if word >> 25 & 1 else 'masked v0.t')
            return name, role, line
        return None

    def elf(self, data):
        assert data[:6] == b'\x7fELF\x01\x01', 'requires little-endian ELF32'
        assert struct.unpack_from('<H', data, 18)[0] == 243, 'requires RISC-V ELF'
        offset = struct.unpack_from('<I', data, 32)[0]
        size, count = struct.unpack_from('<HH', data, 46)
        assert size == 40
        sections = [struct.unpack_from('<10I', data, offset+i*size) for i in range(count)]
        symbols = []
        for sec in sections:
            if sec[1] != 2: continue
            strings = sections[sec[6]]; names = data[strings[4]:strings[4]+strings[5]]
            for p in range(sec[4], sec[4]+sec[5], sec[9]):
                n, start, length, info, _, shndx = struct.unpack_from('<IIIBBH', data, p)
                if info & 15 == 2 and length and shndx < count:
                    label = names[n:].split(b'\0', 1)[0].decode()
                    symbols.append((start, start+length, label))
        out = collections.defaultdict(lambda: collections.defaultdict(set))
        configs = set()
        for sec in sections:
            if not sec[2] & 4 or sec[1] != 1: continue
            pos, end = sec[4], sec[4]+sec[5]
            while pos+2 <= end:
                half = int.from_bytes(data[pos:pos+2], 'little')
                length = 2 if half & 3 != 3 else 4 if half & 31 != 31 else 6 if half & 63 == 31 else 8
                if length == 4 and pos+4 <= end:
                    word = int.from_bytes(data[pos:pos+4], 'little'); d = self.decode(word)
                    if d:
                        form, role, line = d; pc = sec[3]+pos-sec[4]
                        function = next((s[2] for s in symbols if s[0] <= pc < s[1]), '<no-function-symbol>')
                        out[function][form].add(role)
                        if form in {'vsetvli', 'vsetivli'}:
                            vtype = word >> 20 & (1023 if form == 'vsetivli' else 2047)
                            sew = 8 << (vtype >> 3 & 7); lm = vtype & 7
                            configs.add((str(sew), {0:'m1',1:'m2',2:'m4',3:'m8',5:'mf8',6:'mf4',7:'mf2'}.get(lm, 'reserved'),
                                         'ta' if vtype & 64 else 'tu', 'ma' if vtype & 128 else 'mu'))
                pos += length
        return dict(functions={k:{f:sorted(roles) for f,roles in sorted(v.items())} for k,v in sorted(out.items())},
                    literal_vtypes=sorted(configs), scope='STATIC_ONLY: literal vtypes are not runtime VL/branch/influence observations')


class ActualValidation:
    def __init__(self, inventory):
        self.i = inventory
        inventory.read('actual_form_validation.py')
        inventory.read('test_actual_form_validation.py')
        inventory.read(SPEC)
        self.root = inventory.root
        self.W = inventory.evidence_root
        self.D = self.W/'artifacts/rvv_validation_delivery_20261009'
        self.names = inventory.names
        self.aliases = {k:(v['form'], 'ara/ALIAS_RULES.json; spec lines '+v['spec_lines'])
                        for k,v in inventory.j('ara/ALIAS_RULES.json').items()}
        self.aliases.update({k:(v[0], SPEC+':'+v[1]) for k,v in PSEUDOS.items()})
        for n in (1,2,4,8): self.aliases[f'vl{n}r.v'] = (f'vl{n}re8.v', SPEC+':2065; EEW8 whole-load pseudo')
        self.decoder = EncodingIndex(inventory.read('artifacts/rvv_opcode_audit_20261006/rv_v').decode(), self.names)
        self.rows = inventory.rows('SUITE_RUN_MANIFEST.csv')
        self.suites = sorted({r['suite'] for r in self.rows})
        self.sets = {s:{stage:set() for stage in STAGES} for s in self.suites}
        self.candidates = collections.defaultdict(lambda: {stage:set() for stage in STAGES})
        self.bindings = []; self.missing = []; self.decoded = {}; self.elf_paths = {}
        self.corrections = {x['superseded_ELF']:x for x in inventory.j('artifacts/rvv_validation_delivery_20261009/rif-interface67/policy-preserved/CORRECTIONS.json')}
        self.roster = {x['root']:x for x in inventory.j('artifacts/rvv_validation_delivery_20261009/rif-generation64/ROSTER_FROZEN.json')}
        self.atg = {self.locator(x['body']):x for x in inventory.j('artifacts/rvv_validation_delivery_20261009/atg-generation62/OUTPUT_MANIFEST.json') if x.get('body')}
        self.atg_inputs = {x['id']:x for x in inventory.j('artifacts/rvv_validation_delivery_20261009/atg-generation62/INPUTS_FROZEN.json')}
        # Existing source-target/checker records supply exact same-ELF contexts.
        self.scope_index = collections.defaultdict(set)
        self.scope_fields = ('target_instruction','SEW','LMUL','VLEN','VL','AVL_source','mask','policy','initial_vstart_source','source_target_lines','checker_lines','configuration_evidence')
        for x in inventory.suite_rows:
            if x['elf_sha256'] not in {'UNKNOWN','待查',''}:
                self.scope_index[x['suite'],x['elf_sha256']].add(tuple(x.get(k,UNKNOWN)for k in self.scope_fields))
        self.ara_targets = inventory.rows('ara/ASSERTION_TARGETS.csv')
        self.ara_by_file = collections.defaultdict(list)
        for x in self.ara_targets: self.ara_by_file[Path(x['path']).stem].append(x)
        self.ara_groups = {x['name']:x for x in inventory.j('artifacts/rvv_validation_delivery_20261009/ara-remainder52/GROUPS.json')}
        self.ara_cases = {x['name']:x for x in inventory.j('artifacts/rvv_validation_delivery_20261009/ara-source51/CASES_BUILT.json')}
        self.act_registered = inventory.j('artifacts/rvv_validation_delivery_20261009/act-generation53/REGISTERED.json')

    @staticmethod
    def locator(value):
        # Historical metadata keeps original absolute provenance. Match by the
        # evidence-tree suffix without requiring the original workstation path.
        return 'artifacts/' + value.split('/artifacts/', 1)[1] if '/artifacts/' in value else value

    def canonical(self, value):
        value = value.strip()
        if value in self.names: return value
        if value in self.aliases: return self.aliases[value][0]
        return None

    def forms(self, value):
        return {f for x in tokens(value) if (f := self.canonical(x))}

    def elf_metadata(self, r):
        sha = r['elf_sha256']
        if sha in self.decoded: return self.decoded[sha]
        raw = self.W/r['raw_stdout']
        source = self.W/r['source_file']
        options = [raw.parent.parent/'original.elf', source.parent/'original.elf', raw.parent.parent/'linux.elf']
        if r['suite'] == 'libriscv':
            stem = r['source_case'].removesuffix('-B').removesuffix('-M1').removesuffix('-M2').removesuffix('-BOTH')
            for x in self.i.j('artifacts/rvv_validation_delivery_20261009/libriscv-regression57/ELF_STATIC_FORMS_DECODED.json'):
                if x['elf_sha256'] == sha: options.insert(0, self.D/'libriscv-regression57'/x['elf'])
        p = next((p for p in options if p.is_file()), None)
        if p is None:
            self.decoded[sha] = None
            self.missing.append(dict(suite=r['suite'],row_id=r['row_id'],source_case=r['source_case'],missing_field='retained linked ELF locator for '+sha,known_evidence=r['result_evidence']))
            return None
        data=p.read_bytes()
        assert hashlib.sha256(data).hexdigest()==sha, ('retained linked ELF differs from registered identity',r['row_id'],str(p))
        d = self.decoder.elf(data); self.decoded[sha] = d; self.elf_paths[sha] = str(p.relative_to(self.W))
        return d

    def mark(self, suite, candidate, stage, forms):
        self.sets[suite][stage].update(forms)
        self.candidates[suite,candidate][stage].update(forms)

    def contexts(self, r, target):
        scope = {k:UNKNOWN for k in ('SEW','LMUL','VL','mask','tail','vstart')}
        scope['VLEN'] = r['VLEN']
        refs = [r['source_inventory']]
        exact = self.scope_index.get((r['suite'],r['elf_sha256']),set())
        if exact:
            scope['retained_same_ELF_source_contexts'] = 'ACTUAL_FORM_CONFIGURATION_CONTEXTS.json ['+r['suite']+':'+r['elf_sha256']+']'
            refs.append(scope['retained_same_ELF_source_contexts'])
            for destination,field in (('SEW','SEW'),('LMUL','LMUL'),('VL','VL'),('mask','mask'),('tail','policy'),('vstart','initial_vstart_source')):
                i=self.scope_fields.index(field)
                values=sorted({x[i]for x in exact if x[0] in target and x[i] not in {'UNKNOWN','待查','unknown',''}})
                if values:scope[destination]={'source_context_values_not_cartesian_or_runtime_proof':values}
        if r['elf_sha256'] in self.decoded and self.decoded[r['elf_sha256']]:
            scope['linked_literal_vtypes_not_runtime_tuple']=self.decoded[r['elf_sha256']]['literal_vtypes']
            scope['emitted_operand_roles_not_runtime_mask_state']=sorted({role for forms in self.decoded[r['elf_sha256']]['functions'].values()for roles in forms.values()for role in roles})
        if r['suite']=='SiFive RIF':
            root = r['source_case']
            for suffix in ('-same-ELF-QEMU','-BOTH','-M1','-M2','-B'): root = root.removesuffix(suffix)
            if root in self.roster:
                x=self.roster[root]; scope.update(SEW=x['sew'],mask='source masked' if 'MaskedOperation' in x['attrs'] else 'source unmasked' if 'NonmaskedOperation' in x['attrs'] else UNKNOWN,
                                                 VL='dynamic strip-mining of original length500; exact runtime VL unknown')
                refs.append('artifacts/rvv_validation_delivery_20261009/rif-generation64/ROSTER_FROZEN.json [root='+root+']')
        if r['suite']=='RVV-ATG':
            x=self.atg.get(self.locator(r['source_file']))
            if x:
                p=self.atg_inputs[x['input']];scope.update(SEW=str(p['vsew']),LMUL=str(p['lmul']),mask=str(p['masked']),tail='tu',vstart=UNKNOWN)
                refs.extend(['artifacts/rvv_validation_delivery_20261009/atg-generation62/OUTPUT_MANIFEST.json [input='+x['input']+',stage='+x['stage']+']',
                             str(Path(r['source_file']).parent/'observer.json')])
        if r['suite']=='ACT' and r['cohort']=='Task53-pinned-default-generation':
            prefix=r['source_case'].split('-')[0]
            known=[x for x in self.act_registered['inputs'] if x['extension']==prefix and x['form'] in target]
            if known: scope['SEW']=sorted({str(x['sew']) for x in known})
            scope['source_allowed_LMUL_not_runtime_coverage']=self.act_registered['SEW_LMUL']
            refs.append('artifacts/rvv_validation_delivery_20261009/act-generation53/cases/'+r['source_case']+'/SCOPE_AUDIT.json')
            refs.extend(['artifacts/rvv_validation_delivery_20261009/act-generation53/SCOPE_AUDIT.json','artifacts/rvv_validation_delivery_20261009/act-generation53/REGISTERED.json'])
        if r['suite']=='Ara':
            groups = self.ara_groups.get(r['source_case']);case = self.ara_cases.get(r['source_case'])
            if groups or case:
                g=groups or case;scope['source_contexts']=[{k:x.get(k,UNKNOWN) for k in ('line','sew','lmul','avl','vtype','actual_vl')}for x in g.get('vsets',[])]
                refs.append('artifacts/rvv_validation_delivery_20261009/'+('ara-remainder52/GROUPS.json' if groups else 'ara-source51/CASES_BUILT.json')+' [name='+r['source_case']+']')
        return scope, refs

    def run(self):
        for r in self.rows:
            suite=r['suite'];candidate=r['candidate'];fs=self.forms(r['target_forms'])
            # Declaration support is not presence of an executable source case.
            if r['row_kind'] in {'SOURCE_CASE','SOURCE_INPUT'}:
                self.mark(suite,candidate,'source_present',fs)
                if r['build_status'] in {'PASS','BUILT','ORIGINAL_SOURCE_ENVIRONMENT_ADAPTER'}: self.mark(suite,candidate,'compiled_source',fs)
            if r['row_kind'] != 'EXECUTION':
                if suite in {'SiFive RIF','RVISmith','libriscv'} and r['row_kind']=='SOURCE_SUPPORT' and re.fullmatch('[0-9a-f]{64}',r['elf_sha256']) and r['build_status'] in {'PASS','BUILT','ORIGINAL_SOURCE_ENVIRONMENT_ADAPTER'}:
                    d=self.elf_metadata(r)
                    if d:
                        static={f for forms in d['functions'].values()for f in forms}
                        self.mark(suite,candidate,'compiled_source',static)
                        self.mark(suite,candidate,'emitted',static)
                        self.support_binding(r,static)
                continue
            is_dut = not candidate.startswith(('reference:', 'host:')) and candidate not in {'UNKNOWN','historical-unresolved'}
            if not is_dut: continue
            actual = r['returncode'] not in {'UNKNOWN','待查',''} and r['raw_stdout'] not in {'UNKNOWN','待查',''}
            program_ran = actual and r['dut_status'] in {'PASS','RESULT_MISMATCH'}
            accepted = program_ran and r['dut_status']=='PASS'
            quarantine = r['elf_sha256'] in self.corrections
            checked=set();coupled=set();emitted=set();target=set(fs);binding='UNESTABLISHED';extra=[]
            # For C-generated programs decode retained linked bytes against existing
            # encoding/spec audit, not disassembler spelling or intrinsic name guesses.
            if actual and suite in {'SiFive RIF','RVISmith','libriscv'}:
                d=self.elf_metadata(r)
                if d:
                    emitted={f for forms in d['functions'].values() for f in forms}
                    extra.append('ACTUAL_FORM_EMISSION.json [elf_sha256='+r['elf_sha256']+']')
                    if suite=='SiFive RIF':
                        p=self.W/r['source_file']; pred=p.parent/'PREDICATES_FROZEN.json'
                        if pred.is_file():
                            predicates=self.i.j(str(pred)); rootforms=set();symbols=set()
                            for x in predicates:
                                if x['kind']!='operation-result': continue
                                fn=x['function'].removeprefix('golden_');symbols.add(fn)
                                m=re.fullmatch(r'v(.+)_operator_\d+',fn)
                                f=self.canonical('v'+m[1].replace('_','.') ) if m else None
                                if f: rootforms.add(f)
                                elif m:
                                    self.missing.append(dict(suite=suite,row_id=r['row_id'],source_case=r['source_case'],missing_field='source predicate '+fn+' has no single canonical encoding mapping; compound compiler lowering requires output/dataflow binding, not opcode-wide acceptance',known_evidence=str(pred.relative_to(self.W))))
                            operation_emitted={f for fn in symbols for f in d['functions'].get(fn,{})}
                            target=rootforms
                            if r['source_status'] == 'TASK75_SOURCE_BACKED_PRODUCER_INTERFACE_DERIVATIVE':
                                # Retained scalar goldens have a host initialization defect;
                                # zero-absorbing inputs additionally lack target dependence.
                                # Keep the declared reduction endpoint, never all static forms.
                                target = fs
                                if accepted: coupled = target & operation_emitted
                                binding='TASK75_FROZEN_SCALAR_ENDPOINT_ONLY; host uninitialized model; no independent form or method admission credit'
                            else:
                                if accepted and not quarantine: checked=target & operation_emitted;coupled=emitted-checked
                                binding='ORIGINAL_OPERATION_GOLDEN_TO_COMPILED_SYMBOL; no individual opcode execution count'
                            extra.append(str(pred.relative_to(self.W)))
                            for f in target-operation_emitted:
                                self.missing.append(dict(suite=suite,row_id=r['row_id'],source_case=r['source_case'],missing_field='operation '+f+' is not emitted in retained operation symbol; compiler lowering/dataflow-to-golden mapping',known_evidence=str(pred.relative_to(self.W))))
                        else:
                            binding='MISSING_OPERATION_PREDICATE_LOCATOR'
                    else:
                        target=emitted
                        if accepted: coupled=emitted
                        binding='COUPLED_PROGRAM_ENDPOINT; static emission does not prove execution or result influence'
            elif suite in {'ACT','Ara','CHIPS'}:
                emitted=fs if r['build_status'] in {'PASS','BUILT'} else set()
                if accepted:
                    if r['target_forms'].startswith('STATIC_PRESENCE_ONLY:') or 'CONTEXT_DIAGNOSTIC' in r['cohort']:
                        coupled=fs;binding='COUPLED_CONTEXT_ENDPOINT'
                    else:
                        checked=fs;binding='EXISTING_TARGET_CHECKER_BINDING_TO_PROGRAM_RECEIPT; static branches not dynamically counted'
            elif suite=='RVV-ATG':
                emitted=fs
                if accepted: checked=fs;binding='ORIGINAL_TARGET_MACROS_TO_WRITTEN_REFERENCE_SIGNATURE; extraction helpers coupled'
            elif suite=='RVVTS':
                emitted=fs if re.fullmatch('[0-9a-f]{64}',r['elf_sha256']) and (actual or r['build_status'] in {'PASS','BUILT'}) else set()
                if accepted: coupled=fs;binding='COUPLED_SEQUENCE_ENDPOINT; overwritten intermediate results unobserved'
            elif actual:
                coupled=fs if accepted else set();binding='DIAGNOSTIC_PROGRAM_OR_NONVECTOR_SCOPE'
            if quarantine:
                checked=set();coupled=set();binding='QUARANTINED_RIF_O2_POLICY; raw original golden PASS retained diagnostically'
            associated=fs|emitted|target
            if associated:
                self.mark(suite,candidate,'source_present',target or fs)
                if r['build_status'] in {'PASS','BUILT','ORIGINAL_SOURCE_ENVIRONMENT_ADAPTER'}:self.mark(suite,candidate,'compiled_source',target or fs)
                self.mark(suite,candidate,'emitted',emitted)
                if program_ran:self.mark(suite,candidate,'program_executed',associated)
                self.mark(suite,candidate,'result_checked',checked)
                self.mark(suite,candidate,'coupled_endpoint',coupled)
                if program_ran:self.mark(suite,candidate,'executed_without_independent_form_check',associated-checked)
                if quarantine:self.mark(suite,candidate,'diagnostic_only',associated)
                if r['dut_status']!='PASS':self.mark(suite,candidate,'failed_or_blocked',associated)
            if actual or associated:
                scope,refs=self.contexts(r,target);refs+=extra
                self.bindings.append(dict(ledger_row_id=r['row_id'],ledger_row_kind=r['row_kind'],suite=suite,candidate=candidate,
                    executable_sha256=r['executable_sha256'],library_sha256=r['library_sha256'],elf_sha256=r['elf_sha256'],
                    source_case=r['source_case'],source_file=r['source_file'],source_status=r['source_status'],adapter=r['adapter'],
                    arm=r['arm'],flags_json=r.get('flags_json',UNKNOWN),command_evidence='SUITE_RUN_MANIFEST.csv [row_id='+r['row_id']+',field=original_command]',configuration_known_json=js(scope),configuration_evidence=';'.join(refs),
                    target_forms=';'.join(sorted(target)),emitted_forms=';'.join(sorted(emitted)),
                    result_checked_forms=';'.join(sorted(checked)),coupled_endpoint_forms=';'.join(sorted(coupled)),
                    result=r['dut_status'],acceptance='DIAGNOSTIC_ONLY_SUPERSEDED_POLICY' if quarantine else 'ACCEPTED_SCOPED' if accepted else 'ORIGINAL_FAILURE_OR_BLOCKER',
                    binding=binding,observed_state=r['checked_state'] if len(r['checked_state'])<2500 else 'SUITE_RUN_MANIFEST.csv [row_id='+r['row_id']+',field=checked_state]',
                    checker_scope=r['checker_scope'],checker_identity=r['checker_identity'],reference_identity=r['reference_identity'],
                    raw_stdout=r['raw_stdout'],raw_stderr=r['raw_stderr'],result_evidence=r['result_evidence'],
                    remaining=r['shared_oracle_limit']+'; '+r['blocker']))
        return self

    def support_binding(self,r,static):
        scope,refs=self.contexts(r,static)
        refs.append('ACTUAL_FORM_EMISSION.json [elf_sha256='+r['elf_sha256']+']')
        self.bindings.append(dict(ledger_row_id=r['row_id'],ledger_row_kind=r['row_kind'],suite=r['suite'],candidate=r['candidate'],
            executable_sha256=r['executable_sha256'],library_sha256=r['library_sha256'],elf_sha256=r['elf_sha256'],
            source_case=r['source_case'],source_file=r['source_file'],source_status=r['source_status'],adapter=r['adapter'],arm=r['arm'],flags_json=r.get('flags_json',UNKNOWN),command_evidence='SUITE_RUN_MANIFEST.csv [row_id='+r['row_id']+',field=original_command]',
            configuration_known_json=js(scope),configuration_evidence=';'.join(refs),target_forms=r['target_forms'],
            emitted_forms=';'.join(sorted(static)),result_checked_forms='',coupled_endpoint_forms='',result=r['dut_status'],
            acceptance='BUILD_ONLY_NO_RESULT_ACCEPTANCE',binding='BUILD_ONLY_STATIC_EMISSION',observed_state='No DUT result acceptance from compiler/reference receipt',
            checker_scope=r['checker_scope'],checker_identity=r['checker_identity'],reference_identity=r['reference_identity'],
            raw_stdout=r['raw_stdout'],raw_stderr=r['raw_stderr'],result_evidence=r['result_evidence'],remaining=r['shared_oracle_limit']+'; '+r['blocker']))

    def columns(self, form):
        result={}
        for s in self.suites:
            for stage in STAGES:
                result[s+'_'+stage] = 'YES' if form in self.sets[s][stage] else 'UNKNOWN'
            result[s+'_actual_evidence'] = 'ACTUAL_FORM_VALIDATION_BINDINGS.csv [suite='+s+',target/emitted/result_checked/coupled contains='+form+']; SUITE_RUN_MANIFEST.csv row_id retained'
        return result

    def summary(self):
        suites=[]
        for s in self.suites:
            g=[r for r in self.rows if r['suite']==s]
            ref=[r for r in g if (r['candidate'].startswith('reference:') or (r['row_kind']=='SOURCE_SUPPORT' and r['reference_identity'].startswith('QEMU11.1-same-ELF:'))) and r['returncode'] not in {'UNKNOWN','待查',''} and r['raw_stdout'] not in {'UNKNOWN','待查',''}]
            dut=[b for b in self.bindings if b['suite']==s and b['binding']!='BUILD_ONLY_STATIC_EMISSION' and b['result'] in {'PASS','RESULT_MISMATCH','REFERENCE_ERROR'} and b['raw_stdout'] not in {'UNKNOWN','待查',''}]
            suites.append(dict(suite=s,forms={k:sorted(v) for k,v in self.sets[s].items()},
                counts={k:len(v) if v else None for k,v in self.sets[s].items()},
                ledger_rows=len(g),source_case_rows=sum(r['row_kind']=='SOURCE_CASE'for r in g),
                registered_reference_receipt_rows=len(ref),registered_dut_receipt_rows=len(dut),
                reference_receipt_scope='EXECUTION plus explicit same-ELF QEMU SOURCE_SUPPORT; not all producer/capture references are registered here',
                distinct_DUT_runtime_identities=len({(b['elf_sha256'],b['executable_sha256'],b['library_sha256'],b['arm'],b['flags_json'])for b in dut}),
                candidates=[dict(candidate=c,forms={k:sorted(v)for k,v in stages.items()},counts={k:len(v)if v else None for k,v in stages.items()})
                            for (suite,c),stages in sorted(self.candidates.items())if suite==s]))
        return dict(scope='Existing627 inventory;595 applicable; unknown depth is null, not zero. Sets overlap; never sum suites/stages. Program execution does not prove static opcode execution or result influence.',
                    suites=suites,union_result_checked_forms=sorted(set().union(*(v['result_checked']for v in self.sets.values()))),
                    source_inventory_sha256=self.i.inputs['artifacts/external_suite_coverage_20261007/FORM_VERIFICATION_EVIDENCE.csv'],
                    ledger_sha256=self.i.inputs['artifacts/external_suite_coverage_20261007/SUITE_RUN_MANIFEST.csv'],
                    quarantined_RIF_O2_ELFs=len(self.corrections),missing_join_cases=self.missing,DUT_calls=0,reference_calls=0,compiler_calls=0)

    def targets(self):
        summary=self.summary()
        emission={sha:dict(elf_locator=self.elf_paths.get(sha,UNKNOWN),recorded_elf_sha256=sha,**data) for sha,data in sorted(self.decoded.items())if data}
        return {'ACTUAL_FORM_VALIDATION_BINDINGS.csv':csv_bytes(self.bindings,list(self.bindings[0])),
                'ACTUAL_FORM_VALIDATION_SUMMARY.json':(json.dumps(summary,ensure_ascii=False,indent=2)+'\n').encode(),
                'ACTUAL_FORM_EMISSION.json':(json.dumps(emission,ensure_ascii=False,indent=2)+'\n').encode(),
                'ACTUAL_FORM_MISSING_JOINS.csv':csv_bytes(self.missing,['suite','row_id','source_case','missing_field','known_evidence']),
                'ACTUAL_FORM_CONFIGURATION_CONTEXTS.json':(json.dumps({s+':'+sha:[dict(zip(self.scope_fields,x)) for x in sorted(contexts)]for (s,sha),contexts in sorted(self.scope_index.items())},ensure_ascii=False,indent=2)+'\n').encode(),
                'JSERV_VERIFICATION_SUMMARY.md':self.readable_summary(),
                'ACTUAL_SUITE_FORM_LISTS.md':self.suite_lists(),
                'ACTUAL_FORM_ALIAS_RULES.json':(json.dumps({k:dict(form=v[0],evidence=v[1]) for k,v in sorted(self.aliases.items())},indent=2)+'\n').encode()}

    def readable_summary(self):
        summary=self.summary()
        lines=['# RVV implementation scope and actual external validation','',
            'Current Task76 synchronization of accepted Task74 indexing and Task75 finite derivative observations; Task71 views are preserved as historical lineage. No new DUT, reference, compiler or generator execution. The fixed inventory has **627 named forms: 595 applicable to RV32/full-V/ELEN64 and 32 ei64 indexed forms outside that profile**. This is a form inventory, not an all-configuration conformance percentage. [Inventory](FORM_VERIFICATION_EVIDENCE.csv) · [decoder/routes](../rvv_route_matrix_20261007/README.md).','',
            '**595 forms have a joined positive target/checker record across the existing evidence.** Historical2af5, historical-f8123 and clean961 identities remain separate in every binding and in the candidate sets. No suite totals are added. [627-row readable table](COMPLETE_FORM_INVENTORY_ZH.md) · [CSV](COMPLETE_FORM_SUITE_INVENTORY.csv) · [candidate-specific exact sets](ACTUAL_FORM_VALIDATION_SUMMARY.json).','',
            'Source means named source/config/testplan presence. Compiled means its source was built; emitted means a retained target assembly binding or a decoded linked opcode. Program means a guest program reached an outcome, **not that every associated static opcode ran or influenced output**. Result-checked means an explicit target/output checker binding; it still does not establish every branch, state or configuration. Coupled endpoints retain useful sequence/program output comparisons with no independent per-form check. UNKNOWN means no established join, not zero coverage.','',
            '| Suite | Source forms | Compiled source | Emitted forms | Program-associated, without independent form check | Result-checked forms | Coupled endpoint forms |',
            '|---|---:|---:|---:|---:|---:|---:|']
        for x in summary['suites']:
            c=x['counts'];show=lambda k:str(c[k])if c[k] is not None else 'UNKNOWN'
            lines.append('| '+x['suite']+' | '+' | '.join(show(k)for k in ('source_present','compiled_source','emitted','executed_without_independent_form_check','result_checked','coupled_endpoint'))+' |')
        lines+=['',
            'The stage sets overlap: a form can have both a checked case and another unobserved/failed case. Compilation/emission includes retained diagnostic attempts; **acceptance excludes the 543 quarantined RIF O2 derivative ELFs**. [Correction lineage](../rvv_validation_delivery_20261009/rif-interface67/policy-preserved/CORRECTIONS.json). Exact source, emitted, checked, coupled, diagnostic and failure lists for every suite are generated in [suite form lists](ACTUAL_SUITE_FORM_LISTS.md); select the form in [actual bindings](ACTUAL_FORM_VALIDATION_BINDINGS.csv) to reach the immutable ledger row_id, source/assertion, reference, raw result and candidate.','',
            '| Family | Inventoried | Applicable | Target/result-checked union | Coupled endpoint union |',
            '|---|---:|---:|---:|---:|']
        checked=set(summary['union_result_checked_forms']);coupled=set().union(*(x['coupled_endpoint']for x in self.sets.values()))
        for family in sorted({f['family']for f in self.i.forms}):
            g=[f for f in self.i.forms if f['family']==family];names={f['form']for f in g}
            lines.append(f"| {family} | {len(g)} | {sum(f['rv32_elen64_applicability']=='REQUIRED'for f in g)} | {len(names&checked)} | {len(names&coupled)} |")
        lines+=['',
            '**Observed state and configuration.** CHIPS compares selected destination words/store prefixes, with vxsat/CSR checks only where present; configuration answers include disclosed local ELEN64 constants. ACT compares BASE element0/bit0, LEN destination regions under its recorded tail rules, and selected flags/CSR/scalar outputs. Ara uses original typed vector/scalar/memory and CSR predicates; original short buffers and incomplete reduction stores remain visible. RVVTS compares sequence-end registers/CSRs (some scoped packets include FPR/memory), with no universal intermediate-state or agnostic-history oracle. [Original checker audits](CHIPS_ORACLE_AUDIT.json) · [source-target/checker records](SUITE_EXECUTED_CASE_COVERAGE.csv).','',
            'ATG binds original target macros to written Spike signatures, then same-ELF QEMU/DUT bytes; e64 extraction observes low32 and FP32/cumulative flags, not full state. RIF binds emitted operation symbols to unchanged operation-result goldens, while initialization reports are vacuous and helpers/configuration opcodes are coupled. RVISmith and libriscv retain printed values, aggregates/hashes and selected memory outputs as program endpoints; emitted forms alone are not individually validated. [ATG metadata](../rvv_validation_delivery_20261009/atg-generation62/OUTPUT_MANIFEST.json) · [RIF final scope](../rvv_validation_delivery_20261009/rif-interface67/SUMMARY_FINAL.json) · [RVISmith observer](../rvv_validation_delivery_20261009/rvismith-print70/CHECKER_SCOPE.json) · [libriscv checker bindings](../rvv_validation_delivery_20261009/libriscv-regression57/SOURCE_CHECKER_BINDINGS.json).','',
            'Each binding retains original/derivative source status, executable/library/ELF, arm/full flags, known SEW/LMUL/VLEN/VL/mask/tail/vstart scope, output/CSR/memory observer, checker/reference/raw links, and remaining limitations. Source contexts and linked literal vtypes are explicitly different from runtime tuples; missing dimensions remain UNKNOWN. [Same-ELF contexts](ACTUAL_FORM_CONFIGURATION_CONTEXTS.json) · [linked emission and operand roles](ACTUAL_FORM_EMISSION.json) · [spec-backed aliases](ACTUAL_FORM_ALIAS_RULES.json).','',
            '**Calls, sources and forms use different units.** The ledger retains 99,115 rows (98,359 prior rows preserved plus 756 Task75 rows) including definitions, aliases, planned configurations, references, failures and diagnostics. RIF earlier final scope is 1,500 accepted roots/6,000 DUT calls; Task75 separately adds 108 source-backed producer/interface derivatives, 108 same-ELF QEMU references and 432 clean961 B/M1/M2/BOTH calls, all PASS with exit0/no timeout; unchanged goldens and original failures remain. These scalar endpoints receive no independent form credit; 543 superseded O2 derivatives/2,172 DUT calls are diagnostic. RIF64/65 retains 889 same-ELF references; Task67 adds 1,154 actual references, of which 611 final and 543 diagnostic. RVISmith Task66 retains 76 QEMU calls/73 unique ELFs/31 accepted references and 124 DUT calls; Task70 adds 42 same-ELF references/168 independently main-reviewed byte comparisons, from 45 builds/3 ELF aliases. Its print-only include/PRIx64 adapter preserves the original calculations; **no nonzero input high32 coverage is claimed**. These calls do not increase the 595-form union. [Task70 result](../rvv_validation_delivery_20261009/SESSION0_RESULT_70.md) · [RIF accounting](../rvv_validation_delivery_20261009/rif-interface67/SUMMARY_FINAL.json).','',
            'The JSON separately counts registered source-case rows, reference receipt rows, DUT receipt rows and distinct runtime identities. Some capture/reference calls live in producer summaries rather than EXECUTION rows, so registered receipt counts are not campaign call totals. Controls are separate. Four repeated ACT vfadd runtime calls and five unnecessary CHIPS width profiles remain disclosed in their accepted batch accounts.','',
            '**Remaining implementation/platform defects:** clean961 guest signal handling still blocks the original QEMU noexec handler-completion test; general precise vector fault restoration/retry and native fault-state proof remain incomplete. Host256 is outside this fixed build’s chunk profile. The separate P4 fault candidate is not clean961 validation, and P4-04 remains blocked. Existing storage/profile corrections have scoped regressions; an original FAIL is not relabeled PASS. [QEMU outcome](../rvv_validation_delivery_20261009/SESSION0_RESULT_58.md) · [remaining implementation obligations](../rvv_validation_delivery_20261009/REMAINING_OBLIGATIONS.md).','',
            '**Remaining test-source/checker blockers:** all **108 RIF reduction producer errors** remain blocked (literal loaded.size()/loaded[] guest emission; 54 also have split _m suffixes), not ISA N/A. Task75 repaired derivatives preserve the original seed, 500 inputs, graph, mask, zero accumulator and checker suffixes. The host scalar evaluator reads an uninitialized allocation; frozen PASS observations do not establish full generator correctness. The 24 absorbing-zero AND/unsigned-min checks separately lack target dependence; 162 initialization reports are vacuous. No host golden regeneration or per-PC M1/M2 admission is credited. ATG has nine producer interface/macro contracts and two source-EEW-overlap reference rejects. rv32emu’s original and three-literal derivative both retain FAIL; the derivative reaches 8/304 checks (7 pass, check8 assumes ELEN32), leaving 296 unreached and no data-vector result coverage. Ara’s missing/legacy macros, original store gaps and reserved inputs; CHIPS’s eight unsafe original store outputs; ACT’s unresolved form/profile or privileged signatures; RVISmith’s 34 compiler-error entries; RiESCUE RV32 runtime/address/high-half contracts; FORCE’s unbuilt platform/ELF64 writer and model-only assertions; CTK RV64 entry and 1,056 retained Tenstorrent privileged RV64 cases remain separate. [RIF108 derivative decision](../rvv_validation_delivery_20261009/rif-reductions75/RESULT.md) · [ATG audit](../rvv_validation_delivery_20261009/SESSION0_RESULT_69.md) · [CSR audit](../rvv_validation_delivery_20261009/SESSION0_RESULT_68.md) · [source dispositions](SUITE_RUN_MANIFEST.csv).','',
            '**Task74 mapping resolution:** the immutable Task71 missing872-row CSV/views remain in [historical lineage](../rvv_validation_delivery_20261009/form-consolidation71/BEFORE_TASK76_ACTUAL_FORM_MISSING_JOINS.csv). Its 218 obligations resolve to 174 lowering absences, 6 checked compound sequences, 8 genuine vmv.v.v checker gaps and 30 exporter false misses; 52 O2 obligations/208 rows remain diagnostic. The uppercase-hex correction regenerates RIF checked200 and libriscv coupled198; union595 is unchanged. The current missing-join CSV records unresolved joins, not a reopened execution queue. **Remaining test dimensions and joins:** exact missing operation-to-emission/dataflow bindings are listed by case/row in [missing joins](ACTUAL_FORM_MISSING_JOINS.csv); no form check is fabricated from a compiler substitution. Full register/CSR/memory state, memory-access suppression, write-history-aware agnostic choices, intermediate results/flags, general overlap/restart and per-PC M1/M2 admission are incomplete outside their specifically accepted witnesses. RIF is one-root/length500/one seed/VLEN128; ATG uses its frozen e32m1 and limited e64 extension profile; RVISmith retains wildcards/NaN normalization and zero observed high32. Other SEW/LMUL/VLEN/VL/mask/tail/vstart combinations remain unknown where not recorded. Thesis/repository integration can now use this precise scope; this consolidation does not declare full RVV conformance.','',
            '[Previous long history](../../archive/JSERV_VERIFICATION_SUMMARY_before_Task71.md) is archived once. Rebuild current views with `export_readable_coverage.py --complete-inventory`; add `--check` for read-only deterministic verification.']
        return ('\n'.join(lines)+'\n').encode()

    def suite_lists(self):
        lines=['# Exact suite form sets — generated Task76','',
            '[Current answer](JSERV_VERIFICATION_SUMMARY.md) · [627-row table](COMPLETE_FORM_INVENTORY_ZH.md) · [binding evidence](ACTUAL_FORM_VALIDATION_BINDINGS.csv) · [candidate-separated JSON](ACTUAL_FORM_VALIDATION_SUMMARY.json)','',
            'These sets overlap. Program-associated/static forms do not establish dynamic opcode execution or result influence. Result-checked forms require the recorded target/output binding; coupled endpoints are listed separately. No recorded set means UNKNOWN, not proof of absence. Candidate and original/derivative identities are retained in binding and ledger rows.','']
        for s in self.suites:
            lines+=['## '+s,'',f'Evidence: select `suite={s}` and exact semicolon-delimited form in [bindings](ACTUAL_FORM_VALIDATION_BINDINGS.csv); `ledger_row_id` selects the immutable [SUITE_RUN row](SUITE_RUN_MANIFEST.csv).','']
            for stage in STAGES:
                fs=sorted(self.sets[s][stage]);lines+=['<details>',f'<summary>{stage}: {len(fs) if fs else "UNKNOWN"} forms</summary>','',', '.join('`'+f+'`'for f in fs)if fs else 'No established joins in this stage.','', '</details>','']
        return ('\n'.join(lines)+'\n').encode()
