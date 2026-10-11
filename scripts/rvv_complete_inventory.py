"""Offline readable inventory, one row per canonical form. Never runs/imports a test runner.

Source presence, target execution, historical filename association and route proof remain
separate. Configuration contexts are linked to their original rows, never Cartesian-expanded.
"""
import collections
import csv
import hashlib
import io
import json
import re
import os
from urllib.parse import quote, unquote, urlsplit
from pathlib import Path

# Per-form provenance aggregates can exceed the csv module's 128 KiB default.
csv.field_size_limit(64 * 1024 * 1024)

R = Path(__file__).resolve().parent
W = R.parent.parent
CORE = ('CHIPS', 'ACT', 'Ara', 'RVVTS')
EXTRA = ('RiESCUE', 'CTK', 'FORCE_RISCV', 'RVV_ATG', 'SiFive_RIF', 'RVISmith', 'Tenstorrent')
FAMILIES = {
    'configuration': '向量配置', 'integer_single_width': '同寬整數算術與比較',
    'integer_widening': '整數加寬', 'integer_narrowing': '整數窄化',
    'integer_extension': '整數延伸', 'integer_reduction': '整數歸約',
    'fixed_point': '定點與飽和', 'floating_point': '浮點',
    'mask_bits': '遮罩位元運算', 'mask_to_integer': '遮罩到整數',
    'permutation': '排列與元素搬移', 'whole_register_move': '整個暫存器搬移',
    'data_memory': '單位／跨距／分段資料記憶體', 'indexed_memory': '索引記憶體',
    'mask_memory': '遮罩記憶體', 'whole_register_memory': '整個暫存器記憶體',
}
CORE_FIELDS = ('來源', '來源索引', '執行分類', '已接合DUT列數', '歷史待查列數',
               '未執行列數', 'reference列數', '主批別名列數', '配置原始索引',
               '配置值摘要非組合', 'checker比較狀態', 'checker中文摘要', '盲區',
               '結果原值', '套件版本', 'DUT版本', '版本索引', 'M1路徑', 'M2路徑',
               '路徑證據索引', '案例原始索引')
EXTRA_FIELDS = ('來源', '來源索引', '執行與checker', '版本', '缺口',
                '配置原始索引', '結果', 'M1路徑', 'M2路徑')
FIELDS = ['form', 'family', '家族', 'RV32_ELEN64適用性', 'FORM原始索引', '規格版本',
          '完整語意驗收', '共同缺口'] + [f'{s}_{k}' for s in CORE for k in CORE_FIELDS] + [
          f'{s}_{k}' for s in EXTRA for k in EXTRA_FIELDS]


def joined(values):
    return '；'.join(sorted({str(v) for v in values if str(v).strip()})) or '待查'


def counted(values):
    return '；'.join(f'{key}×{n}' for key, n in sorted(collections.Counter(values).items())) or '無記錄'


def valid(value):
    return value not in ('', '待查', 'unknown', 'MISSING', 'N/A reference engine')


def selector(path, **fields):
    return f'{path} [選取 ' + ', '.join(f'{k}={v}' for k, v in fields.items()) + ']'


def md(value):
    return str(value).replace('|', '\\|').replace('\n', ' ')


def link(path, label):
    p = Path(path)
    if not p.is_absolute():
        p = W / p if str(p).startswith('artifacts/') else R / p
    # Reports are in R: repository evidence uses ../relative links, not host paths.
    import os
    return f'[{label}]({os.path.relpath(p, R)})'


class Inventory:
    def __init__(self):
        self.root = R
        self.evidence_root = W
        self.inputs = {}
        self.csvs = {}

    def read(self, path):
        p = Path(path)
        if not p.is_absolute():
            p = W / p if str(p).startswith('artifacts/') else R / p
        b = p.read_bytes()
        self.inputs[str(p.relative_to(W))] = hashlib.sha256(b).hexdigest()
        return b

    def rows(self, path):
        if str(path) not in self.csvs:
            self.csvs[str(path)] = list(csv.DictReader(io.StringIO(self.read(path).decode())))
        return self.csvs[str(path)]

    def j(self, path):
        return json.loads(self.read(path))

    @staticmethod
    def index(rows, key):
        out = collections.defaultdict(list)
        for number, row in enumerate(rows, 1):
            out[row[key]].append((number, row))
        return out

    def load(self):
        self.forms = self.rows('FORM_VERIFICATION_EVIDENCE.csv')
        self.names = {f['form'] for f in self.forms}
        assert len(self.forms) == len(self.names) == 627
        assert collections.Counter(f['rv32_elen64_applicability'] for f in self.forms) == {
            'REQUIRED': 595, 'NOT_APPLICABLE': 32}
        assert set(f['family'] for f in self.forms) == set(FAMILIES)
        self.source = {name: self.index(self.rows(name + '/SOURCE_FORMS.csv'), 'form') for name in (
            'chips_configs', 'act_upstream_testplans', 'act_including_smv',
            'act_archived_corpus_only', 'rvvts_generator')}
        self.capability = self.j('SOURCE_CAPABILITY_SUMMARY.json')
        self.ara = {x['form']: x for x in self.rows('ara/FORM_COVERAGE.csv')}
        assert set(self.ara) == self.names
        self.ara_ops = self.index(self.rows('ara/OPCODE_OCCURRENCES.csv'), 'form')
        self.ara_assertions = self.index(self.rows('ara/ASSERTION_TARGETS.csv'), 'form')
        self.ara_summary = self.j('ara/SUMMARY.json')
        self.chips = self.index(self.rows('CHIPS_INSTRUCTION_BATCH_COVERAGE.csv'), 'instruction')
        self.alias = self.index(self.rows('artifacts/rvv_final_regression_20261007/ALIAS_RESULTS.csv'), 'form')
        self.final_identity = self.j('artifacts/rvv_final_regression_20261007/sources/CANDIDATE_IDENTITY.json')
        self.geometry = self.index(self.rows('artifacts/rvv_geometry_obligations_20261007/EVIDENCE.csv'), 'form')
        self.suite = collections.defaultdict(list)
        self.suite_rows = self.rows('SUITE_EXECUTED_CASE_COVERAGE.csv')
        self.suite_check = self.j('SUITE_EXECUTED_CASE_CHECK.json')
        assert self.inputs[str((R / 'SUITE_EXECUTED_CASE_COVERAGE.csv').relative_to(W))] == self.suite_check['csv_sha256'], 'SUITE/check identity mismatch'
        self.unassigned = []
        self.associations = collections.Counter()
        for number, x in enumerate(self.suite_rows, 1):
            form = x['target_instruction']
            association = 'target_instruction'
            if form not in self.names and x['suite'] == 'ACT':
                # Filename association is a historical locator, never a target/checker proof.
                tail = x['recorded_case'].partition('-')[2]
                if tail.endswith('.S'):
                    tail = tail[:-2]
                match = re.fullmatch(r'(.+)-\d+', tail)
                form = tail if tail in self.names else match[1] if match and match[1] in self.names else ''
                association = 'recorded_case_filename_only'
            if form in self.names:
                self.suite[form, x['suite']].append((number, x, association))
                self.associations[association] += 1
            else:
                self.unassigned.append((number, x['suite'], x['recorded_case']))
        assert len(self.suite_rows) == self.suite_check['rows']
        assert dict(collections.Counter(x['suite'] for x in self.suite_rows)) == self.suite_check['rows_by_suite']
        assert sum(self.associations.values()) + len(self.unassigned) == len(self.suite_rows)
        self.additional = {x['form']: x for x in self.rows('additional_generators/FORM_SOURCE_JOIN.csv')}
        assert set(self.additional) == self.names
        self.additional_summary = self.j('additional_generators/SUMMARY.json')
        self.atg = self.index(self.rows('atg_rif/ATG_OPCODE_DECLARATIONS.csv'), 'declaration')
        self.atg_summary = self.j('atg_rif/SUMMARY.json')
        self.rif = self.rows('atg_rif/RIF_OPERATORS.csv')
        self.selection = self.rows('EXECUTION_BATCHES.csv')
        self.ten = self.j('tenstorrent/PROVENANCE.json')
        self.ten_mentions = collections.defaultdict(list)
        for number, text in enumerate(self.read('tenstorrent/rv64v_0.S').decode().splitlines(), 1):
            match = re.match(r'^\s*(v[a-z0-9]+(?:\.[a-z0-9]+)*)\s', text.split('#')[0])
            if match and match[1] in self.names:
                self.ten_mentions[match[1]].append(number)
        # Task notes are not evidence inputs; updating handoff must not stale the inventory.
        self.read('export_readable_coverage.py')
        self.read('export_complete_form_inventory.py')
        assert len(self.chips) == 595 and sum(map(len, self.chips.values())) == 724
        assert {f['form'] for f in self.forms if f['rv32_elen64_applicability'] == 'REQUIRED'} == set(self.chips)
        for f in self.forms:
            aliases = [x for _, x in self.alias.get(f['form'], []) if x['control'] == 'False']
            assert len(aliases) == int(f['final_positive_aliases']), ('FORM alias count', f['form'])
            assert len({x['cell_id'] for x in aliases}) == int(f['final_unique_positive_cells']), ('FORM cells', f['form'])
            batches = json.loads(f['source_checker_batches_json'])
            assert {x['batch'] for x in batches} == {x['batch'] for _, x in self.chips.get(f['form'], [])}, ('FORM batch join', f['form'])

    def source_info(self, f, suite):
        form = f['form']
        if suite == 'Ara':
            x = self.ara[form]
            ops = self.ara_ops.get(form, [])
            presence = ('有原始assertion target' if x['native_assertion_covered'] == 'True' else
                        '有source mention但未確認checker target' if ops else
                        '未知' if x['native_state'] == 'unknown' else '已盤點範圍無assertion target')
            return presence + f"；RV32原body={x['rv32_state']}", joined([
                selector('ara/FORM_COVERAGE.csv', form=form), selector('ara/OPCODE_OCCURRENCES.csv', form=form),
                x['source_lines']]), self.ara_summary['revision']
        names = {'CHIPS': ('chips_configs',), 'ACT': ('act_upstream_testplans', 'act_including_smv',
                 'act_archived_corpus_only'), 'RVVTS': ('rvvts_generator',)}[suite]
        notes, refs, versions = [], [], []
        for name in names:
            present = self.source[name].get(form, [])
            labels = {'chips_configs': 'config', 'act_upstream_testplans': 'Vx/Vf/Vls計畫',
                      'act_including_smv': '含SmV來源', 'act_archived_corpus_only': '歷史檔名來源',
                      'rvvts_generator': 'grammar/table'}
            notes.append(labels[name] + ('有' if present else '未列'))
            refs.append(selector(name + '/SOURCE_FORMS.csv', form=form))
            # Complete source locators remain readable CSV text, not nested JSON.
            refs.extend(x['source'] + ':' + x['locator'] for _, x in present)
            versions.append(self.capability[name]['revision'])
        if suite == 'ACT' and form.startswith('vset'):
            notes.append('SmV為特權generator來源，不等於RV32 Linux-user已跑')
        return '；'.join(notes), joined(refs), joined(versions)

    def route(self, f, suite, records):
        form = f['form']
        m1 = '未知：配置開關或PASS不證逐PC的M1准入'
        m2 = '未知：未有此形式逐PC的M2路徑證明'
        refs = []
        entries = json.loads(f['m1_actual_admission_evidence_json'])
        if suite == 'RVVTS' and entries:
            arms = collections.Counter(x['arm'] for x in entries)
            m1 = '有受限PC→FORM→動態FRAME證據：' + counted(x['arm'] for x in entries) + '；歷史／版本／幾何限各原列'
            assert all(arm in ('M1', 'BOTH') for arm in arms)
            refs.append(selector('FORM_VERIFICATION_EVIDENCE.csv', form=form, field='m1_actual_admission_evidence_json'))
            for x in entries:
                refs.extend(x[k] for k in ('evidence', 'identity_evidence', 'branch_evidence') if x.get(k))
        if suite == 'RVVTS' and form == 'vfadd.vv':
            p = 'artifacts/rvv_native_boundaries_20261008/FRAME_GUARD_BOUNDARY_CODE_JOIN.csv'
            proof = self.rows(p)
            assert any(x['arm'] == 'BOTH' and int(x['highchunk_member_operations_skipped']) > 0 for x in proof)
            m2 = 'Both有VL15高chunk跳過／VL17,32高chunk執行／VL0 helper退回的code+FRAME推導；非分支telemetry；M2單獨逐PC仍待查'
            refs.append(selector(p, arm='BOTH', seed='20261089或20261090', VL='0/15/17/32原列'))
        if suite == 'RVVTS' and form == 'vfadd.vv':
            m1 += '；AD單一VLEN2048/e32/m1/VL64：M1/Both ordinal1–3同frame width2/k4兩resource batches，code＋guard不變式＋FRAME count1推導；不增加歷史91 aggregate准入'
            refs.append('artifacts/rvv_multichunk_batch_20261009/FRAME_BATCH_CODE_JOIN.csv')
        if suite == 'RVVTS' and form == 'vfadd.vf':
            m1='M1/Both數值PASS但multi_member_runs=0；setup/spill單member形成不算vfadd目標PC/frame准入，仍OPEN'
            m2='四配置終態一致；尚無vfadd逐PC active-chunk/run-bound路徑證明'
            refs.append('artifacts/rvv_scalar_box_port_20261009/PATH_SCOPE.json')
        # Retain explicit negative/limited formation observations as evidence, not positive admission.
        zero = [x for _, x, _ in records if 'FORM/FRAME0' in x['remaining_gap']]
        if zero:
            m1 += '；另有M1/Both FORM/FRAME0記錄（未形成）'
            refs.extend(selector('SUITE_EXECUTED_CASE_COVERAGE.csv', target_instruction=form,
                                 suite=suite, batch=x['batch'], arm=x['arm']) for x in zero)
        return m1, m2, joined(refs) if refs else '未知；FORM原列m1_actual_admission及SUITE remaining_gap可查'

    def core(self, f, suite):
        form = f['form']
        records = self.suite.get((form, suite), [])
        executed = [(n, x, a) for n, x, a in records if not x['result'].startswith('NOT_EXECUTED_')]
        refs = [(n, x, a) for n, x, a in executed if x['engine'] in ('qemu', 'spike')]
        candidate = [(n, x, a) for n, x, a in executed if x['engine'] not in ('qemu', 'spike')]
        pending = [(n, x, a) for n, x, a in candidate if a != 'target_instruction' or
                   'PENDING' in x['result'] or 'historical' in x['engine']]
        joined_dut = [(n, x, a) for n, x, a in candidate if (n, x, a) not in pending]
        not_run = [x for _, x, _ in records if x['result'].startswith('NOT_EXECUTED_')]
        main = [(n, x) for n, x in self.alias.get(form, []) if x['control'] == 'False'] if suite == 'CHIPS' else []
        assert all(x['status'] == 'PASS' and x['returncode'] == '0' for _, x in main)
        source, source_refs, revision = self.source_info(f, suite)
        status = []
        if main:
            status.append(f'CHIPS主批已接合{len(main)}別名列／{len({x["cell_id"] for _, x in main})}unique cells，四臂PASS')
        if joined_dut:
            status.append(f'已接合DUT執行{len(joined_dut)}索引列（不是獨立case數）')
        if pending:
            status.append(f'歷史待查{len(pending)}列；檔名或ELF接合不等於完整source/checker驗收')
        if not_run:
            prefix='前段保留未執行診斷'if suite=='Ara'and form in {'vsetvli','vsetvl','vsetivli'}else'明確未執行'
            status.append(f'{prefix}{len(not_run)}列／{counted(x["result"] for x in not_run)}')
        if refs:
            if suite == 'Ara' and form == 'vsetvli':
                startup=[x for _,x,_ in refs if x['result']=='REFERENCE_PROFILE_UNSUPPORTED_VLEN2048']
                checked_ref=[x for _,x,_ in refs if x['result']=='PASS']
                status.append(f'保留QEMU啟動拒絕{len(startup)}靜態綁定（同一次call、0 guest）；另固定Spike原checker通過{len(checked_ref)}case綁定（同一完整檔call），不算DUT')
            else:
                status.append(f'reference已執行{len(refs)}索引列，另計不算DUT')
        if not status:
            status.append('未找到DUT執行接合；來源存在不能當runtime PASS')
        if f['rv32_elen64_applicability'] == 'NOT_APPLICABLE':
            status.insert(0, 'N/A：RV32不適用；來源／歷史記錄保留但不計RV32正例')
        configs = [selector('SUITE_EXECUTED_CASE_COVERAGE.csv', suite=suite, target_instruction=form),
                   '選取欄位：batch,recorded_case,target_id,source_target_lines,engine,arm,SEW,LMUL,VLEN,VL,AVL_source,mask,policy,configuration_evidence,configuration_scope']
        cases = [selector('SUITE_EXECUTED_CASE_COVERAGE.csv', suite=suite, target_instruction=form)]
        if any(a != 'target_instruction' for _, _, a in records):
            historical_names = sorted({x['recorded_case'] for _, x, a in records if a != 'target_instruction'})
            cases.append('歷史補選：suite=ACT,target_instruction=待查,recorded_case屬於{' + ','.join(historical_names) + '}；只按檔名關聯')
            configs.append(cases[-1])
        if main:
            cases.append(selector('artifacts/rvv_final_regression_20261007/ALIAS_RESULTS.csv', form=form, control='False'))
            configs.extend([selector('CHIPS_INSTRUCTION_BATCH_COVERAGE.csv', instruction=form),
                selector('artifacts/rvv_geometry_obligations_20261007/EVIDENCE.csv', form=form, kind='CHIPS-target-vset'),
                f['configuration_index']])
        if suite == 'Ara':
            configs.append(selector('ara/ASSERTION_TARGETS.csv', form=form))
        if suite == 'ACT':
            configs.append(selector('ACT_SEMANTIC_PLAN.csv', form=form) + '（source coverpoint計畫，非runtime組合）')
            if form in {'vmfeq.vf','vmflt.vf','vmfle.vf'}:
                configs.append(selector('artifacts/act_fp_scalar_compare_current_20261009/COMPARE_CASE_DEPTH.csv', form=form))
                cases.append(selector('artifacts/act_fp_scalar_compare_current_20261009/SOURCE_LANE_COMPARE_RAW.csv', form=form)+'（原vector operand／scalar FPR與scratch來源／FLEN64與load寬度／mask bits／NaN與零／Sail mask結果／FFLAGS）；原FLW valid boxing及FLD full-width，無invalid boxing區辨例；BASE只比bit0，LEN全1024bits，tail接受原signature或1或原VLMAX答案；輔助VLMAX沒有獨立DUT結果或flags checker')
            if form in {'vmfeq.vv','vmflt.vv','vmfle.vv'}:
                configs.append(selector('artifacts/act_fp_compare_current_20261009/COMPARE_CASE_DEPTH.csv', form=form))
                cases.append(selector('artifacts/act_fp_compare_current_20261009/SOURCE_LANE_COMPARE_RAW.csv', form=form)+'（原兩operand／mask bits／NaN與零／Sail mask結果／FFLAGS）；BASE只比bit0，LEN全1024bits，tail接受原signature或1或原VLMAX答案；輔助VLMAX沒有獨立DUT結果或flags checker')
            if form in {'vfrec7.v','vfrsqrt7.v'}:
                configs.append(selector('artifacts/act_fp_estimate_current_20261009/ESTIMATE_CASE_DEPTH.csv', form=form))
                cases.append(selector('artifacts/act_fp_estimate_current_20261009/SPECIAL_VALUE_CHECKER_RAW.csv', form=form)+'（原input/frm/flag slot與exact估值位元）；DEPTH_SUMMARY.json列同input跨rounding無區辨限制')
            if form in {'vfmin.vv','vfmax.vv','vfclass.v'}:
                configs.append(selector('artifacts/act_fp_special_current_20261009/TARGET_CONFIG_CHECKER_RAW.csv', form=form))
                cases.append(selector('artifacts/act_fp_special_current_20261009/SPECIAL_VALUE_CHECKER_RAW.csv', form=form) + '（原input label/byte/bits、alias後load、原Sail result/FFLAGS slot/checker行號/raw）')
        compared = [x['checker_compared_state'] for _, x, _ in records]
        if suite == 'Ara':
            secondary = [x['secondary_checkers'] for _, x in self.ara_assertions.get(form, []) if x['secondary_checkers']]
            if secondary:
                compared.append('來源secondary checker（不是動態執行證明）=' + joined(secondary))
                cases.append(selector('ara/ASSERTION_TARGETS.csv', form=form, field='secondary_checkers'))
        scopes = [x['checker_scope'] for _, x, _ in records]
        gaps = [x['remaining_gap'] for _, x, _ in records]
        versions = [x['DUT_executable_sha256'] for _, x, _ in records if valid(x['DUT_executable_sha256'])]
        version_refs = [x['engine_identity_evidence'] for _, x, _ in records if valid(x['engine_identity_evidence'])]
        values = [f"{k}觀測/標籤值={joined(x[k] for _, x, _ in records)}" for k in ('VLEN', 'SEW', 'LMUL', 'VL', 'mask', 'policy')] if records else []
        if main:
            batches = [x for _, x in self.chips[form]]
            compared.extend(x['checker'] + f"；source word assertions={x['source_word_assertions']}；vxsat={x['vxsat_assertions']}；CSR={x['direct_CSR_assertions']}" for x in batches)
            scopes.append('static source assertions + whole-file PASS；不是逐指令動態assertion計數')
            gaps.append('只比選取目的群組／特定vxsat與CSR；未全面比所有32v、來源保存、flags、memory邊界、vstart、fault/restart；store/gather各原checker有盲區')
            versions.append(self.final_identity['build']['stage/elfrun'])
            version_refs.append(f['final_candidate_identity_evidence'])
            values.append('CHIPS主批VLEN標籤=' + joined(x['vlen'] for _, x in main) + '；SEW/LMUL/mask看原geometry同列，不能相乘')
        if not records and not main:
            compared.append('未建立此形式已執行checker比較範圍')
            gaps.append('來源／計畫不證RV32可執行或checker完整；資料、tail、mask、flags、source保存、memory/fault/retry仍未建立')
        if suite == 'ACT':
            legacy = json.loads(f['act_legacy_execution_json'])
            gaps.append('歷史source／signature／runner／版本接合限制以原列為準；source presence不算PASS')
            cases.extend([legacy['base_evidence'], legacy['archive_evidence'],
                          selector('FORM_VERIFICATION_EVIDENCE.csv', form=form, field='act_legacy_execution_json')])
        if suite == 'Ara' and form in {'vsetvli','vsetvl','vsetivli'}:
            status.append('續批外部原checker PASS：同封存ELF／VLEN2048固定Spike先行＋四臂，各28原例完整成功；每檔5tuples／140case綁定。先前QEMU2048啟動拒絕及84靜態診斷保留')
            gaps.append('三完整原檔各28例保留；RV32 CSR/GPR/vill/clobber/Linux diff及compiled gate完成。不可縮AVL/SEW/LMUL或刪例硬通過；非法FAIL漏加num_failed，需檢查原FAILED及28例完成數；vsetivli avl實為rd，rd==VL非獨立AVL公式驗證')
            configs.append('artifacts/ara_vset_current_20261009/AVL_CAPACITY.json（靜態容量，不是實測配置）')
            configs.append('artifacts/ara_vset_current_20261009/SPIKE_ORIGINAL_CASE_RAW.csv（實測原checker參數／每例完整成功）')
            cases.append('artifacts/ara_vset_current_20261009/README.md')
        if suite == 'RVVTS' and form == 'vfadd.vf':
            status.append('外部原生成三完整序列／48原consumer；新ELF雙reference6packet＋固定candidate四配置12PASS；288列是192DUT＋96reference綁定')
            gaps.append('只比原16相依序列終態，被覆寫中間vector/逐指令flags無獨立oracle；非完整GPR/PC/mstatus/memory；其他幾何/rounding/boxing/restart/fault仍OPEN；X/Y失敗及103 reserved原樣保留')
            cases.append('artifacts/rvv_scalar_box_port_20261009/README.md')
        if suite == 'RVVTS' and form == 'vfadd.vv':
            status.append('AD既有新geometry接合：4 candidate tuples＋1成功Spike reference、16原ordinal共80綁定；CLI失敗保留；不增加形式或91 aggregate native准入')
            compared.append('AD原MachineState full32v8192 bytes＋32full64FPR＋10CSR終態；FPR注入/前後/未寫v exact；padding排除；單一Spike算術模型')
            configs.append('artifacts/rvv_multichunk_batch_20261009/CASE_FULL_STATE_RAW.csv')
            cases.append('artifacts/rvv_multichunk_batch_20261009/README.md')
            gaps.append('AD width2/k4兩批已補；v10/v30有跨批晚期observer見證；v26 ordinal16覆寫無獨立中間oracle。一般pressure-cut下一frame/其他geometry/逐指令flags/memory/fault/retry仍缺。AB/AC只裁決既有ta packet，原FAIL保留；通用history-aware oracle仍缺，不沿舊OPEN重跑VL邊界或width1')
        if suite == 'CHIPS':
            assessment='artifacts/chips_ext_fractional_20261008/CURRENT_GAP_ASSESSMENT.csv'
            matches=[r for r in self.rows(assessment)if r['form']==form]
            for r in matches:
                gaps.append('AE rank'+r['rank']+' 指定VLEN'+r['vlen']+'/e'+r['sew']+'/'+r['lmul']+'：'+r['ae_current_gap_kind']+'；'+r['ae_today_evidence']+'；仍缺：'+r['ae_remaining_exact_obligation']+'；原生成器：'+r['ae_original_generator_capability']+'；阻擋：'+r['ae_platform_or_checker_blocker'])
            if matches: cases.append(assessment+';按rank分開，不以其他geometry關閉')
        if suite == 'ACT' and form in {'vsmul.vv','vsmul.vx'}:
            gaps.append('下一最高價值可執行項：固定ACT原cr_vxrm_vs2_vs1_edges/cr_vxrm_vs2_rs1_edges API預記小批Vx8/Vx16完整輸出，離線查explicit rnu/rne active checked half-tie及alias/ELF/signature鏈。原API確實cross四模式，但未保證有tie；全輸出保留，無手換operand/CSR/golden；准入後才Sail原signature→同ELFreference→四配置。既有搜尋零合格，不重跑原fixture；未證平台阻擋。')
            cases.append('artifacts/external_suite_coverage_20261007/act_checker/raw/source/generators/testgen/src/testgen/coverpoints/vector/cr_vxrm_vs_reg_edges.py')
        m1, m2, route_refs = self.route(f, suite, records)
        summary = self.checker_zh(suite, records, bool(main), form)
        results = []
        if main:
            results.append('CHIPS主批DUT PASS別名列=' + str(len(main)))
        for label, group in (('DUT案例索引', joined_dut), ('歷史待查索引', pending),
                             ('reference索引', refs)):
            if group:
                results.append(label + '：' + counted(x['result'] for _, x, _ in group))
        if not_run:
            results.append('未執行索引：' + counted(x['result'] for x in not_run))
        out = dict(zip(CORE_FIELDS, [source, source_refs, '；'.join(status), len(joined_dut), len(pending),
            len(not_run), len(refs), len(main), joined(configs), joined(values), joined(compared + scopes),
            summary, joined(gaps), '；'.join(results) if results else '無執行結果紀錄',
            joined([revision, *(x['suite_revision'] for _, x, _ in records)]), joined(versions),
            joined(version_refs), m1, m2, route_refs, joined(cases)]))
        return out

    def checker_zh(self, suite, records, main, form):
        if suite == 'RVVTS' and form == 'vfadd.vf':
            return '固定原RVVTS生成器API產生原body/input，Z只修本地禁C/page-aligned wrapper及full-FLEN傳輸；48原scalar malformed upper bits接实际FPR before/after/encoding。新同ELF QEMU＋Spike/PK packet，由原MachineState.compare精確比full32v＋32個full64 FPR＋10CSR，另比原input=actual before=after；三endpoint fflags0/0/16，沒有自算golden。只證三完整序列終態，不證每consumer中間結果／逐指令flags或M1 native准入；reference與candidate分列'
        if suite == 'ACT' and form in {'vmfeq.vf','vmflt.vf','vmfle.vf'}:
            return '固定Sail＋原processor，FP32/64兩完整原檔同ELF QEMU及四臂PASS；BASE存byte但vmxor.mm/vfirst.m在VL1只比mask bit0；LEN比全部1024mask bits，active exact、mu exact／ma原reference-or-1，tail不論vta接受原signature／1／原VLMAX重算；輔助VLMAX無獨立DUT結果／FFLAGS checker。原vector operand/alias後load、scalar FPR原LI/sw scratch與FLW/FLD、fixed FLEN64、load寬度／compiled word；原FLW皆valid box，沒有malformed box區辨原例／direct upper FPR observer、mask、NaN/±zero、Sail mask bits及aggregate FFLAGS逐例接合；不是全32v或M1/M2准入，cross-owner限制保留'
        if suite == 'ACT' and form in {'vmfeq.vv','vmflt.vv','vmfle.vv'}:
            return '固定Sail＋原processor，FP32/64兩完整原檔同ELF QEMU及四臂PASS；BASE存byte但vmxor.mm/vfirst.m在VL1只比mask bit0；LEN比全部1024mask bits，active exact、mu exact／ma原reference-or-1，tail不論vta接受原signature／1／原VLMAX重算；輔助VLMAX無獨立DUT結果／FFLAGS checker。原两operand/alias後load、mask、NaN/±zero、Sail mask bits及aggregate FFLAGS逐例接合；不是全32v或M1/M2准入，cross-owner限制保留'
        if suite == 'ACT' and form in {'vfrec7.v','vfrsqrt7.v'}:
            return '固定Sail＋原processor，FP32/64兩完整原檔QEMU與四臂PASS；原vmsne.vv精確比估值全部32/64bits，BASE lane0、LEN依policy比目的群組，FFLAGS原slot四bytes；各檔128原custom sig inputs接合，五frm各10例但同input答案/旗標全同，沒有rounding區辨/overflow selection原例；非數值tolerance或自填golden，非allstate/native准入'
        if suite == 'ACT' and form in {'vfmin.vv','vfmax.vv','vfclass.v'}:
            detail='min/max原sNaN→NV16、qNaN→0、±zero兩次序及雙NaNcanonical結果'if form!='vfclass.v'else'原十類bit0–9，含sNaN/qNaN，FFLAGS全0'
            return '固定Sail原signature＋原processor，FP32/64兩完整原檔同ELF QEMU與四臂PASS；'+detail+'；原BASE lane0，LEN按checker LMUL與tu/mu或ta/ma規則比destination group；FFLAGS比較XLEN32四bytes（FP64 stride8 padding不算）；來源/body/input/checker/conditional不改，跨owner setup read限制逐列保留；不證all32v/GPR/CSR、動態branch或M1/M2准入；歷史未接合列另保留'
        if suite == 'Ara' and form in {'vsetvli','vsetvl','vsetivli'}:
            return '原check_vtype_vl固定Spike＋四臂：每完整檔28例／140case綁定；合法vtype/AVL==VL及非法vill(bit31)/VL0關係，逐例開始/成功/FAILED核對。另接主審既有336組candidate原ARA_CONFIG對同ELF Spike全等（每形式112，含vsetivli rd/VL獨立觀察對照），新engine/PASS0；vsetivli avl是rd輸出，未自算AVL公式或替換答案；不證全state/M1/M2准入，QEMU拒絕保留'
        if main:
            if form in ('vsetvl', 'vsetvli', 'vsetivli'):
                return 'CHIPS主批比VL/vtype/vstart等原CSR常數與rd關係；答案含本地ELEN64公式／literal，不是Spike CSR capture'
            text = 'CHIPS主批比選取目的群組的32-bit words；vxsat/CSR僅原檔有assertion者'
            if form in ('vcpop.m', 'vfirst.m', 'vmv.x.s', 'vfmv.f.s'):
                text += '；scalar結果搬回vector再store/readback比較，非獨立完整scalar暫存器oracle'
            if form.startswith('vs') and any(word in form for word in ('e8', 'e16', 'e32', 'e64', 'ei')):
                text += '；store記憶體prefix／coupled鏈的盲區須查原列'
            return text + ('；補測比較範圍另見CSV' if records else '')
        checked = [x for _, x, a in records if x['result'] == 'PASS' and a == 'target_instruction']
        known = [x for _, x, a in records if a == 'target_instruction']
        text = ' '.join(x['checker_compared_state'] + ' ' + x['checker_scope'] for x in known)
        prefix = '' if checked else '未有已接合PASS；以下為歷史／未跑checker索引：'
        if suite == 'RVVTS':
            if not known:
                return '只有grammar/table來源；未接合此形式合法生成序列／已執行checker，不算已測'
            return prefix + '整段序列終點32個實體vreg＋10 CSR（含flags）；非逐指令中間oracle；失敗／未跑另保留'
        if suite == 'ACT':
            notes = []
            if 'element 0' in text or 'element0' in text: notes.append('BASE常只比element0')
            if 'LEN' in text or 'physical' in text: notes.append('LEN依原signature範圍比目的群組')
            if 'fflags' in text.lower() or 'FFLAGS' in text: notes.append('部分原macro另比fflags')
            if 'scalar register' in text: notes.append('選取scalar暫存器signature')
            if not known:
                return '來源／歷史檔名存在；實際target與signature比較範圍待查，不算已測'
            return prefix + '；'.join(notes or ['依原signature macro所列目的值']) + '；歷史compiled target/signature接合保留原限制，full source/runner與動態branch仍待查；未建立all32v/source保存'
        if suite == 'Ara':
            shapes = sorted({(int(n), int(w)) for n, w in re.findall(r'(\d+) listed (\d+)-bit destination elements', text)})
            notes = [f'{n}個{w}-bit目的elements' for n, w in shapes]
            if 'XCMP:' in text: notes.append('XCMP比1個32-bit scalar結果')
            if 'VVCMP' in text or 'VMCMP' in text: notes.append('memory/store readback或prefix；不證完整memory邊界')
            source = [x for _, x in self.ara_assertions.get(form, [])]
            if not notes:
                notes.append('來源checker=' + joined(x['checker'] for x in source) if source else '未確認此形式checker target')
            if any(x['checker'] == 'check_vtype_vl' for x in source):
                notes.append('來源比VL/vtype CSR；未建立此形式已執行接合')
            if any(x['secondary_checkers'] for x in source):
                notes.append('來源另有' + joined(re.sub(r':\d+', '', name) for x in source for name in x['secondary_checkers'].split(';') if name) + '；source行存在不證本批逐次執行')
            return prefix + '；'.join(notes) + '；coupled/未知input限制見原列；非全32v/CSR/flags'
        if not known:
            return '未有此形式已執行checker接合；來源不算PASS，N/A不補猜測項'
        return '原補測目的群組words或store prefix；依原target列；其他register/flags/memory全範圍未建立'

    def extra(self, form, suite):
        x = self.additional[form]
        if suite in ('RiESCUE', 'CTK', 'FORCE_RISCV'):
            if suite == 'RiESCUE':
                presence = f"descriptor={x['riescue_descriptor_present']}；default target={x['riescue_default_target_present']}"
                paths = (x['riescue_descriptor_source'], x['riescue_default_target_source'])
                revision = self.additional_summary['revisions']['riescue']
            elif suite == 'CTK':
                presence = 'CTK選取default group=' + x['ctk_selected_default_group'] + '；不能把RiESCUE descriptor全627當選取target'
                paths = (x['riescue_default_target_source'],)
                revision = self.additional_summary['revisions']['riescue']
            else:
                presence = f"descriptor={x['force_descriptor_present']}；literal template target={x['force_literal_template_target']}"
                paths = (x['force_descriptor_source'], x['force_literal_template_source'])
                revision = self.additional_summary['revisions']['force-riscv']
            refs = selector('additional_generators/FORM_SOURCE_JOIN.csv', form=form) + '；原repository locator=' + joined(paths)
            gap = 'RV32原生body/checker/DUT oracle未知；descriptor/default/template三層分開，未展開未知參數化patterns'
        elif suite == 'RVV_ATG':
            declarations = self.atg.get(form, [])
            presence = '有literal opcode宣告（非assertion target）' if declarations else '既有literal宣告未列；alias/參數化能力未知'
            refs = selector('atg_rif/ATG_OPCODE_DECLARATIONS.csv', declaration=form)
            refs += '；原source=' + joined(x['source'] + ':' + x['line'] for _, x in declarations)
            revision = self.atg_summary['rvv_atg']['revision']
            gap = 'RV32 runner/checker未知；來源scan沒有展開四個unmatched alias，不能當語意PASS'
        elif suite == 'SiFive_RIF':
            presence = '未知：已有typed intrinsic operator盤點，無逐ISA形式編譯接合'
            refs = 'atg_rif/RIF_OPERATORS.csv（operation_id不是form，不能猜對應）；atg_rif/SUMMARY.json'
            revision = self.atg_summary['rif']['revision']
            gap = 'RV32／optional FP16／完整failure accounting未知；未把intrinsic能力冒充此form測項'
        elif suite == 'Tenstorrent':
            lines = self.ten_mentions.get(form, [])
            presence = ('保留RV64 sample有literal mention（setup/target/checker未接合）' if lines else
                        '未知：保留sample未見literal，不等於整個1056檔source無此form')
            refs = 'tenstorrent/PROVENANCE.json；tenstorrent/TREE.json；tenstorrent/rv64v_0.S'
            if lines: refs += '原行=' + ','.join(map(str, lines))
            revision = self.ten['revision']
            gap = '未完成全RV64 corpus逐形式source/checker及RV32全body相容性；不推source缺席'
        else:
            presence = '未知：已列生成器候選，沒有retained emitted ISA form索引'
            refs = selector('EXECUTION_BATCHES.csv', suite='RVISmith')
            revision = '未知；沿既有selection限制，不補猜commit'
            gap = 'generator輸出／版本／RV32 checker與逐ISA接合未知'
        return dict(zip(EXTRA_FIELDS, [presence, refs,
            '既有此source盤點未跑DUT；runtime/checker比較狀態未知；不計ISA PASS', revision, gap,
            '未知：未有此形式已跑配置索引；來源定位=' + refs,
            '未跑；不是PASS或FAIL', '未知：無此套件此形式逐PC證據', '未知：無此套件此形式逐PC證據']))

    def render(self):
        from rvv_actual_form_validation import ActualValidation
        self.actual = ActualValidation(self).run()
        self.actual_fields = list(self.actual.columns(self.forms[0]['form']))
        output = []
        for number, f in enumerate(self.forms, 1):
            row = dict(form=f['form'], family=f['family'], 家族=FAMILIES[f['family']],
                RV32_ELEN64適用性=f['rv32_elen64_applicability'],
                FORM原始索引=selector('FORM_VERIFICATION_EVIDENCE.csv', form=f['form']) + f'；CSV data record={number}',
                規格版本=f['spec_revision'], 完整語意驗收='未完成；盤點完整不等於完整RVV驗收',
                共同缺口='；'.join(json.loads(f['unverified_json'])))
            for suite in CORE:
                row.update({suite + '_' + k: v for k, v in self.core(f, suite).items()})
            for suite in EXTRA:
                row.update({suite + '_' + k: v for k, v in self.extra(f['form'], suite).items()})
            row.update(self.actual.columns(f['form']))
            output.append(row)
        assert len(output) == len({x['form'] for x in output}) == 627
        assert sum(x['RV32_ELEN64適用性'] == 'NOT_APPLICABLE' for x in output) == 32
        assert sum(int(x['CHIPS_主批別名列數']) > 0 for x in output) == 595
        assert sum(int(x['CHIPS_主批別名列數']) for x in output) == sum(
            x['control'] == 'False' and x['form'] in self.names for _, rows in self.alias.items() for _, x in rows)
        assert sum(int(x[s + '_已接合DUT列數']) + int(x[s + '_歷史待查列數']) +
                   int(x[s + '_未執行列數']) + int(x[s + '_reference列數'])
                   for x in output for s in CORE) + len(self.unassigned) == len(self.suite_rows)
        stream = io.StringIO(newline='')
        writer = csv.DictWriter(stream, FIELDS + self.actual_fields, lineterminator='\n')
        writer.writeheader(); writer.writerows(output)
        markdown = self.markdown(output)
        return output, stream.getvalue().encode(), markdown.encode()

    def markdown(self, rows):
        lines = ['# RVV 627形式逐套件完整盤點', '',
            '本頁只整理既有證據；627形式全部列出，RV32／ELEN64必需595、ei64 indexed不適用32。沒有執行DUT、compiler、generator或改答案；計畫／狀態由主審維護。', '',
            '一個指令形式一節，四個主要套件各一列；其他已盤點套件另列source／未知／未跑。來源有測項、原checker真正接合、歷史待查及明確未跑分開；N/A仍保留來源與歷史記錄。', '',
            '[完整627列CSV](COMPLETE_FORM_SUITE_INVENTORY.csv)可篩選`form`。欄位前綴是套件名，`已接合DUT列數`是索引列而非獨立case／PASS數；reference另計。`歷史待查列數`保留檔名／ELF接合，不升格成current PASS。', '',
            'CHIPS主批從FORM＋[CHIPS batch索引](CHIPS_INSTRUCTION_BATCH_COVERAGE.csv)＋' +
            link('artifacts/rvv_final_regression_20261007/ALIAS_RESULTS.csv', 'final別名索引') +
            '加入全部595必需形式；SUITE只收CHIPS補測，不能拿它的7種形式當整套CHIPS廣度。', '',
            '配置是原source或觀測的同列context；SEW／LMUL／VLEN／mask值摘要不能相乘。AVL標籤不等於runtime VL；whole-file PASS不證每個branch有動態count。M1/M2開關也不證實際路徑。', '',
            '詳細案例：在[SUITE](SUITE_EXECUTED_CASE_COVERAGE.csv)選取`target_instruction=form,suite=套件`；看`batch,recorded_case,target_id,engine,arm,SEW,LMUL,VLEN,VL,AVL_source,mask,policy,checker_compared_state,checker_scope,result,target_join_status,DUT_executable_sha256,result_evidence,raw_stdout,raw_stderr,configuration_evidence,remaining_gap`。歷史ACT `target_instruction=待查`須另按本CSV的`ACT_案例原始索引`所列recorded_case選取，只是檔名關聯。', '',
            'CHIPS主批：batch CSV選`instruction=form`；ALIAS_RESULTS選`form=form,control=False`，看`batch,test,arm,vlen,cell_id,status,raw_directory`；' +
            link('artifacts/rvv_geometry_obligations_20261007/EVIDENCE.csv', '配置索引') +
            '選`form=form,kind=CHIPS-target-vset`，看`source,line,vlen,sew,lmul,masked,requested_vl,policy,report`。不用巨大JSON當表格：完整selector／版本SHA／checker原文／來源行見本CSV與[FORM](FORM_VERIFICATION_EVIDENCE.csv)。', '',
            '版本：CHIPS ' + self.capability['chips_configs']['revision'] + '；ACT ' + self.capability['act_including_smv']['revision'] +
            '；Ara ' + self.ara_summary['revision'] + '；RVVTS ' + self.capability['rvvts_generator']['revision'] +
            '。DUT各candidate／historical版本不合併，按CSV的`套件_DUT版本`與`版本索引`查。', '',
            'Task71依SUITE_RUN接合45–70：逐形式新增source/compiled/emitted/program/result-check/coupled欄；[目前套件摘要](JSERV_VERIFICATION_SUMMARY.md)與[實際綁定](ACTUAL_FORM_VALIDATION_BINDINGS.csv)。下面舊source-only盤點是歷史資料；目前執行以新增欄為準。', '',
            '尚待查：ACT歷史source/runner/signature provenance、其他套件RV32可執行checker、全幾何／全state與中間oracle、未逐PC證實的M1/M2路徑。這些阻礙不會被盤點報表改成PASS。', '',
            '重建：`python3 artifacts/external_suite_coverage_20261007/export_readable_coverage.py --complete-inventory`；' +
            '只讀核對加`--check`，驗分母、唯一form、原索引列數接合、CHIPS595主批、來源hash及三份產出一致。', '', '## 家族索引', '']
        grouped = collections.defaultdict(list)
        for row in rows: grouped[row['family']].append(row)
        for family, title in FAMILIES.items():
            lines.append(f'- [{title}](#family-{family})：{len(grouped[family])}形式')
        for family, title in FAMILIES.items():
            lines.extend(['', f'<a id="family-{family}"></a>', f'## {title}（{len(grouped[family])}形式）', ''])
            for x in sorted(grouped[family], key=lambda x: x['form']):
                name = x['form']; app = '必需' if x['RV32_ELEN64適用性'] == 'REQUIRED' else 'N/A：RV32不支援ei64索引，保留列'
                lines.extend([f'### `{name}` — {app}', '',
                    f'追溯：[FORM](FORM_VERIFICATION_EVIDENCE.csv)選`form={name}`；[完整CSV](COMPLETE_FORM_SUITE_INVENTORY.csv)同選。所有結果／版本原值與盲區詳見各套件欄位。', '',
                    '| 套件 | 來源與執行 | checker比哪些狀態／缺口 | M1／M2路徑 |',
                    '|---|---|---|---|'])
                for suite in CORE:
                    execution = x[suite + '_執行分類']
                    state = x[suite + '_來源'] + '；' + execution
                    # Show outcome labels, including FAIL and NOT_EXECUTED, not just PASS totals.
                    results = x[suite + '_結果原值']
                    state += '；結果=' + results
                    route = x[suite + '_M1路徑'] + '；M2：' + x[suite + '_M2路徑']
                    lines.append('| ' + ' | '.join(map(md, [suite, state, x[suite + '_checker中文摘要'], route])) + ' |')
                lines.extend(['', '**Task71 current evidence stages** (UNKNOWN means no established join; program receipt does not prove every opcode ran):', '', '| Suite | Source | Compiled source | Emitted | Program | Result checked | Coupled endpoint | Diagnostic |', '|---|---|---|---|---|---|---|---|'])
                for suite in self.actual.suites:
                    lines.append('| '+suite+' | '+' | '.join(x[suite+'_'+k] for k in ('source_present','compiled_source','emitted','program_executed','result_checked','coupled_endpoint','diagnostic_only'))+' |')
                lines.extend(['', '[Actual bindings](ACTUAL_FORM_VALIDATION_BINDINGS.csv): select suite and target/emitted/result_checked/coupled field containing `'+name+'`; ledger row_id retains candidate, source, checker, reference, raw and limitations.', ''])
                if name in {'vrgather.vi','vrgatherei16.vv'}:
                    witness='VL1/max64，masked lane0→index13→0xf245，舊值0xded1'if name=='vrgather.vi'else'VL23/max256，masked lane10→index135→0xe106，舊值0xc443；同EEW16 source/index alias'
                    lines.extend(['', '10-09 ACT完整原檔補驗：VLEN1024/e16，'+witness+'；獨立QEMU先行及固定四臂完整原checker PASS。另列all0-mask mu 64元素保存，沒有configuration/input/operand/expected改動或generation。歷史signature producer身分仍未知；gather target未進M1 FORM，M2單PC路徑未知，rank15 VLEN256/e64/m8 masked仍OPEN。'+link('artifacts/gather_masked_20261009/README.md','原source／checker／raw／限定範圍'), ''])
                lines.extend(['', '配置／案例原索引：CHIPS用上述主批三表＋SUITE補測；ACT/Ara/RVVTS用SUITE逐target同列。' +
                    f'選取`form={name}`或`target_instruction={name}`，suite再分開；個別source context／待查AVL/VL及完整盲區不合併成組合。', '',
                    '<details>', '<summary>其他七個套件的逐形式來源與缺口</summary>', '',
                    '| 其他已盤點套件 | 此形式來源／能力 | 執行／缺口 |', '|---|---|---|'])
                for suite in EXTRA:
                    label = suite.replace('_', '-')
                    lines.append('| ' + ' | '.join(map(md, [label, x[suite + '_來源'], x[suite + '_執行與checker'] + '；' + x[suite + '_缺口']])) + ' |')
                lines.extend(['', '歷史source盤點逐形式selector／source行／版本（不作目前執行結論）：本CSV的`RiESCUE_*、CTK_*、FORCE_RISCV_*、RVV_ATG_*、SiFive_RIF_*、RVISmith_*、Tenstorrent_*`。', '', '</details>', ''])
        return '\n'.join(lines) + '\n'


def main(check=False, output=None):
    inventory = Inventory(); inventory.load()
    rows, csv_bytes, md_bytes = inventory.render()
    assert len(re.findall(r'^### `', md_bytes.decode(), re.M)) == 627
    assert sum(row['RV32_ELEN64適用性'] == 'REQUIRED' for row in rows) == 595
    report = dict(status='PASS_OFFLINE_COMPLETE_FORM_INVENTORY', forms=627, required=595, not_applicable=32,
        unique_form_rows=627, core_suites=list(CORE), other_suites=list(EXTRA),
        chips_main_forms=595, chips_main_alias_rows=sum(int(x['CHIPS_主批別名列數']) for x in rows),
        suite_rows=len(inventory.suite_rows), suite_association_counts=dict(inventory.associations),
        suite_unassigned_rows=inventory.unassigned,
        suite_rows_by_suite=dict(collections.Counter(x['suite'] for x in inventory.suite_rows)),
        family_counts=dict(collections.Counter(x['family'] for x in rows)),
        inputs=dict(sorted(inventory.inputs.items())),
        output_sha256={'COMPLETE_FORM_SUITE_INVENTORY.csv': hashlib.sha256(csv_bytes).hexdigest(),
                       'COMPLETE_FORM_INVENTORY_ZH.md': hashlib.sha256(md_bytes).hexdigest()},
        DUT_calls=0, compiler_calls=0, generator_calls=0, answers_changed=False,
        configuration_scope='original index/context rows only; no Cartesian products',
        blockers=['historical ACT source/ELF/runner/signature join limitations retained',
                  'source presence not runtime PASS; other suites checker/RV32 unknown or not run',
                  'M1/M2 per-PC path unknown unless original scoped PC/frame/code evidence exists',
                  'inventory completeness does not close full-state/all-geometry/intermediate oracle/fault/restart gaps'])
    actual_targets = inventory.actual.targets()
    report['output_sha256'].update({name:hashlib.sha256(content).hexdigest() for name,content in actual_targets.items()})
    report['actual_validation'] = {'ledger_rows':len(inventory.actual.rows), 'binding_rows':len(inventory.actual.bindings), 'missing_join_rows':len(inventory.actual.missing), 'quarantined_RIF_O2_ELFs':len(inventory.actual.corrections), 'scope':'target checks and coupled endpoints separate; no opcode execution/influence inferred from program receipts'}
    report_bytes = (json.dumps(report, ensure_ascii=False, indent=2) + '\n').encode()
    targets = {'COMPLETE_FORM_SUITE_INVENTORY.csv': csv_bytes,
               'COMPLETE_FORM_INVENTORY_ZH.md': md_bytes,
               'COMPLETE_FORM_INVENTORY_CHECK.json': report_bytes}
    targets.update(actual_targets)
    # No partially updated output on a failed assertion; --check writes nothing.
    for path, digest in inventory.inputs.items():
        assert hashlib.sha256((W / path).read_bytes()).hexdigest() == digest, ('input changed during export', path)
    if not check:
        # Preserve internal report links and relocate external evidence links.
        def relocate(m):
            href = m[1]
            if urlsplit(href).scheme or href.startswith('#'):
                return m[0]
            path, sep, anchor = href.partition('#')
            if path in targets:
                return m[0]
            target = R / unquote(path)
            return '](' + quote(os.path.relpath(target, output), safe='/') + (sep + anchor) + ')'
        for name, content in targets.items():
            if name.endswith('.md'):
                targets[name] = re.sub(r'\]\(([^)]+)\)', relocate, content.decode()).encode()
        report['output_sha256'] = {name: hashlib.sha256(content).hexdigest()
                                   for name, content in targets.items()
                                   if name != 'COMPLETE_FORM_INVENTORY_CHECK.json'}
        report['reproducer_sha256'] = {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in (Path(__file__), Path(__file__).with_name('rvv_actual_form_validation.py'))}
        targets['COMPLETE_FORM_INVENTORY_CHECK.json'] = (json.dumps(report, ensure_ascii=False, indent=2) + '\n').encode()
    for name, content in targets.items():
        if check: assert (R / name).read_bytes() == content, ('stale output/input identity', name)
        else: (output / name).write_bytes(content)
    print(f'{"CHECK PASS" if check else "Exported"}: 627 forms / 595 required / 32 N/A; CHIPS main 595; '
          f'{len(inventory.suite_rows)} SUITE rows accounted; unassigned={len(inventory.unassigned)}; DUT/compiler/generator=0')


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evidence-root', type=Path, required=True,
                   help='extracted evidence tree containing artifacts/, not the code checkout')
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--check', action='store_true', help='read-only comparison with retained reports')
    mode.add_argument('--output', type=Path, help='new report directory; runs no external tests')
    args = p.parse_args()
    W = args.evidence_root.resolve()
    R = W / 'artifacts/external_suite_coverage_20261007'
    if args.output:
        args.output.mkdir(parents=True, exist_ok=False)
    main(args.check, args.output)
