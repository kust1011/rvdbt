import unittest
from rvv_scope_report import STAGES, report


class ScopeTests(unittest.TestCase):
    def data(self):
        forms = [{'form': 'vadd.vv', 'rv32_elen64_applicability': 'REQUIRED'},
                 {'form': 'vadd.vx', 'rv32_elen64_applicability': 'REQUIRED'}]
        def suite(name, checked=(), coupled=(), diagnostic=()):
            stages = {k: [] for k in STAGES}
            stages.update(source_present=['vadd.vv', 'vadd.vx'], result_checked=list(checked),
                          coupled_endpoint=list(coupled), diagnostic_only=list(diagnostic))
            return {'suite': name, 'forms': stages, 'candidates': [{'candidate': 'original-build'}]}
        summary = {'scope': 'finite profile', 'suites': [suite('A', ['vadd.vv']),
                   suite('B', ['vadd.vv'], ['vadd.vx']), suite('C', diagnostic=['vadd.vx'])]}
        return forms, summary

    def test_overlap_endpoint_and_diagnostic_do_not_inflate_checked_union(self):
        forms, summary = self.data()
        result = report(forms, summary, 'vadd.vx')
        self.assertEqual(result['checked_union'], 1)
        self.assertIsNone(result['per_form'][0]['suites'][1]['result_checked'])
        self.assertTrue(result['per_form'][0]['suites'][1]['coupled_endpoint'])
        self.assertIsNone(result['per_form'][0]['suites'][2]['program_executed'])
        self.assertEqual(result['candidate_scopes'][0]['candidates'][0]['candidate'], 'original-build')

    def test_unknown_forms_duplicate_forms_and_unknown_stage_members_rejected(self):
        forms, summary = self.data()
        with self.assertRaises(ValueError): report(forms, summary, 'unknown')
        with self.assertRaises(ValueError): report(forms + forms[:1], summary)
        summary['suites'][0]['forms']['result_checked'].append('unknown')
        with self.assertRaises(ValueError): report(forms, summary)

    def test_delivered_compact_forms_header_preserves_report(self):
        forms, summary = self.data()
        compact = [{'form': r['form'], 'applicability': r['rv32_elen64_applicability']} for r in forms]
        self.assertEqual(report(compact, summary, 'vadd.vv'), report(forms, summary, 'vadd.vv'))

    def test_conflicting_applicability_headers_rejected(self):
        forms, summary = self.data()
        forms[0]['applicability'] = 'UNKNOWN'
        with self.assertRaisesRegex(ValueError, 'conflicting applicability'):
            report(forms, summary)

class NavigationTests(unittest.TestCase):
    def test_original_bindings_shared_alias_and_applicability(self):
        from rvv_scope_report import navigation, selected_navigation
        forms = [{'form': f, 'family': 'integer_single_width', 'applicability': a}
                 for f,a in [('vadd.vv','REQUIRED'),('alias','REQUIRED'),('ei64','NOT_APPLICABLE')]]
        packages = {'CHIPS': {'records':[{'form':'vadd.vv','case':'same'}, {'form':'alias','case':'same'}]}}
        binding = {'suite':'CHIPS','result_checked_forms':'vadd.vv;alias','ledger_row_id':'id',
                   'configuration_known_json':'{"VL":"UNKNOWN"}', 'remaining':'unobserved'}
        x = navigation(forms,[binding,binding],packages,{'original':'hash'})
        self.assertEqual(len(x['canonical_bindings']),1)
        self.assertEqual(x['forms'][0]['selectors']['Task90'],x['forms'][1]['selectors']['Task90'])
        r = selected_navigation(x,'vadd.vv',{})
        self.assertEqual(r['canonical_bindings'][0],binding)
        self.assertEqual(r['new_guest_executions'],0)
        self.assertFalse(x['forms'][2]['selectors'])
        with self.assertRaisesRegex(ValueError,'unknown form'):
            selected_navigation(x,'other',{})

    def test_missing_applicable_navigation_fails(self):
        from rvv_scope_report import navigation
        with self.assertRaisesRegex(ValueError,'missing retained CHIPS'):
            navigation([{'form':'vadd.vv','family':'integer','applicability':'REQUIRED'}],[],{}, {})

    def test_modified_package_selector_rejected(self):
        from rvv_scope_report import package_index
        from tempfile import TemporaryDirectory
        from pathlib import Path
        import json
        with TemporaryDirectory() as temp:
            p = Path(temp)
            (p/'FILES.json').write_text(json.dumps({'NAVIGATION.csv':{'sha256':'0'*64}}))
            (p/'NAVIGATION.csv').write_text('form,case\nvadd.vv,case\n')
            with self.assertRaisesRegex(ValueError,'package index identity'):
                package_index({'CHIPS':p})

    def test_selected_raw_output_is_authenticated(self):
        from rvv_scope_report import package_index, navigation, selected_navigation
        from tempfile import TemporaryDirectory
        from pathlib import Path
        import hashlib
        import json
        with TemporaryDirectory() as temp:
            root = Path(temp)
            files = {}
            def put(name, value):
                path = root/name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(value)
                files[name] = {'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
            row = {'form':'vadd.vv','case':'one','source':'case/one.S','result':'case/RESULT.json'}
            put('CASES.json', json.dumps([row]))
            put('case/one.S', 'vadd.vv v1, v2, v3\n')
            put('case/RESULT.json', json.dumps({'DUT':[{'raw':'raw/B'}], 'reference':[]}))
            put('case/raw/B/result.json', '{}')
            put('case/raw/B/command.json', '[]')
            put('case/raw/B/stdout', 'PASS\n')
            put('case/raw/B/stderr', '')
            (root/'FILES.json').write_text(json.dumps(files))
            packages = package_index({'ACT':root})
            packages['CHIPS'] = {'records':[{'form':'vadd.vv'}]}
            index = navigation([{'form':'vadd.vv','family':'integer','applicability':'REQUIRED'}],
                               [{'suite':'ACT','result_checked_forms':'vadd.vv'}],packages,{})
            selected_navigation(index,'vadd.vv',{'ACT':root})
            (root/'case/raw/B/stdout').write_text('FAIL\n')
            with self.assertRaisesRegex(ValueError,'payload identity'):
                selected_navigation(index,'vadd.vv',{'ACT':root})


class ReplayReceiptTests(unittest.TestCase):
    def fixture(self, root, stdout='PASS\n'):
        import json
        from rvv_tests import digest, classify
        raw = root/'raw'; raw.mkdir()
        cell = dict(id='one', elf_sha256='a'*64, vlen=128, control=False,
                    aliases=[{'arm':'B'}],
                    expected_returncode=0, expected_stdout='PASS\n',
                    flags=['--fsroot={WORK}/fs', '--cache={WORK}/cache', '--', '/t.elf'])
        original = root/'original.json'
        def save(p, v): p.write_text(json.dumps(v))
        save(original, dict(cells=[cell], timeout_seconds=120))
        build = {'stage/elfrun':'b'*64, 'stage/libdbtjitshared.so':'c'*64}
        save(raw/'manifest.json', dict(cells=[cell], timeout_seconds=120, candidate={'build':build}))
        identities = {'/engine':'b'*64, '/lib':'c'*64}
        save(raw/'invocation.json', dict(selected_cases=['one'], engine_files_before=identities,
                                        manifest_sha256=digest(raw/'manifest.json')))
        save(raw/'summary.json', dict(candidate_unchanged=True, engine_files_after=identities))
        case = raw/'one'; case.mkdir(); save(case/'case.json', cell)
        (case/'stdout').write_text(stdout); (case/'stderr').write_text('')
        result = dict(id='one', status=classify(0, stdout.encode(), cell), returncode=0, error=None,
                      control=False, elf_sha256=cell['elf_sha256'], stdout_sha256=digest(case/'stdout'),
                      stderr_sha256=digest(case/'stderr'), checker='original predicate')
        save(case/'result.json', result); save(raw/'results.json', [result])
        save(case/'command.json', ['/engine']+[f.replace('{WORK}', '/remote/one/work') for f in cell['flags']])
        row = dict(candidate='clean961', cell_id='one', elf_sha256=cell['elf_sha256'], VLEN='128',
                   form='vadd.vv', arm='B', case='original', batch='batch', control='False',
                   receipt='old/receipt', source='original.S')
        binding = dict(suite='CHIPS', candidate='clean961', elf_sha256=cell['elf_sha256'], arm='B',
                       source_case='original', result_checked_forms='vadd.vv', flags_json=json.dumps(cell['flags']))
        index = dict(packages={'CHIPS':{'records':[row]}}, canonical_bindings=[binding],
                     forms=[dict(form='vadd.vv', applicability='REQUIRED', family='integer')])
        return index, raw, original

    def test_current_receipt_join_and_preserved_failure(self):
        from tempfile import TemporaryDirectory
        from pathlib import Path
        from rvv_scope_report import chips_replay
        for stdout, expected in [('PASS\n', 1), ('WRONG\n', 0)]:
            with TemporaryDirectory() as temp:
                root = Path(temp); args = self.fixture(root, stdout)
                result = chips_replay(*args, root/'output')
                self.assertEqual(result['checked_union_count'], expected)
                self.assertEqual(result['total'], 1)
                self.assertEqual(result['unattempted'], 0)
                self.assertIn('old/receipt', (root/'output/replay-receipts.csv').read_text())

    def test_changed_oracle_stream_and_candidate_rejected(self):
        from tempfile import TemporaryDirectory
        from pathlib import Path
        import json
        from rvv_scope_report import chips_replay
        for field in ('oracle', 'stream', 'candidate'):
            with TemporaryDirectory() as temp:
                root = Path(temp); index, raw, original = self.fixture(root)
                if field == 'oracle':
                    value = json.loads(original.read_text()); value['cells'][0]['expected_stdout']='WRONG\n'
                    original.write_text(json.dumps(value))
                elif field == 'stream':
                    (raw/'one/stdout').write_text('WRONG\n')
                else:
                    value=json.loads((raw/'summary.json').read_text());value['engine_files_after']['/engine']='d'*64
                    (raw/'summary.json').write_text(json.dumps(value))
                with self.assertRaises(ValueError): chips_replay(index, raw, original, root/'output')
                self.assertFalse((root/'output').exists())


if __name__ == '__main__':
    unittest.main()
