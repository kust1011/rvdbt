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


if __name__ == '__main__':
    unittest.main()
