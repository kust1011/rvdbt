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
