import json
import unittest

from rvv_compact_scope import project, render
from rvv_scope_report import STAGES


class CompactScopeTests(unittest.TestCase):
    def data(self):
        forms = [{'form': f, 'family': 'integer', 'rv32_elen64_applicability': 'REQUIRED'}
                 for f in ('vadd.vv', 'vadd.vx')]
        stages = {k: [] for k in STAGES}
        stages.update(result_checked=['vadd.vv'], coupled_endpoint=['vadd.vx'])
        summary = {'scope': 'saved finite sets', 'suites': [{'suite': 'A', 'forms': stages}]}
        routes = [{'form': 'vadd.vv', 'applicability': 'REQUIRED',
                   'decoder_routes': '["vialu"]', 'runtime_status': 'NOT_PROVEN',
                   'route_implementations': json.dumps({'vialu': {'direct_qir': 'recorded QIR',
                                                                 'helper': 'recorded helper'}})}]
        return forms, summary, routes

    def test_endpoint_missing_route_and_literal_classes_preserved(self):
        data = project(*self.data())
        text, rows, counts = render(data)
        self.assertEqual(counts['checked_union'], 1)
        self.assertEqual(rows[1]['checked_suites'], '')
        self.assertEqual(rows[1]['endpoint_suites'], 'A')
        self.assertIsNone(data['forms'][1]['recorded_routes'])
        self.assertEqual(rows[1]['implementation_classes_json'], 'null')
        self.assertIn('recorded QIR', text)
        self.assertEqual(rows[0]['route_runtime_status'], 'NOT_PROVEN')

    def test_operand_specific_variants_are_not_collapsed(self):
        forms, summary, routes = self.data()
        routes.append({**routes[0], 'form': 'vadd.vx', 'route_implementations':
                       json.dumps({'vialu': {'direct_qir': 'different body', 'helper': 'same route'}})})
        text, rows, counts = render(project(forms, summary, routes))
        self.assertIn('vialu/1', text)
        self.assertIn('vialu/2', text)
        self.assertIn('different body', text)
        self.assertEqual(rows[0]['recorded_routes'], rows[1]['recorded_routes'])

    def test_invalid_projection_and_memberships_rejected(self):
        forms, summary, routes = self.data()
        with self.assertRaises(ValueError):
            project(forms, summary, routes + routes)
        with self.assertRaises(ValueError):
            project(forms, summary, [{**routes[0], 'applicability': 'EXCLUDED'}])
        data = project(forms, summary, routes)
        data['suites'][0]['coupled_endpoint'].append('unknown')
        with self.assertRaises(ValueError):
            render(data)
        data = project(forms, summary, routes)
        data['forms'][0]['applicability'] = 'EXCLUDED'
        with self.assertRaises(ValueError):
            render(data)


if __name__ == '__main__':
    unittest.main()
