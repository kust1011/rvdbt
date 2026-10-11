import copy
import json
import unittest
from pathlib import Path
from rvv_ara_accepted import positive, unique, render_evidence
from rvv_compact_scope import render


class AraAcceptanceTests(unittest.TestCase):
    def test_duplicate_identity_rejected(self):
        with self.assertRaises(ValueError):
            unique([{'id':1},{'id':1}], lambda r:r['id'])

    def test_complete_same_block_arms_required(self):
        rows=[dict(arm=a,status='PASS') for a in ('reference','B','M1','M2','BOTH')]
        self.assertTrue(positive(rows))
        self.assertFalse(positive(rows[:-1]))
        rows[-1]['status']='FAIL'
        self.assertFalse(positive(rows))

    def test_accepted_snapshot_partition_and_other_suites(self):
        p=Path(__file__).resolve().parents[1]/'docs/rvv-validation/current-scope/compact-input.json'
        data=json.loads(p.read_text())
        e=data.get('ara_evidence')
        if not e: self.skipTest('Task87 bundle not yet generated')
        original=json.loads(__import__('subprocess').check_output(['git','show','HEAD:docs/rvv-validation/current-scope/compact-input.json']))
        self.assertEqual([s for s in original['suites'] if s['suite']!='Ara'],[s for s in data['suites'] if s['suite']!='Ara'])
        invalid=[b for b in e['bindings'] if b['scope']=='INVALID_CONTEXT_HISTORY']
        self.assertEqual(len(invalid),80)
        self.assertFalse(any(b['positive'] for b in invalid))
        self.assertEqual(len({b['case'] for b in invalid}),16)
        self.assertEqual(len(e['diff']['new']),396)
        self.assertEqual(len(e['diff']['added']),95)
        self.assertEqual(e['diff']['removed'],[])
        self.assertEqual(len(e['diff']['source_only_new']),31)
        self.assertEqual(len(e['dispositions']),124)
        self.assertEqual(len(e['bindings']),1600)
        unique(e['bindings'],lambda b:tuple(b['identity']))
        failed=set(e['fp_blocks']['reserved_overlap_failures'])
        self.assertEqual(len(failed),2)
        self.assertFalse(any(b['positive'] for b in e['bindings'] if b.get('case') in failed))
        self.assertFalse(any(b['multi_member_M1_admission'] for b in e['bindings']))
        self.assertEqual(render(data)[2],dict(forms=627,applicable=595,excluded=32,checked_union=595,new_DUT_executions=0))
        self.assertIn('291 all-five PASS',render_evidence(e))
        for mutation in ('invalid','duplicate','join'):
            bad=copy.deepcopy(data)
            be=bad['ara_evidence']
            if mutation=='invalid':
                next(b for b in be['bindings'] if b['scope']=='INVALID_CONTEXT_HISTORY')['positive']=True
            elif mutation=='duplicate':
                be['bindings'].append(be['bindings'][0])
            else:
                be['diff']['new'].remove(be['diff']['added'][0])
            with self.assertRaises(ValueError): render(bad)

if __name__=='__main__': unittest.main()
