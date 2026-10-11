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
        self.assertEqual(len(e['diff']['new']),422)
        self.assertEqual(len(e['diff']['added']),121)
        self.assertEqual(e['diff']['removed'],[])
        self.assertEqual(len(e['diff']['source_only_new']),5)
        self.assertEqual(len(e['dispositions']),124)
        self.assertEqual(len(e['bindings']),2430)
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


    def test_ara89_source_only_and_failed_history_excluded(self):
        p=Path(__file__).resolve().parents[1]/'docs/rvv-validation/current-scope/compact-input.json'
        data=json.loads(p.read_text()); e=data['ara_evidence']
        if 'ara89' not in e: self.skipTest('Task90 not yet generated')
        a=e['ara89']
        self.assertEqual(len(a['checkpoint_diff']['added']),26)
        self.assertEqual(a['checkpoint_diff']['removed'],[])
        self.assertEqual(set(a['checkpoint_diff']['new'])-set(a['checkpoint_diff']['old']),set(a['review']['scoped_forms']))
        self.assertEqual(set(e['diff']['source_only_new']),{'vfwadd.wv','vnsra.wv','vnsrl.wv','vssseg3e8.v','vssseg3e32.v'})
        self.assertEqual(a['unique_calls']['actual_reference'],47)
        self.assertEqual(len({b['raw_root'] for b in e['bindings'] if b.get('task')=='ara89'}),195)
        self.assertIsNone(a['M2_fast_admission'])
        self.assertEqual(a['M2_target_admission_status'],'UNOBSERVED')
        selected=[b for b in e['bindings'] if b.get('task')=='ara89']
        self.assertTrue(all(b['M2_fast_admission'] is None and b['M2_target_admission_status']=='UNOBSERVED' for b in selected))
        for mutation in ('history','source_only','whole_file','optimized','inferred_zero'):
            bad=copy.deepcopy(data)
            if mutation=='history':bad['ara_evidence']['ara89']['failed_history'][0]['positive']=True
            elif mutation=='source_only':bad['ara_evidence']['diff']['source_only_new'].pop()
            elif mutation=='inferred_zero':
                next(b for b in bad['ara_evidence']['bindings'] if b.get('task')=='ara89')['M2_fast_admission']=0
            else:
                b=next(b for b in bad['ara_evidence']['bindings'] if b.get('task')=='ara89')
                b['whole_file_pass' if mutation=='whole_file' else 'M2_fast_admission']=True
            with self.assertRaises(ValueError):render(bad)

if __name__=='__main__': unittest.main()
