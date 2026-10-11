"""Focused exporter tests; no ISA execution or experimental results."""
import collections
import json
from pathlib import Path
import tempfile
import unittest
from rvv_actual_form_validation import ActualValidation, EncodingIndex, PSEUDOS, STAGES

R=Path(__file__).resolve().parent

class FormValidationTests(unittest.TestCase):
    def test_encoding_mask_and_v0_operand_forms_are_distinct(self):
        names={'vadd.vv','vadc.vvm','vmadc.vv','vmadc.vvm'}
        text='vadd.vv 31..26=0 vm vs2 vs1 14..12=0 vd 6..0=0x57\nvadc.vvm 31..26=16 25=0 vs2 vs1 14..12=0 vd 6..0=0x57\nvmadc.vv 31..26=17 25=1 vs2 vs1 14..12=0 vd 6..0=0x57\nvmadc.vvm 31..26=17 25=0 vs2 vs1 14..12=0 vd 6..0=0x57'
        d=EncodingIndex(text,names)
        self.assertEqual(d.decode(0x01ac8c57)[:2],('vadd.vv','masked v0.t'))
        self.assertEqual(d.decode(0x03ac8c57)[:2],('vadd.vv','unmasked'))
        self.assertEqual(d.decode(0x41ac8c57)[:2],('vadc.vvm','v0 carry/borrow operand'))
        self.assertEqual(d.decode(0x46108057)[0],'vmadc.vv')
        self.assertEqual(d.decode(0x44108057)[0],'vmadc.vvm')

    def test_uppercase_hex_conversion_selectors_do_not_swallow_other_forms(self):
        # Retained rv_v uses uppercase A..F. Previously the first unconstrained
        # selector swallowed narrowing and RTZ conversions sharing funct6.
        selectors = {'vfwcvt.f.xu.v': '0A', 'vfwcvt.f.x.v': '0B',
                     'vfwcvt.f.f.v': '0C', 'vfwcvt.rtz.xu.f.v': '0E',
                     'vfwcvt.rtz.x.f.v': '0F', 'vfncvt.x.f.w': '11',
                     'vfncvt.xu.f.w': '10', 'vfncvt.rtz.x.f.w': '17'}
        text = '\n'.join(f'{name} 31..26=0x12 vm vs2 19..15=0x{selector} 14..12=0x1 vd 6..0=0x57'
                         for name, selector in selectors.items())
        d = EncodingIndex(text, set(selectors))
        for name, selector in selectors.items():
            for vm in (0, 1):
                word = (0x12 << 26) | (vm << 25) | (8 << 20) | (int(selector, 16) << 15) | (1 << 12) | (9 << 7) | 0x57
                with self.subTest(name=name, vm=vm):
                    self.assertEqual(d.decode(word)[:2], (name, 'unmasked' if vm else 'masked v0.t'))
        self.assertEqual(d.decode(0x4a8894d7)[0], 'vfncvt.x.f.w')

    def test_configuration_without_dot_and_nf_expansion(self):
        text='vsetvli 31=0 zimm11 rs1 14..12=7 rd 6..0=0x57\n'\
             'vsetivli 31=1 30=1 zimm10 zimm5 14..12=7 rd 6..0=0x57\n'\
             'vsetvl 31=1 30..25=0 rs2 rs1 14..12=7 rd 6..0=0x57\n'\
             'vle32.v nf 28=0 27..26=0 vm 24..20=0 rs1 14..12=6 vd 6..0=7'
        d=EncodingIndex(text,{'vsetvli','vsetivli','vsetvl','vle32.v','vlseg8e32.v'})
        self.assertEqual(d.decode(0x0c06f7d7)[0],'vsetvli')
        self.assertEqual(d.decode(0xc0007057)[0],'vsetivli')
        self.assertEqual(d.decode(0x80007057)[0],'vsetvl')
        self.assertEqual(d.decode(0xe2006007)[0],'vlseg8e32.v')

    def test_spec_aliases_and_json_array_form_fields(self):
        v=ActualValidation.__new__(ActualValidation)
        v.names={'vfsgnjx.vv','vmslt.vv','vsetvl','vl1re8.v'}
        v.aliases={k:(f,ref) for k,(f,ref) in PSEUDOS.items()}
        v.aliases['vl1r.v']=('vl1re8.v','spec:2065')
        self.assertEqual(v.forms('["vfabs.v", "vmsgt.vv", "vsetvl", "vl1r.v"]'),v.names)
        self.assertEqual(v.forms('vmsgt.vv; free text'),{'vmslt.vv'})
        self.assertIn('swap vector sources',v.aliases['vmsgt.vv'][1])

    def fixture(self, root):
        v=ActualValidation.__new__(ActualValidation);v.W=Path(root);v.names={'vadd.vv','vsetvli','vl1re8.v'};v.aliases={}
        v.suites=['ACT','RVVTS','SiFive RIF'];v.sets={s:{k:set()for k in STAGES}for s in v.suites}
        v.candidates=collections.defaultdict(lambda:{k:set()for k in STAGES})
        v.bindings=[];v.missing=[];v.corrections={'old-elf':{}};v.rows=[]
        v.contexts=lambda r,t:({'SEW':'UNKNOWN','VLEN':r['VLEN']},[])
        v.i=type('Reader',(),{'j':staticmethod(lambda p:json.loads(Path(p).read_text()))})()
        v.elf_metadata=lambda r:{'functions':{'vadd_vv_operator_0':{'vadd.vv':['masked v0.t'],'vsetvli':['configuration'],'vl1re8.v':['unmasked']}}}
        return v

    def row(self, suite, identity, status='PASS'):
        fields=['row_id','suite','candidate','target_forms','row_kind','returncode','raw_stdout','raw_stderr',
                'elf_sha256','source_file','source_case','source_status','source_inventory','cohort','build_status',
                'checked_state','checker_scope','checker_identity','reference_identity','adapter','arm','VLEN',
                'executable_sha256','library_sha256','result_evidence','shared_oracle_limit','blocker']
        r={k:'UNKNOWN'for k in fields};r.update(row_id=identity,suite=suite,candidate='clean961',target_forms='vadd.vv',
                row_kind='EXECUTION',returncode='0',raw_stdout='receipt/stdout',raw_stderr='receipt/stderr',
                elf_sha256=identity,source_file='case/original.c',dut_status=status,build_status='BUILT',VLEN='128')
        return r

    def test_program_endpoint_does_not_create_independent_form_check(self):
        with tempfile.TemporaryDirectory() as root:
            v=self.fixture(root);v.rows=[self.row('RVVTS','endpoint'),self.row('ACT','failed','RESULT_MISMATCH')];v.run()
            self.assertEqual(v.sets['RVVTS']['result_checked'],set())
            self.assertEqual(v.sets['RVVTS']['coupled_endpoint'],{'vadd.vv'})
            self.assertEqual(v.sets['ACT']['result_checked'],set())
            self.assertEqual(v.columns('vsetvli')['ACT_result_checked'],'UNKNOWN')

    def test_superseded_policy_and_helper_forms_not_accepted_as_target(self):
        with tempfile.TemporaryDirectory() as root:
            p=Path(root)/'case';p.mkdir();(p/'original.c').write_text('')
            (p/'PREDICATES_FROZEN.json').write_text(json.dumps([{'kind':'operation-result','function':'golden_vadd_vv_operator_0'}]))
            v=self.fixture(root);v.rows=[self.row('SiFive RIF','old-elf'),self.row('SiFive RIF','replacement')];v.run()
            self.assertEqual(v.bindings[0]['acceptance'],'DIAGNOSTIC_ONLY_SUPERSEDED_POLICY')
            self.assertEqual(v.bindings[0]['result_checked_forms'],'')
            self.assertEqual(v.bindings[1]['result_checked_forms'],'vadd.vv')
            self.assertEqual(set(v.bindings[1]['coupled_endpoint_forms'].split(';')),{'vsetvli','vl1re8.v'})
            self.assertEqual(v.sets['SiFive RIF']['result_checked'],{'vadd.vv'})
            self.assertIn('vsetvli',v.sets['SiFive RIF']['emitted'])

    def test_task75_retained_scalar_endpoint_does_not_credit_helpers_or_forms(self):
        with tempfile.TemporaryDirectory() as root:
            p=Path(root)/'case'; p.mkdir()
            (p/'PREDICATES_FROZEN.json').write_text(json.dumps([{'kind':'operation-result','function':'golden_vadd_vv_operator_0'}]))
            v=self.fixture(root)
            r=self.row('SiFive RIF','derivative')
            r['source_status']='TASK75_SOURCE_BACKED_PRODUCER_INTERFACE_DERIVATIVE'
            v.rows=[r]; v.run()
            self.assertEqual(v.bindings[0]['result_checked_forms'],'')
            self.assertEqual(v.bindings[0]['coupled_endpoint_forms'],'vadd.vv')
            self.assertIn('ENDPOINT_ONLY',v.bindings[0]['binding'])
            self.assertEqual(v.sets['SiFive RIF']['result_checked'],set())
            self.assertEqual(v.sets['SiFive RIF']['coupled_endpoint'],{'vadd.vv'})

if __name__=='__main__':unittest.main()
