#!/usr/bin/env python3
"""Corrupt retained fixtures in memory; no execution and no receipt modification."""
import gzip, json, os, unittest
from pathlib import Path
import audit

RESULT = Path(__file__).resolve().parents[3]/'docs/rvv-validation/denial-task188/RESULT.json.gz'
MIRROR = Path(os.environ.get('RVV_DENIAL188_MIRROR','/home/user/research/materials/task188-denial-offline-20261014'))

class DenialAudit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows=json.loads(gzip.decompress(RESULT.read_bytes()))['rows']

    def fixture(self, row=None):
        row=row or self.rows[0]
        p=MIRROR/'home/vick/rvv-task181/focused'/row['suite']/'replay'/row['key']/row['arm']
        return row['expected'],json.loads(audit.read(p/'execution.json')),audit.read(p/'stdout'),audit.read(p/'stderr')

    def mutate(self, change):
        expected,execution,stdout,stderr=self.fixture()
        text=stderr.decode();lines=text.splitlines();index=next(i for i,s in enumerate(lines) if s.startswith(audit.MARKER))
        snapshot=json.loads(lines[index][len(audit.MARKER):]);change(snapshot)
        lines[index]=audit.MARKER+json.dumps(snapshot);stderr=('\n'.join(lines)+'\n').encode()
        execution['stderr_sha256']=audit.digest(stderr) # defeat hash-only rejection
        return audit.adjudicate(expected,execution,stdout,stderr)

    def test_original_all_592_exact(self):
        for row in self.rows:
            with self.subTest(suite=row['suite'],key=row['key'],arm=row['arm']):
                self.assertEqual(audit.adjudicate(*self.fixture(row))['category'],'EXACT_EXPECTED_FAULT')

    def test_semantic_corruptions(self):
        for field,value in [('pc',123),('raw',0),('element',99),('reason','protection'),('access','store'),('address',0),('field',99),('eew_bytes',8),('nf',8),('host_signal',11),('host_code',2)]:
            with self.subTest(field=field):
                r=self.mutate(lambda s:s.update({field:value}))
                self.assertEqual(r['category'],'GENERIC_FAILURE');self.assertTrue(r['rejection_reasons'])

    def test_csr_gpr_vector_corruptions(self):
        changes=[lambda s:s['csrs'].update(vstart=99),lambda s:s['csrs'].update(vl=99),lambda s:s['csrs'].update(fflags=0),lambda s:s['gpr'].__setitem__(18,0),lambda s:s['vreg_hex'].__setitem__(31,'00'*16)]
        for change in changes:
            self.assertEqual(self.mutate(change)['category'],'GENERIC_FAILURE')

    def test_missing_fields_are_unverified(self):
        for field in ['pc','raw','element','reason','address','csrs','gpr','fpr_hex','vreg_hex']:
            with self.subTest(field=field):
                r=self.mutate(lambda s:s.pop(field))
                self.assertEqual(r['category'],'INSUFFICIENT_OBSERVATION');self.assertEqual(r['adjudication'],'UNVERIFIED');self.assertTrue(r['missing_fields'])

    def test_terminal_cause_corruption(self):
        expected,execution,stdout,stderr=self.fixture()
        stderr=stderr.replace(b'helper_sync signal=11 code=1',b'helper_sync signal=7 code=2')
        execution['stderr_sha256']=audit.digest(stderr)
        self.assertEqual(audit.adjudicate(expected,execution,stdout,stderr)['category'],'GENERIC_FAILURE')

    def test_truncated_capture(self):
        expected,execution,stdout,stderr=self.fixture();stderr=stderr[:200]
        execution['stderr_sha256']=audit.digest(stderr)
        r=audit.adjudicate(expected,execution,stdout,stderr)
        self.assertEqual(r['category'],'INSUFFICIENT_OBSERVATION')
        self.assertIn('truncated',str(r['missing_fields']))

    def test_wrong_target_process_crash_with_keyword(self):
        expected,execution,stdout,stderr=self.fixture()
        execution['returncode']=-11;stderr=b'wrong program: segmentation fault\n';execution['stderr_sha256']=audit.digest(stderr)
        self.assertEqual(audit.adjudicate(expected,execution,stdout,stderr)['category'],'GENERIC_FAILURE')

    def test_crash_cannot_borrow_good_snapshot(self):
        expected,execution,stdout,stderr=self.fixture();execution['returncode']=-11
        self.assertEqual(audit.adjudicate(expected,execution,stdout,stderr)['category'],'GENERIC_FAILURE')

    def test_command_identity_rejection(self):
        self.assertEqual(audit.adjudicate(*self.fixture(),identity_errors=['wrong-target fsroot'])['category'],'GENERIC_FAILURE')

    def test_generic_keyword_without_snapshot(self):
        expected,execution,stdout,stderr=self.fixture();stderr=b'fault trap segmentation\n';execution['stderr_sha256']=audit.digest(stderr)
        r=audit.adjudicate(expected,execution,stdout,stderr)
        self.assertEqual(r['category'],'INSUFFICIENT_OBSERVATION');self.assertEqual(r['adjudication'],'UNVERIFIED')

    def test_duplicate_snapshot(self):
        expected,execution,stdout,stderr=self.fixture();stderr+=stderr.splitlines(keepends=True)[0];execution['stderr_sha256']=audit.digest(stderr)
        self.assertEqual(audit.adjudicate(expected,execution,stdout,stderr)['category'],'INSUFFICIENT_OBSERVATION')

    def test_raw_origin_does_not_establish_native(self):
        r=self.mutate(lambda s:s.update(origin='NativeUnit'))
        self.assertEqual(r['raw_origin_label'],'NativeUnit');self.assertTrue(r['native_admission'].startswith('UNVERIFIED'))
        self.assertEqual(r['architectural_fault_state'],'UNVERIFIED')

    def test_elf_target_corruption(self):
        row=self.rows[0];p=MIRROR/'home/vick/rvv-task165/guard-pilot'/row['key'];raw=bytearray(audit.read(p/'test.elf'))
        # Corrupt ELF machine identity; target byte corruption checked independently below.
        raw[18]=0
        with self.assertRaises(ValueError):audit.elf(raw)
        raw=bytearray(audit.read(p/'test.elf'));target=row['expected']['raw'].to_bytes(4,'little');i=raw.index(target);raw[i]^=1
        plan=json.loads(audit.read(MIRROR/'home/vick/rvv-task181/focused/guard165/audit/PLAN.json'))
        record=next(r for r in plan['records'] if r['arm']==row['arm'] and r['kind']=='enabled-denied' and r['case']['mnemonic']=='vle8')
        with self.assertRaisesRegex(ValueError,'independent encoding'):
            audit.expectations('guard165',record,raw,audit.read(p/'test.S').decode())

if __name__=='__main__': unittest.main()
