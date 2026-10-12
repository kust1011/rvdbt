"""Evidence controls: exact identity, tampered receipts and scoped acceptance."""
import copy
import tempfile
import unittest
from pathlib import Path
from rvv_host512_corpus import partition, read, validate_record, RAW128, REMOTE128, RAW129, REMOTE129

DOCS = Path(__file__).resolve().parents[1]/'docs/rvv-validation'


class EvidenceControls(unittest.TestCase):
    def test_full_call_subtraction_rejects_config_substitution(self):
        a = dict(form='vadd.vv',arm='B',elf_sha256='a',flags=['--vlen=128'])
        b = dict(a,flags=['--vlen=1024'])
        self.assertEqual(partition([a,b],[a],[b])['original'],2)
        with self.assertRaisesRegex(ValueError,'union'):
            partition([a,b],[a],[dict(b,elf_sha256='other')])
        with self.assertRaisesRegex(ValueError,'overlap'):
            partition([a,b],[a],[a,b])
        with self.assertRaisesRegex(ValueError,'duplicate'):
            partition([a,a],[a],[])

    @unittest.skipUnless(RAW128.is_dir(),'requires separately retained Task128 raw')
    def test_pinned_raw_and_candidate_flags(self):
        record = next(r for r in read(DOCS/'host512-task128/RECEIPTS.json.gz') if r['suite']=='chips')
        local = RAW128/Path(record['receipt']).relative_to(REMOTE128)
        validate_record(record,local)
        for field in ('candidate','flags','result'):
            bad=copy.deepcopy(record)
            if field=='candidate':
                k=next(iter(bad['executable_pins']));bad['executable_pins'][k]='0'*64
            elif field=='flags':
                bad['original_call']['flags'][0]='--vlen=4096'
            else:
                bad['result']['status']='RESULT_MISMATCH'
            with self.subTest(field=field),self.assertRaises(ValueError):
                validate_record(bad,local)

    @unittest.skipUnless(RAW128.is_dir(),'requires separately retained Task128 raw')
    def test_stream_tamper_is_rejected(self):
        record = next(r for r in read(DOCS/'host512-task128/RECEIPTS.json.gz') if r['suite']=='chips')
        local=RAW128/Path(record['receipt']).relative_to(REMOTE128)
        with tempfile.TemporaryDirectory() as d:
            target=Path(d)
            for name in ('IDENTITY.json','command.json','result.json','stdout','stderr'):
                (target/name).write_bytes((local/name).read_bytes())
            (target/'stdout').write_bytes((target/'stdout').read_bytes()+b'tampered')
            with self.assertRaisesRegex(ValueError,'stream identity'):
                validate_record(record,target)

    @unittest.skipUnless(RAW129.is_dir(),'requires separately retained Task129 raw')
    def test_scoped_mac_cannot_receive_whole_file_credit(self):
        record=next(r for r in read(DOCS/'host512-task129/RECEIPTS.json.gz') if r['result']['status']=='SCOPED_PASS')
        local=RAW129/Path(record['receipt']).relative_to(REMOTE129)
        validate_record(record,local)
        with tempfile.TemporaryDirectory() as d:
            target=Path(d)
            for name in ('IDENTITY.json','command.json','result.json','stdout','stderr','observer.json'):
                (target/name).write_bytes((local/name).read_bytes())
            bad=copy.deepcopy(record)
            bad['files']={}
            bad['result']['whole_file_pass']=True
            # Even consistent tampering of the ledger and its raw result must
            # not override the original TEST_CASE1/2 scope.
            import json
            (target/'result.json').write_text(json.dumps(bad['result']))
            with self.assertRaisesRegex(ValueError,'whole-file scope'):
                validate_record(bad,target)


if __name__=='__main__':
    unittest.main()
