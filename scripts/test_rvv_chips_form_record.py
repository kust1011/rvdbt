"""Host reporting tests with synthetic bindings; these are not ISA tests."""
import csv
import io
import json
from pathlib import Path
import tempfile
import unittest

import rvv_tests
from verify_rvv_chips_inspection import digest, form_record


class FormRecordTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.files = {}
        self.source = 'sources/chips/demo/stage2/add.S'
        self.put(self.source, '# Generating tests for VL: 7, LMUL: mf8, SEW: e8, Mask: false\n'
                 'li t0, 7\nvsetvli t1, t0, e8,mf8,tu,mu\nvadd.vv v20, v1, v31\n'
                 'vse8.v v20, (a0)\nTEST_CASE(2, t0, 0x1234, lw t0, 0(a0))\n')
        self.cell = {'id': 'cell', 'elf_sha256': 'e' * 64, 'vlen': 128, 'flags': ['--vlen=128'],
                     'control': False, 'expected_returncode': 0, 'expected_stdout': 'PASS\n'}
        self.row = {'candidate': 'clean961', 'form': 'vadd.vv', 'source_form': 'vadd.vv',
                    'arm': 'B', 'VLEN': '128', 'batch': 'demo', 'case': 'add',
                    'cell_id': 'cell', 'ledger_row_id': 'ledger', 'source': self.source,
                    'source_sha256': self.files[self.source]['sha256'],
                    'elf_sha256': self.cell['elf_sha256'], 'receipt': 'raw/cell'}
        self.binding = {'ledger_row_id': 'ledger', 'candidate': 'clean961', 'arm': 'B',
                        'elf_sha256': self.cell['elf_sha256'], 'flags_json': json.dumps(self.cell['flags']),
                        'configuration_known_json': json.dumps({'VLEN': '128', 'VL': 'UNKNOWN',
                            'SEW': 'UNKNOWN', 'LMUL': 'UNKNOWN', 'vstart': 'UNKNOWN'}),
                        'result_checked_forms': 'vadd.vv', 'result': 'PASS', 'acceptance': 'ACCEPTED_SCOPED'}
        self.csv('NAVIGATION.csv', [self.row])
        self.csv('records/scope/PRIMARY_BINDINGS.csv', [self.binding])
        self.json('records/historical/MANIFEST.json', {'cells': [self.cell]})
        self.json('LITERAL_CONFIG_CONTEXTS.json', [])
        self.csv('sources/chips/SOURCE_GEOMETRY.csv', [{'source': 'demo/stage2/add.S',
            'source_sha256': self.row['source_sha256'], 'line': '1', 'requested_vl': '7',
            'sew': 'e8', 'lmul': 'mf8', 'masked': 'false'}])
        self.put('sources/chips/demo/stage1/add.S', 'original synthetic input\n')
        self.put('sources/chips/demo/patches/add.patch', 'original synthetic capture\n')
        self.json('sources/chips/demo/file_hashes.json', {})
        build = {'command': ['compiler', 'add.S'], 'returncode': 0}
        self.json('sources/chips/demo/build_commands.json', [build])
        self.chain = {'batch': 'demo', 'case': 'add', 'source': self.source,
            'source_sha256': self.row['source_sha256'], 'elf_sha256': self.cell['elf_sha256'],
            'assertions': {'count': 1}, 'stage1': 'sources/chips/demo/stage1/add.S',
            'capture_patch': 'sources/chips/demo/patches/add.patch',
            'original_hash_manifest': 'sources/chips/demo/file_hashes.json',
            'build_commands': [{'file': 'sources/chips/demo/build_commands.json', 'ordinal': 1, 'record': build}]}
        self.json('SOURCE_CHAIN.json', [self.chain])
        self.put('tools/runner.original.py', Path(rvv_tests.__file__).read_text())
        self.put('raw/cell/stdout', 'PASS\n')
        self.put('raw/cell/stderr', '')
        self.result = {'id': 'cell', 'elf_sha256': self.cell['elf_sha256'], 'returncode': 0,
                       'status': 'PASS', 'error': None, 'stdout_sha256': self.files['raw/cell/stdout']['sha256'],
                       'stderr_sha256': self.files['raw/cell/stderr']['sha256']}
        self.json('raw/cell/result.json', self.result)
        self.json('raw/cell/case.json', self.cell)
        self.json('raw/cell/command.json', ['engine', '--vlen=128'])

    def put(self, name, text):
        p = self.root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        self.files[name] = {'sha256': digest(p)}

    def json(self, name, value):
        self.put(name, json.dumps(value))

    def csv(self, name, rows):
        stream = io.StringIO()
        writer = csv.DictWriter(stream, rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
        self.put(name, stream.getvalue())

    def record(self, rows=None):
        return form_record(self.root, rows or [self.row], self.files)

    def test_exact_tuples_unknown_runtime_and_literal_assertions(self):
        result = self.record()
        self.assertEqual(result['source_contexts'][0]['requested_vl'], '7')
        self.assertEqual(json.loads(result['bindings'][0]['configuration_known_json'])['VL'], 'UNKNOWN')
        self.assertEqual(result['sources'][self.source]['assertions'][0]['line'], 6)
        self.assertEqual(result['receipts']['raw/cell']['offline_original_classify'], 'PASS')
        self.assertEqual(result['new_guest_executions'], 0)

    def test_aliases_keep_witnesses_but_share_receipt_and_binding(self):
        result = self.record([self.row, dict(self.row)])
        self.assertEqual(len(result['witnesses']), 2)
        self.assertEqual(len(result['bindings']), 1)
        self.assertEqual(len(result['receipts']), 1)

    def test_changed_source_rejected_before_reporting(self):
        (self.root / self.source).write_text('changed')
        with self.assertRaisesRegex(ValueError, 'payload hash'):
            self.record()

    def test_wrong_output_with_updated_transport_hashes_rejected(self):
        self.put('raw/cell/stdout', 'FAIL\n')
        self.result['stdout_sha256'] = self.files['raw/cell/stdout']['sha256']
        self.json('raw/cell/result.json', self.result)
        with self.assertRaisesRegex(ValueError, 'OUTPUT_MISMATCH'):
            self.record()

    def test_exit_and_timeout_rejected(self):
        for update in ({'returncode': 1}, {'status': 'TIMEOUT'}):
            with self.subTest(update=update):
                self.json('raw/cell/result.json', {**self.result, **update})
                with self.assertRaisesRegex(ValueError, 'acceptance rejected'):
                    self.record()

    def test_changed_registered_expectation_rejected(self):
        self.json('raw/cell/case.json', {**self.cell, 'expected_stdout': 'FAIL\n'})
        with self.assertRaisesRegex(ValueError, 'registered expectation changed'):
            self.record()

    def test_source_geometry_is_checked_against_literal_line(self):
        self.csv('sources/chips/SOURCE_GEOMETRY.csv', [{'source': 'demo/stage2/add.S',
            'source_sha256': self.row['source_sha256'], 'line': '1', 'requested_vl': '8',
            'sew': 'e8', 'lmul': 'mf8', 'masked': 'false'}])
        with self.assertRaisesRegex(ValueError, 'geometry source line'):
            self.record()

    def test_missing_raw_and_wrong_join_rejected(self):
        with self.assertRaisesRegex(ValueError, 'ELF join'):
            self.record([{**self.row, 'elf_sha256': 'f' * 64}])
        (self.root / 'raw/cell/stderr').unlink()
        with self.assertRaisesRegex(ValueError, 'missing/escaping payload'):
            self.record()

    def test_same_opcode_initialization_is_not_test_body(self):
        self.put(self.source, '# Generating tests for VL: 7, LMUL: mf8, SEW: e8, Mask: false\n'
                 'vadd.vv v1, v2, v3\n# TEST BEGIN\nvadd.vv v20, v1, v31\n# TEST END\n'
                 'TEST_CASE(2, t0, 0x1234, lw t0, 0(a0))\n')
        self.row['source_sha256'] = self.files[self.source]['sha256']
        self.chain['source_sha256'] = self.row['source_sha256']
        self.json('SOURCE_CHAIN.json', [self.chain])
        self.csv('sources/chips/SOURCE_GEOMETRY.csv', [{'source':'demo/stage2/add.S',
            'source_sha256':self.row['source_sha256'],'line':'1','requested_vl':'7',
            'sew':'e8','lmul':'mf8','masked':'false'}])
        roles = [r['source_role'] for r in self.record()['sources'][self.source]['target_instructions']]
        self.assertEqual(roles, ['OUTSIDE_TEST_BODY', 'TEST_BODY'])


if __name__ == '__main__':
    unittest.main()
