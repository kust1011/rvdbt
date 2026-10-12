# SPDX-License-Identifier: Apache-2.0
"""Focused host-only rejection controls over db2's original raw predicates."""
import ast
import json
import shlex
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from verify_rvv_act_db2 import original_predicates, validate_raw


class RawControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.predicates=original_predicates((Path(sys.argv_package)/'records/execute109.py').read_text())

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.case='control';self.sig=self.root/'capture.sig';self.sig.write_text('12345678\n')
        for n in ('command.json','IDENTITY.json','IDENTITY_AFTER.json'):(self.root/n).write_text('{}')
        self.write(0,'RVCP-SUMMARY: TEST PASSED - Test File "control.S"\n')

    def tearDown(self):self.tmp.cleanup()
    def write(self,rc,text):
        (self.root/'result.json').write_text(json.dumps(dict(returncode=rc,timeout=rc is None)))
        (self.root/'stdout').write_text(text);(self.root/'stderr').write_text('')
    def check(self):return validate_raw(self.root,self.predicates[2],self.case,self.sig)
    def test_valid(self):self.check()
    def test_missing_raw(self):
        (self.root/'stderr').unlink()
        with self.assertRaises(ValueError):self.check()
    def test_nonzero(self):
        self.write(1,(self.root/'stdout').read_text())
        with self.assertRaises(ValueError):self.check()
    def test_failed_summary(self):
        (self.root/'stderr').write_text('TEST FAILED')
        with self.assertRaises(ValueError):self.check()
    def test_missing_summary(self):
        self.write(0,'ordinary output')
        with self.assertRaises(ValueError):self.check()
    def test_duplicate_summary(self):
        self.write(0,(self.root/'stdout').read_text()*2)
        with self.assertRaises(ValueError):self.check()
    def test_timeout(self):
        self.write(None,(self.root/'stdout').read_text())
        with self.assertRaises(ValueError):self.check()
    def test_sail_missing_signature(self):
        self.write(0,'SUCCESS TEST SIGRUN - Test File "control.S"');self.sig.unlink()
        with self.assertRaises(ValueError):validate_raw(self.root,self.predicates[0],self.case,self.sig)
    def test_export_and_shell_syntax(self):
        exporter=Path(__file__).with_name('replay_rvv_act_db2.py')
        for case,expected in [('Vls8-vluxei8.v',8),('Vf32-vfmv.f.s',4)]:
            output=self.root/case
            cmd=[sys.executable,str(exporter),sys.argv_package,'--case',case,'--output',str(output),'--sail','/opt/sail','--qemu','/opt/qemu','--stage','/opt/clean961','--clang','/opt/clang-22']
            p=subprocess.run(cmd,capture_output=True,text=True)
            self.assertEqual(p.returncode,0,p.stderr)
            self.assertEqual(json.loads(p.stdout)['commands'],expected)
            commands=json.loads((output/'COMMANDS.json').read_text())
            self.assertNotIn('/home/vick/rvv-task109/',json.dumps(commands))
            self.assertEqual(subprocess.run(['sh','-n',str(output/'replay.sh')]).returncode,0)
            # Shell syntax alone accepts a quoted, invalid multiline Python string.
            shell_tokens=shlex.split((output/'replay.sh').read_text(),comments=True)
            for i, token in enumerate(shell_tokens[:-2]):
                if token=='python3' and shell_tokens[i+1]=='-c':
                    ast.parse(shell_tokens[i+2])

    def test_task104_not_exported(self):
        cmd=[sys.executable,str(Path(__file__).with_name('replay_rvv_act_db2.py')),sys.argv_package,'--case','Vls32-vluxei32.v','--output',str(self.root/'join'),'--sail','/opt/sail','--qemu','/opt/qemu','--stage','/opt/clean961']
        p=subprocess.run(cmd,capture_output=True,text=True)
        self.assertNotEqual(p.returncode,0);self.assertIn('Task104 join',p.stderr)
    def test_optimized_import_entry(self):
        code='from pathlib import Path; from verify_rvv_act_db2 import verify; verify(Path("missing"))'
        for opt in ('-O','-OO'):
            p=subprocess.run([sys.executable,opt,'-c',code],cwd=Path(__file__).parent,capture_output=True,text=True)
            self.assertNotEqual(p.returncode,0);self.assertIn('rejects -O',p.stderr)

if __name__=='__main__':
    if not __debug__:raise RuntimeError('negative controls require normal Python')
    sys.argv_package=sys.argv.pop(1);unittest.main()
