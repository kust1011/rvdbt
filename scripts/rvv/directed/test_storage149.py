#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compatibility, exact identity, deduplication and reserve regression checks."""
import os,tempfile,unittest,json
from pathlib import Path
from unittest.mock import patch
import storage149 as s
class Storage(unittest.TestCase):
    def test_retention(self):
        with tempfile.TemporaryDirectory() as d,patch.dict(os.environ,{'RVV_COMPRESS':'1'}):
            root=Path(d);raw=bytes(range(256))*100
            plain=root/'legacy';plain.write_bytes(raw);self.assertEqual(s.verify(plain),raw)
            p=root/'stdout';s.write(p,raw);self.assertFalse(p.exists());self.assertEqual(s.verify(p),raw)
            m=json.loads(Path(str(p)+'.storage.json').read_text());self.assertEqual(m['logical_sha256'],s.digest(raw));self.assertNotEqual(m['logical_sha256'],m['compressed_sha256'])
            alias=root/'packets.bin';s.write(alias,raw,alias=p);self.assertEqual(s.physical(p).stat().st_ino,s.physical(alias).stat().st_ino)
            self.assertTrue(s.materialize(p));self.assertEqual(s.verify(p),raw);p.unlink()
            m['logical_sha256']='0'*64;Path(str(alias)+'.storage.json').write_text(json.dumps(m))
            with self.assertRaises(ValueError):s.verify(alias)
    def test_elf_alias_survives_materialized_source_cleanup(self):
        with tempfile.TemporaryDirectory() as d,patch.dict(os.environ,{'RVV_COMPRESS':'1'}):
            root=Path(d);source=root/'test.elf';raw=b'\x7fELF'+bytes(range(256))*200
            s.write(source,raw);s.materialize(source)
            fs=root/'fs';fs.mkdir();target=fs/'t.elf'
            s.link_compressed(source,target);source.unlink()
            self.assertEqual(s.verify(target),raw)
            self.assertTrue(s.materialize(target));self.assertEqual(target.read_bytes(),raw)
            target.unlink();self.assertEqual(s.verify(target),raw)
    def test_reserve(self):
        with patch.dict(os.environ,{'RVV_COMPRESS':'1'}),patch.object(s.shutil,'disk_usage',return_value=type('Disk',(),{'free':s.RESERVE})()):
            with self.assertRaises(RuntimeError):s.reserve(Path('/tmp'))
    def test_stream_capture(self):
        import sys
        with tempfile.TemporaryDirectory() as d,patch.dict(os.environ,{'RVV_COMPRESS':'1'}):
            p=Path(d)/'run';r=s.execute([sys.executable,'-c','import sys;sys.stdout.buffer.write(bytes(range(256))*10000);sys.stderr.write("diagnostic")'],p,dict(os.environ),10)
            self.assertEqual(r['returncode'],0);self.assertEqual(s.verify(p/'stdout'),bytes(range(256))*10000);self.assertEqual(s.verify(p/'stderr'),b'diagnostic')
if __name__=='__main__':unittest.main()
