from pathlib import Path
import shutil
import tempfile
import unittest

from reworkbench.engine import analyze
from reworkbench.process import run
from reworkbench.storage import Store


class BinaryViewTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('gcc') and shutil.which('readelf') and shutil.which('objdump'), 'GNU araçları yok')
    def test_real_gnu_structured_sections_symbols_and_instructions(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            source=Path(__file__).parent/'fixtures/hello.c'
            target=root/'hello'
            self.assertEqual(run([shutil.which('gcc'),'-g','-O0','-o',str(target),str(source)])['returncode'],0)
            result=analyze(Store(root/'data'),target,['elf','disassembly','metrics'])
            binary=result['modules']['elf']
            self.assertEqual(binary['status'],'ok')
            self.assertTrue(any(s['name']=='.text' for s in binary['sections']))
            self.assertTrue(any(s['name']=='main' for s in binary['symbols']))
            self.assertTrue(binary['segments'])
            self.assertTrue(any('libc' in x for x in binary['dependencies']))
            disasm=result['modules']['disassembly']
            self.assertEqual(disasm['status'],'ok')
            self.assertTrue(disasm['rows'])
            self.assertTrue(any(row.get('function')=='main' or row.get('section')=='.text' for row in disasm['rows']))
            self.assertGreater(result['modules']['metrics']['entropy'],0)
            self.assertLessEqual(result['modules']['metrics']['entropy'],8)

    def test_mnemonics_are_not_consumed_as_hex_bytes(self):
        from reworkbench.binary_views import objdump_rows
        rows = objdump_rows("  1000:\t48 83 c4 08    \tadd $0x8,%rsp\n  1004:\td503201f \tnop\n")
        self.assertEqual(rows[0]['mnemonic'], 'add')
        self.assertEqual(rows[0]['bytes'], '4883c408')
        self.assertEqual(rows[1]['mnemonic'], 'nop')

    def test_entropy_empty_and_repeated_data(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            sample=root/'zero'
            sample.write_bytes(b'\0'*4096)
            result=analyze(Store(root/'data'),sample,['metrics'])
            self.assertEqual(result['modules']['metrics']['entropy'],0)
            self.assertEqual(sum(result['modules']['metrics']['histogram']),4096)
            sample.write_bytes(b'')
            result=analyze(Store(root/'data'),sample,['metrics'])
            self.assertEqual(result['modules']['metrics']['entropy'],0)
