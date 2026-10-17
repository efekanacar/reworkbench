import hashlib
from pathlib import Path
import queue
import shutil
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from reworkbench.engine import analyze, hex_page, identify, indicators, strings
from reworkbench.jobs import Jobs
from reworkbench.process import Cancelled, run
from reworkbench.storage import MAX_FILE, Store, markdown
from reworkbench.dynamic import Sandbox


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'input ; $(touch PWNED).txt'
        self.source.write_bytes(b'Hello https://example.org/docs error: demonstration\n192.0.2.10\n')
        self.store = Store(self.root / 'data')
        self.cancel = threading.Event()

    def test_hash_snapshot_and_runs(self):
        a = analyze(self.store, self.source, ['strings'], self.cancel)
        b = analyze(self.store, self.source, ['strings'], self.cancel)
        self.assertEqual(a['file']['hashes']['sha256'], hashlib.sha256(self.source.read_bytes()).hexdigest())
        for key in ('md5', 'sha1'):
            self.assertEqual(a['file']['hashes'][key], hashlib.new(key, self.source.read_bytes()).hexdigest())
        self.assertNotEqual(a['run_id'], b['run_id'])
        self.assertEqual(len(list((self.store.root / 'reports').glob('*/*.json'))), 2)
        self.assertFalse((self.root / 'PWNED').exists())
        self.assertTrue(a['indicators'])
        self.assertEqual(self.store.root.stat().st_mode & 0o777, 0o700)
        self.assertEqual(len(list((self.store.root / 'quarantine').iterdir())), 1)

    def test_snapshot_limits_and_symlink(self):
        link = self.root / 'link'
        link.symlink_to(self.source)
        with self.assertRaises(OSError):
            self.store.snapshot(link, self.cancel)
        huge = self.root / 'huge'
        with huge.open('wb') as stream:
            stream.truncate(MAX_FILE + 1)
        with self.assertRaises(ValueError):
            self.store.snapshot(huge, self.cancel)
        self.assertEqual(list((self.store.root / 'quarantine').iterdir()), [])

    def test_cancellation_and_fifo(self):
        self.cancel.set()
        with self.assertRaises(Cancelled):
            self.store.snapshot(self.source, self.cancel)
        self.assertEqual(list((self.store.root / 'quarantine').iterdir()), [])
        import os
        fifo = self.root / 'fifo'
        os.mkfifo(fifo)
        with self.assertRaises(ValueError):
            self.store.snapshot(fifo, threading.Event())

    def test_identify_no_extension(self):
        for signature, kind in [(b'\x7fELF', 'ELF'), (b'%PDF-1.7', 'PDF'),
                                (b'PK\x03\x04', 'archive'), (b'#!/bin/sh\n', 'script'),
                                (b'\xfe\xed\xfa\xcf', 'Mach-O'), (b'\xd0\xcf\x11\xe0', 'document (OLE)')]:
            self.source.write_bytes(signature)
            self.assertEqual(identify(self.source, self.cancel)['format'], kind)

    def test_strings_and_indicators(self):
        self.source.write_bytes('Unicode Türkçe güvenli\n'.encode() + 'UTF16 test'.encode('utf-16-le'))
        result = strings(self.source, self.cancel)
        self.assertTrue(any('Türkçe' in row['text'] for row in result['rows']))
        self.assertTrue(any(row['encoding'] == 'utf-16-le' for row in result['rows']))
        self.assertEqual(indicators([{'offset': 0, 'text': '999.999.999.999'}]), [])

    @unittest.skipUnless(shutil.which('readelf'), 'readelf yok')
    def test_real_elf_and_malformed(self):
        result = analyze(self.store, Path('/bin/true').resolve(), ['elf'])
        self.assertEqual(result['modules']['elf']['status'], 'ok')
        self.assertTrue(result['modules']['elf']['entry'].startswith('0x'))
        self.source.write_bytes(b'\x7fELFbad')
        result = analyze(self.store, self.source, ['elf'])
        self.assertEqual(result['modules']['elf']['status'], 'error')

    def test_hex_and_markdown(self):
        self.assertIn('00000004', hex_page(self.source, 4))
        with self.assertRaises(ValueError):
            hex_page(self.source, -1)
        report = markdown({'untrusted': '```\n<script>ignored</script>'})
        self.assertIn('````json', report)

    def test_process_timeout_limit_cancel(self):
        result = run([sys.executable, '-c', 'print("x" * 100000)'], limit=100)
        self.assertEqual(len(result['text']), 100)
        self.assertTrue(result['limited'])
        started = time.monotonic()
        result = run([sys.executable, '-c', 'import time; time.sleep(10)'], timeout=0.1)
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(result['limited'], 'Süre sınırı')
        event = threading.Event()
        event.set()
        with self.assertRaises(Cancelled):
            run([sys.executable, '-c', 'pass'], event)

    def test_missing_dependencies_explicit(self):
        with patch('reworkbench.engine.shutil.which', return_value=None):
            self.assertEqual(identify(self.source, self.cancel)['description']['status'], 'unavailable')

    def test_dynamic_no_runtime_and_no_approval(self):
        sandbox = Sandbox()
        sandbox.runtime = None
        self.assertFalse(sandbox.availability()[0])
        with self.assertRaises(ValueError):
            sandbox.prepare(self.source)
        with self.assertRaises(ValueError):
            sandbox.execute('invented-approval')

    def test_job_queue_real_worker(self):
        events = queue.Queue()
        jobs = Jobs(self.store.root, lambda kind, data: events.put((kind, data)))
        self.addCleanup(jobs.close)
        jobs.submit(self.source, ['strings'])
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            kind, data = events.get(timeout=10)
            if kind == 'result':
                self.assertTrue(data['file']['hashes']['sha256'])
                return
            if kind == 'error':
                self.fail(data)
        self.fail('Worker timeout')


if __name__ == '__main__':
    unittest.main()


@unittest.skipUnless(__import__('importlib.util', fromlist=['find_spec']).find_spec('elftools') and
                     __import__('importlib.util', fromlist=['find_spec']).find_spec('capstone') and shutil.which('gcc'),
                     'pyelftools/Capstone/gcc yok; yapılandırılmış ELF+disassembly testi çalıştırılmadı')
class OptionalBinaryTests(unittest.TestCase):
    def test_structured_elf_symbols_and_disassembly(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'hello'
            fixture = Path(__file__).parent / 'fixtures' / 'hello.c'
            compiled = run([shutil.which('gcc'), '-g', '-O0', '-o', str(target), str(fixture)])
            self.assertEqual(compiled['returncode'], 0)
            result = analyze(Store(Path(directory) / 'data'), target, ['elf', 'disassembly'])
            binary = result['modules']['elf']
            self.assertEqual(binary['status'], 'ok')
            self.assertTrue(any(s['name'] == 'main' and s['type'] == 'STT_FUNC' for s in binary['symbols']))
            self.assertTrue(binary['sections'])
            self.assertTrue(result['modules']['disassembly']['rows'])
