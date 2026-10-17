import hashlib
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from reworkbench.dynamic import Sandbox


class SandboxPlanTests(unittest.TestCase):
    def test_plan_is_restricted_immutable_and_single_use(self):
        with tempfile.TemporaryDirectory() as directory:
            data = b'harmless non-executable fixture'
            path = Path(directory) / hashlib.sha256(data).hexdigest()
            path.write_bytes(data)
            sandbox = Sandbox()
            sandbox.runtime = '/usr/bin/podman'
            sandbox.image = 'sha256:' + 'a' * 64
            with patch.object(sandbox, 'availability', return_value=(True, 'fixture')):
                ticket, plan = sandbox.prepare(path)
            command = plan['command']
            for flag in ['--network=none', '--read-only', '--cap-drop=all', '--security-opt=no-new-privileges', '--pids-limit=64', '--pull=never']:
                self.assertIn(flag, command)
            self.assertFalse(any('privileged' in arg for arg in command))
            plan['command'][0] = 'tampered preview'
            # A UI preview must not mutate the command retained for approval.
            with patch('reworkbench.dynamic.run', return_value={'text': 'fixture', 'returncode': 0, 'limited': None}) as runner:
                sandbox.execute(ticket, threading.Event())
                self.assertEqual(runner.call_args_list[0].args[0][0], '/usr/bin/podman')
                self.assertIn('rm', runner.call_args_list[-1].args[0])
            with self.assertRaises(ValueError):
                sandbox.execute(ticket)

    def test_changed_snapshot_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            data = b'original'
            path = Path(directory) / hashlib.sha256(data).hexdigest()
            path.write_bytes(data)
            sandbox = Sandbox()
            sandbox.runtime = '/usr/bin/podman'
            with patch.object(sandbox, 'availability', return_value=(True, 'fixture')):
                ticket, _ = sandbox.prepare(path)
            path.write_bytes(b'changed')
            with self.assertRaises(ValueError):
                sandbox.execute(ticket)
