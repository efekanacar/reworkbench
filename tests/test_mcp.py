import asyncio
import importlib.util
import json
import os
from pathlib import Path
import queue
import socket
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch

from reworkbench.mcp_client import Config, MCP, validate_schema

HAS_SDK = importlib.util.find_spec('mcp') is not None
HAS_SCHEMA = importlib.util.find_spec('jsonschema') is not None
try:
    with socket.socket():
        HAS_SOCKET = True
except PermissionError:
    HAS_SOCKET = False


class ConfigTests(unittest.TestCase):
    def test_no_invented_address(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError):
                Config.load()

    def test_remote_plain_http_and_credentials_rejected(self):
        for address in ['http://example.org/mcp', 'https://user:secret@example.org/mcp', 'https://example.org/mcp?token=secret']:
            with patch.dict(os.environ, {'REWB_MCP_URL': address}, clear=True):
                with self.assertRaises(ValueError):
                    Config.load()

    def test_explicit_transport(self):
        with patch.dict(os.environ, {'REWB_MCP_URL': 'http://127.0.0.1/mcp', 'REWB_MCP_TRANSPORT': 'invented'}, clear=True):
            with self.assertRaises(ValueError):
                Config.load()


@unittest.skipUnless(HAS_SCHEMA, 'jsonschema bağımlılığı yok')
class SchemaTests(unittest.TestCase):
    def test_safe_validation(self):
        with self.assertRaises(ValueError):
            validate_schema({'$ref': 'https://example.org/schema'})
        with self.assertRaises(ValueError):
            validate_schema({'pattern': '(a+)+$'})
        with self.assertRaises(ValueError):
            validate_schema({'type': 'object', 'required': ['count']}, {})

    def test_immutable_one_time_approval(self):
        client = MCP(Config())
        client.tools['discovered'] = {'name': 'discovered', 'callable': True, 'inputSchema': {'type': 'object'}}
        arguments = {'text': 'original'}
        ticket, payload = client.prepare('discovered', arguments)
        arguments['text'] = 'changed'
        self.assertEqual(client.consume(ticket), ('discovered', {'text': 'original'}))
        with self.assertRaises(ValueError):
            client.consume(ticket)
        with self.assertRaises(ValueError):
            client.prepare('guessed', {})
        ticket, _ = client.prepare('discovered', {})
        client.tools['discovered']['inputSchema'] = {'type': 'object', 'required': ['x']}
        with self.assertRaises(ValueError):
            client.consume(ticket)
        self.assertNotIn('sample', payload)


@unittest.skipUnless(HAS_SDK and HAS_SCHEMA, 'MCP SDK/jsonschema yok; entegrasyon çalıştırılmadı')
class IntegrationTests(unittest.TestCase):
    def test_real_sdk_in_memory_server(self):
        from mcp import Client
        from mcp.server.mcpserver import MCPServer
        server = MCPServer('in-memory fixture')

        @server.tool()
        async def entirely_discovered_name_932(text: str) -> str:
            """Harmless echo tool."""
            return text

        @server.tool()
        async def deliberate_failure_932() -> str:
            """Harmless error."""
            raise ValueError('fixture failure')

        async def scenario():
            bridge = MCP(Config())
            async with Client(server, read_timeout_seconds=3) as client:
                await bridge.discover(client)
                self.assertIn('entirely_discovered_name_932', bridge.tools)
                ticket, _ = bridge.prepare('entirely_discovered_name_932', {'text': '<b>untrusted</b>'})
                name, arguments = bridge.consume(ticket)
                reply = await client.call_tool(name, arguments)
                self.assertIn('<b>untrusted</b>', reply.model_dump_json())
                ticket, _ = bridge.prepare('deliberate_failure_932', {})
                name, arguments = bridge.consume(ticket)
                reply = await client.call_tool(name, arguments)
                self.assertTrue(reply.is_error)
        asyncio.run(asyncio.wait_for(scenario(), 10))

    def test_full_bridge_lifecycle_with_sdk_memory_transport(self):
        from mcp.client._memory import InMemoryTransport
        from mcp.server.mcpserver import MCPServer
        server = MCPServer('transport fixture')

        @server.tool()
        async def no_name_assumption_432(value: str) -> str:
            """Echo harmless text."""
            return value

        requests, events = queue.Queue(), []
        bridge = MCP(Config(url='https://example.invalid/not-contacted', timeout=2))
        def publish(kind, data):
            events.append((kind, data))
            if kind == 'mcp_ready':
                ticket, _ = bridge.prepare('no_name_assumption_432', {'value': 'fixture'})
                requests.put(('call', ticket))
            elif kind == 'mcp_result':
                requests.put(None)
        async def scenario():
            with patch('mcp.client.streamable_http.streamable_http_client', return_value=InMemoryTransport(server)):
                await bridge.serve(requests, publish)
        asyncio.run(asyncio.wait_for(scenario(), 10))
        self.assertEqual([kind for kind, _ in events], ['mcp_ready', 'mcp_result', 'mcp_closed'])
        self.assertIn('fixture', json.dumps(events[1][1]))

    @unittest.skipUnless(HAS_SOCKET, "Ortam yerel soket oluşturmayı yasaklıyor")
    def test_real_http_discovery_approval_call_and_server_error(self):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        server = subprocess.Popen([sys.executable, str(Path(__file__).with_name('mock_mcp_server.py')), str(port)],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(lambda: server.kill() if server.poll() is None else None)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=0.1):
                    break
            except OSError:
                if server.poll() is not None:
                    self.fail('Mock MCP server did not start')
                time.sleep(0.05)
        requests, events = queue.Queue(), queue.Queue()
        client = MCP(Config(url=f'http://127.0.0.1:{port}/mcp', timeout=3))
        thread = threading.Thread(target=lambda: asyncio.run(client.serve(requests, lambda k, v: events.put((k, v)))), daemon=True)
        thread.start()
        self.addCleanup(lambda: requests.put(None))
        kind, data = events.get(timeout=15)
        self.assertEqual(kind, 'mcp_ready', data)
        self.assertIn('fixture_echo_731', client.tools)
        self.assertTrue(data['capabilities']['tools'] is not None)
        text = '<script>alert("untrusted")</script>'
        ticket, preview = client.prepare('fixture_echo_731', {'message': text})
        self.assertIn(text.replace('"', '\\"'), preview)
        requests.put(('call', ticket))
        kind, data = events.get(timeout=10)
        self.assertEqual(kind, 'mcp_result', data)
        self.assertIn(text, json.dumps(data).replace('\\"', '"'))
        requests.put(('call', ticket))
        self.assertEqual(events.get(timeout=10)[0], 'mcp_error')
        ticket, _ = client.prepare('fixture_error_731', {})
        requests.put(('call', ticket))
        kind, data = events.get(timeout=10)
        self.assertEqual(kind, 'mcp_result')
        self.assertTrue(data['isError'])
        requests.put(None)
        thread.join(timeout=10)
        self.assertFalse(thread.is_alive())
        server.terminate()
        server.wait(timeout=5)

    @unittest.skipUnless(HAS_SOCKET, "Ortam yerel soket oluşturmayı yasaklıyor")
    def test_network_failure_is_safe(self):
        # Port held without listen: deterministic connection refusal.
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            client = MCP(Config(url=f'http://127.0.0.1:{sock.getsockname()[1]}/mcp', timeout=1))
            events = []
            asyncio.run(client.serve(queue.Queue(), lambda k, v: events.append((k, v))))
        self.assertEqual(events[0][0], 'mcp_error')
        self.assertNotIn('Traceback', events[0][1])
        self.assertEqual(events[-1][0], 'mcp_closed')
