import asyncio
import importlib.util
import unittest

HAS_HTTP = importlib.util.find_spec('httpx2') is not None


@unittest.skipUnless(HAS_HTTP, 'MCP HTTP bağımlılığı yok')
class HTTPLimitsTests(unittest.TestCase):
    def test_limit_before_parser_and_reject_compression(self):
        import httpx2
        from reworkbench.http_limits import limited_transport

        class Stream(httpx2.AsyncByteStream):
            async def __aiter__(self):
                for _ in range(3):
                    yield b'x' * 800000

        class Inner:
            async def handle_async_request(self, request):
                self.encoding = request.headers['Accept-Encoding']
                return httpx2.Response(200, stream=Stream())
            async def aclose(self):
                pass

        class Compressed(Inner):
            async def handle_async_request(self, request):
                return httpx2.Response(200, headers={'Content-Encoding': 'gzip'}, stream=Stream())

        async def scenario():
            transport = limited_transport()
            await transport.inner.aclose()
            inner = Inner()
            transport.inner = inner
            response = await transport.handle_async_request(httpx2.Request('POST', 'https://example.invalid'))
            with self.assertRaises(ValueError):
                await response.aread()
            self.assertEqual(inner.encoding, 'identity')
            await response.aclose()
            transport.inner = Compressed()
            with self.assertRaises(ValueError):
                await transport.handle_async_request(httpx2.Request('POST', 'https://example.invalid'))
            await transport.aclose()
        asyncio.run(scenario())
