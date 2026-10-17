"""Bound HTTP response bytes before JSON parsing by the MCP SDK."""


def limited_transport():
    import httpx2

    class BoundedStream(httpx2.AsyncByteStream):
        def __init__(self, inner):
            self.inner = inner

        async def __aiter__(self):
            size = 0
            async for chunk in self.inner:
                size += len(chunk)
                if size > 2_000_000:
                    raise ValueError("MCP yanıt boyutu sınırı.")
                yield chunk

        async def aclose(self):
            await self.inner.aclose()

    class BoundedTransport(httpx2.AsyncBaseTransport):
        def __init__(self):
            self.inner = httpx2.AsyncHTTPTransport(retries=0)

        async def handle_async_request(self, request):
            # Prevent compressed response expansion before the parser's limit.
            request.headers['Accept-Encoding'] = 'identity'
            response = await self.inner.handle_async_request(request)
            if response.headers.get('content-encoding', 'identity').lower() != 'identity':
                await response.aclose()
                raise ValueError('Sıkıştırılmış MCP yanıtları desteklenmiyor.')
            response.stream = BoundedStream(response.stream)
            return response

        async def aclose(self):
            await self.inner.aclose()

    return BoundedTransport()
