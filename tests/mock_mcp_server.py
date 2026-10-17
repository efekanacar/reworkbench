"""Harmless loopback-only test server; never reads or executes files."""

import sys
from mcp.server.mcpserver import MCPServer

server = MCPServer('REWB fixture')


@server.tool()
async def fixture_echo_731(message: str) -> str:
    """Return text verbatim; HTML is intentionally untrusted."""
    return message


@server.tool()
async def fixture_error_731() -> str:
    """Return a deliberate server error."""
    raise ValueError('test failure')


if __name__ == '__main__':
    server.run(transport='streamable-http', host='127.0.0.1', port=int(sys.argv[1]),
               stateless_http=True, json_response=True)
