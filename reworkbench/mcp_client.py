"""Explicit MCP discovery and immutable, one-use call approvals.

No sample paths, contents, roots, prompts, or credentials are added to tool arguments.
"""

import asyncio
from contextlib import AsyncExitStack
from dataclasses import dataclass
import hashlib
import json
import logging
import os
from pathlib import Path
import secrets
from urllib.parse import urlsplit

# Third-party transports may include HTTP headers or server content in diagnostics.
for _package in ("mcp", "httpx2", "httpcore2"):
    _logger = logging.getLogger(_package)
    _logger.handlers = [logging.NullHandler()]
    _logger.propagate = False


@dataclass
class Config:
    transport: str = "streamable-http"
    url: str = ""
    token_env: str = "REWB_MCP_TOKEN"
    auth: str = "none"
    timeout: int = 20

    @classmethod
    def load(cls, path=None):
        values = {}
        if path:
            values = json.loads(Path(path).read_text(encoding="utf-8"))
        for key in cls.__dataclass_fields__:
            value = os.environ.get("REWB_MCP_" + key.upper())
            if value is not None:
                values[key] = int(value) if key == "timeout" else value
        config = cls(**values)
        parts = urlsplit(config.url)
        if config.transport not in ("streamable-http", "sse"):
            raise ValueError("Desteklenen taşımalar: streamable-http ve sse. stdio kapalıdır.")
        if config.auth not in ("none", "bearer"):
            raise ValueError("Bu sürüm yalnızca none/bearer kimlik doğrulamasını destekler; OAuth yok.")
        if not config.url:
            raise ValueError("MCP adresi ayarlanmamış; REWB_MCP_URL veya yerel JSON yapılandırmasını kullanın.")
        if parts.username or parts.password or parts.query or parts.fragment:
            raise ValueError("URL içinde kimlik bilgisi, sorgu veya fragment kullanmayın.")
        if parts.scheme != "https" and not (parts.scheme == "http" and parts.hostname in ("localhost", "127.0.0.1", "::1")):
            raise ValueError("Uzak sunucu için HTTPS gerekli; HTTP yalnızca loopback için.")
        if not 1 <= config.timeout <= 120:
            raise ValueError("MCP zaman aşımı 1–120 saniye olmalı.")
        return config


def validate_schema(schema, arguments=None):
    from jsonschema import Draft202012Validator

    def forbid_refs(node, depth=0):
        if depth > 32:
            raise ValueError("Şema derinlik sınırı.")
        if isinstance(node, dict):
            if any(k in node for k in ("$ref", "$dynamicRef", "pattern", "patternProperties")):
                raise ValueError("Referanslı veya regex içeren uzak şemalar bu sürümde kapalı.")
            for value in node.values():
                forbid_refs(value, depth + 1)
        elif isinstance(node, list):
            for value in node:
                forbid_refs(value, depth + 1)
    if len(json.dumps(schema)) > 65536:
        raise ValueError("MCP şema boyutu sınırı.")
    forbid_refs(schema)
    Draft202012Validator.check_schema(schema)
    if arguments is not None:
        if not isinstance(arguments, dict) or len(json.dumps(arguments)) > 65536:
            raise ValueError("Parametreler en fazla 64 KiB JSON nesnesi olmalı.")
        if not Draft202012Validator(schema).is_valid(arguments):
            raise ValueError("Parametreler aracın giriş şemasına uymuyor.")


class MCP:
    def __init__(self, config):
        self.config = config
        self.tools = {}
        self.pending = {}
        self.info = {}

    async def serve(self, requests, publish):
        """Keep all transport context managers on one async task/thread."""
        try:
            import httpx2
            from mcp import Client
            from mcp.client.streamable_http import streamable_http_client
            from mcp.client.sse import sse_client
            from .http_limits import limited_transport
            headers = {}
            if self.config.auth == "bearer":
                token = os.environ.get(self.config.token_env)
                if not token:
                    raise ValueError("Token ortam değişkeni ayarlanmamış.")
                headers["Authorization"] = "Bearer " + token
            async with AsyncExitStack() as stack:
                if self.config.transport == "sse":
                    def factory(**kwargs):
                        kwargs["trust_env"] = False
                        kwargs["transport"] = limited_transport()
                        return httpx2.AsyncClient(**kwargs)
                    transport = sse_client(self.config.url, headers=headers,
                                           timeout=self.config.timeout, sse_read_timeout=self.config.timeout,
                                           httpx_client_factory=factory)
                else:
                    http = await stack.enter_async_context(httpx2.AsyncClient(
                        headers=headers, timeout=self.config.timeout, trust_env=False, transport=limited_transport(),
                        follow_redirects=False))
                    transport = streamable_http_client(self.config.url, http_client=http,
                                                       max_sse_event_size=2_000_000)
                client = await stack.enter_async_context(Client(transport, read_timeout_seconds=self.config.timeout))
                self.info = {"server": client.server_info.model_dump(mode="json") if client.server_info else None,
                             "protocol": client.protocol_version,
                             "capabilities": client.server_capabilities.model_dump(mode="json")}
                await self.discover(client)
                publish("mcp_ready", {**self.info, "tools": list(self.tools.values())})
                while True:
                    try:
                        request = requests.get_nowait()
                    except __import__("queue").Empty:
                        await asyncio.sleep(0.05)
                        continue
                    if request is None:
                        break
                    action, payload = request
                    try:
                        if action == "refresh":
                            await self.discover(client)
                            publish("mcp_ready", {**self.info, "tools": list(self.tools.values())})
                        elif action == "call":
                            name, arguments = self.consume(payload)
                            reply = await client.call_tool(name, arguments)
                            data = reply.model_dump(mode="json", by_alias=True)
                            if len(json.dumps(data)) > 2_000_000:
                                raise ValueError("MCP sonuç boyutu sınırı.")
                            publish("mcp_result", data)
                    except Exception:
                        publish("mcp_error", "MCP çağrısı başarısız: şema, sunucu hatası veya süre sınırı. Otomatik tekrar yapılmadı.")
        except Exception:
            publish("mcp_error", "MCP bağlantısı kurulamadı/kesildi. SDK, adres, taşıma, TLS ve kimlik ayarlarını kontrol edin.")
        finally:
            self.tools = {}
            self.pending = {}
            publish("mcp_closed", "Bağlantı kapalı")

    async def discover(self, client):
        tools = {}
        cursor = None
        for _ in range(20):
            page = await client.list_tools(cursor=cursor, cache_mode="refresh")
            for tool in page.tools:
                data = tool.model_dump(mode="json", by_alias=True)
                try:
                    validate_schema(data["inputSchema"])
                    data["callable"] = True
                except Exception:
                    data["callable"] = False
                    data["restriction"] = "Şema geçersiz veya bu sürümün güvenli alt kümesinin dışında."
                tools[tool.name] = data
                if len(tools) > 500:
                    raise ValueError("MCP araç sayısı sınırı.")
            cursor = page.next_cursor
            if cursor is None:
                self.tools = tools
                self.pending = {}
                return
        raise ValueError("MCP sayfalama sınırı.")

    def prepare(self, name, arguments):
        tool = self.tools.get(name)
        if not tool or not tool.get("callable"):
            raise ValueError("Araç bulunamadı veya çağrıya kapalı; listeyi yenileyin.")
        validate_schema(tool["inputSchema"], arguments)
        payload = json.dumps({"name": name, "arguments": arguments}, ensure_ascii=False, sort_keys=True)
        if len(self.pending) >= 8:
            self.pending.pop(next(iter(self.pending)))
        ticket = secrets.token_hex(24)
        self.pending[ticket] = (payload, hashlib.sha256(json.dumps(tool, sort_keys=True).encode()).hexdigest())
        return ticket, payload

    def consume(self, ticket):
        if ticket not in self.pending:
            raise ValueError("Geçerli bir tek kullanımlık onay gerekli.")
        payload, schema_hash = self.pending.pop(ticket)
        data = json.loads(payload)
        tool = self.tools.get(data["name"])
        if not tool or hashlib.sha256(json.dumps(tool, sort_keys=True).encode()).hexdigest() != schema_hash:
            raise ValueError("Araç değişti; yeniden onay gerekli.")
        return data["name"], data["arguments"]
