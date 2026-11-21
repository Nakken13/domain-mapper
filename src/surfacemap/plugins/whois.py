"""WHOIS (RFC 3912) fallback: name servers of a scope root whose TLD has no RDAP server.

Traffic: TCP port 43 to third-party WHOIS servers only, one query each: `whois.iana.org`
for the TLD's referral, then the registry it names, for the root. Skipped whenever the
TLD has an HTTPS RDAP server (see `rdap.py`): registries discourage automated WHOIS, so
this stays a rare, cached, rate-limited fallback. A referral naming the target itself or
an IP literal is refused (`PassiveViolationError`), as in the HTTP client.

WHOIS text is full of contacts and is never stored: only the referral and the parsed
name servers are cached.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
from typing import Protocol

from surfacemap.collect.http import PassiveViolationError, is_ip_literal
from surfacemap.models import Domain, Entity, Observation
from surfacemap.plugins.base import PluginContext, RootOnlyPlugin
from surfacemap.plugins.rdap import ns_observation, rdap_server
from surfacemap.scope import try_normalize_domain

IANA_WHOIS = "whois.iana.org"
WHOIS_PORT = 43
_REFER = re.compile(r"^\s*refer\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
_NAME_SERVER = re.compile(
    r"^\s*(?:name\s*servers?|nserver)\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE
)


class WhoisTransport(Protocol):
    async def query(self, server: str, text: str) -> str:
        """Send one WHOIS query and return the whole answer."""
        ...


class SocketTransport:
    """Plain RFC 3912: connect, send the query and CRLF, read until the server closes."""

    def __init__(self, port: int = WHOIS_PORT, timeout: float = 15.0, max_bytes: int = 256_000):
        self.port = port
        self.timeout = timeout
        self.max_bytes = max_bytes

    async def query(self, server: str, text: str) -> str:
        async with asyncio.timeout(self.timeout):
            reader, writer = await asyncio.open_connection(server, self.port)
            try:
                writer.write(f"{text}\r\n".encode("ascii"))
                await writer.drain()
                answer = bytearray()
                while len(answer) < self.max_bytes:
                    chunk = await reader.read(self.max_bytes - len(answer))
                    if not chunk:
                        break
                    answer += chunk
            finally:
                writer.close()
                with contextlib.suppress(OSError):  # a reset after the answer loses nothing
                    await writer.wait_closed()
        return answer.decode("utf-8", "replace")


def _name_servers(text: str, root: str) -> list[str]:
    servers: set[str] = set()
    for raw in _NAME_SERVER.findall(text):
        name = try_normalize_domain(raw)
        if name and name != root:
            servers.add(name)
    return sorted(servers)


class WhoisPlugin(RootOnlyPlugin):
    name = "whois"
    consumes = frozenset({"domain"})
    runs_out_of_scope = False

    def __init__(self, transport: WhoisTransport | None = None) -> None:
        self.transport: WhoisTransport = transport if transport is not None else SocketTransport()

    async def _ask(self, server: str, text: str, ctx: PluginContext) -> str:
        if is_ip_literal(server) or ctx.scope.is_target_host(server):
            raise PassiveViolationError(f"{self.name}: refused to contact {server} directly")
        await ctx.limiter.acquire(self.name)
        return await self.transport.query(server, text)

    async def _referral(self, tld: str, ctx: PluginContext) -> str:
        key = f"refer {tld}"
        cached = ctx.cache.get(self.name, key)
        if cached is None:
            match = _REFER.search(await self._ask(IANA_WHOIS, tld, ctx))
            cached = match.group(1).lower() if match else ""
            ctx.cache.set(self.name, key, cached)
        return cached

    async def _servers_of(self, root: str, ctx: PluginContext) -> list[str]:
        registry = await self._referral(root.rsplit(".", 1)[-1], ctx)
        if not registry:
            return []
        key = f"{registry} {root}"
        cached = ctx.cache.get(self.name, key)
        if cached is None:
            # Parsed before caching: the raw answer (contacts) never reaches the disk.
            cached = json.dumps(_name_servers(await self._ask(registry, root, ctx), root))
            ctx.cache.set(self.name, key, cached)
        return list(json.loads(cached))

    async def run(self, entity: Entity, ctx: PluginContext) -> list[Observation]:
        if not isinstance(entity, Domain):
            return []
        root = entity.fqdn
        if await rdap_server(root, ctx) is not None:
            return []
        servers = await self._servers_of(root, ctx)
        if not servers:
            return []
        return [ns_observation(self, root, servers, f"whois {root}", ctx)]
