from __future__ import annotations

import asyncio

import pytest
import respx

from surfacemap.collect.http import PassiveViolationError
from surfacemap.models import Domain, IPAddress, RelationType
from surfacemap.plugins.base import Plugin, PluginContext, ScopeView, default_registry
from surfacemap.plugins.rdap import BOOTSTRAP_URL
from surfacemap.plugins.whois import IANA_WHOIS, SocketTransport, WhoisPlugin

ROOT = Domain(fqdn="example.com", in_scope=True)

IANA_ANSWER = """% IANA WHOIS server
domain:       COM
refer:        whois.registry.example
status:       ACTIVE
"""

REGISTRY_ANSWER = """Domain Name: EXAMPLE.COM
Registrant Name: Jane Synthetic-Doe
Registrant Email: jane.synthetic@example.org
Name Server: NS1.EXAMPLE.NET
Name Server: ns2.example.net 192.0.2.53
nserver: ns2.example.net
Name Server: not_a_host
Name Server: example.com
"""


class FakeTransport:
    def __init__(self, answers: dict[tuple[str, str], str]) -> None:
        self.answers = answers
        self.sent: list[tuple[str, str]] = []

    async def query(self, server: str, text: str) -> str:
        self.sent.append((server, text))
        return self.answers.get((server, text), "")


@pytest.fixture
def no_rdap() -> respx.Route:
    return respx.get(BOOTSTRAP_URL).respond(200, json={"services": []})


def fake() -> FakeTransport:
    return FakeTransport(
        {
            (IANA_WHOIS, "com"): IANA_ANSWER,
            ("whois.registry.example", "example.com"): REGISTRY_ANSWER,
        }
    )


def test_declares_a_root_only_enrichment_plugin(scope_view: ScopeView) -> None:
    plugin = WhoisPlugin(fake())
    assert isinstance(plugin, Plugin)
    assert plugin.name == "whois"
    assert plugin.runs_out_of_scope is False
    assert plugin.applies_to(ROOT, scope_view)
    assert not plugin.applies_to(Domain(fqdn="www.example.com", in_scope=True), scope_view)
    assert isinstance(default_registry().get("whois"), WhoisPlugin)
    assert isinstance(WhoisPlugin().transport, SocketTransport)


@respx.mock
async def test_emits_name_servers_and_caches_nothing_personal(
    plugin_ctx: PluginContext, no_rdap: respx.Route
) -> None:
    transport = fake()

    [observation] = await WhoisPlugin(transport).run(ROOT, plugin_ctx)

    assert transport.sent == [(IANA_WHOIS, "com"), ("whois.registry.example", "example.com")]
    assert observation.provenance.query == "whois example.com"
    assert {r.key for r in observation.relations} == {
        ("domain:example.com", RelationType.NS, "domain:ns1.example.net"),
        ("domain:example.com", RelationType.NS, "domain:ns2.example.net"),
    }
    assert "Synthetic" not in observation.model_dump_json()
    bodies = [b for (b,) in plugin_ctx.cache._db.execute("SELECT body FROM responses")]
    assert bodies
    assert not any("Synthetic" in b or "synthetic@" in b for b in bodies)

    # Second run: served from the cache, nothing sent.
    await WhoisPlugin(transport).run(ROOT, plugin_ctx)
    assert len(transport.sent) == 2


@respx.mock
async def test_skipped_when_rdap_covers_the_tld(plugin_ctx: PluginContext) -> None:
    respx.get(BOOTSTRAP_URL).respond(
        200, json={"services": [[["com"], ["https://rdap.registry.example/"]]]}
    )
    transport = fake()
    assert await WhoisPlugin(transport).run(ROOT, plugin_ctx) == []
    assert transport.sent == []


@respx.mock
async def test_no_referral_means_nothing(plugin_ctx: PluginContext, no_rdap: respx.Route) -> None:
    transport = FakeTransport({(IANA_WHOIS, "com"): "% no such TLD\n"})
    assert await WhoisPlugin(transport).run(ROOT, plugin_ctx) == []


@respx.mock
async def test_no_name_server_means_nothing(
    plugin_ctx: PluginContext, no_rdap: respx.Route
) -> None:
    transport = FakeTransport({(IANA_WHOIS, "com"): IANA_ANSWER})
    assert await WhoisPlugin(transport).run(ROOT, plugin_ctx) == []


@respx.mock
@pytest.mark.parametrize("server", ["whois.example.com", "192.0.2.43", "[2001:db8::43]"])
async def test_never_contacts_the_target_or_an_ip(
    plugin_ctx: PluginContext, no_rdap: respx.Route, server: str
) -> None:
    transport = FakeTransport({(IANA_WHOIS, "com"): f"refer: {server}\n"})
    with pytest.raises(PassiveViolationError):
        await WhoisPlugin(transport).run(ROOT, plugin_ctx)
    assert transport.sent == [(IANA_WHOIS, "com")]


async def test_ignores_entities_that_are_not_domains(plugin_ctx: PluginContext) -> None:
    assert await WhoisPlugin(fake()).run(IPAddress(address="192.0.2.1"), plugin_ctx) == []


async def test_socket_transport_speaks_rfc_3912() -> None:
    received: list[bytes] = []

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        received.append(await reader.readline())
        writer.write("Name Server: ns1.example.net\r\nnon-ascii: \xe9\r\n".encode("latin-1"))
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        text = await SocketTransport(port=port, timeout=5).query("127.0.0.1", "example.com")
    assert received == [b"example.com\r\n"]
    assert text.startswith("Name Server: ns1.example.net")


async def test_socket_transport_caps_the_answer() -> None:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.readline()
        writer.write(b"x" * 5000)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        text = await SocketTransport(port=port, timeout=5, max_bytes=1000).query(
            "127.0.0.1", "example.com"
        )
    assert len(text) == 1000
