from __future__ import annotations

import asyncio
import dataclasses
import hashlib
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
import respx

from surfacemap.collect.http import FetchError
from surfacemap.models import Certificate, Domain, IPAddress, RelationType
from surfacemap.plugins import crtsh
from surfacemap.plugins.base import Plugin, PluginContext, ScopeView, default_registry
from surfacemap.plugins.crtsh import CRTSH_URL, CrtshPlugin
from surfacemap.scope import Scope, ScopeEntry

ROOT = Domain(fqdn="example.com", in_scope=True)


def mock_crtsh(body: object, status: int = 200) -> respx.Route:
    return respx.get(CRTSH_URL, params={"q": "%.example.com", "output": "json"}).mock(
        return_value=httpx.Response(status, json=body)
    )


def test_declares_a_root_only_enrichment_plugin(scope_view: ScopeView) -> None:
    plugin = CrtshPlugin()
    assert isinstance(plugin, Plugin)
    assert plugin.name == "crtsh"
    assert plugin.consumes == frozenset({"domain"})
    assert plugin.runs_out_of_scope is False
    assert plugin.applies_to(ROOT, scope_view)
    assert not plugin.applies_to(Domain(fqdn="www.example.com", in_scope=True), scope_view)
    assert not plugin.applies_to(Domain(fqdn="cdn.net", in_scope=False), scope_view)
    assert not plugin.applies_to(IPAddress(address="192.0.2.1"), scope_view)


@respx.mock
async def test_emits_subdomains_seen_in_certificates(
    plugin_ctx: PluginContext, load_fixture: Callable[[str], Any]
) -> None:
    route = mock_crtsh(load_fixture("crtsh_example.json"))
    respx.get(CRTSH_URL).respond(404)  # certificate downloads: covered below

    [observation] = await CrtshPlugin().run(ROOT, plugin_ctx)

    assert route.call_count == 1
    assert observation.provenance.source == "crtsh"
    assert observation.provenance.query == "%.example.com"
    fqdns = sorted(e.fqdn for e in observation.entities if isinstance(e, Domain))
    # Wildcard stripped, case/trailing dot normalized, duplicates merged; the email,
    # the invalid `_` label and the co-tenant name outside the root are dropped.
    assert fqdns == ["api.example.com", "dev.example.com", "example.com", "www.example.com"]
    assert all(isinstance(e, Domain) and e.in_scope for e in observation.entities)
    assert observation.relations == ()


@respx.mock
async def test_no_certificate_means_no_observation(plugin_ctx: PluginContext) -> None:
    mock_crtsh([])
    assert await CrtshPlugin().run(ROOT, plugin_ctx) == []


@respx.mock
async def test_ignores_malformed_rows(plugin_ctx: PluginContext) -> None:
    mock_crtsh([{"name_value": 42}, "not-a-row", {"common_name": "ok.example.com"}])
    [observation] = await CrtshPlugin().run(ROOT, plugin_ctx)
    assert [e.id for e in observation.entities] == ["domain:ok.example.com"]


@respx.mock
async def test_non_list_payload_is_a_fetch_error(plugin_ctx: PluginContext) -> None:
    mock_crtsh({"error": "busy"})
    with pytest.raises(FetchError, match="crtsh: unexpected payload"):
        await CrtshPlugin().run(ROOT, plugin_ctx)


@respx.mock
async def test_invalid_json_is_a_fetch_error(plugin_ctx: PluginContext) -> None:
    respx.get(CRTSH_URL).mock(return_value=httpx.Response(200, text="<html>busy</html>"))
    with pytest.raises(FetchError, match="crtsh: unexpected payload"):
        await CrtshPlugin().run(ROOT, plugin_ctx)


def test_is_a_built_in_plugin() -> None:
    assert isinstance(default_registry().get("crtsh"), CrtshPlugin)


async def test_ignores_entities_that_are_not_domains(plugin_ctx: PluginContext) -> None:
    assert await CrtshPlugin().run(IPAddress(address="192.0.2.1"), plugin_ctx) == []


@respx.mock
async def test_cached_body_holds_no_email_and_only_needed_fields(
    plugin_ctx: PluginContext, load_fixture: Callable[[str], Any]
) -> None:
    mock_crtsh(load_fixture("crtsh_example.json"))
    respx.get(CRTSH_URL).respond(404)
    await CrtshPlugin().run(ROOT, plugin_ctx)

    rows = plugin_ctx.cache._db.execute("SELECT body FROM responses").fetchall()
    assert rows
    for (body,) in rows:
        assert "jane.doe" not in body
        assert "issuer_ca_id" not in body
        assert "www.example.com" in body  # the name after the dropped email survives


@respx.mock
async def test_cached_body_keeps_only_hostname_identities_and_no_issuer_email(
    plugin_ctx: PluginContext,
) -> None:
    # S/MIME certificates carry a person's name as CN; the issuer DN may carry an email.
    mock_crtsh(
        [
            {
                "common_name": "Jane Doe",
                "name_value": "Jane Doe\nwww.example.com",
                "issuer_name": "C=US, O=Acme, emailAddress=pki@acme.test",
            }
        ]
    )
    respx.get(CRTSH_URL).respond(404)
    await CrtshPlugin().run(ROOT, plugin_ctx)

    [(body,)] = plugin_ctx.cache._db.execute("SELECT body FROM responses").fetchall()
    assert "Jane" not in body
    assert "pki@acme.test" not in body
    assert "www.example.com" in body


def mock_pem(cert_id: int, body: str, status: int = 200) -> respx.Route:
    return respx.get(CRTSH_URL, params={"d": str(cert_id)}).respond(status, text=body)


DER = b"synthetic-der-bytes-for-tests-only"


@respx.mock
async def test_downloads_valid_certificates_and_links_their_names(
    plugin_ctx: PluginContext, load_fixture: Callable[[str], Any]
) -> None:
    mock_crtsh(load_fixture("crtsh_example.json"))
    pem = load_fixture("crtsh_cert.pem")
    routes = [mock_pem(cert_id, pem) for cert_id in (1000000001, 1000000002, 1000000003)]

    domains, *certs = await CrtshPlugin().run(ROOT, plugin_ctx)

    assert all(route.call_count == 1 for route in routes)
    assert len(domains.entities) == 4
    assert [o.provenance.query for o in certs] == [
        "crt.sh id 1000000001",
        "crt.sh id 1000000002",
        "crt.sh id 1000000003",
    ]
    [cert] = certs[1].entities
    assert isinstance(cert, Certificate)
    assert cert.sha256 == hashlib.sha256(DER).hexdigest()
    assert cert.issuer == "C=US, O=Let's Encrypt, CN=R11"
    assert cert.not_before == datetime(2026, 4, 1, 9, tzinfo=UTC)
    assert cert.not_after == datetime(2026, 6, 30, 9, tzinfo=UTC)
    assert cert.sans == ("*.dev.example.com", "api.example.com")
    assert sorted((r.source, r.type) for r in certs[1].relations) == [
        ("domain:api.example.com", RelationType.SECURED_BY),
        ("domain:dev.example.com", RelationType.SECURED_BY),
    ]
    # The S/MIME certificate keeps only its hostname, never the email.
    [smime] = certs[2].entities
    assert isinstance(smime, Certificate)
    assert smime.sans == ("www.example.com",)
    # Only the fingerprint is cached: the DER may embed email SANs.
    bodies = [b for (b,) in plugin_ctx.cache._db.execute("SELECT body FROM responses")]
    assert hashlib.sha256(DER).hexdigest() in bodies
    assert not any("BEGIN CERTIFICATE" in b for b in bodies)


@respx.mock
async def test_secured_by_edges_only_for_in_scope_hosts(plugin_ctx: PluginContext) -> None:
    view = ScopeView(
        Scope([ScopeEntry(domain="example.com", include_subdomains=False, authorization="t")]),
        plugin_ctx.scope.today,
    )
    ctx = dataclasses.replace(plugin_ctx, scope=view)
    mock_crtsh(
        [
            {
                "id": 7,
                "issuer_name": "CN=Test CA",
                "name_value": "example.com\nstaging.example.com",
                "not_before": "2026-05-01T00:00:00",
                "not_after": "2026-08-01T00:00:00",
            }
        ]
    )
    mock_pem(7, "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")

    domains, cert = await CrtshPlugin().run(ROOT, ctx)

    assert {e.id: e.in_scope for e in domains.entities} == {
        "domain:example.com": True,
        "domain:staging.example.com": False,
    }
    assert [r.source for r in cert.relations] == ["domain:example.com"]


def row(cert_id: int, not_before: str, not_after: str) -> dict[str, object]:
    return {
        "id": cert_id,
        "issuer_name": "CN=Test CA",
        "name_value": f"c{cert_id}.example.com",
        "not_before": not_before,
        "not_after": not_after,
    }


@respx.mock
async def test_skips_expired_and_future_certificates(plugin_ctx: PluginContext) -> None:
    # The run date is pinned to 2026-06-01 (scope view).
    mock_crtsh(
        [
            row(1, "2025-01-01T00:00:00", "2025-04-01T00:00:00"),
            row(2, "2026-07-01T00:00:00", "2026-10-01T00:00:00"),
            row(3, "not-a-date", "2026-10-01T00:00:00"),
            row(4, "2026-05-01T00:00:00", "2026-08-01T00:00:00"),
        ]
    )
    valid = mock_pem(4, "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")

    domains, cert = await CrtshPlugin().run(ROOT, plugin_ctx)

    assert valid.call_count == 1
    assert len(domains.entities) == 4  # every name is still recorded
    assert cert.provenance.query == "crt.sh id 4"


@respx.mock
async def test_caps_downloads_to_the_newest_certificates(
    plugin_ctx: PluginContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(crtsh, "MAX_CERTIFICATES", 1)
    mock_crtsh(
        [
            row(1, "2026-05-01T00:00:00", "2026-08-01T00:00:00"),
            row(2, "2026-05-20T00:00:00", "2026-08-01T00:00:00"),
        ]
    )
    newest = mock_pem(2, "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")

    _, cert = await CrtshPlugin().run(ROOT, plugin_ctx)

    assert newest.call_count == 1
    assert cert.provenance.query == "crt.sh id 2"


@respx.mock
async def test_a_bad_certificate_download_is_skipped(plugin_ctx: PluginContext) -> None:
    mock_crtsh(
        [
            row(1, "2026-05-01T00:00:00", "2026-08-01T00:00:00"),
            row(2, "2026-05-01T00:00:00", "2026-08-01T00:00:00"),
            row(3, "2026-05-01T00:00:00", "2026-08-01T00:00:00"),
        ]
    )
    mock_pem(1, "", status=404)
    mock_pem(2, "<html>not a certificate</html>")
    mock_pem(3, "-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n")

    [domains] = await CrtshPlugin().run(ROOT, plugin_ctx)

    assert len(domains.entities) == 3


@respx.mock
async def test_downloads_stop_at_their_time_budget_and_keep_results(
    plugin_ctx: PluginContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(crtsh, "DOWNLOAD_BUDGET", 0.2)
    mock_crtsh(
        [
            row(1, "2026-05-02T00:00:00", "2026-08-01T00:00:00"),
            row(2, "2026-05-01T00:00:00", "2026-08-01T00:00:00"),
        ]
    )
    mock_pem(1, "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")

    async def slow(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(5)
        return httpx.Response(200, text="never")

    respx.get(CRTSH_URL, params={"d": "2"}).mock(side_effect=slow)

    domains, cert = await CrtshPlugin().run(ROOT, plugin_ctx)

    assert len(domains.entities) == 2  # the subdomains survive the cut
    assert cert.provenance.query == "crt.sh id 1"


@respx.mock
async def test_a_precertificate_and_its_certificate_count_once(plugin_ctx: PluginContext) -> None:
    precert = {**row(10, "2026-05-01T00:00:00", "2026-08-01T00:00:00"), "serial_number": "0abc"}
    leaf = {**row(11, "2026-05-01T00:00:00", "2026-08-01T00:00:00"), "serial_number": "0abc"}
    other = {**row(12, "2026-05-01T00:00:00", "2026-08-01T00:00:00"), "serial_number": "0def"}
    mock_crtsh([precert, leaf, other])
    pem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
    routes = {cert_id: mock_pem(cert_id, pem) for cert_id in (10, 11, 12)}

    _, *certs = await CrtshPlugin().run(ROOT, plugin_ctx)

    assert sorted(o.provenance.query for o in certs) == ["crt.sh id 11", "crt.sh id 12"]
    assert routes[10].call_count == 0
