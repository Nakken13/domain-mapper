from datetime import date
from typing import Any

import pytest

from domain_mapper.models import Domain, Entity, IPAddress, Observation
from domain_mapper.plugins.base import (
    ENTITY_KINDS,
    Plugin,
    PluginBase,
    PluginContext,
    PluginRegistry,
    ScopeView,
    default_registry,
)
from domain_mapper.scope import Scope, ScopeEntry

TODAY = date(2026, 6, 1)


def scope_view(**entries: Any) -> ScopeView:
    defaults = [
        ScopeEntry(domain="example.com", authorization="contract #1"),
        ScopeEntry(domain="old.org", authorization="x", expires=date(2026, 1, 1)),
        ScopeEntry(domain="apex.net", authorization="x", include_subdomains=False),
    ]
    return ScopeView(Scope(entries.get("entries", defaults)), today=TODAY)


class Dummy(PluginBase):
    name = "dummy"
    consumes = frozenset({"domain"})
    runs_out_of_scope = False

    async def run(self, entity: Entity, ctx: PluginContext) -> list[Observation]:
        return []


def make(name: str = "dummy", consumes: frozenset[str] = frozenset({"domain"})) -> Dummy:
    plugin = Dummy()
    plugin.name = name
    plugin.consumes = consumes
    return plugin


# --- ScopeView -------------------------------------------------------------


def test_scope_view_in_scope_uses_the_pinned_date() -> None:
    view = scope_view()
    assert view.today == TODAY
    assert view.is_in_scope("www.example.com")
    assert not view.is_in_scope("old.org")  # expired before TODAY
    assert not view.is_in_scope("cdn.cloudfront.net")
    assert not view.is_in_scope("not a domain")


def test_scope_view_root_of_returns_the_authorizing_entry() -> None:
    view = scope_view()
    assert view.root_of("a.b.example.com") == "example.com"
    assert view.root_of("example.com") == "example.com"
    assert view.root_of("cdn.cloudfront.net") is None


@pytest.mark.parametrize(
    "host",
    [
        "example.com",
        "deep.www.example.com",
        "old.org",
        "sub.apex.net",
        "EXAMPLE.com.",
        "_dmarc.example.com",  # rejected by normalize_domain: must still be refused
    ],
)
def test_target_host_is_any_name_under_a_listed_domain(host: str) -> None:
    # Fail closed: expired or subdomain-restricted entries still forbid direct traffic.
    assert scope_view().is_target_host(host)


@pytest.mark.parametrize("host", ["crt.sh", "evil-example.com", "example.com.evil.net", ""])
def test_third_party_hosts_are_not_target_hosts(host: str) -> None:
    assert not scope_view().is_target_host(host)


# --- Protocol and PluginBase ----------------------------------------------


def test_plugin_base_satisfies_the_protocol_with_permissive_defaults() -> None:
    plugin = Dummy()
    assert isinstance(plugin, Plugin)
    assert plugin.enabled(settings=None)  # type: ignore[arg-type]
    entity = Domain(fqdn="www.example.com", in_scope=True)
    assert plugin.applies_to(entity, scope_view())


def test_entity_kinds_match_the_model() -> None:
    assert {"domain", "ip", "asn", "certificate", "technology", "archived_url"} == ENTITY_KINDS


# --- Registry ---------------------------------------------------------------


def test_register_and_get() -> None:
    registry = PluginRegistry()
    plugin = registry.register(make("crtsh"))
    assert registry.get("crtsh") is plugin
    assert "crtsh" in registry


def test_iteration_is_sorted_by_name() -> None:
    registry = PluginRegistry()
    for name in ("wayback", "crtsh", "dns"):
        registry.register(make(name))
    assert [p.name for p in registry] == ["crtsh", "dns", "wayback"]


def test_duplicate_name_is_refused() -> None:
    registry = PluginRegistry()
    registry.register(make("crtsh"))
    with pytest.raises(ValueError, match="already registered"):
        registry.register(make("crtsh"))


@pytest.mark.parametrize("name", ["", "  ", "Has Space", "UPPER"])
def test_invalid_name_is_refused(name: str) -> None:
    with pytest.raises(ValueError, match="name"):
        PluginRegistry().register(make(name))


@pytest.mark.parametrize("consumes", [frozenset(), frozenset({"domain", "planet"})])
def test_invalid_consumed_kinds_are_refused(consumes: frozenset[str]) -> None:
    with pytest.raises(ValueError, match="consumes"):
        PluginRegistry().register(make(consumes=consumes))


def test_object_missing_the_contract_is_refused() -> None:
    with pytest.raises(TypeError, match="Plugin protocol"):
        PluginRegistry().register(object())  # type: ignore[arg-type]


def test_runs_out_of_scope_must_be_declared_as_a_bool() -> None:
    plugin = make()
    plugin.runs_out_of_scope = "yes"  # type: ignore[assignment]
    with pytest.raises(TypeError, match="runs_out_of_scope"):
        PluginRegistry().register(plugin)


def test_enabled_filters_on_settings() -> None:
    class NeedsKey(Dummy):
        name = "keyed"

        def enabled(self, settings: Any) -> bool:
            return bool(settings)

    registry = PluginRegistry()
    registry.register(make("free"))
    registry.register(NeedsKey())
    assert [p.name for p in registry.enabled(settings=None)] == ["free"]  # type: ignore[arg-type]


def test_default_registry_is_fresh_each_call() -> None:
    first = default_registry()
    first.register(make("only-here"))
    assert "only-here" not in default_registry()


def test_ip_entities_are_not_domains_for_applies_to() -> None:
    entity = IPAddress(address="192.0.2.1")
    assert Dummy().applies_to(entity, scope_view())


def test_scope_view_require_uses_the_pinned_date() -> None:
    from domain_mapper.scope import OutOfScopeError

    view = scope_view()
    assert view.require("WWW.Example.com.") == "www.example.com"
    with pytest.raises(OutOfScopeError):
        view.require("old.org")  # expired on the pinned date, whatever today is


@pytest.mark.parametrize(
    "host", ["straße.example", "www.xn--strae-oqa.example", "strasse.example", "STRASSE.example"]
)
def test_target_host_matches_every_idna_spelling(host: str) -> None:
    # IDNA 2003 (Python codec, used by scope) maps ß to ss; IDNA 2008 (httpx) keeps it.
    view = ScopeView(Scope([ScopeEntry(domain="straße.example", authorization="x")]), TODAY)
    assert view.is_target_host(host)


def test_engine_source_name_is_reserved() -> None:
    with pytest.raises(ValueError, match="reserved"):
        PluginRegistry().register(make("domain-mapper"))
