from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest

from domain_mapper.plugins.base import ScopeView, default_registry
from domain_mapper.plugins.dorks import CATEGORIES, Dork, generate_dorks
from domain_mapper.scope import OutOfScopeError


def test_builds_search_links_for_an_in_scope_domain(scope_view: ScopeView) -> None:
    dorks = generate_dorks("Example.COM", scope_view)

    assert dorks
    assert all(isinstance(d, Dork) for d in dorks)
    assert all("example.com" in d.query for d in dorks)
    first = dorks[0]
    assert first == Dork(
        category="Subdomains",
        query="site:*.example.com -www",
        url="https://www.google.com/search?q=site%3A%2A.example.com+-www",
    )
    for dork in dorks:
        parts = urlsplit(dork.url)
        assert (parts.scheme, parts.netloc, parts.path) == ("https", "www.google.com", "/search")
        assert parse_qs(parts.query) == {"q": [dork.query]}


def test_refuses_an_out_of_scope_domain(scope_view: ScopeView) -> None:
    with pytest.raises(OutOfScopeError):
        generate_dorks("not-authorized.example.net", scope_view)


def test_no_template_hunts_credentials_people_or_injection() -> None:
    queries = [q for templates in CATEGORIES.values() for q in templates]
    for forbidden in ("password", "DB_PASSWORD", "wp-config", 'intext:"@', "?id=", "linkedin"):
        assert not any(forbidden.lower() in q.lower() for q in queries), forbidden
    assert all("{domain}" in q for q in queries)


def test_order_is_stable(scope_view: ScopeView) -> None:
    assert generate_dorks("example.com", scope_view) == generate_dorks("example.com", scope_view)


def test_is_not_a_collection_plugin() -> None:
    # It never sends anything: the user opens the links by hand.
    assert "dorks" not in default_registry()
