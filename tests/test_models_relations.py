from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from domain_mapper.models import Provenance, Relation, RelationType

NOW = datetime(2026, 11, 20, tzinfo=UTC)


def test_relation_key_identifies_the_edge() -> None:
    rel = Relation(source="domain:example.com", type="RESOLVES_TO", target="ip:192.0.2.1")
    assert rel.type is RelationType.RESOLVES_TO
    assert rel.key == ("domain:example.com", RelationType.RESOLVES_TO, "ip:192.0.2.1")


@pytest.mark.parametrize(
    ("rtype", "source", "target"),
    [
        ("HAS_SUBDOMAIN", "domain:example.com", "domain:www.example.com"),
        ("CNAME_TO", "domain:www.example.com", "domain:cdn.example.net"),
        ("MX", "domain:example.com", "domain:mx.example.net"),
        ("NS", "domain:example.com", "domain:ns1.example.net"),
        ("ANNOUNCED_BY", "ip:192.0.2.1", "asn:64496"),
        ("SECURED_BY", "domain:example.com", "cert:" + "a" * 64),
        ("USES_TECH", "domain:example.com", "tech:nginx"),
        ("ARCHIVED_AT", "domain:example.com", "url:example.com/login"),
    ],
)
def test_every_relation_type_accepts_its_endpoint_kinds(
    rtype: str, source: str, target: str
) -> None:
    assert Relation(source=source, type=rtype, target=target).type == rtype


@pytest.mark.parametrize(
    ("rtype", "source", "target"),
    [
        ("RESOLVES_TO", "domain:example.com", "domain:other.example"),
        ("ANNOUNCED_BY", "domain:example.com", "asn:64496"),
        ("USES_TECH", "ip:192.0.2.1", "tech:nginx"),
    ],
)
def test_relation_refuses_wrong_endpoint_kinds(rtype: str, source: str, target: str) -> None:
    with pytest.raises(ValidationError, match="endpoints"):
        Relation(source=source, type=rtype, target=target)


def test_relation_refuses_self_loop() -> None:
    with pytest.raises(ValidationError):
        Relation(source="domain:example.com", type="CNAME_TO", target="domain:example.com")


def test_relation_refuses_unknown_type() -> None:
    with pytest.raises(ValidationError):
        Relation(source="domain:a.example", type="OWNS", target="domain:b.example")


def test_provenance_requires_aware_datetime() -> None:
    prov = Provenance(source="crtsh", retrieved_at=NOW, query="%.example.com")
    assert prov.retrieved_at == NOW
    with pytest.raises(ValidationError):
        Provenance(source="crtsh", retrieved_at=datetime(2026, 11, 20), query="x")


@pytest.mark.parametrize(
    "query", ["https://api.example/?key=abc", "host:example.com token=xyz", "apikey=1", "Secret=2"]
)
def test_provenance_query_refuses_credentials(query: str) -> None:
    with pytest.raises(ValidationError, match="credential"):
        Provenance(source="shodan", retrieved_at=NOW, query=query)


def test_provenance_source_must_not_be_blank() -> None:
    with pytest.raises(ValidationError):
        Provenance(source=" ", retrieved_at=NOW, query="x")


def test_credentials_never_appear_in_the_error_message() -> None:
    with pytest.raises(ValidationError) as excinfo:
        Provenance(source="shodan", retrieved_at=NOW, query="https://api.x/?key=SUPERSECRET123")
    assert "SUPERSECRET123" not in str(excinfo.value)


@pytest.mark.parametrize(
    "query",
    [
        "Authorization: Bearer abc",
        "https://user:pass@api.example/",
        "auth=abc",
        "sig=abc",
        "pwd=abc",
        "access_token=abc",
        "https://api.example/?key%3Dabc",
    ],
)
def test_provenance_query_refuses_more_credential_shapes(query: str) -> None:
    with pytest.raises(ValidationError, match="credential"):
        Provenance(source="x", retrieved_at=NOW, query=query)


@pytest.mark.parametrize(
    "query",
    [
        "monkey=1",
        "%.example.com",
        "hostname:example.com",
        "bearer.example.com",
        "authorization.example",
    ],
)
def test_provenance_query_accepts_innocent_text(query: str) -> None:
    assert Provenance(source="x", retrieved_at=NOW, query=query).query == query


def test_relation_between_uses_canonical_entity_ids() -> None:
    from domain_mapper.models import Domain

    apex = Domain(fqdn="Example.com", in_scope=True)
    www = Domain(fqdn="WWW.example.com", in_scope=True)
    rel = Relation.between(apex, RelationType.HAS_SUBDOMAIN, www)
    assert rel.key == ("domain:example.com", RelationType.HAS_SUBDOMAIN, "domain:www.example.com")
