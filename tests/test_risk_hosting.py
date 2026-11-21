"""Multiple-hosting-providers rule: sprawl across ASN holders. Graph-only, no network."""

from __future__ import annotations

from datetime import date

from risk_helpers import graph_of
from domain_mapper.models import (
    ASN,
    Domain,
    Entity,
    Finding,
    IPAddress,
    Relation,
    RelationType,
    Severity,
)
from domain_mapper.risk import RuleContext
from domain_mapper.risk.hosting import MIN_PROVIDERS, HostingSprawlRule, provider_key


def check(*items: Entity | Relation) -> tuple[Finding, ...]:
    ctx = RuleContext(graph=graph_of(*items), today=date(2026, 11, 21))
    return tuple(HostingSprawlRule().evaluate(ctx))


def hosted(
    name: str, ip: str, asn: int, holder: str | None, *, in_scope: bool = True
) -> list[Entity | Relation]:
    d = Domain(fqdn=name, in_scope=in_scope)
    i = IPAddress(address=ip)
    a = ASN(number=asn, holder=holder)
    return [
        d,
        i,
        a,
        Relation.between(d, RelationType.RESOLVES_TO, i),
        Relation.between(i, RelationType.ANNOUNCED_BY, a),
    ]


def sprawl(n: int) -> list[Entity | Relation]:
    items: list[Entity | Relation] = []
    for k in range(n):
        items += hosted(f"s{k}.example.com", f"192.0.2.{k + 1}", 64500 + k, f"HOST{k}-NET, US")
    return items


def test_provider_key_groups_same_operator() -> None:
    assert provider_key("AMAZON-02, US", 1) == provider_key("AMAZON-AES, US", 2) == "amazon"
    assert provider_key("OVH SAS, FR", 3) == "ovh"
    assert provider_key(None, 64500) == "as64500"


def test_few_providers_is_fine() -> None:
    assert check(*sprawl(MIN_PROVIDERS - 1)) == ()


def test_many_providers_is_one_low_finding() -> None:
    (finding,) = check(*sprawl(MIN_PROVIDERS))
    assert finding.rule_id == "hosting-sprawl"
    assert finding.severity is Severity.LOW
    assert str(MIN_PROVIDERS) in finding.title
    assert len(finding.evidence) == MIN_PROVIDERS
    assert all(e.startswith("asn:") for e in finding.evidence)


def test_same_operator_asns_count_once() -> None:
    items = sprawl(MIN_PROVIDERS - 1)
    # Holder tokens in sprawl() are host0/host1...: reuse the first one for a second ASN.
    items += hosted("x.example.com", "192.0.2.99", 64999, "HOST0-OTHER, US")
    assert check(*items) == ()


def test_out_of_scope_names_do_not_count() -> None:
    items = sprawl(MIN_PROVIDERS - 1)
    items += hosted("cdn.other.org", "192.0.2.98", 64998, "ELSE-NET", in_scope=False)
    assert check(*items) == ()


def test_cname_chain_is_followed_to_the_address() -> None:
    items = sprawl(MIN_PROVIDERS - 1)
    www = Domain(fqdn="www.example.com", in_scope=True)
    cdn = Domain(fqdn="x.cdn.example.net", in_scope=False)
    ip = IPAddress(address="192.0.2.77")
    asn = ASN(number=64777, holder="CDNCO, US")
    items += [
        www,
        cdn,
        ip,
        asn,
        Relation.between(www, RelationType.CNAME_TO, cdn),
        Relation.between(cdn, RelationType.RESOLVES_TO, ip),
        Relation.between(ip, RelationType.ANNOUNCED_BY, asn),
    ]
    assert len(check(*items)) == 1


def test_cname_loop_terminates() -> None:
    a = Domain(fqdn="a.example.com", in_scope=True)
    b = Domain(fqdn="b.example.com", in_scope=True)
    loop: list[Entity | Relation] = [
        a,
        b,
        Relation.between(a, RelationType.CNAME_TO, b),
        Relation.between(b, RelationType.CNAME_TO, a),
    ]
    assert check(*loop) == ()
