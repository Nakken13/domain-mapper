"""Takeover rule: dangling CNAME to a claimable provider. Pure graph analysis, no network."""

from __future__ import annotations

from datetime import UTC, date, datetime
from pathlib import Path

import pytest

from surfacemap.graph.builder import SurfaceGraph, build_graph
from surfacemap.models import (
    DnsRecord,
    Domain,
    Entity,
    Observation,
    Provenance,
    Relation,
    RelationType,
    Severity,
)
from surfacemap.risk import RuleContext, run_rules
from surfacemap.risk.takeover import Provider, TakeoverRule, load_providers

NXDOMAIN = DnsRecord(type="RCODE", value="NXDOMAIN")
T0 = datetime(2026, 1, 1, tzinfo=UTC)


def graph_of(*items: Entity | Relation) -> SurfaceGraph:
    return build_graph(
        [
            Observation(
                provenance=Provenance(source="dns_records", retrieved_at=T0, query="example.com"),
                entities=[i for i in items if not isinstance(i, Relation)],
                relations=[i for i in items if isinstance(i, Relation)],
            )
        ]
    )


def cname(source: Domain, target: Domain) -> Relation:
    return Relation.between(source, RelationType.CNAME_TO, target)


def evaluate(graph: SurfaceGraph, rule: TakeoverRule | None = None):
    rule = rule or TakeoverRule((Provider("GitHub Pages", ("github.io",)),))
    return tuple(rule.evaluate(RuleContext(graph=graph, today=date(2026, 11, 21))))


BLOG = Domain(fqdn="blog.example.com", in_scope=True)
DEAD = Domain(fqdn="acme.github.io", in_scope=False, records=(NXDOMAIN,))
ALIVE = Domain(fqdn="acme.github.io", in_scope=False)


def test_dangling_cname_to_risky_provider_is_flagged() -> None:
    (finding,) = evaluate(graph_of(BLOG, DEAD, cname(BLOG, DEAD)))
    assert finding.rule_id == "takeover"
    assert finding.severity is Severity.HIGH
    assert finding.evidence == (BLOG.id, DEAD.id)
    assert "GitHub Pages" in finding.rationale
    assert "no HTTP request" in finding.rationale


def test_resolving_target_is_not_flagged() -> None:
    assert evaluate(graph_of(BLOG, ALIVE, cname(BLOG, ALIVE))) == ()


def test_nxdomain_on_unlisted_provider_is_not_flagged() -> None:
    other = Domain(fqdn="gone.example.net", in_scope=False, records=(NXDOMAIN,))
    assert evaluate(graph_of(BLOG, other, cname(BLOG, other))) == ()


def test_suffix_match_respects_label_boundary() -> None:
    # "evilgithub.io" must not match the "github.io" provider.
    lookalike = Domain(fqdn="evilgithub.io", in_scope=False, records=(NXDOMAIN,))
    assert evaluate(graph_of(BLOG, lookalike, cname(BLOG, lookalike))) == ()


def test_out_of_scope_source_is_not_reported() -> None:
    foreign = Domain(fqdn="blog.other.org", in_scope=False)
    assert evaluate(graph_of(foreign, DEAD, cname(foreign, DEAD))) == ()


def test_target_missing_from_graph_is_not_flagged() -> None:
    # Without the NXDOMAIN observation the absence is unconfirmed: stay silent.
    assert evaluate(graph_of(BLOG, cname(BLOG, DEAD))) == ()


def test_runs_through_engine() -> None:
    ctx = RuleContext(graph=graph_of(BLOG, DEAD, cname(BLOG, DEAD)), today=date(2026, 11, 21))
    rule = TakeoverRule((Provider("GitHub Pages", ("github.io",)),))
    assert len(run_rules(ctx, [rule])) == 1


def test_bundled_provider_list_loads() -> None:
    providers = load_providers()
    assert providers
    assert all(p.name and p.suffixes for p in providers)
    assert any("github.io" in p.suffixes for p in providers)


def test_load_providers_rejects_malformed_file(tmp_path: Path) -> None:
    bad = tmp_path / "p.yaml"
    bad.write_text("providers:\n  - name: X\n", encoding="utf-8")
    with pytest.raises(ValueError, match="suffixes"):
        load_providers(bad)
