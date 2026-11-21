import xml.etree.ElementTree as ET
from datetime import UTC, datetime

from surfacemap.evaluation.sources import (
    render_venn_svg,
    source_counts,
    subdomains_by_source,
    venn_regions,
)
from surfacemap.graph.builder import build_graph
from surfacemap.models import Domain, IPAddress, Observation, Provenance

T0 = datetime(2026, 1, 1, tzinfo=UTC)
APEX = "example.com"


def obs(source: str, *entities) -> Observation:
    return Observation(
        provenance=Provenance(source=source, retrieved_at=T0, query=APEX),
        entities=tuple(entities),
        relations=(),
    )


def dom(fqdn: str, in_scope: bool = True) -> Domain:
    return Domain(fqdn=fqdn, in_scope=in_scope)


def graph():
    return build_graph(
        [
            obs("crtsh", dom("example.com"), dom("a.example.com"), dom("b.example.com")),
            obs("wayback", dom("b.example.com"), dom("c.example.com")),
            obs("dns", dom("b.example.com"), IPAddress(address="192.0.2.1")),
            obs("crtsh", dom("evil.org", in_scope=False), dom("notexample.com")),
        ]
    )


def test_subdomains_by_source_keeps_only_real_in_scope_subdomains() -> None:
    result = subdomains_by_source(graph(), APEX)
    assert result == {
        "crtsh": frozenset({"a.example.com", "b.example.com"}),
        "wayback": frozenset({"b.example.com", "c.example.com"}),
        "dns": frozenset({"b.example.com"}),
    }


def test_apex_itself_and_lookalike_suffix_are_not_subdomains() -> None:
    result = subdomains_by_source(graph(), APEX)
    seen = set().union(*result.values())
    assert "example.com" not in seen
    assert "notexample.com" not in seen


def test_source_counts_are_sorted_by_count_then_name() -> None:
    counts = source_counts(subdomains_by_source(graph(), APEX))
    assert list(counts.items()) == [("crtsh", 2), ("wayback", 2), ("dns", 1)]


def test_venn_regions_are_exclusive_and_sum_to_the_union() -> None:
    sets = subdomains_by_source(graph(), APEX)
    regions = venn_regions(sets)
    assert regions == {
        frozenset({"crtsh"}): 1,  # a
        frozenset({"wayback"}): 1,  # c
        frozenset({"crtsh", "wayback", "dns"}): 1,  # b
    }
    assert sum(regions.values()) == len(set().union(*sets.values()))


def test_empty_graph_gives_empty_results() -> None:
    empty = build_graph([])
    assert subdomains_by_source(empty, APEX) == {}
    assert venn_regions({}) == {}


def svg_root(sets):
    return ET.fromstring(render_venn_svg(sets))  # noqa: S314 - our own output


def svg_texts(root) -> list[str]:
    return ["".join(t.itertext()) for t in root.iter("{http://www.w3.org/2000/svg}text")]


def test_venn_svg_is_well_formed_and_shows_region_counts() -> None:
    root = svg_root(subdomains_by_source(graph(), APEX))
    texts = svg_texts(root)
    assert len(list(root.iter("{http://www.w3.org/2000/svg}circle"))) == 3
    # exclusive regions: crtsh-only 1, wayback-only 1, all three 1
    assert texts.count("1") == 3


def test_venn_svg_keeps_only_top_three_sources_and_says_so() -> None:
    sets = {
        "a": frozenset({"1.example.com", "2.example.com", "3.example.com"}),
        "b": frozenset({"1.example.com", "2.example.com"}),
        "c": frozenset({"1.example.com"}),
        "d": frozenset({"9.example.com"}),
    }
    texts = svg_texts(svg_root(sets))
    assert any("not shown" in t and "d" in t for t in texts)
    assert len(list(svg_root(sets).iter("{http://www.w3.org/2000/svg}circle"))) == 3


def test_venn_svg_handles_one_and_two_sources() -> None:
    one = {"crtsh": frozenset({"a.example.com"})}
    two = {**one, "dns": frozenset({"a.example.com", "b.example.com"})}
    assert len(list(svg_root(one).iter("{http://www.w3.org/2000/svg}circle"))) == 1
    assert len(list(svg_root(two).iter("{http://www.w3.org/2000/svg}circle"))) == 2


def test_venn_svg_escapes_source_names() -> None:
    sets = {'<script>&"': frozenset({"a.example.com"})}
    svg = render_venn_svg(sets)
    assert "<script>" not in svg
    ET.fromstring(svg)  # noqa: S314 - our own output, still valid XML


def test_venn_svg_for_no_data_is_still_valid() -> None:
    root = svg_root({})
    assert len(list(root.iter("{http://www.w3.org/2000/svg}circle"))) == 0
    assert any("no subdomain" in t for t in svg_texts(root))
