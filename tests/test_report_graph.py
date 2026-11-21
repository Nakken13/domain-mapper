"""The interactive graph: data for Cytoscape.js and its inlining in the report."""

from __future__ import annotations

import json
import re

from risk_helpers import graph_of
from surfacemap.models import Domain, IPAddress, Relation, RelationType
from surfacemap.report import render_report
from surfacemap.report.graphdata import graph_elements, to_script_json


def _graph():
    return graph_of(
        Domain(fqdn="example.com", in_scope=True),
        Domain(fqdn="app.example.com", in_scope=True),
        Relation(
            source="domain:example.com",
            type=RelationType.HAS_SUBDOMAIN,
            target="domain:app.example.com",
        ),
        # Endpoint no observation described: must still be drawn.
        Relation(
            source="domain:app.example.com",
            type=RelationType.CNAME_TO,
            target="domain:out.other.net",
        ),
    )


def test_elements_list_every_node_and_edge_with_its_kind() -> None:
    elements = graph_elements(_graph())
    nodes = {n["id"]: n for n in elements["nodes"]}
    assert set(nodes) == {"domain:example.com", "domain:app.example.com", "domain:out.other.net"}
    assert nodes["domain:app.example.com"]["kind"] == "domain"
    assert nodes["domain:app.example.com"]["label"] == "app.example.com"
    assert {(e["source"], e["type"], e["target"]) for e in elements["edges"]} == {
        ("domain:example.com", "HAS_SUBDOMAIN", "domain:app.example.com"),
        ("domain:app.example.com", "CNAME_TO", "domain:out.other.net"),
    }


def test_elements_flag_nodes_outside_the_scope() -> None:
    nodes = {n["id"]: n for n in graph_elements(_graph())["nodes"]}
    assert nodes["domain:app.example.com"]["in_scope"] is True
    assert nodes["domain:out.other.net"]["in_scope"] is False


def test_every_entity_kind_has_a_distinct_colour() -> None:
    """A kind without a colour would silently render grey (it happened once)."""
    from surfacemap.graph._common import _BY_PREFIX
    from surfacemap.report.graphdata import KIND_COLORS

    kinds = {kind for kind, _label in _BY_PREFIX.values()}
    assert set(KIND_COLORS) == kinds
    assert len(set(KIND_COLORS.values())) == len(kinds)


def test_elements_carry_the_colour_of_their_kind() -> None:
    from surfacemap.report.graphdata import KIND_COLORS

    nodes = {n["id"]: n for n in graph_elements(_graph())["nodes"]}
    assert nodes["domain:app.example.com"]["color"] == KIND_COLORS["domain"]


def test_script_json_cannot_close_the_script_block() -> None:
    payload = to_script_json({"label": "</script><img src=x onerror=alert(1)>", "x": "<!--"})
    assert "</" not in payload
    assert "<!--" not in payload
    # Still valid JSON that round-trips to the original text.
    assert json.loads(payload)["label"] == "</script><img src=x onerror=alert(1)>"


def test_report_inlines_cytoscape_and_the_graph_data() -> None:
    html = render_report(_graph(), [], domain="example.com")
    assert "cytoscape" in html.lower()
    assert "domain:out.other.net" in html
    assert re.search(r'id="cy"', html)


def test_report_keeps_the_cytoscape_licence_notice() -> None:
    html = render_report(_graph(), [], domain="example.com")
    assert "The Cytoscape Consortium" in html
    assert "Permission is hereby granted" in html


def test_report_still_loads_nothing_from_the_network_with_the_graph() -> None:
    html = render_report(_graph(), [], domain="example.com")
    assert not re.search(r"""(?:src|href)\s*=\s*["']?(?:https?:)?//""", html, re.IGNORECASE)


def test_vendored_cytoscape_matches_the_pinned_hash() -> None:
    """Supply-chain guard: the inlined library is exactly cytoscape 3.33.1 from npm."""
    import hashlib
    from importlib.resources import files

    blob = (files("surfacemap.report") / "vendor" / "cytoscape.min.js").read_bytes()
    assert (
        hashlib.sha256(blob).hexdigest()
        == "f55947f3daa3bae53209d4b885c195c157f595c225e508a6b382598d9452d6e2"
    )


def test_report_counts_every_drawn_node() -> None:
    html = render_report(_graph(), [], domain="example.com")
    assert "3 nodes, 2 relations" in html


def test_only_domains_can_be_flagged_out_of_scope() -> None:
    graph = graph_of(
        Domain(fqdn="example.com", in_scope=True),
        IPAddress(address="192.0.2.1"),
        Relation(
            source="domain:example.com",
            type=RelationType.RESOLVES_TO,
            target="ip:192.0.2.1",
        ),
        Relation(
            source="domain:example.com",
            type=RelationType.CNAME_TO,
            target="domain:out.other.net",
        ),
    )
    nodes = {n["id"]: n for n in graph_elements(graph)["nodes"]}
    assert nodes["domain:out.other.net"]["out_of_scope"] is True
    assert nodes["domain:example.com"]["out_of_scope"] is False
    # An IP has no scope: drawing it as "outside the authorized scope" would mislead.
    assert nodes["ip:192.0.2.1"]["out_of_scope"] is False
