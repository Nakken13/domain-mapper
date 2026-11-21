"""Render the surface graph and findings as one offline HTML file.

Autoescape is always on: entity values and finding texts come from third-party
sources (DNS, certificates, archives) and must never be interpreted as markup.
"""

from __future__ import annotations

from collections.abc import Sequence
from importlib.resources import files

from jinja2 import Environment, PackageLoader, select_autoescape

from domain_mapper.graph.builder import SurfaceGraph
from domain_mapper.models import Finding, Severity
from domain_mapper.report.graphdata import graph_elements, to_script_json

_VENDOR = files("domain_mapper.report") / "vendor"

_ENV = Environment(
    loader=PackageLoader("domain_mapper.report", "templates"),
    autoescape=select_autoescape(default=True, default_for_string=True),
    trim_blocks=True,
    lstrip_blocks=True,
)


_RANK = {severity: rank for rank, severity in enumerate(Severity)}


def _worst_first(findings: Sequence[Finding]) -> list[Finding]:
    """Triage order: highest severity first; ties keep a stable, readable order."""
    return sorted(findings, key=lambda f: (-_RANK[f.severity], f.rule_id, f.evidence))


def render_report(graph: SurfaceGraph, findings: Sequence[Finding], *, domain: str) -> str:
    """Return the report as a single HTML string with no external resource."""
    elements = graph_elements(graph)
    return _ENV.get_template("report.html.j2").render(
        domain=domain,
        node_count=len(elements["nodes"]),
        edge_count=len(elements["edges"]),
        findings=_worst_first(findings),
        graph_json=to_script_json(elements),
        # Vendored, version-pinned and hash-checked by tests: trusted, rendered with |safe.
        cytoscape_js=(_VENDOR / "cytoscape.min.js").read_text(encoding="utf-8"),
        cytoscape_licence=(_VENDOR / "cytoscape.LICENSE").read_text(encoding="utf-8"),
    )
