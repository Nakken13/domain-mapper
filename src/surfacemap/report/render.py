"""Render the surface graph and findings as one offline HTML file.

Autoescape is always on: entity values and finding texts come from third-party
sources (DNS, certificates, archives) and must never be interpreted as markup.
"""

from __future__ import annotations

from collections.abc import Sequence

from jinja2 import Environment, PackageLoader, select_autoescape

from surfacemap.graph.builder import SurfaceGraph
from surfacemap.models import Finding

_ENV = Environment(
    loader=PackageLoader("surfacemap.report", "templates"),
    autoescape=select_autoescape(default=True, default_for_string=True),
    trim_blocks=True,
    lstrip_blocks=True,
)


def render_report(graph: SurfaceGraph, findings: Sequence[Finding], *, domain: str) -> str:
    """Return the report as a single HTML string with no external resource."""
    return _ENV.get_template("report.html.j2").render(
        domain=domain,
        node_count=len(graph.nodes),
        edge_count=len(graph.edges),
        findings=list(findings),
    )
