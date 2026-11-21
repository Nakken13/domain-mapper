"""Render the surface graph and findings as one offline HTML file.

Autoescape is always on: entity values and finding texts come from third-party
sources (DNS, certificates, archives) and must never be interpreted as markup.
"""

from __future__ import annotations

from collections.abc import Sequence
from importlib.resources import files

from jinja2 import Environment, PackageLoader, select_autoescape

from surfacemap.graph.builder import SurfaceGraph
from surfacemap.models import Finding
from surfacemap.report.graphdata import graph_elements, to_script_json

_VENDOR = files("surfacemap.report") / "vendor"

_ENV = Environment(
    loader=PackageLoader("surfacemap.report", "templates"),
    autoescape=select_autoescape(default=True, default_for_string=True),
    trim_blocks=True,
    lstrip_blocks=True,
)


def render_report(graph: SurfaceGraph, findings: Sequence[Finding], *, domain: str) -> str:
    """Return the report as a single HTML string with no external resource."""
    elements = graph_elements(graph)
    return _ENV.get_template("report.html.j2").render(
        domain=domain,
        node_count=len(elements["nodes"]),
        edge_count=len(elements["edges"]),
        findings=list(findings),
        graph_json=to_script_json(elements),
        # Vendored, version-pinned and hash-checked by tests: trusted, rendered with |safe.
        cytoscape_js=(_VENDOR / "cytoscape.min.js").read_text(encoding="utf-8"),
        cytoscape_licence=(_VENDOR / "cytoscape.LICENSE").read_text(encoding="utf-8"),
    )
