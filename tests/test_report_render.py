"""The HTML report is one self-contained, escaped file."""

from __future__ import annotations

import re

from risk_helpers import graph_of
from surfacemap.models import Domain, Finding, Severity
from surfacemap.report import render_report


def _finding(**overrides: object) -> Finding:
    data: dict[str, object] = {
        "rule_id": "dangling-cname",
        "severity": Severity.HIGH,
        "title": "Dangling CNAME",
        "rationale": "The target no longer exists.",
        "evidence": ("domain:app.example.com",),
        "remediation": "Remove the record.",
    }
    data.update(overrides)
    return Finding(**data)  # type: ignore[arg-type]


def _html(*findings: Finding) -> str:
    graph = graph_of(Domain(fqdn="app.example.com", in_scope=True))
    return render_report(graph, list(findings), domain="example.com")


def test_report_is_a_complete_html_document_naming_the_target() -> None:
    html = _html()
    assert html.lstrip().lower().startswith("<!doctype html>")
    assert "example.com" in html


def test_report_loads_nothing_from_the_network() -> None:
    html = _html(_finding())
    # No script/link/img may point at a remote origin: the file must work offline.
    assert not re.search(r"""(?:src|href)\s*=\s*["']?(?:https?:)?//""", html, re.IGNORECASE)


def test_report_escapes_untrusted_finding_text() -> None:
    html = _html(_finding(title="<script>alert(1)</script>"))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_findings_are_listed_worst_severity_first() -> None:
    html = _html(
        _finding(severity=Severity.LOW, title="Low one"),
        _finding(severity=Severity.CRITICAL, title="Critical one"),
        _finding(severity=Severity.MEDIUM, title="Medium one"),
    )
    positions = [html.index(t) for t in ("Critical one", "Medium one", "Low one")]
    assert positions == sorted(positions)


def test_findings_table_shows_severity_as_text_evidence_and_fix() -> None:
    html = _html(_finding(remediation="Remove the record."))
    assert "<table" in html
    assert ">critical<" in _html(_finding(severity=Severity.CRITICAL)).lower()
    assert "domain:app.example.com" in html
    assert "Remove the record." in html


def test_report_without_findings_says_so_instead_of_an_empty_table() -> None:
    html = _html()
    assert "No findings" in html
    assert "<table" not in html


def test_every_node_kind_has_its_own_colour_in_the_graph_script() -> None:
    """The palette is keyed by `kind_of` values; a missing key silently turns nodes grey."""
    from surfacemap.graph._common import _BY_PREFIX

    palette = re.search(r"var colors = \{(.*?)\};", _html(), re.DOTALL)
    assert palette is not None
    keys = set(re.findall(r"(\w+):\s*\"#", palette.group(1)))
    kinds = {kind for kind, _label in _BY_PREFIX.values()}
    assert kinds <= keys, f"no colour for: {sorted(kinds - keys)}"
