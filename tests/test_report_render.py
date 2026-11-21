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
