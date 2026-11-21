"""Build the FICTIONAL demo report used for the README GIF.

Not a scan: every name is under example.com (RFC 2606) and every address in a documentation
range (RFC 5737), so nothing here describes a real system. The graph shows what the report does
with shared infrastructure (hubs, articulation points) and which risk rules fire.

Traffic: none.

    python media/make_demo_report.py media/demo-report.html
"""

from __future__ import annotations

import sys
from datetime import UTC, date, datetime
from hashlib import sha256
from pathlib import Path

from surfacemap.cli import _default_rules
from surfacemap.graph.builder import build_graph
from surfacemap.models import (
    ASN,
    Certificate,
    Domain,
    IPAddress,
    Observation,
    Provenance,
    Relation,
    RelationType,
)
from surfacemap.report import render_report
from surfacemap.risk.engine import RuleContext, run_rules

ROOT = "example.com"
TODAY = date(2026, 11, 21)
WHEN = datetime(2026, 11, 21, tzinfo=UTC)


def _obs(source: str, query: str, *items: object) -> Observation:
    ents = tuple(i for i in items if not isinstance(i, Relation))
    rels = tuple(i for i in items if isinstance(i, Relation))
    return Observation(
        provenance=Provenance(source=source, retrieved_at=WHEN, query=query),
        entities=ents,  # type: ignore[arg-type]
        relations=rels,
    )


def build_demo() -> list[Observation]:
    apex = Domain(fqdn=ROOT, in_scope=True)
    hosts = [
        Domain(fqdn=f"{n}.{ROOT}", in_scope=True) for n in ("www", "api", "app", "staging", "mail")
    ]
    dangling = Domain(fqdn=f"old.{ROOT}", in_scope=True)
    cdn = Domain(fqdn="shop.cdn-provider.example", in_scope=False)
    edge = IPAddress(address="192.0.2.10")
    mail = IPAddress(address="198.51.100.25")
    asn = ASN(number=64500, holder="Example Hosting", country="FR")
    cert = Certificate(
        sha256=sha256(b"surfacemap-demo").hexdigest(),
        issuer="Example CA",
        not_before=datetime(2026, 1, 1, tzinfo=UTC),
        not_after=datetime(2026, 12, 1, tzinfo=UTC),
        sans=tuple(h.fqdn for h in hosts[:4]),
    )
    rel = Relation.between
    obs = [
        _obs(
            "crtsh",
            f"%.{ROOT}",
            apex,
            *hosts,
            dangling,
            cert,
            *[rel(apex, RelationType.HAS_SUBDOMAIN, h) for h in (*hosts, dangling)],
            *[rel(h, RelationType.SECURED_BY, cert) for h in hosts[:4]],
        ),
        _obs(
            "dns_records",
            ROOT,
            edge,
            mail,
            cdn,
            *[rel(h, RelationType.RESOLVES_TO, edge) for h in hosts[:4]],
            rel(apex, RelationType.RESOLVES_TO, edge),
            rel(hosts[4], RelationType.RESOLVES_TO, mail),
            rel(apex, RelationType.MX, hosts[4]),
            rel(dangling, RelationType.CNAME_TO, cdn),
        ),
        _obs(
            "asn",
            "192.0.2.10",
            asn,
            rel(edge, RelationType.ANNOUNCED_BY, asn),
            rel(mail, RelationType.ANNOUNCED_BY, asn),
        ),
    ]
    return obs


def main(out: Path) -> None:
    graph = build_graph(build_demo())
    findings = run_rules(RuleContext(graph=graph, today=TODAY), _default_rules())
    out.write_text(render_report(graph, findings, domain=ROOT), encoding="utf-8")
    print(f"{len(graph.nodes)} nodes, {len(findings)} findings -> {out}")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
