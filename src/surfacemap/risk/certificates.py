"""Certificate rule: an in-scope name whose latest certificate is expired or about to expire.

Traffic: none. Reads `SECURED_BY` edges and certificate validity dates from Certificate
Transparency data already in the graph, against the pinned `ctx.today`.

A name is judged on its *latest* certificate (largest `not_after`): CT logs keep expired
certificates forever, and a renewal is issued before the old one ends, so flagging each
certificate on its own would be mostly noise. CT shows what was issued, not what the server
presents, hence the wording "no valid certificate seen" rather than "site is broken".
"""

from __future__ import annotations

from collections.abc import Iterable

from surfacemap.models import Certificate, Domain, Finding, RelationType, Severity
from surfacemap.risk.engine import RuleContext

SOON_DAYS = 30
"""A certificate ending within this many days is reported (MEDIUM)."""
URGENT_DAYS = 7
"""... and HIGH within this many."""


class CertificateRule:
    id = "certificates"

    def evaluate(self, ctx: RuleContext) -> Iterable[Finding]:
        latest: dict[str, Certificate] = {}
        for source, rel_type, target in ctx.graph.edges:
            if rel_type is not RelationType.SECURED_BY:
                continue
            host, cert_node = ctx.graph.nodes.get(source), ctx.graph.nodes.get(target)
            if host is None or cert_node is None:
                continue
            domain, cert = host.entity, cert_node.entity
            if not (isinstance(domain, Domain) and isinstance(cert, Certificate)):
                continue
            if not domain.in_scope:
                continue
            best = latest.get(domain.id)
            if best is None or cert.not_after > best.not_after:
                latest[domain.id] = cert

        for domain_id in sorted(latest):
            cert = latest[domain_id]
            fqdn = domain_id.removeprefix("domain:")
            days_left = (cert.not_after.date() - ctx.today).days
            evidence = (domain_id, cert.id)
            if days_left < 0:
                yield Finding(
                    rule_id=self.id,
                    severity=Severity.MEDIUM,
                    title=f"Expired certificate on {fqdn}",
                    rationale=(
                        f"The newest certificate seen in Certificate Transparency logs for "
                        f"{fqdn} expired {-days_left} day(s) ago ({cert.not_after:%Y-%m-%d}); "
                        "no valid one has been logged since. Browsers reject expired "
                        "certificates, and a forgotten host is a takeover candidate."
                    ),
                    evidence=evidence,
                    remediation="Renew the certificate, or decommission the name and its DNS.",
                )
            elif days_left <= SOON_DAYS:
                yield Finding(
                    rule_id=self.id,
                    severity=Severity.HIGH if days_left <= URGENT_DAYS else Severity.MEDIUM,
                    title=f"Certificate on {fqdn} expires in {days_left} day(s)",
                    rationale=(
                        f"The newest certificate seen for {fqdn} ends on "
                        f"{cert.not_after:%Y-%m-%d} and no renewal has been logged yet."
                    ),
                    evidence=evidence,
                    remediation="Renew now and check that automatic renewal works.",
                )
