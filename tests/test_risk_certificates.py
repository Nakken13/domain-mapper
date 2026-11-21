"""Certificate rule: expired / soon-expiring. Judged on a domain's latest cert, pinned date."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

from risk_helpers import graph_of
from surfacemap.models import (
    Certificate,
    Domain,
    Entity,
    Finding,
    Relation,
    RelationType,
    Severity,
)
from surfacemap.risk import RuleContext
from surfacemap.risk.certificates import SOON_DAYS, CertificateRule

TODAY = date(2026, 11, 21)
NOW = datetime(2026, 11, 21, 12, tzinfo=UTC)
WWW = Domain(fqdn="www.example.com", in_scope=True)


def cert(n: int, *, ends_in_days: int, host: Domain = WWW) -> tuple[Certificate, Relation]:
    c = Certificate(
        sha256=f"{n:064x}",
        issuer="Example CA",
        not_before=NOW - timedelta(days=400),
        not_after=NOW + timedelta(days=ends_in_days),
    )
    return c, Relation.between(host, RelationType.SECURED_BY, c)


def check(*items: Entity | Relation) -> tuple[Finding, ...]:
    ctx = RuleContext(graph=graph_of(*items), today=TODAY)
    return tuple(CertificateRule().evaluate(ctx))


def test_valid_for_long_is_fine() -> None:
    assert check(WWW, *cert(1, ends_in_days=200)) == ()


def test_expired_only_cert_is_medium() -> None:
    (finding,) = check(WWW, *cert(1, ends_in_days=-5))
    assert finding.rule_id == "certificates"
    assert finding.severity is Severity.MEDIUM
    assert "expired" in finding.title.lower()
    assert finding.evidence[0] == WWW.id
    assert len(finding.evidence) == 2


def test_expiring_within_a_week_is_high() -> None:
    (finding,) = check(WWW, *cert(1, ends_in_days=3))
    assert finding.severity is Severity.HIGH
    assert "3 day" in finding.title


def test_expiring_within_the_window_is_medium() -> None:
    (finding,) = check(WWW, *cert(1, ends_in_days=SOON_DAYS))
    assert finding.severity is Severity.MEDIUM


def test_just_outside_window_is_fine() -> None:
    assert check(WWW, *cert(1, ends_in_days=SOON_DAYS + 2)) == ()


def test_renewed_cert_hides_the_old_one() -> None:
    old, old_rel = cert(1, ends_in_days=-30)
    new, new_rel = cert(2, ends_in_days=80)
    assert check(WWW, old, old_rel, new, new_rel) == ()


def test_out_of_scope_domain_ignored() -> None:
    foreign = Domain(fqdn="cdn.other.org", in_scope=False)
    assert check(foreign, *cert(1, ends_in_days=-5, host=foreign)) == ()


def test_expiry_day_itself_counts_as_expiring_not_expired() -> None:
    (finding,) = check(WWW, *cert(1, ends_in_days=0))
    assert finding.severity is Severity.HIGH


def test_expiring_today_is_worded_today() -> None:
    (finding,) = check(WWW, *cert(1, ends_in_days=0))
    assert "today" in finding.title


def test_tie_on_not_after_picks_the_same_cert_whatever_the_order() -> None:
    first, first_rel = cert(1, ends_in_days=3)
    second, second_rel = cert(2, ends_in_days=3)
    a = check(WWW, first, first_rel, second, second_rel)
    b = check(WWW, second, second_rel, first, first_rel)
    assert a == b
