"""Email-auth rule: missing/weak DMARC and SPF. Pure graph analysis, no network."""

from __future__ import annotations

from datetime import UTC, date, datetime

from risk_helpers import graph_of
from surfacemap.models import (
    DnsRecord,
    Domain,
    Entity,
    Finding,
    Relation,
    RelationType,
    Severity,
)
from surfacemap.risk import RuleContext
from surfacemap.risk.email_auth import EmailAuthRule

T0 = datetime(2026, 1, 1, tzinfo=UTC)
MAIL = Domain(fqdn="mail.example.net", in_scope=False)
GOOD_DMARC = "v=DMARC1; p=reject; rua=mailto:r@example.com"
GOOD_SPF = "v=spf1 include:_spf.example.net -all"


def root(
    *records: tuple[str, str], in_scope: bool = True, mx: bool = True
) -> list[Entity | Relation]:
    domain = Domain(
        fqdn="example.com",
        in_scope=in_scope,
        records=tuple(DnsRecord(type=t, value=v) for t, v in records),
    )
    items: list[Entity | Relation] = [domain]
    if mx:
        items += [MAIL, Relation.between(domain, RelationType.MX, MAIL)]
    return items


def check(*items: Entity | Relation) -> tuple[Finding, ...]:
    ctx = RuleContext(graph=graph_of(*items), today=date(2026, 11, 21))
    return tuple(EmailAuthRule().evaluate(ctx))


def titles(findings: tuple[Finding, ...]) -> set[str]:
    return {f.title for f in findings}


def test_healthy_domain_has_no_finding() -> None:
    assert check(*root(("DMARC", GOOD_DMARC), ("TXT", GOOD_SPF))) == ()


def test_absent_dmarc_is_medium() -> None:
    (finding,) = check(*root(("DMARC", ""), ("TXT", GOOD_SPF)))
    assert finding.rule_id == "email-auth"
    assert finding.severity is Severity.MEDIUM
    assert "DMARC" in finding.title
    assert finding.evidence == ("domain:example.com",)


def test_unknown_dmarc_is_not_reported() -> None:
    # No DMARC record at all = lookup never ran or failed: unknown, not absent.
    assert check(*root(("TXT", GOOD_SPF))) == ()


def test_invalid_dmarc_is_reported() -> None:
    findings = check(*root(("DMARC", "v=DMARC1; p=bogus"), ("TXT", GOOD_SPF)))
    assert any("invalid" in f.title.lower() for f in findings)


def test_monitoring_only_policy_is_medium() -> None:
    (finding,) = check(*root(("DMARC", "v=DMARC1; p=none; rua=mailto:r@x.com"), ("TXT", GOOD_SPF)))
    assert finding.severity is Severity.MEDIUM
    assert "p=none" in finding.title


def test_partial_percentage_is_low() -> None:
    (finding,) = check(*root(("DMARC", "v=DMARC1; p=reject; pct=20"), ("TXT", GOOD_SPF)))
    assert finding.severity is Severity.LOW
    assert "20" in finding.title


def test_weaker_subdomain_policy_is_low() -> None:
    (finding,) = check(*root(("DMARC", "v=DMARC1; p=reject; sp=none"), ("TXT", GOOD_SPF)))
    assert finding.severity is Severity.LOW
    assert "sp=none" in finding.title


def test_missing_spf_on_mail_domain_is_medium() -> None:
    (finding,) = check(*root(("DMARC", GOOD_DMARC), ("TXT", "google-site-verification=abc")))
    assert finding.severity is Severity.MEDIUM
    assert "SPF" in finding.title


def test_missing_spf_without_mx_is_not_reported() -> None:
    assert check(*root(("DMARC", GOOD_DMARC), mx=False)) == ()


def test_plus_all_is_high() -> None:
    (finding,) = check(*root(("DMARC", GOOD_DMARC), ("TXT", "v=spf1 +all")))
    assert finding.severity is Severity.HIGH


def test_neutral_all_and_no_all_are_medium() -> None:
    for spf in ("v=spf1 ip4:192.0.2.1 ?all", "v=spf1 ip4:192.0.2.1"):
        (finding,) = check(*root(("DMARC", GOOD_DMARC), ("TXT", spf)))
        assert finding.severity is Severity.MEDIUM, spf


def test_redirect_without_all_is_fine() -> None:
    assert check(*root(("DMARC", GOOD_DMARC), ("TXT", "v=spf1 redirect=_spf.example.net"))) == ()


def test_softfail_ok_when_dmarc_enforced_low_otherwise() -> None:
    soft = ("TXT", "v=spf1 ip4:192.0.2.1 ~all")
    assert check(*root(("DMARC", GOOD_DMARC), soft)) == ()
    # pct=50 means DMARC is not fully enforced, so softfail is no longer backed up.
    findings = check(*root(("DMARC", "v=DMARC1; p=reject; pct=50"), soft))
    (softfail,) = [f for f in findings if "softfail" in f.title.lower()]
    assert softfail.severity is Severity.LOW


def test_two_spf_records_is_medium() -> None:
    findings = check(*root(("DMARC", GOOD_DMARC), ("TXT", GOOD_SPF), ("TXT", "v=spf1 -all")))
    assert any("several" in f.title.lower() for f in findings)


def test_too_many_lookups_is_medium() -> None:
    spf = "v=spf1 " + " ".join(f"include:s{i}.example.net" for i in range(11)) + " -all"
    (finding,) = check(*root(("DMARC", GOOD_DMARC), ("TXT", spf)))
    assert finding.severity is Severity.MEDIUM
    assert "lookup" in finding.title.lower()


def test_ptr_mechanism_is_low() -> None:
    (finding,) = check(*root(("DMARC", GOOD_DMARC), ("TXT", "v=spf1 ptr -all")))
    assert finding.severity is Severity.LOW


def test_out_of_scope_domain_is_ignored() -> None:
    assert check(*root(("DMARC", ""), in_scope=False)) == ()


def test_missing_spf_stays_silent_without_a_recorded_dmarc_state() -> None:
    # No DMARC record at all: the mail enrichment may not have run, so do not guess.
    assert check(*root(("TXT", "google-site-verification=abc"))) == ()
