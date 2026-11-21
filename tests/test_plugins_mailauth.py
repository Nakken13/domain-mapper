from __future__ import annotations

import pytest

from surfacemap.models import DnsRecord, Domain
from surfacemap.plugins.mailauth import (
    DmarcPolicy,
    SpfPolicy,
    dmarc_of,
    parse_dmarc,
    parse_spf,
    spf_of,
)


def test_parses_a_strict_spf_record() -> None:
    spf = parse_spf("v=spf1 ip4:192.0.2.0/24 include:_spf.example.net mx -all")
    assert spf == SpfPolicy(
        all_qualifier="-",
        includes=("_spf.example.net",),
        redirect=None,
        dns_lookups=2,
        uses_ptr=False,
    )
    assert spf.is_strict


@pytest.mark.parametrize(
    ("record", "qualifier", "strict"),
    [
        ("v=spf1 ~all", "~", False),
        ("v=spf1 ?all", "?", False),
        ("v=spf1 +all", "+", False),
        ("v=spf1 all", "+", False),
        ("V=SPF1 -ALL", "-", True),
        ("v=spf1 include:a.example.net", None, False),
    ],
)
def test_reads_the_all_qualifier(record: str, qualifier: str | None, strict: bool) -> None:
    spf = parse_spf(record)
    assert spf is not None
    assert spf.all_qualifier == qualifier
    assert spf.is_strict is strict


def test_counts_every_mechanism_that_costs_a_dns_lookup() -> None:
    record = "v=spf1 a mx:mail.example.com ptr exists:%{i}.x.example include:a.example " + (
        "include:b.example redirect=c.example"
    )
    spf = parse_spf(record)
    assert spf is not None
    assert spf.dns_lookups == 7
    assert spf.uses_ptr
    assert spf.redirect == "c.example"
    assert spf.includes == ("a.example", "b.example")
    assert not parse_spf("v=spf1 " + "include:x.example " * 11 + "-all").within_lookup_limit  # type: ignore[union-attr]


@pytest.mark.parametrize("record", ["", "v=spf10 -all", "spf1 -all", "v=DMARC1; p=none"])
def test_rejects_what_is_not_spf(record: str) -> None:
    assert parse_spf(record) is None


def test_finds_spf_records_among_txt_records() -> None:
    domain = Domain(
        fqdn="example.com",
        in_scope=True,
        records=(
            DnsRecord(type="TXT", value="google-site-verification=abc"),
            DnsRecord(type="TXT", value="v=spf1 -all"),
            DnsRecord(type="DMARC", value="v=spf1 ~all"),
        ),
    )
    assert [p.all_qualifier for p in spf_of(domain)] == ["-"]


def test_parses_a_dmarc_policy_without_keeping_report_addresses() -> None:
    policy = parse_dmarc(
        "v=DMARC1; p=reject; sp=quarantine; pct=50; rua=mailto:d@example.com; adkim=s"
    )
    assert policy == DmarcPolicy(
        policy="reject",
        subdomain_policy="quarantine",
        percent=50,
        reports=True,
        strict_dkim_alignment=True,
        strict_spf_alignment=False,
    )
    assert "example.com" not in repr(policy)
    assert not policy.is_enforced  # 50 % only


@pytest.mark.parametrize(
    ("record", "enforced"),
    [
        ("v=DMARC1; p=none", False),
        ("v=DMARC1; p=quarantine", True),
        ("v=DMARC1;p=REJECT;pct=100", True),
    ],
)
def test_enforcement(record: str, enforced: bool) -> None:
    policy = parse_dmarc(record)
    assert policy is not None
    assert policy.is_enforced is enforced
    assert policy.subdomain_policy == policy.policy  # sp defaults to p
    assert policy.reports is False


@pytest.mark.parametrize(
    "record",
    [
        "",
        "v=DMARC1",
        "v=DMARC1; p=maybe",
        "v=DMARC1; p=none; pct=abc",
        "v=DMARC1; p=none; pct=101",
        "v=DMARC1; p=none; sp=bad",
        "p=none; v=DMARC1",
        "v=spf1 -all",
    ],
)
def test_rejects_invalid_dmarc(record: str) -> None:
    assert parse_dmarc(record) is None


def test_reads_dmarc_from_a_domain() -> None:
    def with_records(*records: DnsRecord) -> Domain:
        return Domain(fqdn="example.com", in_scope=True, records=records)

    found = dmarc_of(with_records(DnsRecord(type="DMARC", value="v=DMARC1; p=none")))
    assert found is not None
    assert found.policy == "none"
    # Confirmed absence vs. never looked up / lookup failed.
    assert dmarc_of(with_records(DnsRecord(type="DMARC", value=""))) == "absent"
    assert dmarc_of(with_records()) is None
    # More than one DMARC record: RFC 7489 section 6.6.3 discards them all.
    two = (
        DnsRecord(type="DMARC", value="v=DMARC1; p=none"),
        DnsRecord(type="DMARC", value="v=DMARC1; p=reject"),
    )
    assert dmarc_of(with_records(*two)) == "invalid"
    assert dmarc_of(with_records(DnsRecord(type="DMARC", value="v=DMARC1; p=bad"))) == "invalid"
