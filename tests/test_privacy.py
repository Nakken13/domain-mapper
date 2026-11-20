from datetime import UTC, datetime

import pytest

from surfacemap.models import (
    Certificate,
    DnsRecord,
    Domain,
    Observation,
    Provenance,
    Relation,
    Technology,
)
from surfacemap.privacy import (
    drop_email_sans,
    redact_observation,
    redact_registration,
    scrub_emails,
    strip_query,
)

NOW = datetime(2026, 11, 20, tzinfo=UTC)

RDAP = {
    "ldhName": "example.com",
    "nameservers": [{"ldhName": "ns1.example.net"}],
    "status": ["active"],
    "entities": [
        {
            "roles": ["registrant"],
            "vcardArray": ["vcard", [["fn", {}, "text", "Jane Doe"]]],
        }
    ],
    "events": [{"eventAction": "registration", "eventDate": "2001-01-01T00:00:00Z"}],
    "remarks": [{"description": ["Contact jane.doe@example.com for abuse"]}],
}

WHOIS = {
    "domain_name": "example.com",
    "registrar": "Example Registrar SAS",
    "registrant_name": "Jane Doe",
    "Admin Email": "jane@example.com",
    "tech_contact": {"phone": "+33 1 23 45 67 89"},
    "name": "Jane Doe",
    "emails": ["jane@example.com"],
    "creation_date": "2001-01-01",
}


def test_rdap_contacts_are_dropped_and_technical_fields_kept() -> None:
    redacted = redact_registration(RDAP)
    assert "entities" not in redacted
    assert redacted["nameservers"] == [{"ldhName": "ns1.example.net"}]
    assert redacted["events"] == RDAP["events"]
    assert "jane.doe@example.com" not in repr(redacted)


def test_whois_contact_keys_are_dropped() -> None:
    redacted = redact_registration(WHOIS)
    assert redacted == {
        "domain_name": "example.com",
        "registrar": "Example Registrar SAS",
        "creation_date": "2001-01-01",
    }


def test_redact_registration_does_not_mutate_input() -> None:
    before = repr(RDAP)
    redact_registration(RDAP)
    assert repr(RDAP) == before


def test_scrub_emails_replaces_addresses() -> None:
    assert scrub_emails("v=DMARC1; rua=mailto:jane@example.com") == (
        "v=DMARC1; rua=mailto:[redacted-email]"
    )
    assert scrub_emails("no address here") == "no address here"


def test_drop_email_sans() -> None:
    assert drop_email_sans(("example.com", "jane@example.com", "*.example.com")) == (
        "example.com",
        "*.example.com",
    )


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://example.com/login?token=abc#top", "https://example.com/login"),
        ("https://example.com/", "https://example.com/"),
        ("/reset?email=jane@example.com", "/reset"),
    ],
)
def test_strip_query(url: str, expected: str) -> None:
    assert strip_query(url) == expected


def test_redact_observation_cleans_every_free_text_field() -> None:
    obs = Observation(
        provenance=Provenance(source="dns", retrieved_at=NOW, query="mail jane@example.com"),
        entities=[
            Domain(
                fqdn="example.com",
                in_scope=True,
                records=[DnsRecord(type="TXT", value="rua=mailto:jane@example.com")],
            ),
            Certificate(
                sha256="a" * 64,
                issuer="R3",
                not_before=NOW,
                not_after=NOW,
                sans=["example.com", "jane@example.com"],
            ),
            Technology(name="nginx", category="web-server", evidence="admin: bob@example.com"),
        ],
        relations=[Relation(source="domain:example.com", type="USES_TECH", target="tech:nginx")],
    )
    redacted = redact_observation(obs)
    assert "@example.com" not in redacted.model_dump_json()
    domain, cert, tech = redacted.entities
    assert isinstance(cert, Certificate)
    assert cert.sans == ("example.com",)
    assert isinstance(domain, Domain)
    assert domain.records[0].value == "rua=mailto:[redacted-email]"
    assert isinstance(tech, Technology)
    assert tech.evidence == "admin: [redacted-email]"
    assert redacted.relations == obs.relations
    assert Observation.model_validate(redacted.model_dump()) == redacted


def test_redact_observation_leaves_clean_data_unchanged() -> None:
    obs = Observation(
        provenance=Provenance(source="dns", retrieved_at=NOW, query="example.com"),
        entities=[Domain(fqdn="example.com", in_scope=True)],
    )
    assert redact_observation(obs) == obs
