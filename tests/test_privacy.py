from datetime import UTC, datetime

import pytest

from domain_mapper.models import (
    ASN,
    ArchivedURL,
    Certificate,
    DnsRecord,
    Domain,
    Observation,
    Provenance,
    Relation,
    Technology,
)
from domain_mapper.privacy import (
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
    "org": "Jane Doe",
    "state": "Paris",
    "zipcode": "75001",
    "country": "FR",
    "phone_number": "+33 1 23 45 67 89",
    "text": "Registrant Name: Jane Doe\nRegistrant Phone: +1.555",
    "creation_date": "2001-01-01",
    "name_servers": ["ns1.example.net"],
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
        "name_servers": ["ns1.example.net"],
    }


def test_rdap_free_text_and_unknown_keys_are_dropped() -> None:
    redacted = redact_registration(RDAP)
    assert "remarks" not in redacted
    assert set(redacted) == {"ldhName", "nameservers", "status", "events"}


def test_rdap_nested_objects_keep_only_allowed_keys() -> None:
    payload = {
        "nameservers": [{"ldhName": "ns1.example.net", "entities": [{"fn": "Jane"}]}],
        "events": [{"eventAction": "expiration", "eventDate": "2030-01-01", "eventActor": "Jane"}],
    }
    assert redact_registration(payload) == {
        "nameservers": [{"ldhName": "ns1.example.net"}],
        "events": [{"eventAction": "expiration", "eventDate": "2030-01-01"}],
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


@pytest.mark.parametrize(
    "text",
    [
        "josé@example.com",
        "jane@exämple.fr",
        "用户@例子.中国",
        "jane@example.xn--p1ai",
        "/unsubscribe/jane%40example.com",
        "JANE@EXAMPLE.COM",
    ],
)
def test_scrub_emails_handles_unicode_uppercase_and_percent_encoding(text: str) -> None:
    scrubbed = scrub_emails(text)
    assert "@" not in scrubbed
    assert "%40" not in scrubbed
    assert "example" not in scrubbed.replace("[redacted-email]", "")


def test_scrub_emails_keeps_the_surrounding_path() -> None:
    assert scrub_emails("/users/jane@example.com/profile") == "/users/[redacted-email]/profile"


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
    assert tech.evidence == ("admin: [redacted-email]",)
    assert redacted.relations == obs.relations
    assert Observation.model_validate(redacted.model_dump()) == redacted


def test_redact_observation_leaves_clean_data_unchanged() -> None:
    obs = Observation(
        provenance=Provenance(source="dns", retrieved_at=NOW, query="example.com"),
        entities=[Domain(fqdn="example.com", in_scope=True)],
    )
    assert redact_observation(obs) == obs


def test_redact_observation_scrubs_every_string_field_and_relation_endpoints() -> None:
    url = ArchivedURL(
        host="example.com", path="/users/jane@example.com/profile", first_seen=NOW, last_seen=NOW
    )
    obs = Observation(
        provenance=Provenance(source="wayback", retrieved_at=NOW, query="example.com"),
        entities=[
            url,
            Certificate(
                sha256="b" * 64,
                issuer="CN=Jane Doe, emailAddress=jane@example.com",
                not_before=NOW,
                not_after=NOW,
            ),
            ASN(number=64496, holder="jane@example.com"),
            Technology(name="x jane@example.com", category="cat bob@example.com"),
        ],
        relations=[Relation(source="domain:example.com", type="ARCHIVED_AT", target=url.id)],
    )
    redacted = redact_observation(obs)
    dumped = redacted.model_dump_json() + repr([e.id for e in redacted.entities])
    assert "@" not in dumped.replace("[redacted-email]", "")
    assert redacted.relations[0].target == "url:example.com/users/[redacted-email]/profile"
    assert redacted.entities[0].id == redacted.relations[0].target


def test_redact_observation_revalidates_constructed_models() -> None:
    cert = Certificate.model_construct(
        kind="certificate",
        sha256="c" * 64,
        issuer="R3",
        not_before=NOW,
        not_after=NOW,
        sans=("jane@example.com", "Example.com"),
    )
    obs = Observation.model_construct(
        provenance=Provenance(source="crtsh", retrieved_at=NOW, query="example.com"),
        entities=(cert,),
        relations=(),
    )
    (clean,) = redact_observation(obs).entities
    assert isinstance(clean, Certificate)
    assert clean.sans == ("example.com",)


def test_unexpected_shapes_are_dropped_not_kept() -> None:
    payload = {
        "registrar": {"name": "Jane Doe", "email": "jane@example.com"},
        "status": ["active", {"note": "Jane"}],
        "events": "registered by Jane",
        "nameservers": ["ns1.example.net", {"ldhName": "ns2.example.net"}],
    }
    assert redact_registration(payload) == {
        "status": ["active"],
        "nameservers": [{"ldhName": "ns2.example.net"}],
    }


def test_scrub_emails_stays_linear_on_long_unseparated_input() -> None:
    import time

    text = "a%4" * 20_000  # no separator, no real address: worst case for backtracking
    start = time.perf_counter()
    assert scrub_emails(text) == text
    assert time.perf_counter() - start < 1.0
