from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import TypeAdapter, ValidationError

from domain_mapper.models import (
    ASN,
    ArchivedURL,
    Certificate,
    DnsRecord,
    Domain,
    Entity,
    IPAddress,
    Technology,
)

SHA = "AB" * 32
T0 = datetime(2026, 1, 1, tzinfo=UTC)
T1 = datetime(2026, 6, 1, tzinfo=UTC)


def test_domain_id_uses_normalized_fqdn() -> None:
    domain = Domain(fqdn="WWW.Example.COM.", in_scope=True)
    assert domain.fqdn == "www.example.com"
    assert domain.id == "domain:www.example.com"


def test_domain_rejects_invalid_name() -> None:
    with pytest.raises(ValidationError):
        Domain(fqdn="not a domain", in_scope=False)


def test_domain_records_are_an_immutable_tuple() -> None:
    domain = Domain(
        fqdn="example.com",
        in_scope=True,
        records=[{"type": "txt", "value": "v=spf1 -all"}],
    )
    assert domain.records == (DnsRecord(type="TXT", value="v=spf1 -all"),)


def test_entities_are_frozen() -> None:
    domain = Domain(fqdn="example.com", in_scope=True)
    with pytest.raises(ValidationError):
        domain.in_scope = False  # type: ignore[misc]


def test_entities_reject_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        Domain(fqdn="example.com", in_scope=True, owner="someone")  # type: ignore[call-arg]


def test_ip_id_uses_compressed_form() -> None:
    ip = IPAddress(address="2001:0db8:0000:0000:0000:0000:0000:0001", country="fr")
    assert ip.id == "ip:2001:db8::1"
    assert ip.country == "FR"


def test_ip_rejects_bad_country_code() -> None:
    with pytest.raises(ValidationError):
        IPAddress(address="192.0.2.1", country="France")


def test_asn_id_accepts_as_prefix() -> None:
    assert ASN(number="AS13335", holder="CLOUDFLARENET").id == "asn:13335"
    assert ASN(number=64496).id == "asn:64496"


@pytest.mark.parametrize("number", [0, -1, 2**32])
def test_asn_rejects_out_of_range(number: int) -> None:
    with pytest.raises(ValidationError):
        ASN(number=number)


def test_certificate_id_is_lowercase_sha256_without_colons() -> None:
    cert = Certificate(
        sha256=":".join(SHA[i : i + 2] for i in range(0, 64, 2)),
        issuer="R3",
        not_before=T0,
        not_after=T1,
        sans=["Example.com", "www.example.com"],
    )
    assert cert.id == "cert:" + SHA.lower()
    assert cert.sans == ("example.com", "www.example.com")


def test_certificate_rejects_bad_fingerprint() -> None:
    with pytest.raises(ValidationError):
        Certificate(sha256="abc", issuer="R3", not_before=T0, not_after=T1)


def test_certificate_validity_must_be_ordered() -> None:
    with pytest.raises(ValidationError):
        Certificate(sha256=SHA, issuer="R3", not_before=T1, not_after=T0)


def test_datetimes_must_be_timezone_aware_and_become_utc() -> None:
    paris = timezone(timedelta(hours=1))
    cert = Certificate(
        sha256=SHA, issuer="R3", not_before=datetime(2026, 1, 1, 1, tzinfo=paris), not_after=T1
    )
    assert cert.not_before == T0
    with pytest.raises(ValidationError):
        Certificate(sha256=SHA, issuer="R3", not_before=datetime(2026, 1, 1), not_after=T1)


def test_technology_id_is_case_insensitive() -> None:
    tech = Technology(name="Nginx", category="web-server", evidence="Server header")
    assert tech.id == "tech:nginx"
    assert tech.name == "Nginx"


def test_archived_url_id_and_normalization() -> None:
    url = ArchivedURL(host="WWW.example.com", path="/login", first_seen=T0, last_seen=T1)
    assert url.id == "url:www.example.com/login"


def test_archived_url_defaults_empty_path_to_root() -> None:
    url = ArchivedURL(host="example.com", path="", first_seen=T0, last_seen=T0)
    assert url.path == "/"


@pytest.mark.parametrize("path", ["/a?token=x", "/a#frag"])
def test_archived_url_refuses_query_and_fragment(path: str) -> None:
    with pytest.raises(ValidationError):
        ArchivedURL(host="example.com", path=path, first_seen=T0, last_seen=T1)


def test_archived_url_seen_dates_must_be_ordered() -> None:
    with pytest.raises(ValidationError):
        ArchivedURL(host="example.com", path="/", first_seen=T1, last_seen=T0)


def test_entity_union_is_discriminated_by_kind() -> None:
    adapter = TypeAdapter(Entity)
    entity = adapter.validate_python({"kind": "ip", "address": "192.0.2.1"})
    assert isinstance(entity, IPAddress)
    assert adapter.validate_python(entity.model_dump()) == entity


def test_validation_errors_never_echo_the_input() -> None:
    with pytest.raises(ValidationError) as excinfo:
        Certificate(sha256=SHA, issuer="R3", not_before=T0, not_after=T1, sans="jane@example.com")  # type: ignore[arg-type]
    assert "jane@example.com" not in str(excinfo.value)


def test_technology_name_is_stripped_and_blank_refused() -> None:
    assert Technology(name=" Nginx ", category="web-server").name == "Nginx"
    with pytest.raises(ValidationError):
        Technology(name="   ", category="web-server")


def test_technology_evidence_is_a_tuple() -> None:
    tech = Technology(name="nginx", category="web-server", evidence=["Server header"])
    assert tech.evidence == ("Server header",)


def test_dns_record_type_must_not_be_blank() -> None:
    with pytest.raises(ValidationError):
        DnsRecord(type="  ", value="x")


def test_certificate_sans_use_the_same_idna_form_as_domains() -> None:
    cert = Certificate(
        sha256=SHA,
        issuer="R3",
        not_before=T0,
        not_after=T1,
        sans=["Café.example.", "*.Café.example", "192.0.2.1"],
    )
    fqdn = Domain(fqdn="café.example", in_scope=True).fqdn
    assert cert.sans == (fqdn, f"*.{fqdn}", "192.0.2.1")
