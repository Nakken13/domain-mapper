from __future__ import annotations

import pytest

from domain_mapper.collect.http import FetchError, is_ip_literal, parse_json
from domain_mapper.plugins._util import country_code, is_public_ip
from domain_mapper.scope import try_normalize_domain


def test_try_normalize_domain_returns_none_instead_of_raising() -> None:
    assert try_normalize_domain(" WWW.Example.COM. ") == "www.example.com"
    assert try_normalize_domain("not a host") is None
    assert try_normalize_domain("_dmarc.example.com") is None  # strict: no underscore


def test_parse_json_checks_the_type_and_names_the_source() -> None:
    assert parse_json('{"a": 1}', "src", dict) == {"a": 1}
    assert parse_json("[1]", "src", list) == [1]
    for body, kind in (("{", dict), ("[]", dict), ("{}", list), ("null", dict)):
        with pytest.raises(FetchError, match="src: unexpected payload"):
            parse_json(body, "src", kind)


def test_is_ip_literal_accepts_bracketed_v6() -> None:
    assert is_ip_literal("192.0.2.1")
    assert is_ip_literal("[2001:db8::1]")
    assert not is_ip_literal("example.com")


def test_country_code_only_keeps_two_letters() -> None:
    assert country_code("FR") == "FR"
    assert country_code("None") is None
    assert country_code("FRA") is None


def test_is_public_ip_rejects_private_ranges() -> None:
    assert is_public_ip("8.8.8.8")
    assert not is_public_ip("10.0.0.1")
    assert not is_public_ip("::1")
