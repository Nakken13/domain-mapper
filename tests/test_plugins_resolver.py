from __future__ import annotations

import dns.exception
import dns.message
import dns.name
import dns.resolver
import pytest

from surfacemap.plugins._resolver import (
    DnsAnswer,
    DnsError,
    DnspythonResolver,
    ResourceRecord,
    answer_from_message,
)


def message(text: str) -> dns.message.Message:
    return dns.message.from_text(text)


CHAIN = """id 1
opcode QUERY
rcode NOERROR
flags QR RD RA
;QUESTION
www.example.com. IN A
;ANSWER
WWW.Example.com. 300 IN CNAME d1.cdn.example.net.
d1.cdn.example.net. 60 IN A 198.51.100.7
d1.cdn.example.net. 60 IN A 198.51.100.8
"""

DANGLING = """id 2
opcode QUERY
rcode NXDOMAIN
flags QR RD RA
;QUESTION
shop.example.com. IN A
;ANSWER
shop.example.com. 300 IN CNAME gone.herokuapp.example.
"""

MIXED = """id 3
opcode QUERY
rcode NOERROR
flags QR RD RA
;QUESTION
example.com. IN TXT
;ANSWER
example.com. 300 IN TXT "v=spf1 " "include:_spf.example.net -all"
example.com. 300 IN MX 10 mail.example.com.
example.com. 300 IN MX 0 .
example.com. 300 IN NS ns1.example.net.
example.com. 300 IN AAAA 2001:db8:0:0::1
example.com. 300 IN CAA 0 issue "letsencrypt.org"
"""


def test_a_cname_chain_keeps_each_owner() -> None:
    answer = answer_from_message(message(CHAIN))
    assert answer == DnsAnswer(
        rcode="NOERROR",
        records=(
            ResourceRecord("www.example.com", "CNAME", "d1.cdn.example.net"),
            ResourceRecord("d1.cdn.example.net", "A", "198.51.100.7"),
            ResourceRecord("d1.cdn.example.net", "A", "198.51.100.8"),
        ),
    )


def test_nxdomain_keeps_the_dangling_chain() -> None:
    answer = answer_from_message(message(DANGLING))
    assert answer.rcode == "NXDOMAIN"
    assert answer.records == (
        ResourceRecord("shop.example.com", "CNAME", "gone.herokuapp.example"),
    )


def test_record_values_are_flattened_per_type() -> None:
    answer = answer_from_message(message(MIXED))
    assert answer.records == (
        ResourceRecord("example.com", "TXT", "v=spf1 include:_spf.example.net -all"),
        ResourceRecord("example.com", "MX", "mail.example.com"),
        ResourceRecord("example.com", "MX", ""),  # null MX (RFC 7505): no mail accepted
        ResourceRecord("example.com", "NS", "ns1.example.net"),
        ResourceRecord("example.com", "AAAA", "2001:db8::1"),
        ResourceRecord("example.com", "CAA", '0 issue "letsencrypt.org"'),
    )


def test_server_failure_is_an_error() -> None:
    with pytest.raises(DnsError, match="SERVFAIL"):
        answer_from_message(message(DANGLING.replace("NXDOMAIN", "SERVFAIL")))


class StubAnswer:
    def __init__(self, response: dns.message.Message) -> None:
        self.response = response


class StubResolver:
    def __init__(self, outcome: object) -> None:
        self.outcome = outcome
        self.calls: list[tuple[str, str, dict[str, object]]] = []

    async def resolve(self, name: str, rtype: str, **kwargs: object) -> StubAnswer:
        self.calls.append((name, rtype, kwargs))
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        assert isinstance(self.outcome, dns.message.Message)
        return StubAnswer(self.outcome)


async def test_resolves_through_dnspython_without_search_domains() -> None:
    stub = StubResolver(message(CHAIN))
    answer = await DnspythonResolver(stub).resolve("www.example.com", "A")  # type: ignore[arg-type]
    assert answer.records[0].type == "CNAME"
    assert stub.calls == [("www.example.com", "A", {"raise_on_no_answer": False, "search": False})]


async def test_nxdomain_exception_still_yields_the_chain() -> None:
    qname = dns.name.from_text("shop.example.com")
    nx = dns.resolver.NXDOMAIN(qnames=[qname], responses={qname: message(DANGLING)})
    answer = await DnspythonResolver(StubResolver(nx)).resolve("shop.example.com", "A")  # type: ignore[arg-type]
    assert answer.rcode == "NXDOMAIN"
    assert answer.records[0].value == "gone.herokuapp.example"


async def test_nxdomain_without_response_is_an_empty_nxdomain() -> None:
    qname = dns.name.from_text("gone.example.com")
    nx = dns.resolver.NXDOMAIN(qnames=[qname], responses={})
    answer = await DnspythonResolver(StubResolver(nx)).resolve("gone.example.com", "A")  # type: ignore[arg-type]
    assert answer == DnsAnswer(rcode="NXDOMAIN", records=())


async def test_other_resolver_failures_become_dns_errors() -> None:
    stub = StubResolver(dns.exception.Timeout())
    with pytest.raises(DnsError, match="Timeout"):
        await DnspythonResolver(stub).resolve("example.com", "A")  # type: ignore[arg-type]


def test_default_resolver_uses_the_system_configuration() -> None:
    resolver = DnspythonResolver()
    assert resolver.timeout > 0


def test_the_os_configuration_is_only_read_on_first_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import dns.asyncresolver

    built: list[object] = []
    monkeypatch.setattr(dns.asyncresolver, "Resolver", lambda: built.append(1) or object())
    DnspythonResolver()
    assert built == []  # creating the registry must not touch the OS resolver config
